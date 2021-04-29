# RISC-V与coreboot源码分析

## 概要

coreboot是一个开源的项目，旨在替换计算机中的专有固件（BIOS）。coreboot之前被称为LinuxBIOS。coreboot在进行一些硬件初始化后运行一个payload，这个payload可以是标准固件实现、操作系统的引导或操作系统本身。

coreboot运行分为多个过程，每个过程是一个独立的程序。主要过程如下：

- bootblock：初始化部分硬件（Flash），引导加在romstage
- romstage：初始化存储器和部分芯片组，并引导执行ramstage
- ramstage：设备枚举资源分配，并加载执行payload
- payload：操作系统、操作系统引导或者标准固件等

## 文件夹分布

- `src/arch`，其下子目录对应特定的机器架构相关的代码
- `src/drivers`设备驱动，由具体SoC或主板通过config配置选择
- `src/soc`，其下子目录存放SoC相关代码
- `src/mainboard`，其下保存和主板相关的代码
- `src/lib`，架构相关代码平台无关
- `util`，其下有些工具链和一些小工具

## 终端

主要代码位于：

> src/include/console
>
> src/console

coreboot支持多种类型的终端，信息可以输出到各种类型的设备。具体使用那个设备通过config配置文件（`src/console/Kconfig`）配置。对于一个终端设备需要实现以下几个接口

```c
void init(void);
void tx_byte(unsigned char byte);
void tx_flush(void);
```

上面的函数是伪代码，具体函数参见`src/include/console`下的设备头文件。

## HLS(Hart Local storage)

coreboot在堆栈分配时根据hart id为每个hart分配一页内存用作堆栈，并在栈顶存放了一个数据结构，这个数据结构叫做HLS。

因为堆栈是页对齐，使用可以通过对堆栈指针进行对齐操作找到当前hart的栈顶，代码如下：

```c
// 通过对齐处理找出当前堆栈的栈顶
#define MACHINE_STACK_TOP() ({ \
	/* coverity[uninit_use] : FALSE */ \
	register uintptr_t sp asm ("sp"); \
	(void*)((sp + RISCV_PGSIZE) & -RISCV_PGSIZE); })
```

因为HLS存放在栈顶可以通过如下代码找到当前hart的HLS，代码如下：

```c
// 计算出当前HLS的位置
#define HLS() ((hls_t*)(MACHINE_STACK_TOP() - HLS_SIZE))
```

因为堆栈是根据hart id连续分配的，所以可以通过hart id的差值计算出其他hart的HLS，代码如下：

```c
// 通过hart id差值计算出其他hart的HLS
#define OTHER_HLS(id) ((hls_t*)((void*)HLS() + RISCV_PGSIZE * ((id) - HLS()->hart_id)))
```

## 多核处理

coreboot当前不支持多核，在每一个阶段的起始位置禁用不需要的核心，在运行下一个阶段时把其他hart唤醒跳转到下一个阶段。为了处理这个问题，在HLS中存放了如下数据结构：

```c
struct blocker {
	void *arg;
	void (*fn)(void *arg);
	atomic_t sync_a;
	atomic_t sync_b;
}脚本;
```

其中，`fn`和`arg`用于设定唤醒后运行的代码。sync_a和sync_b用于同步处理。处理函数位于`src/arch/riscv/smp.c`。主要逻辑如下

 主hart:

1. 设置sync_b = 0
2. 设置sync_a = 0x01234567
3. 等待所有的hart进入休眠状态（sync_b + 1 >= 核心数）
4. 设置sync_a = 0，sync_b = 0
5. 运行当前阶段的主要代码
6. 设置其他hart的唤醒入口
7. 发送ipi中断

次hart:

1. 等待sync_a 等于0x01234567
2. 对sync_b加1
3. 进入休眠状态，等待ipi唤醒
4. 运行blocker指定的函数

coreboot运行下一个阶段的入口为arch_prog_run，在这个函数中调用`smp_resume`

## 链接脚本

coreboot通过一个链接脚本来链接多个阶段。具体的段该如何链接，代码位于`src/lib/program.ld`。多个阶段共用一个链接脚本主要通过`src/include/memlayout.h`来实现。这里以bootblock为示例

```c
#if ENV_BOOTBLOCK
	#define BOOTBLOCK(addr, sz) \
		SYMBOL(bootblock, addr) \
		_ebootblock = ABSOLUTE(_bootblock + sz); \
		RECORD_SIZE(bootblock) \
		_ = ASSERT(_eprogram - _program <= sz, \
			STR(Bootblock exceeded its allotted size! (sz))); \
		INCLUDE "bootblock/lib/program.ld"
#else
	#define BOOTBLOCK(addr, sz) \
		REGION(bootblock, addr, sz, 1)
#endif
```

ENV_BOOTBLOCK是Makefile输出的宏，根据当前编译的阶段不同，定义的宏不同。然后输出两个符号放别标识段的开始和接收位置，如该编译当前阶段就引入`src/lib/program.ld`文件。

## 固件文件

固件文中包含一个一个的块，通过如下两个结构体描述

```c
struct fmap_area {
	uint32_t offset;		/* offset relative to base */
	uint32_t size;			/* size in bytes */
	uint8_t  name[FMAP_STRLEN];	/* descriptive name */
	uint16_t flags;			/* flags for this area */
}  __packed;

struct fmap {
	uint8_t  signature[8];		/* "__FMAP__" (0x5F5F464D41505F5F) */
	uint8_t  ver_major;		/* major version */
	uint8_t  ver_minor;		/* minor version */
	uint64_t base;			/* address of the firmware binary */
	uint32_t size;			/* size of firmware binary in bytes */
	uint8_t  name[FMAP_STRLEN];	/* name of this firmware binary */
	uint16_t nareas;		/* number of areas described by
					   fmap_areas[] below */
	struct fmap_area areas[];
} __packed;
```

fmap的位置通过内存布局``src/include/memlayout.h``中的宏`FMAP_CACHE`来设定，这样C代码就可以方便的访问到这个结构。

这些快中有一个名字为COREBOOT的块，其中存放了cbfs。cbfs是一些顺序存放的结构，结构如下

```
struct cbfs_file {
	char magic[8];
	uint32_t len;
	uint32_t type;
	uint32_t attributes_offset;
	uint32_t offset;
	char filename[];
} __packed;
```

offset和len指定了数据的位置。attributes_offset指定了属性的位置。属性有如下结构

```c
struct cbfs_file_attribute {
	uint32_t tag;
	/* len covers the whole structure, incl. tag and len */
	uint32_t len;
	uint8_t data[0];
} __packed;

struct cbfs_file_attr_compression {
	uint32_t tag;
	uint32_t len;
	/* whole file compression format. 0 if no compression. */
	uint32_t compression;
	uint32_t decompressed_size;
} __packed;

struct cbfs_file_attr_hash {
	uint32_t tag;
	uint32_t len;
	uint32_t hash_type;
	/* hash_data is len - sizeof(struct) bytes */
	uint8_t  hash_data[];
} __packed;
```

`cbfs_file`中的type指定了cbfs的类型，有如下类型

```c
#define CBFS_TYPE_STAGE      0x10
#define CBFS_TYPE_SELF       0x20
#define CBFS_TYPE_FIT        0x21
#define CBFS_TYPE_OPTIONROM  0x30
#define CBFS_TYPE_BOOTSPLASH 0x40
#define CBFS_TYPE_RAW        0x50
#define CBFS_TYPE_VSA        0x51
#define CBFS_TYPE_MBI        0x52
#define CBFS_TYPE_MICROCODE  0x53
#define CBFS_TYPE_STRUCT     0x70
#define CBFS_COMPONENT_CMOS_DEFAULT 0xaa
#define CBFS_COMPONENT_CMOS_LAYOUT 0x01aa
```

比较常见的类型有STAGE，STAGE的数据段还会有关附加头用于描述如何加载执行

```c
struct cbfs_stage {
	uint32_t compression;  /** Compression type */
	uint64_t entry;  /** entry point */
	uint64_t load;   /** Where to load in memory */
	uint32_t len;          /** length of data to load */
	uint32_t memlen;	   /** total length of object in memory */
} __packed;
```

## bootblock

此部分是机器上电最先执行的代码，负责初始化备份硬件然后引导romstage。最初代码是一段汇编用于初始化C运行环境，然后跳转到C代码入口。汇编代码如下：

```c
_start:
	# The boot ROM may pass the following arguments to coreboot:
	#   a0: the value of mhartid
	#   a1: a pointer to the flattened devicetree
	#
	# Preserve only the FDT pointer. We can query mhartid ourselves at any
	# time.
	#
	csrw mscratch, a1

	# initialize cache as ram
	call cache_as_ram

	# initialize stack point for each hart
	# and the stack must be page-aligned.
	# 0xDEADBEEF used to check stack overflow
	csrr a0, mhartid
	la   t0, _stack
	slli t1, a0, RISCV_PGSHIFT
	add  t0, t0, t1
	li   t1, 0xDEADBEEF
	STORE t1, 0(t0)
	li   t1, RISCV_PGSIZE - HLS_SIZE
	add  sp, t0, t1

	# initialize hart-local storage
	csrr a0, mhartid
	csrrw a1, mscratch, zero
	call hls_init

	li   a0, CONFIG_RISCV_WORKING_HARTID
	call smp_pause

	# initialize entry of interrupt/exception
	la t0, trap_entry
	csrw mtvec, t0

	# clear any pending interrupts
	csrwi mip, 0

	# set up the mstatus register
	call mstatus_init
	tail main

	// These codes need to be implemented on a specific SoC.
	.weak cache_as_ram
cache_as_ram:
	ret
```

这部分代码主要执行了如下操作：

1. 把cache用作ram
2. 初始化堆栈
3. 初始化HLS(hart local storage)
4. 多核处理，只保留一个工作的hart，把其他hart禁用
5. 异常初始化
6. mstatus初始化
7. 跳转到C程序入口

C程序代码位于`src/lib/bootblock.c`，此文件通过几个弱函数来让具体平台实现自己的功能

```c
__weak void bootblock_soc_early_init(void) { /* do nothing */ }
__weak void bootblock_mainboard_early_init(void) { /* no-op */ }
__weak void bootblock_soc_init(void) { /* do nothing */ }
__weak void bootblock_mainboard_init(void) { /* do nothing */ }
```

上面的函数以及根据调用的先后顺序排序，前两个函数和后来个函数之间还有一些基础的初始化，主要是coms终端和异常。

## romstage

romstage一般和bootblock共用堆栈，所以不需要重新初始C程序运行环境。romstage的入口程序位于`src/arch/riscv/romstage.c`。入口程序只负责重新初始化HLS，然后把其他hart休眠。romstage具体需要初始化那些设备与具体的主板有关，所以代码位于`src/manboard`下具体板子的目录下。一般情况下此过程需要初始化内存，为运行ramstage做准备。

## ramstage

ramstage因为内存已经初始化完成，这时可以使用内存作堆栈，所以需要重新初始化堆栈。程序入口位于`src/arch/riscv/ramstage.S`，这里的汇编和bootblock的类似，这里有个弱符号`exit_car`用于在必要时退出cache as ram。

ramstage有框架代码代码位于`src/lib/hardwaremain.c`。此文件把初始化过程分成12步。

```c
typedef enum {
	BS_PRE_DEVICE,
	BS_DEV_INIT_CHIPS,
	BS_DEV_ENUMERATE,
	BS_DEV_RESOURCES,
	BS_DEV_ENABLE,
	BS_DEV_INIT,
	BS_POST_DEVICE,
	BS_OS_RESUME_CHECK,
	BS_OS_RESUME,
	BS_WRITE_TABLES,
	BS_PAYLOAD_LOAD,
	BS_PAYLOAD_BOOT,
} boot_state_t;
```

每一个过程需要执行的操作通过如下结构体描述

```c
struct boot_state {
	const char *name;
	boot_state_t id;
	u8 post_code;
	struct boot_phase phases[2];
	boot_state_t (*run_state)(void *arg);
	void *arg;
	int num_samples;
	int complete : 1;
};
```

其中，boot_phase可以用来在阶段前和阶段后插入一些hook方法，具体定义如下：

```c
struct boot_phase {
	struct boot_state_callback *callbacks;
	int blockers;
};

struct boot_state_callback {
	void *arg;
	void (*callback)(void *arg);
	/* For use internal to the boot state machine. */
	struct boot_state_callback *next;
#if CONFIG(DEBUG_BOOT_STATE)
	const char *location;
#endif
};
```

ramstage要执行的主要操作通过一个数组记录，如下：

```c
static struct boot_state boot_states[] = {
	BS_INIT_ENTRY(BS_PRE_DEVICE, bs_pre_device),
	BS_INIT_ENTRY(BS_DEV_INIT_CHIPS, bs_dev_init_chips),
	BS_INIT_ENTRY(BS_DEV_ENUMERATE, bs_dev_enumerate),
	BS_INIT_ENTRY(BS_DEV_RESOURCES, bs_dev_resources),
	BS_INIT_ENTRY(BS_DEV_ENABLE, bs_dev_enable),
	BS_INIT_ENTRY(BS_DEV_INIT, bs_dev_init),
	BS_INIT_ENTRY(BS_POST_DEVICE, bs_post_device),
	BS_INIT_ENTRY(BS_OS_RESUME_CHECK, bs_os_resume_check),
	BS_INIT_ENTRY(BS_OS_RESUME, bs_os_resume),
	BS_INIT_ENTRY(BS_WRITE_TABLES, bs_write_tables),
	BS_INIT_ENTRY(BS_PAYLOAD_LOAD, bs_payload_load),
	BS_INIT_ENTRY(BS_PAYLOAD_BOOT, bs_payload_boot),
};
```

coreboot提供了一种方法来添加阶段前和间断后需要执行的代码。coreboot定义了一个结构体来描述这些要执行的hook

```c
struct boot_state_init_entry {
	boot_state_t state;
	boot_state_sequence_t when;
	struct boot_state_callback bscb;
};
```

并添加了一个宏，用于把这些机构体放到一个段，使其构成数组

```c
#if ENV_RAMSTAGE
#define BOOT_STATE_INIT_ATTR  __attribute__((used, section(".bs_init")))
#else
#define BOOT_STATE_INIT_ATTR  __attribute__((unused))
#endif

#define BOOT_STATE_INIT_ENTRY(state_, when_, func_, arg_)		\
	static struct boot_state_init_entry func_ ##_## state_ ##_## when_ = \
	{								\
		.state = state_,					\
		.when = when_,						\
		.bscb = BOOT_STATE_CALLBACK_INIT(func_, arg_),		\
	};								\
	static struct boot_state_init_entry *				\
		bsie_ ## func_ ##_## state_ ##_## when_ BOOT_STATE_INIT_ATTR = \
		&func_ ##_## state_ ##_## when_;
```

通过变量数组就可以找到需要执行的代码。