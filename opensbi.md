# opensbi源码分析

risc-v有三种特权等级，opensbi是一个运行在M-Mode的服务程序，提供[sbi](https://github.com/riscv/riscv-sbi-doc/blob/master/riscv-sbi.adoc)服务。

## firmware

firmware通过汇编代码实现，定义了opensbi如何初始化，如何处理中断，以及如何链接。相关代码主要位于firmware目录中。

当前opensbi可以编译出三种类型的固件：

1. fw_jump：后一级固件存放在一个固定地址（FW\_JUMP\_ADDR），opensbi执行完成后降级到S-Mode并跳转到此固定地址
2. fw_payload：后一级固件嵌入在opensbi中，opensbi执行完成后降级到S-Mode并跳转到嵌入固件的起始地址
3. fw_dynamic：下一级固件的信息由前一级固件通过寄存器传递给opensbi

opensbi从前级固件接收的参数：

1. a0：hartid
2. a1：fdt在内存中的地址
3. a2：在fw\_dynamic类型的固件中使用，用于传递下一级固件信息（struct fw\_dynamic\_info）

固件的主要代码位于`firmware/fw_base.s`中，为了实现三种类型的固件留出了一些hook接口，这些接口需要通过汇编函数实现（有些寄存器保存了信息不能使用，C代码使用的寄存器不好控制），这里为了便于理解使用C声明加以说明

```c
// 反回启动的主hart，用于执行fw_base.S中主要的初始化工作
// 如果返回-1，将通过原子指令随机选择
int fw_boot_hart();

// 用于保存信息，主要用在fw_dynamic固件中
void fw_save_info();

// 返回下一级固件的地址
uintptr_t fw_next_addr();

// 返回下级固件的参数arg1（fdt地址）
uintptr_t fw_next_arg1();

// 返回下一级固件运行的特权等级
int fw_next_mode();

// 返回一些选项，用于控制输出信息
unsigned long fw_options();
```

当前固件可以编译为位置无关代码或位置相关代码，通过变量`FW_PIC`控制（默认生成位置相关代码，`make FW_PIC=y`生成位置无关代码）

固件的初始化过程

```
            +------------------+        non boot hart
            | select boot hart |-------------------------+
            +------------------+                         |
                     ↓ boot hart                         | 
+---------------------------------------------------+    |
| move to link address / fix relocation information |    |
+---------------------------------------------------+    |
                     ↓                                   |
          +---------------------+                        |
          | jmp to link address |                        |
          +---------------------+                        |
                     ↓                                   ↓
        +-------------------------+         +-------------------------+
        | mark relocate copy done |         | wait relocate copy done |
        +-------------------------+         +-------------------------+
                     ↓                                   ↓
               +-----------+                  +---------------------+
               | bss clean |                  | jmp to link address |
               +-----------+                  +---------------------+
                     ↓                                   |
              +--------------+                           |
              | scratch init |                           |
              +--------------+                           |
                     ↓                                   |
       +----------------------------+                    |
       | move fdt to target address |                    |
       +----------------------------+                    |
                     ↓                                   ↓
            +---------------------+           +---------------------+
            | mask boot hart done |           | wait boot hart done |
            +---------------------+           +---------------------+
                     |                                   |
                     +-----------------------------------+
                                      ↓
                            +-------------------+
                            | scratch / sp init |
                            +-------------------+
                                      ↓ 
                                 +-----------+
                                 | tarp init |
                                 +-----------+
                                      ↓
                                 +----------+
                                 | sbi init |
                                 +----------+
```

最终内存布局如下

```
+--------------+ <--------- _fw_start
|              |
|              |
|              |
|              |
|              |
|              |
+--------------+ <---------- _fw_end
|              |
|              |
|   ↑stack     | hart index n scratch
+--------------+
|   scratch    |
+--------------+ <----------- _fw_end + 1 * stack_size
    ↓heap
.
.
.
+--------------+ <----------- _fw_end + (hart_count - 2) * stack_size
|   ↓heap      |
|              | 
|   ↑stack     | hart index 1 scratch
|--------------|
|   scratch    |
+--------------+ <----------- _fw_end + (hart_count - 1) * stack_size
|   ↓heap      |
|              |
|   ↑stack     | hart index 0 scratch
|--------------|
|   scratch    |
+--------------+ <----------- _fw_end + (hart_count - 0) * stack_size
    ↓heap
```

firmware中异常处理的关键在于处理两种情况：1. 异常来自M-Mode；2. 异常来自非M-Mode。如果异常来自M-Mode SP保持不变，如果异常来自低等级模式需要重新初始化SP为scratch。

## 重要数据结构

### sbi_scratch

每一个hart有一个sbi\_scratch用于保存一些全局信息，每个hart的sbi\_scratch的地址保存在mscratch寄存器中，sbi\_scratch结构如下：

```c
struct sbi_scratch {
	/** Start (or base) address of firmware linked to OpenSBI library */
	unsigned long fw_start;
	/** Size (in bytes) of firmware linked to OpenSBI library */
	unsigned long fw_size;
	/** Arg1 (or 'a1' register) of next booting stage for this HART */
	unsigned long next_arg1;
	/** Address of next booting stage for this HART */
	unsigned long next_addr;
	/** Priviledge mode of next booting stage for this HART */
	unsigned long next_mode;
	/** Warm boot entry point address for this HART */
	unsigned long warmboot_addr;
	/** Address of sbi_platform */
	unsigned long platform_addr;
	/** Address of HART ID to sbi_scratch conversion function */
	unsigned long hartid_to_scratch;
	/** Address of trap exit function */
	unsigned long trap_exit;
	/** Temporary storage */
	unsigned long tmp0;
	/** Options for OpenSBI library */
	unsigned long options;
};
```

sbi\_scratch保存了自己在内存中的位置（fw\_start/fw\_size），以及在opensbi执行完成后要运行的程序的信息（next\_addr/next\_mode/next\_arg1），以及平台相关扩展数据结构（struct sbi\_platform）的地址（platform\_addr）

通过上面firmware可知scratch是连续分布的，可以很简单的访问到其他hart的scratch。

sbi\_scratch内存分配的空间远远大于这个结构，其后的空间用于动态内存的申请。主要有以下两个接口函数：
```c
// 申请内存，返回相对scratch起始地址的偏移量
// 分配操作会影响所有hart，因为这里使用一个全局变量来记录内存分配的位置
unsigned long sbi_scratch_alloc_offset(unsigned long size, const char *owner);

// 释放内存（不能真正的释放内存）
void sbi_scratch_free_offset(unsigned long offset);
```

这里的内存分配是发生在每一个hart上的，这里主要是为了扩展结构体sbi_scratch，这里通过内存申请建立的变量都可以在sbi_scratch中定义。但为了灵活性，在各个模块中申请，这样可以保持sbi_scratch的代码稳定性，并且可以向其他模块隐藏这些变量。

sbi\_scratch之前的内存分配给堆栈

### sbi_platform

sbi\_platform主要记录平台的一些描述信息，并且记录平台相关操作的数据结构（struct sbi\_platform\_operations）的地址platform\_ops\_addr。结构如下：

```c
/** Representation of a platform */
struct sbi_platform {
	/**
	 * OpenSBI version this sbi_platform is based on.
	 * It's a 32-bit value where upper 16-bits are major number
	 * and lower 16-bits are minor number
	 */
	u32 opensbi_version;
	/**
	 * OpenSBI platform version released by vendor.
	 * It's a 32-bit value where upper 16-bits are major number
	 * and lower 16-bits are minor number
	 */
	u32 platform_version;
	/** Name of the platform */
	char name[64];
	/** Supported features */
	u64 features;
	/** Total number of HARTs */
	u32 hart_count;
	/** Per-HART stack size for exception/interrupt handling */
	u32 hart_stack_size;
	/** Pointer to sbi platform operations */
	unsigned long platform_ops_addr;
	/** Pointer to system firmware specific context */
	unsigned long firmware_context;
	/**
	 * HART index to HART id table
	 *
	 * For used HART index <abc>:
	 *     hart_index2id[<abc>] = some HART id
	 * For unused HART index <abc>:
	 *     hart_index2id[<abc>] = -1U
	 *
	 * If hart_index2id == NULL then we assume identity mapping
	 *     hart_index2id[<abc>] = <abc>
	 *
	 * We have only two restrictions:
	 * 1. HART index < sbi_platform hart_count
	 * 2. HART id < SBI_HARTMASK_MAX_BITS
	 */
	const u32 *hart_index2id;
};
```

### sbi_platform_operations

此结构用于记录平台特定的操作，这些操作作为hook被系统框架调用



## 异常处理

异常处理是opensbi的关键，这是运行时的东西。sbi的关键是处理ecall指令（来自M-Mode和S-Mode）触发的异常。opensbi除了处理ecall，还处理了一些必要的中断（定时器、ipi），和一些异常：非法指令异常（用来模拟一些CSR操作）、非对齐内存访问（通过字节操作模拟，用在不支持非对其访问内存的机器上）

异常处理的现场保护现场恢复代码位于`firmware/fw_base.S`中，要点是区分异常是否来自低特权等级，低特权等级需要重新初始化SP（低特权等级有自己的堆栈）

异常处理的C代码入口位于`lib/sbi/sbi_trap.c`中，入口代码如下：

```c
void sbi_trap_handler(struct sbi_trap_regs *regs)
{
	int rc = SBI_ENOTSUPP;
	const char *msg = "trap handler failed";
	ulong mcause = csr_read(CSR_MCAUSE);
	ulong mtval = csr_read(CSR_MTVAL), mtval2 = 0, mtinst = 0;
	struct sbi_trap_info trap;

	if (misa_extension('H')) {
		mtval2 = csr_read(CSR_MTVAL2);
		mtinst = csr_read(CSR_MTINST);
	}
	
    /* mcause最高位用于标记是否为中断 */
	if (mcause & (1UL << (__riscv_xlen - 1))) {
		mcause &= ~(1UL << (__riscv_xlen - 1));
		switch (mcause) {
		case IRQ_M_TIMER: /* 时钟中断处理 */
			sbi_timer_process();
			break;
		case IRQ_M_SOFT: /* 核间中断ipi处理 */
			sbi_ipi_process();
			break;
		default:
			msg = "unhandled external interrupt";
			goto trap_error;
		};
		return;
	}

    /* 异常处理 */
	switch (mcause) {
	case CAUSE_ILLEGAL_INSTRUCTION: /* 非法指令异常 */
		rc  = sbi_illegal_insn_handler(mtval, regs);
		msg = "illegal instruction handler failed";
		break;
	case CAUSE_MISALIGNED_LOAD:     /* 非对齐读取内存 */
		rc = sbi_misaligned_load_handler(mtval, mtval2, mtinst, regs);
		msg = "misaligned load handler failed";
		break;
	case CAUSE_MISALIGNED_STORE:    /* 非对齐写内存 */
		rc  = sbi_misaligned_store_handler(mtval, mtval2, mtinst, regs);
		msg = "misaligned store handler failed";
		break;
	case CAUSE_SUPERVISOR_ECALL:    /* 来自S-Mode的ecall */
	case CAUSE_MACHINE_ECALL:       /* 来自M-Mode的ecall */
		rc  = sbi_ecall_handler(regs);
		msg = "ecall handler failed";
		break;
	default: /* 其他异常交给低特权等级处理 */
		/* If the trap came from S or U mode, redirect it there */
		trap.epc = regs->mepc;
		trap.cause = mcause;
		trap.tval = mtval;
		trap.tval2 = mtval2;
		trap.tinst = mtinst;
		rc = sbi_trap_redirect(regs, &trap);
		break;
	};

trap_error:
	if (rc)
		sbi_trap_error(msg, rc, mcause, mtval, mtval2, mtinst, regs);
}
```

### sbi

sbi主要处理来自M-Mode和S-Mode的异常处理，sbi调用接口经过了一次改版

#### 传统sbi

老版本的sbi调用接口如下：

| 寄存器  | 描述                                |
| ------- | ----------------------------------- |
| a7      | 用于传递要调用的SBI功能             |
| a0 - a3 | 用于传递参数                        |
| a0      | 返回值，绝大部分sbi调用并没有返回值 |

老版本sbi接口比较少，主要有如下功能

```c
void sbi_set_timer(uint64_t stime_value);

void sbi_send_ipi(const unsigned long *hart_mask);

void sbi_clear_ipi(void);

void sbi_remote_fence_i(const unsigned long *hart_mask);

void sbi_remote_sfence_vma(const unsigned long *hart_mask,
                           unsigned long start,
                           unsigned long size);
 
void sbi_remote_sfence_vma_asid(const unsigned long *hart_mask,
                                unsigned long start,
                                unsigned long size,
                                unsigned long asid);

int sbi_console_getchar(void);

void sbi_console_putchar(int ch);

void sbi_shutdown(void);
```

#### 新sbi

新sbi对老sbi的一些缺陷做了改进，添加了扩展性，每次调用可以确认是否调用成功，调用接口如下：

| 寄存器  | 描述                               |
| ------- | ---------------------------------- |
| a7      | 扩展的编号（扩展是一组功能的集合） |
| a6      | 功能的编号                         |
| a0 - a5 | 参数                               |
| a0      | 返回值，错误信息                   |
| a1      | 返回值，结果                       |

#### 相关代码

新sbi接口，把一组功能视为一个扩展，一个扩展可以包含多个扩展编号。这样把传统的sbi作为一组扩展添加到新sbi接口中，保持向西兼容。为了管理各种扩展系统定义了一个结构体`struct sbi_ecall_extension`（位于`include/sbi/sbi_ecall.h`）

```c
struct sbi_ecall_extension {
	struct sbi_dlist head;     /* 双向链表的节点 */
	unsigned long extid_start; /* 扩展编号的起始编号 */
	unsigned long extid_end;   /* 扩展编号的结束编号 */
    /* 一组扩展可能不会使用extid_start到extid_end中的所有编号
     * 此接口用于检测某个具体的编号，是否被支持
     */
	int (* probe)(unsigned long extid, unsigned long *out_val);
    
    /* 用于处理ecall调用 */
	int (* handle)(unsigned long extid,   /* 扩展编号 */
                   unsigned long funcid,  /* 功能编号 */
                   const struct sbi_trap_regs *regs, /* 寄存器信息 */
                   unsigned long *out_val,/* 返回结果 */
                   struct sbi_trap_info *out_trap);
};
```

对于一个扩展需要实现上面的一个结构体，系统提供如下函数来管理扩展（代码位于`lib/sbi/sbi_ecall.c`)

```c
/* 获取主版本信息 */
u16 sbi_ecall_version_major(void);

/* 获取次版本信息 */
u16 sbi_ecall_version_minor(void);

/* 获取sbi是由那个程序实现的
 * 0 -> Berkeley Boot Loader
 * 1 -> OpenSBI
 * 2 -> Xvisor
 * 3 -> KVM
 * 4 -> RustSBI
 * 5 -> Diosix
 */
unsigned long sbi_ecall_get_impid(void);

/* 查找一个扩展id，如果存在返回对应的struct sbi_ecall_extension的结构 */
struct sbi_ecall_extension *sbi_ecall_find_extension(unsigned long extid);

/* 注册一个扩展（添加到链表中） */
int sbi_ecall_register_extension(struct sbi_ecall_extension *ext);

/* 注销一个扩展（从链表中移除） */
void sbi_ecall_unregister_extension(struct sbi_ecall_extension *ext);
```

由于新的sbi具有灵活的扩展性，所以添加了一个扩展（名为base，扩展号为0x10）用于获取sbi信息一级探测某个sbi接口是否可用。代码实现位于`lib/sbi/sbi_ecall_base.c`，功能如下：

```c
static int sbi_ecall_base_handler(unsigned long extid, unsigned long funcid,
				  const struct sbi_trap_regs *regs,
				  unsigned long *out_val,
				  struct sbi_trap_info *out_trap)
{
	int ret = 0;

	switch (funcid) {
	case SBI_EXT_BASE_GET_SPEC_VERSION:
            /* 获取主版本号信息 */
		*out_val = (SBI_ECALL_VERSION_MAJOR <<
			   SBI_SPEC_VERSION_MAJOR_OFFSET) &
			   (SBI_SPEC_VERSION_MAJOR_MASK <<
			    SBI_SPEC_VERSION_MAJOR_OFFSET);
		*out_val = *out_val | SBI_ECALL_VERSION_MINOR;
		break;
	case SBI_EXT_BASE_GET_IMP_ID:
            /* 获取实现的id号 */
		*out_val = sbi_ecall_get_impid();
		break;
	case SBI_EXT_BASE_GET_IMP_VERSION:
            /* 获取版本号 */
		*out_val = OPENSBI_VERSION;
		break;
	case SBI_EXT_BASE_GET_MVENDORID:
            /* 获取CSR寄存器mvendorid */
		*out_val = csr_read(CSR_MVENDORID);
		break;
	case SBI_EXT_BASE_GET_MARCHID:
            /* 获取CSR寄存器mhartid */
		*out_val = csr_read(CSR_MARCHID);
		break;
	case SBI_EXT_BASE_GET_MIMPID:
            /* 获取CSR寄存器mimpid */
		*out_val = csr_read(CSR_MIMPID);
		break;
	case SBI_EXT_BASE_PROBE_EXT:
            /* 查询一个扩展号是否被支持 */
		ret = sbi_ecall_base_probe(regs->a0, out_val);
		break;
	default:
		ret = SBI_ENOTSUPP;
	}

	return ret;
}
```



## 初始化

在firmware完成基本的初始化后，会跳转到C程序的初始化入口`sbi_init`

opensbi只需要初始化一次，通过一个静态变量和原子操作实现。当一个线程通过原子交换指令，读取到0时，被选择作为冷启动hart。每一个功能模块有一个初始化函数，它接收一个参数用于标识是否为冷启动。只有在冷启动完成后才能运行热启动，启动过程如下：

```
                 +-----------------------+
                 | select cold boot hart |
                 +-----------------------+
               cold hart      |
                +-------------+--------------------------+
                ↓                                        |
      +-------------------+                              |
      | do some cold init |                              |
      +-------------------+                              |
                ↓                                        ↓
 +--------------------------------+         +--------------------------+
 | mark boot done wake other hart |         | wait cold hart init done |
 +--------------------------------+         +--------------------------+
                |                                         |
                |                           +-------------------------+
                |                           | HMS status is suspended |
                |                           +-------------------------+
                |                                         |
                |              +--------------------------+
                |              ↓                          ↓
                |       +-------------+         +-------------------+
                |       | init resume |         | do some warm init |
                |       +-------------+         +-------------------+
                |             |                          |
                |             +--------------------------+
                ↓                                        ↓
     +----------------------+                 +----------------------+
     | hsm prepare next jmp |                 | hsm prepare next jmp |
     +----------------------+                 +----------------------+
                ↓                                        ↓
        +----------------+                      +----------------+
        | jmp next stage |                      | jmp next stage |
        +----------------+                      +----------------+
```

冷启动的hart会把HSM（hart status machine）的状态初始化stop除了它自己为pending。这会导致，冷启动上电时只有一个核能进入下一个stage。其他hart，需要下一个stage通过SBI调用（SBI\_EXT\_HSM\_HART\_START）换醒

## 功能

### 基础功能

```
/* 一些汇编相关的基础功能
 *   1. 汇编中使用的一些宏
 *   2. csr寄存器相关操作
 *   3. cpu扩展检测 字长检测
 *   4. pmp读写
 */
include/sbi/riscv_asm.h
lib/sbi/riscv_asm.c

/* 原子操作 */
include/sbi/riscv_atomic.h
lib/sbi/riscv_atomic.c

/* 内存屏障 */
include/sbi/riscv_barrier.h

/* elf相关的宏，用在汇编中，处理位置无关代码 */
include/sbi/riscv_elf.h

/* 一些RISCV编码相关的宏
 *   CSR寄存器地址
 *   异常CAUSE相关的宏
 *   指令编码相关的宏
 */
include/sbi/riscv_encoding.h

/* 一些用于读写浮点寄存器的宏，以及一些访问浮点相关CSR寄存器的宏 */
include/sbi/riscv_fp.h
lib/sbi/riscv_hardfp.S

/* 一些外设操作方法（添加内存屏障） */
include/sbi/riscv_io.h

/* 实现了一个原子锁 */
include/sbi/riscv_locks.h
lib/sbi/riscv_locks.c

/* 实现了一个bitmap，以及一些基本位运算：与/或/异或/置位/清零/拷贝等 */
include/sbi/sbi_bitmap.h
lib/sbi/sbi_bitmap.c

/* 实现了一些位操作 */
include/sbi/sbi_bitops.h
lib/sbi/sbi_bitops.c

/* 实现了一些宏用来定义常数 */
include/sbi/sbi_const.h

/* 基础CSR寄存器是否可写或可读
 * 通过设置一个临时的异常向量，然后执行CSR读写操作
 * 如果触发异常，将记录下异常信息
 */
include/sbi/sbi_csr_detect.h
lib/sbi/sbi_expected_trap.S

/* sbi调用的返回值 */
include/sbi/sbi_error.h

/* 定义了一些数据类型 */
include/sbi/sbi_types.h

/* 版本号 */
include/sbi/sbi_version.h

/* 在M-Mode下以非特权模式访问内存和指令 */
include/sbi/sbi_unpriv.h
lib/sbi/sbi_unpriv.c

/* 字符串操作 */
include/sbi/sbi_string.h
lib/sbi/sbi_string.c

/* 双向链表 */
include/sbi/sbi_list.h

/* 一些数学函数 */
include/sbi/sbi_math.h
lib/sbi/sbi_math.c

/* 一个线程安全的fifo */
include/sbi/sbi_fifo.h
lib/sbi/sbi_fifo.c

/* 基于bitmap，用于标记一组hart */
include/sbi/sbi_hartmask.h
```

### sbi_ecall

代码位于：

> include/sbi/sbi_ecall.h
>
> lib/sbi/sbi_ecall.c

此模块用于管理SBI扩展。一个扩展通过一个结构体描述：

```c
struct sbi_ecall_extension {
	struct sbi_dlist head;
	unsigned long extid_start;
	unsigned long extid_end;
	int (* probe)(unsigned long extid, unsigned long *out_val);
	int (* handle)(unsigned long extid, unsigned long funcid,
		       const struct sbi_trap_regs *regs,
		       unsigned long *out_val,
		       struct sbi_trap_info *out_trap);
};
```

对于比较复杂的SBI扩展可能对应多个扩展id，扩展id可以是连续的，也可以有间隙的。如果有间隙一点要提供probe方法。handle用于中断处理。

系统通过链表来维护扩展，并通过两个函数来维护列表：

```c
int sbi_ecall_register_extension(struct sbi_ecall_extension *ext);
void sbi_ecall_unregister_extension(struct sbi_ecall_extension *ext);
```

并提供一些辅助函数

```c
// 确定一个扩展id是否有效
struct sbi_ecall_extension *sbi_ecall_find_extension(unsigned long extid);

// SBI处理
int sbi_ecall_handler(struct sbi_trap_regs *regs);
```

#### sbi_ecall_base

代码位于：

> lib/sbi/sbi_ecall_base.c

此扩展主要用来提供SBI信息：

1. SBI版本信息
2. 实现id，即由什么软件实现
3. 实现的版本号
4. 读取一些CSR寄存器（MVENDORID、MARCHID、MIMPID）
5. 确定一个扩展id是否有效

#### sbi_ecall_vendor

代码位于：

> lib/sbi/sbi_ecall_vendor.c

此部分代码实现了一个sbi\_ecall\_extension结构体，主要用来封装厂商的SBI接口（扩展id 0x09000000 - 0x09FFFFFF）。这部分接口位于：

```c
struct sbi_platform_operations {
	/** platform specific SBI extension implementation probe function */
	int (*vendor_ext_check)(long extid);
	/** platform specific SBI extension implementation provider */
	int (*vendor_ext_provider)(long extid, long funcid,
				   const struct sbi_trap_regs *regs,
				   unsigned long *out_value,
				   struct sbi_trap_info *out_trap);
}
```

### sbi_console

代码位于：

>include/sbi/sbi_console.h
>
>lib/sbi/sbi_console.c

此模块实现了类似`sprintf`/`printf`的函数，并导出了`sbi_getc`和`sbi_putc`方便在SBI中调用。在`sbi_platform_operations`中预留了三个接口用于初始化和读写终端：

```c
struct sbi_platform_operations {
    // ...
	/** Write a character to the platform console output */
	void (*console_putc)(char ch);
	/** Read a character from the platform console input */
	int (*console_getc)(void);
	/** Initialize the platform console */
	int (*console_init)(void);
    // ...
}
```

### sbi_timer

代码位于：

> include/sbi/sbi_timer.h
>
> lib/sbi/sbi_timer.c

此模块用于管理定时事件。RISC-V特权等级定义了两个内存映射的64位CSR寄存器（mtime/mtimecmp）用于定时器控制，但这两个寄存器不是强制实现的，对于一些平台可以通过外设实现定时器控制。所以，opensbi提供了一些接口用于特定平台实现定时器功能：

```c
struct sbi_platform_operations {
    // ...
    /** Get platform timer value */
	u64 (*timer_value)(void);
	/** Start platform timer event for current HART */
	void (*timer_event_start)(u64 next_event);
	/** Stop platform timer event for current HART */
	void (*timer_event_stop)(void);
	/** Initialize platform timer for current HART */
	int (*timer_init)(bool cold_boot);
	/** Exit platform timer for current HART */
	void (*timer_exit)(void);
	// ...
}
```

上述接口被封装出以下接口：

```c
// 定时器初始化
int sbi_timer_init(struct sbi_scratch *scratch, bool cold_boot);

// 设定定时事件
void sbi_timer_event_start(u64 next_event);

// 定时事件异常处理，从定向给S-Mode(触发S-Mode时间中断)
void sbi_timer_process(void);

// 定时器反初始化
void sbi_timer_exit(struct sbi_scratch *scratch);
```

除了实现定时相关功能外还实现了虚拟的htimedelta寄存器，这个寄存器用于在虚拟模式下对mtime进行偏移，即虚拟模式下访问到的mtime的值比非虚拟模式下访问到的mtime的值大htimedelta。并提供以下接口在`lib/sbi/sbi_emulate_csr.c`中访问：

```c
// 非虚拟模式读取mtime
u64 sbi_timer_value(void);

// 虚拟模式读取mtime
u64 sbi_timer_virt_value(void);

// 读取htimedelta
u64 sbi_timer_get_delta(void);

// 写htimedelta
void sbi_timer_set_delta(ulong delta);

// 写htimedeltah
void sbi_timer_set_delta_upper(ulong delta_upper);
```

### sbi_ipi

代码位于：

>include/sbi/sbi_ipi.h
>
>lib/sbi/sbi_ipi.c

ipi(Inter-Processor Interrupt)，核间中断，是用于多核通讯的一种方法。硬件的ipi通过操作映射到内存的寄存器，可以向目标hart发生一个ipi中断。sbi_ipi通过软件实现了ipi类型，每一种类型的ipi都可以双向传递参数。

为了实现这种能力sbi_ipi首先在每一个hart的scratch上创建了一个变量`ipi_data`。它的类型如下：

```c
struct sbi_ipi_data {
	unsigned long ipi_type;
};
```

它的其中的每一个比特标识一种ipi类型，每一种类型的ipi对应一些列的处理方法，处理方法通过`sbi_ipi_event_ops`结构体描述，结构体如下：

```c
struct sbi_ipi_event_ops {
	/** ipi操作的名字 */
	char name[32];

	/** 由发送ipi中断的hart调用，在发生中断前调用,用于传递信息给目标hart */
	int (* update)(struct sbi_scratch *scratch,
			struct sbi_scratch *remote_scratch,
			u32 remote_hartid, void *data);

	/** 由发送ipi中断的hart调用。在中断发送后调用 */
	void (* sync)(struct sbi_scratch *scratch);

	/** 由接收ipi中断的hart调用，用于处理中断 */
	void (* process)(struct sbi_scratch *scratch);
};

/** 此数组记录每一种ipi中断的处理方法 */
static const struct sbi_ipi_event_ops *ipi_ops_array[SBI_IPI_EVENT_MAX];
```

这里注意一个方法：

```c
int sbi_ipi_send_many(ulong hmask, ulong hbase, u32 event, void *data);
```

上面的含义是向如下hart发送ipi中断

```c
for (int i=0; hmask; i++){
    if (hmask & 1)
        // send ipi to hartid == hbase + i
    hmask = hmask >> 1;
}
```

之所以要这么做，是为了一次调用请求向更多的hart发生ipi中断。但受限与long的长度只支持32或64个，所以添加了一个hbase参数。

具体平台需要为sbi_ipi实现如下接口：

```c
struct sbi_platform_operations {
    // ...
	/** Send IPI to a target HART */
	void (*ipi_send)(u32 target_hart);
	/** Clear IPI for a target HART */
	void (*ipi_clear)(u32 target_hart);
	/** Initialize IPI for current HART */
	int (*ipi_init)(bool cold_boot);
	/** Exit IPI for current HART */
	void (*ipi_exit)(void);
    // ...
}
```

### sbi_tlb

代码位于：

> include/sbi/sbi_tlb.h
>
> lib/sbi/sbi_tlb.c

此模块用于在多个hart之间执行缓存一致性操作，通过ipi在多个hart直接传递缓存一致性操作的命令。缓存一致性操作命令如下：

```c
struct sbi_tlb_info {
	unsigned long start; // 起始地址
	unsigned long size;  // 大小
	unsigned long asid;  // 要刷新的页表的标识(address space identifier)
	unsigned long vmid;  // 要刷新的虚拟页表的标识（virtual machine identifier）
	void (*local_fn)(struct sbi_tlb_info *tinfo); // 刷新方法，一个函数指针
	struct sbi_hartmask smask; // 发送这条命令的源hart
};
```

一个hart可能同时接收到好几个hart发送过来的内存一致性操作请求，为此每个hart在scratch上创建了一个sbi\_tlb\_info的队列，此队列用于存放接收到的命令。为了等待目标hart完成操作，每个hart在scratch上创建了一个`tlb_sync`用于同步，发送操作的hart等待属于自己的`tlb_sync`一次翻转，接收操作的hart通过`sbi_tlb_info->smask`访问到放送的操作的hart的`tlb_sync`，并写入一次翻转。

为了提高性能，在执行ipi的update时会检测目标hart的操作队列，如果当前操作可以和队列中的操作合并，就不在队列中插入新的操作，而是修改队列中的命令。

### sbi_hsm

代码位于：

>include/sbi/sbi_hsm.h
>
>lib/sbi/sbi_hsm.c

hsm(hart status management)，此扩展用于管理hart，可以用于管理hart休眠，或者重新加载操作系统。为了使每个hart具有自己的状态，通过在scratch上创建了一个变量，用于记录核心状态：

```c
struct sbi_hsm_data {
    // 原子类型，记录核心状态
	atomic_t state;
    // suspend具有多种类型，有简单的挂起（wfi）,和深度休眠需要重新跳转到热启动入口
	unsigned long suspend_type;
	unsigned long saved_mie; // 用于在suspend时保存恢复中断使能信息
	unsigned long saved_mip; // 用于在suspend保存恢复中断pending信息
};
```

每个hart具有如下状态：

```c
#define SBI_HSM_STATE_STARTED			0x0
#define SBI_HSM_STATE_STOPPED			0x1
#define SBI_HSM_STATE_START_PENDING		0x2
#define SBI_HSM_STATE_STOP_PENDING		0x3
#define SBI_HSM_STATE_SUSPENDED			0x4
#define SBI_HSM_STATE_SUSPEND_PENDING		0x5
#define SBI_HSM_STATE_RESUME_PENDING		0x6
```

hart的状态树如下：

```
                                     +--------+
                                     | stoped |
                                     +--------+
                                       |    ↑sbi_hsm_exit call by self
        +------------------------------+    +------------------------------+
        ↓sbi_hsm_hart_start call by other                                  |
+---------------+                                                   +--------------+
| start pending |                                                   | stop pending |
+---------------+                                                   +--------------+
        |wfi                                  sbi_hsm_hart_stop call by self↑
        +------------------------------+     +------------------------------+
sbi_hsm_prepare_next_jump call by self ↓     |
                                     +---------+ sbi_hsm_hart_resume_finish call by self
        +----------------------------| started |<---------------------------+
        |                            +---------+                            |
        |                                 ↑                                 |
        |                                 |                         +----------------+
        |                                 | wfi                     | resume pending |
        |                                 |                         +----------------+
        |                            +---------+                            ↑
        +--------------------------->| suspend |----------------------------+
   sbi_hsm_hart_suspend call by self +---------+   wfi, sbi_hsm_hart_resume_start call by self
```

### sbi_domain

代码位于：

> include/sbi/sbi_domain.h
>
> lib/sbi/sbi_domain.c

sbi\_domain用于管理一组hart，它们具有相同的内存访问权限（物理内存访问权限，PMP）。sbi、_domain通过如下结构体描述。

```c
struct sbi_domain {
	// domain的索引
	u32 index;
	// 相关的hart
	struct sbi_hartmask assigned_harts;
	// domain的名字
	char name[64];
	// 可能的hart，在调用注册函数前需要赋值
	const struct sbi_hartmask *possible_harts;
	// 内存区域
	struct sbi_domain_memregion *regions;
	// 启动这个domain的hart的编号，就说运行注册函数的hart
	u32 boot_hartid;
	/** Arg1 (or 'a1' register) of next booting stage for this domain */
	unsigned long next_arg1;
	/** Address of next booting stage for this domain */
	unsigned long next_addr;
	/** Privilege mode of next booting stage for this domain */
	unsigned long next_mode;
	/** Is domain allowed to reset the system */
	bool system_reset_allowed;
};

// 内存区域的结构
struct sbi_domain_memregion {
	// 大小，2^order
	unsigned long order;
	// 起始地址，对齐到2^order
	unsigned long base;
	// 内存属性
#define SBI_DOMAIN_MEMREGION_READABLE		(1UL << 0) // 可读
#define SBI_DOMAIN_MEMREGION_WRITEABLE		(1UL << 1) // 可写
#define SBI_DOMAIN_MEMREGION_EXECUTABLE		(1UL << 2) // 可执行
#define SBI_DOMAIN_MEMREGION_MMODE		(1UL << 3)     // 这将给PMP设定上锁
#define SBI_DOMAIN_MEMREGION_ACCESS_MASK	(0xfUL)

#define SBI_DOMAIN_MEMREGION_MMIO		(1UL << 31)    // 标记这段内存是一个外设
	unsigned long flags;
};
```

当前的系统支持32个domain，通过如下数据结构维护

```c
// 这个数组用于记录domain
struct sbi_domain *domidx_to_domain_table[SBI_DOMAIN_MAX_INDEX] = { 0 };
// 这个变量用于记录当前domidx_to_domain_table中有几个是有效的
static u32 domain_count = 0;
```

每个hart与一个domain绑定，通过一个表记录hartid与domain的关系

```c
struct sbi_domain *hartid_to_domain_table[SBI_HARTMASK_MAX_BITS] = { 0 };
```

注册domain，就是维护以上数据结构。当前系统维护了一个root domain，主要数据结构有：

```c
static struct sbi_hartmask root_hmask = { 0 };

// 最多有16个内存区域
#define ROOT_REGION_MAX	16
// 记录root_memregs中有几个元素，用于添加新的内存区域
static u32 root_memregs_count = 0;
static struct sbi_domain_memregion root_memregs[ROOT_REGION_MAX + 1] = { 0 };
// 此内存区域用来记录opensbi在内存中的位置，防止低特权等级访问此位置
static struct sbi_domain_memregion root_fw_region;

struct sbi_domain root = {
	.name = "root",
	.possible_harts = &root_hmask,
	.regions = root_memregs,
	.system_reset_allowed = TRUE,
};
```

主要的接口函数如下：

```c
// 创建一个内存区域
void sbi_domain_memregion_init(unsigned long addr,
				unsigned long size,
				unsigned long flags,
				struct sbi_domain_memregion *reg);

// 向一个root domain中添加内存区域
int sbi_domain_root_add_memregion(const struct sbi_domain_memregion *reg);

// 判断一个hart是否属于当前domain
bool sbi_domain_is_assigned_hart(const struct sbi_domain *dom, u32 hartid);

// 检测地址权限
bool sbi_domain_check_addr(const struct sbi_domain *dom,
			   unsigned long addr, unsigned long mode,
			   unsigned long access_flags);

// 通过终端打印domain信息
void sbi_domain_dump(const struct sbi_domain *dom, const char *suffix);

// 通过中断打印所有的domain的信息
void sbi_domain_dump_all(const char *suffix);

// 冻结domain信息，此函数调用后将不能再注册新的domain
int sbi_domain_finalize(struct sbi_scratch *scratch, u32 cold_hartid);

// 初始化domain
int sbi_domain_init(struct sbi_scratch *scratch, u32 cold_hartid);
```

为了让具体的平台可以修改root domain，以及添加自己的domain，在platform在预留了如下接口：

```c
struct sbi_platform_operations {
    // ...
	/** Get platform specific root domain memory regions */
	struct sbi_domain_memregion *(*domains_root_regions)(void);
	/** Initialize (or populate) domains for the platform */
	int (*domains_init)(void);
    // ...
}
```





