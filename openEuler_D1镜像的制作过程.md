# openEuler_D1镜像的制作过程

## 1. 下载openEuler的[镜像文件](https://repo.openeuler.org/openEuler-preview/RISC-V/Image/openEuler-preview.riscv64.qcow2)

## 2. 挂载openEuler的文件系统

1. 安装软件： `sudo apt install qemu-utils`
2. 使能NBD: `sudo modprobe nbd max_part=8`
3. 连接 QCOW2 作为网络块设备: `sudo qemu-nbd --connect=/dev/nbd0 openEuler-preview.riscv64.qcow2`
4. 进行分区映射：`sudo kpartx -av /dev/nbd0`
5. 挂载分区：`mkdir /tmp/oE; sudo mount /dev/mapper/nbd0p1 /tmp/oE`

## 3. 构建buildroot

1. 下载buildroot: `git clone https://gitee.com/weidongshan/neza-d1-buildroot.git`
2. 编译： `make all`
3. 镜像位于：`output/images/sdcard.img`

## 4. 把buildroot镜像烧写到SD卡

1. `dd if=output/images/sdcard.img of=/dev/sdx`

## 5. 调整分区大小

因为openEuler根文件系统有990M。buildroot镜像的根文件系统只有500M。所以需要调整分区大小。

1. `sudo fdisk -l /dev/sdx`,记录下最后一个分区的起始扇区
2. `sudo fdisk /dev/sdx`，然后按`d`，删除最后一个分区，然后按`n`重建记住起始山区保持不变，大小设置为1.2G
3. `resizefs /dev/sdx4`，调整文件系统大小，如果提示需要修复文件系统，按提示操作后重新执行此命令

## 6. 修改根文件系统

1. 删除sdcard根文件系统下的文件，只保留内核模块`/lib/modules/5.4.61`
2. 拷贝/tmp/oE下的所有文件到sdcard根目录

## 7. 修改uboot的环境变量

修改完后重启发现，systemd报错。检查后发现根文件系统只读，需要修改内核的命令行选项。

1. 把sdcard插入到电脑
2. 安装软件：`sudo apt install u-boot-tools`
3. 添加配置信息，用于读写uboot的环境变量：
```
cat << EOF | sudo tee /etc/fw_env.config
/dev/sda1	0x00000	0x20000
/dev/sda2	0x00000	0x20000
EOF
```
4. 查看原来的内核参数：
```
➜  ~ sudo fw_printenv | grep bootargs
bootargs=earlyprintk=sunxi-uart,0x02500000 clk_ignore_unused initcall_debug=0 console=ttyS0,115200 loglevel=8 root=/dev/mmcblk0p4 init=/sbin/init partitions=ext4 cma=8M gpt=1
```
5. 修改根文件系统为可读写
```
➜  ~ sudo fw_setenv bootargs earlyprintk=sunxi-uart,0x02500000 clk_ignore_unused initcall_debug=0 console=ttyS0,115200 loglevel=8 root=/dev/mmcblk0p4 rw init=/sbin/init partitions=ext4 cma=8M gpt=1
```

## 8. dump出系统镜像

1. `sudo fdisk -l /dev/sdx`，记录下最后一个分区的介绍扇区n
2. `sudo dd if=/dev/sdx of=openEuler-D1.img bs=512 count=n+1`