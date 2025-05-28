# AOBO: An AArch64 Online Binary Optimizer
[Ocolos](https://github.com/upenn-acg/ocolos-public) is the first _online_ code layout optimization system on the Intel64 platform for unmodified applications.  Building upon the OCOLOS framework, we develop the AOBO by redesigning crucial modules to support the AArch64 instruction set architecture. This work has been published in [ACM TACO](https://dl.acm.org/doi/abs/10.1145/3578360.3580255)
## Prerequisites
Please refer instructions from links or directly run commands listed below to install prerequisites: 
- Linux Perf:`sudo apt-get install linux-tools-common linux-tools-generic` 
- libunwind: [https://github.com/libunwind/libunwind](https://github.com/libunwind/libunwind) (1.7+ version)
- Rust: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh` 
- boost_1_73_0 (for MySQL): [https://www.boost.org/users/history/version_1_73_0.html](https://www.boost.org/users/history/version_1_73_0.html) 
- binutils (for objdump) [^1] : [https://ftp.gnu.org/gnu/binutils/](https://ftp.gnu.org/gnu/binutils/) 
- boost: `sudo apt-get install libboost-all-dev` 
[^1]:If your `objdump` version is older than 2.27, please download the latest version of `binutils`.  

## Download AOBO for mysql
```bash
> git clone git@github.com:onroadmuwl/ocolos-public-aarch64.git
```


## Install BOLT 
To use `llvm-bolt` and `perf2bolt` utilities, `BOLT` needs to be installed. \
The BOLT has been updated to support online code replacement and to enhance the effectiveness of code layout optimization. \
Please follow the commands below to install `BOLT` 
```bash
> mkdir BOLT && cd BOLT
> git clone git@github.com:onroadmuwl/llvm-project-bolt.git llvm-bolt
> cd llvm-bolt
> cd ..
> mkdir build && cd build
> cmake -G "Unix Makefiles" ../llvm-bolt/llvm -DLLVM_TARGETS_TO_BUILD="X86;AArch64" -DCMAKE_BUILD_TYPE=Release -DLLVM_ENABLE_ASSERTIONS=ON -DLLVM_ENABLE_PROJECTS="clang;lld;bolt"
> make -j
```


## Build MySQL from source 
```bash
> git clone https://github.com/mysql/mysql-server.git 
> cd mysql-server 
> git checkout 6846e6b2f72931991cc9fd589dc9946ea2ab58c9 
```
In `CMakeList.txt`, at line 580, please add [^2]: 
[^2]: If the mysqld binary compiled by gcc generates `callq` instructions rather than `call` instructions, please refer to the solution discussed in [this page](https://github.com/upenn-acg/ocolos-public/issues/1).
```
STRING_APPEND(CMAKE_C_FLAGS  " -fno-jump-tables")
STRING_APPEND(CMAKE_CXX_FLAGS " -fno-jump-tables")
STRING_APPEND(CMAKE_C_FLAGS " -no-pie")
STRING_APPEND(CMAKE_CXX_FLAGS " -no-pie")
```
Also, in `CMakeList.txt`, turn off `ld.gold` linker: \
change `OPTION(USE_LD_GOLD "Use GNU gold linker" ON)` to be `OPTION(USE_LD_GOLD "Use GNU gold linker" OFF)`

Then build `mysqld` from source:
```bash
> export CC=gcc 
> export CXX=g++
> mkdir build && cd build 
> cmake .. -DWITH_BOOST={path of the boost_1_73_0 directory} -DCMAKE_CXX_LINK_FLAGS=-Wl,--emit-relocs -DCMAKE_C_LINK_FLAGS=-Wl,--emit-relocs -DBUILD_CONFIG=mysql_release 
> make -j
> make install
```


To initialize MySQL, run:
```bash
> chown -R {user} {path to MySQL directory}
> {path to MySQL directory}/bin/mysqld --initialize-insecure --user=root --datadir={your data dir path of MySQL} 
> {path to MySQL directory}/bin/mysqld --user=root --port=3306 --datadir={your data dir path of MySQL}
```
In another terminal, run:
```bash
> mysql -u root
> CREATE USER 'aobo'@'localhost';
> GRANT ALL PRIVILEGES ON *.* TO 'aobo'@'localhost' WITH GRANT OPTION;
> CREATE DATABASE aobo_db;
> QUIT;
> mysqladmin -u root shutdown
```
_Note_: 
1. {path to MySQL directory} is normally `/usr/local/mysql` unless otherwise specified during MySQL server's installation.  
2. {user} should be your linux user name. 


## Build Sysbench 
```bash
> sudo apt-get update 
> sudo apt-get install sysbench
```
Or if you prefer to build sysbench from source, please refer instructions in the following webpage:\
[https://github.com/akopytov/sysbench](https://github.com/akopytov/sysbench) 


## Build & run AOBO
- Navigate to `ocolos-public-aarch64` directory.  
- In the file `config`, specify the absolute path for `nm`,`perf`,`objdump`,`llvm-bolt`,`perf2bolt` [^3]
   [^3]: if `nm`,`objdump` and `perf` are already in shell, it's OK that their paths are not specified in `config`. This can be checked by `which nm`, `which objdump` and `which perf`.
- In `config`, please also specify the commands to run `MySQL server` and `sysbench`. The example commands are given in the config file. 
   * _Note_: the first argument of the command (a.k.a. the binary being invoked in the command) should be written in its full path. 
- Please also remember to export the path of `ocolos-public-aarch64`'s directory.
```bash
> export OCOLOS_PATH=/your/path/to/ocolos-public-aarch64
```
- Then run the following commands:

```bash
> make
> ./extract_call_sites
> ./tracer

```
- `make` will produce 2 executables (`tracer` & `extract_call_sites`)+ 1 shared library (`replace_function.so`). 
   * If libunwind library is stored in other places instead of `/usr/local/lib`, you also need to edit Makefile and update it to the corresponding path.
   * If libunwind's header files are stored in other places instead of `/usr/local/include`, you also need to edit Makefile and update it to the corresponding path. 
- `./extract_call_sites` will produce 2 files which store all call sites information extracted from the target binary (a.k.a. `mysqld`) to the `tmp_data_dir` you specified in the config file. 
- `./tracer` will invoke both `MySQL` server process and sysbench workloads `oltp_read_only`, and then perform code layout optimization during runtime. 
   * The output of sysbench's throughput can be found in `sysbench_output.txt`. At about the 130th second, you will see a significant throughput improvement, since AOBO has replace the code layout to be the optimized one at that time.
   * After one run (~3 minutes), if you want to start another run, please first run `mysqladmin -u root shutdown` command to shutdown the current `MySQL` server process. 


## Miscellaneous (notes about how to debug AOBO)
In `Makefile`'s `CXXFLAGS`,
- if `-DAArch64` flag is added, AOBO will support the AArch64 platform;
- if `-DIntel64` flag is added, AOBO will support the Intel64 platform;
- if `-DTIME_MEASUREMENT` flag is added, AOBO will print the execution time of code replacement;
- if `-DMEASUREMENT` flag is added, AOBO will print metrics such as:  
  * the number of functions on the call stack when target process is paused,
  * the number of functions that are moved by `BOLT`,
  * the number of functions that are in the `BOLT` and original functions.
- if `-DDEBUG_INFO` flag is added, AOBO will print debug information such as:
  * the information about detailed behavior of tracer
  * the content in the call stack when the target process is paused
  * `-DDEBUG_INFO` can also be defined in `src/replace_function.hpp`. In this way, the ld_preload library will store all machine code per function it inserted to the target process as a `uint8_t` format array into a file. The file can be found in the `tmp_data_path` you defined in the config file. 
- if `-DDEBUG` flag is added, after code replacement, AOBO will first send `SIGSTOP` signal to target process and then resume the target process by `PTRACE_DETACH`. In this way, it allows debugging tools such as `GDB` to attach to the target process and observe what goes wrong after code replacement.

If the code replacement runs into a failure, you may want to do the following things to fix this problem
- first add the `-DDEBUG_INFO` to `CXXFLAGS` in Makefile and compile again.
- then run `./tracer` 
- after `tracer` run into an error, you can check `{tmp_data_dir}/machine_code.txt`'s last few lines
