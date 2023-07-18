# What is this

9aout runs unmodified Plan 9 binaries in Linux userspace using [Syscall User Dispatch](https://docs.kernel.org/admin-guide/syscall-user-dispatch.html) to translate Plan 9 syscalls into Linux syscalls (just as [WSL 1](https://en.wikipedia.org/wiki/Windows_Subsystem_for_Linux#WSL_1) does).

# Requirements

Linux 5.11+ on amd64, because SUD seems ([correct me](https://github.com/forked-from-1kasper/9aout/issues) if I’m wrong) to be unsupported on everything else & GNU Make & GCC

# Installation

```sh
$ make
$ ./9aout example/hello
Hello, World!
```

or

```sh
$ make DEBUG=1
$ ./9aout example/hello
(10000) PWRITE fd = 1 buf = 0x7ffc00000000 len = 14 offset = -1
Hello, World!
(10000) exits: main
```

`scripts/install-binfmt.sh` installs `9aout` binary in `binfmt_misc`, so Plan 9 binaries can be run directly (i.e. `./example/hello` instead of `./9aout example/hello`).

`scripts/uninstall-binfmt.sh` reverts everything.

# See also

* [Plan 9 binary format description](http://man.9front.org/6/a.out) from 9front manuals.

* [Glendix](https://www.glendix.org/) ([GitHub](https://github.com/anantn/glendix)): (very) outdated project doing the same thing but using kernel driver instead. Still can be built in, for example, (probably chroot’ed) Debian Trusty.

* [9vx](https://github.com/9fans/vx32/tree/main/src/9vx): lightweight (32-bit) Plan 9 VM.

* [plan9port](https://github.com/9fans/plan9port): port of Plan 9 libraries and utilities to Unix (more like [Cygwin](https://www.cygwin.com/)).

* [Limbo](https://github.com/meme/limbo): abandoned (?) XNU emulator using SUD.