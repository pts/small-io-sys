# small-io-sys: the world's smallest Windows 98 SE io.sys

small-io-sys is a binary patched release of the Windows 98 SE (MS-DOS 7.1)
16-bit kernel file io.sys, aiming to be the smallest in terms of byte size,
at the expense of a few milliseconds of additional waiting for the
decompression at boot time. For completeness and speed measurements,
uncompressed variants are also supplied.

Byte sizes:

* 222670 bytes, original Windows 98 SE io.sys released by Microsoft in [KB311561](https://www.betaarchive.com/wiki/index.php?title=Microsoft_KB_Archive/311561): *winboot.98s*
* 138477 bytes, [w3xstart](https://web.archive.org/web/20240918013509/https://msfn.org/board/topic/97945-windows-311-and-ms-dos-71/#findComment-964141) patch applied, recompressed: *IO.SYS.win98sekbumc*
* 128365 bytes, [w3xstart](https://web.archive.org/web/20240918013509/https://msfn.org/board/topic/97945-windows-311-and-ms-dos-71/#findComment-964141) patch applied, recompressed with LZMA: *IO.SYS.win98sekbuml*
* 72617 bytes, without the logo and MSDCM, [w3xstart](https://web.archive.org/web/20240918013509/https://msfn.org/board/topic/97945-windows-311-and-ms-dos-71/#findComment-964141) patch applied, recompressed: *IO.SYS.win98sekbpc*
* 70396 bytes, without the logo and MSDCM, [w3xstart](https://web.archive.org/web/20240918013509/https://msfn.org/board/topic/97945-windows-311-and-ms-dos-71/#findComment-964141) patch applied, recompressed with LZMA: *IO.SYS.win98sekbpl*

How to use: build it, then overwrite io.sys with the just-built smaller
alternative on your boot floppies (bothe bare metal and floppy disk image)
or Windows 98 SE systems installed to your HDD partitions (both bare metal
and disk image for emulators). If you don't have it installed, but still
want to try small-io-sys quickly, then boot the built floppy disk image
*fd.img* in QEMU (see instructions as part of the build instrunctions).

See also docs about the [structure of MS-DOS v7 (and Windows ME)
io.sys](https://retrocomputing.stackexchange.com/a/15598), incuding the
details on what MSDCM does.

## How to build it

There are no prebuilt binaries. To get a working io.sys, you have to build
everything from source. Part of source is the [winboot.98s file within
KB311561](https://web.archive.org/web/20020204073516/http://download.microsoft.com/download/win98/patch/22527/w98/en-us/311561usa8.exe)
(downloaded automatically if needed as part of the build), all other sources
are files and the build tools are part of the small-io-sys Git repository.

To build from source (except for winboot.98s, from which binary code and
data is extracted and reused), you need a Linux i386 or amd64 system. (In
the future, maybe a build system will be provided for Win32 as well.)
Emulation (such as WSL2) and containers (such as Docker) also work fine. The
Linux distribution doesn't matter, because the build tool programs are
provided as statically linked Linux i386 executables.

To build small-io-sys, clone the Git repository and run compile.sh. More
specifically, run these commands in a Linux i368 or amd64 terminal
(command-line) window (each line without the leading `$`):

```
$ git clone https://github.com/pts/small-io-sys
$ cd small-io-sys
$ ./compile.sh
```

This will download *winboot.98s*, and generate the other files (such as
*IO.SYS.win98sekbumc* and *IO.SYS.win98sekbpc*). For the boot
in QEMU, it also downloads a copy of Windows 98 SE *command.com*, and adds
it to the floppy disk image.

An alterative way of running *compile.sh* is `tools/busybox sh compile.sh`.

For your convenience, the build process (*compile.sh*) will generate a
bootable floppy disk image, which you can try in QEMU (*qemu-system-i386*).
*compile.sh* prints the exact command to run to start QEMU. Within the black
QEMU window, the *Starting Windows 98...* message appears, and then the
*C:\\>* prompt appears. If you don't know which command to run, try `ver`
and then `dir /a`.

## Techniques used to reduce the file size of io.sys

* The msload part of io.sys (first 2048 bytes) have been rewritten from
  scratch in 8086 assembly. The new size is only 832 bytes.
* The kernel (msbio.bin, msdos.bin) code and data have been compressed
  using aPACK 1.00.
* The compressed boot logo has been decompressed and recompressed using
  aPACK 1.00. The kernel code and data and the boot logo have been
  concatenated, and compressed together.
* MSDCM code and data have been decompressed and recompressed. using aPACK
  1.00 16-bit DOS .exe compression.
* The boot logo and MSDCM have been removed from some binaries.
  * It's possible, but less entertaining to boot the Windows GUI even
    without this boot logo. Also an external *logo.sys* can be used to
    restore this functionality.)
  * It's possible to boot the Windows GUI even without MSDCM in most
    installations, i.e. those which don't use multiple hardware profiles.
* Unused code, now-unused support code (such as the decompressor for the
  compressed boot logo) and now-unused message strings have been overwritten
  with NULs to make subsequent compression more efficient.

## Build tools used

Most of the additional code is written in i386 assembly language, NASM
dialect, and the rest are short Perl scripts. The build is automated in
shell scripts, BusyBox syntax. These build tools are used (part of the
[tools/](tools/) directory:

* [NASM](https://nasm.us/) 0.98.39: Netwide Assember for building the msload
  binary, patching and cutting io.sys, building the floppy boot sector code,
  generating the floppy disk image.
* [cabextract](https://www.cabextract.org.uk/): for extracting and
  decompressing *winboot.98s* from the downloaded KB311561 *311561usa8.exe*.
* [unEXPACK](https://github.com/w4kfu/unEXEPACK): for decompressing the
  MSDCM part of io.sys
* [aPACK](https://web.archive.org/web/20240424165219/https://ibsensoftware.com/products_aPACK.html)
  ([apack1p](https://github.com/pts/apack1p)) 1.00: for compressing
  code and data (global variables, logo and MSDCM).
* [UPX](https://upx.github.io/) 3.91: for compressing code and data (global
  variables and logo) with the LZMA algorithm and format.
* [Perl](https://www.perl.org/) 5.004\_04: for running data transformation
  script for which shell is too slow and AWK doesn't work (i.e. binary input
  and output), for example decompressing the boot logo (splash screen)
  embedded in *winboot.98s*.
* [BusyBox](https://www.busybox.net/): for running shell scripts and doing
  some data processing (such as *sha256sum*).
* [Mtools](https://www.gnu.org/software/mtools/): for copying files to/from
  FAT disk images (e.g. copying *io.sys* and *command.com* to the bootable
  floppy disk image).

Copies of these build tool programs precompiled for Linux i386 (also runs on
amd64) are provided in the small-io-sys Git repostory, there is no need to
install anything manually.
