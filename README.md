# small-io-sys: the world's smallest Windows 98 SE io.sys

small-io-sys is a binary patched release of the Windows 98 SE (MS-DOS 7.1)
16-bit kernel file io.sys, aiming to be the smallest in terms of byte size,
at the expense of a few milliseconds of additional waiting for the
decompression at boot time. For completeness and speed measurements,
uncompressed variants are also supplied.

**TL;DR Where are the download links?** There are no direct download links.
To get the io.sys file variants listed below, you have to follow the build
instructions in this document. It takes less than a minute if you already
have Linux running.

Byte sizes:

* 222670 bytes, original Windows 98 SE io.sys released by Microsoft in [KB311561](https://web.archive.org/web/20070510143604/http://support.microsoft.com/kb/311561) ([backup link](https://www.betaarchive.com/wiki/index.php?title=Microsoft_KB_Archive/311561)): *winboot.98s*
* 138477 bytes, [w3xstart](https://web.archive.org/web/20240918013509/https://msfn.org/board/topic/97945-windows-311-and-ms-dos-71/#findComment-964141) patch applied, recompressed: *IO.SYS.win98sekbumc*
* 128365 bytes, [w3xstart](https://web.archive.org/web/20240918013509/https://msfn.org/board/topic/97945-windows-311-and-ms-dos-71/#findComment-964141) patch applied, recompressed with LZMA: *IO.SYS.win98sekbuml*
* 72617 bytes, without the logo and MSDCM, [w3xstart](https://web.archive.org/web/20240918013509/https://msfn.org/board/topic/97945-windows-311-and-ms-dos-71/#findComment-964141) patch applied, recompressed: *IO.SYS.win98sekbpc*
* 68270 bytes, without the logo and MSDCM, [w3xstart](https://web.archive.org/web/20240918013509/https://msfn.org/board/topic/97945-windows-311-and-ms-dos-71/#findComment-964141) patch applied, recompressed with LZMA and custom decompressor: *IO.SYS.win98sekbplx*

How to use: build it, then overwrite io.sys with the just-built smaller
alternative on your boot floppies (both physical hardware and floppy disk
image) or Windows 98 SE systems installed to your HDD partitions (both bare
metal and disk image for emulators). If you don't have a Windows 98 system
installed, but still want to try small-io-sys quickly, then boot the built
floppy disk image *fd.img* in QEMU (see instructions as part of the build
instructions).

See also docs about the [structure of MS-DOS v7 (and Windows ME)
io.sys](https://retrocomputing.stackexchange.com/a/15598), incuding the
details on what MSDCM does.

## How to build it

There are no prebuilt binaries. To get a working io.sys, you have to build
everything from sources and originals. The original file is the [winboot.98s
file within
KB311561](https://web.archive.org/web/20020204073516/http://download.microsoft.com/download/win98/patch/22527/w98/en-us/311561usa8.exe)
(downloaded automatically if needed as part of the build). Everything else
(source files and build tools) is part of the small-io-sys Git repository.

To build it, you need a Linux i386 or amd64 system. (In the future, a build
system could be provided for native Win32 as well.) Emulation (such as WSL2)
and containers (such as Docker) also work fine. The build process works on
any Linux distribution, because the build tool programs are provided as
statically linked Linux i386 executables.

To build small-io-sys, clone the Git repository and run compile.sh. More
specifically, run these commands in a Linux i368 or amd64 terminal
(command-line) window (each line without the leading `$`):

```
$ git clone https://github.com/pts/small-io-sys
$ cd small-io-sys
$ ./compile.sh
```

This will download *winboot.98s*, and generate the other files (such as
*IO.SYS.win98sekbumc* and *IO.SYS.win98sekbpc*, see above). For the boot
in QEMU, it also downloads a copy of Windows 98 SE *command.com*, and adds
it to the floppy disk image.

An alterative way of running *compile.sh* is `tools/busybox sh compile.sh`.

For your convenience, the build process (*compile.sh*) will generate a
bootable floppy disk image, which you can try in QEMU (*qemu-system-i386*).
*compile.sh* prints the exact command to run to start QEMU. Within the black
QEMU window, the *Starting Windows 98...* message appears, and then the
*A:\\>* prompt appears. If you don't know which command to run, try `ver`
and then `dir /a`.

## Techniques used to reduce the file size of io.sys

* The msload part of io.sys (the first 2048 bytes) have been rewritten from
  scratch in 8086 assembly. The new size is only 832 bytes.
* The kernel (msbio.bin, msdos.bin) code and data have been compressed
  using aPACK 1.00 and UPX 3.94, and the shorter output has been chosen.
* The compressed boot logo has been decompressed and recompressed together
  in the same batch as (i.e. concatenated to) the kernel code and data.
* The LZMA algorithm and file format supported by UPX 3.94
  has also been used for compressing the kernel code and data and the boot
  logo. The output of this is smaller, but it takes longer to decompress at
  boot time (0.5 to 1 seconds extra in an emulator). *compile.sh* generates
  io.sys output files both with LZMA compression (small output, slow to
  decompress, compressed by UPX) and LZSS compression (larger output, very
  fast to decompress, compressed by aPACK and UPX, and the smaller is
  chosen).
* MSDCM code and data have been decompressed and recompressed. using aPACK
  1.00 and UPX 3.94 16-bit DOS .exe compression. Again, the shorter
  output (aPACK) has been chosen.
* The boot logo and MSDCM have been removed from some binaries.
  * It's possible, but less entertaining to boot the Windows GUI even
    without this boot logo. Also an external *logo.sys* can be used to
    restore this functionality.)
  * It's possible to boot the Windows GUI even without MSDCM in most
    installations, i.e. those which don't use multiple hardware profiles.
* Originally unused code, newly unused support code (such as the
  decompressor for the compressed boot logo) and newly unused message
  strings have been overwritten with NULs to make subsequent compression
  more efficient.
* Before compressing io.sys, a compression-enhancing filter has been applied.
  Various UPX filters (0x01--0x06, 0x46, 0x49) have been tried, and the
  smallest has been chosen. The winner is filter 0x06, which converts 16-bit
  near jump and near call instructions from relative to absolute address,
  and from little-endian to big-endian.

  Please note that the *upx* command-line tool doesn't even allow filter
  0x06 for 8086 (16-bit) code longer than 64 KiB, so the filter had to be
  applied manually before running UPX.
* LZMA compression settings (e.g. preset, pb, lc, mf, nice) have been
  manually tuned for this input, producing the smallest possible size using
  `xz --format=lzma -9e --lzma1=...`.
* The decompressor code has been rewritten in assembly and optimized for
  size. For example, in *IO.SYS.win98sekbplx*:
  * The decompressor mode switches to i386 protected mode for the duration
    of the decompression, because the i386 LZMA decompress function is
    shorter than the 8086 one.
  * The LZMA decompress function (C source found in UPX 3.94) has been
    recompiled with multiple C compilers and settings, and the smallest has
    been chosen. The winner is a recent *wcc386* in OpenWatcom (2023-03-04)
    with size-optimization flags.
  * The compiled LZMA decompress function has been compressed with various
    simpler methods (such as all NRV methods in UPX 3.94, the aPACK 1.00
    methods, WDOSX-PACK, LZO1X-999 used by SYSLINUX 4.07 and the WWPACK
    method), and the shortest (both C compiler and compression method) has
    been chosen. The winner is NRV2B\_8 in UPX 3.94.
  * The compressed output of NRV2B\_8 has been truncated: 5 bytes at the
    end are not needed to decompress it correctly.
  * A size-optimized i386 (32-bit protected mode) decompress function has
    been written for the NRV2B\_8 method: it's only 82 bytes. (The original
    in UPX is 143 bytes.) Similarly, a size-optimized i386 unfilter function
    has been written for filter 0x06: it's only 23 bytes.
  * The UPX filters have been tried for the compiled LZMA decompress
    function, but it looks like it doesn't benefit from these filters if
    we also add the size of the unfilter code.
  * The i386 setup code (which copies data around, sets up registers, calls
    the decompress function and calls the unfilter function) has been
    written and optimized for code size.

## Build tools used

Most of the additional code is written in i386 assembly language, NASM
dialect, and the rest are short Perl scripts. The build is automated in
shell scripts, BusyBox syntax. The following build tools are used (they are in
the [tools/](tools/) directory):

* [NASM](https://nasm.us/) 0.98.39: Netwide Assember for building the msload
  binary, patching and cutting io.sys, building the floppy boot sector code,
  and generating the floppy disk image.
* [cabextract](https://www.cabextract.org.uk/): for extracting and
  decompressing *winboot.98s* from the downloaded KB311561 *311561usa8.exe*.
* [unEXPACK](https://github.com/w4kfu/unEXEPACK): for decompressing the
  MSDCM part of io.sys
* [aPACK](https://web.archive.org/web/20240424165219/https://ibsensoftware.com/products_aPACK.html)
  ([apack1p](https://github.com/pts/apack1p)) 1.00: for compressing
  code and data (global variables, logo and MSDCM).
* [UPX](https://upx.github.io/) 3.94: for compressing code and data (global
  variables and logo) with the LZMA algorithm and format. Also used for
  regular (LZSS) compression, and its output is chosen if shorter than than
  the output of aPACK. UPX 3.91 also works identically, but it's not
  self-contained: there hasn't been a statically linked Linux i386 release,
  and when rebuilt from source it produces different output.
* [Perl](https://www.perl.org/) 5.004\_04: for running data transformation
  script for which shell is too slow and AWK doesn't work (i.e. binary input
  and output), for example decompressing the boot logo (splash screen)
  embedded in *winboot.98s*.
* [BusyBox](https://www.busybox.net/): for running shell scripts and doing
  some data processing (such as *sha256sum*).
* [Mtools](https://www.gnu.org/software/mtools/) 4.0.18: for copying files
  to/from FAT disk images (e.g. copying *io.sys* and *command.com* to the
  bootable floppy disk image).

Copies of these build tool programs precompiled for Linux i386 (also runs on
amd64) are provided in the small-io-sys Git repostory, there is no need to
install anything manually.
