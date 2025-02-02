#! /bin/sh --
#
# compile.sh: compile script for patchio98se
# by pts@fazekas.hu at Wed Jan 29 16:13:54 CET 2025
#
# Run it on Linux i386 or amd64: tools/busybox sh compile.sh
#

test "$0" = "${0%/*}" || cd "${0%/*}"
export LC_ALL=C  # For deterministic output. Typically not needed. Is it too late for Perl?
export TZ=GMT  # For deterministic output. Typically not needed. Perl respects it immediately.
if test "$1" != --sh-script; then export OPATH="$PATH" export PATH=/dev/null/missing; exec tools/busybox sh "${0##*/}" --sh-script "$@"; exit 1; fi
shift
test "$ZSH_VERSION" && set -y 2>/dev/null  # SH_WORD_SPLIT for zsh(1). It's an invalid option in bash(1), and it's harmful (prevents echo) in ash(1).
set -ex

cabextract=tools/cabextract-1.11.upx
perl=tools/miniperl-5.004.04.upx
nasm=tools/nasm-0.98.39.upx
mtools=tools/mtools-4.0.18.upx
apack1p=tools/apack1p-1.00.upx
upx=tools/upx-3.91.upx
unexepack=tools/pts-unexepack-v1.upx

# Downloads:
#
# * https://web.archive.org/web/20221002040438/https://www.allbootdisks.com/disk_files/Win98se/IO.SYS  (old, unpatched)
# * https://web.archive.org/web/20250129012842/https://www.allbootdisks.com/disk_files/Win98se/COMMAND.COM
# * https://web.archive.org/web/20020204073516/http://download.microsoft.com/download/win98/patch/22527/w98/en-us/311561usa8.exe  (contains the patched io.sys of KB311561)
if test -f winboot.98s && test -f command.com; then  # !! Add an option to omit command.com.
  :
else
  # Try to find the non-BusyBox wget(1) on PATH.
  wget="$(set +ex; IFS=: ; for dir in ${OPATH:-$PATH}; do p="$dir/wget" && test -f "$p" && test -x "$p" && printf '%s' "$p" && break; done; :)"
  wget_flags="-nv -O"
  if test -z "$wget"; then  # If wget(1) not found, try curl(1).
    wget="$(set +ex; IFS=: ; for dir in ${OPATH:-$PATH}; do p="$dir/curl" && test -f "$p" && test -x "$p" && printf '%s' "$p" && break; done; :)"
    wget_flags=-sSLfo
  fi
  if ! test -f winboot.98s; then
    if ! test -f 311561usa8.exe; then
      "$wget" $wget_flags 311561usa8.exe.tmp https://web.archive.org/web/20020204073516/http://download.microsoft.com/download/win98/patch/22527/w98/en-us/311561usa8.exe
      test "$(sha256sum 311561usa8.exe.tmp)" = "569ecb4fe36a7c00bf7f6d353467d8f95e4708fb8809d3e456760a8ef42be6fc  311561usa8.exe.tmp"
      mv -f 311561usa8.exe.tmp 311561usa8.exe
    fi
    test "$(sha256sum 311561usa8.exe)" = "569ecb4fe36a7c00bf7f6d353467d8f95e4708fb8809d3e456760a8ef42be6fc  311561usa8.exe"
    # echo "incbin '311561usa8.exe', 67224, 222099" >tc.nasm   # No need for this, cabextract works directly on 311561usa8.exe
    # nasm-0.98.39 -O0 -w+orphan-labels -f bin -o tc.cab tc.nasm  # Input file: 311561usa8.exe
    "$cabextract" -q -F winboot.98s 311561usa8.exe
    test "$(sha256sum winboot.98s)" = "d34436a7ce911ed39549fce6107f3b55ad5d413565ebabc1398e13f2df103271  winboot.98s"
  fi
  if ! test -f command.com; then
    "$wget" $wget_flags command.com.tmp https://web.archive.org/web/20250129012842/https://www.allbootdisks.com/disk_files/Win98se/COMMAND.COM
    test "$(sha256sum command.com.tmp)" = "c3b5899620d6c58b90727b640bb7bb6a723f6013629c9459c241e9dc9e7ff20b  command.com.tmp"
    mv -f command.com.tmp command.com
  fi
fi

test "$(sha256sum winboot.98s)" = "d34436a7ce911ed39549fce6107f3b55ad5d413565ebabc1398e13f2df103271  winboot.98s"
test "$(sha256sum command.com)" = "c3b5899620d6c58b90727b640bb7bb6a723f6013629c9459c241e9dc9e7ff20b  command.com"

"$nasm" -O0 -w+orphan-labels -f bin -o fd.img -DP_1440K fat12b.nasm

"$perl" -x logod.pl --fofs=0x1e010 winboot.98s IO.SYS.win98sekb.bmp
"$unexepack" -q winboot.98s IO.SYS.win98sekb.msdcm

"$apack1p" -q -3 -h IO.SYS.win98sekb.msdcm IO.SYS.win98sekb.msdcmc  # !! Automatically try both --apack1p and --upx here, find the better one.

"$nasm" -DNOPATCH -O0 -w+orphan-labels -f bin -DNOPATCH -o IO.SYS.win98sekb patchio98se.nasm
cmp winboot.98s IO.SYS.win98sekb

#"$nasm" -O0 -w+orphan-labels -f bin -DMSLOAD_SECTOR_COUNT=4 -DJUST_MSLOAD -o msloadv7is4.bin msloadv7i.nasm
#"$nasm" -O0 -w+orphan-labels -f bin -DMSLOAD_SECTOR_COUNT=2 -DJUST_MSLOAD -o msloadv7is2.bin msloadv7i.nasm
"$nasm" -O0 -w+orphan-labels -f bin -DMSLOAD_SECTOR_COUNT=0 -DJUST_MSLOAD -o msloadv7is0.bin msloadv7i.nasm

#"$nasm" -O0 -w+orphan-labels -f bin -DMSLOAD_SECTOR_COUNT=4 -o IO.SYS.win98sekb4 patchio98se.nasm  # Uses msloadv7s4.bin.
#"$nasm" -O0 -w+orphan-labels -f bin -DMSLOAD_SECTOR_COUNT=2 -o IO.SYS.win98sekb2 patchio98se.nasm  # Uses msloadv7s2.bin.
"$nasm" -O0 -w+orphan-labels -f bin -DMSLOAD_SECTOR_COUNT=0 -o IO.SYS.win98sekb0 patchio98se.nasm  # Uses msloadv7s0.bin.
"$nasm" -O0 -w+orphan-labels -f bin -DMSLOAD_SECTOR_COUNT=0 -DOPTIMIZE_FOR_COMPRESSION -o IO.SYS.win98sekbp patchio98se.nasm  # Uses msloadv7s0.bin.
"$perl" -x fixmsdcm.pl IO.SYS.win98sekbp  # No need for fixing, this just does some checks.
"$perl" -x io7pack.pl --apack1p="$apack1p" --ignores-logo IO.SYS.win98sekbp IO.SYS.win98sekbpc  # !! Automatically try both --apack1p and --upx here, find the better one. --apack1p wins here.
"$perl" -x io7pack.pl --upx-lzma="$upx"    --ignores-logo IO.SYS.win98sekbp IO.SYS.win98sekbpl

"$nasm" -O0 -w+orphan-labels -f bin -DMSLOAD_SECTOR_COUNT=0 -o IO.SYS.win98sekbu ucio98se.nasm  # Uses msloadv7s0.bin.
"$nasm" -O0 -w+orphan-labels -f bin -DMSLOAD_SECTOR_COUNT=0 -DOPTIMIZE_FOR_COMPRESSION -o IO.SYS.win98sekbuu ucio98se.nasm  # Uses msloadv7s40bin.
"$perl" -x fixmsdcm.pl IO.SYS.win98sekbuu  # No need for fixing, this just does some checks.
"$perl" -x io7pack.pl --upx="$upx"      IO.SYS.win98sekbuu IO.SYS.win98sekbuc  # !! Automatically try both --apack1p and --upx here, find the better one. --upx wins here.
"$perl" -x io7pack.pl --upx-lzma="$upx" IO.SYS.win98sekbuu IO.SYS.win98sekbul

"$nasm" -O0 -w+orphan-labels -f bin -DMSLOAD_SECTOR_COUNT=0 -DMSDCM -o IO.SYS.win98sekbum ucio98se.nasm  # Uses msloadv7s4.bin.
"$perl" -x fixmsdcm.pl IO.SYS.win98sekbum
"$nasm" -O0 -w+orphan-labels -f bin -DMSLOAD_SECTOR_COUNT=0 -DMSDCM -DOPTIMIZE_FOR_COMPRESSION -o IO.SYS.win98sekbumu ucio98se.nasm  # Uses msloadv7s0.bin.
"$perl" -x fixmsdcm.pl IO.SYS.win98sekbumu  # !! TODO(pts): Combine this with io7pack.pl, to make .minalloc smaller.
"$perl" -x io7pack.pl --upx="$upx"       IO.SYS.win98sekbumu IO.SYS.win98sekbumc  # !! Automatically try both --apack1p and --upx here, find the better one. --upx wins here.
"$perl" -x io7pack.pl --upx-lzma="$upx"  IO.SYS.win98sekbumu IO.SYS.win98sekbuml

# ---

#"$mtools" -c mcopy -bsomp -i fd.img winboot.98s ::IO.SYS
"$mtools" -c mcopy -bsomp -i fd.img IO.SYS.win98sekbpc ::IO.SYS
"$mtools" -c mattrib -i fd.img +s ::IO.SYS
"$mtools" -c mcopy -bsomp -i fd.img command.com ::COMMAND.COM

: qemu-system-i386 -M pc-1.0 -m 2 -nodefaults -vga cirrus -drive file=fd.img,format=raw,if=floppy -boot a

: "$0" OK.
