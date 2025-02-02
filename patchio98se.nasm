;
; patchio98se.nasm: patch Windows 98 SE io.sys
; by pts@fazekas.hu at Sat Jan 18 13:37:13 CET 2025
;
; Compile with: nasm -O0 -w+orphan-labels -f bin -o IO.SYS.win98sekbp patchio98se.nasm
; To get back the original io.sys, compile with: nasm -DNOPATCH -O0 -w+orphan-labels -f bin -o IO.SYS.win98sekb patchio98se.nasm
; Minimum NASM version required to compile: 0.98.39
;
; Feature changes:
;
; * Embedded logo (splash screen) removed.
; * Embedded MSDCM (device configuration manager) removed.
; * Error message about MSDCM missing removed. !! Release a separate patch which has this.
; * Applied the Windows 3.x setup patch.
;
; Size optimizations:
;
; * Removed attempts to run MSDCM.
; * Removed the use of the embedded logo. !! Extract it and provide logo.sys.
; * Removed logo decompressor. (This made the compressed io.sys smaller.)
; * Removed MSDCM caller. (This made the compressed io.sys smaller.)
; * Removed strange_change_io_sys and 2 functions used by it. (This made the compressed io.sys smaller.)
; * Replaced the two long run of MPADs with NULs. (This made the compressed io.sys smaller.)
; * Compressed the file after msload with APACK 1.00 (io7pack.pl).
; * Added use of shorter msload (832 bytes instead of 2048 bytes).
;
; Size (in bytes) after each step:
;
; * 222670: original KB118579 Windows 98 SE io.sys, MS-DOS 7.1 (winboot.98s)
; * 189440: without MSDCM (this removes some rarely needed functionality)
; * 122880: without the compressed logo (this makes the boot process more boring unless logo.sys is added)
; * 121664: with the shorter msload
; * 72880: compressed with APACK 1.00 (iopack7.pl)
; * 72617: some unused code and data replaced with runs of a single byte
;
; Docs about the structure of MS-DOS v7 (and Windows ME) io.sys: https://retrocomputing.stackexchange.com/a/15598
;
; msdos.sys:
;
; * docs: https://www.computerhope.com/msdossys.htm
; * docs: https://www.betaarchive.com/wiki/index.php/Microsoft_KB_Archive/118579
; * `[Paths]`: HostWinBootDrv=, UninstallDir=, WinBootDir=, WinDir=
; * `[Options]`:
;   * Not all of the booleans have an OPTVAL_.
;   * AutoScan=number: 0, 1 or 2.
;   * BootDelay=seconds: Windows 98 ignores it, it uses the <Ctrl> key pressed state instead.
;   * BootMenuDelay=number
;   * BootMenuDefault=number
;   * BootSafe=: <<??. (db 1, 0x20, 0x4c)
;   * BootGUI=: <<5.
;   * BootKeys=: <<3.
;   * BootMenu=: <<??. (db 1, 0x1c, 0x4c).
;   * BootMulti=: <<7.
;   * BootWarn=: <<8.
;   * BootWin=: <<4.
;   * DoubleBuffer=: <<??. (db 1, 0xa5, 0xad).
;   * DBLSpace=: <<1.
;   * DRVSpace=: <<2.
;   * LoadTop=: <<6.
;   * Logo=: <<0.
;   * Network=: <<??. (db 1, 0x21, 0x4c).
;   * SystemReg=: <<9. Must be set to 0 if no skio-msdcm or pretend-success-msdcm patch applied, and MSDCM is not present in io.sys.
;   * WinVer=: <<?? (db 0, 0xd0, 0x64).
;   * DisableLog=: <<?? (db 0, 0xd6, 0x64). '\BOOTLOG.TXT'.
;
; Recommended msdos.sys and config.sys for Windows 98 SE: https://www.deinmeister.de/dosconf_e.htm
;
; If config.sys contains dos=noauto, then io.sys won't load himem.sys, aspi2dos.sys, aspi2hlp.sys, dblbuff.sys, ifshlp.sys and setver.exe.
;
; Coparison of DOS kernels: Windows 98 SE, Windows ME, FreeDOS: https://flaterco.com/kb/DOS-kernels.html
;
; Docs about logo.sys (uncompresed) file format: https://www.daubnet.com/en/file-format-sys
;
; More docs about logo.sys and it is loaded and can be controlled: http://retro.timb.us/Documents/Software/DOS-LOGO.html
;
; logo.sys can be extracted from io.sys using https://github.com/pierce-smith1/io7 .
; Extract: `dd if=winboot.98s bs=16 skip=7681 count=4159 of=winboot.io7`
; Run it with: `deno --allow-read --allow-write io7.ts`.
;

%ifndef MSLOAD_SECTOR_COUNT  ; Can be 0, 2 or 4. 4 for compatibility.
  %define MSLOAD_SECTOR_COUNT 0
%endif
%ifndef NOPATCH
%else
  %define MSLOAD_SECTOR_COUNT 4  ; Override other settings with -DNOPATCH.
%endif

%if MSLOAD_SECTOR_COUNT==0
  %define MSLOAD_PARA_SIZE 0x34
%else
  %assign MSLOAD_PARA_SIZE (MSLOAD_SECTOR_COUNT)<<5
%endif
%undef MSLOAD_SECTOR_COUNT

OBASE: equ $$+((MSLOAD_PARA_SIZE-0x80)<<4)

; All option values must be 0 or 1.
OPTVAL_DisableLog equ 0
OPTVAL_Logo equ 1  ; <<0.
OPTVAL_DBLSpace equ 1  ; <<1.
OPTVAL_DRVSpace equ 1  ; <<2.
OPTVAL_BootKeys equ 1  ; <<3.
OPTVAL_BootWin equ 1  ; <<4.
OPTVAL_BootGUI equ 1  ; <<5.
OPTVAL_LoadTop equ 1  ; <<6.
OPTVAL_BootMulti equ 0  ; <<7.
OPTVAL_BootWarn equ 1  ; <<8.
OPTVAL_SystemReg equ 1  ; <<9. Must be set to 0 if MSDCM is not present without the 

bits 16
cpu 386  ; Some instructions don't work with `cpu 386'.

%macro assert_hfofs 1
  times +(%1)-($-$$) times 0 nop
  times -(%1)+($-$$) times 0 nop
%endm

%macro assert_fofs 1
  times +(%1)-($-OBASE) times 0 nop
  times -(%1)+($-OBASE) times 0 nop
%endm

; A patched IO.SYS by Microsoft KB311561, downloaded From here:
;
; * https://www.betaarchive.com/wiki/index.php?title=Microsoft_KB_Archive/311561
; * http://download.microsoft.com/download/win98/patch/22527/w98/en-us/311561usa8.exe
; * `7z x 311561usa8.exe`
; * The contained winboot.98g and winboot.98s files are identical, timestamps  in the .exe are local times:
;   ```
;   $ ls -ld --full-time winboot.98[gs]
;   -rw-rw-r-- 1 pts pts 222670 2001-11-30 15:31:16.000000000 +0100 winboot.98g
;   -rw-rw-r-- 1 pts pts 222670 2001-12-01 09:37:12.000000000 +0100 winboot.98s
;   ```
; * `sha256sum winboot.98s`: d34436a7ce911ed39549fce6107f3b55ad5d413565ebabc1398e13f2df103271  winboot.98s
%define ORIG_IO_FN 'winboot.98s'

%macro incbin_until_fofs 1
  %if (%1)<($-OBASE)
    times +(%1)-($-OBASE) times 0 nop  ; Make it eventually fail if we are already past %1.
  %endif
  incbin ORIG_IO_FN, $-OBASE, (%1)-($-OBASE)
  assert_fofs %1
%endm

%macro patch 3  ; %1: db, dw or dd; %2: old value; %3: new value
  %ifndef NOPATCH
    %1 %3
  %else
    %1 %2
  %endif
%endm

%macro patch_fofs 4  ; %1: byte offset; %2: db, dw or dd; %3: old value; %4: new value
  ; Convert `cmp -l' output: cmp -l a b | perl -ne 'my @L = split(" ", $_); printf "patchb_fofs 0x%x, 0x%x, 0x%x\n", $L[0]-1, oct($L[1]), oct($L[2])'
  incbin_until_fofs %1
  patch %2, %3, %4
%endm

%macro patch_fofs_ab1 3  ; %1: start byte offset; %2: end byte offset; %3: single-byte-instruction (e.g. nop).
  incbin_until_fofs %1
  %ifndef NOPATCH
    times (%2)-(%1) %3
  %else
    incbin_until_fofs %2
  %endif
%endm

%macro patch_fofs_abdw 3  ; %1: start byte offset; %2: end byte offset; %3: word value.
  incbin_until_fofs %1
  %ifndef NOPATCH
    times ((%2)-(%1))>>1 dw %3
    times ((%1)-(%2))&1 db (%3)&0xff
  %else
    incbin_until_fofs %2
  %endif
%endm

%macro patch_fofs_ab_cli_hlt 2  ; %1: start byte offset; %2: end byte offset.
  %ifdef OPTIMIZE_FOR_COMPRESSION
    patch_fofs_ab1 %1, %2, db 0
  %else
    patch_fofs_abdw %1, %2, 0xf4fa  ; cli ++ hlt.
  %endif
%endm

mz_header:
.signature:	db 'MZ'  ; Magic bytes checked by the boot sector code.
.lastsize:      patch dw, 0x1ce, 0 ; dw (end-.signature) & 0x1ff  ; The value 0 and 0x200 are equivalent here. Microsoft Linker 3.05 generates 0, so do we. Number of bytes in the last 0x200-byte block in the .exe file.
.nblocks:       patch dw, 0x1b3, 0 ; dw (end-.signature +0x1ff)>> 9  ; Number of 0x200-byte blocks in .exe file (rounded up).
.nreloc:	dw 0  ; No relocations. That's always true, even for MSDCM.
.hdrsize:	patch dw, 0x2e40, 0x1e00+MSLOAD_PARA_SIZE-0x80  ; dw (end-.signature)>>4  ; Used by msload to determine (at least) how many paragraphs of msbio to load, the count includes the msload in the beginning, even though it is not loaded.
.minalloc:	patch dw, 0x362, 0  ; 0x11
.maxalloc:	patch dw, -1, 0  ; -1
.ss:		patch dw, 0x838, 0  ; 0x6cf
.sp:		patch dw, 0x80, 0  ; 0x80
.checksum:	dw 0
.ip:		patch dw, 0x10, 0
.cs:		patch dw, 0x7f6, 0
%ifndef NOPATCH
assert_hfofs 0x18
%if MSLOAD_PARA_SIZE==0x34
		incbin 'msloadv7is0.bin', 0x18, (MSLOAD_PARA_SIZE<<4)-0x18
%elif MSLOAD_PARA_SIZE==0x40
		incbin 'msloadv7is2.bin', 0x18, (MSLOAD_PARA_SIZE<<4)-0x18
%elif MSLOAD_PARA_SIZE==0x80
		incbin 'msloadv7is4.bin', 0x18, (MSLOAD_PARA_SIZE<<4)-0x18  ; Code from original ORIG_IO_FN is fragile, and cannot load a truncated io.sys unless a magic smaller .hdsize value is specified.
%else
  %error UNSUPPORTED_MSLOAD_PARA_SIZE_VALUE  ; This still gets substituted in NASM 0.98.39: 'unsupported MSLOAD_PARA_SIZE value'.
%endif
%else
.relocpos:	dw 0x1e
.noverlay:	dw 0
assert_hfofs 0x1c
		incbin ORIG_IO_FN, $-$$, (MSLOAD_PARA_SIZE<<4)-($-$$)
		;incbin_until_fofs 0x800  ; Non-working alternative to the above. It fails for MSLOAD_PARA_SIZE!=0x80.
%endif
assert_hfofs MSLOAD_PARA_SIZE<<4
assert_fofs 0x800

%ifndef NOPATCH
%if 0  ; For debugging.
		incbin_until_fofs 0x10d7  ; INIT+4.
init: equ $-4
init4:		call .here  ; Save offset of .here.
.here:		pushf  ; Save.
		push dx ; Save.
		mov dx, 'ax'
		call print_kv
		mov dx, 'bx'
		mov ax, bx
		call print_kv
		mov dx, 'cx'
		mov ax, cx
		call print_kv
		mov dx, 'dx'
		pop ax  ; Restore DX to AX.
		call print_kv

		mov dx, 'si'
		mov ax, si
		call print_kv
		mov dx, 'di'
		mov ax, di
		call print_kv
		mov dx, 'bp'
		mov ax, bp
		call print_kv
		mov dx, 'fl'
		pop ax  ; Restore FLAGS to AX.
		call print_kv

		call print_crlf

		mov dx, 'cs'
		mov ax, cs
		call print_kv
		mov dx, 'ip'
		pop ax  ; Restore .here to AX.
		sub ax, strict word .here-init
		call print_kv

		mov dx, 'ds'
		mov ax, ds
		call print_kv

		mov dx, 'es'
		mov ax, es
		call print_kv

		mov dx, 'ss'
		mov ax, ss
		call print_kv

		mov dx, 'sp'
		mov ax, sp
		call print_kv

		call print_crlf

.dump_bpb:	push ss
		pop ds
		mov si, bp
		mov cx, 0x62
		mov al, ' '
		call print_1c
.again:		lodsb
		call print_al_hex
		loop .again
		call print_crlf

.poweroff:  ; ATX power managmenet power off. https://superuser.com/questions/1094409/how-do-i-auto-turn-off-a-dos-only-machine-using-software-the-pc-has-no-power-sw
		mov ax, 0x5301
		xor bx, bx
		int 0x15
		mov ax, 0x530e
		xor bx, bx
		mov cx, 0x0102
		int 0x15
		mov ax, 0x5307
		xor bx, bx
		inc bx
		mov cx, 0x0003
		int 0x15

.hlt:		cli
.hang:		hlt
		jmp short .hang	 ; In case the `hlt' didn't work.


print_crlf:  ; Prints CRLF to the QEMU debug console.
		push dx  ; Save.
		push ax  ; Save.
		mov dx, 0xe9  ; QEMU debug console (qemu-system-i386 -debugcon stdio) port.
		mov al, 13  ; CR.
		out dx, al
		mov al, 10  ; LF.
		out dx, al
		pop ax  ; Restore.
		pop dx  ; Restore.
		ret

print_1c:  ; Prints byte in AL to the QEMU debug console.
		push dx  ; Save.
		mov dx, 0xe9  ; QEMU debug console (qemu-system-i386 -debugcon stdio) port.
		out dx, al
		pop dx  ; Restore.
		ret

print_kv:  ; Prints DX with print_2cd, then prints AX with print_AX to the QEMU debug console.
		xchg ax, dx
		call print_2cd
		xchg ax, dx
		call print_ax_hex
		ret

print_2cd:  ; Prints space, byte in AL, byte in AH, colon to the QEMU debug console.
		push dx  ; Save.
		mov dx, 0xe9  ; QEMU debug console (qemu-system-i386 -debugcon stdio) port.
		push ax  ; Save.
		mov al, ' '
		out dx, al
		pop ax  ; Restore.
		out dx, al
		xchg al, ah
		out dx, al
		xchg al, ah
		push ax  ; Save.
		mov al, ':'
		out dx, al
		pop ax  ; Restore.
		pop dx  ; Restore.
		ret

print_ax_hex:  ; Prints word in AL as 4 hex digits to the QEMU debug console.
		xchg al, ah
		call print_al_hex
		xchg al, ah
		; Fall through.
print_al_hex:  ; Prints byte in AL as 2 hex digits to the QEMU debug console.
		push ax  ; Save.
		push dx  ; Save.
		mov dx, 0xe9  ; QEMU debug console (qemu-system-i386 -debugcon stdio) port.
		aam 0x10
		xchg al, ah
		call .print_nibble  ; Print high nibble.
		xchg al, ah
		call .print_nibble  ; Print low nibble.
		pop dx ; Restore.
		pop ax  ; Restore.
		ret
.print_nibble:	add al, '0'
		cmp al, '9'
		jna .adjusted
		add al, 'a'-'0'-10
.adjusted:	out dx, al
		ret
%endif
%endif

%if 1
; C;\logo.sys, if available, still works: wget https://archive.org/download/win95-logo.sys/logo.sys
patch_fofs 0x13ed, dw, 0x0e29, 0xa390  ; Force load_para_count to be 0, effectively ignoring the embedded compressed logo (splash screen). It also makes io.sys ignore the mz_header.hdrsize value after msload has completed.
%endif

		incbin_until_fofs 0x503d
disablelog:	db OPTVAL_DisableLog+(~OPTVAL_DisableLog&2)  ; 0 --> 2; 1 --> 1. Based on http://forum.ru-board.com/topic.cgi?forum=62&topic=31453&start=300#9

patch_fofs_ab1 0x54c2, 0x5702, db 0  ; Replace `times 0x90 db 'MPAD'` with NULs, for better compression.

		incbin_until_fofs 0x6e67
%ifndef NOPATCH
  %if 0  ; %ifdef OPTIMIZE_FOR_COMPRESSION  ; Works, but makes it larger.
		incbin_until_fofs 0x6e67+0xb
  %else
		mov ax, es
		dec ax
		mov es, ax
		mov byte [es:0], 0xcb  ; Restore the last byte of msdos_sys_payload, which was truncated by the patch below.
  %endif
%else
		incbin_until_fofs 0x6e67+0xb
%endif
assert_fofs 0x6e67+0xb

%if 1  ; Overwrite embedded logo relocator with compressible code and data.
patch_fofs_ab1 0x6e67+0xb, 0x6eab, nop  ; Code, being executed.
%endif

		incbin_until_fofs 0x7138
%ifndef NOPATCH  ; Unused, useless code (strange_change_io_sys).
		jmp strict near $+(0x723a-0x7138)
		patch_fofs_ab_cli_hlt 0x713b, 0x723a
%else
		incbin_until_fofs 0x723a
%endif
assert_fofs 0x723a

%if 1
patch_fofs 0x7390, db, 0xe8, 0xba  ; Patch skip-msdcm-call: Skip running MSDCM, not even calling the function. Also prevents the error message: `Warning: the system configuration manager failed to run.'...
%endif

patch_fofs_ab_cli_hlt 0x7531, 0x7546  ; Used only by 0x7138.

		incbin_until_fofs 0x9523
; Based on https://www.vogons.org/viewtopic.php?p=1124590#p1124590
msdos_sys_options: dw (~OPTVAL_Logo&1)<<0 | (~OPTVAL_DBLSpace&1)<<1 | (~OPTVAL_DRVSpace&1)<<2 | (~OPTVAL_BootKeys&1)<<3 | (~OPTVAL_BootWin&1)<<4 | (~OPTVAL_BootGUI&1)<<5 | (~OPTVAL_LoadTop&1)<<6 | (~OPTVAL_BootMulti&1)<<7 | (~OPTVAL_BootWarn&1)<<8 | (~OPTVAL_SystemReg&1)<<9

patch_fofs_ab_cli_hlt 0xda09, 0xda37  ; Used only by 0x7531.

%if 1  ; Overwrite embedded logo decompressor with compressible code and data.
  patch_fofs_ab_cli_hlt 0xf6d0, 0xf730  ; Code.
  %ifdef OPTIMIZE_FOR_COMPRESSION
    patch_fofs_ab1 0xf739, 0x1018b, db 0  ; Data, then code.
  %else
    patch_fofs_ab1 0xf739, 0xf762, db 0  ; Data.
    patch_fofs_ab_cli_hlt 0xf762, 0x1018b  ; Code.
  %endif
%endif

%if 1  ; Overwrite the MSDCM runner with compressible code and data.
patch_fofs_ab1 0x104fb, 0x1052e, db 0
patch_fofs_ab_cli_hlt 0x1052e, 0x10552
;patch_fofs_ab_cli_hlt 0x10552, 0x1064d  ; Not patching it, this code is also used somewhere else (other than MSDCM).
patch_fofs_ab_cli_hlt 0x1064d, 0x10844  ; Overwrite MSDCM-related code with useless instructions.
%endif

%if 1  ; Overwrite the MSDCM messages with compressible data.
		incbin_until_fofs 0x112a5
%ifndef NOPATCH
		db '$'  ; Make the massege empty, since we never display it.
		times 0x112d3-0x112a5-1 db ' '
%else
		db 'Process the system registry [Enter=Y,Esc=N]?$', 0
%endif	
assert_fofs 0x112d3
		incbin_until_fofs 0x115ed
%ifndef NOPATCH
		db '$'  ; Make the massege empty, since we never display it.
		times 0x1166d-0x115ed-1 db ' '
%else
		db 'Warning: the system configuration manager failed to run.', 13, 10
		db 'Some of your real-mode device drivers may not initialize properly.', 13, 10, '$', 0  ; MSDCM EXEC error message.
%endif
assert_fofs 0x1166d
%endif

patch_fofs_ab1 0x11c49, 0x12e51, db 0 ; Replace `times 0x47e db 'MPAD'` with NULs, for better compression.

; This is the w3xstart patch, i.e. to make Windows 3.x work under MS-DOS 7.1 (Windows 98). Here are the patches for io.sys:
;
; * For MS-DOS 7.0 (Windows 95 before OSR2):              81ff00047306be0400e9e7fd5032c086065c0f0ac05874ee --> 81ff00007306be0400e9e7fd5032c086065c0f0ac0589090
; * For MS-DOS 7.1 (Windows 95 OSR2, Windows 98 FE--SE):  81ff00047306be0400e9e7fd5032c086065c0f0ac05874ee --> 81ff00037306be0400e9e7fd5032c086065c0f0ac0589090
; * For MS-DOS 8.0 (Windows ME):                          81ff00047306be0400e9effd5032c086065c0f0ac05874ee --> 81ff00037306be0400e9effd5032c086065c0f0ac0589090
;
; This patch is already applied to Windows 98 SE io.sys in:
;
; * By Tihiy on https://msfn.org/board/topic/45103-reduced-iosys/#findComment-312901
; * Bitwise identical to Tihiy, copied by MDGx on https://msfn.org/board/topic/77019-windows-me-iosys-winbootsys-format/#findComment-524681
; * MS-DOS 7.1 (CDU) on https://winworldpc.com/product/ms-dos/7x
;
; These are unpatched:
;
; * MS-DOS 7.1 uploaded by Master-Link on https://archive.org/details/ms-dos-7.1_202308
; * MSDOS8.ISO on http://www.multiboot.ru/download/
;
; Some more links about the w2xstart patch:
;
; * https://msfn.org/board/topic/97945-windows-311-and-ms-dos-71/#findComment-964141
; * automated tool win3x.bug/w3xstart.exe available as part of osr2fix.exe: http://web.archive.org/web/20071015004054/http://www.smspower.org/maxim/16bit/files/osr2fix.exe
; * osr2fix.exe is also available from here: https://www.vogons.org/download/file.php?id=10289
; * OSR2FIX also linked from here: https://www.mdgx.com/dos.htm
;
; To locate the affected code in the disassembled io.sys, search for `xchg al,[0xf`.
;
; Additionally, to make Windows 3.1 and 3.11 work on FAT32 filesystems, apply this patch
; (from https://www.vogons.org/viewtopic.php?p=262579#p262579) on Windows
; 3.x win386.exe:
;
; * Windows 3.1
;   ```
;   0005EA26: 66C74649FFFF --> 6AFF8F464990
;   0005EC38: 66C74649FFFF --> 6AFF8F464990
;   ```
; * Windows 3.11:
;   ```
;   00065A26: 66C74649FFFF --> 6AFF8F464990
;   00065C38: 66C74649FFFF --> 6AFF8F464990
patch_fofs 0x136c2, db, 4, 3
patch_fofs 0x136d5, dw, 0xee74, 0x9090

;patch_fofs 0x1e000, db, 0xcb, 0xcb  ; retf. This is indeed used. We restore it as `0xcb' above.

; Unused code near the end.
;patch_fofs_ab_cli_hlt 0x1e001, 0x1e010

incbin_until_fofs 0x1e000

%ifndef NOPATCH  ; Truncate.
  %if 0  ; %ifdef OPTIMIZE_FOR_COMPRESSION  ; Works, but makes it larger.
    incbin_until_fofs 0x1e001   ; The final 0xcb (retf) byte is important. The most efficient way is including it.
  %endif
%else
  incbin ORIG_IO_FN, $-OBASE
  assert_fofs 0x365ce  ; Check size. sha256sum is: d34436a7ce911ed39549fce6107f3b55ad5d413565ebabc1398e13f2df103271  winboot.98s
%endif
