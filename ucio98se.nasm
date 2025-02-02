;
; patchio98se.nasm: patch Windows 98 SE io.sys to use an uncompressed logo
; by pts@fazekas.hu at Wed Jan 29 23:38:57 CET 2025
;
; Size of io.sys:
;
; * 222670 uncompressed: IO.SYS.win98sekb
; * 117993 compressed, without MSDCM: IO.SYS.win98sekbuc (including logo, compressed)
; * 139373 compressed: 118448 prefix of IO.SYS.win98sekbumc (including logo, compressed), 20925 MSDCM.EXE.win98sekbc (compressed, apack1p -3 -h)
; * would be 96768 without the logo, thus the logo adds 45547 bytes; with appack (aPLib 1.1.1), the logo is 45004 bytes
;
; !! Update the size measurements in patchio98se.nasm.
; !! make apack1p work without yes c, also in apack1p: yes c | dosbox.nox.static --cmd --mem-mb=6 apack.exe -3 -h wasmr.exe wasmrc.exe
; !! add `upx --lzma' compression: it can save 11 KB for IO.SYS.win98sekbumc; for MSDCM it dosn't make it any smaller; it has 0 relocations
;

bits 16
cpu 386  ; Some instructions don't work with `cpu 386'.

;%define MSDCM  ; Run it with `nasm -DMSDCM', post-process it with fixmsdcm.pl.

%ifndef MSLOAD_SECTOR_COUNT  ; Can be 0, 2 or 4. 4 for compatibility.
  %define MSLOAD_SECTOR_COUNT 0  ; Use 0, it is the smallest.
%endif
%ifndef NOPATCH
%else
  %define MSLOAD_SECTOR_COUNT 4  ; Override other settings with -DNOPATCH.
  %error NOPATCH_NOT_SUPPORTED
  db 1/0
%endif

%if MSLOAD_SECTOR_COUNT==0
  %define MSLOAD_PARA_SIZE 0x34
%else
  %assign MSLOAD_PARA_SIZE (MSLOAD_SECTOR_COUNT)<<5
%endif
%undef MSLOAD_SECTOR_COUNT

%macro assert_hfofs 1
  times +(%1)-($-$$) times 0 nop
  times -(%1)+($-$$) times 0 nop
%endm

%macro assert_fofs 1
  times +(%1)-($-OBASE) times 0 nop
  times -(%1)+($-OBASE) times 0 nop
%endm

OBASE: equ $$+((MSLOAD_PARA_SIZE-0x80)<<4)

%define ORIG_IO_FN 'winboot.98s'
%define MSDCM_FN 'IO.SYS.win98sekb.msdcmc'
;%define MSDCM_FN 'asc.exe'  ; !!

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

msload:

mz_header:

%ifdef MSDCM
.signature:	db 'MF'	 ; Signature. Indicates that fixmsdcm.pl has to be run.
.lastsize:	incbin MSDCM_FN, 2, 4  ; .lastsize and .nblocks will be fixed by running fixmsdcm.pl.
%else
.signature:	db 'MZ'	 ; Signature. Checked by the boot sector boot code: cmp word [bx], 'MZ'
.lastsize:	dw 0  ; Value correct only if there is no MSDCM.  ; (eof-.signature) & 0x1ff     ; The value 0 and 0x200 are equivalent here. Microsoft Linker 3.05 generates 0, so do we. Number of bytes in the last 0x200-byte block in the .exe file.
.nblocks:	dw 0  ; Value correct only if there is no MSDCM.  ; (eof-.signature +0x1ff)>> 9  ; Number of 0x200-byte blocks in .exe file (rounded up).
%endif
.nreloc:	dw 0  ; No relocations. That's always true, even for MSDCM. msloadv7i.nasm requires it, because its code starts at file offset 0x18.
.hdrsize:	dw (logo_payload_end-mz_header+0xf)>>4  ;0x2e40  ; dw (end-.signature)>>4  ; Will be copied to load_para_count. Used by msload to determine how many bytes of msbio to load.
%ifdef MSDCM
.minalloc:	incbin MSDCM_FN, 0xa, 0x18-0xa  ; .minalloc will be fixed by running fixmsdcm.pl.
%else
.minalloc:	dw 0  ; Value correct only if there is no MSDCM. It's hard to get this right in NASM, so MSDCM will be will be fixed by fixmsdcm.pl.
.maxalloc:	dw 0  ; Value correct only if there is no MSDCM.
.ss:		dw 0  ; Value correct only if there is no MSDCM.
.sp:		dw 0  ; Value correct only if there is no MSDCM.
.checksum:	dw 0
.ip:		dw 0  ; Value correct only if there is no MSDCM.
.cs:		dw 0  ; Value correct only if there is no MSDCM.
%endif
;.relocpos:	dw ?
;.noverlay:	dw ?
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
assert_hfofs MSLOAD_PARA_SIZE<<4
assert_fofs 0x800

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

patch_fofs_ab1 0x54c2, 0x5702, db 0  ; Replace `times 0x90 db 'MPAD'` with NULs, for better compression.

; C;\logo.sys, if available, still works: wget https://archive.org/download/win95-logo.sys/logo.sys
;patch_fofs 0x13ed, dw, 0x0e29, 0xa390  ; Force load_para_count to be 0, effectively ignoring the embedded compressed logo (splash screen). It also makes io.sys ignore the mz_header.hdrsize value after msload has completed.

; Remove unnused, useless code (strange_change_io_sys).
		incbin_until_fofs 0x7138
		jmp strict near $+(0x723a-0x7138)
		patch_fofs_ab_cli_hlt 0x713b, 0x723a
assert_fofs 0x723a

%ifndef MSDCM
  patch_fofs 0x7390, db, 0xe8, 0xba  ; Patch skip-msdcm-call: Skip running MSDCM, not even calling the function.
%endif

patch_fofs_ab_cli_hlt 0x7531, 0x7546  ; Used only by 0x7138.

patch_fofs_ab_cli_hlt 0xda09, 0xda37  ; Used only by 0x7531.

		incbin_until_fofs 0xf6d0
logo_payload_far_ptr_csofs equ 0x1524
read_from_logo_and_decompress:  ; Reads at most 0x8000 uncmpressed logo bytes to DS:DX, decompresses it from CS:csofs_from_fofs(logo_payload_far_ptr) (may increment it), returns actual number of bytes read in AX, indicates error with CF=1.
		pusha  ; Save.
		push ds  ; Save.
		push es  ; Save.
		push ds
		pop es
		mov di, dx
		lds si, [cs:logo_payload_far_ptr_csofs]
		mov cx, 0x8000>>1
		rep movsw  ; We don't decompress here, the aPACK self-decompressor has already done it.
		mov bx, ds
		add bh, 8
		mov [cs:logo_payload_far_ptr_csofs+2], bx
		pop es  ; Restore.
		pop ds  ; Restore.
		popa  ; Restore.
		;xor ax, ax  ; The caller ignores it.
		;xor cx, cx  ; The caller ignores it.
		clc  ; Indicates success.
		ret
%if 1  ; Overwrite embedded logo decompressor with compressible code and data.
  ;patch_fofs_ab_cli_hlt 0xf6d0, 0xf730  ; Code.
  patch_fofs_ab_cli_hlt $-OBASE, 0xf730  ; Code.
  %ifdef OPTIMIZE_FOR_COMPRESSION
    patch_fofs_ab1 0xf739, 0x1018b, db 0  ; Data, then code.
  %else
    patch_fofs_ab1 0xf739, 0xf762, db 0  ; Data.
    patch_fofs_ab_cli_hlt 0xf762, 0x1018b  ; Code.
  %endif
%endif

%ifndef MSDCM  ; Overwrite the MSDCM runner with compressible code and data.
  %ifdef OPTIMIZE_FOR_COMPRESSION
    patch_fofs_ab1 0x104fb, 0x1052e, db 0
    patch_fofs_ab_cli_hlt 0x1052e, 0x10552
    ;patch_fofs_ab_cli_hlt 0x10552, 0x1064d  ; Not patching it, this code is also used somewhere else (other than MSDCM).
    patch_fofs_ab_cli_hlt 0x1064d, 0x10844  ; Overwrite MSDCM-related code with useless instructions.
  %endif
%endif

%ifndef MSDCM  ; Overwrite the MSDCM messages with compressible data.
  %ifdef OPTIMIZE_FOR_COMPRESSION
		incbin_until_fofs 0x112a5
		db '$'  ; Make the massege empty, since we never display it.
		times 0x112d3-0x112a5-1 db ' '
    assert_fofs 0x112d3
		incbin_until_fofs 0x115ed
		db '$'  ; Make the massege empty, since we never display it.
		times 0x1166d-0x115ed-1 db ' '
    assert_fofs 0x1166d
  %endif
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

		incbin_until_fofs 0x1e010

logo_payload:  ; Used to be compressed_logo_payload, but here it is uncompressed.
		;incbin 'IO.SYS.win98sekb.logo'  ; Compressed.
		;incbin 'LOGO.SYS.win98se'  ; Uncompressed.
		incbin 'IO.SYS.win98sekb.bmp'  ; Uncompressed, we've just decompressed it.
logo_payload_end:

%ifdef MSDCM
		times ($$-$)&0xf db 0
msdcm_exe_image:
%if 0
		mov al, 'H'
		int 0x29  ; Print character.
		mov al, 'i'
		int 0x29  ; Print character.
		mov ax, 0x4c00
		int 0x21  ; Exit successfully.
%endif
		incbin MSDCM_FN, 0x20  ; Recompressed msdcm. We assume that it mz_header is 0x20 bytes. this is true for `apack1p -3 -h' output.
eof:
%endif
