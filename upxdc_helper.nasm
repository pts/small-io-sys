;
; upxdc_helper.nasm: build i386 decompressors of UPX-compressed data
; by pts@fazekas.hu at Sat Mar 29 23:06:27 CET 2025
;
; See upxbc.pl for compile commands.
; Example compile command: tools/nasm-0.98.39.upx -O0 -w+orphan-labels -f bin -DEXTRACT32 -DMETHOD=14 -DFILTER=0 -DFILTER_CTO=0 -DLZMA_PROBS_SIZE=15980 -DLZMA_HEADER_DWORD=0x20003 -DCDATAFN='hi.txt.bin.tmp' -o hi.txt.bin upxdc_helper.nasm
; Minimum NASM version needed: 0.98.39.
;
; All code in this file is position-independent.
;
; !! Add overlap detection, use minimum overlap between uncompressed and compressed data.

bits 32
cpu 386

%ifdef DECOMPRESS32  ; Specified on the command line.
  ; DECOMPRESS32 is one of the main output modes. It selects creating an
  ; i386 function (move_decompress) which does the decompression and
  ; unfiltering when called.
  %ifdef FLAT32
    %error ERROR_MULTIPLE_OFMT  ; See upxdc.pl for example compile command invocation (with -DDECOMPRESS32 or -DFLAT32).
    db 1/0
  %endif
  %ifdef FLAT16_386
    %error ERROR_MULTIPLE_OFMT  ; See upxdc.pl for example compile command invocation (with -DDECOMPRESS32 or -DFLAT32).
    db 1/0
  %endif
  %define FLAT 0
%elifdef FLAT32  ; Specified on the command line.
  ; FLAT32 is one of the main output modes. It selects creating an i386
  ; piece of self-decompressor code which decompresses the compressed data
  ; back to itself, and then runs it in place.
  %ifdef FLAT16_386
    %error ERROR_MULTIPLE_OFMT  ; See upxdc.pl for example compile command invocation (with -DDECOMPRESS32 or -DFLAT32).
    db 1/0
  %endif
  %ifndef USIZE  ; Specified on the command line.
    %error ERROR_MISSING_USIZE
    db 1/0
  %endif
  %define FLAT 1
%elifdef FLAT16_386  ; Specified on the command line.
  ; FLAT32 is one of the main output modes. It selects creating an i386
  ; real-mode piece of self-decompressor code which decompresses the
  ; compressed data back to itself, and then runs it in place. It is like
  ; FLAT32, but it first switches from (16-bit) real mode to protected mode,
  ; and in the end it switches back to real mode.
  %ifndef FLAT16_SEGMENT  ; Specified on the command line.
    %ifdef FLAT16_OFFSET
      %error ERROR_MISSING_FLAT16_SEGMENT_FOR_FLAT16_OFFSET
      db 1/0
    %endif
  %else
    %assign FLAT16_SEGMENT FLAT16_SEGMENT
  %endif
  %ifndef FLAT16_OFFSET  ; Specified on the command line.
    %ifdef FLAT16_SEGMENT
      %error ERROR_MISSING_FLAT16_OFFSET_FOR_FLAT16_SEGMENT
      db 1/0
    %endif
  %else
    %assign FLAT16_OFFSET FLAT16_OFFSET
  %endif
  %define FLAT 1
%else
  %error ERROR_MISSING_OFMT_MODE  ; See upxdc.pl for example compile command invocation (with -DDECOMPRESS32).
  db 1/0
%endif
%ifndef METHOD  ; Specified on the command lone.
  %error ERROR_MISSING_METHOD
  db 1/0
%else
  %assign METHOD METHOD
%endif
%ifndef FILTER  ; Specified on the command lone.
  %error ERROR_MISSING_FILTER
  db 1/0
%else
  %assign FILTER FILTER
%endif
%ifndef FILTER_CTO  ; Specified on the command lone.
  %if FILTER==0
    %define FILTER_CTO 0
  %else
    %error ERROR_MISSING_FILTER_CTO
    db 1/0
  %endif
%else
  %assign FILTER_CTO FILTER_CTO
%endif
%ifndef CDATAFN  ; Specified on the command line.
  %error ERROR_MISSING_CDATAFN
%endif
%ifndef CDATASKIP  ; Specified on the command line.
  %define CDATASKIP 0
%else
  %assign CDATASKIP CDATASKIP
%endif
%ifndef COMPRESSED_LZMAD  ; Specified on the command line.
  %define COMPRESSED_LZMAD 8  ; Enable it by default.
%elif COMPRESSED_LZMAD
  %assign COMPRESSED_LZMAD COMPRESSED_LZMAD
  %if COMPRESSED_LZMAD!=8 && COMPRESSED_LZMAD!=16 && COMPRESSED_LZMAD!=32
    %error ERROR_BAD_COMPRESSED_LZMAD COMPRESSED_LZMAD
    db 1/0
  %endif
%else
  %define COMPRESSED_LZMAD 0  ; -DCOMPRESSED_LZMAD=0 explicitly disables it.
%endif
%ifdef USIZE  ; Can be specified on the command line.
  %assign USIZE_LIMIT USIZE
%else
  %define USIZE_LIMIT 0
%endif
%ifndef SMALL  ; Specified on the command line.
  %define SMALL 0  ; The small NRV2B decompressors may be slow or unstable, so don't enable them by default.
%elif SMALL
  %define SMALL 1
%else
  %define SMALL 0
%endif

%ifdef FLAT16_SEGMENT
  %ifndef FLAT16_386
    %error ERROR_UNEXPECTED_FLAT16_SEGMENT
    db 1/0
  %endif
%endif
%ifdef FLAT16_OFFSET
  %ifndef FLAT16_386
    %error ERROR_UNEXPECTED_FLAT16_OFFSET
    db 1/0
  %endif
%endif

%ifdef USIZE
  %if USIZE<=5   ; The filter doesn't change short data. Make it explicit so that the unfilter code doesn't have to check for overflows.
    %if FILTER>=1 && FILTER<=6 && USIZE<=3  ; Corresponds to upx-3.94-src/src/filter/ct.h .
      %define FILTER 0
    %elif FILTER==0x46 || FILTER==0x49  ; Corresponds to upx-3.94-src/src/filter/ctok.h .
      %define FILTER 0
    %endif
  %endif
%endif

%define UNCOMPRESSED_LZMAD_SIZE 2459  ; See the command creating upxdc_lzmadfb.bin below.
; UPX compression method constants.
%define M_NRV2B_LE32    2
%define M_NRV2B_8       3
%define M_NRV2B_LE16    4
%define M_NRV2D_LE32    5
%define M_NRV2D_8       6
%define M_NRV2D_LE16    7
%define M_NRV2E_LE32    8
%define M_NRV2E_8       9
%define M_NRV2E_LE16    10
%define M_LZMA          14

%if METHOD==M_LZMA && COMPRESSED_LZMAD
  %assign NRV_USIZE_LIMIT UNCOMPRESSED_LZMAD_SIZE
%else
  %assign NRV_USIZE_LIMIT USIZE_LIMIT
%endif

%if METHOD==M_LZMA
  %ifndef LZMA_PROBS_SIZE  ; Specified on the command line.
    %error ERROR_MISSING_LZMA_PROBS_SIZE
    db 1/0
  %else
    %assign LZMA_PROBS_SIZE LZMA_PROBS_SIZE
  %endif
  %ifndef LZMA_HEADER_DWORD  ; Specified on the command line.
    %error ERROR_MISSING_LZMA_HEADER_DWORD
    db 1/0
  %else
    %assign LZMA_HEADER_DWORD LZMA_HEADER_DWORD
  %endif
  %ifndef LZMAD_BIN
    %define LZMAD_BIN 'upxdc_lzmad.bin'
  %endif
  %ifndef CLZMAD_BIN
    %if COMPRESSED_LZMAD==8
      %define CLZMAD_BIN 'upxdc_lzmadfb8.bin'
    %elif COMPRESSED_LZMAD==16
      %define CLZMAD_BIN 'upxdc_lzmadfb16.bin'
    %elif COMPRESSED_LZMAD==32
      %define CLZMAD_BIN 'upxdc_lzmadfb32.bin'
    %endif
  %endif
%endif
%if METHOD==M_LZMA && COMPRESSED_LZMAD
  %if COMPRESSED_LZMAD==8
    %assign NRV2B_METHOD M_NRV2B_8
  %elif COMPRESSED_LZMAD==16
    %assign NRV2B_METHOD M_NRV2B_LE16
  %elif COMPRESSED_LZMAD==32
    %assign NRV2B_METHOD M_NRV2B_LE32
  %endif
%elif METHOD==M_NRV2B_LE32 || METHOD==M_NRV2B_LE16 || METHOD==M_NRV2B_8
  %assign NRV2B_METHOD METHOD
%else
  %undef NRV2B_METHOD
%endif

%ifidn __OUTPUT_FORMAT__, elf
  section .text align=1
%elifidn __OUTPUT__FORMAT__, obj
  section CONST2 USE32 class=DATA align=4  ; Other, non-string-literal .rodata.
  group DGROUP CONST2
%endif

%if FLAT
  %if METHOD!=M_LZMA
    stack_usage equ 48+52  ; !! Why 52? can we estimate less usage?
  %elif COMPRESSED_LZMAD
    stack_usage equ 48+(LZMA_PROBS_SIZE)+368+((UNCOMPRESSED_LZMAD_SIZE+3)&~3)
  %else
    stack_usage equ 48+(LZMA_PROBS_SIZE)+368
  %endif
%endif

%macro debug_chr 1 ; For QEMU: `qemu-system-i386 -debugcon stdio'.
  push eax
  mov al, %1
  out 0xe9, al
  pop eax
%endm

global payload
global _payload
payload:
_payload:
%ifdef FLAT16_386
  ; Decompresses the compressed payload in place (back to
  ; move_smart_decompress), and jumps back to it. Uses some extra bytes
  ; (stack space + temporary copy of the decompressor and the compressed
  ; data (as code)) after payload_end, and keeps those bytes uninitialized
  ; (i.e. garbage, junk, leftover, arbitrary). Needs a read-write-execute
  ; permission for the extra bytes (i.e. link with `gcc -Wl,-N').
  ;
  ; Loaded to (segment:offset) FLAT16_SEGMENT:FLAT16_OFFSET in real mode.
  ; There is at least 48 bytes of stack available (at SS:SP, wherever it
  ; is). It is allowed to switch to i386 32-bit protected mode for
  ; decompression, but then it must switch back to real mode, and jump to
  ; back here.
  ;
  ; It preserves all 8 general-purpose 32-bit registers, EFLAGS and all
  ; segment registers.
  ;
  ; If FLAT16_SEGMENT is not defined, then the code below assumes that it is
  ; loaded to real-mode segment:offset FLAT32_SEGMENT:FLAT32_OFFSET in the
  ; first 1 MiB of physical memory. By knowing the load address beforehand,
  ; the code can be shorter. Otherwise the code below is
  ; position-independent code, i.e. it can be loaded to any real-mode
  ; segment:offset in the first 1 MiB of physical memory, just IP must be
  ; <0xff80) if FLAT16_SEGMENT is not defined.
  ;
  ; See the `caller_stack_usage +=' comments below to see how many stack
  ; bytes it uses. The total is 50 bytes. After that it switches to its
  ; own stack (see `stack_usage equ' above for its size).
  %ifdef FLAT16_SEGMENT
    %if FLAT16_OFFSET>=0xff80
      %error ERROR_FLAT16_OFFSET_TOO_LARGE  ; No space for flat16_386_start within the segment before switching to protected mode.
      times -1 nop
    %endif
    flat16_base equ (FLAT16_SEGMENT<<4)+FLAT16_OFFSET  ; Physical (linear) address of flat16_386_start.
    flat16_offset equ FLAT16_OFFSET
    %define FLAT16_LINEAR(label) ((label)-payload+flat16_base)
    %define FLAT16_COPIED_LINEAR(label) ((label)-smart_decompress+copied_smart_decompress_linear)
    %define FLAT16_OFSVAL(label) ((label)-payload+flat16_offset)
  %endif
  bits 16
  global flat16_386_start
  flat16_386_start:
		pushf  ; Save for iret. caller_stack_usage += 2.
		push cs  ; Save for iret. caller_stack_usage += 2.
		call .to_protected  ; Save for iret. Will return to payload (above) in the `iret' in return_from_smart_decompress.prot16. caller_stack_usage += 2.
  .to_protected:  ; Switch to i386 32-bit protected mode.
		push ds  ; Save. caller_stack_usage += 2.
		push es  ; Save. caller_stack_usage += 2.
		pushad  ; Save. caller_stack_usage += 8 * 4.
		; Now: dword [sp] is the saved EDI; dword [sp+7*4] is the saved EAX; word [sp+8*4] is the saved ES; word [sp+8*4+2] is the saved DS; word [sp+8*4+4] is the actual offset .to_protected; word [sp+8*4+6] is the saved CS; word [sp+8*4+8] is the saved FLAGS.
		push sp  ; caller_stack_usage += 2. On i386+, this pushes the old SP value.
		push ss  ; caller_stack_usage += 2.
		pop ebp  ; EBP := orig_SS|orig_SP<<16. return_from_smart_decompress.to_real uses it to restore SS:SP. This is an unusual word ordering, but the other way would break the orig_SP value.
		call .gdtnext  ; Doesn't affect the maximum of caller_stack_usage.
  .pbase:  ; Address after the call. Used for implementing position-independent code.
  .gdtr:	dw .gdt_end-.gdt-1  ; GDT limit.
  %ifdef FLAT16_SEGMENT
		dd FLAT16_LINEAR(.gdt)  ; GDT base.
  %else
		dd .gdt-.pbase  ; GDT base. To get the final value, the linear address of .pbase will be added below.
  %endif
  .gdt: equ $-8  ; We use arbitrary values for segment 0, hence the -8. No need to align this to a multiple of 4, since it is only used in the `mov ds, ...' instructions, not for regular data access.
  .prot32_cs: equ $-.gdt  ; Segment .prot32_cs == 8.    32-bit, code, read-execute, base 0, limit 4GiB-1, granularity 0x1000.
                dw 0xffff, 0, 0x9a00, 0xcf
  .prot32_ds: equ $-.gdt  ; Segment .prot32_ds == 0x10. 32-bit, data, read-write,   base 0, limit 4GiB-1, granularity 0x1000.
                dw 0xffff, 0, 0x9200, 0xcf
  .gdt_end:
  .gdtnext:	cli  ; No stack usage for a while.
  %ifdef FLAT16_SEGMENT
		lgdt [cs:FLAT16_OFSVAL(.gdtr)]  ; Use .gdtr, which points to .gdt.
  %else
		xor ecx, ecx
		mov cx, cs
		shl ecx, 4
		xor ebx, ebx
		pop bx  ; BX := CS-based offset of .gdtr and .pbase.
		add ecx, ebx  ; ECX := linear address of .gdtr and .pbase.
		add [cs:bx+2], ecx  ; Update the GDT base in the GDTR.
		lgdt [cs:bx]  ; Use .gdtr, which points to .gdt.
  %endif
		mov eax, cr0
		or al, 1  ; PE := 1.
		mov cr0, eax
		mov ax, .prot32_ds
  %ifdef FLAT16_SEGMENT
    %if FLAT16_LINEAR($+5)<=0xffff
		jmp .prot32_cs:FLAT16_LINEAR(.prot32)  ; 5 bytes. Jumps to .prot32 (right below), activates 32-bit protected mode in CS.
    %else
		jmp .prot32_cs:dword FLAT16_LINEAR(.prot32)  ; 8 bytes. Jumps to .prot32 (right below), activates 32-bit protected mode in CS.
    %endif
  %else  ; The instructions below are quite long (especially because they need 32-bit prefix bytes), but we needed them for position-independent code.
		o32 push byte .prot32_cs  ; Segment 8. Pushes 4 bytes. Doesn't affect the maximum of caller_stack_usage.
		add ecx, byte .prot32-.pbase  ; ECX := linear address of .prot32.
		push ecx  ; caller_stack_usage += 4.
		o32 retf  ; Jumps to .prot32 below in 32-bit protected mode.
  %endif
  bits 32
  .prot32:  ; Execution continues here in i386 32-bit protected mode.
		mov ds, ax
		mov es, ax  ; `stosb' etc. instructions use it implicitly.
		mov ss, ax  ; We'll set up ESP below.
		;mov fs, ax  ; No need, we don't use it.
		;mov gs, ax  ; No need, we don't use it.

  %ifdef FLAT16_SEGMENT
		mov eax, FLAT16_LINEAR(payload)
    copied_smart_decompress_linear equ (FLAT16_LINEAR(payload)+(USIZE)+stack_usage)&-4  ; Destination address of the copy of smart_decompress...payload_end.
		mov esp, copied_smart_decompress_linear
  %else
		lea eax, [byte ecx+payload-.prot32]  ; EAX := linear address of payload (== address of start of uncompressed data output). This is BYTE_DIFF1. smart_decompress below needs the latter in EAX.
    %if .prot32-payload>0x7f
      %error ERROR_BYTE_DIFF1_TOO_LARGE  ; See BYTE_DIFF1 elsewhere in this file.
      times -1 nop
    %endif
		lea esp, [dword eax+(USIZE)+stack_usage]  ; !! Instead of USIZE, use a smaller value coming from overlap detection. Also put the stack after the copy of the compressed data, i.e. add ECX here and subtract ECX from EDI below.
		and esp, byte -4  ; Align to multiple of 4. The UPX LZMA decompressor requires this for stack cleaning, but stack cleaning and thus the requirement has been removed from our LZMA decompressor. Also it's faster this way.
  %endif
		; SS:ESP is valid, we can use our protected-mode stack from now. The real-mode stack is inaccessible.
		mov ecx, payload_end-smart_decompress  ; Size of the copy of smart_decompress...payload_end.
  %if 1  ; Use `%if 1' if it fits.
    %define USE_BYTE_DIFF2
		lea esi, [byte eax+ecx+(smart_decompress-payload)-1]  ; This is one instance of BYTE_DIFF2. This instruction is only 4 bytes, using FLAT16_SEGMENT would make it longer.
  %elifdef FLAT16_SEGMENT
		mov esi, FLAT16_LINEAR(payload_end)-1
  %else
		lea esi, [dword eax+ecx+(smart_decompress-payload)-1]
  %endif
		lea edi, [byte esp+ecx-1]  ; This instruction is only 4 bytes, using FLAT16_SEGMENT would make it longer.
		std
		rep movsb  ; Copy smart_decompress...payload_end to payload+USIZE...
		cld
		; The outp argument (output buffer pointer) of the smart_decompress call below is already in EAX, it points (back) to payload.
		jmp esp  ; Jump to the copied smart_decompress function. Same as `inc edi' ++ `jmp edi' if we don't care about the value of EDI later.
%elifdef FLAT32
  ; i386 (32-bit protected mode) GCC and Watcom C: void payload(void);
  ;
  ; Ruins: nothing, it even preserves EFLAGS.
  ;
  ; Decompresses the compressed payload in place (back to
  ; move_smart_decompress), and jumps back to it. Uses some extra bytes
  ; (stack space + temporary copy of the decompressor and the compressed
  ; data (as code)) after payload_end, and keeps those bytes uninitialized
  ; (i.e. garbage, junk, leftover, arbitrary). Needs a read-write-execute
  ; permission for the extra bytes (i.e. link with `gcc -Wl,-N').
  ;
  ; Similar to `upxbc --flat32' output, but the compressed file size is
  ; smaller.
  move_smart_decompress:
		push eax  ; Dummy value, will be replaced below with the return address of smart_decompress. caller_stack_usage += 4.
		pushf  ; caller_stack_usage += 4.
		pusha  ; caller_stack_usage += 8 * 4.
		mov ebp, esp  ; Save original caller ESP to EBP. No more caller_stack_usage increase below.
		call .next
  .next:	pop eax  ; EAX := actual address where this code is running (.next), for position-independent code.
		lea eax, [byte eax-.next+payload]  ; EAX := linear address of payload.
		mov [ebp+9*4], eax  ; Overwrite the dummy return address of smart_decompress with the real one, it will return back to the beginning of the payload.
		mov ecx, strict dword payload_end-smart_decompress
		lea esi, [dword eax+(USIZE)+stack_usage]  ; !! Instead of USIZE, use a smaller value coming from overlap detection.
		and esi, byte -4  ; Align to multiple of 4. The UPX LZMA decompressor requires this for stack cleaning, but stack cleaning and thus the requirement has been removed from our LZMA decompressor. Also it's faster this way.
		mov esp, esi
  %define USE_BYTE_DIFF2
		lea esi, [byte eax+ecx+(smart_decompress-payload)-1]  ; This is one instance of BYTE_DIFF2.
		lea edi, [byte esp+ecx-1]
		std
		rep movsb  ; Copy smart_decompress[:smart_decompress_size] to payload+USIZE...
		cld
		; The outp argument (output buffer pointer) of the smart_decompress call below is already in EAX, it points (back) to payload.
		jmp esp  ; Jump to the copied smart_decompress function.
%elifdef DECOMPRESS32
  ; GCC: char *smart_decompress_func(char *output) __attribute__((__regparm__(3)));
  ; Watcom C: char * __watcall smart_decompress_func(char *output);
  ;
  ; Input: EAX: Address of start of uncompressed data output.
  ; Output: EAX: Address of end of uncompressed data output.
  ; Ruins: EFLAGS.
  global smart_decompress_func
  global smart_decompress_func_
  smart_decompress_func:
  smart_decompress_func_:
		pusha
%else
  %error ERROR_START_UNKNOWN
  times -1 nop
%endif

%if FLAT
  %define SMART_DECOMPRESS_RETURNS_UDATA_END_PTR 0  ; It returns void instead. move_smart_decompress will restore all registers.
%else
  %define SMART_DECOMPRESS_RETURNS_UDATA_END_PTR 1
%endif

; Input: EAX: Address of start of uncompressed data output.
; Output: EAX: Address of end of uncompressed data output, or garbage if SMART_DECOMPRESS_RETURNS_UDATA_END_PTR is false.
; Ruins: EFLAGS, EBX, ECX, EDX, ESI, EDI. (Keeps EBP.)
smart_decompress:
%ifdef USE_BYTE_DIFF2
  %if smart_decompress-payload-1>0x7f
    %assign VALUE smart_decompress-payload-1-0x7f
    %error ERROR_BYTE_DIFF2_TOO_LARGE VALUE  ; See BYTE_DIFF2 elsewhere in this file.
    times -1 nop
  %endif
%endif
%ifdef FLAT16_SEGMENT  ; This direct `mov' saves 1 byte compared to `lea' below.
		mov esi, FLAT16_COPIED_LINEAR(compressed_data_pre)  ; Linear address of copy of compressed_data_pre.
%elif FLAT
		; This is about 0xe0 bytes. If it was <=0x7f, we could save 3 bytes here by using `byte' instead of `dword' in the displacement.
		lea esi, [dword edi+1+(compressed_data_pre-smart_decompress)]  ; This is a size optimization: the currently running address of smart_decompress is in EDI+1.
%else
		call .next
.next:		pop esi  ; ESI := actual address where this code is running (.next), for position-independent code.
		add esi, strict dword compressed_data_pre-.next
%endif
%if FILTER!=0
		push eax  ; Save return value of smart_decompress. It's the adddress of start of uncompressed data output.
%endif
%if METHOD==M_LZMA && COMPRESSED_LZMAD
		push ebp
		mov ebp, esp
		sub esp, (UNCOMPRESSED_LZMAD_SIZE+3)&~3
		mov edi, esp
		push edi  ; Address of the uncompressed LZMA decompressor function on the stack. This relies on read-write-execute stack (produced by `minicc', but not by GCC default).
		push eax  ; Save address of start of uncompressed data output.
%else
		xchg edi, eax  ; EDI := EAX (address of start of uncompressed data output); EAX := junk.
%endif

; Decompressor code. Decompresses from ESI to EDI, stops at the first EOF
; marker within the compressed data. When it returns, sets EDI to the
; address of the byte after the uncompressed data. Ruins everyting else,
; including EFLAGS.
;
; !! Try LZO (successor of NRV) and LZ4 as well, maybe they can generate a few byte shorter decompressor+data combo.
;
; Details about NRV compression:
;
; * NRV compression algorithms have been implemented by 3 libraries:
;   * NRV (compression and decompression, closed source, discontinued, unavailable, http://www.oberhumer.com/products/nrv/);
;   * UCL (compression and decompression, open source, C and assembly, last
;     release is
;     [1.03](http://www.oberhumer.com/opensource/ucl/download/ucl-1.03.tar.gz)
;     on 2004-07-20, http://www.oberhumer.com/opensource/ucl/). UCL is an
;     open-source reimplementation of some NRV compression algorithms.
;   * UPX (decompression only, some algorithms only, 8086 16-bit assembly language, i386 32-bit protected mode (flat model) assembly language, assembly for others).
; * There are 3 NRV compression algorithm families: B, D and E. Within each
;   family, there are 3 types of bit encodings: 8-bit, 16-bit little-endian,
;   32-bit little-endian.
; * Thus these are all the NRV compression algorithms:
;   ```
;   M_NRV2B_8       3  ucl_nrv2b_decompress_safe_8
;   M_NRV2B_LE16    4  ucl_nrv2b_decompress_safe_le16
;   M_NRV2B_LE32    2  ucl_nrv2b_decompress_safe_le32
;   M_NRV2D_8       6  ucl_nrv2d_decompress_safe_8
;   M_NRV2D_LE16    7  ucl_nrv2d_decompress_safe_le16
;   M_NRV2D_LE32    5  ucl_nrv2d_decompress_safe_le32
;   M_NRV2E_8       9  ucl_nrv2e_decompress_safe_8
;   M_NRV2E_LE16   10  ucl_nrv2e_decompress_safe_le16
;   M_NRV2E_LE32    8  ucl_nrv2e_decompress_safe_le32
;   ```
; * Each NRV algoritm is a variation of LZSS, i.e. the compressed stream
;   contains literal bytes and (distance, length) pairs. There is no entropy
;   coding (such as Huffman coding, arithmetic coding and range coding).
; * Each compressed NRV stream is a mixture (multiplexing) of a byte stream
;   and a bit stream. The byte stream encodes the literal bytes, and the bit
;   stream encodes the (distance, length) pairs, in variable-length coding.
; * It is not necessary to use delimiters or lengths to (de)multiplex the
;   compressed NRV stream. It's encoded the following way: the bit stream is
;   encoded as blocks of 8-bit, 16-bit little-endian or 32-bit little endian
;   integers. The bytes in the byte stream are in between these blocks. A
;   new block comes as soon as it's necessary, i.e. just when the
;   decompressor needs a new bit.
; * The difference in the bit encoding (i.e. block size) makes the compresed
;   NRV streams within the same family incompatible. But their sizes are
;   roughly the same (+-3 bytes), they just contain the same information in
;   a slightly different order.
; * The 16-bit and the 32-bit varialts are slightly faster to decompress
;   (and the decompressor code is also tighter) on 16-bit and 32-bit CPUs,
;   respectively.
;
; !! Add conversion from e.g. NRV2B_LE16 to NRV2B_LE32 etc.
; !! Is it true that NRV2B_LE16 can have a maximum length and distance of 0xffff? Thus they are not fully eqivalent. Check for backreferences longer than 0xffff in DOS .exe.
decompress:  ; Must keep EBP intact.
%if METHOD==M_NRV2B_8 || METHOD==M_NRV2D_8 || METHOD==M_NRV2E_8
  %macro nrv_get_bit 0-1  ; Reads a bit from the bit stream, and puts it to CF. If needed, reads the next block (to BL).
                  add bl, bl
                  jnz short %%done
    %if %0  ; If the macro has an argument.
      %1:  ; Define label specified by the argument.
    %endif
                  mov bl, [esi]
                  sub esi, byte -1  ; This also sets CF := 1, which the `adc' below uses to increment EBX, which is important for end-of-bit-buffer detection in `add bl, bl' ++ jnz.
                  adc bl, bl
    %%done:
  %endm
%elif METHOD==M_NRV2B_LE16 || METHOD==M_NRV2D_LE16 || METHOD==M_NRV2E_LE16
  %macro nrv_get_bit 0-1  ; Reads a bit from the bit stream, and puts it to CF. If needed, reads the next block (to BX).
                  add bx, bx
                  jnz short %%done
    %if %0  ; If the macro has an argument.
      %1:  ; Define label specified by the argument.
    %endif
                  mov bx, [esi]  ; !! Optimize this with `xchg eax, ebx' ++ lodsw, making it 1 byte shorter.
                  sub esi, byte -2  ; This also sets CF := 1, which the `adc' below uses to increment EBX, which is important for end-of-bit-buffer detection in `add bx, bx' ++ jnz.
                  adc bx, bx
    %%done:
  %endm
%else  ; Assume 32-bit blocks in NRV. It is also used for (METHOD==M_LZMA && COMPRESSED_LZMAD).
  %macro nrv_get_bit 0-1  ; Reads a bit from the bit stream, and puts it to CF. If needed, reads the next block (to EBX).
    ; !! Write it shorter (too many repetitions of `add ebx, ebx' ++ `jnz'). How much slower does it get?
                  add ebx, ebx
                  jnz short %%done
    %if %0  ; If the macro has an argument.
      %1:  ; Define label specified by the argument.
    %endif
                  mov ebx, [esi]
                  sub esi, byte -4  ; This also sets CF := 1, which the `adc' below uses to increment EBX, which is important for end-of-bit-buffer detection in `add ebx, ebx' ++ jnz.
                  adc ebx, ebx
    %%done:
  %endm
%endif
%if (METHOD==M_LZMA && COMPRESSED_LZMAD) || (SMALL && (METHOD==M_NRV2B_LE32 || METHOD==M_NRV2B_LE16 || METHOD==M_NRV2B_8))  ; !! Enable it by default after extensive testing and benchmarking.
  ; Must keep EBP intact. Stack usage: 8 bytes (because of the two `call's).
  %if NRV2B_METHOD==M_NRV2B_8
    decompress_nrv2b_8_small:  ; 82 bytes between .start and .done. Based on (but a bit longer than because of 32-bit instruction encoding) upx-3.94-src/src/stub/src/arch/i086/nrv2b_d16.S .
    %define BLOCKREG bl
		mov BLOCKREG, 1<<7
  %elif NRV2B_METHOD==M_NRV2B_LE16
    decompress_nrv2b_le16_small:  ; 87 bytes between .start and .done. Based on (but a bit longer than because of 32-bit instruction encoding) upx-3.94-src/src/stub/src/arch/i086/nrv2b_d16.S .
    %define BLOCKREG bx
		mov BLOCKREG, 1<<15
  %elif NRV2B_METHOD==M_NRV2B_LE32
    decompress_nrv2b_le32_small:  ; 85 bytes between .start and .done. Based on (but a bit longer than because of 32-bit instruction encoding) upx-3.94-src/src/stub/src/arch/i086/nrv2b_d16.S .
    %define BLOCKREG ebx
		mov BLOCKREG, 1<<31
  %endif
  %if FLAT  ; The `rep' above in move_smart_decompress guarantees ECX == 0 here.
  %else
		xor ecx, ecx
  %endif
  %if METHOD==M_LZMA && COMPRESSED_LZMAD  ; Initialization of last_m_off is not needed for this input, checked by `upxdc.pl --truncate-nrv2b-le32'.
  %else
		or edx, byte -1  ; Initial -last_m_off value, so last_m_off == 1. This is missing from the UPX 3.94 .com output.
  %endif
  .start:	db 0xa8  ; Opcode byte of `test al, ...', to skip over the `movsb'. Shorter equivalent of: jmp short .next_token
  .literal:	movsb  ; Process an LZSS literal: copy a byte from the input byte stream to the output.
  .next_token:
		call .get_bit  ; Read token type: CF == 0 means reference, CF == 1 means literal.
		jc short .literal
  .read_m_off:  ; Now start reading m_off to CX. CX is 0 now.
		inc ecx  ; CX := 1.
  .next_off_bit:
		call .read_varint_bit
		; This finishes the decompression if we've read 16
		; consecutive 0 bits from the varint (i.e. the first 32 bits
		; of 000000000000000000000000000000000000000000001001).
		; This is good enough for outputs smaller than 1<<24 bytes.
  %if NRV_USIZE_LIMIT<0 || NRV_USIZE_LIMIT>0xffff
  %else
		jcxz .done  ; Would be incorrect with `jecxz'. Correct increments ESI only if compressed data has been processed by `upxdc.pl --truncate-nrv2b-le32'.
  %endif
		jnc short .next_off_bit  ; CF == 0 means continue reading more varint bits.
		sub ecx, byte 3
		jc short .read_m_len  ; Jump if m_off == 2. (And use -last_m_off in EDX for the offset.)
		xchg eax, ecx  ; EAX := ECX; ECX := junk.
		shl eax, 8
		lodsb  ; Read 8 more bits (m_off_low_byte).
  %if NRV_USIZE_LIMIT<0 || NRV_USIZE_LIMIT>0xffff
		xor eax, byte -1  ; EAX := -(EAX + 1). So EAX becomes the final -m_off.
		jz short .done  ; m_off == 0xffffffff (here EAX == 0) indicates end-of-stream (EOS). If this jumps, then EAX == 0 (indicating success). We ignore the return value.
  %else
		not eax  ; EAX := -(EAX + 1). This completes formula: m_off := m_off_from_varint - 3) * 256 + m_off_low_byte.
  %endif
		xchg edx, eax  ; EDX := EAX; EAX := junk. EDX becomes the final -last_m_off.
  .read_m_len:  ; Now start reading m_len to ECX.
		xor ecx, ecx  ; ECX := 0, the initial value of m_len.
		call .read_varint_bit  ; Reads first bit from the bottom of ECX.
		adc ecx, ecx  ; Reads second bit from the bottom of ECX.
		jnz short .copy_reference
		; The first 2 bits read were 0, so read a varint (more bits of m_len) into ECX.
		inc ecx
  .next_len_bit:
		call .read_varint_bit
		jnc short .next_len_bit  ; CF == 0 means continue reading more varint bits.
		; m_len += 2. (This is part of the NRV2B algorithm.)
		times 2 inc ecx
		; if (m_off > 0xd00) { m_len++; } m_len++;
  .copy_reference:  ; Process an LZSS reference: (length, distance) == (m_len, last_m_off) == (ECX, -EDX) pair by copying an already-built substring of the output.
  %if NRV_USIZE_LIMIT<0 || NRV_USIZE_LIMIT>0xffff
		cmp edx, -0xd00
		adc ecx, byte 1
  %elif NRV_USIZE_LIMIT<0 || NRV_USIZE_LIMIT>0xd00  ; UPX does a more accurate check: ph.max_offset_found <= 0xd00 ? "NRVLED00" : "NRVGTD00".
		cmp dh, -0xd
		adc ecx, byte 1
  %else  ; We can assume that `m_off >0xd00' is never true.
		inc ecx  ; just do the 2nd m_len++.
  %endif
		xchg eax, esi  ; Save ESI; ESI := junk.
		lea esi, [edx+edi]  ; EAX := source offset for the reference. EDX is now -last_m_off.
		rep movsb  ; Copy the an already-built substring of the output. Can overlap itself. Also sets CX := 0 at the end.
		xchg esi, eax  ; Restore ESI; EAX := junk.
		jmp short .next_token
  .read_varint_bit:  ; Reads a bit to ECX (shifting it left, setting its low bit). Then it reads the continuation bit to CF.
		call .get_bit
		adc ecx, ecx
		; Falls through to .get_bit for reading the continuation bit.
  .get_bit:  ; Reads a bit from the input bit stream to CF. Ruins EAX. Updates EBX, reads another block if needd.
		add BLOCKREG, BLOCKREG
		jnz short .ret
  %if NRV2B_METHOD==M_NRV2B_8
		lodsb  ; Read next block to AL.
  %elif NRV2B_METHOD==M_NRV2B_LE16
		lodsw  ; Read next block to AX.
  %elif NRV2B_METHOD==M_NRV2B_LE32
		lodsd  ; Read next block to EAX.
  %endif
		xchg ebx, eax  ; BL/BX/EBX := new block; EAX := junk; higher_bits_of_EBX := junk.
		adc BLOCKREG, BLOCKREG  ; Sets the low bit of BLOCKREG to 1, and also sets CF to the previous high bit of BLOCKREG. That's becase the shifted-out high bit by the `add BLOCKREG, BLOCKREG' is always 1. This low bit in BLOCKREG will become the shifted-out high bit later.
  .ret:		ret
  .done:	; Now we are done with decompression. EDI == address of end of uncompressed data output.
  %define UDATA_END_REG edi
%elif METHOD==M_NRV2B_LE32 || METHOD==M_NRV2B_LE16 || METHOD==M_NRV2B_8
  ; Must keep EBP intact. Stack usage: 4 bytes.
  decompress_nrv2b:  ; 143 bytes for M_NRV2B_LE32 and for M_NRV2B_8. Based on upx-3.94-src/src/stub/src/arch/i386/nrv2b_d32.S: ucl_nrv2b_decompress_le32 in 32-bit assembly.
		or edx, byte -1  ; Use EDX to store -last_m_off. Since the initial value is last_m_off == 1, EDX becomes -1 here.
		jmp short .start
  .x77:		movsb  ; Process an LZSS literal: copy a byte from the input byte stream to the output.
  .x78:		nrv_get_bit .start
  .x83:		jc short .x77
		xor eax, eax
		inc eax  ; EAX := 1. Now we will build m_off in EAX.
  .x88:		nrv_get_bit
		adc eax, eax
		nrv_get_bit
		jnc short .x88
		xor ecx, ecx  ; ECX := 0. Start building m_len in ECX.
		sub eax, byte 3
		jc short .xb6  ; This jumps if m_off == 2. This will reuse last_m_off as m_off, no need to change any registers.
		shl eax, byte 8
		lodsb
		xor eax, byte -1  ; EAX := -(EAX + 1). So EAX becomes the final -m_off.
		jz short .done  ; m_off == 0xffffffff (here EAX == 0) indicates end-of-stream (EOS). If this jumps, then EAX == 0 (indicating success). We ignore the return value.
		xchg edx, eax  ; Save -m_off (EAX) to -last_m_off (EDX); EAX := junk.
  .xb6:		nrv_get_bit
		adc ecx, ecx
		nrv_get_bit
		adc ecx, ecx
		jnz short .xef
		inc ecx
  .xd3:		nrv_get_bit
		adc ecx, ecx
		nrv_get_bit
		jnc short .xd3
		times 2 inc ecx  ; m_len += 2.
  .xef:		cmp edx, -0xd00
		adc ecx, byte 1  ; if (m_off > 0xd00) { m_len++; } m_len++;  ; But EDX is -last_m_off, so we do the negative.
		push esi  ; Process an LZSS reference: (length, distance) == (m_len, last_m_off) == (ECX, -EDX) pair by copying an already-built substring of the output.
		lea esi, [edi+edx]
		rep movsb  ; Copy the an already-built substring of the output. Can overlap itself.
		pop esi
		jmp strict near .x78
  .done:	; Now we are done with decompression. EAX == 0 (unused below); EDI == address of end of uncompressed data output.
  %define UDATA_END_REG edi
%elif METHOD==M_NRV2D_LE32 || METHOD==M_NRV2D_LE16 || METHOD==M_NRV2D_8  ; !! Write it shorter (too much `add ebx, ebx' ++ `jnz'.
  ; Must keep EBP intact. Stack usage: 4 bytes.
  decompress_nrv2d:  ; 164 bytes for M_NRV2D_LE32 and for M_NRV2D_8. Based on upx-3.94-src/src/stub/src/arch/i386/nrv2d_d32.S: ucl_nrv2d_decompress_le32 in 32-bit assembly.
		or edx, byte -1
		jmp short .start
  .x6c:		movsb
  .x6d:		nrv_get_bit .start
		jc short .x6c
		xor eax, eax
		inc eax
  .x7d:		nrv_get_bit
		adc eax, eax
		nrv_get_bit
		jc short .xa7
		dec eax
		nrv_get_bit
		adc eax, eax
		jmp short .x7d
  .xa7:		xor ecx, ecx
		sub eax, byte 3
		jc short .xbf
		shl eax, byte 8
		lodsb
		xor eax, byte -1
		jz short .done  ; If this jumps, then EAX == 0 (indicating success). We ignore the return value.
		sar eax, 1
		xchg edx, eax  ; EDX := EAX; EAX := junk.
		jmp short .xca
  .xbf:		nrv_get_bit
  .xca:		adc ecx, ecx
		nrv_get_bit
		adc ecx, ecx
		jnz short .xf8
		inc ecx
  .xdc:		nrv_get_bit
		adc ecx, ecx
		nrv_get_bit
		jnc short .xdc
		inc ecx
		inc ecx
  .xf8:		cmp edx, -0x500
		adc ecx, byte 1
		push esi
		lea esi, [edi+edx]
		rep movsb
		pop esi
		jmp strict near .x6d  ; !! Is there a shorter one?
  .done:	; Now we are done with decompression. EAX == 0 (unused below); EDI == address of end of uncompressed data output.
  %define UDATA_END_REG edi
%elif METHOD==M_NRV2E_LE32 || METHOD==M_NRV2E_LE16 || METHOD==M_NRV2E_8  ; !! Write it shorter (too much `add ebx, ebx' ++ `jnz'.
  ; Must keep EBP intact. Stack usage: 4 bytes.
  decompress_nrv2e:  ; 177 bytes for M_NRV2E_LE32 and for M_NRV2E_8. Based on upx-3.94-src/src/stub/src/arch/i386/nrv2d_d32.S: ucl_nrv2e_decompress_le32 in 32-bit assembly.
		or edx, byte -1
		jmp short .start
  .x6c:		movsb
  .x6d:		nrv_get_bit .start
		jc short .x6c
		xor eax, eax
		inc eax
  .x7d:		nrv_get_bit
		adc eax, eax
		nrv_get_bit
		jc short .xb6
		dec eax
		nrv_get_bit
		adc eax, eax
		jmp short .x7d
  .xa7:		nrv_get_bit
		adc ecx, ecx
		jmp short .x105
  .xb6:		xor ecx, ecx
		sub eax, byte 3
		jc short .xce
		shl eax, byte 8
		lodsb
		xor eax, byte -1
		jz short .done  ; If this jumps, then EAX == 0 (indicating success). We ignore the return value.
		sar eax, 1
		xchg edx, eax  ; EDX := EAX; EAX := junk.
		jmp short .xd9
  .xce:		nrv_get_bit
  .xd9:		jc short .xa7
		inc ecx
		nrv_get_bit
		jc short .xa7
  .xe9:		nrv_get_bit
		adc ecx, ecx
		nrv_get_bit
		jnc short .xe9
		inc ecx
		inc ecx
  .x105:	cmp edx, -0x500
		adc ecx, byte 2
		push esi
		lea esi, [edi+edx]
		rep movsb
		pop esi
		jmp strict near .x6d  ; !! Is there a shorter one?
  .done:	; Now we are done with decompression. EAX == 0 (unused below); EDI == address of end of uncompressed data output.
  %define UDATA_END_REG edi
%elif METHOD==M_LZMA  ; It is implemented right below.
%else
  %error ERROR_UNSUPPORTED_METHOD METHOD
  times -1 nop
%endif
%if METHOD==M_LZMA
  ; Must keep EBP intact (it will save and restore it). Stack usage: LZMA_PROBS_SIZE+368 bytes.
  %if COMPRESSED_LZMAD
    decompress_lzma_with_compressed_lzmad:
		pop edi  ; Restore EDI := address of start of uncompressed data output.
		pop eax  ; Restore EAX := address of the uncompressed LZMA decompressor function on the stack. This relies on read-write-execute stack (produced by `minicc', but not by GCC default).
		sub esp, strict dword LZMA_PROBS_SIZE  ; Won't be 7-bit.
		push strict dword LZMA_HEADER_DWORD  ; Won't be 7-bit.
		mov ebx, esp
		call eax  ; Call the uncompressed LZMA decompressor function on the stack. This relies on read-write-execute stack (produced by `minicc', but not by GCC default).
		; The uncompressed LZMA decompressor ends with leave ++ ret.
		; We will do the outer `leave' below. It's not safe if it
		; does the outer leave, because it would be running from an
		; unknown stack.
  %else
    decompress_lzma:
		push ebp
		mov ebp, esp  ; Corresponds to the outer leave below.
		sub esp, strict dword LZMA_PROBS_SIZE  ; Won't be 7-bit.
		push strict dword LZMA_HEADER_DWORD  ; Won't be 7-bit.
		mov ebx, esp
  %endif
  %if COMPRESSED_LZMAD
    ; Already done everything above.
    %define UDATA_END_REG eax
  %elif 1
    ; This only works with streamed LZMA data, i.e. which has the LZMA
    ; end-of-stream (EOS) == end-of-payload (EOP) marker at the end.
    ; (Effectively this makes it 5 or 6 bytes longer (see
    ; http://man.he.net/man1/lzma), but the decompressor becomes shorter,
    ; because it doesn't have to count the byts.
    ;
    ; UPX 3.94 doesn't generate the EOS marker, but our patched
    ; tools/upx-3.94-lzma-eos.upx does. xz-utils lzma(1) (`xz --format=lzma1')
    ; always creates the EOS marker.
    .lzma_d_cw:
		; Watcom C: #pragma aux LzmaDecodeV "LzmaDecodeAsm" __parm [__ebx] [__esi] [__edi] __value [__eax] __modify [__eax __ebx __ecx __edx __esi __edi]
		; unsigned char *LzmaDecodeV(CLzmaDecoderState *vs, const unsigned char *inStream, unsigned char *outStream);
		; Header: push ebp ++ mov ebp, esp
		; Footer: mov esp, ebp ++ pop ebp ++ ret. Will be removed.
		; Footer replacement for upxdc_lzmadf.bin: leave ++ leave ++ ret.
		; $ perl -0777 -pe 'die("bad header\n") if !m@\x55\x89\xe5@; die("bad footer\n") if !s@\x89\xec\x5d\xc3\Z@@' <lzma_d_cw.bin >upxdc_lzmad.bin
		; $ perl -0777 -pe 'die("bad header\n") if !m@\x55\x89\xe5@; die("bad footer\n") if !s@\x89\xec\x5d\xc3\Z@\xc9\xc3@' <lzma_d_cw.bin >upxdc_lzmadf.bin
		; $ tools/miniperl-5.004.04.upx upxdc.pl --raw --nrv2b --no-filter upxdc_lzmadf.bin upxdc_lzmadfb32.bin
		; info: running compressor: ./tools/upx-3.94-lzma-eos.upx -qq --best --no-lzma --nrv2b --no-filter -- upxdc_lzmadfb32.bin.tmp
		; info: UPX compression results: 2459 --> 1082 bytes, method NRV2B_LE32, filter none
		; info: written compressed output: upxdc_lzmadfb32.bin (1082 bytes, format raw, method NRV2B_LE32, filter none)
		; --nrv2b produces shorter output (in terms of decompressor+compressed_data) than --nrv2d or --nrv2e for the upxdc_lzmadf.bin payload.
		; $ tools/miniperl-5.004.04.upx upxdc.pl --truncate-nrv2b-le32 upxdc_lzmadfb32.bin
		; info: truncating NRV32B_LE32 file to 1077 bytes: upxdc_lzmadfb32.bin
		; $ tools/miniperl-5.004.04.upx upxdc.pl --raw --nrv2b --no-filter --expert-upx-tmp-format=com upxdc_lzmadf.bin upxdc_lzmadfb16.bin
		; info: running compressor: ./tools/upx-3.94-lzma-eos.upx -qq --best --crp-nrv-ms=99999 --no-lzma --nrv2b --no-filter -- upxdc_lzmadfb16.bin.tmp.com
		; info: UPX compression results: 2459 --> 1080 bytes, method NRV2B_LE16, filter none
		; info: written compressed output: upxdc_lzmadfb16.bin (1080 bytes, format raw, method NRV2B_LE16, filter none)
		; $ tools/miniperl-5.004.04.upx upxdc.pl --truncate-nrv2b-16 upxdc_lzmadle16.bin
		; info: truncating NRV2B_LE16 file to 1077 bytes: upxdc_lzmadfb16.bin
		; $ tools/miniperl-5.004.04.upx upxdc.pl --raw --nrv2b --no-filter --expert-upx-tmp-format=exe upxdc_lzmadf.bin upxdc_lzmadfb8.bin
		; info: running compressor: ./tools/upx-3.94-lzma-eos.upx -qq --best --crp-nrv-ms=99999 --no-lzma --nrv2b --no-filter -- upxdc_lzmadfb8.bin.tmp
		; info: UPX compression results: 2459 --> 1079 bytes, method NRV2B_8, filter none
		; info: written compressed output: upxdc_lzmadfb8.bin (1079 bytes, format raw, method NRV2B_8, filter none)
		; $ tools/miniperl-5.004.04.upx upxdc.pl --truncate-nrv2b-8 upxdc_lzmadfb8.bin
		; info: truncating NRV2B_8 file to 1076 bytes: upxdc_lzmadfb8.bin
		; !! Produce the FILTER==0x46 and FILTER==0x49 version of upxdc_lzmadf.bin, and reuse whichever filter is available.
		incbin LZMAD_BIN
    .lzma_d_cw.end:
    %define UDATA_END_REG eax
		leave  ; Equivalent to `mov esp, ebp' ++ `pop ebp', from LzmaDecodeAsm in LZMAD_BIN above.
  %else  ; Dummy output, for debugging.
		mov eax, 'DUMY'
		stosd
		pop eax  ; LZMA_HEADER_DWORD.
		stosd
		mov eax, LZMA_PROBS_SIZE
		stosd
		movsd
    %define UDATA_END_REG edi
  %endif
		leave  ; Outer leave.
%endif
		; Now we are done with decompression, UDATA_END_REG (EAX or EDI) == address of end of uncompressed data output.

unfilter:
%if FILTER==0
  %ifnidn (UDATA_END_REG), (eax)
		xchg eax, UDATA_END_REG  ; EAX := address of end of uncompressed data output. UDATA_END_REG := junk.
  %endif
		;pop eax  ; Not pushed (`FILTER!=0' above).
%elif FILTER==0x46 || FILTER==0x49 || (FILTER >= 1 && FILTER <= 6)
  ; This filter code must not modify EBP for FLAT, because FLAT relies on it to restore the stack.
  %if FILTER==0x46  ; Based on upx-3.94-src/src/stub/src/arch/i386/macros.S
    unfilter_ctok32_0x46:
  %elif FILTER==0x49  ; Based on upx-3.94-src/src/stub/src/arch/i386/macros.S
    unfilter_ctok32_jxx_0x49:
  %elif FILTER==0x01
    unfilter_ct16_e8_le_0x01:
  %elif FILTER==0x02
    unfilter_ct16_e9_le_0x02:
  %elif FILTER==0x03
    unfilter_ct16_e8e9_le_0x03:
  %elif FILTER==0x04
    unfilter_ct16_e8_be_0x04:
  %elif FILTER==0x05
    unfilter_ct16_e9_be_0x05:
  %elif FILTER==0x06
    unfilter_ct16_e8e9_be_0x06:
  %else
    %error ERROR_UNSUPPORTED_FILTER_LABEL FILTER
    times -1 nop
  %endif
  ; Hardcoding `pop edi ++ mov ecx, USIZE' here wouldn't make it shorter.
  %ifnidn (UDATA_END_REG), (edi)
		xchg edi, UDATA_END_REG  ; EDI := address of end of uncompressed data output. UDATA_END_REG := junk.
  %endif
		pop esi  ; ESI := address of start of uncompressed data output.
  %if SMART_DECOMPRESS_RETURNS_UDATA_END_PTR
		push edi
  %endif
		mov ecx, edi
		sub ecx, esi  ; ECX := size of uncompressed data output.
		mov edi, esi  ; EDI := ESI := address of start of uncompressed data output. One of them will be used as a base address (unchanged throughout .ckloop3).
  %if FILTER==0x46 || FILTER==0x49
		jmp short .ckstart
  .ckloop3:	mov al, [edi]
		inc edi
  %endif
  %if FILTER==0x46
		sub al, 0xe8  ; Matches both 0xe8 (call) and 0xe9 (jmp near).
		cmp al, 1
		ja short .ckcount
		cmp ecx, byte 4
		jc short .ckend
		mov eax, [edi]
		sub al, FILTER_CTO
		jnz short .ckcount
		xchg al, ah  ; Convert EAX from big-endian to little-endian here (and 2 more instructions).
		rol eax, 16
		xchg al, ah
		sub eax, edi
		add eax, esi  ; Add base address.
		sub ecx, byte 4
		stosd
    .ckstart:
  %elif FILTER==0x49
		cmp al, 0x80  ; Matches jxx near, i.e. a conditional jump with 4-byte target.
		jc short .ckloop2
		cmp al, 0x8f  ; .ckloop2
		ja short .ckloop2
		cmp byte [edi-2], 0xf
		jz short .ckmark
    .ckloop2:	sub al, 0xe8  ; Matches both 0xe8 (call) and 0xe9 (jmp near).
		cmp al, 1
		ja short .ckcount
    .ckmark:	cmp ecx, byte 4
		jc short .ckend
		mov eax, [edi]
		sub al, FILTER_CTO
		jnz short .ckcount
		xchg al, ah  ; Convert EAX from big-endian to little-endian here (and 2 more instructions).
		rol eax, 16
		xchg al, ah
		sub eax, edi
		add eax, esi ; Add base address.
		sub ecx, byte 4
		stosd
    .ckstart:	sub ecx, byte 1
		jc short .ckend
		mov al, [edi]
		inc edi
		jmp short .ckloop2
  %elif FILTER==0x01 || FILTER==0x02 || FILTER==0x04 || FILTER==0x05
    %if FILTER==0x01 || FILTER==0x04
      %define FILTER_OPCODE_BYTE 0xe8
    %elif FILTER==0x02 || FILTER==0x05
      %define FILTER_OPCODE_BYTE 0xe9
    %else
      %error ERROR_UNSUPPORTED_FILTER_FOR_OPCODE_BYTE FILTER
      times -1 nop
    %endif
		sub ecx, byte 3  ; This value has been tested and it works. (-2 would be incompatible with UPX, because it also matches right before EOF.)
		; The driver program is responsible to avoid new ECX <= 0 here.
    %if FILTER>=4
    .more1:	mov al, FILTER_OPCODE_BYTE
		repne scasb
		jne short .ckend
		mov ax, [edi]
		xchg al, ah  ; Convert word from big-endian to little-endian.
		sub eax, edi  ; The high word of EAX is ignored, but this instruction is 1 byte shorter than `sub ax, di'.
		add eax, esi  ; Add base address.
		stosw
    %else
		mov al, FILTER_OPCODE_BYTE
    .more:	repne scasb
		jne short .ckend
		sub [edi], di
		add [edi], si  ; Add base address.
		times 2 inc edi
    %endif
		sub ecx, byte 2
		ja short .more
  %elif FILTER==0x03  || FILTER==0x06
		lea ecx, [ecx+esi-3]  ; This value has been tested and it works. (-2 would be incompatible with UPX, because it also matches right before EOF.)
		; The driver program is responsible to avoid new ECX <= ESI here.
    .next_byte:	lodsb
		sub al, 0xe8
		cmp al, 1
		ja short .try_next
    %if FILTER>=4
		rol word [esi], 8  ; Convert word from big-endian to little-endian.
    %endif
		sub [esi], si
		add [esi], di  ; Add base address.
		times 2 inc esi
    .try_next:	cmp esi, ecx  ; !! To save space, the driver could hardcode the number of repacements to ECX, and thus just do a `loop' here.
		jb short .next_byte
  %else
    %error ERROR_UNSUPPORTED_FILTER_IMPL FILTER
    times -1 nop
  %endif
  %if FILTER==0x46 || FILTER ==0x49
  .ckcount:	sub ecx, byte 1
		jnc short .ckloop3
  %endif
  .ckend:
  %if SMART_DECOMPRESS_RETURNS_UDATA_END_PTR
		pop eax  ; EAX := address of end of uncompressed data output.
  %endif
%else
  %error ERROR_UNSUPPORTED_FILTER FILTER
  times -1 nop
%endif

return_from_smart_decompress:
%ifdef DECOMPRESS32
		mov [esp+7*4], eax  ; Will return the current EAX even though the `popa' below.
		popa
		ret
%elifdef FLAT32
		mov esp, ebp  ; Restore original caller ESP.
		popa  ; Doesn't pop ESP.
		popf
		ret
%elifdef FLAT16_386
  .to_real:  ; Switch back to (16-bit) real mode. This is position-independent code.
		; This works in 86Box-4.2.1, Intel 430VX chipset, Pentium-S P54C 90 MHz
		; CPU. What didn't work there (but worked in QEMU 2.11.1, VirtualBox and
		; https://copy.sh/v86) is a far jump with a 32-bit offset to a 16-bit
		; protected mode segment.
		;
		; We assume that the GDT in flat16_386_start is no longer valid, so we set up our own GDT:
		;
		; %define BACK16_BASE LINEAR_ADDRESS_OF_COPIED(.s16base).
		; Segment 8 descriptor (back16): 16-bit, code, read-execute, base 0, limit 4GiB-1, granularity 0x1000. Used for switching back to real mode.
		; dw 0xffff, (BACK16_BASE)&0xffff, 0x9e00|(((BACK16_BASE)>>16)&0xff), 0x8f|(((BACK16_BASE)>>24)&0xff)<<8
  %ifdef FLAT16_SEGMENT
                lgdt [FLAT16_COPIED_LINEAR(.gdtr)]
    .s16base:  ; The exact location doesn't matter, but it must be before .prot16.
  %else  ; This is for position-independent code. We put .gdtr and .gdt to the stack. This works, and it is much shorter than the alternative.
		call .s16base
    .s16base:	pop eax  ; EAX := linear address of .s16base. Tht will be the base of segment 8 in the GDT.
    %if 1  ; Only if EAX < (1 << 24), i.e. we are in the low 16 MiB physical memory. That's true, we are in the low 1 MiB, because we came from real mode.
		push word 0x8f
		or eax, 0x9e000000
    %else  ; This is only 5 bytes longer than its alternative, but it supports this code running in the full 4 GiB range.
		rol eax, 8
		mov ch, al
		mov cl, 0x8f
		push cx  ; Last word of the segment 8 descriptor.
		mov al, 0x9e
		ror eax, 8
    %endif
		push eax  ; Middle two words of the segment 8 descriptor.
		push word -1  ; First word of the segment 8 descriptor.
		lea eax, [esp-8]  ; EAX := address of the GDT.
		push eax  ; GDT base field of the GDTR.
		push word 2*8-1  ; GDT limit of the GDTR.
		lgdt [esp]
  %endif
		dw 0xea66, .prot16-.s16base, 8  ; 6-byte far jump with 16-bit offset to segment 8 (back16). 1 byte shorter than a `push dword' ++ `o16 retf'.
  bits 16
  .prot16:	;add esp, byte 6+8  ; No stack cleanup needed (6 for the GDTR, 8 for the GDT), since we are overwriting the ESP below. We don't need the old GDT in memory, since we won't ever load any segment registers from it.
		mov eax, cr0
		and al, byte ~1  ; PE := 0. Leave protected mode, enter real mode.
		mov cr0, eax
		; There seems to be no need to do a far jump to .real2 just
		; yet (see https://stackoverflow.com/q/79551879 for
		; details). Thus we remain in 16-bit protected mode (based
		; on the descriptor of CS) until the `iret' below.
		mov ss, bp  ; Restore SS from value saved to the low word of EBP by flat16_386_start.to_protected.
		shr ebp, 16  ; This will also set the high word of ESP to 0, which is needed by subsequent QEMU 2.11.1 SeaBIOS int 10h AH == 0eh (character write).
		mov esp, ebp  ; Restore original caller SP, with high word of ESP set to 0. Now SS:SP and SS:ESP are both valid, we can use the stack.
		sub word [bp+8*4+4], byte flat16_386_start.to_protected-payload  ; Adjust the destination of the `iret' below back to payload. Originally it was flat16_386_start.to_protected. This is BYTE_DIFF3
  %if flat16_386_start.to_protected-payload>0x7f
    %error ERROR_BYTE_DIFF3_TOO_LARGE  ; See BYTE_DIFF3 elsewhere in this file.
    times -1 nop
  %endif
		popad  ; Restore.
		pop es  ; Restore. Also overwrites the descriptor from protected mode.
		pop ds  ; Restore. Also overwrites the descriptor from protected mode.
		;mov fs, ax  ; No need, we don't use it.
		;mov gs, ax  ; No need, we don't use it.
		iret  ; It also enables interrupts, because it restores the flags. It doesn't restore SS or SP in this case.
  %ifdef FLAT16_SEGMENT
  .gdtr:	dw .gdt_end-.gdt-1  ; GDT limit.
		dd FLAT16_COPIED_LINEAR(.gdt)  ; GDT base.
  .gdt: equ $-8  ; We use arbitrary values for segment 0, hence the -8. No need to align this to a multiple of 4, since it is only used in the `mov ds, ...' instructions, not for regular data access.
		; Segment 8 descriptor (back16): 16-bit, code, read-execute, base 0, limit 4GiB-1, granularity 0x1000. Used for switching back to real mode.
		dd (FLAT16_COPIED_LINEAR(.s16base)&0xffff)<<16|0xffff, 0x8f9e00|((FLAT16_COPIED_LINEAR(.s16base)>>24)&0xff)<<24|((FLAT16_COPIED_LINEAR(.s16base)>>16)&0xff)
  .gdt_end:
  %endif
  bits 32  ; Doesn't matter much, we'll get incbins anyway.
%else
  %error ERROR_RETURN_UNKNOWN
  times -1 nop
%endif

global compressed_data_pre
compressed_data_pre:
%if METHOD==M_LZMA && COMPRESSED_LZMAD
		incbin CLZMAD_BIN  ; !! Compress it even more with `xz --format=lzma --lzma1=...'.
; compressed_data must follow directly here, we rely on an increasing ESI after the M_NRV2B_LE32 decompression of compressed_data_pre.
%endif

global compressed_data
compressed_data:  ; For FLAT, this is actually compressed machine code.
%ifdef CDATAFN
		incbin CDATAFN, CDATASKIP
%endif

%if FLAT
  global payload_end
  global _payload_end
  payload_end:
  _payload_end:
%endif

; __END__
