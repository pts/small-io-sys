;
; nrv2_exe.nasm: build DOS .exe (8086, 16-bit) from NRV2-compressed DOS .exe
; by pts@fazekas.hu at Sun Apr  6 14:57:07 CEST 2025
;
; Compile with: nasm -O0 -w+orphan-labels -f bin -DUPXEXEFN="'myupxed.exe'" -D...=... -o myout.exe nrv2_exe.nasm
; Minimum NASM version needed: 0.98.39
;

%ifndef CPU  ; Specified on the command line. Typically 8086, 186 or 386.
  %define CPU 8086  ; Most compatible.
%elif CPU==8086
  %define CPU 8086
%elif CPU==186
  %define CPU 186
%else
  ;%assign CPU CPU
  %define CPU 286  ; We don't need more.
%endif

%ifndef UPXEXEFN  ; Specified on the command line.
  %error ERROR_MISSING_UPXEXEFN
  db 1/0
%endif

%ifdef C_SP  ; Must not be specified on the command line.
  %error ERROR_UNEXPECTED_C_SP C_SP
  db 1/0
%endif
%ifdef C_MINALLOC  ; Must not be specified on the command line.
  %error ERROR_UNEXPECTED_C_MINALLOC C_MINALLOC
  db 1/0
%endif
%ifdef C_MAXALLOC  ; Must not be specified on the command line.
  %error ERROR_UNEXPECTED_C_MAXALLOC C_MAXALLOC
  db 1/0
%endif

; UPX compression method constants.
M_NRV2B_LE32    equ 2
M_NRV2B_8       equ 3
M_NRV2B_LE16    equ 4
M_NRV2D_LE32    equ 5
M_NRV2D_8       equ 6
M_NRV2D_LE16    equ 7
M_NRV2E_LE32    equ 8
M_NRV2E_8       equ 9
M_NRV2E_LE16    equ 10
M_LZMA          equ 14

; !! Better parsing of command-line %defines.
%assign CPU CPU
%assign METHOD METHOD  ; M_NRV2B_8, M_NRV2D_8 or M_NRV2E_8.
%assign FILTER FILTER
%assign FILTER_CHANGE_COUNT FILTER_CHANGE_COUNT
%assign CSIZE CSIZE
%assign CDATASKIP CDATASKIP
%assign USIZE USIZE
%assign CRELOC_SIZE CRELOC_SIZE
%assign U_MINALLOC U_MINALLOC
%assign U_MAXALLOC U_MAXALLOC
%assign U_SP U_SP
%assign U_SS U_SS
%assign OVERLAP OVERLAP
%assign MAXDIST MAXDIST
%assign U_BASE_SIZE U_BASE_SIZE

; ---

bits 16
cpu CPU

%if CSIZE>0xffff
  %error ERROR_CSIZE_TOO_LARGE_FOR_DECOMPRESSOR CSIZE  ; DO_ADJUST_C_SEG not implemented.
  db 1/0
%endif
%if USIZE>0xffff
  %error ERROR_USIZE_TOO_LARGE_FOR_DECOMPRESSOR USIZE  ; DO_ADJUST_U_SEG not implemented.
  db 1/0
%endif
%if METHOD==M_NRV2B_LE16 || METHOD==M_NRV2D_LE16 || METHOD==M_NRV2E_LE16
  %define BLOCKREG bx
  %define BLOCKBITC 16
%elif METHOD==M_NRV2B_8 || METHOD==M_NRV2D_8 || METHOD==M_NRV2E_8
  %define BLOCKREG bl
  %define BLOCKBITC 8
%else
  %error ERROR_UNSUPPORTED_METHOD METHOD
  db 1/0
%endif

%macro assert_fofs 1
  times +(%1)-($-$$) times 0 nop
  times -(%1)+($-$$) times 0 nop
%endm
%macro assert_at 1
  times +(%1)-$ times 0 nop
  times -(%1)+$ times 0 nop
%endm

exe_header:  ; DOS .exe header: http://justsolve.archiveteam.org/wiki/MS-DOS_EXE
.signature:	db 'MZ'
.lastsize:	dw  exe_image_size_hdr&0x1ff  ; Length of load module mod 0x200.
.nblocks:	dw (exe_image_size_hdr+0x1ff)>>9  ; Number of 0x200 pages in load module.
.nreloc:	dw 0  ; Number of relocation items; no relocations.
.hdrsize:	dw (exe_image-exe_header)>>4  ; Size of header in paragraphs.
.minalloc:	dw C_MINALLOC  ; Minimum number of paragraphs required above load module.
.maxalloc:	dw C_MAXALLOC  ; Maximum number of paragraphs required above load module.
.ss:		dw C_SS  ; Offset of stack segment in load module.
.sp:		dw C_SP  ; Initial value of SP.
.checksum:	dw 0  ; Checksum.
.ip:		dw exe_start-exe_image  ; Initial value of IP.
.cs:		dw 0  ; Offset of code segment within load module (segment).
.relocpos:	dw 0  ; File offset of first relocation item.  ; !! Use .hdrsize==0, overlap header and image. Save 8 bytes starting from .relocpos.
.noverlay:	dw 0  ; Overlay number.

relocs:  ; At file offset 0x1c. Relocations. 4 bytes each.
.0:		dw 0, 0  ; (offset, segment). Unused beause UPXEXEFN is the output file of `upx --no-reloc'.
		times (exe_header-$)&0xf db 0  ; Align to paragraph boundary (0x10).
exe_image:

exe_start:  ; Compressed .exe entry point.
setup_code:
		; !! Do a simpler copy if the compressed input file (including the decompressor) is short enough.
		mov cx,  ((copy_source_end-compressed_data+1)>>1)&0x7fff
		mov si, (((copy_source_end-compressed_data+1)&~1)-2)&0xffff
		mov di, si
		push ds  ; Save PSP_segment. Will be popped by `pop es' in jump_to_program.
		db 0xa9  ; Opcode byte for `test ax, strict word ...'.
.next_64k:	mov ch, 0x10000>>9
		mov ax, cs
		add ax, strict word (compressed_data-exe_image)>>4  ; Self-modifying code below modifies this number.
.delta_high_byte: equ $-1
		mov ds, ax
		add ax, strict word COPY_DELTA  ; Measured in paragraphs (0x10 bytes).
		mov es, ax
		std
		rep movsw
		cld  ; Now SI == DI == 0xfffe == -2.
		sub byte [cs:si+2+.delta_high_byte-exe_start], 0x10000>>12  ; Self-modifying code, modifies the argument of the add at @0xe above.
		jnc short .next_64k
		xchg ax, dx
		scasw  ; SI += 2. SI := 0. With side effect.
		lodsw  ; DI += 2. DI := 0. With side effect.
		push cs  ; Save orig_load_base_CS. Will be popped by `pop bp' in restore_bp_cs.
%if CRELOC_SIZE
		push cs  ; Save orig_load_base_CS. Will be popped by `pop bx' in apply_relocations. This is an extra `push cs' as compared to an .exe file without reloactions. !! Reorganize.
%endif
		push cs  ; Will be popped right below by `pop es'.
		push es  ; Will be popped right below by `pop ds'.
		pop ds
		pop es
		push ss  ; Will be popped right below by `retf'. Because of this `push ss', OVERLAP, COPY_DELTA and C_SS must correspond to each other.
		mov BLOCKREG, 1<<(BLOCKBITC-1)  ; 0x80 or 0x8000.
%if LASTMOFF1
		mov bp, -1  ; last_m_off := 1 (-BP).
%endif
%if CPU==8086
		mov ax, ((decompress.start-exe_image)&0xf)
		push ax  ; Will be popped right below by `retf'.
%else
		push byte ((decompress.start-exe_image)&0xf)
%endif
		retf
; !! For paragraph alignment purposes, make this 5 bytes shorter, move code to decompress_nrv2b_8, skip over first byte `movsb' with `test al, ...'.

align_before_compressed_data:
		times (exe_image-$)&0xf db 0  ; !! Get rid of this alignment by making the (long) copy above smarter.

compressed_data:  ; With method M_NRV2B_8.
		incbin UPXEXEFN, CDATASKIP, CSIZE
.end:
MIN_STACK_SIZE equ 0x80
MIN_COPY_DELTA equ (OVERLAP-(compressed_data-exe_image)+0xf)>>4  ; Measured in paragraphs (0x10 bytes).
MIN_C_SS equ ((compressed_data.end-exe_image)>>4)+MIN_COPY_DELTA  ; Measured in paragraphs (0x10 bytes).
MIN_C_SP equ 0x200  ; UPX default. !! Try smaller, calculate it (later) as: MIN_C_SP equ copy_source_end-(decompress-((exe_image-decompress)&0xf))+MIN_STACK_SIZE
%if MIN_C_SS<=U_SS && MIN_C_SP<=U_SP
  C_SS equ U_SS  ; This makes the decompressor shorter, because `lea ax, [...]' ++ `mov ss, ax' is not needed in jump_to_program.
%else
  C_SS equ MIN_C_SS
%endif
COPY_DELTA equ C_SS-((compressed_data.end-exe_image)>>4)
%if C_SS==U_SS && MIN_C_SP<=U_SP
  C_SP equ U_SP
%else
  C_SP equ MIN_C_SP
%endif

decompress:
%if METHOD==M_NRV2B_8 || METHOD==M_NRV2B_LE16
  ; This implementation doesn't work if CSIZE>0xffff or USIZE>0xffff.
  .literal:	movsb  ; Process an LZSS literal: copy a byte from the input byte stream to the output.
  .start:
  .next_token:	call .get_bit  ; Read token type: CF == 0 means match, CF == 1 means literal.
		jc short .literal
		; Start reading m_off to CX. CX is 0 now, see `xor cx, cx' above.
		inc cx  ; CX := 1.
  .next_m_off_bit:
		call .read_varint_bit
		; This finishes the decompression if we've read 16
		; consecutive 0 bits from the varint (i.e. the first 32 bits
		; of 000000000000000000000000000000000000000000001001).
		; This is good enough for outputs smaller than 1<<24 bytes.
		jcxz .done  ; Would be incorrect with `jecxz'. Correctly increases SI only if compressed data has been processed by `upfx.pl --truncate-nrv2b-le32'.
		jnc short .next_m_off_bit  ; CF == 0 means continue reading more varint bits.
		sub cx, byte 3
		jc short .get_m_len  ; Jump if m_off == 2. (And use -last_m_off in BP for the offset.)
		mov ah, cl  ; AX := CL<<8; AL := junk.  We store only the lowest word of m_off in AX. This is without overflow, because DO_ADJUST_U_SEG==0 implies USIZE<=0xffff, which implies m_off<0x10000.
		lodsb  ; Read 8 more bits (m_off_low_byte).
		not ax  ; AX := -(AX + 1). This completes formula: m_off := m_off_from_varint - 3) * 256 + m_off_low_byte.
		xchg bp, ax  ; BP := AX; AX := junk. BP becomes the final -last_m_off.
  .get_m_len:  ; Start reading m_len to CX.
		xor cx, cx  ; CX := 0, the initial value of m_len.
		call .read_varint_bit  ; Reads first bit from the bottom of CX.
		adc cx, cx  ; Reads second bit from the bottom of CX.
		jnz short .maybe_adjust_m_len
		; The first 2 bits read were 0, so read a varint (more bits of m_len) into CX.
		inc cx
  .next_m_len_bit:
		call .read_varint_bit
		jnc short .next_m_len_bit  ; CF == 0 means continue reading more varint bits.
		; m_len += 2. (This is part of the NRV2B algorithm.)
		times 2 inc cx  ; m_len += 2.
  .maybe_adjust_m_len:  ; if (m_off > 0xd00) { m_len++; } m_len++;
  %if MAXDIST<0 || MAXDIST>0xd00
		cmp bp, -0xd00
		adc cx, byte 1  ; if (m_off > 0xd00) { m_len++; } m_len++;  ; But BP is -last_m_off, so we do the negative.
  %else
		inc cx  ; Just do the unconditional m_len++.
  %endif
  .copy_match:  ; Process an LZSS match: (distance, length) == (last_m_off, m_len) == (CX, -BP) pair by copying an already-built substring of the output.
		xchg ax, si  ; Save SI; SI := junk.
		lea si, [di+bp]  ; AX := source offset for the match. BP is now -last_m_off.
		es rep movsb  ; Copy the an already-built substring of the output. Can overlap itself. Also sets CX := 0 at the end.
		xchg si, ax  ; Restore SI; AX := junk.
		jmp short .next_token
  .read_varint_bit:  ; Reads a bit to CX (shifting it left, setting its low bit). Then it reads the continuation bit to CF.
		call .get_bit
		adc cx, cx
		; Falls through to .get_bit for reading the continuation bit.
  .get_bit:  ; Reads a bit from the input bit stream to CF. Ruins AX. Updates BX, reads another block if needd.
		add BLOCKREG, BLOCKREG
		jnz short .ret
		; Now CF == 1, because the highest bit of BLOCKREG was 1 before the `add'.
  %if BLOCKBITC==8
		lodsb  ; Read next block to AL.
  %elif BLOCKBITC==16
		lodsw  ; Read next block to AX.
  %endif
		xchg bx, ax  ; BL/BX := new block; AX := junk; higher_bits_of_BX := junk.
		adc BLOCKREG, BLOCKREG  ; Sets the low bit of BLOCKREG to 1, and also sets CF to the high bit of BLOCKREG. That's becase the shifted-out high bit by the `add BLOCKREG, BLOCKREG' is always 1. This low bit in BLOCKREG will become the shifted-out high bit later.
  .ret:		ret
  .done:	; Now we are done with decompression. ES:DI == address of end of uncompressed data output.
%elif METHOD==M_NRV2D_8 || METHOD==M_NRV2D_LE16 || METHOD==M_NRV2E_8 || METHOD==M_NRV2E_LE16  ; !! Implement these, the short version.
  .start:
  %error ERROR_UNIMPLEMENTED_METHOD METHOD
  db 1/0
%else
  .start:
  %error ERROR_UNSUPPORTED_METHOD METHOD
  db 1/0
%endif

after_decompress:

unfilter:
%if FILTER && FILTER_CHANGE_COUNT && 0  ; !! Remove `^&& 0'. !! Untested.
  %if FILTER<1 || FILTER>6
    %error ERROR_UNSUPPORTED_FILTER FILTER
    db 1/0
  %endif
		; This code must preserve ES, because apply_relocations needs it.
		xor si, si
		pop ds  ; Restore DS := orig_load_base_CS.
		push ds  ; Push orig_load_base_CS back, subsequent code will need it. !! Maybe move it to setup_code, if there is more room there.
		mov cx, FILTER_CHANGE_COUNT&0xffff
  %if FILTER_CHANGE_COUNT>0xffff
		mov bp, FILTER_CHANGE_COUNT>>16
  %endif
  .next:	lodsb
  %if (FILTER % 3)==1  ; 0xe8: call only.
		cmp al, 0xe8
		je short .apply_change
  %elif (FILTER % 3)==2  ; 0xe9: jmp near only.
		cmp al, 0xe8
		je short .apply_change
  %else  ; 0xe8 and 0xe9: both call and jmp near.
		sub al, 0xe8  ; Filters 0x03 and 0x06 match on both 0xe8 and 0xe9.
		cmp al, 1
		ja short .next
  %endif
  .apply_change:
		lodsw
  %if FILTER>3
		xchg al, ah  ; Change back from big-endian to little-endian. Filters 0x04..0x06 need it.
  %endif
		sub ax, si
		times 2 inc ax
		mov [si-2], ax
		loop .next  ; Incorrect if FILTER_CHANGE_COUNT==0, so we have an `%if' above to avoid this here.
  %if FILTER_CHANGE_COUNT>0x10000
		dec bp
		jnz short .next
  %endif
%endif  ; %if FILTER && FILTER_CHANGE_COUNT

restore_bp_cs:
		pop bp  ; Restore BP := orig_load_base_CS, set up by setup_code. This is the relocation delta that will be added to each segment value.

apply_relocations:
%if CRELOC_SIZE
		push es  ; Will be popped right below by `pop ds'.
		pop ds
		lea si, [word di-CRELOC_SIZE]  ; Compressed relocation info at the end of udata.
		lodsw
		pop bx  ; Restore BX := orig_load_base_CS. This will be used as a segment value and increased in the loop below so that BX:DI points to the next word to which the relocation delta should be added.
		xchg ax, cx  ; CX := 0x35. First word loaded from compressed_relocation_info.
		lodsw
		xchg ax, dx  ; DX := 0x19f. Seems to be the same as U_CS. Second word loaded from compressed_relocation_info.
		lodsw
		xchg ax, di  ; DI := 0x8. Third word loaded from compressed_relocation_info.
		lodsw  ; AX (paragraph_offset) := 0xa. Fourth word loaded from compressed_relocation_info.
		add bx, ax  ; base_segment += paragraph_offset.
		mov es, bx
		xor ax, ax
.next0:		add di, ax
		add [es:di], bp  ; Apply single relocation: add relocation delta (BP == orig_load_base_CS) to a segment value.
.load:		lodsb  ; AH == 0; loads AL := skip_code.
		dec ax
		jz short .next_block  ; skip_code==1 means: DI += 0xfe, and load next block if not EOF.
		inc ax
		jnz short .next0  ; skip_code>=2 means: DI += skip_code.
		inc di  ; Otherwise, skip_code==0. Process it by scanning udata (.exe image).
.scan:		inc di
		cmp byte [es:di], 0x9a  ; 0x9a is the opcode of the far call (`call SEGMENT:OFFSET') instruction.
		jnz short .scan
		cmp [es:di+3], dx  ; DX == 0x19f (== U_CS). Compare the SEGMENT in the far call to limit (in DX).
		ja short .scan  ; If SEGMENT value is larger than DX (== U_CS) (why not too low??), then don't apply the relocation.
		mov al, 3  ; Skip over the far call opcode and the offset. Relocation will be applied to the Segment.
		jmp short .next0
.next_block:	add di, 0xfe
		loop .load
%endif

jump_to_program:
		pop es  ; Restore ES := PSP_segment.
		push es  ; Will be popped right below by `pop ds'.
		pop ds  ; DS := PSP_segment.
%if C_SS!=U_SS
  %if CPU==8086  ; Play it extra safe for old, broken 8086, which doesn't disable interrupts after `mov ss, ...'.
		pushf
		cli
  %endif
  %if U_SS>=-0x80 && U_SS<=0x7f
		lea ax, [byte bp+U_SS]  ; AX := BP+sp_from_real_exe_header. The original exe_header.ss could be patched here.
  %else
		lea ax, [word bp+U_SS]  ; AX := BP+sp_from_real_exe_header. The original exe_header.ss could be patched here.
  %endif
		mov ss, ax
%endif
%if C_SP!=U_SP
		mov sp, U_SP
%endif
%if U_CS==0
%elif U_CS>=-0x80 && U_CS<=0x7f
		add bp, byte U_CS
%else
		add bp, strict word U_CS
%endif
		push bp  ; orig_load_base_CS. Will be popped by the `retf' below.
%if CPU==8086
		mov ax, U_IP  ; Will be popped by the `retf' below.
		push ax  ; U_IP.
%elif U_IP>=-0x80 && U_IP<=0x7f
		push byte U_IP
%else
		push strict word U_IP
%endif
%if C_SS!=U_SS && CPU==8086
		iret
%else
		retf
%endif

copy_source_end:

MIN_MEM_FOR_COMPRESSION equ (C_SS<<4)+C_SP
%if copy_source_end-exe_image+MIN_STACK_SIZE>MIN_MEM_FOR_COMPRESSION
  %error ERROR_MEM_USAGE_LARGER_THAN_STACK_END
  db 1/0
%endif

;exe_image_size_nohdr equ $-exe_image  ; Unused.
exe_image_size_hdr equ $-exe_header

C_BASE_SIZE equ ((exe_image_size_hdr+0x1ff)>>9<<(9-4))-((exe_image-exe_header)>>4)
MIN_C_MINALLOC equ ((MIN_MEM_FOR_COMPRESSION+0xf)>>4)-C_BASE_SIZE  ; Measured in paragraphs (0x10 bytes).
%if U_MINALLOC==0 || U_MINALLOC==0xffff
  C_MINALLOC equ U_MINALLOC
%else
  %if C_BASE_SIZE+MIN_C_MINALLOC>U_BASE_SIZE+U_MINALLOC
    C2_MINALLOC equ MIN_C_MINALLOC
  %else
    C2_MINALLOC equ U_MINALLOC+U_BASE_SIZE-C_BASE_SIZE
    ; !! Report UPX bug: the C_MINALLOC value calculated by UPX 3.94 is too small. Our value is correct (verified).
  %endif
  %if C2_MINALLOC<1
    C_MINALLOC equ 1
  %elif C2_MINALLOC>0xffff
    %error ERROR_COMPRESSED_EXE_NEEDS_TOO_MUCH_MEMORY
    db 1/0
    C_MINALLOC equ 0xffff
  %else
    C_MINALLOC equ C2_MINALLOC
  %endif
%endif
%if U_MAXALLOC==0 || U_MAXALLOC==0xffff
  C_MAXALLOC equ U_MAXALLOC
%else
  %if C_BASE_SIZE+MIN_C_MINALLOC>U_BASE_SIZE+U_MAXALLOC
    C2_MAXALLOC equ MIN_C_MINALLOC
  %else
    C2_MAXALLOC equ U_MAXALLOC+U_BASE_SIZE-C_BASE_SIZE
    ; !! Report UPX bug: the C_MAXALLOC value calculated by UPX 3.94 is too small. Our value is correct (verified).
  %endif
  %if C2_MAXALLOC<1
    C_MAXALLOC equ 1
  %elif C2_MAXALLOC>0xffff
    C_MAXALLOC equ 0xffff
  %else
    C_MAXALLOC equ C2_MAXALLOC
  %endif
  %if C_MAXALLOC<C_MINALLOC && C_MINALLOC!=0 && C_MINALLOC!=0xffff  ; Should not happen.
    %error ERROR_COMPRESSED_EXE_MAXALLOC_SMALLER_THAN_MINALLOC
    db 1/0
  %endif
%endif

; __END__
