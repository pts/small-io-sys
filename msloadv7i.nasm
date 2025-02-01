;
; msloadv7i.nasm: an improved implementation of MS-DOS v7 msload
; by pts@fazekas.hu at Mon Jan 13 10:52:15 CET 2025
;
; Compile with: nasm -O0 -w+orphan-labels -f bin -o IO.SYS.win98cdn7.1i msloadv7i.nasm
; Minimum NASM version required to compile: 0.98.39
;
; Improvements over MS-DOS 7.1 (particularly Windows 98 SE) msload:
;
; * 832 bytes (== 0x340) instead of 2048 bytes (== 0x800 bytes, 4 sectors).
; * It can load a fragmented io.sys.
; * It uses 8086 instructions only (no 386).
; * It can load an io.sys which is not longer than `mz_header.hdrsize<<4`
;   bytes. (The original sometimes needs a weird alignment of
;   mz_header.hdrsize for that.)
;
; Limitations:
;
; * Reads a single sector at a time. It could do batches of up to 0x40
;   sectors == 0x8000 bytes, as long as they are contiguous on disk.
;   However, there is no space (in 0x340 bytes) to implement batching.
; * It is not able load and decompress the Windows ME compressed msbio
;   payload. (But it is able to load the uncompressed version in the
;   unofficial MS-DOS 8.0 based on Windows ME: MSDOS8.ISO on
;   http://www.multiboot.ru/download/).
;
; For documentation, see https://retrocomputing.stackexchange.com/a/15598 and
; https://pushbx.org/ecm/doc/ldosboot.htm#protocol-sector-msdos7
;
; Memory layout:
;
; * 0...0x400: Interrupt table.
; * 0x400...0x500: BIOS data area.
; * 0x500...0x700: Unused.
; * 0x700...0x40700: Load location of the msbio part of io.sys. We will load it, and then do the far jump `jmp 0x70:0'. Maximum io.sys file size after msload (i.e. msbio payload size): 256 KiB - 0x100 bytes.
; * 0x40700..0x40800: (0x4000:0x700) Our stack after cont_relocated. Memory address of its end: SS:0x800 == SS:BP.
; * 0x40800..0x40c00: (0x4000:0x800) For non-TIGHT, our relocated msload code and data: CS:0x800 == DS:0x800 == ES:0x800 == SS:0x800 == SS:BP. Use `[bp-$$+var....]` for access, and `-rorg+var....` to get the address. (See .setup_reloc_segment for alternative address values.) The `-$$` is a displacement size optimization (from 2 to 1 byte).
; * 0x40800..0x41000: (0x4000:0x800) For TIGHT, our relocated msload code and data + msbio prefix: CS:0x800 == DS:0x800 == ES:0x800 == SS:0x800 == SS:BP. Same address, but longer than non-TIGHT.
; * 0x40c00..0x40e00: (0x40b0:0x100) For non-TIGHT, cached sector read from the FAT.
; * 0x41000..0x41400: (0x40f0:0x100) For TIGHT, cached sector read from the FAT.
;

bits 16
cpu 8086
org 0  ; Base offfsets are added manually where needed.

%macro assert_fofs 1
  times +(%1)-($-$$) times 0 nop
  times -(%1)+($-$$) times 0 nop
%endm

%ifndef JUST_MSLOAD
  %define ORIG_IO_SYS 'IO.SYS.win98cdn7.1app'
  ;%define ORIG_IO_SYS 'IO.SYS.win98se'
%endif

%ifndef MSLOAD_SECTOR_COUNT  ; Can be 0, 2 or 4. 4 for compatibility.
  %define MSLOAD_SECTOR_COUNT 0
%endif

%if MSLOAD_SECTOR_COUNT==0
  %define MSLOAD_SECTOR_COUNT 2
  %define TIGHT  ; Overlap the prefix of the msbio payload to the second sector.
%endif

%ifdef TIGHT  ; Overlap the prefix of the msbio payload to the second sector.
  %if MSLOAD_SECTOR_COUNT!=2
    %error DTIGHT_REQUIRES_DMSLOAD_SECTOR_COUNT_2  ; '-DTIGHT requires -DMSLOAD_SECTOR_COUNT=2'
    db 1/0
  %endif
  %define EXTRA_SKIP_SECTOR_COUNT 2  ; 2 sectors at 0x400 are already loaded by the boot sector.
%else
  %define EXTRA_SKIP_SECTOR_COUNT 0
%endif

; The following overlap in memory (fat_header, bpb, var, mz_header,
; load_code). It's OK, because we don't use everything at the same time.

; More info about FAT12, FAT16 and FAT32: https://en.wikipedia.org/wiki/Design_of_the_FAT_file_system
fat_header:  ; https://en.wikipedia.org/wiki/Design_of_the_FAT_file_system#Boot_Sector
;.jmp_inst_word:
;.chs_or_lba: equ fat_header+2  ; db. 0x90 for CHS. Another possible value is 0x0e for LBA (and 0x0c is also for LBA). Windows 95 OSR2, Windows 98 and Windows ME boot sector code uses it for enabling LBA. We ignore it. See also var.chs_or_lba.
;.oem_name: equ fat_header+3  ; db*8. Example: 'MSDOS5.0'.

bpb: equ fat_header+0xb  ; FAT BIOS parameter block. https://en.wikipedia.org/wiki/Design_of_the_FAT_file_system#BIOS_Parameter_Block
bpb.copy_start: equ fat_header+0xb  ; It will be rounded down to even, i.e. +0xa, for the actual copy.
bpb.bytes_per_sector: equ fat_header+0xb  ; dw 0x200  ; The value 0x200 is always hardcoded.
bpb.sectors_per_cluster: equ fat_header+0xd  ; db (%4)
bpb.reserved_sector_count: equ fat_header+0xe  ; dw (%1)+(%8)
bpb.fat_count: equ fat_header+0x10  ; db (%3)  ; Must be 1 or 2. MS-DOS 6.22 supports only 2. Windows 95 DOS mode supports 1 or 2.
bpb.rootdir_entry_count: equ fat_header+0x11  ; dw (%6)<<4  ; 0 for FAT32, nonzero otherwise. Each FAT directory entry is 0x20 bytes. Each sector is 0x200 bytes.
bpb.sector_count_zero: equ fat_header+0x13  ; dw. If 0, see true value in .sector_count. FAT32 has it always 0.
bpb.media_descriptor: equ fat_header+0x15  ; db 0xf8  ; 0xf8 for HDD.
bpb.sectors_per_fat_fat1x: equ fat_header+0x16  ; dw. for FAT32, nonzero otherwise. IBM PC DOS 7.1 detects FAT32 by checking word [.sectors_per_fat_fat1x] == 0 here. We also do it like this.
bpb.sectors_per_track: equ fat_header+0x18  ; dw. Track == cylinder. Will be overwritten with value from BIOS int 13h AH == 8. FreeDOS 1.2 `dir c:' needs a correct value for .sectors_per_track and .head_count. MS-DOS 6.22 and FreeDOS 1.3 ignore these values (after boot).
bpb.head_count: equ fat_header+0x1a  ; dw. Will be overwritten with value from BIOS int 13h AH == 8.
bpb.hidden_sector_count: equ fat_header+0x1c  ; dd. Occupied by MBR and previous partitions. We use this value, and we ignore the partition table.
bpb.sector_count: equ fat_header+0x20  ; dd. Excluding hidden sectors, including reserved sectors (which include the boot sector).
bpb.sectors_per_fat_fat32: equ fat_header+0x24  ; dd.
;bpb.mirroring_flags_fat32: equ fat_header+0x28  ; dw 0  ; As created by mkfs.vfat.
;bpb.version_fat32: equ fat_header+0x2a  ; dw 0.
;bpb.rootdir_start_cluster_fat32: equ fat_header+0x2c  ; dd 2.
bpb.copy_end: equ fat_header+0x30  ; It will be rounded up to even, i.e. +0x24, for the actual copy. The msbio payload uses everything before here, and also byte [bp-$$+.drive_number_fat32].
;bpb.fsinfo_sec_ofs_fat32: equ fat_header+0x30  ; dw.
;bpb.first_boot_sector_copy_sec_ofs_fat32: equ fat_header+0x32  ; dw.
;bpb.reserved_fat32: equ fat_header+0x34  ; db*12.
;bpb.drive_number_fat32: equ fat_header+0x40  ; db 0x80.
;bpb.extended_boot_signature_fat32_nc: equ fat_header+0x42  ; db 0x29. Not copied here, not used by us.
;bpb.fstype_fat32_nc: equ fat_header+0x52  ; db*8. Not copied here, not used by us.
bpb.drive_number_fat1x: equ fat_header+0x24  ; db. 0x80 for HDD.
;bpb.var_unused_fat1x_nu: equ fat_header+0x25  ; db 0. Some boot code uses it as temporary variable .var_read_head_fat1x. Not used by us.
;bpb.extended_boot_signature_fat1x_nu: equ fat_header+0x26  ; db 0x29. Not used by us.
;bpb.volume_id_fat1x_nu: equ fat_header+0x27  ; dd 0x1234abcd  ; 1234-ABCD. Not used by us.
;bpb.volume_label_fat1x_nu: equ fat_header+0x2b  ; db*0xb. Example: 'NO NAME    '. Not used by us.
;bpb.fstype_fat1x_nc: equ fat_header+0x36  ; db 'FAT16   '. Not copied here, not used by us.

var:
; Initialized data goes to initialized_data below.
; Don't use var+0, [bp] is 1 byte longer than [bp-$$+1].
.chs_or_lba: equ var+2  ; db. 0x90 for CHS. Another possible value is 0x0e for LBA (and 0x0c is also for LBA). Expected by msbio at this offset. Windows 95 OSR2, Windows 98 and Windows ME boot sector code uses it for enabling LBA. We ignore it.
.unused_byte equ var+3 ; db.
.remaining_para_count: equ var+4  ; dw. Number of paragraphs (16-byte blocks) remaining, including the ignored msload paragraphs in the beginning, then the actually loaded msbio paragraphs. Will be decremented after each sector loaded.
.our_cluster_ofs: equ var+6  ; dd. The high word is arbitrary and ignored for non-FAT32 (i.e. FAT12 and FAT16).
.no_more_vars_here: equ var+0xa  ; We can go up to var+0xa here, then we have to skip over to bpb.copy_end.
.sectors_per_fat: equ var+0x24  ; dd. Same location as .sectors_per_fat_fat32, but we will copy the non-FAT32 value to heere as well.
.next_available_var: equ var+0x30  ; After bpb.copy_end.
.fat_sec_ofs: equ var+0x30  ; dd.
.msbio_passed_para_count equ var+0x34 ; dw. Paragraph count passed to msbio.
.drive_number: equ var+0x40  ; db. 0x80 for HDD. Expected by msbio at this offset.
.clusters_sec_ofs: equ var+0x5a  ; dd. Expected by msbio at this offset.
.orig_dipt_offset: equ var+0x5e  ; dw. Expected by msbio at this offset.
.orig_dipt_segment: equ var+0x60  ; dw. Expected by msbio at this offset.
.end: equ var+0x62

; Use it for getting offset of local variables when running the relocated
; msload: `mov si, -rorg+errmsg_dos7'.
rorg: equ $-0x800

CHS_OR_LBA:
.CHS equ 0x90
.LBA equ 0x0e  ; 0x0c may also indicate LBA.

RELOC_BASE_SEGMENT equ 0x4000  ; Works with msbio payload size <= 256 KiB - 0x100 == (0x4000 << 4) - 0x100 bytes. 0x100 because of .copy_kernel_sector.

msload:

mz_header:  ; DOS .exe header: http://justsolve.archiveteam.org/wiki/MS-DOS_EXE
.signature:	db 'MZ'  ; Magic bytes checked by the boot sector code.
%ifdef JUST_MSLOAD
.lastsize:	dw 0
.nblocks:	dw 0
%elif MSLOAD_SECTOR_COUNT==2  ; This works only if MSDCM has been removed from io.sys. Fix it by a post-processing: subtracting 2 sectors from .nblocks.
.lastsize:      dw (end-.signature) & 0x1ff  ; The value 0 and 0x200 are equivalent here. Microsoft Linker 3.05 generates 0, so do we. Number of bytes in the last 0x200-byte block in the .exe file.
.nblocks:       dw (end-.signature +0x1ff)>> 9  ; Number of 0x200-byte blocks in .exe file (rounded up).
%else
.lastsize:	incbin ORIG_IO_SYS, 2, 4
%endif
.nreloc:	dw 0  ; No relocations. That's always true, even for MSDCM.
%ifdef JUST_MSLOAD
.hdrsize:	dw 0  ; Will have to be changed later to `(end_before_msdcm-.signature)>>4'.
.minalloc:	dw 0
.maxalloc:	dw 0
.ss:		dw 0
.sp:		dw 0
.checksum:	dw 0
.ip:		dw 0
.cs:		dw 0
%elif 1  ;%elif MSLOAD_SECTOR_COUNT==2  ; This works only if MSDCM has been removed from io.sys. Fix it by fixing .nblocks first.
.hdrsize:	dw (end-.signature)>>4  ; This value is OK both with and without MSDCM, but it's unnecessarily large with MSDCM. It should be `(end_before_msdcm-.signature)>>4'.
.minalloc:	dw 0
.maxalloc:	dw 0
.ss:		dw 0
.sp:		dw 0
.checksum:	dw 0
.ip:		dw 0
.cs:		dw 0
%else
.hdrsize:	incbin ORIG_IO_SYS, 8, 0x18-8  ; Used by the MSDCM DOS .exe embedded in Windows 95 and Windows 98 io.sys. When converting an existing io.sys without MSDCM, set this value to `dw (end_before_msdcm-.signature)>>4'. Original Windows 98 SE io.sys works only with a smaller value (-0 ... -0x80 (4 sectors)), the exact allowed values being very strange, also depending on the cluster size.
%endif
assert_fofs 0x18
load_code:
		; This code assumes that msload is loaded to CS:0 with any value of CS. (Actually it's CS==0x70, part of https://pushbx.org/ecm/doc/ldosboot.htm#protocol-sector-msdos7 .)
		cld
.setup_reloc_segment:
		;mov ax, ((end-mz_header)>>4)  ; Just behind the msbio payload.
		mov ax, RELOC_BASE_SEGMENT
		mov es, ax
		push cs
		pop ds
		push si  ; Will be moved from to stack to [si-$$+var.our_cluster_ofs+2] below.
		xor si, si
		mov cx, [si-$$+mz_header.hdrsize]  ; Making a copy early, because it will be overwritten (partially) with a copy of bpb.fat_header below.
		; Reverse engineering Windows 98 SE io.sys msbio code
		; indicates that the intended input meaning of
		; msbio_passed_para_count is the number of 0x10-byte
		; paragraphs loaded from io.sys (file offset 0x800) to
		; 0x70:0. The number in mz_header.hdrsize also includes the
		; size of msload (MSLOAD_SECTOR_COUNT<<5 bytes), so we
		; subtract that below.
		;
		; Please note that Windows 98 SE io.sys msload actually
		; loads many paragraphs more than mz_header.hdrsize-0x80
		; (exactly how much more depends on the file size and the
		; cluster size), and it passes msbio_passed_para_count ==
		; mz_header.hdrsize-0x20 to msbio, in which -0x20 is an
		; arbitrary value, but io.sys makes sure that
		; msbio_passed_para_count is not more than the number of
		; paragraphs loaded.
		;sub cx, byte 0x20  ; This would match Windows 98 SE io.sys msbio, but we don't want to indicate that much, because a custom truncated io.sys without a logo may not have that much.
%if MSLOAD_SECTOR_COUNT>4
  %error MSLOAD_TOO_LARGE
  db 1/0
%elif MSLOAD_SECTOR_COUNT==4
		add cx, byte -0x80
%else
		sub cx, byte (msload_end-msload)>>4
%endif
		pop word [si-$$+var.our_cluster_ofs+2]  ; High word, coming from SI. It is arbitrary, and it will be ignored for FAT12 and FAT16. It's important that this instruction is not earlier, because of overlap between load_code and var.
		push cx  ; Will be popped to msbio_passed_para_count below.
%if MSLOAD_SECTOR_COUNT==4
		sub cx, byte -0x80
%else
		add cx, byte (msload_end-msload)>>4  ; We add it back, because in remaining_para_count we also count msload.
%endif
		; Overlap between load_code and all data above (fat_header, bpb, var) ends by here.
		mov [si-$$+var.remaining_para_count], cx  ; Copy it first, because the from-BPB below copy overwrites its original location (mz_header.hdrsize).
		; The boot sector has also set `dword [bp-4]' to the sector offset of the first data sector (var.clusters_sec_ofs). We ignore it, because we'll compute our own.
		; The boot sector has also set SI:DI to the cluster index of io.sys (i.e.e the file to be loaded).
		mov [si-$$+var.our_cluster_ofs], di
		mov cx, [bp-4]  ; Low word of first data sector.
		; Copy our msload (0x400 bytes) from its current location (CS:0) to its final location (ES:0x800).
		mov di, -rorg+msload
		push di
%ifdef TIGHT
		mov cx, (tight_msload_sector_end-msload)>>1  ; Copy 0x400 bytes: 0x340 bytes of msload code and 0x4c0 bytes of msbio prefix.
%else
		mov cx, 0x400>>1  ; Copy 0x200 bytes: <=0x340 bytes of msload code and data would be enough.
%endif
		rep movsw  ; Copy CX<<1 bytes (the msloadv7i code and data) from DS:SI to ES:DI.
		; Copy BPB from the loaded boot sector (SS:BP+0xb) to its final location (ES:0x70b).
		lea si, [bp+((bpb.copy_start-msload)&~1)]
		mov di, -rorg+msload+((bpb.copy_start-msload)&~1)
		mov cx, ((bpb.copy_end-bpb)-((bpb.copy_start-bpb)&~1)+1)>>1
%if $-msload<bpb.copy_end-msload
  %error OVERLAP_BETWEEN_BPB_AND_LOAD_CODE_1
  dw 1/0
%endif
		ss rep movsw  ; Copy CX<<1 bytes from SS:SI to ES:DI.
		mov ds, ax  ; RELOC_BASE_SEGMENT.
		pop di  ; DI := 0x800.
		mov bx, [di-$$+bpb.sector_count_zero]
		test bx, bx
		jz .done_sector_count
		mov [di-$$+bpb.sector_count], bx
		mov [di-$$+bpb.sector_count+2], cx  ; 0.
.done_sector_count:
		pop word [di-$$+var.msbio_passed_para_count]
		pop bx  ; Discard value from boot sector boot code.
		pop bx  ; Discard value from boot sector boot code.

		jmp short initialized_data.end
		align 2, nop
initialized_data:
%if $-msload<var.end-var
  %error OVERLAP_BETWEEN_VAR_AND_INIIALIZED_DATA
  dw 1/0
%endif
var.single_cached_fat_sec_ofs: dd 0
var.is_fat12: db 0  ; 1 for FAT12, 0 otherwise.
var.skip_sector_count: db MSLOAD_SECTOR_COUNT+EXTRA_SKIP_SECTOR_COUNT
var.fat_cache_segment: dw RELOC_BASE_SEGMENT+0xc0-0x10+(EXTRA_SKIP_SECTOR_COUNT<<5)  ; Right after the relocated copy of our code. !! This depends on TIGHT.
%if $-msload>=0x80
  %error INIIALIZED_DATA_ENDS_TOO_LATE  ; This prevents single-byte-displacement optimization, e.g. [bp-$$+0x7f] is single-byte, [bp-$$+0x80] is two bytes.
  dw 1/0
%endif
initialized_data.end:

%if $-msload<var.end-var
  %error OVERLAP_BETWEEN_VAR_AND_LOAD_CODE_2
  dw 1/0
%endif
		pop word [di-$$+var.orig_dipt_offset]   ; Use value from boot sector boot code.
		pop word [di-$$+var.orig_dipt_segment]  ; Use value from boot sector boot code.
		; No need to move around the 0xb bytes of the DPT (current
		; int 13h vector), we can assume that the boot sector has
		; set it up to a location which survives the boot process.
		; The Windows 95--98--ME boot sectos copy the 0xb bytes to
		; 0:0x522, which is such an address.
		mov dl, [bp-$$+var.drive_number]  ; Windows 98 SE boot sector doesn't pass DL to msload. This is only correct for FAT32. We get it later for non-FAT32.
		mov bp, di  ; BP := 0x800.
		cli
		mov ss, ax  ; RELOC_BASE_SEGMENT.
		mov sp, bp
		sti
		mov ax, [bp-$$+bpb.sectors_per_fat_fat1x]
		cmp ax, cx  ; AX == 0 for FAT32.
		je .done_sectors_per_fat  ; Jump if FAT32.
		mov dl, [bp-$$+bpb.drive_number_fat1x]  ; Do this early, because [bp-$$+var.sectors_per_fat overlaps [bp-$$+bpb.drive_number_fat1x] .
		mov [bp-$$+var.sectors_per_fat], ax
		mov [bp-$$+var.sectors_per_fat+2], cx  ; 0.
.done_sectors_per_fat:
		mov [bp-$$+var.drive_number], dl  ; msbio needs it here, no matter the filesystem.
		push ds  ; RELOC_BASE_SEGMENT.
		mov ax, -rorg+cont_relocated
		push ax
		retf

read_fat_sector_to_cache:  ; Read sector DX:AX to ES:0, and save the sector offset (DX:AX) to dword [bp-$$+var.single_cached_fat_sec_ofs].
		mov [bp-$$+var.single_cached_fat_sec_ofs], ax
		mov [bp-$$+var.single_cached_fat_sec_ofs+2], dx  ; Mark sector DX:AX as buffered.
		; Fall through to read_sector_ex_0x100.

; Reads a sector from disk, using LBA or CHS.
; Inputs: DX:AX: sector offset (LBA); ES: ES:0x100 points to the destination buffer.
; Outputs: none.
; Ruins: flags.
read_sector_es_0x100:
		push ax  ; Save.
		push bx  ; Save.
		push cx  ; Save.
		push dx  ; Save.
		push si  ; Save.
		mov bx, 0x100   ; Use read destination offset 0 in ES:BX.  This implements sector wraparound protection: https://retrocomputing.stackexchange.com/a/31157
.js:		jmp short .chs  ; Self-modifying code: EBIOS autodetection may change this to `jmp short .lba' by setting byte [bp-.header+.c].
.lba:		; Construct .dap (Disk Address Packet) for BIOS int 13h AH == 42, on the stack.
		xor cx, cx
		push cx  ; High word of .dap_lba_high.
		push cx  ; Low word of .dap_lba_high.
		push dx  ; High word of .dap_lba.
		push ax  ; Low word of .dap_lba.
		push es  ; .dap_mem_seg.
		push bx  ; .dap_mem_ofs.
		inc cx
		push cx  ; .dap_sector_count := 1.
		mov cl, 0x10
		push cx  ; .dap_size := 0x10.
		mov si, sp
		mov ah, 0x42
.do_read:	mov dl, [bp-$$+var.drive_number]
		int 0x13  ; BIOS syscall to read sectors.
		mov si, -rorg+errmsg_disk
		jc fatal
		add sp, byte 0x10  ; Pop the .dap and keep CF (indicates error).
		pop si  ; Restore.
		pop dx  ; Restore.
		pop cx  ; Restore.
		pop bx  ; Restore.
		pop ax  ; Restore.
		ret
.chs:		; Converts sector offset (LBA) value in DX:AX to BIOS-style
		; CHS value in CX and DH. Ruins DL, AX and flag. This is
		; heavily optimized for code size.
		xchg ax, cx
		xchg ax, dx
		xor dx, dx
		div word [bp-$$+bpb.sectors_per_track]  ; We assume that .sectors_per_track is between 1 and 63.
		xchg ax, cx
		div word [bp-$$+bpb.sectors_per_track]
		inc dx  ; Like `inc dl`, but 1 byte shorter. Sector numbers start with 1.
		xchg cx, dx  ; CX := sec value.
		div word [bp-$$+bpb.head_count]  ; We assume that .head_count is between 1 and 255.
		; Now AX is the cyl value (BIOS allows between 0 and 1023),
		; DX is the head value (between 0 and 254), thus the DL is
		; also the head value, CX is the sec value (BIOS allows
		; between 1 and 63), thus CL is also the sec value. Also the
		; high 6 bits of AH (and AX) are 0, because BIOS allows cyl
		; value less than 1024. (Thus `ror ah, 1` below works.)
		;
		; BIOS int 13h AH == 2 wants the head value in DH, the low 8
		; bits of the cyl value in CH, and it wants CL ==
		; (cyl>>8<<6)|head. Thus we copy DL to DH (cyl value), AL to
		; CH (low 8 bits of the cyl value), AH to CL (sec value),
		; and or the 2 bits of AH (high 8 bits of the cyl value)
		; shifted to CL.
		mov dh, dl
		mov ch, al
		ror ah, 1
		ror ah, 1
		or cl, ah
		mov ax, 0x201  ; AL == 1 means: read 1 sector.
		sub sp, byte 0x10  ; Adapt to the .do_read ABI.
		jmp short .do_read

fatal1:		mov si, -rorg+errmsg_dos7
fatal:		les di, [bp-$$+var.orig_dipt_offset]  ; We are doing this early because we have space in the first sector for this.
		mov ax, -rorg+cont_fatal  ; Continue here after print_msg.
		push ax  ; Return address for simulated `call'.
		; Fall through to print_msg.

; Prints NUL-terminated message starting at DS:SI, and halts.
; Ruins: AX, BX, SI, flags.
print_msg:	mov ah, 0xe
		xor bx, bx
.next_msg_byte:	lodsb  ; Assumes DS == 0.
		test al, al  ; Found terminating NUL?
		jz .ret
		int 0x10
		jmp short .next_msg_byte
.ret:		ret

cont_relocated:	; Now: AX==CS==DS==ES==SS: segment of the relocated msload; BP==SP==0x800: offset of the relocated msload; BX: any; CX: 0; DL: .drive_number; DH: any; SI: any; DI: any.
		;
		; Now these are initialized: var.remaining_para_count,
		; var.msbio_passed_para_count, var.drive_number,
		; var.our_cluster_ofs, bpb.copy_start,
		; bpb.bytes_per_sector, bpb.sectors_per_cluster,
		; bpb.reserved_sector_count, bpb.fat_count,
		; bpb.rootdir_entry_count, bpb.media_descriptor,
		; var.sectors_per_fat,
		; bpb.sectors_per_fat_fat1x (0 for FAT32),
		; bpb.sectors_per_track (from BPB, not from BIOS yet),
		; bpb.head_count (from BPB, not from BIOS yet),
		; bpb.hidden_sector_count, bpb.sector_count.

check_ebios:	mov byte [bp-$$+var.chs_or_lba], CHS_OR_LBA.CHS
		mov ah, 0x41  ; Check extensions (EBIOS). DL already contains the drive number.
		mov bx, 0x55aa
		int 0x13  ; BIOS syscall.
		jc .done_ebios	 ; No EBIOS.
		cmp bx, 0xaa55
		jne .done_ebios	 ; No EBIOS.
		ror cl, 1
		jnc .done_ebios	 ; No EBIOS.
		mov byte [bp-$$+var.chs_or_lba], CHS_OR_LBA.LBA  ; Indicate to msbio to use LBA.
		mov byte [bp-$$+read_sector_es_0x100.js+1], read_sector_es_0x100.lba-(read_sector_es_0x100.js+2)  ; Self-modifying code: change the `jmp short .chs' at `read_sector_es_0x100.js' to `jmp short .lba'.
.done_ebios:

get_chs_sizes:	xor di, di  ; Workaround for buggy BIOS. Also the 0 value will be used later.
		; DL still contains the drive number.
		mov ah, 8  ; Read drive parameters.
		push dx
		int 0x13  ; BIOS syscall.
		jc fatal1
		and cx, byte 0x3f
		mov [bp-$$+bpb.sectors_per_track], cx
		mov dl, dh
		mov dh, 0
		inc dx
		mov [bp-$$+bpb.head_count], dx
		mov ah, 1  ; Get status of last drive operation. Needed after the AH == 8 call.
		pop dx  ; mov dl, [bp-$$+var.drive_number]
		int 0x13  ; BIOS syscall.

		; Figure out where FAT and data areas start.
get_fat_sizes:	xor dx, dx
		mov ax, [bp-$$+bpb.reserved_sector_count]
		add ax, [bp-$$+bpb.hidden_sector_count]
		adc dx, [bp-$$+bpb.hidden_sector_count+2]
		mov [bp-$$+var.fat_sec_ofs], ax
		mov [bp-$$+var.fat_sec_ofs+2], dx
		xor cx, cx
		mov cl, [bp-$$+bpb.fat_count]  ; 1 or 2.
.add_fat:	add ax, [bp-$$+var.sectors_per_fat]
		adc dx, [bp-$$+var.sectors_per_fat+2]
		loop .add_fat
                ; Now: DX:AX == the sector offset (LBA) of the root directory in this FAT filesystem.
		mov bx, [bp-$$+bpb.rootdir_entry_count]  ; 0 far FAT32.
		add bx, byte 0xf
		mov cl, 4  ; Assuming word [bp-$$+bpb.bytes_per_sector] == 0x200.
		shr bx, cl
		xor cx, cx
		add ax, bx
		adc dx, cx
		mov [bp-$$+var.clusters_sec_ofs], ax
		mov [bp-$$+var.clusters_sec_ofs+2], dx  ; dword [bp-$$+var.clusters_sec_ofs] := DX:AX (final value).

detect_fat12:  ; Input: CX == 0.
		;mov byte [bp-$$+var.is_fat12], 0  ; Already initialized to 0.
		cmp [bp-$$+bpb.sectors_per_fat_fat1x], cx  ; Assumes CX == 0.
		je .done  ; If FAT32, then already done.
		mov dx, [bp-$$+bpb.sector_count+2]
		mov ax, [bp-$$+bpb.sector_count]
		sub ax, [bp-$$+bpb.reserved_sector_count]
		sbb dx, cx  ; Assumes CX == 0.
		mov bx, [bp-$$+var.sectors_per_fat]
		mov cl, [bp-$$+bpb.fat_count]  ; 1 or 2.
		dec cx
		shl bx, cl
		sub ax, bx
		sbb dx, byte 0
		mov bx, [bp-$$+bpb.rootdir_entry_count]
		add bx, byte 0xf
		mov cl, 4  ; 1<<4 directory entries per sector (of size 0x200).
		shr bx, cl
		sub ax, bx
		sbb dx, byte 0
		mov cl, [bp-$$+bpb.sectors_per_cluster]
		push ax
		xchg ax, dx  ; AX : = DX; DX := junk.
		xor dx, dx
		div cx
		pop ax
		div cx
		; Now: AX: number of clusters.
		cmp ax, 4096-10  ; 0xff8-2. Same cluster number check as in MS-DOS 6.22 and MS-DOS 7.x.
		jnc .done
		inc byte [bp-$$+var.is_fat12]
.done:

read_msbio:
%ifdef TIGHT
		mov ax, 0x70+(EXTRA_SKIP_SECTOR_COUNT<<5)  ; 0x70+2*0x20 == 0xb0.
		mov es, ax
%else
		mov es, [bp-$$+jump_to_msbio.jmp_far_inst+3]  ; 0x70.
%endif
		mov ax, [bp-$$+var.our_cluster_ofs]
		mov dx, [bp-$$+var.our_cluster_ofs+2]
next_kernel_cluster:  ; Now: CX, SI and DI are ruined, BX is unused, BP is used as base address for variables (bpb.* and var.*), DX:AX is the cluser number (DX is ignored for FAT12 and FAT16).
		push dx
		push ax  ; Save cluster number (DX:AX).

cluster_to_lba:  ; Converts cluster number in DX:AX (DX is ignored for FAT12 and FAT16) to the sector offset (LBA).
		;call print_star  ; For debugging.
		cmp word [bp-$$+bpb.sectors_per_fat_fat1x], byte 0
		je .fat32
		;call print_dot  ; For debugging.
		xor dx, dx
		cmp [bp-$$+var.is_fat12], dl
		je .cmp_low  ; Jump for FAT16.
		cmp ax, strict word 0xff8  ; FAT12 maximum number of clusters: 0xff8.
		jmp short .jb_low
.fat32:		cmp dx, 0x0fff
		jne .jb_low
.cmp_low:	cmp ax, strict word 0xfff8  ; FAT32 maximum number of clusters: 0x0ffffff8. FAT16 maximum number of clusters: 0xfff8.
.jb_low:	jb no_eoc
		; EOC encountered before we could read the desired number of sectors.
.jmp_fatal1:	jmp strict near fatal1

errmsg_dos7:	db 'DOS7 load error', 0
errmsg_disk:	db 'Disk error', 0

		times 0x200-($-$$) db '-'

assert_fofs 0x200
; The boot sector boot code jumps here: jmp 0x70:200; with CS: 0x70; IP: 0x200; SS: 0; BP: 0x7c00; DL: drive number.
entry:		db 'BJ'  ; Magic bytes: `inc dx ++ dec dx'. The Windows 98 SE boot sector code checks for this: cmp word [bx+0x200], 'BJ'
		jmp strict near load_code

; Execution continues here after `jmp near read_msbio', after `load_code'.
no_eoc:		sub ax, byte 2
		sbb dx, byte 0
		jc cluster_to_lba.jmp_fatal1  ; It's an error to follow cluster 0 (free) and 1 (reserved for temporary allocations).
		mov cl, [bp-$$+bpb.sectors_per_cluster]
		mov ch, cl
		; Sector := (cluster-2) * clustersize + data_start.
		jmp short .maybe_shift
.next_shift:	shl ax, 1
		rcl dx, 1
.maybe_shift:	shr ch, 1
		jnz .next_shift
		; Now: CX is sectors per cluster.
		add ax, [bp-$$+var.clusters_sec_ofs]
		adc dx, [bp-$$+var.clusters_sec_ofs+2]

read_kernel_sector:  ; Now: CX is sectors per cluster; DX:AX is sector offset (LBA).
		sub byte [bp-$$+var.skip_sector_count], 1
		jnc .after_sector
		inc byte [bp-$$+var.skip_sector_count]  ; Change it back from -1 to 0.
		;call print_star  ; For debugging.
		call read_sector_es_0x100  ; TODO(pts): Read multiple sectors at once, for faster speed, especially on floppies.
		push cx  ; Save (CX == sectors per cluster).
		mov si, 0x100
%ifdef TIGHT
		mov di, tight_msload_sector_end-tight_msbio_payload-(EXTRA_SKIP_SECTOR_COUNT<<9)  ; 0xc0. Bytes between 0x70:0 and 0x70:0xc0 will be copied to from sector 1 (0x70+:0x340) loaded by the boot sector.
%else
		xor di, di
%endif
		mov cx, si  ; Copy 1 sector: 0x200 bytes from 0x80+:0 to 0x70+:0. We read to 0x80 (a multiple of 0x20) because of sector wraparound protection (https://retrocomputing.stackexchange.com/a/31157), but the load protocol needs 0x70.
.copy_kernel_sector:
		es rep movsw  ; Copy CX words from ES:SI to ES:DI.
		mov si, es
		lea si, [si+0x20]
		mov es, si  ; Read location for next sector.
		pop cx  ; Restore (CX := sectors per cluster).
.after_sector:	add ax, byte 1  ; Next sector.
		adc dx, byte 0
		sub word [bp-$$+var.remaining_para_count], byte 0x20
		ja continue_reading

jump_to_msbio:
		; No need to pop anything, msbio v7 (START$, then INIT in bios/msinit.asm) doesn't look at the stack.
		; Now: SS == RELOC_BASE_SEGMENT == 0x4000; SP == 0x800-4 (the cluster number (dword) is pushed).
		;call print_dot  ; For debugging.
%ifdef TIGHT  ; Copy bytes from sector 1 (0x70+:0x340) loaded by the boot sector to 0x70:0 and 0x70:0xc0.
		mov si, -rorg+tight_msbio_payload
		mov es, [bp-$$+jump_to_msbio.jmp_far_inst+3]  ; 0x70.
		xor di, di
		mov cx, (tight_msload_sector_end-tight_msbio_payload)>>1
		rep movsw  ; Copy from tight_msbio_payload until the end of the sector to the beginning of the final msbio.
		xchg ax, cx  ; AX := 0; CX := junk. ; xor ax, ax  ; `mov ax, [0x7fa]' of the original (0x800-byte) msload, the value is 0.
%else
		xor ax, ax  ; `mov ax, [0x7fa]' of the original (0x800-byte) msload, the value is 0.
%endif
		xor bx, bx  ; `mov ax, [0x7fa+2]' of the original (0x800-byte) msload, the value is 0.
		mov di, [bp-$$+var.msbio_passed_para_count]
		mov dl, [bp-$$+var.drive_number]
		mov dh, [bp-$$+bpb.media_descriptor]  ; Is this actually used? https://retrocomputing.stackexchange.com/q/31129
		; More values are passed (some of them from the BPB) to
		; msbio, starting at SS:BP, and it uses these values later,
		; for example, it uses the LBA flag ([BP+2] here).
.jmp_far_inst:	jmp 0x70:0  ; Jump to msbio loaded from io.sys.

continue_reading:
		loop read_kernel_sector  ; Consume 1 sector from the cluster (from CX).
		pop ax
		pop dx  ; Restore cluster number (DX:AX).

next_cluster:  ; Find the number of the next cluster following DX:AX (DX is ignored for FAT12 and FAT16) in the FAT chain. Ruins SI.
		;call print_dot  ; For debugging.
		push es  ; Save.
		mov si, ax
		xor cx, cx
		cmp word [bp-$$+bpb.sectors_per_fat_fat1x], byte 0
		je .fat32
		xor dx, dx
		cmp [bp-$$+var.is_fat12], dl  ; 0.
		je .fat16
.fat12:		shr ax, 1
		add ax, si
		mov cx, ax
		rcr ax, 1
		and ch, 1  ; Keep low 9 bits in CX (will be swapped to SI).
		xchg cx, si  ; CX := cluster number; SI := byte offset of the pointer word.
		mov ch, cl  ; Keeping it for the low bit (parity).
		mov cl, 4  ; Bit shift amount of 4 for FAT12.
		jmp short .low8
.fat16:		and si, 0xff
		shl si, 1
.low8:		mov al, ah
		mov ah, 0
		jmp short .maybe_read_fat_sector
.fat32:		and si, byte 0x7f  ; Assumes word [bp-.header+.bytes_per_sector] == 0x200.
		shl si, 1
		shl si, 1
		mov cx, 7  ; Will shift DX:AX right by 7. Assumes word [bp-.header+.bytes_per_sector] == 0x200.
.shr7_again:	shr dx, 1
		rcr ax, 1
		loop .shr7_again
.maybe_read_fat_sector:
		; Now: DX:AX is the sector offset within the first FAT.
		; Now: SI is the byte offset of the pointer word or dword within the sector (can be 0x1ff for FAT12; for others, it's at most 0x1fe).
		; Now: CL is 4 for FAT12, 0 for others. It will be used as a shift amount on the low word of the byte offset.
		; Now: CH is the low byte of the cluster number (will be used for its low bit, parity) for FAT12, 0 for others.
		add ax, [bp-$$+var.fat_sec_ofs]
		adc dx, [bp-$$+var.fat_sec_ofs+2]
		; Now: DX:AX is the sector offset (LBA); SI is the byte offset within the sector.
		mov es, [bp-$$+var.fat_cache_segment]
		; Is it the last accessed and already buffered FAT sector?
		cmp ax, [bp-$$+var.single_cached_fat_sec_ofs]
		jne .fat_read_sector_now
		cmp dx, [bp-$$+var.single_cached_fat_sec_ofs+2]
		je .fat_sector_read
.fat_read_sector_now:
		call read_fat_sector_to_cache
.fat_sector_read:
		push word [es:si+0x100]  ; Save low word of next cluster number.
		cmp si, 0x1ff
		jne .got_new_pointer
		add ax, byte 1  ; Next sector.
		adc dx, byte 0
		call read_fat_sector_to_cache
		pop ax  ; Restore low word of next cluster number to AX.
		mov ah, [es:0x100]  ; Get high byte of next cluster number from the next sector.
		push ax  ; Make the following `pop ax' a nop.
.got_new_pointer:
		pop ax  ; Restore low word of next cluster number to AX.
		mov dx, [es:si+0x102]  ; Harmless for FAT12 and FAT16, we don't use the value.
		and dh, 0xf  ; Mask out top 4 bits, because FAT32 FAT pointers are only 28 bits. Harmless for FAT12 and FAT16.
		test ch, 1  ; Is FAT12 cluster number odd?
		jnz .odd
		shl ax, cl  ; This is no-op (since CL==0) for FAT16 and FAT32.
.odd:		shr ax, cl  ; This is no-op (since CL==0) for FAT16 and FAT32.
		; Now: DX:AX is the number of next cluster (DX is garbage for FAT12 and FAT16).
		pop es  ; Restore.
		; Now: CX and SI are ruined.
		jmp strict near next_kernel_cluster

cont_fatal:  ; Continue handling a fatal error.
		mov si, -rorg+errmsg_replace
		call print_msg
		xor ax, ax  ; Good for setting DS and also sets AH := 0 for the `int 0x16' below.
		mov ds, ax
		int 0x16  ; Wait for keystroke, and read it.
		;les di, [bp-$$+var.orig_dipt_offset]  ; Already done in `fatal:'.
		mov si, (0x1e<<2)  ; DPT (.dipt) int 1eh vector.
		mov [si], di  ; Offset of int 1eh vector.
		mov [si+2], es  ; Segment of int 1eh vector.
		int 0x19  ; Reboot.
		; Not reached.

errmsg_replace:	db 13, 10, 'Replace the disk, and then press any key', 13, 10, 0  ; Same message as in Windows 98 SE.

%if 0  ; For debugging.
		mov al, [bp-$$+var.chs_or_lba]
		mov [bp-$$+errmsg_dos7], al
		jmp fatal1
%endif

%if 0  ; For debugging.
print_si:
		push ax
		mov ax, si
		call print_ax
		pop ax
		ret

print_dxax:
		push ax
		mov ax, dx
		call print_ax
		pop ax
		call print_ax
		ret

print_many:
		push ax
		push bx
		mov ax, 0xe00|'M'
		mov bx, 7
		int 0x10
		pop bx
		pop ax
		;
		push ax
		call print_ax
		mov ax, bx
		call print_ax
		mov ax, cx
		call print_ax
		mov ax, dx
		call print_ax
		mov ax, es
		call print_ax
		pop ax
		ret


print_ax:
		push ax
		push bx
		push dx
		xchg dx, ax  ; DX := AX; AX := junk.
		mov ax, 0xe00|','
		mov bx, 7
		int 0x10  ; Print comma.
		mov al, dh
		call .print_byte_aam
		xchg ax, dx  ; AL := DL; AH := junk; DX := junk.
		call .print_byte_aam
		pop dx
		pop bx
		pop ax
		ret
.print_byte_aam:
		aam 0x10
		push ax
		mov al, ah
		call .print_nibble  ; Print high nibble.
		pop ax
		call .print_nibble  ; Print low nibble.
		ret
.print_nibble:	add al, '0'
		cmp al, '9'
		jna .adjusted
		add al, 'a'-'0'-10
.adjusted:	mov ah, 0xe
		int 0x10  ; Print byte in AL. Assumes BX == 7.
		ret
%endif

%if 0  ; For debugging.
print_star:  ; For debugging.
		push ax
		push bx
		mov ax, 0xe00|'*'
		mov bx, 7
		int 0x10
		pop bx
		pop ax
		ret

print_dot:  ; For debugging.
		push ax
		push bx
		mov ax, 0xe00|'.'
		mov bx, 7
		int 0x10
		pop bx
		pop ax
		ret
%endif

%if MSLOAD_SECTOR_COUNT==2
  %ifdef TIGHT
		times (msload-$-4)&0xf db '+'
		db 'ML7I'  ; Signature.
    assert_fofs 0x340  ; 0xc0 bytes for tight_msbio_payload until the end of the sector. It could work with a larger offset if we need more code for msload.
    msload_end:
    tight_msbio_payload:
    tight_msload_sector_end: equ msload+0x800  ; The boot sector has already loaded 0x800 bytes.
  %else
		times 0x400-4-($-msload) db '-'
		db 'ML7I'  ; Signature.
    msload_end:
  %endif
%else
		times 0x400-($-msload) db '-'
  assert_fofs 0x400
		times ((MSLOAD_SECTOR_COUNT-2)<<9)-2 db 0
		db 'MS'  ; Magic bytes which nobody checks.
  msload_end:
%endif

%ifndef JUST_MSLOAD
msbio:		incbin ORIG_IO_SYS, 4<<9  ; msbio payload, assuming input msload sector count == 4.
		align 16, nop
end:
%endif

; __END__
