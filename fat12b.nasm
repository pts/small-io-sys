;
; fat12b.nasm: create bootable DOS FAT12 disk images
; by pts@fazekas.hu at Wed Jan 15 15:11:13 CET 2025
;
; Compile with: nasm -O0 -w+orphan-labels -f bin -DP_1200K -o myfd.img fat12b.nasm
; Minimum NASM version required to compile: 0.98.39
;

; All floppy image sizes officially supported by MS-DOS and PC-DOS are
; available below as presets.
;
; See floppy.md for a more detailed description of these values.
fat_sector_size equ 0x200
fat_fat_count equ 2
fat_reserved_sector_count equ 1  ; Only the boot sector.
fat_hidden_sector_count equ 0  ; No sectors preceding the boot sector.
%ifdef P_160K
  fat_sector_count equ 320
  fat_head_count equ 1
  fat_sectors_per_track equ 8
  fat_media_descriptor equ 0xfe
  fat_sectors_per_cluster equ 1
  fat_rootdir_entry_count equ 64
  fat_cluster_count equ 313
  fat_expected_sectors_per_fat equ 1
%elifdef P_180K
  fat_sector_count equ 360
  fat_head_count equ 1
  fat_sectors_per_track equ 9
  fat_media_descriptor equ 0xfc
  fat_sectors_per_cluster equ 1
  fat_rootdir_entry_count equ 64
  fat_cluster_count equ 351
  fat_expected_sectors_per_fat equ 2
%elifdef P_320K
  fat_sector_count equ 640
  fat_head_count equ 2
  fat_sectors_per_track equ 8
  fat_media_descriptor equ 0xff
  fat_sectors_per_cluster equ 2
  fat_rootdir_entry_count equ 112
  fat_cluster_count equ 315
  fat_expected_sectors_per_fat equ 1
%elifdef P_360K
  fat_sector_count equ 720
  fat_head_count equ 2
  fat_sectors_per_track equ 9
  fat_media_descriptor equ 0xfd
  fat_sectors_per_cluster equ 2
  fat_rootdir_entry_count equ 112
  fat_cluster_count equ 354
  fat_expected_sectors_per_fat equ 2
%elifdef P_720K
  fat_sector_count equ 1440
  fat_head_count equ 2
  fat_sectors_per_track equ 9
  fat_media_descriptor equ 0xf9
  fat_sectors_per_cluster equ 2
  fat_rootdir_entry_count equ 112
  fat_cluster_count equ 713
  fat_expected_sectors_per_fat equ 3
%elifdef P_1200K
  fat_sector_count equ 2400
  fat_head_count equ 2
  fat_sectors_per_track equ 15
  fat_media_descriptor equ 0xf9
  fat_sectors_per_cluster equ 1
  fat_rootdir_entry_count equ 224
  fat_cluster_count equ 2371
  fat_expected_sectors_per_fat equ 7
%elifdef P_1440K
  fat_sector_count equ 2880
  fat_head_count equ 2
  fat_sectors_per_track equ 18
  fat_media_descriptor equ 0xf0
  fat_sectors_per_cluster equ 1
  fat_rootdir_entry_count equ 224
  fat_cluster_count equ 2847
  fat_expected_sectors_per_fat equ 9
%elifdef P_2880K
  fat_sector_count equ 5760
  fat_head_count equ 2
  fat_sectors_per_track equ 36
  fat_media_descriptor equ 0xf0
  fat_sectors_per_cluster equ 2
  fat_rootdir_entry_count equ 240
  fat_cluster_count equ 2863
  fat_expected_sectors_per_fat equ 9
%else
  %error MISSING_PRESET_USE_DP  ; 'Missing preset, use e.g. nasm -DP_1440K'
  db 1/0  ; Force fatal error in NASM 0.98.39.
%endif

bits 16
cpu 8086
org  0  ; Boot code is independent of `org 0x7c00'.

%macro assert_fofs 1
  times +(%1)-($-$$) times 0 nop
  times -(%1)+($-$$) times 0 nop
%endm
%macro assert_at 1
  times +(%1)-$ times 0 nop
  times -(%1)+$ times 0 nop
%endm

fat_sectors_per_fat equ ((((fat_cluster_count+2)*3+1)>>1)+0x1ff)>>9  ; Good formula for FAT12. We have the +2 here because clusters 0 and 1 have a next-pointer in the FATs, but they are not stored on disk.
fat_rootdir_sector_count equ (fat_rootdir_entry_count+0xf)>>4
fat_fat_sec_ofs equ fat_hidden_sector_count+fat_reserved_sector_count
fat_rootdir_sec_ofs equ fat_fat_sec_ofs+fat_fat_count*fat_sectors_per_fat
fat_clusters_sec_ofs equ fat_rootdir_sec_ofs+fat_rootdir_sector_count
fat_minimum_sector_count equ fat_clusters_sec_ofs+fat_cluster_count*fat_sectors_per_cluster-fat_hidden_sector_count
fat_maximum_sector_count equ fat_minimum_sector_count+fat_sectors_per_cluster-1

%if fat_rootdir_entry_count&0xf
  %error BAD_ROOTDIR_ENTRY_COUNT  ; 'Rootdir entry count must be a multiple of 0x10.'  ; Some DOS msload boot code relies on this (i.e. rounding down == rounding up).
%endif
%if fat_sectors_per_fat!=fat_expected_sectors_per_fat
  %error BAD_SECTORS_PER_FAT  ; 'Bad number of sectors per FAT.'
%endif
%if fat_sector_count<fat_minimum_sector_count
  %error TOO_MANY_SECTORS  ; 'Too many sectors.'
  db 1/0  ; Force fatal error in NASM 0.98.39.
%endif
%if fat_sector_count>fat_maximum_sector_count
  %error TOO_FEW_SECTORS  ; 'Too few sectors.'
  db 1/0  ; Force fatal error in NASM 0.98.39.
%endif
%if fat_sector_count>0xffff
  %error TOO_MANY_SECTOS_FOR_FAT12  ; 'Too many sectors, not supported by our FAT12 boot code.'
%endif

BOOT_SIGNATURE equ 0xaa55  ; dw.

boot_sector:
assert_fofs 0
; More info about FAT12, FAT16 and FAT32: https://en.wikipedia.org/wiki/Design_of_the_FAT_file_system
.header:	jmp strict short .boot_code
		nop  ; 0x90 for CHS. Another possible value is 0x0e for LBA. Who uses it? It is ignored by .boot_code.
assert_at .header+3
.oem_name:	db 'MSDOS5.0'
assert_at .header+0xb
.bytes_per_sector: dw 0x200  ; The value 0x200 is hardcoded in boot_sector.boot_code, both explicitly and implicitly.
assert_at .header+0xd
.sectors_per_cluster: db fat_sectors_per_cluster
assert_at .header+0xe
.reserved_sector_count: dw fat_reserved_sector_count
assert_at .header+0x10
.fat_count:	db fat_fat_count  ; Must be 1 or 2. MS-DOS 6.22 supports only 2. Windows 95 DOS mode supports 1 or 2.
assert_at .header+0x11
.rootdir_entry_count: dw fat_rootdir_entry_count  ; Each FAT directory entry is 0x20 bytes. Each sector is 0x200 bytes.
assert_at .header+0x13
%if fat_sector_count>0xffff  ; This doesn't happen for our FAT12.
.sector_count_zero: dw 0  ; See true value in .sector_count.
%else
.sector_count_zero: dw fat_sector_count
%endif
assert_at .header+0x15
.media_descriptor: db fat_media_descriptor  ; 0xf8 for HDD. 0xf8 is also used for some floppy disk formats as well.
assert_at .header+0x16
.sectors_per_fat: dw fat_sectors_per_fat
assert_at .header+0x18
; FreeDOS 1.2 `dir c:' needs a correct value for .sectors_per_track and
; .head_count. MS-DOS 6.22 and FreeDOS 1.3 ignore these values (after boot).
.sectors_per_track: dw fat_sectors_per_track  ; Track == cylinder. Dummy nonzero value to pacify mtools(1). Here it is not overwritten with value from BIOS int 13h AH == 8.
assert_at .header+0x1a
.head_count: dw fat_head_count  ; Dummy nonzero value to pacify mtools(1). Here it is not overwritten with value from BIOS int 13h AH == 8.
assert_at .header+0x1c
.hidden_sector_count: dd fat_hidden_sector_count ; Occupied by MBR and previous partitions.
assert_at .header+0x20
.sector_count: dd fat_sector_count
assert_at .header+0x24
;.fstype_fat32: equ .header+0x52
;.drive_number_fat32: equ .header+0x40
assert_at .header+0x24
.drive_number: db 0
assert_at .header+0x25
.var_unused: db 0  ; Can be used as a temporary variable in .boot_code.
assert_at .header+0x26
.extended_boot_signature: db 0x29
assert_at .header+0x27
.volume_id: dd 0x1234abcd  ; 1234-ABCD.
assert_at .header+0x2b
.volume_label:	db 'NO NAME    '
assert_at .header+0x36
.fstype:	db 'FAT12   '
assert_at .header+0x3e
.boot_code:

; --- MS-PC-DOS-3.30-v6-v7 universal, independent FAT12 boot sector code.
;
; Features:
;
; * It is able to boot io.sys+msdos.sys from MS-DOS 3.30--6.22. Tested with:
;   3.30, 4.01, 5.00 and 6.22.
; * It is able to boot ibmbio.com+ibmdos.com from IBM PC DOS 3.30--7.1.
;   Tested with: 7.0 and 7.1.
; * It is able to boot io.sys from Windows 95 RTM (OSR1), Windows 95 OSR2,
;   Windows 98 FE, Windows 98 SE, and the unofficial MS-DOS 8.0 (MSDOS8.ISO
;   on http://www.multiboot.ru/download/) based on Windows ME.
; * It autodetects the operating sytem (based on the kernel filenames and
;   their sizes), and uses the appropriate load protocol: MS-DOS v6
;   (supported by MS-DOS 3.30--6.22 and IBM PC DOS 3.30--7.0), MS-DOS v7
;   (supported by Windows 95--98--ME) and IBM PC DOS 7.1.
; * Although it is designed to boot from floppy disk, it can also boot from
;   HDD. But since it works only if io.sys or ibmbio.com is within the first
;   32 MiB of the disk, this limits the general usability on HDD.)
; * All the boot code fits to a boot sector (512 bytes, minus the size of
;   the FAT12 header).
; * It works with a 8086 CPU (no need for 186, 286 or 386).
; * It works even if the kernel files are fragmented.
;   This is of limited use, because the subsequent phase (msload, at the
;   beginning of the kernel file) doesn't work for a fragmented io.sys.
; * It works no matter where the kernel files are on disk.
;   This is of limited use for DOS earlier than 5.00, because those
;   versions want to load the io.sys (or ibmbio.com) from cluster 2.
; * It works even if the kernel files are not the first ones in the root
;   directory.
; * It loads the minimum number of sectors needed by the boot protocol. That
;   can be as little as 4: boot sector (already loaded), 1 sector of root
;   directory, 3 sectors at the start of the primary kernel file. Typically
;   though, it also loads at least 1 sector of the FAT pointers.
; * It caches the last FAT pointer sector loaded, and reuses it if possible
;   in the next cluster chain lookup.
;
; Limitations:
;
; * It supports only the FAT12 filesystem to boot from.
; * This boot sector supports CHS only (no EBIOS, no LBA).
; * Maximum filesystem size: 32 MiB, because the sector count is stored in
;   16 bits. (The code would not fit if it used 32 bits.)
; * It needs a special sys tool to precompute some sector offset (LBA)
;   values (indicated as `000` in the code). When the entire disk image is
;   generated by NASM (i.e. default), these values are precemputed
;   automatically.
; * Requirements: The following BPB fields must be correctly populated:
;   .media_desciptor, .hidden_sector_count (partition sector offset (LBA)),
;   .sectors_per_track (CHS cyls) and .head_count (CHS heads).
; * Before jumping to the boot sector code, the BIOS (or the MBR) must set
;   DL to the BIOS drive number.
; * It halts the system upon error, not letting the user to reboot with a
;   single keypress.
; * Error messages are not descriptive:
;   * `No IO      SYS` means that kernel files (io.sys, msdos.sys,
;     ibmbio.com and/or ibmdos.com) haven't been found in the root
;     directory.
;   * `p` means disk I/O read error.
;   * `SYS` means that an invalid value has been found when following a FAT
;     chain pointer.
;   * `MK` is a subsequent error message displayed by MS-DOS v7 io.sys
;     msload. If you see it, press a key to reboot.
;
; History:

; * Based on the FreeDOS FAT32 boot sector.
; * Modified heavily by Eric Auer and Jon Gentle in July 2003.
; * Modified heavily by Tinybit in February 2004.
; * Snapshotted code starting at *Entry_32* in stage2/grldrstart.S in
;   grub4dos-0.4.6a-2024-02-26, by pts.
; * Adapted to the MS-DOS v7 load protocol (moved away from the GRLDR--NTLDR
;   load protocol), and added MS-DOS v6 load protocol support and IBM PC DOS
;   7.1 load protocol support by pts in January 2025.
; * Changed from FAT32 to FAT16 by pts in January 2025.
; * Changed from MBR-dependent to independent by pts in January 2025.
; * Changed from FAT16 to FAT12 by pts in January 2025.
;
; You can use and copy source code and binaries under the terms of the
; GNU Public License (GPL), version 2 or newer. See www.gnu.org for more.
;
; Memory layout:
;
; * 0...0x400: Interrupt table.
; * 0x400...0x500: BIOS data area.
; * 0x500...0x700: Unused.
; * 0x700...0xf00: 4 sectors loaded from io.sys.
; * 0xf00...0x2000: Unused.
; * 0x2000...0x2200: Sector read from the FAT12 FAT.
; * 0x2200...0x7b00: Unused.
; * 0x7b00...0x7c00: Stack used by this boot sector.
; * 0x7c00...0x7e00: This boot sector.
;

.org: equ -0x7c00+.header
;.var_fat_sec_ofs: equ .boot_code+4  ; Only the low word is used. dd. Sector offset (LBA) of the first FAT in this FAT filesystem, from the beginning of the drive (overwriting unused bytes). Only used if .fat_sectors_per_cluster<4.
;.var_single_cached_fat_sec_ofs_low: equ .boot_code+8  ; Removed. dw. Last accessed FAT sector offset (LBA), low word (overwriting unused bytes). Some invalid value if not populated.
.var_clusters_sec_ofs: equ .header-4  ; Only the low word is used. dd. Sector offset (LBA) of the clusters (i.e. cluster 2) in this FAT filesystem, from the beginning of the drive. This is also the start of the data.
.var_orig_int13_vector: equ .header-8  ; dd. segment:offset. Old DPT pointer.

		mov bp, -.org+.header
		cli
		xor ax, ax
		mov ss, ax
		mov sp, bp

		mov [bp-.header+.drive_number], dl  ; BIOS or MBR has passed drive number in DL.

		; Copy the disk initialization parameter table (.dipt, DPT).
		mov bx, 0x1e<<2  ; int 1eh vector (DPT).
		lds si, [bx]
		push si
		mov di, 0x522  ; Windows 95--98--ME also copy to here. https://stanislavs.org/helppc/bios_data_area.html also lists it.
		mov [es:bx], di  ; Change int 1eh vector (DPT).
		mov [es:bx+2], es
		mov cx, 0xb
		rep movsb  ; Size of the DPT.
		pop si  ; Will be pushed below.
		mov byte [es:di-2], 0xf  ; Set floppy head bounce delay == head settle time, in milliseconds, to 0xf: https://stanislavs.org/helppc/int_1e.html ; https://retrocomputing.stackexchange.com/q/31099/3494
		mov cx, [bp-.header+.sectors_per_track]
		mov [es:di-7], cl  ; Set sectors_per_track in the DPT.

		; Figure out where FAT and data areas start.
%if 0  ; There isn't enough space to compute this here.
		xchg dx, ax  ; DX := AX (0); AX := junk. AX has been set to 0 by fat_boot_sector_common.
		mov ax, [bp-.header+.reserved_sector_count]
		add ax, [bp-.header+.hidden_sector_count]
		adc dx, [bp-.header+.hidden_sector_count+2]
		mov [bp-.header+.var_fat_sec_ofs], ax
		dec ax
		;mov [bp-.header+.var_single_cached_fat_sec_ofs_low], ax  ; Cache not populated yet.
		inc ax
		mov [bp-.header+.var_fat_sec_ofs+2], dx
		xor cx, cx
		mov cl, [bp-.header+.fat_count]  ; 1 or 2.
.add_fat:	add ax, [bp-.header+.sectors_per_fat]
		adc dx, byte 0
		loop .add_fat
                ; Now: AX == the sector offset (LBA) of the root directory in this FAT filesystem.
		mov bx, [bp-.header+.rootdir_entry_count]
		mov di, bx
		add di, byte 0xf
		mov cl, 4  ; Assuming word [bp-.header+.bytes_per_sector] == 0x200.
		shr di, cl
		xor cx, cx
		add di, ax
		adc cx, dx
                push cx
                push di  ; dword [bp-.header+.var_clusters_sec_ofs] := CX:DI (final value).
                mov cx, bx
		mov bx, 0x1e<<2  ; int 1eh vector (DPT).
%else
		;xor ax, ax ; Already 0. mov ax, 000  ; High word of dword [bp-.header+.var_clusters_sec_ofs]
		push ax  ; High word of dword [bp-.header+.var_clusters_sec_ofs] to 0. Needed by MS-DOS v7 msload at [SS:BP-2].
		mov ax, fat_clusters_sec_ofs  ; mov ax, 000  ; Low word of dword [bp-.header+.var_clusters_sec_ofs].
		push ax
		;mov word [bp-.header+.var_fat_sec_ofs], 000  ; Hardcoded it to the `add' instruction below.
		mov cx, fat_rootdir_entry_count  ; mov cx, 000  ; Number of root directory entries.
		;mov dx, 000  ; Zero. High word of the sector offset (LBA) of the root directory in this FAT filesystem.
		mov ax, fat_rootdir_sec_ofs  ; mov ax, 000  ; Low word of the sector offset (LBA) of the root directory in this FAT filesystem.
%endif

		push ds  ; Segment of dword [.var_orig_int13_vector].
		push si  ; Offset of dword [.var_orig_int13_vector].
		push ss  ; Will be discarded by MS-DOS v7 msload. Push segment 0 for compatibility. In practice, msload in MS-DOS v7 ignores this value.
		;mov bx, 0x1e<<2  ; No need, already true.
		push bx  ; Will be discarded by MS-DOS v7 msload. Push offset 0x78 == (0x1e<<2) for compatibility. In practice, msload in MS-DOS v7 ignores this value.

		push es
		pop ds  ; DS := ES (0).
		mov es, [bp-.header+.jmp_far_inst+3]  ; mov es, 0x700>>4. Load root directory and kernel (io.sys) starting at 0x70:0 (== 0x700).

		; Search the root directory for a kernel file.
                ; Now: AX == the sector offset (LBA) of the root directory in this FAT filesystem; CX: number of root directory entries.
		; BL := missing-filename-bitset (io.sys: 1 and msdos.sys: 2). Starts from 3 == (1|2), since both are missing.
		; BH := number of sectors to load. Initialize it to 3, and we increment to 4 later if needed. MS-DOS 7.x (Windows 95, Windows 98) and 8.0 (Windows ME) need >=4, MS-DOS 3.30..6.22 work with >=3.
		; It doesn't work with MS-DOS 3.30, because it doesn't have msload: MS-DOS 3.30 boot sector loads the entire io.sys (16138 == 0x3f0a bytes).
		mov bx, 0x303
.read_rootdir_sector:
                ; Now: AX == the next sector offset (LBA) of the root directory in this FAT filesystem; CX: number of root directory entries remaining.
		call .read_disk
		inc ax  ; Next sector.
		xor di, di  ; Points to next directory entry to compare filename against.
.next_entry:  ; Search for kernel file name, and find start cluster.
		push cx  ; Save.
		push di  ; Save.
		mov si, -.org+.io_sys
		mov cx, 11  ; .io_sys_end-.io_sys
		repe cmpsb
		jne .not_io_sys
		cmp [es:di-11+0x1c+2], cl  ; 0x1c is the offset of the dword-sized file size in the FAT directory entry.
		je .do_io_sys_or_ibmbio_com  ; Jump if file size of io.sys is shorter than 0x10000 bytes. This is true for MS-DOS v6 (e.g. 6.22), false for MS-DOS v7 (e.g. Windows 95).
		mov byte [bp-.header+.jmp_far_inst+2], 2  ; MS-DOS v7 load protocol wants `jmp 0x70:0x200', we set the 2 here.
		inc bh  ; Increment number of sectors to load from 3 to 4.
		and bl, ~2  ; No need for msdos.sys.
.do_io_sys_or_ibmbio_com:
		mov si, 0x500+0x1a  ; Load protocol: io.sys expects directory entry of io.sys at 0x500.
		and bl, ~1
		jmp short .copy_entry
.not_io_sys:	pop di
		push di
		inc cx  ; Skip over NUL.
		add si, cx  ; Assumes that .ibmbio_com follows .io_sys. mov si, -.org+.ibmbio_com
		mov cl, 11  ; .io_sys_end-.io_sys
		repe cmpsb
		je .do_io_sys_or_ibmbio_com
		pop di
		push di
		add si, cx  ; Assumes that .msdos_sys follows .ibmbio_com. Like this, but 1 byte shorter: mov si, -.org+.msdos_sys
		mov cl, 11  ; .msdos_sys_end-.msdos_sys  ; CH is already 0.
		repe cmpsb
		jne .not_msdos_sys
.do_msdos_sys_or_ibmdos_com:
		and bl, ~2
		mov si, 0x520+0x1a  ; Load protocol: io.sys expects directory entry of msdos.sys at 0x520.
.copy_entry:	; MS-DOS <=6.22 and IBM PC DOS 7.1 only use 2 words of the
		; 0x20-byte FAT directory entries copied to 0x500 (io.sys)
		; and 0x520 (msdos.sys); the low (+0x1a) and high (+0x14)
		; words of the file start cluster number. The latter is only
		; used for FAT32. So we only copy those words here.
		mov cx, [es:di-11+0x1a]  ; Copy low word of file start cluster number.
		mov [si], cx  ; Save to [0x500+0x1a] or [0x520+0x1a].
		jmp short .entry_done
.not_msdos_sys:
		pop di
		push di
		add si, cx  ; Assumes that .ibmdos_com follows .msdos_sys. mov si, -.org+.ibmdos_com
		mov cl, 11  ; .io_sys_end-.io_sys
		repe cmpsb
		je .do_msdos_sys_or_ibmdos_com
		; Fall through to .entry_done.
.entry_done:	pop di  ; Restore.
		pop cx  ; Restore the remaining number of rootdir sectors to read.
		;test bl, bl  ; Not needed, ZF is already correct because of `jne' or `and dh, ~...'.
		jz .found_both_sys_files
		loop .try_next_entry
		mov si, -.org+.errmsg_missing   ; No more root directory entries. This means that kernel file was not found.
		;jmp short .fatal  ; Fall through.
; Prints NUL-terminated message starting at SI, and halts. Ruins many registers.
.fatal:
		mov ah, 0xe
		xor bx, bx  ; mov bx, 7  ; BL == 7 (foreground color) is used in graphics modes only.
.next_msg_byte:	lodsb
		test al, al  ; Found terminating NUL?
		jz .halt
		int 0x10
		jmp short .next_msg_byte
.halt:		cli
.hang:		hlt
		jmp .hang
		; Not reached.
.try_next_entry:
		lea di, [di+0x20]  ; DI := address of next directory entry.
		cmp di, [bp-.header+.bytes_per_sector]  ; 1 byte shorter than `cmp di, 0x200'.
		jne .next_entry ; next directory entry
		jmp short .read_rootdir_sector

.found_both_sys_files:  ; Kernel directory entry is found. Scratch registers: CX, SI.
		xor dx, dx  ; We'll store the in-cache FAT sector offset in DX. 0 means unpopulated.
		mov di, [0x500+0x1a]  ; Get cluster number. DI will be used later by the MS-DOS v7 load protocol.
		mov ax, di
		; Read msload (first few sectors) of the kernel (io.sys).
		;
		; AX: current cluster number.
		; BL: number of remaining sectors to load from the current cluster (will be set later, in .cluster_to_lba).
		; BH: number of remaining sectors to load.
		; DX: sector offset (LBA) of the in-cache FAT sector. 0 means unpopulated.
		; DI: start cluster number of the kernel (io.sys or ibmbio.com). It will be used later by the MS-DOS v7 load protocol.
		; BP: points to the beginning of the boot sector (0x7c00).
		; ES: segment to load the next sector of the kernel to. Will be used by .read_disk. Starts with 0x70, thus load starts at 0x70:0 (== 0x700).
		; CX, SI: scratch registers.
.next_kernel_cluster:  ; Now: AX: next cluster number; BX: ruined; CH: number of remaining sectors to read; CL: ruined.
		push ax  ; Save cluster number.
.cluster_to_lba:  ; Converts cluster number to the sector offset (LBA).
		dec ax
		dec ax
		cmp ax, strict word 0xff8-2  ; Make it fail for 0, 1 and >=0xff8 (FAT12 minimum special cluster number).
		;jc .no_eoc
		; EOC encountered before we could read 4 sectors.
		mov si, -.org+.errmsg_sys
		jnc .fatal
.no_eoc:	; Sector := (cluster-2) * clustersize + data_start.
		mov bl, [bp-.header+.sectors_per_cluster]
		push bx  ; Save for BH (number of remaining sectors to load).
		mov bh, 0
		mul bx
		pop bx  ; Restore for BH.
		add ax, [bp-.header+.var_clusters_sec_ofs]
		;adc dx, [bp-.header+.var_clusters_sec_ofs+2]  ; Also CF := 0 for regular data.
.read_kernel_sector:  ; Now: CL is sectors per cluster; AX is sector offset (LBA).
		call .read_disk
		inc ax  ; Next sector.
		mov si, es
		add si, byte 0x20
		mov es, si
		dec bh
		jz .jump_to_msload
.cont_kernel_cluster:
		dec bl  ; Consume 1 sector from the cluster.
		jnz .read_kernel_sector
		pop ax  ; Restore cluster number.
.next_cluster:  ; Find the number of the next cluster in the FAT12.
		; Now: AX: cluster number.
		push es  ; Save.
		; This is the magic logic which calculates FAT12 FAT sector number (to AX) and byte offset within sector (to SI).
		mov cx, ax
		shr ax, 1
		add ax, cx
		mov si, ax
		rcr ax, 1
		and si, 0x1ff  ; Keep low 9 bits in SI.
		; Now: AX == sector number (within the first FAT); CX == cluster number; SI == byte offset of the pointer word.
		mov ch, cl  ; Keeping it for the low bit (parity).
		mov cl, 4  ; Bit shift amount of 4 for FAT12.
		mov al, ah
		mov ah, 0
		; Now: AX is the sector offset within the first FAT.
		; Now: SI is the byte offset of the pointer word or dword within the sector (can be 0x1ff, which indicates split word).
		; Now: CL is 4. It will be used as a shift amount on the low word of the byte offset.
		; Now: CH is the low byte of the cluster number (will be used for its low bit, parity) for FAT12, 0 for others.
		add ax, strict word fat_fat_sec_ofs  ; add ax, strict word 000  ; Low word of [bp+var.fat_sec_ofs].
		;adc dx, [bp+var.fat_sec_ofs+2]
		mov es, [bp-.header+.bytes_per_sector]  ; Tricky way to `mov es, 0x200'.
		cmp ax, dx  ; Is sector with offset AX cached?
		je .fat_sector_read  ; If cached, skip reading it again.
		call .read_fat_sector_to_cache
.fat_sector_read:
		push word [es:si]  ; Save low word of next cluster number.
		cmp si, 0x1ff
		jne .got_new_pointer
		inc ax  ; Next sector.
		call .read_fat_sector_to_cache
		pop ax  ; Restore low word of next cluster number to AX.
		mov ah, [es:0]  ; Get high byte of next cluster number from the next sector.
		push ax  ; Make the following `pop ax' a nop.
.got_new_pointer:
		pop ax  ; Restore low word of next cluster number to AX.
		test ch, 1  ; Is FAT12 cluster number odd?
		jnz .odd
		shl ax, cl
.odd:		shr ax, cl
		; Now: AX is the number of next cluster.
		pop es  ; Restore.
		; Now: AX: next cluster number.
		jmp short .next_kernel_cluster

.jump_to_msload:
		pop ax  ; Discard current cluster number.
		; Fill registers according to MS-DOS v6 load protocol.
		mov bx, [bp-.header+.var_clusters_sec_ofs]
		xor ax, ax  ; mov ax, [bp-.header+.var_clusters_sec_ofs+2]
		; Fill registers according to MS-DOS v7 load protocol: https://pushbx.org/ecm/doc/ldosboot.htm#protocol-sector-msdos7
		; True by design: SS:BP -> boot sector with (E)BPB, typically at linear 0x7c00.
		; True by design: dword [ss:bp-4] = (== dword [bp-.header+.var_clusters_sec_ofs]) first data sector of first cluster, including hidden sectors.
		mov word [bp+0x1ee], -.org+.msdosv7_message_table  ; For MS-DOS v7, fill word [SS:BP+0x1ee] pointing to a message table. bp+0x1ee overwrites 2 byte in the middle of .ibmdos_com (11 bytes, not needed anymore). The format of this table is described in lDebug's source files https://hg.pushbx.org/ecm/ldebug/file/66e2ad622d18/source/msg.asm#l1407 and https://hg.pushbx.org/ecm/ldebug/file/66e2ad622d18/source/boot.asm#l2577 .
		; Fill registers according to MS-DOS v6 load protocol.
		mov dl, [bp-.header+.drive_number]  ; MS-DOS v7 (such as Windows 98 SE) expects the drive number in the BPB (.drive_number_fat1x and .drive_number_fat32) instead.
		; Fill registers according to MS-DOS v7 load protocol: https://pushbx.org/ecm/doc/ldosboot.htm#protocol-sector-msdos7
		; Already filled: DI == first cluster of load file if FAT12 or FAT16. (SI:DI == first cluster of load file if FAT32.)
		; Fill registers according to MS-DOS v6 load protocol: https://pushbx.org/ecm/doc/ldosboot.htm#protocol-sector-msdos6
		mov ch, [bp-.header+.media_descriptor]  ; https://retrocomputing.stackexchange.com/q/31129 . IBM PC DOS 7.1 boot sector seems to set it, propagating it to the DRVFAT variable, propagating it to DiskRD. Does it actually use it? MS-DOS 6.22 fails to boot if this is not 0xf8 for HDD (Is it true? Does it accept 0xf0 as well? Or anything?). MS-DOS 4.01 io.sys GOTHRD (in bios/msinit.asm) uses it, as media byte. MS-DOS 4.01 io.sys GOTHRD (in bios/msinit.asm) uses it, as media byte.
		; Pass orig DPT (int 13h vector value) to MS-DOS v6 and IBM
		; PC DOS 7.0 in DS:SI. MS-DOS v7 and IBM PC DOS 7.1 expect
		; it on the stack instead (we've already pushed it, as dword
		; [.var_orig_int13_vector] above): they pop 4 bytes from the
		; stack, and then they pop offset (word [SS:SP+4]), then
		; segment ((word [SS:SP+6])) of the original DPT.
		; https://stanislavs.org/helppc/int_1e.html
		lds si, [bp-.header+.var_orig_int13_vector]
.jmp_far_inst:	jmp 0x70:0  ; Jump to boot code (msload) loaded from io.sys. Self-modifying code: the offset 0 has been changed to 0x200 for MS-DOS v7.
.errmsg_disk: equ $-2  ; Just write 'p', 0. ('p' == 0x70.) We don't have space anywhere else for a more descriptive error message.
.read_fat_sector_to_cache:
		mov dx, ax  ; Save sector offset in AX to the cached sector offset (DX).
		; Fall through to .read_disk.

; Reads a sector from disk, using CHS.
; Inputs: AX: sector offset (LBA); ES: ES:0 points to the destination buffer.
; Ruins: flags.
.read_disk:
		push ax  ; Save.
		push bx  ; Save.
		push cx  ; Save.
		push dx  ; Save.
		; Converts sector offset (LBA) value in AX to BIOS-style
		; CHS value in CX and DH. Ruins DL, AX and flag. This is
		; heavily optimized for code size.
		xor dx, dx
		div word [bp-.header+.sectors_per_track]  ; We assume that .sectors_per_track is between 1 and 63.
		inc dx  ; Like `inc dl`, but 1 byte shorter. Sector numbers start with 1.
		mov cx, dx  ; CX := sec value.
		xor dx, dx
		div word [bp-.header+.head_count]  ; We assume that .head_count is between 1 and 255.
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
		xor bx, bx  ; Use offset 0 in ES:BX.
		mov dl, [bp-.header+.drive_number]  ; This offset depends on the filesystem type (FAT16 or FAT32). %if fat_32.
		int 0x13  ; BIOS syscall to read sectors.
		jnc .read_disk_ok
.jc_fatal_disk:	mov si, -.org+.errmsg_disk
		jmp near .fatal
.read_disk_ok:	pop dx  ; Restore.
		pop cx  ; Restore.
		pop bx  ; Restore.
		pop ax  ; Restore.
		;adc dx, byte 0
		ret

.errmsg_missing: db 'No '  ; Overlaps the following .io_sys.
.io_sys:	db 'IO      SYS', 0  ; Must be followed by .ibmbio_com in memory.
.io_sys_end:
.errmsg_sys: equ $-4  ; Just write 'SYS', 0.
.ibmbio_com:	db 'IBMBIO  COM'  ; Must be followed by .msdos_sys in memory.
.ibmbio_com_end:
.msdos_sys:	db 'MSDOS   SYS'  ; Must be followed by .ibmdos_com in memory.
.msdos_sys_end:
.ibmdos_com:	db 'IBMDOS  COM'  ; Must follow .ibmdos_com in memory.
.ibmdos_com_end:

; MS-DOS v7 msload expects word [SS:BP+0x1ee] point to a message table (as
; an offset from the start of the boot sector).
;
; Since we are very tight on space in this boot sector, we add only a
; message table with single-byte messages ('M' as a regular message and 'K'
; for press-any-key).
;
; More docs about the format of the message table:
; https://hg.pushbx.org/ecm/ldebug/file/66e2ad622d18/source/msg.asm#l1407
.msdosv7_message_table: db 3, 2, 1, 2, 'M', 0xff, 'K', 0

		times 0x1fe-($-.header) db '-'  ; Padding.
.boot_signature: dw BOOT_SIGNATURE
assert_at .header+0x200

remaining_reserved_sectors:
assert_fofs 1<<9
		times (fat_reserved_sector_count-1)<<7 dd 0  ; `times ...<<7 dd 0' is faster than `times <<9 db 0' in NASM 0.98.39.
assert_fofs fat_reserved_sector_count<<9

first_fat:
assert_fofs (fat_fat_sec_ofs-fat_hidden_sector_count)<<9
.fat:		db fat_media_descriptor, 0xff, 0xff  ; For FAT16, there would be another 0xff here.
		times 0x10-($-.fat) db 0  ; Free.
		times (fat_sectors_per_fat<<7)-4 dd 0  ; Rest of the clusters are free.

%if fat_fat_count>1  ; fat_fat_count must be 2.
second_fat:
.fat:		db fat_media_descriptor, 0xff, 0xff  ; For FAT16, there would be another 0xff here.
		times 0x10-($-.fat) db 0  ; Free.
		times (fat_sectors_per_fat<<7)-4 dd 0  ; Rest of the clusters are free.
%endif

root_directory:
assert_fofs (fat_rootdir_sec_ofs-fat_hidden_sector_count)<<9
		times fat_rootdir_sector_count<<7 dd 0  ; Empty.

clusters:
assert_fofs (fat_clusters_sec_ofs-fat_hidden_sector_count)<<9
		;times (fat_sector_count-fat_clusters_sec_ofs)<<7 dd 0  ; Empty.
		section .end start=((fat_sector_count<<9)-1) align=1  ; This is much faster than the `times' above.
		db 0  ; Make sure that the section is actually emitted.

; __END__
