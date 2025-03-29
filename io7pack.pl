#!/bin/sh --
eval 'PERL_BADLANG=x;export PERL_BADLANG;exec perl -x "$0" "$@";exit 1'
#!perl  # Start marker used by perl -x.
+0 if 0;eval("\n\n\n\n".<<'__END__');die$@if$@;__END__

#
# io7pack.pl: compressor for MS-DOS 7.x and 8.0 IO.SYS
# by pts@fazekas.hu at Tue Jan 21 21:29:16 CET 2025
#
# This script works with Perl 5.004.04 (1997-10-15) or later.
#
# Based on: IOPAK8.ZIP my Mercury: https://disk.yandex.ru/d/8XVJOSoOLOFheA/IOPAK8.ZIP
#
# TODO(pts): Add `upx --lzma' compression, it can make 68 KiB instead of 72 KiB io.sys.
#

BEGIN { $ENV{LC_ALL} = "C" }  # For deterministic output. Typically not needed. Is it too late for Perl?
BEGIN { $ENV{TZ} = "GMT" }  # For deterministic output. Typically not needed. Perl respects it immediately.
BEGIN { $^W = 1 }  # Enable warnings.
use integer;
use strict;

my $apack1p_prog;  # https://github.com/pts/apack1p
my $upx_prog;  # https://upx.github.io/  For our needs (LZMA compression), UPX 3.91--4.2.4 produce identical results.
my $do_ignores_logo = 0;
my $apack1p_compressor;
my $upx_compressor;
my $filter = 0;
for (my $i = 0; $i < @ARGV; ++$i) {
  my $arg = $ARGV[$i];
  if ($arg eq "--") { splice(@ARGV, 0, $i + 1); last }
  elsif ($arg eq "-" or $arg !~ m@^-@) { splice(@ARGV, 0, $i); last }
  elsif ($arg =~ m@^--apack1p=(.*)@s) { $apack1p_prog = $1; $apack1p_compressor = "apack1p" }
  elsif ($arg =~ m@^--upx=(.*)@s) { $upx_prog = $1; $upx_compressor = "upx" }
  elsif ($arg =~ m@^--upx-?lzma=(.*)@s) { $upx_prog = $1; $upx_compressor = "upx-lzma" }
  elsif ($arg eq "--ignores-logo") { $do_ignores_logo = 1 }
  elsif ($arg =~ m@^--filter=(.*)@s) { $filter = (int($1) or 0) }  # A non-zero filter value breaks the output, but is good for experimenting with compressibility.
  else { die "fatal: unknown command-line flag: $arg\n" }
}
my $compressor = defined($upx_compressor) ? $upx_compressor : $apack1p_compressor;
die "Usage: $0 [<flag> ...] <input.sys> <output.sys>\n" if @ARGV != 2;
die "fatal: compressor not chosen, specify at least one of --apack1p=..., --upx=... and --upx-lzma=...\n" if !defined($compressor);
my $infn = $ARGV[0];
my $outfn = $ARGV[1];

sub fnopenq($) { $_[0] =~ m@[-+.\w]@ ? $_[0] : "./" . $_[0] }
sub read_file($) {
  my $fn = $_[0];
  die "fatal: open: $fn: $!\n" if !open(FR, "< " . fnopenq($fn));
  binmode(FR);
  my $s = join("", <FR>);
  die if !close(FR);
  $s
}
sub write_file($$) {
  my($fn, $data) = @_;
  die "fatal: open for write: $fn\n" if !open(F, "> " . fnopenq($fn));
  binmode(F);
  { my $fh = select(F); $| = 1; select($fh); }
  die "fatal: error writing to $fn\n" if !print(F $data);
  die "fatal: error flushing: $fn\n" if !close(F);
}

$_ = read_file($infn);
my $insize = length($_);
my($msload, $upx_init_ofs, $rbseg, $rbseg_fofs, $var_fat_cache_segment_fofs, $apack1p_udata);
my($msdcm_image, $msdcm_minallocx, $msdcm_ss, $msdcm_sp, $msdcm_ip, $msdcm_cs);
{
  die "fatal: not an io.sys file: $infn\n" if substr($_, 0, 2) ne "MZ" or substr($_, 0x200, 2) ne "BJ";
  my $msloadsize = (substr($_, 0x340 - 4, 4) eq "ML7I") ? 0x340 : (substr($_, 0x400 - 4, 4) eq "ML7I") ? 0x400 : (substr($_, 0x800 - 2, 2) eq "MS" and substr($_, 0x800 - 10, 4) eq "ML7I") ? 0x800 : 0;
  die "fatal: missing ML7I msload in io.sys file: $infn\n" if !$msloadsize;
  my($signature, $lastsize, $nblocks, $nreloc, $hdrsize, $minalloc, $maxalloc, $ss, $sp, $checksum, $ip, $cs) = unpack("a2v11", substr($_, 0, 0x18));
  die "fatal: assert: bad MZ signature: $infn\n" if $signature ne "MZ";   # Also checked above.
  die "fatal: bad MZ nreloc: $infn\n" if $nreloc;   # Also checked above.
  die "fatal: bad MZ hdrsize: $infn\n" if ((length($_) + 0xf) >> 4) < $hdrsize;
  if (!$nblocks) {
    # It's OK to have any $checksum value.
    die "fatal: bad missing MSDCM in MZ header: $infn\n" if $lastsize or $nblocks or $minalloc or $maxalloc or $ss or $sp or $ip or $cs;
  } else {
    my $image_size = (($lastsize & 0x1ff) or 0x200) + (($nblocks - 1) << 9);
    die "fatal: unexpected MZ maxalloc: $infn\n" if $maxalloc != 0xffff;
    die sprintf("fatal: bad MZ image size: 0x%x vs 0x%x: %s\n", $image_size, length($_), $infn)
        if $image_size != length($_);  # In general, we could be lenient and check > instead of !=.
    substr($_, $image_size) = "";
  }
  die "fatal: msbio payload too short: $infn\n" if length($_) < $msloadsize + 3;
  die "fatal: MZ hdrsize too large: $infn\n" if ((length($_) + 0xf) >> 4) < $hdrsize;
  $msload = substr($_, 0, $msloadsize);
  $msdcm_image = (length($_) > ($hdrsize << 4)) ? substr($_, $hdrsize << 4) : "";
  $msdcm_minallocx = ($nblocks << 5) + $minalloc - $hdrsize;
  ($msdcm_ss, $msdcm_sp, $msdcm_ip, $msdcm_cs) = ($ss, $sp, $ip, $cs);
  my $insize2 = $hdrsize << 4;
  die "fatal: MZ hdrsize too large: $infn\n" if $insize2 > (($insize + 0xf) & ~0xf);
  $insize = $insize2 if $insize > $insize2;
  substr($_, $insize) = "";
  #$signature = "MZ";  # Unchanged.
  $nreloc = $minalloc = $maxalloc = $ss = $sp = $checksum = $ip = $cs = 0;
  $hdrsize = $msloadsize >> 4;
  my $rbseg_code;
  $rbseg_fofs = 0x1a;
  ($rbseg_code, $rbseg) = unpack("a2v", substr($msload, $rbseg_fofs - 2, 4));  # Typical $rbseg value: 0x4800.
  die "fatal: bad reloc-base-segment code: $infn\n" if $rbseg_code ne "\xfc\xb8";  # cld ++ mov ax, RELOC_BASE_SEGMENT.
  die "fatal: bad reloc-base-segment value: $infn\n" if $rbseg < 0x3400 or $rbseg > 0x5000;  # Other values may work, this is just a sanity check.
  $var_fat_cache_segment_fofs = index($msload, "\x5b\x5b\xeb\x09\x90");  # pop bx ++ pop bx ++ jmp short initialized_data.end ++ nop.
  die "fatal: initialized_data not found in msload: $infn\n" if $var_fat_cache_segment_fofs < 0 or $var_fat_cache_segment_fofs > 0x80;  # Typical value is 0x61.
  $var_fat_cache_segment_fofs += 5 + 4 + 2;
  my $var_fat_cache_segment = unpack("v", substr($msload, $var_fat_cache_segment_fofs, 2));
  die "fatal: bad var_fat_cache_segment value in msload: $infn\n" if  # Also checked in fixmsdcm.pl.
      # This corresponds to `var.fat_cache_segment: dw RELOC_BASE_SEGMENT+0xc0-0x10+(EXTRA_SKIP_SECTOR_COUNT<<5)' in msloadv7i.nasm.
      $var_fat_cache_segment != $rbseg + 0xc0 - 0x10 + ((length($msload) == 0x340) << 6);
  if (defined($upx_compressor) and defined($apack1p_compressor)) {
    $apack1p_udata = $_;
    $lastsize = ($insize & 0x1ff);
    $nblocks = ($insize + 0x1ff) >> 9;
    substr($apack1p_udata, 0, 0x18) = pack("a2v11", $signature, $lastsize, $nblocks, $nreloc, $hdrsize, $minalloc, $maxalloc, $ss, $sp, $checksum, $ip, $cs);
  }
  if ($compressor =~ m@^upx@) {
    die "fatal: bad jmp-near-init opcode: $infn\n" if substr($_, $msloadsize, 1) ne "\xe9";  # Opcode of `jmp strict near INIT'.
    $upx_init_ofs = unpack("v", substr($_, $msloadsize + 1, 2)) + 3;  # Offset of `INIT' code in msbio. Segment is is 0x70.
    die "fatal: bad init offset: $infn\n" if $upx_init_ofs < 3 or $upx_init_ofs >= 0x8003;
    die "fatal: bad start code: $infn\n" if substr($_, $msloadsize + $upx_init_ofs, 4) ne "\xfa\xfc\x2b\xf6";  # cli ++ cld ++ sub si, si.
    substr($_, $msloadsize, 3) = "\xfa\x17\xc3";  # replace_start_code: cli ++ pop ss ++ ret.
    substr($_, $msloadsize + $upx_init_ofs, 4) = "\x61\xfc\x17\x90";  # popa ++ cld ++ pop ss ++ nop.  # popa needs at least 186 CPU.
    #substr($_, $msloadsize, 8) = "\xba\xe9\x00\xb0\x43\xee\xfa\xf4";  # Debug msbio payload: write C to QEMU console, and halt. This takes about 0.5 in QEMU, because LZMA decompression is slow.
    #my $regdump_code = read_file("regdump.com"); substr($_, $msloadsize, length($regdump_code)) = $regdump_code;  # Debug msbio payload: dump all registers and halt.
    substr($_, 0x3c, 4) = "\0\0\0\0" if $hdrsize >= 4;  # Prevent UPX from failing to detect this DOS MZ .exe as an NE, LE or PE.
    # We locate a long enough (>=0xa0 bytes) of unused bytes, to be used by `pop ss' above.
    my $msgfofs = index($_, "\0IOSYSMSG", $msloadsize);
    die "fatal: missing IOSYSMSG: $infn\n" if $msgfofs < 0;
    die "fatal: bad IOSYSMSG location\n" if $msgfofs < 0x3000 or $msgfofs > 0x7000;  # We could be more permissive here.
    $msgfofs += 9 + 2;  # Skip 2 offset bytes.
    my $stack_data = substr($_, $msgfofs, 0xd0);  # There are typically 0x240 unused bytes.
    $stack_data =~ s@\A(?:MPAD|\0)+@@;
    die "fatal: no unused space after IOSYSMSG: $infn\n" if length($stack_data);
    my $stackbot_fofs = $msgfofs + (-($msgfofs - 0xa) & 0xf) - 0xa;
    die "fatal: assert: stackbot not at page boundary\n" if $stackbot_fofs & 0xf;
    ($ss, $sp) = (($stackbot_fofs >> 4) - $hdrsize - 0x66, 0x700 - 0x16);  # SP := 0x700 - 0x16, this makes SS:SP+2 == 0:0x700-0x14, so that the `popa` and the second `pop ss' will get their values pushed by $before_decompressor_code below.
    substr($_, $stackbot_fofs + -0x660 + 0x700 - 0x16, 2) = "\0\0";  # The first `pop ss' above will set SS := 0. The SP value -0x660 + 0x700 - 0x16 is a bit larger than 0x80, good enough for temporary stack.
  }
  $lastsize = ($insize & 0x1ff);
  $nblocks = ($insize + 0x1ff) >> 9;
  substr($_, 0, 0x18) = pack("a2v11", $signature, $lastsize, $nblocks, $nreloc, $hdrsize, $minalloc, $maxalloc, $ss, $sp, $checksum, $ip, $cs);
}

my $ufn = "apack1.tmp";  # Compression input. !! Use temporary filenames depending on the input file. Maybe only one file.
my $cfn = "apack2.tmp";  # Compressed output. !! Use temporary filenames depending on the input file. Maybe only one file.
unlink($ufn, $cfn);
if ($filter) {  # Apply filter on $_. The filter must not change the .exe MZ header plus a few bytes (first 0x20 bytes in total) and the size.
  # Similar to UPX 3.94 DOS .com filters: 1: f_ct16_e8, 2: f_ct16_e9, 3: f_ct16_e8e9, 4: f_ct16_e8_bswap_le, 5: f_ct16_e9_bswap_le, 6: f_ct16_e8e9_bswap_le.
  #
  # !! Apply filter 6 for real: save about 1429 (== 70393 - 68964) bytes (minus the filter code). Implement filter 6 in 8086 assembly manually, for longer than 64 KiB.
  #    $ for FI in 1 2 3 4 5 6; do tools/miniperl-5.004.04.upx -x io7pack.pl '--upx-lzma=tools/upx-3.94.upx' --ignores-logo --filter="$FI" IO.SYS.win98sekbp IO.SYS.win98sekbplf"$FI"; done
  #    $ ls -ld --sort=size IO.SYS.win98sekbplf? IO.SYS.win98sekbpl
  #
  # $ tools/miniperl-5.004.04.upx -x io7pack.pl '--upx-lzma=tools/upx-3.94.upx' --ignores-logo --filter=6 IO.SYS.win98sekbp IO.SYS.win98sekbplf6
  # $ ~/prg/upxbc/upxbc --upx=upx.pts --flat32 --lzma -f -o apack0.tmp.lzma4x apack0.tmp
  # info: read input: apack0.tmp (121632 bytes, format flat32)
  # info: running with udata_size=121632 padding_size=0 udata2_size=0: upx.pts -qq --best --lzma -- apack0.tmp.lzma4x.tmp
  # info: writing compressed output: apack0.tmp.lzma4x (71303 bytes, format flat32, method LZMA, filter none)
  #
  # !! Use i386 32-bit protected-mode LZMA decompressor, making it much faster (in QEMU). Unfortunately the predicted code size is much more (69762 > 68964), and the switching to protected mode will be on top of that.
  #    The UPX LZMA decompressor for 8086 16-bit is ~1800 bytes (slow), and for i386 32-bit is ~2700 bytes. Maybe we can make the 32-bit code ~2500 bytes only by optimizing its surroundings.
  # $ ~/prg/upxbc/upxbc --upx=upx.pts --flat32 --ultra-brute --no-filter -f -o apack3.tmp.lzma6 apack3.tmp
  # info: read input: apack3.tmp (121632 bytes, format flat32)
  # info: running with udata_size=121632 padding_size=0 udata2_size=0: upx.pts -qq --lzma --ultra-brute --no-filter -- apack3.tmp.lzma6.tmp
  # info: writing compressed output: apack3.tmp.lzma6 (69762 bytes, format flat32, method LZMA, filter none)
  write_file("apack0.tmp", substr($_, 0x20));  # For upxbc.
  my $i_limit = length($_) - 2;
  my $addvalue = -0x21;  # !! Is this absolutely correct?
  if ($filter >= 1 and $filter <= 6) {
    my $filter3 = $filter % 3;
    my $e8 = ($filter3 == 1 or $filter3 == 0) ? 0xe8 : -1;
    my $e9 = ($filter3 == 2 or $filter3 == 0) ? 0xe9 : -1;
    my $packchar = ($filter >= 4) ? "n" : "v";
    for (my $i = 0x20; $i < $i_limit; ++$i) {
      my $v = vec($_, $i, 8);
      if ($v == $e8 or $v == $e9) {
        ++$i;
        substr($_, $i, 2) = pack($packchar, ((unpack("v", substr($_, $i, 2)) + $addvalue + $i) & 0xffff));
        ++$i;
      }
    }
    write_file("apack3.tmp", substr($_, 0x20));  # For upxbc.
  } else {
    die "fatal: unknown filter: $filter\n";
  }
}
write_file($ufn, $_);
$_ = undef;  # Save memory.
sub compress($) {
  my($compressor) = @_;
  my @compress_cmd = ($compressor eq "upx-lzma") ? ($upx_prog, "--lzma", "--small", "-f", "-q", "-q", "-q", "-o", $cfn, $ufn) :
      ($compressor eq "upx") ? ($upx_prog, "--no-lzma", "--no-reloc", "--ultra-brute", "--small", "-f", "-q", "-q", "-q", "-o", $cfn, $ufn) :
      ($compressor eq "apack1p") ? ($apack1p_prog, "-q", "-1", $ufn, $cfn) : die();
  print(STDERR "info: running compress cmd: @compress_cmd\n");  # TODO(pts): Escape arguments.
  die "fatal: error running $compressor: $compress_cmd[0]\n" if system(@compress_cmd);
  die "fatal: compressed output file not created: $cfn\n" if !-f($cfn);
  my $cdata = read_file($cfn);
  unlink($cfn);
  my $outsize_estimate = length($cdata) + 3 * !$do_ignores_logo + (($compressor eq "upx-lzma") ? 36 + 3 : ($compressor eq "upx") ? 36 + 6 : ($compressor eq "apack1p") ? 6 - 0xb : die());
  ($compressor, $cdata, $outsize_estimate)
}
my($used_compressor, $cdata, $outsize_estimate) = compress($compressor);
if (defined($upx_compressor) and defined($apack1p_compressor)) {
  write_file($ufn, $apack1p_udata);
  $apack1p_udata = undef;  # Save memory.
  my($compressor3, $cdata3, $outsize_estimate3) = compress($apack1p_compressor);
  ($used_compressor, $cdata, $outsize_estimate) = ($compressor3, $cdata3, $outsize_estimate3) if $outsize_estimate3 < $outsize_estimate;
  print(STDERR "info: chosen better compressor: $used_compressor\n");
}
unlink($ufn, $cfn);
($_, $cdata) = ($cdata, undef);  # Save memory.
my $outsize;
{
  die "fatal: compressed output not a DOS .exe file: $cfn\n" if substr($_, 0, 2) ne "MZ";
  die "fatal: compressed output too short: $cfn\n" if length($_) < 0x22 + 1 + 0xb;
  my($csignature, $clastsize, $cnblocks, $cnreloc, $chdrsize, $cminalloc, $cmaxalloc, $css, $csp, $cchecksum, $cip, $ccs, $crelocpos) = unpack("a2v12", substr($_, 0, 0x1a));
  # We ignore: $cminalloc (except for size calculations), $cmaxalloc, $css, $csp, $cchecksum.
  die "fatal: assert: bad MZ signature in compressed output: $cfn\n" if $csignature ne "MZ";   # Also checked above.
  die "fatal: bad hdrsize in compressed output: $cfn\n" if $chdrsize != 2;
  die "fatal: bad ccs in compressed output: $cfn\n" if $ccs != 0;
  die "fatal: bad cip in compressed output: $cfn\n" if $cip != 0;
  my $expected_csize = (($clastsize & 0x1ff) or 0x200) + (($cnblocks - 1) << 9);
  die "fatal: bad compressed output size: $cfn\n" if length($_) != $expected_csize;
  # +0x70 is msbio base segment; +0xa is stack space (0xa0 bytes); -0x60 is
  # to compensate for the offsets (+0x700 for temporary stack, +0x800 for
  # relocated msload).
  my $min_rbseg = ($cnblocks << 5) - $chdrsize + $cminalloc + 0x70 + 0xa - 0x60;
  if ($rbseg < $min_rbseg) {  # If $rbseg in $msload is too low to fit the decompressor, increase it. Typically this increases $rbseg from 0x4000 to near 0x4300 for LZMA with the logo included.
    # Windows 98 SE is resilient enough so that it boots fine to GUI even if
    # SS:BP points to garbage (rather than the 0x62 bytes copied from the
    # beginning of the boot sector (BPB), with some bytes overwritten). We
    # apply this fix so that SS:BP will correctly point to these bytes, at
    # the beginning of the relocated first msload sector.
    my $new_var_fat_cache_segment = unpack("v", substr($msload, $var_fat_cache_segment_fofs, 2)) + ($min_rbseg - $rbseg);
    $new_var_fat_cache_segment = (($new_var_fat_cache_segment + 0x10) & ~0xfff) + 0x20 - 0x10 if
        (($new_var_fat_cache_segment + 0x10) & 0xfff) > 0xfe0;  # If the sector read would cross a 64 KiB boundary, fix it. https://retrocomputing.stackexchange.com/a/31157
    printf(STDERR "info: increasing rbseg: old=0x%x new=0x%x new_vfcs=0x%x vfcs_fofs=0x%x\n", $rbseg, $min_rbseg, $new_var_fat_cache_segment, $var_fat_cache_segment_fofs);
    substr($msload, $rbseg_fofs, 2) = pack("v", $min_rbseg);
    substr($msload, $var_fat_cache_segment_fofs, 2) = pack("v", $new_var_fat_cache_segment);
    $rbseg = $min_rbseg;  # For `if ($used_compressor =~ m@^upx@)' below.
  }
  my $msbio_passed_para_count = ($insize - length($msload)) >> 4; # Same as load_para_count in msbio. Passed in DI from msload to msbio.
  if ($used_compressor =~ m@^upx@) {
    die "fatal: bad nreloc in compressed output: $cfn\n" if $cnreloc != 0;
    my($reg_init_code, $do_set_es_to_psp);
    if (substr($_, $chdrsize << 4, 5) eq "\x16\x07\xbb\x00\x80") {  # push ss ++ pop es ++ mov bx, 0x8000. Only true for the output of `upx --lzma'.
      $do_set_es_to_psp = 0;
      $reg_init_code = "\xbb\x00\x80";  # mov bx, 0x8000
    } elsif (substr($_, $chdrsize << 4, 6) =~ m@^[\xb8-\xbf]..[\xb8-\xbf]..@s) {  # mov cx, ? (\xb9) ++ mov si, ? (\xbe) ++ mov di, si (\x89\xf7) ++ push ds (\x1e). The output of `upx --no-lzma'.
      # die "fatal: output of upx --no-lzma not supported yet: $cfn: $infn\n";
      $do_set_es_to_psp = 1;
      $reg_init_code = substr($_, $chdrsize << 4, 6);  # Copy the `mov cx, ?' and the `mov si, ?' instructions.
      substr($_, ($chdrsize << 4) + 5, 1) = "\x90";  # nop.
    } else {
      die "fatal: bad decompressor starter code: $cfn: $infn\n";
    }
    my $before_decompressor_code = join("",  # Add code to be called before the decompressor:
        # Now (as set up by msloadv7i.nasm): SS == RELOC_BASE_SEGMENT == 0x4400; SP <= 0x800 (0x800 or a few bytes less), BP == 0x800, AX == 0, BX == 0, DI == msbio_passed_para_count == load_para_count == hdrsize - msload_para_size.
        "\xfa",  # cli  ; Prevent stack from being used while modifying SP below.
        "\xbc", pack("v", 0x70 - 0x10),  # mov sp, 0x70-0x10
        "\x8e\xd4",  # mov ss, sp
        "\x8e\xdc",  # mov ds, sp  ; Fake PSP segment for DOS MZ .exe.
        $do_set_es_to_psp ? "\x8e\xc4" : "",  # mov es, sp  ; Fake PSP segment for DOS MZ .exe.
        "\xbc", pack("v", 0x700 - ((0x70 - 0x10) << 4)),  # mov sp, 0x700-((0x70-0x10)<<4)  # mov sp, 0x100
        "\x68", pack("v", $rbseg),  # push strict word 0x4800 ; Segment for the second `pop ss'. This push needs at least 186 CPU.
        ($do_ignores_logo ? "" : "\xbf" . pack("v", $msbio_passed_para_count)),  # mov di, $msbio_passed_para_count
        "\x31\xf6",  # xor si, si  ; Instead of the `sub si, si` in the start code.
        "\x60",  # pusha  ; For the popa. Needs at least 186 CPU. The `popa' also needs at least 186 CPU.
        "\x68", pack("v", $upx_init_ofs),  # push strict word 0x8d3  ; Offset for the ret. This push needs at least 186 CPU.
        "\xbc", pack("v", $css + 0x70),  # mov sp, mz_header_compressed.ss+0x70
        "\x8e\xd4",  # mov ss, sp
        $do_set_es_to_psp ? "" : "\x8e\xc4",  # mov es, sp
        "\xbc", pack("v", $csp),  # mov sp, mz_header_compressed.sp
        "\xfb",  # sti
        #"\x16",  # push ss
        #"\x07",  # pop es
        #"\xba\xe9\x00",  # mov dx, 0xe9
        #"\xb0\x42",  # mov al, 'B'
        #"\xee",  # out dx, al  ; Debug: Write AL == 'B' to MSBIO console.
        $reg_init_code,
        "\xea", pack("vv", $cip + 5, $ccs + 0x70));  # jmp 0x70:5  ; Jump to decompressor code, after 5 bytes.
    die "fatal: assert: bad decompressor code size\n" if length($before_decompressor_code) != 36 + 3 * !$do_ignores_logo + length($reg_init_code);
    #my $regdump_code = read_file("regdump.com"); substr($before_decompressor_code, 14) = $regdump_code;  # Debug msbio payload: dump all registers and halt.
    my $before_decompressor_addr = 0x700 + length($_) - ($chdrsize << 4);
    substr($_, $chdrsize << 4, 5) = pack("avv", "\xea", $before_decompressor_addr & 0xf, $before_decompressor_addr >> 4);
    #write_file("t.bin", $before_decompressor_code);
    $outsize = length($_) + length($before_decompressor_code);
    $_ .= $before_decompressor_code;
  } else {  # apack1p.
    die "fatal: bad nreloc in compressed output: $cfn\n" if $cnreloc != 1;
    die "fatal: bad crelocpos in compressed output: $cfn\n" if $crelocpos != 0x1c;
    my($reloc0ofs, $reloc0seg) = unpack("vv", substr($_, $crelocpos, 4));
    my $expected_reloc0_fofs = ($chdrsize << 4) + ($reloc0seg << 4) + $reloc0ofs;
    die "fatal: bad reloc0 fofs: $cfn\n" if $expected_csize - $expected_reloc0_fofs != 2;  # Patch the very last 2 bytes, i.e. the segmeint in the `jmp 0:0' instruction.
    die "fatal: unexpected APACK-compressed MZ starter code bytes: $cfn\n" if substr($_, 0x20, 2) ne "\x1e\x06";
    my $trailer_code = unpack("H*", substr($_, -0xb));
    # pop es ++ pop ds ++ mov ss, ax ++ xor sp, sp ++ jmp 0:0  # The segment of the jump would be modified by a relocation, which we ignore.
    die "fatal: unexpected APACK-compressed MZ trailer code bytes: $trailer_code\n" if $trailer_code ne "071f8ed033e4ea00000000";
    my $trailer_code2 = $do_ignores_logo ? "\x61\xea\0\0\x70\0" :  # popa ++ jmp 0x70:0. Please note that `popa' and the self-extractor code uses 186 instructions, thus it will (silently) fail on the 8086.
        "\x61\xbf" . pack("v", $msbio_passed_para_count) . "\xea\0\0\x70\0";  # \xbf is: mov di, the value is msbio_passed_para_count, same as load_para_count.
    die "fatal: assert: bad trailer code size\n" if length($trailer_code2) - 0xb != 6 - 0xb + 3 * !$do_ignores_logo;
    $outsize = length($_) + length($trailer_code2) - 0xb;
    substr($_, $chdrsize << 4, 2) = "\x60\x90";  # We must not change the size, hence we add a nop (\x90).
    substr($_, -0xb) = $trailer_code2;
  }
  #substr($_, $chdrsize << 4, 8) = "\xba\xe9\x00\xb0\x41\xee\xfa\xf4";  Debug msbio payload: write A to QEMU console, and halt.
  #substr($_, $chdrsize << 4, 9) = "\xb8\x41\x0e\x31\xdb\xcd\x10\xfa\xf4";  # Debug msbio playload: write to the emulated screen, and halt.
  die "fatal: assert: bad outsize 1\n" if length($_) != $outsize;
  die "fatal: assert: bad outsize estimate: esitimate=$outsize_estimate actual=$outsize: $cfn\n" if $outsize != $outsize_estimate;
  $outsize += length($msload) - ($chdrsize << 4);
  #$_ .= "\0" x (-length($_) & 0xf);  # No need to pad file size to a multiple of 0x10, msloadv7i works without such padding. For MSDCM, we will pad it later.
  my $hdrsize = ($outsize + 0xf) >> 4;
  my $image_size = ($hdrsize << 4) + length($msdcm_image);
  my $nblocks = ($image_size + 0x1ff) >> 9;
  my $minalloc = $msdcm_minallocx - ($nblocks << 5) + $hdrsize;
  $minalloc = 1 if $minalloc < 1;
  my $lastsize = $image_size & 0x1ff;
  my($signature, $nreloc, $maxalloc, $checksum) = ("MZ", 0, 0xffff, 0);
  ($lastsize, $nblocks, $minalloc, $maxalloc, $msdcm_ss, $msdcm_sp, $msdcm_ip, $msdcm_cs) = (0, 0, 0, 0, 0, 0, 0, 0) if !length($msdcm_image);
  substr($_, 0, $chdrsize << 4) = $msload;
  substr($_, 0, 0x18) = pack("a2v11", $signature, $lastsize, $nblocks, $nreloc, $hdrsize, $minalloc, $maxalloc, $msdcm_ss, $msdcm_sp, $checksum, $msdcm_ip, $msdcm_cs);
  die "fatal: assert: bad outsize 2\n" if length($_) != $outsize;
  if (length($msdcm_image)) { $_ .= "\0" x (-length($_) & 0xf); $_ .= $msdcm_image; $outsize = length($_) }
  write_file($outfn, $_);
  $_ = undef;  # Save memory.
}

printf(STDERR "info: compressed io.sys %s (%d bytes) to %s (%d bytes)\n", $infn, $insize, $outfn, $outsize);
unlink($ufn, $cfn);

__END__
