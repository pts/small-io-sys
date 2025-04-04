#!/bin/sh --
eval 'PERL_BADLANG=x;export PERL_BADLANG;exec perl -x "$0" "$@";exit 1'
#!perl  # Start marker used by perl -x.
+0 if 0;eval("\n\n\n\n".<<'__END__');die$@if$@;__END__

#
# upxdc.pl: UPX-based data and self-extracting code compressor
# by pts@fazekas.hu at Mon Mar 31 15:35:35 CEST 2025
#
# This script works with Perl 5.004.04 (1997-10-15) or later.
#
# !!! UPX doesn't use the specified filter: !! Patch UPX.
#     $ tools/miniperl-5.004.04.upx upxdc.pl --flat32 --prefix=0x340 --force-lzma --filter=0x49 ~/prg/small-io-sys/IO.SYS.win98sekbp IO.SYS.win98sekbplx
#    But here it does correctly:
#     $ tools/miniperl-5.004.04.upx upxdc.pl --flat32 --force-lzma --filter=0x49 memtest86+-5.01-dist.bin t
# !!! Sometimes (1 out of 10) Win98 decompression stucks at boot. It's flaky. Is it a QEMU bug? Does it happen to the uncompressed kernel? Does it happen if the kernel file is unchanged? Investigate.
#

BEGIN { $ENV{LC_ALL} = "C" }  # For deterministic output. Typically not needed. Is it too late for Perl?
BEGIN { $ENV{TZ} = "GMT" }  # For deterministic output. Typically not needed. Perl respects it immediately.
BEGIN { $^W = 1 }  # Enable warnings.
use integer;
use strict;

sub fnopenq($) { $_[0] =~ m@[-+.\w]@ ? $_[0] : "./" . $_[0] }
# This is Unix-only, it should be ported to Windows (CommandLineToArgvW).
sub shq($) { my $arg = $_[0]; if (!length($arg) or $arg !~ y@-:=+./A-Za-z0-9@@) { $arg =~ s@'@'\\''@g; $arg = "'$arg'" } $arg }

sub read_file($) {
  my $fn = $_[0];
  die("fatal: open: $fn: $!\n") if !open(FR, "< " . fnopenq($fn));
  binmode(FR);
  my $s = join("", <FR>);
  die("") if !close(FR);
  $s
}
sub write_file($$) {
  my($fn, $data) = @_;
  die("fatal: open for write: $fn\n") if !open(F, "> " . fnopenq($fn));
  binmode(F);
  { my $fh = select(F); $| = 1; select($fh); }
  die("fatal: error writing to $fn\n") if !print(F $data);
  die("fatal: error flushing: $fn\n") if !close(F);
}

sub create_elf32_from_data($) {
  my $udata = $_[0];
  my $e_osabi = 3;  # Linux.
  my $base = 0x10000;
  # Without this padding, UPX 3.94 PackLinuxElf32::canPack(...) would raise
  # an IOException in fi->readx(...), causing linux/i386 to be disabled and
  # linux.exec/i386 used instead.
  my $padding_size = length($udata) + 0x54 < 500 ? 500 - length($udata) - 0x54 : 0;
  pack("a4CCCCCx7vvVVVVVvvvvvvVVVVVVVV", "\x7fELF", 1, 1, 1, $e_osabi, 0, 2, 3, 1, $base + 0x54, 0x34, 0, 0, 0x34, 0x20, 1, 0x28, 0, 0,
       1, 0, $base, $base, 0x54 + length($udata), 0x54 + length($udata), 5, 0x1000
      ) . $udata . ("\0" x $padding_size);
}

my %methods = (0 => "uncompressed", 2 => "NRV2B_LE32", 3 => "NRV2B_8", 4 => "NRV2B_LE16", 5 => "NRV2D_LE32", 6 => "NRV2D_8", 7 => "NRV2D_LE16", 8 => "NRV2E_LE32", 9 => "NRV2E_8", 10 => "NRV2E_LE16", 14 => "LZMA");
my %elf_filters = (0 => "none", 0x46 => "ctok32_0x46", 0x49 => "ctok32_jxx_0x49");  # Only for UPX Linux i386. UPX Win32 PE supports more filters.
my %com_filters = (0 => "none", 1 => "ct16_e8_le_0x01", 2 => "ct16_e9_le_0x02", 3 => "ct16_e8e9_le_0x03", 4 => "ct16_e8_be_0x04", 5 => "ct16_e9_be_0x05", 6 => "ct16_e8e9_be_0x06"); # 6 gives the best compression most of the time.
my %filters = (%elf_filters, %com_filters);
my %filters_with_cto = (0x46 => 1, 0x49 => 1);

sub M_LZMA() { 14 }

sub does_method_match_category($$) {
  my($method, $category) = @_;
  return !defined($category) ? 1 :
      ($category eq "lzma") ? $method == M_LZMA :
      ($category eq "nrv2b") ? ($method >= 2 and $method <= 4) :
      ($category eq "nrv2d") ? ($method >= 5 and $method <= 7) :
      ($category eq "nrv2e") ? ($method >= 8 and $method <= 10) : 0
}

# TODO(pts): Implement filters 0x46 and 0x49 (with filter_cto), or add a wrapper which just runs upx(1) for the filter.
sub is_filter_implemented($) {
  my $filter = $_[0];
  defined($filter) and $filter >= 0 and $filter <= 6
}

# Modifies $_[0] in place. $addvalue is used by filters 0x01..0x06, the value is 0x100 for .com, 0 for .sys.
sub do_filter($$$$) {
  my($s, $filter, $filter_cto, $addvalue) = @_;
  return if !$filter;  # Filter none is a no-op.
  die("fatal: bad filter value: $filter\n") if $filter < 0 or $filter > 0xff;
  die(sprintf("fatal: filter not implemented: %s\n", ($filters{$filter} or sprintf("0x%02x", $filter)))) if !is_filter_implemented($filter);
  # This is an implementation of filters ct16_e8_le_0x01, ct16_e9_le_0x02,
  # ct16_e8e9_le_0x03, ct16_e8_be_0x04, ct16_e9_be_0x05, ct16_e8e9_be_0x06.
  # Based on upx-3.94-src/src/filter/ct.h . It is exactly the same as in UPX 3.94.
  my $i_limit = length($s) - 3;  # This could be 1 less and still be correct, but we keep it as is to remain compatible with UPX 3.94.
  my $filter3 = $filter % 3;
  my $e8 = ($filter3 == 1 or $filter3 == 0) ? 0xe8 : -1;
  my $e9 = ($filter3 == 2 or $filter3 == 0) ? 0xe9 : -1;
  my $packchar = ($filter >= 4) ? "n" : "v";
  for (my $i = 0; $i < $i_limit; ++$i) {
    my $v = vec($s, $i, 8);
    if ($v == $e8 or $v == $e9) {
      ++$i;
      substr($_[0], $i, 2) = pack($packchar, ((unpack("v", substr($s, $i, 2)) + $addvalue + $i) & 0xffff));  # Update $_[0] in place.
      ++$i;
    }
  }
}

# Modifies $_[0] in place.
# $packchar defines the byte order ("v" for litte-endian, "n" for big-endian).
sub add_to_filter_addvalue($$$;$) {
  my($s, $filter, $addvalue_delta, $packchar) = @_;
  return if !$filter or !$addvalue_delta or $filter < 1 or $filter > 6;
  # Based on upx-3.94-src/src/filter/ct.h .
  my $i_limit = length($s) - 3;  # This could be 1 less and still be correct, but we keep it as is to remain compatible with UPX 3.94.
  my $filter3 = $filter % 3;
  my $e8 = ($filter3 == 1 or $filter3 == 0) ? 0xe8 : -1;
  my $e9 = ($filter3 == 2 or $filter3 == 0) ? 0xe9 : -1;
  $packchar = ($filter >= 4) ? "n" : "v" if !defined($packchar);
  for (my $i = 0; $i < $i_limit; ++$i) {
    my $v = vec($s, $i, 8);
    if ($v == $e8 or $v == $e9) {
      ++$i;
      substr($_[0], $i, 2) = pack($packchar, ((unpack($packchar, substr($s, $i, 2)) + $addvalue_delta) & 0xffff));  # Update $_[0] in place.
      ++$i;
    }
  }
}

# Returns bool indicating whether the filter should be done in the wrapper (this Perl script).
sub should_do_filter_in_wrapper($$) {
  my($desired_filter, $upx_tmpfmt) = @_;
  return 0 if !$desired_filter;  # UPX can always do --no-filter. This also applies when the filter is unspecified (undef).
  return 0 if $desired_filter >= 1 and $desired_filter <= 6 and ($upx_tmpfmt eq "com" or $upx_tmpfmt eq "sys");  # UPX can do it in DOS .com and DOS .sys, but not in DOS .exe or ELF.
  return 0 if ($desired_filter == 0x46 or $desired_filter == 0x49) and $upx_tmpfmt eq "elf";
  1  # Do all other filters in the wrapper.
}

sub get_stats($$$) {
  my($method, $filter, $filter_cto) = @_;
  my $filter_cto_msg = exists($filters_with_cto{$filter}) ? sprintf(", filter cto 0x%02x", $filter_cto) : "";
  "method $methods{$method}, filter $filters{$filter}$filter_cto_msg"
}

# This (unlike compress_upx_data32) allows the output file to be larger than the input.
sub compress_xz_lzma1($$$$$$) {
  my($udata_aryref, $tmpfn, $xz_prog, $lzma_settings, $desired_filter, $do_filter_in_wrapper) = @_;
  my $usize = length($udata_aryref->[0]);
  die("fatal: assert: filter must be done in wrapper\n") if $desired_filter and !$do_filter_in_wrapper;
  do_filter($udata_aryref->[0], $desired_filter, 0, 0) if $do_filter_in_wrapper;  # TODO(pts): Autodetect filter_cto, just like UPX does. The current filters don't use it.
  die("fatal: bad tmp file name for xz\n") if $tmpfn =~ m@[.](?:xz|lzma[12]?)\Z(?!\n)@i;
  # xz(1) always creates a streamed LZMA1 file, i.e. usize unspecified, and containing an end-of-stream (EOS) == end-of-payload marker.
  my @compress_cmd = ($xz_prog, "--format=lzma");
  push @compress_cmd, $1 if $lzma_settings =~ s@^(-[^,]+),+@@;  # Example: -9e,pb=0 . preset=9e,pb=0 produces a different output file.
  substr($lzma_settings, 0, 0) = ",";
  my $dict_size_in;
  if ($lzma_settings !~ m@,dict=@) {
    $dict_size_in = ($usize < 0 or $usize > 0x7fffffff) ? 0x7fffffff : $usize < 4096 ? 4096 : $usize;
    $lzma_settings .= ",dict=$dict_size_in";
  }
  $lzma_settings =~ s@^,+@@;
  push @compress_cmd, "--lzma1=$lzma_settings" if $lzma_settings =~ y@,@@c;
  push @compress_cmd, "--", $tmpfn;
  write_file($tmpfn, pop(@$udata_aryref));
  unlink("$tmpfn.lzma");
  print(STDERR "info: running xz compressor: ", join(" ", map { shq($_) } @compress_cmd), "\n");
  my $status = system(@compress_cmd);
  unlink($tmpfn);
  $tmpfn .= ".lzma";
  if ($status) {
    unlink($tmpfn);
    die("fatal: error running xz compressor: $compress_cmd[0]\n");
  }
  my $s = read_file($tmpfn);
  die("fatal: LZMA1 file too short for header\n") if length($s) < 13;
  my($b, $dict_size, $usize_low, $usize_high) = unpack("CVVV", substr($s, 0, 13));
  die("fatal: bad LZMA1 usize, expected streaming\n") if $usize_low != 0xffffffff and $usize_high != 0xffffffff;
  die("fatal: LZMA1 file too short for data\n") if length($s) <= 13;
  die("fatal: bad LZMA1 dict size\n") if ($dict_size < 4096 and $dict_size >= 0) or ($dict_size & ($dict_size - 1));
  die("fatal: unexpected LZMA1 dict size: $dict_size\n") if defined($dict_size_in) and $dict_size > 4096 and $dict_size < $dict_size_in;
  my $lc = $b % 9; $b /= 9;
  my $lp = $b % 5; $b /= 5;
  my $pb = $b;
  die("fatal: bad LZMA1 pos_bits: $pb\n") if $pb > 4;
  substr($s, 0, 13) = pack("CC", $pb | ($lc + $lp) << 3, $lc | $lp << 4);  # Replace LZMA1 header with UPX-style LZMA header.
  my $method = M_LZMA; my $filter = ($desired_filter or 0); my $filter_cto = 0;
  my $stats = get_stats($method, $filter, $filter_cto);
  my $csize = length($s);
  print(STDERR "info: xz compression results: $usize --> $csize bytes, $stats\n");
  ($method, $filter, $filter_cto, $s)
}

# For technical reasons, even our patched UPX 3.94 cannot return a
# compressed data string longer than the input (uncompressed data). Even if
# they are equal in size, UPX will return the original uncompressed data
# string with method 0.
sub compress_upx_data32($$$$$$$$) {
  my($udata_aryref, $tmpfn, $method_flags, $upx_prog, $upx_tmpfmt, $desired_filter, $desired_method_category, $do_filter_in_wrapper) = @_;
 AGAIN:
  my $usize = length($udata_aryref->[0]);
  die("fatal: uncompressed data empty\n") if !$usize;  # !! TODO(pts): Add workaround by hardcoding.
  # UPX requires specific extensions for some formats.
  die("fatal: bad extension for format $upx_tmpfmt: $tmpfn\n") if $upx_tmpfmt eq "com" and $tmpfn !~ m@[.]com$@;
  my $s = ($upx_tmpfmt eq "com" and !defined($desired_filter)) ? $udata_aryref->[0] :  # We may need it again in AGAIN.
      pop(@$udata_aryref);  # pop(...) to save memory.
  do_filter($s, $desired_filter, 0, 0) if $do_filter_in_wrapper;
  if ($upx_tmpfmt eq "elf") {
    $s = create_elf32_from_data($s);
  } elsif ($upx_tmpfmt eq "exe") {
    # !! Detect the maximum file size here. Should be ~1024 KiB or ~635 KiB.
    my $img_size = length($s) + 0x40;
    substr($s, 0, 0) = pack("a2vvvvx54", "MZ", ($img_size & 0x1ff), ($img_size + 0x1ff) >> 9, 0, 4);  # Add simple DOS .exe header.
  } elsif ($upx_tmpfmt eq "com") {  # Similar to PackCom::canPack() in upx-3.94-src/src/p_com.cpp.
    die("fatal: uncompressed data too large for .com\n") if length($s) > 0xff00;
    die("fatal: found ELF header in .com file\n") if $s =~ m@^\x7fELF@;
    die("fatal: found DOS .exe MZ header in .com file\n") if $s =~ m@^(?:MZ|ZM)@;
    die("fatal: found DOS .sys header in .com file\n") if $s =~ m@^\xff\xff\xff\xff@;
    # UPX uses addvalue == 0x100 when applying filters 0x01..0x06 to DOS
    # .com programs. We preprocess to input to counter this, and get the end
    # result as if addvalue == 0 was used by UPX.
    add_to_filter_addvalue($s, $desired_filter, -0x100, "v") if !$do_filter_in_wrapper;
  }
  my $expected_pi_filesize = length($s);
  write_file($tmpfn, $s);
  $s = undef;  # Save memory.
  my $filter_flag =
      ($do_filter_in_wrapper or (defined($desired_filter) and !$desired_filter)) ? "--no-filter" :
      defined($desired_filter) ? sprintf("--filter=0x%02x", $desired_filter) : "--all-filters";
  my @compress_cmd = ($upx_prog, "-qq", @$method_flags, $filter_flag, "--", $tmpfn);  # !! TODO(pts): Redirect statistics printed by UPX from STDOUT to /dev/null.
  print(STDERR "info: running UPX compressor: ", join(" ", map { shq($_) } @compress_cmd), "\n");
  die("fatal: error opening oldout: $!\n") if !open(OLDOUT, ">&STDOUT");
  my $to_dev_null = ">/dev/null";  # This is Unix-only, it should be ported to Windows.
  die("fatal: error reopening stdout: $!\n") if !open(STDOUT, $to_dev_null);  # To hide the file size debug message.
  my $status = system(@compress_cmd);
  die("fatal: error reopening stdout: $!\n") if !open(STDOUT, ">&OLDOUT");
  die("fatal: error closing oldout: $!\n") if !close(OLDOUT);
  if ($status) {
    unlink($tmpfn);
    die("fatal: error running UPX compressor: $compress_cmd[0]\n")
  }
  $s = read_file($tmpfn);
  unlink($tmpfn);  # !! Also delete it on die(...) in read_file etc.
  my($cdata, $method, $filter, $filter_cto);
  if ($upx_tmpfmt eq "com") {
    die("fatal: found ELF header in UPX output .com file\n") if $s =~ m@^\x7fELF@;
    die("fatal: found DOS .exe MZ header in UPX output .com file\n") if $s =~ m@^(?:MZ|ZM)@;
    die("fatal: found DOS .sys header in UPX output .com file\n") if $s =~ m@^\xff\xff\xff\xff@;
    my $i = index(substr($s, 0, 64), "UPX!");
    die("fatal: missing UPX signature in UPX output .com file\n") if $i < 0;
    die("fatal: EOF in UPX pack header in UPX output .com file\n") if length($s) < $i + 22;
    # PackHeader::putPackHeader(...) with UPX_F_DOS_COM in upx-3.94-src/src/packhead.cpp .
    my($h_version, $h_format, $h_method, $h_level, $h_uadler, $h_cadler, $h_usize, $h_csize, $h_filter, $h_checksum) = unpack("x4CCCCVVvvCC", substr($s, $i, 22));
    $i += 22;
    die("fatal: bad h_format\n") if $h_format != 1;  # UPX_F_DOS_COM.
    die("fatal: bad h_version\n") if $h_version < 10 or $h_version > 14;  # Must be at least 10, UPX 3.94 returns 13.
    die("fatal: unknown h_method: $h_method\n") if !$h_method or !exists($methods{$h_method});
    die("fatal: unknown h_filter: $h_filter\n") if !exists($com_filters{$h_filter});
    die("fatal: bad h_level\n") if $h_level > 10;
    die("fatal: bad h_usize\n") if $h_usize != $usize;
    die("fatal: bad h_csize\n") if $i + $h_csize > length($s);
    $h_filter = 0 if $h_filter >= 1 and $h_filter <= 6 and $usize < 4;  # The filter doesn't change short data. Make it explicit so that the unfilter code doesn't have to check for overflows.
    if (!defined($desired_filter) and $h_filter >= 1 and $h_filter <= 6) {
      # UPX has applied this filter with addvalue == 0x100. We want it with
      # addvalue == 0, so we run UPX again, this time preparing the input
      # with add_to_filter_addvalue(...).
      $desired_filter = $h_filter;
      goto AGAIN;
    }
    $cdata = substr($s, $i, $h_csize);
    $s = undef;  # Save memory.
    ($method, $filter, $filter_cto) = ($h_method, $h_filter, 0);
  } elsif ($upx_tmpfmt eq "exe") {
    die("fatal: found ELF header in UPX output .exe file\n") if $s =~ m@^\x7fELF@;
    die("fatal: found DOS .sys header in UPX output .exe file\n") if $s =~ m@^\xff\xff\xff\xff@;
    die("fatal: missing DOS .exe MZ signature in UPX output\n") if $s !~ m@^MZ@;  # UPX doesn't generate "ZM".
    my($lastsize, $nblocks, $nreloc, $hdrsize, $minalloc, $maxalloc, $ss, $sp, $checksum, $ip, $cs, $relocpos, $noverlay) = unpack("x2v15", substr($s, 0, 0x20));
    die("fatal: unexpected DOS .exe lastsize\n") if $lastsize > 0x200;  # UPX doesn't generate this.
    die("fatal: zero DOS .exe nblocks\n") if $nblocks == 0;
    my $img_size = (($lastsize & 0x1ff) or 0x200) + (($nblocks - 1) << 9);
    die("fatal: too small DOS .exe image size\n") if $img_size < ($hdrsize << 4);
    die("fatal: too large DOS .exe image size\n") if $img_size - ($hdrsize << 4) >> 20;  # Larger than 1 MiB.
    die("fatal: unexpected DOS .exe image size\n") if $img_size != length($s);
    die("fatal: unexpected DOS .exe nreloc\n") if $nreloc != 1;  # UPX generates it like this.
    die("fatal: unexpected DOS .exe hdrsize\n") if $hdrsize != 2;  # UPX generates it like this.
    die("fatal: unexpected DOS .exe cs\n") if $cs;  # UPX generates it like this.
    die("fatal: unexpected DOS .exe ip\n") if $ip;  # UPX generates it like this.
    die("fatal: unexpected DOS .exe relocpos\n") if $relocpos != 0x1c;  # UPX generates it like this.
    my $i = index(substr($s, 0x20, 0x60), "UPX!");
    die("fatal: missing UPX signature in UPX output DOS .exe file\n") if $i < 0;
    die("fatal: EOF in UPX pack header in UPX output DOS .exe file\n") if length($s) < $i + 27;
    # PackHeader::putPackHeader(...) with UPX_F_DOS_EXE in upx-3.94-src/src/packhead.cpp .
    my($eh_version, $eh_format, $eh_method, $eh_level, $eh_uadler, $eh_cadler, $eh_usize, $eh_usize_high, $eh_csize, $eh_csize_high, $eh_filesize, $eh_filesize_high, $eh_filter, $eh_checksum) = unpack("x4CCCCVVvCvCvCCC", substr($s, $i + 0x20, 27));
    $i += 0x20 + 27;
    $eh_usize |= $eh_usize_high << 16;
    $eh_csize |= $eh_csize_high << 16;
    $eh_filesize |= $eh_filesize_high << 16;
    die("fatal: bad eh_format\n") if $eh_format != 3;  # UPX_F_DOS_EXE.
    die("fatal: bad eh_version\n") if $eh_version < 10 or $eh_version > 14;  # Must be at least 10, UPX 3.94 returns 13.
    die("fatal: unknown eh_method: $eh_method\n") if !$eh_method or !exists($methods{$eh_method});
    die("fatal: unknown eh_filter: $eh_filter\n") if !exists($com_filters{$eh_filter});
    die("fatal: bad eh_level\n") if $eh_level > 10;
    die("fatal: bad eh_filesize\n") if $eh_filesize != $usize + 0x40;
    die("fatal: bad eh_usize\n") if $eh_usize != $usize;
    die("fatal: bad eh_csize\n") if $i + $eh_csize > length($s);
    $cdata = substr($s, $i, $eh_csize);
    $s = undef;  # Save memory.
    ($method, $filter, $filter_cto) = ($eh_method, $eh_filter, 0);
  } else {
    die("fatal: found DOS .exe MZ header in UPX output ELF file\n") if $s =~ m@^(?:MZ|ZM)@;
    die("fatal: found DOS .sys header in UPX output ELF file\n") if $s =~ m@^\xff\xff\xff\xff@;
    die("fatal: missing ELF signature in UPX output\n") if substr($s, 0, 4) ne "\x7fELF";
    die("fatal: EOF in ELF header\n") if length($s) < 0x54;
    my($ei_mag, $ei_class, $ei_data, $ei_version, $e_osabi, $e_abiversion, $e_type, $e_machine, $e_version, $e_entry, $e_phoff, $e_shoff, $e_flags, $e_ehsize, $e_phentsize, $e_phnum, $e_shentsize, $e_shnum, $e_shstrndx,
       $p_type, $p_offset, $p_vaddr, $p_paddr, $p_filesz, $p_memsz, $p_flags, $p_align
      ) = unpack("a4CCCCCx7vvVVVVVvvvvvvVVVVVVVV", substr($s, 0, 0x54));
    die("fatal: bad ELF ei_class\n") if $ei_class != 1;
    die("fatal: bad ELF ei_data\n") if $ei_data != 1;
    die("fatal: bad ELF ei_version\n") if $ei_version != 1;
    die("fatal: bad ELF e_osabi\n") if $e_osabi != 3;
    die("fatal: bad ELF e_abiversion\n") if $e_abiversion != 0;
    die("fatal: bad ELF e_type\n") if $e_type != 2;
    die("fatal: bad ELF e_machine\n") if $e_machine != 3;
    die("fatal: bad ELF e_version\n") if $e_version != 1;
    # Deal with $e_entry later.
    die("fatal: bad ELF e_phoff\n") if $e_phoff != 0x34;
    die("fatal: bad ELF e_shoff\n") if $e_shoff != 0;
    die("fatal: bad ELF e_flags\n") if $e_flags != 0;
    die("fatal: bad ELF e_ehsize\n") if $e_ehsize != 0x34;
    die("fatal: bad ELF e_phentsize\n") if $e_phentsize != 0x20;
    die("fatal: bad ELF e_phnum\n") if $e_phnum != 2;
    die("fatal: bad ELF e_shentsize\n") if $e_shentsize != 0x28;
    die("fatal: bad ELF e_shnum\n") if $e_shnum != 0;
    die("fatal: bad ELF e_shstrndx\n") if $e_shstrndx != 0;
    die("fatal: bad ELF p_type\n") if $p_type != 1;
    die("fatal: bad ELF p_offset\n") if $p_offset != 0;
    die("fatal: ELF p_vaddr differs from p_paddr\n") if $p_vaddr != $p_paddr;
    die("fatal: bad ELF e_entry\n") if $e_entry < $p_vaddr or $e_entry >= $p_vaddr + $p_filesz;
    die("fatal: bad ELF p_memsz\n") if $p_memsz < $p_filesz;
    die("fatal: bad ELF p_flags\n") if $p_flags != 5;
    die("fatal: bad ELF p_align\n") if $p_align != 0x1000;
    # Now we parse the Linux i386 ELF-32 executable headers and compressed data emitted by UPX 3.94.
    my $i = 0x74;
    die("fatal: EOF in l_info\n") if length($s) < ($i += 12);
    my($l_checksum, $l_magic, $l_lsize, $l_version, $l_format) = unpack("Va4vCC", substr($s, $i - 12, 12));
    # Ignore $l_checksum.
    die("fatal: bad l_magic\n") if $l_magic ne "UPX!";
    # Ignore $l_size (decompressor size).
    die("fatal: bad l_version\n") if $l_version < 10 or $l_version > 14;  # Must be at least 10, UPX 3.94 returns 13.
    die("fatal: bad l_format\n") if $l_format != 12;  # UPX_F_LINUX_ELFiI386.
    die("fatal: EOF in p_info\n") if length($s) < ($i += 12);
    my($pi_progid, $pi_filesize, $pi_blocksize) = unpack("VVV", substr($s, $i - 12, 12));
    die("fatal: bad pi_progid\n") if $pi_progid != 0;
    die("fatal: bad pi_filesize\n") if $pi_filesize != $expected_pi_filesize;
    die("fatal: bad pi_blocksize\n") if $pi_filesize != $expected_pi_filesize;
    die("fatal: EOF in first b_info\n") if length($s) < ($i += 12);
    my($b1_usize, $b1_csize, $b1_method, $b1_filter, $b1_filter_cto) = unpack("VVCCCx", substr($s, $i - 12, 12));
    die("fatal: bad b1_csize\n") if $b1_csize == 0;
    die("fatal: unknown b1_method: $b1_method\n") if !$b1_method or !exists($methods{$b1_method});
    die("fatal: unknown b1_filter: $b1_filter\n") if !exists($elf_filters{$b1_filter});
    $i += $b1_csize;  # Skip over compressed block. This stores the compressed ELF header.
    die("fatal: EOF in second b_info\n") if length($s) < ($i += 12);
    my($b2_usize, $b2_csize, $b2_method, $b2_filter, $b2_filter_cto) = unpack("VVCCCx", substr($s, $i - 12, 12));
    die("fatal: bad b2_usize\n") if $b2_usize != $usize;
    die("fatal: bad b2_csize\n") if $b2_csize == 0;
    die("fatal: unknown b2_method: $b2_method\n") if !exists($methods{$b1_method});  # It may be uncompressed ($method == 0).
    die("fatal: unknown b2_filter: $b2_filter\n") if !exists($elf_filters{$b2_filter});
    die("fatal: EOF in compressed data\n") if length($s) < $i + $b2_csize;
    $cdata = substr($s, $i, $b2_csize);
    $s = undef;  # Save memory.
    ($method, $filter, $filter_cto) = ($b2_method, $b2_filter, $b2_filter_cto);
  }
  my $stats = get_stats($method, $filter, $filter_cto);
  my $csize = length($cdata);
  print(STDERR "info: UPX compression results: $usize --> $csize bytes, $stats\n");
  die("fatal: desired method category $desired_method_category was not used, got method: $methods{$method}\n") if
      defined($desired_method_category) and !does_method_match_category($method, $desired_method_category);
  my $expected_filter = $do_filter_in_wrapper ? 0 : $desired_filter;
  if (defined($expected_filter) and $filter != $expected_filter) {  # Depending on the file format and file size, UPX silently overrides the method or the filter. We detect that here.
    # This can happen to short DOS .com programs which don't benefit from any filter, so UPX chooses to use 0 instead.
    die(sprintf("fatal: the expected filter %s was not used, got: %s\n",
        ($filters{$expected_filter} or sprintf("0x%02x", $expected_filter)),
        ($filters{$filter} or sprintf("0x%02x", $filter))));
  }
  $filter = $desired_filter if $desired_filter and $do_filter_in_wrapper;  # Filter applied above by do_filter(...), so indicate it.
  ($method, $filter, $filter_cto, $cdata)
}

sub parse_upx_lzma_header($) {
  my($cdata) = $_[0];
  die("fatal: compressed data too short for UPX LZMA output\n") if length($cdata) < 3;
  my $lclp = vec($cdata, 0, 8) >> 3;  # lit_context_bits + lit_pos_bits.
  my $pb = vec($cdata, 0, 8) & 7;  # pos_bits.
  my $lp = vec($cdata, 1, 8) >> 4;  # lit_pos_bits.
  my $lc = vec($cdata, 1, 8) & 0xf;  # lit_context_bits.
  die("fatal: inconsistent UPX LZMA lclp\n") if $lclp != $lc + $lp;
  die("fatal: UPX LZMA lclp too large\n") if $lclp > 12;
  ($lc, $lp, $pb)
}

# ---

if (@ARGV and $ARGV[0] =~ m@^--truncate-nrv2b-(le32|le16|8)\Z(?!\n)@) {  # Based on ucl-1.03/src/n2b_d.c .
  my $method_str = "NRV2B_" . uc($1);
  my $bits = ($1 eq "le32") ? 32 : ($1 eq "le16") ? 16 : 8;
  die("fatal: missing filename\n") if @ARGV != 2;
  my $cfn = $ARGV[1];
  my $s = read_file($cfn);
  my $i = 0; my $bc = 0; my $b = 0; my $csize = length($s);
  my $get_byte = sub {
    die("fatal: EOF in NRV byte\n") if $i >= $csize;
    vec($s, $i++, 8)
  };
  my $get_bit =
      ($bits == 32) ?  sub {
        if (!$bc) { die("fatal: EOF in NRV block\n") if $i + 4 > $csize; $b = unpack("V", substr($s, $i, 4)); $bc = 32; $i += 4 }
        my $r = ($b >> 31) & 1;
        $b <<= 1; $bc -= 1; $r
      } : ($bits == 16) ? sub {
        if (!$bc) { die("fatal: EOF in NRV block\n") if $i + 2 > $csize; $b = unpack("v", substr($s, $i, 2)); $bc = 16; $i += 2 }
        my $r = ($b >> 15) & 1;
        $b <<= 1; $bc -= 1; $r
      } : ($bits == 8) ? sub {
        if (!$bc) { die("fatal: EOF in NRV block\n") if $i >= $csize; $b = vec($s, $i, 8); $bc = 8; ++$i }
        my $r = ($b >> 7) & 1;
        $b <<= 1; $bc -= 1; $r
      } : undef;
  my $last_m_off; my $short_eos_ofs;
 LOOP:
  for (;;) {
    $get_byte->() while $get_bit->();
    my $m_off = 2 | $get_bit->();
    while (!$get_bit->()) {
      $m_off = $m_off << 1 | $get_bit->();
      if ($m_off == 0x10000) {
        $short_eos_ofs = $i;
        last LOOP if $i == $csize;  # Already truncated.
      }
    }
    if ($m_off == 2) {
      die("fatal: initial last_m_off used\n") if !defined($last_m_off);
      $m_off = $last_m_off;
    } else {
      $m_off = ($m_off - 3) << 8 | $get_byte->();
      last if $m_off == 0xffffffff;  # End-of-stream (EOS) marker.
      $last_m_off = ++$m_off;
    }
    die("fatal: short end-of-stream not followed by end-of-stream marker\n") if defined($short_eos_ofs);  # This can trigger for >=24 MiB usize.
    my $m_len = $get_bit->();
    $m_len = $m_len << 1 | $get_bit->();
    if (!$m_len) {
      $m_len = 2 | $get_bit->();
      $m_len = $m_len << 1 | $get_bit->() while !$get_bit->();
      $m_len += 2;
    }
    $m_len += ($m_off > 0xd00);
  }
  die("fatal: short end-of-stream marker not found before end-of-stream marker\n") if !defined($short_eos_ofs);
  die("fatal: end-of-stream marker found before EOF\n") if $csize != $i;
  print(STDERR "info: truncating $method_str file to $short_eos_ofs bytes: $cfn\n");
  die("final: error truncating file: $cfn\n") if !truncate($cfn, $short_eos_ofs);
  exit(0);
}

sub parse_uint($) {
  my $s = $_[0];
  # TODO(pts): Check for overflow.
  return (hex($s) or 0) if $s =~ m@^0[xX][0-9a-fA-F]+\Z(?!\n)@;
  return (oct($s) or 0) if $s =~ m@^0[0-7]*\Z(?!\n)@;
  return (int($s) or 0) if $s =~ m@^[1-9][0-9]*\Z(?!\n)@;  # `0' is covered by oct($s) above.
  die("fatal: bad unsigned integer: $s\n")
}

# ---

my $lzma_mode = 1;  # 0: no LZMA 1: LZMA only; 2: both LZMA and no LZMA.
my $desired_filter;
my $desired_method_category;
my $infn;
my $outfn;
my $ofmt;  # Output format.
my $selfdir = ".";
my $compressed_lzmad = 8;
my $do_ignore_filter = 0;
my $do_filter_in_wrapper;
my @more_method_flags;
my $nasm_ofmt = "bin";
my $upx_tmpfmt = "elf";
my $upx_prog;
my $xz_prog;
my $use_small_decompressor = 0;  # The small NRV2B decompressors may be slow or unstable, so don't enable them by default.
my $skip0_size = 0;
my $prefix_size = 0;
my($flat16_segment, $flat16_offset);
my $lzma_settings;
my $do_update_hdrsize = 0;
{ my $i;
  for ($i = 0; $i < @ARGV; ++$i) {
    my $arg = $ARGV[$i];
    if ($arg eq "--") { ++$i; last }
    elsif ($arg eq "-" or $arg !~ m@^-@) { last }
    elsif ($arg eq "--no-lzma") { $lzma_mode = 0 }
    elsif ($arg eq "--nrv") { $lzma_mode = 0; @more_method_flags = (); $desired_method_category = undef }
    elsif ($arg eq "--nrv2b" or $arg eq "--nrv2d" or $arg eq "--nrv2e") { $lzma_mode = 0; @more_method_flags = ($arg); $desired_method_category = substr($arg, 2) }
    elsif ($arg eq "--force-lzma") { $lzma_mode = 1; $desired_method_category = "lzma" }
    elsif ($arg eq "--maybe-lzma") { $lzma_mode = 2 }
    elsif ($arg eq "--no-filter") { $desired_filter = 0 }
    elsif ($arg eq "--default-filters") { $desired_filter = undef }
    elsif ($arg =~ s@^--filter=@@) { $desired_filter = parse_uint($arg) }
    elsif ($arg =~ s@^--skip0=@@) { $skip0_size = parse_uint($arg) }  # Ignore this many bytes at the beginning of the input. Comaptible with `upxbc --skip0=...': https://github.com/pts/upxbc
    elsif ($arg =~ s@^--prefix=@@) { $prefix_size = parse_uint($arg) }  # Keep this many bytes uncompressed at the beginning of the input (after ignoring --skip0=....). Comaptible with `upxbc --prefix=...': https://github.com/pts/upxbc
    elsif ($arg eq "-o" and $i < @ARGV - 1) { $outfn = $ARGV[++$i] }
    elsif ($arg eq "--format=lzma" or $arg eq "--lzma1") { $ofmt = "lzma1" }  # Compatible with `lzma' and `xz --format=lzma'.
    elsif ($arg eq "--format=upxz" or $arg eq "--upxz") { $ofmt = "upxz" }
    elsif ($arg eq "--format=raw" or $arg eq "--raw") { $ofmt = "raw" }  # Would be compatible with `lzma --format=raw' if the latter created LZMA1 streams.
    elsif ($arg =~ m@^--(?:format=)?(decompress32|flat32|flat16-386)(bin|elf|)\Z(?!\n)@) { $ofmt = $1; $nasm_ofmt = ($2 eq "elf") ? $2 : "bin" }
    elsif ($arg =~ s@^--format=@@) { die("fatal: unknown --format= value: $arg\n") }
    elsif ($arg =~ s@^--lzma1=@@) { $lzma_mode = 1; $desired_method_category = "lzma"; $lzma_settings = $arg }  # To be passed to xz(1). Example: --lzma1=-9e,dict=512K,pb=0,lc=4,mf=bt4,nice=120
    elsif ($arg =~ m@^--flat16-386-start=([^:]+):([^:]+)\Z(?!\n)@) { ($flat16_segment, $flat16_offset) = map { parse_uint($_) } ($1, $2); $nasm_ofmt = "bin" if defined($ofmt) and $ofmt ne "flat16-386"; $ofmt = "flat16-386" }
    elsif ($arg =~ m@^--flat16-386-start=@) { die("fatal: unknown --flat16-386-start= value: $arg\n") }
    elsif ($arg =~ m@^--expert-upx-tmp-format=(elf|com|exe)\Z(?!\n)@) { $upx_tmpfmt = $1 }
    elsif ($arg =~ s@^--expert-upx-tmp-format=@@) { die("fatal: unknown --expert-upx-tmp-format= value: $arg\n") }
    elsif ($arg =~ s@^--upx=@@) { $upx_prog = $arg }
    elsif ($arg =~ s@^--xz=@@) { $xz_prog = $arg }
    elsif ($arg eq "--compressed-lzmad=8" or $arg eq "--compressed-lzmad") { $compressed_lzmad = 8 }
    elsif ($arg eq "--compressed-lzmad=16") { $compressed_lzmad = 16 }
    elsif ($arg eq "--compressed-lzmad=32") { $compressed_lzmad = 32 }
    elsif ($arg eq "--no-compressed-lzmad") { $compressed_lzmad = 0 }
    elsif ($arg eq "--expert-ignore-filter") { $do_ignore_filter = 1 }
    elsif ($arg eq "--no-expert-ignore-filter") { $do_ignore_filter = 0 }
    elsif ($arg eq "--expert-filter-in-wrapper") { $do_filter_in_wrapper = 1 }
    elsif ($arg eq "--no-expert-filter-in-wrapper") { $do_filter_in_wrapper = 0 }
    elsif ($arg eq "--small") { $use_small_decompressor = 1 }
    elsif ($arg eq "--no-small") { $use_small_decompressor = 0 }
    elsif ($arg eq "--update-hdrsize") { $do_update_hdrsize = 1 }
    elsif ($arg eq "--no-update-hdrsize") { $do_update_hdrsize = 0 }
    else { die "fatal: unknown command-line flag: $arg\n" }
  }
  die("fatal: missing input filename\n") if $i >= @ARGV;
  $infn = $ARGV[$i++];
  $outfn = $ARGV[$i++] if $i < @ARGV and !defined($outfn);
  die("fatal: too many command-line arguments\n") if $i < @ARGV;
  die("fatal: missing output filename\n") if !defined($outfn);
  die("fatal: missing outout --format=...\n") if !defined($ofmt);
}
if (defined($lzma_settings)) {
  die("fatal: useless --lzma1=... settings, specify --force-lzma\n") if $lzma_mode != 1;
  die("fatal: missing --filter=... or --no-filter for --lzma1=...\n") if !defined($desired_filter);
  die(sprintf("fatal: desired filter not implemented for --lzma1=...: %s\n", ($filters{$desired_filter} or sprintf("0x%02x", $desired_filter)))) if !is_filter_implemented($desired_filter);
}
if ($selfdir !~ m@^/@) {  # This is Unix-only, it should be ported to Windows.
  my $dir = $0;
  $dir = "." if $dir !~ m@/@;  # Add a dot prefix so Unix won't try to find the tool on the $PATH.
  $dir =~ s@/+[^/]*\Z(?!\n)@@;
  $selfdir =~ s@/+[^/]*\Z(?!\n)@@;
  substr($selfdir, 0, 0) = "$dir/";
  $selfdir =~ s@^(?:[.]/+)*@@;
  $selfdir =~ s@(?:/+[.])+\Z(?!\n)@@;
  substr($selfdir, 0, 0) = "./" if $selfdir =~ m@^-@;
}
$do_filter_in_wrapper = should_do_filter_in_wrapper($desired_filter, $upx_tmpfmt) if !defined($do_filter_in_wrapper);
my @upx_method_flags =
    ($lzma_mode == 0) ? ((@more_method_flags ? ("--best", "--crp-nrv-ms=99999") : ("--ultra-brute")), "--no-lzma", @more_method_flags) :  # --ultra-brute cancels e.g. --nrv2d, so we use --best instead.
    ($lzma_mode == 1) ? ("--best", "--lzma") :
    ("--ultra-brute", "--lzma");
# Even if --filter=... is specified, UPX 3.94 may still decide to use no filter if it makes the output shorter. (Sigh.)
$selfdir = "." if !length($selfdir);
$upx_prog = "$selfdir/tools/upx-3.94-lzma-eos.upx" if !defined($upx_prog);
$xz_prog = "$selfdir/tools/xz-5.6.2-2ubuntu0.2.upx" if !defined($xz_prog);
my $nasm_prog = "$selfdir/tools/nasm-0.98.39.upx";

my $udata_aryref = [read_file($infn)];
if ($skip0_size) {  # !! To save memory, just seek to ($skip0_size - 1) before reading.
  die("fatal: input file is too short for --skip0=$skip0_size\n") if length($udata_aryref->[0]) < $skip0_size;
  substr($udata_aryref->[0], 0, $skip0_size) = "";
}
my $prefix = "";
if ($prefix_size) {
  die("fatal: input file is too short for --prefix=$prefix_size\n") if length($udata_aryref->[0]) < $prefix_size;
  $prefix = substr($udata_aryref->[0], 0, $prefix_size);
  substr($udata_aryref->[0], 0, $prefix_size) = "";
}
if ($do_update_hdrsize) {
  die("fatal: --prefix-size=... value too small for --update-hdrsize\n") if $prefix_size < 0x18;
  die("fatal: missing DOS .exe MZ signature in prefix for --update-hdrsize\n") if substr($prefix, 0, 2) ne "MZ";
}
my $tmpfn = "$outfn.tmp";
if ($upx_tmpfmt eq "com") { $tmpfn .= ".com" }  # Needed by UPX. No such requirement for DOS .exe though.
my $usize = length($udata_aryref->[0]);
my($method, $filter, $filter_cto, $cdata) =
    defined($lzma_settings) ? compress_xz_lzma1($udata_aryref, $tmpfn, $xz_prog, $lzma_settings, $desired_filter, $do_filter_in_wrapper) :
    compress_upx_data32($udata_aryref, $tmpfn, \@upx_method_flags, $upx_prog, $upx_tmpfmt, $desired_filter, $desired_method_category, $do_filter_in_wrapper);
# The filter doesn't change short data. Make it explicit so that the unfilter code doesn't have to check for overflows.
$filter = 0 if $usize <= 5 and (  # Corresponds to upx-3.94-src/src/filter/ct.h and upx-3.94-src/src/filter/ctok.h .
    ($filter >= 1 and $filter <= 6 and $usize <= 3) or
    ($filter == 0x46 or $filter == 0x49));
my $csize = length($cdata);
my $stats = get_stats($method, $filter, $filter_cto);
if ($do_ignore_filter) {
  $filter = $filter_cto = 0;
  $stats =~ s@\bfilter .*@filter ignored@s;
}
if ($ofmt eq "lzma1") {  # .lzma; `xz --format=lzma'; https://raw.githubusercontent.com/WinMerge/sevenzip/refs/heads/master/DOC/lzma.txt
  die("fatal: --format=lzma requires LZMA compression (specify --force-lzma)\n") if $method != M_LZMA;
  die("fatal: --format-lzma requires --no-filter\n") if $filter;
  my($lc, $lp, $pb) = parse_upx_lzma_header($cdata);
  my $dict_size = 0x10000;  # Minimum for file(1) to recognize it.
  $dict_size <<= 1 while $dict_size < $usize and $dict_size > 0;  # Must be a power of 2 for unlzma(1).
  # Also: https://raw.githubusercontent.com/jljusten/LZMA-SDK/refs/heads/master/DOC/lzma-specification.txt
  # For -1, -1 to work, $cdata must contain the LZMA end-of-stream (EOS) ==
  # end-of-payload (EOP) marker. Only our patched UPX 3.94 emits such a
  # file.
  substr($cdata, 0, 2) = pack("CVVV", ($pb * 5 + $lp) * 9 + $lc, $dict_size, -1, -1);  # https://raw.githubusercontent.com/WinMerge/sevenzip/refs/heads/master/DOC/lzma.txt
} elsif ($ofmt eq "upxz") {  # .upxz; `upxbc --upxz': https://github.com/pts/upxbc
  # !! `upcbc --upxz' still fails to decompress these files with UPX 3.94 if they are small: CantUnpackException: p_info corrupted
  substr($cdata, 0, 0) = pack(
      'a4VVCCCCVVvv', 'UPXZ', $usize, length($cdata),
      $method, $filter, $filter_cto, 0,
      -1, # zlib.adler32(udata) & 0xffffffff,  # Placeholder -1, we don't want to use Digest::Adler32, maybe it's not available.
      -1, # zlib.adler32(ch.compressed_data) & 0xffffffff,  # Placeholder -1, we don't want to use Digest::Adler32, maybe it's not available.
      0, 0);
} elsif ($ofmt eq "raw") {  # No headers. The recommended extension is .bin.
  if ($method == M_LZMA) {
    my($lc, $lp, $pb) = parse_upx_lzma_header($cdata);
    $stats .= ", lc $lc, lp $lp, pb $pb";
    substr($cdata, 0, 2) = ""
  }
} elsif ($ofmt eq "decompress32" or $ofmt eq "flat32" or $ofmt eq "flat16-386") {  # Generate extractor function as i386 32-bit protected mode code.
  # !! Reuse $udata if $method == 0. $method == 0 happens if UPX compression wasn't able to decrease the file size.
  die("fatal: cannot have apostrophes or newlines in filename: $tmpfn\n") if $tmpfn =~ m@['\r\n]@;  # For parsing by NASM.
  my @defines = ($ofmt eq "flat32") ? ("-DFLAT32") : ($ofmt eq "flat16-386") ? ("-DFLAT16_386") : ("-DDECOMPRESS32");
  push @defines, sprintf("-DFLAT16_SEGMENT=0x%x", $flat16_segment), sprintf("-DFLAT16_OFFSET=0x%x", $flat16_offset) if defined($flat16_segment) and $ofmt eq "flat16-386";
  push @defines, "-DMETHOD=$method", "-DFILTER=$filter", "-DFILTER_CTO=$filter_cto", "-DUSIZE=$usize", "-DSMALL=$use_small_decompressor";
  if ($method == M_LZMA) {
    my($lc, $lp, $pb) = parse_upx_lzma_header($cdata);
    my $probs_size = (1846 + (768 << ($lc + $lp))) << 1;  # Number of bytes needed for storing the probs array, for decompression.
    die("fatal: cannot have apostrophes or newlines in self-dir: $selfdir\n") if $selfdir =~ m@['\r\n]@;  # For parsing by NASM.
    push @defines, "-DLZMA_PROBS_SIZE=$probs_size", sprintf("-DLZMA_HEADER_DWORD=0x%x", $lc | $lp << 8 | $pb << 16), "-DCOMPRESSED_LZMAD=$compressed_lzmad", "-DLZMAD_BIN='$selfdir/upxdc_lzmad.bin'", "-DCLZMAD_BIN='$selfdir/upxdc_lzmadfb$compressed_lzmad.bin'";
    substr($cdata, 0, 2) = "";
  }
  die("fatal: empty compressed data\n") if !length($cdata);
  write_file($tmpfn, $cdata);
  $cdata = undef;  # Save memory.
  my @nasm_cmd = ($nasm_prog, "-O0", "-w+orphan-labels", "-f", $nasm_ofmt, @defines, "-DCDATAFN='$tmpfn'", "-o", $outfn, "--", "$selfdir/upxdc_helper.nasm");
  print(STDERR "info: running NASM: ", join(" ", map { shq($_) } @nasm_cmd), "\n");
  if (system(@nasm_cmd)) {
    unlink($tmpfn);
    die("fatal: error running NASM: $nasm_cmd[0]\n")
  }
  unlink($tmpfn);
  if (!length($prefix)) {
    $csize = -s($outfn);
    goto AFTER_WRITE;
  }
  $cdata = read_file($outfn);
}
if ($do_update_hdrsize) {
  my $fsize = length($prefix) + length($cdata);
  die("fatal: file too long for --update-hdrsize\n") if $csize >> 20;
  substr($prefix, 8, 2) = pack("v", ($fsize + 0xf) >> 4);
}
substr($cdata, 0, 0) = $prefix;
$csize = length($cdata);
write_file($outfn, $cdata);
AFTER_WRITE:
$stats .= ", prefix " . length($prefix) . " bytes" if length($prefix);
print(STDERR "info: written compressed output: $outfn ($csize bytes, format $ofmt, $stats)\n");

__END__
