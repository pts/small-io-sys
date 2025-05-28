#!/bin/sh --
eval 'PERL_BADLANG=x;export PERL_BADLANG;exec perl -x "$0" "$@";exit 1'
#!perl  # Start marker used by perl -x.
+0 if 0;eval("\n\n\n\n".<<'__END__');die$@if$@;__END__

#
# ufepack.pl: UPX-based packer of filtered DOS .exe
# by pts@fazekas.hu at Tue May 27 20:51:40 CEST 2025
#
# This script works with Perl 5.004.04 (1997-10-15) or later.

BEGIN { $ENV{LC_ALL} = "C" }  # For deterministic output. Typically not needed. Is it too late for Perl?
BEGIN { $ENV{TZ} = "GMT" }  # For deterministic output. Typically not needed. Perl respects it immediately.
BEGIN { $^W = 1 }  # Enable warnings.
use integer;
use strict;
my $is_under_test = [caller()]->[1] ne $0;

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

# Modifies $_[0] in place. $addvalue is used by filters 0x01..0x06, the value is 0x100 for .com, 0 for .sys.
sub do_filter($$;$) {
  my($s, $filter, $addvalue) = @_;
  return (0, 0, 0) if !$filter;  # Filter none is a no-op. This doesn't print stats, that's OK.
  die("fatal: bad filter value: $filter\n") if $filter < 0 or $filter > 0xff;
  $addvalue = 0 if !defined($addvalue);
  my $filter3 = ($filter & 0xf) % 3;
  my $e8 = ($filter3 == 1 or $filter3 == 0) ? 0xe8 : -1;
  my $e9 = ($filter3 == 2 or $filter3 == 0) ? 0xe9 : -1;
  my $packchar = (($filter & 0xf) >= 4) ? "N" : "V";
  $packchar = lc($packchar) if $filter < 0x10;
  my $ipackchar = ($filter < 0x10) ? "v" : "V";
  my $ofs_size = ($filter < 0x10) ? 2 : 4;
  my $i_limit = length($s) - $ofs_size - 1;  # This could be 1 more and still be correct, but we keep it as is to remain compatible with UPX 3.94.
  my $ofs_size1 = $ofs_size - 1;
  my $mask = ($filter < 0x10) ? 0xffff : 0xffffffff;
  my $filter_cto = 0;
  my $count = 0; my $lastofs = 0;
  if (($filter >= 1 and $filter <= 6) or ($filter >= 0x11 and $filter <= 0x16)) {  # Based on upx-3.94-src/src/filter/ct.h .
    # This is an implementation of filters ct16_e8_le_0x01, ct16_e9_le_0x02,
    # ct16_e8e9_le_0x03, ct16_e8_be_0x04, ct16_e9_be_0x05, ct16_e8e9_be_0x06.
    for (my $i = 0; $i < $i_limit; ++$i) {
      my $v = vec($s, $i, 8);
      if ($v == $e8 or $v == $e9) {
        $lastofs = ++$i; ++$count;
        substr($_[0], $i, $ofs_size) = pack($packchar, ((unpack($ipackchar, substr($s, $i, $ofs_size)) + $addvalue + $i) & $mask));  # Modify $_[0] in place.
        $i += $ofs_size1;  # See also ++$i in the for(...) above.
      }
    }
  } else {
    die(sprintf("fatal: assert: unsupported filter: %s\n", sprintf("0x%02x", $filter)));
  }
  my $xcount = ($count) ? $lastofs + $count - ($count - 1) * $ofs_size : 0;
  #write_file("t.f", $_[0]);
  ($filter_cto, $count, $xcount)
}

sub M_NRV2B_LE32() { 2 }
sub M_NRV2B_8() { 3 }
sub M_NRV2B_LE16() { 4 }
sub M_NRV2D_LE32() { 5 }
sub M_NRV2D_8() { 6 }
sub M_NRV2D_LE16() { 7 }
sub M_NRV2E_LE32() { 8 }
sub M_NRV2E_8() { 9 }
sub M_NRV2E_LE16() { 10 }
sub M_LZMA() { 14 }

sub analyze_nrv2($$;$$) {
  my($s, $method) = @_;  # $ $_[2] is the decompressed target string ($udata).
  my $is_lastmoff1_only = $_[3];
  my $mcat =
      ($method == M_NRV2B_LE32 or $method == M_NRV2B_8 or $method == M_NRV2B_LE16) ? M_NRV2B_8 :
      ($method == M_NRV2D_LE32 or $method == M_NRV2D_8 or $method == M_NRV2D_LE16) ? M_NRV2D_8 :
      ($method == M_NRV2E_LE32 or $method == M_NRV2E_8 or $method == M_NRV2E_LE16) ? M_NRV2E_8 : undef;
  my $bits =
      ($method == M_NRV2B_LE32 or $method == M_NRV2D_LE32 or $method == M_NRV2E_LE32) ? 32 :
      ($method == M_NRV2B_8    or $method == M_NRV2D_8    or $method == M_NRV2E_8   ) ? 8 :
      ($method == M_NRV2B_LE16 or $method == M_NRV2D_LE16 or $method == M_NRV2E_LE16) ? 16 : undef;
  die("fatal: unknown NRV method: $method\n") if !defined($mcat) or !defined($bits);
  my $method_str = "method $method";
  my $usize = 0; my $lastmoff1 = 0; my $short_eos_ofs = 0; my $overlap = 0;
  my $max_distance = 0;  # 0 final result means completely uncompressible, i.e. literals only.
  my $i = 0; my $bc = 0; my $b = 0; my $csize = length($s);
  my $get_byte = sub {
    die("fatal: EOF in $method_str byte\n") if $i >= $csize;
    #printf(STDERR "info: byte at 0x%x for get_byte: 0x%02x\n", $i, vec($s, $i, 8));
    vec($s, $i++, 8)
  };
  my $udataref = defined($_[2]) ? \$_[2] : undef;
  my $literal_byte = $udataref ? sub {
    die("fatal: EOF in $method_str byte\n") if $i >= $csize;
    $$udataref .= substr($s, $i++, 1)
  } : $get_byte;
  my $get_bit =
      ($bits == 32) ?  sub {
        if (!$bc) { die("fatal: EOF in $method_str block\n") if $i + 4 > $csize; $b = unpack("V", substr($s, $i, 4)); $bc = 32; $i += 4 }
        my $r = ($b >> 31) & 1;
        $b <<= 1; $bc -= 1; $r
      } : ($bits == 16) ? sub {
        if (!$bc) { die("fatal: EOF in $method_str block\n") if $i + 2 > $csize; $b = unpack("v", substr($s, $i, 2)); $bc = 16; $i += 2 }
        my $r = ($b >> 15) & 1;
        $b <<= 1; $bc -= 1; $r
      } : ($bits == 8) ? sub {
        if (!$bc) { die("fatal: EOF in $method_str block\n") if $i >= $csize; $b = vec($s, $i, 8); $bc = 8; ++$i; #printf(STDERR "info: byte at 0x%x for get_bit: 0x%02x\n", $i - 1, $b);
        }
        my $r = ($b >> 7) & 1;
        #print(STDERR "info: bit: $r\n");
        $b <<= 1; $bc -= 1; $r
      } : undef;
  die("fatal: unknown bits: $bits\n") if !$get_bit;
  my($last_m_off, $m_off, $m_len);
  #print(STDERR "info: analyze $method_str\n");
 LOOP:
  for (;;) {
    while ($get_bit->()) {
      #print(STDERR "info: literal\n");
      $literal_byte->();  # No need to call $update_overlap->(), because $usize - $i is unchanged.
      ++$usize;
    }
    if ($mcat == M_NRV2B_8) {
      $m_off = 2 | $get_bit->();
      #print(STDERR "info: match start m_off: $m_off\n");
      while (!$get_bit->()) {
        $m_off = $m_off << 1 | $get_bit->();
        #printf(STDERR "info: match cont m_off: 0x%x\n", $m_off);
        if ($m_off == 0x10000) {
          #print(STDERR "info: cxz in m_off\n");
          $short_eos_ofs = $i if !$short_eos_ofs;
          last LOOP if $i == $csize;  # Already truncated.
        }
      }
      if ($m_off == 2) {
        # This can easily happen, e.g. for input files with a single byte
        # repeating at the beginning.
        if (!defined($last_m_off)) {
          return 1 if $is_lastmoff1_only;
          ++$lastmoff1;  # Change from 0 to 1.
          #print(STDERR "info: initial last_m_off used\n");
          $last_m_off = 1;
        }
        $m_off = $last_m_off;
      } else {
        return 0 if $is_lastmoff1_only;
        #printf(STDERR "info: m_off before get_byte: m_off=0x%x m_off-3=0x%x\n", $m_off, $m_off - 3);
        $m_off = ($m_off - 3) << 8 | $get_byte->();
        #printf(STDERR "info: m_off after get_byte: 0x%x\n", $m_off);
        last LOOP if $m_off == 0xffffffff;  # End-of-stream (EOS) marker.
        $last_m_off = ++$m_off;
      }
      die("fatal: short end-of-stream not followed by end-of-stream marker in $method_str stream\n") if $short_eos_ofs and $m_off > 0xffffff;
      $m_len = $get_bit->();
      $m_len = $m_len << 1 | $get_bit->();
      # Now $m_len is 0, 1, 2 or 3.
      if (!$m_len) {
        $m_len = 2 | $get_bit->();
        $m_len = $m_len << 1 | $get_bit->() while !$get_bit->();
        $m_len += 2;
      }
      # Now $m_len can be any positive integer.
      $m_len += ($m_off > 0xd00);
    } elsif ($mcat == M_NRV2D_8 or $mcat == M_NRV2E_8) {
      $m_off = 1;
      for (;;) {
        $m_off = $m_off << 1 | $get_bit->();
        last if $get_bit->();
        --$m_off;
        $m_off = $m_off << 1 | $get_bit->();
        if ($m_off >= 0x8000) {
          $short_eos_ofs = $i if !$short_eos_ofs;
          last LOOP if $i == $csize;  # Already truncated.
        }
      }
      if ($m_off == 2) {
        if (!defined($last_m_off)) {
          ++$lastmoff1;  # Change from 0 to 1.
          #print(STDERR "info: initial last_m_off used\n");
          $last_m_off = 1;
        }
        $m_off = $last_m_off;
        $m_len = $get_bit->();
      } else {
        $m_off = ($m_off - 3) << 8 | $get_byte->();
        last LOOP if $m_off == 0xffffffff;  # End-of-stream (EOS) marker. Typically not reached, because the `last' above is reached earlier. Never reached if $usize <= 0xffffff, e.g. for DOS .com and .exe.
        $m_len = ~$m_off & 1;
        $m_off >>= 1;
        $last_m_off = ++$m_off;
      }
      if ($mcat == M_NRV2D_8) {
        $m_len = $m_len << 1 | $get_bit->();
        # Now $m_len is 0, 1, 2 or 3.
        if (!$m_len) {
          $m_len = 2 | $get_bit->();
          $m_len = $m_len << 1 | $get_bit->() while !$get_bit->();
          $m_len += 2;
        }
        # Now $m_len can be any positive integer.
      } elsif ($mcat == M_NRV2E_8) {
        # Now $m_len is 0 or 1.
        if ($m_len) {
          $m_len = 1 + $get_bit->();
          # Now $m_len is 1 or 2.
        } elsif ($get_bit->()) {
          $m_len = 3 + $get_bit->();
          # Now $m_len is 3 or 4.
        } else {
          $m_len = 2 | $get_bit->();
          $m_len = $m_len << 1 | $get_bit->() while !$get_bit->();
          $m_len += 3;
          # Now $m_len is >=5.
        }
        # Now $m_len can be any positive integer.
      } else {
        die("fatal: assert: method not implemented: $method_str\n");
      }
      $m_len += ($m_off > 0x500);
    } else {
      die("fatal: assert: method not implemented: $method_str\n");
    }
    #die("fatal: distance is zero in $method_str stream\n") if !$m_off;  # Always true based on the algorithm above, but it's too slow to always check.
    die("fatal: distance too large in $method_str stream\n") if $m_off < 0 or $m_off > $usize;
    ++$m_len;
    #print(STDERR "info: match distance=$m_off length=$m_len\n");
    $max_distance = $m_off if $m_off > $max_distance;
    $usize += $m_len;
    # $update_overlap->();  # $usize - $i has increased.
    # For a successful decompression, $overlap + $c_ofs >= $u_ofs must be true at any time. This corresponds to $overlap >= $usize - $i.
    $overlap = $usize - $i if $overlap < $usize - $i;
    if (defined($_[2])) {  # $_[2] is decompression output string ($udata).
      for (my $j = 0; $j < $m_len; ++$j) { $_[2] .= substr($_[2], -$m_off, 1) }
    }
  }
  return 0 if $is_lastmoff1_only;
  #printf(STDERR "info: csize after loop: 0x%x\n", $i);
  my $ebb = ($bc) ? 0 : 1;  # $ebb is 1 iff the compressed NRV2 stream has anded at a byte boundary, otherwise 0.
  #printf(STDERR "info: ebb: %u\n", $ebb);
  die("fatal: end-of-stream marker found too early (at $i) in $method_str stream\n") if $i != $csize;
  if ($max_distance <= 0xffffff) {
    die("fatal: short end-of-stream marker not found in $method_str stream\n") if !$short_eos_ofs;
    die("fatal: short end-of-stream marker found too early in $method_str stream\n") if $short_eos_ofs and $short_eos_ofs + 5 < $csize;
  } else {
    $short_eos_ofs = 0;
  }
  ($usize, $short_eos_ofs, $max_distance, $lastmoff1, $overlap, $ebb)
}

sub parse_uint($) {
  my $s = $_[0];
  # TODO(pts): Check for overflow.
  return (hex($s) or 0) if $s =~ m@^0[xX][0-9a-fA-F]+\Z(?!\n)@;
  return (oct($s) or 0) if $s =~ m@^0[0-7]*\Z(?!\n)@;
  return (int($s) or 0) if $s =~ m@^[1-9][0-9]*\Z(?!\n)@;  # `0' is covered by oct($s) above.
  die("fatal: bad unsigned integer: $s\n")
}

# --- Directory configuration.

my $selfdir = ".";
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

# --- Configuration and command-line parsing. !! Let the user change it on the command line.

my $infn;
my $outfn;
my $filter = 0;
my $upx_prog = "$selfdir/tools/upx-3.94.upx";
my $nasm_prog = "$selfdir/tools/nasm-0.98.39.upx";
my $method_str = "nrv2b";
my $cpu = 8086;  # Most compatible.
my @upx_crp_flags;
{ my $i;
  for ($i = 0; $i < @ARGV; ++$i) {
    my $arg = $ARGV[$i];
    if ($arg eq "--") { ++$i; last }
    elsif ($arg eq "-" or $arg !~ m@^-@) { last }
    elsif ($arg eq "--no-lzma") {}
    elsif ($arg eq "--nrv2b" or $arg eq "--nrv2d" or $arg eq "--nrv2e") { $method_str = substr($arg, 2) }
    elsif ($arg eq "--no-filter") { $filter = 0 }
    elsif ($arg =~ s@^--filter=@@) { $filter = parse_uint($arg) }
    elsif ($arg eq "-o" and $i < @ARGV - 1) { $outfn = $ARGV[++$i] }
    elsif ($arg =~ m@^--(?:cpu=)?(8086|186|286|386)\Z(?!\n)@) { $cpu = $1 + 0 }  # This is the minimum CPU requirement (8086 < 186 < 186). Only backward-compatible instructions are used.
    elsif ($arg =~ m@^--crp-(?:nrv|ucl|lzma)-[a-z]+=@ or $arg eq "--prefer-nrv" or $arg eq "--prefer-ucl" or $arg eq "--best" or $arg =~ m@^(-[1-9])\Z(?!\n)@) { push @upx_crp_flags, $arg }  # Pass compressor flag to UPX.
    elsif ($arg =~ s@^--upx=@@) { $upx_prog = $arg }
    elsif ($arg =~ s@^--nasm=@@) { $nasm_prog = $arg }
    else { die "fatal: unknown command-line flag: $arg\n" }
  }
  die("fatal: missing input filename\n") if $i >= @ARGV;
  $infn = $ARGV[$i++];
  $outfn = $ARGV[$i++] if $i < @ARGV and !defined($outfn);
  die("fatal: too many command-line arguments\n") if $i < @ARGV;
  die("fatal: missing output filename\n") if !defined($outfn);
  #die("fatal: missing outout --format=...\n") if !defined($ofmt);
}
my $tmpfn = "$outfn.tmp";

# --- Main program.

my %methods_rev = ("nrv2b" => 3, "nrv2d" => 6, "nrv2e" => 9);  # The 8-bit variants.
my $method = $methods_rev{$method_str};
die("fatal: method not supported: $method\n") if !defined($method);
die("fatal: cannot have apostrophes or newlines in filename: $tmpfn\n") if $tmpfn =~ m@['\r\n]@;  # For parsing by NASM.

my $s = read_file($infn);
die("fatal: missing DOS .exe MZ signature\n") if $s !~ m@^(?:MZ|ZM)@;
my($lastsize, $nblocks, $nreloc, $hdrsize, $minalloc, $maxalloc, $ss, $sp, $checksum, $ip, $cs, $relocpos, $noverlay) =
    unpack("x2v15", substr($s, 0, 0x20));
die("fatal: zero DOS .exe nblocks\n") if $nblocks == 0;
my $img_start = ($hdrsize << 4);
my $img_size = (($lastsize & 0x1ff) or 0x200) + (($nblocks - 1) << 9) - $img_start;
my $img_data = substr($s, $img_start, $img_size);
die("fatal: EOF in DOS .exe image\n") if length($s) < $img_start + $img_size;
die("fatal: unexpected overlay at end of DOS .exe\n") if length($s) > $img_start + $img_size;
my($unused_filter_cto, $count, $xcount) = do_filter($img_data, $filter);  # Modifies $img_data in place.
my $filter_str = sprintf("0x%02x", $filter);
printf(STDERR "info: filtered: $infn: start_ofs=$img_start size=$img_size filter=$filter_str count=$count xcount=$xcount\n");
substr($s, $img_start, $img_size) = $img_data;
write_file($tmpfn, $s);
my $u_exesize = length($s);
my($creloc_size, $csize, $cdataskip, $usize, $c_ss, $c_sp, $c_minalloc, $c_maxalloc, $upx_copy_delta);
{
  my @upx_flags = qw(--best --no-lzma --small --no-reloc --no-filter -f -q -q -q);  # This doesn't support LZMA.
  my @upx_cmd = ($upx_prog, @upx_flags, "--$method_str", @upx_crp_flags, "--", $tmpfn);
  print(STDERR "info: running UPX to compress .exe: ", join(" ", map { shq($_) } @upx_cmd), "\n");
  my $status = system(@upx_cmd);
  if ($status) { unlink($tmpfn); die("fatal: error running UPX: $upx_cmd[0]\n"); }
  $s = read_file($tmpfn);
  die("fatal: missing UPX-compressed DOS .exe MZ signature\n") if $s !~ m@^MZ@;  # UPX doesn't generate "ZM".
  my($clastsize, $cnblocks, $cnreloc, $chdrsize, $cminalloc, $cmaxalloc, $css, $csp, $cchecksum, $cip, $ccs, $crelocpos, $cnoverlay) =
      unpack("x2v15", substr($s, 0, 0x20));
  die("fatal: unexpected UPX-compressed DOS .exe lastsize\n") if $clastsize > 0x200;  # UPX doesn't generate this.
  die("fatal: zero UPX-compressed DOS .exe nblocks\n") if $cnblocks == 0;
  my $i = 0x55;
  die("fatal: missing UPX signature in UPX output DOS .exe file\n") if substr($s, $i, 4) ne "UPX!";
  die("fatal: EOF in UPX pack header in UPX output DOS .exe file\n") if length($s) < $i + 27;
  # PackHeader::putPackHeader(...) with UPX_F_DOS_EXE in upx-3.94-src/src/packhead.cpp .
  my($eh_version, $eh_format, $eh_method, $eh_level, $eh_uadler, $eh_cadler, $eh_usize, $eh_usize_high, $eh_csize, $eh_csize_high, $eh_filesize, $eh_filesize_high, $eh_filter, $eh_checksum) = unpack("x4CCCCVVvCvCvCCC", substr($s, $i, 27));
  $cdataskip = $i + 27;
  $eh_usize |= $eh_usize_high << 16;
  $eh_csize |= $eh_csize_high << 16;
  $eh_filesize |= $eh_filesize_high << 16;
  die("fatal: bad eh_format\n") if $eh_format != 3;  # UPX_F_DOS_EXE.
  die("fatal: bad eh_version\n") if $eh_version < 10 or $eh_version > 14;  # Must be at least 10, UPX 3.94 returns 13.
  die("fatal: bad eh_method: $eh_method\n") if $eh_method != $method;
  die(sprintf("fatal: bad eh_filter: 0x%02x\n", $eh_filter)) if $eh_filter;
  die("fatal: bad eh_level\n") if $eh_level > 10;
  die("fatal: bad eh_filesize\n") if $eh_filesize != $u_exesize;
  $creloc_size = $eh_usize - $img_size;
  die("fatal: bad eh_usize\n") if ($nreloc) ? ($creloc_size <= 0) : ($creloc_size != 0);
  die("fatal: bad eh_csize\n") if $cdataskip + $eh_csize > length($s);
  if ($nreloc) {
    $i = index($s, pack("C4vv", 0xc3, 0x5d, 0x06, 0x1f, 0xb58d, -$creloc_size), $cdataskip + $eh_csize);  # `ret' ++ `pop bp' ++ `push es' ++ `pop ds' ++ `lea si, [word di-...]'.
    die("fatal: missing apply_relocations\n") if $i < 0;
  }
  die("fatal: unexpected (bad?) eh_ss\n") if $css != $ss;
  die("fatal: compressed .exe is too large for decompressor\n") if $eh_csize > 0xffff;
  die("fatal: uncompressed .exe is too large for decompressor\n") if $eh_usize > 0xffff;
  if (1) {  # !! Remove. Also remove $upx_copy_delta.
    pos($s) = 0x20;  # For the \G below.
    die("fatal: missing upx_copy_delta\n") if $s !~ m@\G\xb9..\xbe..\x89\xf7\x1e\xa9\xb5\x80\x8c\xc8\x05\x05\x00\x8e\xd8\x05(..)\x8e\xc0\xfd\xf3\xa5\xfc\x2e\x80\x6c\x12\x10\x73\xe7\x92\xaf\xad\x0e@gs;
    $upx_copy_delta = unpack("v", $1);
  }
  $csize = $eh_csize; $usize = $eh_usize; $c_ss = $css; $c_sp = $csp; $c_minalloc = $cminalloc; $c_maxalloc = $cmaxalloc;
}
my $c_exesize = length($s);
my($analyzed_usize, $short_eos_ofs, $max_distance, $lastmoff1, $overlap, $ebb) = analyze_nrv2(substr($s, $cdataskip, $csize), $method);
die("fatal: bad analyzed NRV2 usize\n") if $analyzed_usize != $usize;
$csize = $short_eos_ofs if 0;  # !! Add truncation of the NRV2 stream to $short_eos_ofs to save a few more bytes.
{
  my @nasm_cmd = (
      $nasm_prog, "-O0", "-w+orphan-labels", "-f", "bin", "-DUPXEXEFN='$tmpfn'",
      "-DCPU=$cpu", "-DMETHOD=$method", sprintf("-DFILTER=0x%02x", $filter), "-DFILTER_CHANGE_COUNT=$count", "-DCSIZE=$csize", "-DCDATASKIP=$cdataskip", "-DUSIZE=$usize", "-DLASTMOFF1=$lastmoff1", "-DMAXDIST=$max_distance", "-DOVERLAP=$overlap",
      "-DUPX_COPY_DELTA=$upx_copy_delta",  # !! Remove.
      "-DCRELOC_SIZE=$creloc_size", "-DC_MINALLOC=$c_minalloc", "-DC_MAXALLOC=$c_maxalloc", "-DU_MINALLOC=$minalloc", "-DU_MAXALLOC=$maxalloc", "-DUPX_C_SS=$c_ss", "-DU_SS=$ss", "-DU_SP=$sp", "-DU_IP=$ip", "-DU_CS=$cs",
      "-o", $outfn, "--", "nrv2_exe.nasm");
  print(STDERR "info: running NASM to generate final .exe: ", join(" ", map { shq($_) } @nasm_cmd), "\n");
  my $status = system(@nasm_cmd);
  unlink($tmpfn);
  die("fatal: error running NASM: $nasm_cmd[0]\n") if $status;
}
my $ocsize = -s($outfn);
my $ofmt = "exe";
my $filter_used_str = ($filter and $count) ? sprintf("0x%02x", $filter) : "none";
my $stats = sprintf("method %s_8, filter %s", uc($method_str), $filter_used_str);
#$stats .= ", prefix " . length($prefix) . " bytes" if length($prefix);
print(STDERR "info: written compressed output: $outfn ($ocsize bytes, format $ofmt, $stats)\n");

__END__
