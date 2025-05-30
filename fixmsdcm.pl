#!/bin/sh --
eval 'PERL_BADLANG=x;export PERL_BADLANG;exec perl -x "$0" "$@";exit 1'
#!perl  # Start marker used by perl -x.
+0 if 0;eval("\n\n\n\n".<<'__END__');die$@if$@;__END__

#
# fixmsdcm.pl: fix DOS .exe MZ header after a compressed MSDCM has been added.
# by pts@fazekas.hu at Thu Jan 30 15:36:23 CET 2025
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

die("Usage: $0 <input.sys> [<output.sys>]\n") if @ARGV != 2 and @ARGV != 1;
my $infn = $ARGV[0];
my $outfn = defined($ARGV[1]) ? $ARGV[1] : $ARGV[0];

sub fnopenq($) { $_[0] =~ m@[-+.\w]@ ? $_[0] : "./" . $_[0] }
sub read_file($) {
  my $fn = $_[0];
  die("fatal: open: $fn: $!\n") if !open(FR, "< " . fnopenq($fn));
  binmode(FR);
  my $s = join("", <FR>);
  die() if !close(FR);
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

$_ = read_file($infn);  # TODO(pts): Read less (0x18 bytes) if $infn equ $outfn.
die("fatal: not an io.sys file: $infn\n") if (substr($_, 0, 2) ne "MZ" and substr($_, 0, 2) ne "MG") or substr($_, 0x200, 2) ne "BJ";
my($signature, $msdcm_lastsize, $msdcm_nblocks, $msdcm_nreloc, $hdrsize, $msdcm_minalloc, $msdcm_maxalloc, $msdcm_ss, $msdcm_sp, $checksum, $msdcm_ip, $msdcm_cs) = unpack("a2v11", substr($_, 0, 0x18));
die("fatal: bad MZ nreloc: $infn\n") if $msdcm_nreloc;   # Also checked above.
die("fatal: bad MZ lastsize, must be 0: $infn\n") if $msdcm_lastsize and !$msdcm_nblocks;
# It's OK to have any $checksum value.
my $has_changed = 0;
my $imagehdr_size = (($msdcm_lastsize & 0x1ff) or 0x200) + (($msdcm_nblocks - 1) << 9);
sub fix_minmaxalloc($$$$$) {
  # minalloc and maxalloc values are paragraph counts beyond the .exe image
  # (i.e. this many paragraphs: (nblocks << 5) - hdrsize).
  my($minmaxalloc, $orig_nblocks, $orig_hdrsize, $nblocks, $hdrsize) = @_;
  return $minmaxalloc if $minmaxalloc == 0 or $minmaxalloc == 0xffff;
  my $minmaxallocx = ($orig_nblocks << 5) + $minmaxalloc - $orig_hdrsize;
  my $minmaxallocy = $minmaxallocx - ($nblocks << 5) + $hdrsize;
  $minmaxallocy < 1 ? 1 : $minmaxallocy
}
if ($signature eq "MZ" and $msdcm_nblocks) {  # Already fixed, just check.
  die("fatal: bad sp in MZ header: $infn\n") if !$msdcm_sp;
  die("fatal: bad MSCDM MZ hdrsize: $infn\n") if ((length($_) + 0xf) >> 4) < $hdrsize;
  die("fatal: missing MSCDM: $infn\n") if ((length($_) + 0xf) >> 4) == $hdrsize;
  die("fatal: image too short: $infn\n") if $imagehdr_size > length($_);
  die("fatal: unexpected overlay: $infn\n") if $imagehdr_size and $imagehdr_size < length($_);
} elsif ($signature eq "MZ" and !$msdcm_nblocks) {  # Already fixed, just check.
  die("fatal: bad MZ signature: $infn\n") if $signature ne "MZ";
  die("fatal: bad missing MSDCM in MZ header: $infn\n") if $msdcm_lastsize or $msdcm_nblocks or $msdcm_minalloc or $msdcm_maxalloc or $msdcm_ss or $msdcm_sp or $msdcm_ip or $msdcm_cs;
  die("fatal: image too short: $infn\n") if $imagehdr_size > length($_);
  die("fatal: kernel image shorter than hdrsize: $infn\n")  if ((length($_) + 0xf) >> 4) < $hdrsize;
  die("fatal: unexpected data after kernel image: $infn\n") if ((length($_) + 0xf) >> 4) > $hdrsize;
} elsif ($signature eq "MG") {
  # The MG header: my($mg_signature, $mg_orig_lastsize, $mg_orig_nblocks, $mg_nreloc, $mg_hdrsize, $mg_orig_minalloc, $mg_orig_maxalloc, $mg_ss, $mg_sp, $mg_orig_hdrsize, $mg_ip, $mg_cs) = unpack("a2v11", substr($_, 0, 0x18));
  # MSDCM must be present if the MG header is used.
  # Values in the MG header are a combination of original MZ headers values ($mg_orig_...) and new MZ header values.
  # Typical size change: $mg_hdrsize < $mg_orig_hdrsize, because the embedded compressed logo has been removed.
  # The code below converts the MG header to a regular DOS .exe MZ header by making the following changes:
  # * It keeps $mg_nreloc (always 0), $mg_ss, $mg_sp, $mg_ip, $mg_cs.
  # * It keeps $mg_hdrsize, which still contains the paragraph offset of MSDCM within the file, or the paragraph size of the file if MSDCM is missing.
  # * It sets $mg_orig_lastsize ($lastsize) and $mg_orig_nblocks  ($nblocks)  to accommodate the change of hdrsize: increase by $mg_hdrsize, decrease by $mg_orig_hdrsize.
  # * It sets $mg_orig_minalloc ($minalloc) and $mg_orig_maxalloc ($maxalloc) to accommodate the change of hdrsize: increase by $mg_hdrsize, decrease by $mg_orig_hdrsize. Please note that the total memory available for MSDCM will be the same.
  # * It sets $mg_signature ($signature) to "MZ".
  # * It sets $mg_orig_hdrsize ($checksum) to 0.
  die("fatal: unexpected MG signature without MSDCM: $infn\n") if !$msdcm_nblocks;
  die("fatal: MG hdrsize too small: $infn\n") if $hdrsize < 1;
  die("fatal: kernel image shorter than hdrsize: $infn\n") if ((length($_) + 0xf) >> 4) < $hdrsize;
  die("fatal: MSDCM is empty: $infn\n") if ((length($_) + 0xf) >> 4) == $hdrsize;
  my $orig_lastsize = $msdcm_lastsize;
  my $orig_nblocks = $msdcm_nblocks;
  my $orig_imagehdr_size = (($msdcm_lastsize & 0x1ff) or 0x200) + (($msdcm_nblocks - 1) << 9);
  my $orig_hdrsize = $checksum;
  my $imagehdr_size_delta_para = $hdrsize - $orig_hdrsize;  # Typically 0 or negative.
  $imagehdr_size += $imagehdr_size_delta_para << 4;
  die("fatal: bad new file size: $infn\n") if $imagehdr_size != length($_);
  $has_changed = 1;
  $signature = "MZ";
  $checksum = 0;
  $msdcm_nblocks = ($imagehdr_size + 0x1ff) >> 9;
  $msdcm_lastsize = $imagehdr_size & 0x1ff;
  $msdcm_minalloc = fix_minmaxalloc($msdcm_minalloc, $orig_nblocks, $orig_hdrsize, $msdcm_nblocks, $hdrsize);
  $msdcm_maxalloc = fix_minmaxalloc($msdcm_maxalloc, $orig_nblocks, $orig_hdrsize, $msdcm_nblocks, $hdrsize);
} else {  # Shouldn't happen, checked above.
  die("fatal: bad signature: $infn\n");
}
my $msloadsize = (substr($_, 0x340 - 4, 4) eq "ML7I") ? 0x340 : (substr($_, 0x400 - 4, 4) eq "ML7I") ? 0x400 : (substr($_, 0x800 - 2, 2) eq "MS") ? 0x800 : 0;
die "fatal: missing msload in io.sys file: $infn\n" if !$msloadsize;
if ($msloadsize != 0x800 or substr($_, 0x800 - 10, 4) eq "ML7I") {  # Check $rdseg.
  my $msload = substr($_, 0, $msloadsize);
  my $rbseg_fofs = 0x1a;
  my($rbseg_code, $rbseg) = unpack("a2v", substr($msload, $rbseg_fofs - 2, 4));  # Typical $rbseg value: 0x4800.
  die("fatal: bad reloc-base-segment code: $infn\n") if $rbseg_code ne "\xfc\xb8";  # cld ++ mov ax, RELOC_BASE_SEGMENT.
  die("fatal: bad reloc-base-segment value: $infn\n") if $rbseg < 0x3400 or $rbseg > 0x5000;  # Other values may work, this is just a sanity check.
  my $var_fat_cache_segment_fofs = index($msload, "\x5b\x5b\xeb\x09\x90");  # pop bx ++ pop bx ++ jmp short initialized_data.end ++ nop.
  die("fatal: initialized_data not found in msload: $infn\n") if $var_fat_cache_segment_fofs < 0 or $var_fat_cache_segment_fofs > 0x80;  # Typical value is 0x61.
  $var_fat_cache_segment_fofs += 5 + 4 + 2;
  my $var_fat_cache_segment = unpack("v", substr($msload, $var_fat_cache_segment_fofs, 2));
  die("fatal: bad var_fat_cache_segment value in msload: $infn\n") if
      # This corresponds to `var.fat_cache_segment: dw RELOC_BASE_SEGMENT+0xc0-0x10+(EXTRA_SKIP_SECTOR_COUNT<<5)' in msloadv7i.nasm.
      $var_fat_cache_segment != $rbseg + 0xc0 - 0x10 + ((length($msload) == 0x340) << 6);
}
if ($imagehdr_size) {  # Do some additional checks if MSDCM is present.
  my $initialized_mem_size = ($imagehdr_size - ($hdrsize << 4));
  die("fatal: image size is smaller than hdrsize: $infn\n") if $initialized_mem_size < 0;
  my $mem_size = $initialized_mem_size + ($msdcm_minalloc or 0xffff) << 4;
  my $entry_laddr = ($msdcm_cs << 4) + $msdcm_ip;
  die("fatal: bad entry address: $infn\n") if $entry_laddr >= $initialized_mem_size;
  my $stacktop_laddr = ($msdcm_ss << 4) + $msdcm_sp;
  die("fatal: bad stack top address: $infn\n") if $stacktop_laddr > $mem_size;
}

if ($outfn ne "" and $outfn ne "." and ($outfn ne $infn or $has_changed)) {
  substr($_, 0, 0x18) = pack("a2v11", $signature, $msdcm_lastsize, $msdcm_nblocks, $msdcm_nreloc, $hdrsize, $msdcm_minalloc, $msdcm_maxalloc, $msdcm_ss, $msdcm_sp, $checksum, $msdcm_ip, $msdcm_cs);
  write_file($outfn, $_)
}

__END__
