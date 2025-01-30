#!/bin/sh --
eval 'PERL_BADLANG=x;export PERL_BADLANG;exec perl -x "$0" "$@";exit 1'
#!perl  # Start marker used by perl -x.
+0 if 0;eval("\n\n\n\n".<<'__END__');die$@if$@;__END__

#
# logod.pl: decompressor for MS-DOS 7.x io.sys embedded logo
# by pts@fazekas.hu at Thu Jan 30 12:03:18 CET 2025
#
# This script works with Perl 5.004.04 (1997-10-15) or later.
#
# Parts based on: https://github.com/pierce-smith1/io7/blob/main/io7.ts
#

BEGIN { $ENV{LC_ALL} = "C" }  # For deterministic output. Typically not needed. Is it too late for Perl?
BEGIN { $ENV{TZ} = "GMT" }  # For deterministic output. Typically not needed. Perl respects it immediately.
BEGIN { $^W = 1 }  # Enable warnings.
use integer;
use strict;

my $fofs = 0;
if (@ARGV and $ARGV[0] =~ m@^--fofs=(?:0x([0-9a-fA-F]+)|([1-9]\d*))\Z(?!\n)@s) { $fofs = defined($1) ? hex($1) : int($1); shift(@ARGV) }
die("Usage: $0 [--fofs=<file-offset>] <input.sys> <output.sys>\n") if @ARGV != 2;
my $infn = $ARGV[0];
my $outfn = $ARGV[1];

sub fnopenq($) { $_[0] =~ m@[-+.\w]@ ? $_[0] : "./" . $_[0] }
sub read_file($;$) {
  my($fn, $fofs) = @_;
  die("fatal: open: $fn: $!\n") if !open(FR, "< " . fnopenq($fn));
  binmode(FR);
  $fofs = 0 if $fofs and seek(FR, $fofs, 0);
  my $s = join("", <FR>);
  $_ = substr($_, $fofs) if $fofs;
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

$_ = read_file($infn, $fofs);
my $ud = "";  # Uncompressed data.
for (my $i = 0; $i < length($_); ) {
  die("fatal: EOF in csize: $infn\n") if $i + 2 > length($_);
  my $csize = unpack("v", substr($_, $i, 2));
  last if $csize == 0;
  if (!($csize & 0x8000)) {  # Uncompressed block. This doesn't happen in practice.
    die "fatal: odd uncompressed block size\n" if $csize & 1;
    $ud .= substr($_, $i + 2, $csize);
    $i += 2 + $csize;
  } else {  # LZSS-compressed block.
    $csize &= 0x7fff;
    die("fatal: EOF in usize: $infn\n") if $i + 6 > length($_);
    my($usize, $signature) = unpack("va4", substr($_, $i + 2, 6));
    die(sprintf("fatal: bad block signature at 0x%x: %s\n", $fofs + $i + 4, $infn)) if $signature ne "DS\0\0";
    die("fatal: block usize too large: $infn\n") if $usize > 0x2000;
    #print(STDERR "info: compressed block at=$i csize=$csize usize=$usize\n");
    my $bi = ($i + 8) << 3;
    my $bj = ($i + 4 + $csize) << 3;
    die("fatal: compressed block too short: $infn\n") if $bi >= $bj;
    my $uds = length($ud) + $usize;
    # The following code is based on: https://github.com/pierce-smith1/io7/blob/main/io7.ts
    my $read_bits = sub {
      my($bc, $v) = ($_[0], 0);
      for (my $bk = 0; $bk < $bc; ++$bk) {
        die("fatal: EOF in compressed block: $infn\n") if $bi == $bj;
        $v |= vec($_, $bi++, 1) << $bk;  # We are lucky that Perl builtin vec(...) has the LSB bit order: vec($s, 0, 1) == (ord($s) & 1).
      }
      $v
    };
    for (;;) {
      my $tag = $read_bits->(2);
      #printf(STDERR "info: tag=$tag\n");
      if ($tag == 1 or $tag == 2) {  # Literal.
        #die("fatal: bad block usize in literal token: $infn\n") if length($ud) + 1 > $uds;  # Catch it early. We don't check it for speed.
        $ud .= chr($read_bits->(7) | ($tag & 1) << 7);
      } else {
        my $offset = !$tag ? $read_bits->(6) : $read_bits->(1) ? $read_bits->(12) + 0x140 : $read_bits->(8) + 0x40;
        if ($offset == 0x113f) {
          #printf(STDERR "info: sentinel token bi=$bi bj=$bj\n");
          last if $bi + 8 > $bj;  # If there is less than 8 bits left after a sentinel token, then it's end of the block.
        } else {
          die("fatal bad offset in offset-length token: $offset\n") if $offset <= 0;
          my $bs = 0;
          ++$bs while !$read_bits->(1);
          my $length = (1 << $bs) + 1 + $read_bits->($bs);
          die("fatal: bad block usize in offset--length token: $infn\n") if length($ud) + $length > $uds;  # Catch it early.
          #printf(STDERR "info: offset--length token: offset=$offset length=$length\n");
          # Below is a faster implementation of:
          # while ($length--) { $ud .= substr($ud, -$offset, 1) }
          for (; $length > $offset; $length -= $offset) {
            $ud .= substr($ud, -$offset);
          }
          $ud .= substr($ud, -$offset, $length);
        }
      }
    }
    die("fatal: bad block usize: $infn\n") if length($ud) != $uds;
    last if $usize < 0x2000;  # Last partial block.
    $i = $bj >> 3;
  }
}
write_file($outfn, $ud);

__END__
