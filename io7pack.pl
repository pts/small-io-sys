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
my $do_ignores_logo = 0;
for (my $i = 0; $i < @ARGV; ++$i) {
  my $arg = $ARGV[$i];
  if ($arg eq "--") { splice(@ARGV, 0, $i + 1); last }
  elsif ($arg eq "-" or $arg !~ m@^-@) { splice(@ARGV, 0, $i); last }
  elsif ($arg =~ m@^--apack1p=(.*)@s) { $apack1p_prog = $1 }
  elsif ($arg eq "--ignores-logo") { $do_ignores_logo = 1 }
  else { die "fatal: unknown command-line flag: $arg\n" }
}
die "Usage: $0 [<flag> ...] <input.sys> <output.sys>\n" if @ARGV != 2;
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
my $msload;
my($msdcm_image, $msdcm_minallocx, $msdcm_ss, $msdcm_sp, $msdcm_ip, $msdcm_cs);
{
  die "fatal: not an io.sys file: $infn\n" if substr($_, 0, 2) ne "MZ" or substr($_, 0x200, 2) ne "BJ";
  my $msloadsize = (substr($_, 0x340 - 4, 4) eq "ML7I") ? 0x340 : (substr($_, 0x400 - 4, 4) eq "ML7I") ? 0x400 : (substr($_, 0x800 - 2, 2) eq "MS") ? 0x800 : 0;
  die "fatal: missing msload in io.sys file: $infn\n" if !$msloadsize;
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
  die "fatal: MZ hdrsize too large: $infn\n" if ((length($_) + 0xf) >> 4) < $hdrsize;
  $msdcm_image = (length($_) > ($hdrsize << 4)) ? substr($_, $hdrsize << 4) : "";
  $msdcm_minallocx = ($nblocks << 5) + $minalloc - $hdrsize;
  ($msdcm_ss, $msdcm_sp, $msdcm_ip, $msdcm_cs) = ($ss, $sp, $ip, $cs);
  my $insize2 = $hdrsize << 4;
  die "fatal: MZ hdrsize too large: $infn\n" if $insize2 > (($insize + 0xf) & ~0xf);
  $insize = $insize2 if $insize > $insize2;
  substr($_, $insize) = "";
  #$signature = "MZ";  # Unchanged.
  $lastsize = ($insize & 0x1ff);
  $nblocks = ($insize + 0x1ff) >> 9;
  $nreloc = $minalloc = $maxalloc = $ss = $sp = $checksum = $ip = $cs = 0;
  $hdrsize = $msloadsize >> 4;
  substr($_, 0, 0x18) = pack("a2v11", $signature, $lastsize, $nblocks, $nreloc, $hdrsize, $minalloc, $maxalloc, $ss, $sp, $checksum, $ip, $cs);
  $msload = substr($_, 0, $msloadsize);
}

unlink(qw(apack1.tmp apack2.tmp APACK1.TMP APACK2.TMP));
write_file("apack1.tmp", $_);
$_ = undef;  # Save memory.
die "fatal: error reopening stdin as /dev/null" if
    !open(STDIN, "< /dev/null");  # Otherwise apack.exe doesn't make progress in dosbox-nox-1.
my @apack_cmd = defined($apack1p_prog) ? ($apack1p_prog, "-q") : ("./dosbox-nox-v1", "--cmd", "--mem-mb=3", "apack.exe");
die "fatal: error running apack\n" if
    system(@apack_cmd, "-1", "apack1.tmp", "apack2.tmp");
die "fatal: apack2.tmp not created\n" if !-f("apack2.tmp");

$_ = read_file("apack2.tmp");
#unlink(qw(apack1.tmp apack2.tmp));
my $outsize;
{
  die "fatal: not a DOS .exe file: $infn\n" if substr($_, 0, 2) ne "MZ";
  die "fatal: not an APACK-compressed DOS .exe file: $infn\n" if substr($_, 0x20, 2) ne "\x1e\x06";
  die "fatal: unexpected hdrsize in APACK-compressed DOS .exe file: $infn\n" if substr($_, 8, 2) ne "\2\0";
  my $apack_hdrsize = 2;  # Checked above.
  my $trailer_code = unpack("H*", substr($_, -0xb));
  # pop es ++ pop ds ++ mov ss, ax ++ xor sp, sp ++ jmp 0x0:0x0  # The segment of the jump would be modified by a relocation, which we ignore.
  die "fatal: unexpected APACK-compressed trailer code bytes: $trailer_code\n" if $trailer_code ne "071f8ed033e4ea00000000";
  my $trailer_code2 = $do_ignores_logo ? "\x61\xea\0\0\x70\0" :  # popa ++ jmp 0x70:0. Please note that `popa' and the self-extractor code uses 186 instructions, thus it will (silently) fail on the 8086.
      "\x61\xbf" . pack("v", ($insize - length($msload)) >> 4) . "\xea\0\0\x70\0";  # \xbf is: mov di, the value is msbio_passed_para_count, same as load_para_count.
  #$outsize = length($_) - 0xb + length($trailer_code2) - ($apack_hdrsize << 4) + length($msload);
  $outsize = length($_) - 0xb + length($trailer_code2) - ($apack_hdrsize << 4) + length($msload);
  substr($_, $apack_hdrsize << 4, 2) = "\x60\x90";  # We must not change the size, hence we add a nop (\x90).
  
  substr($_, -0xb) = $trailer_code2;
  #$_ .= "\0" x (-length($_) & 0xf);  # No need to pad file size to a multiple of 0x10, msloadv7i works without such padding.
  # !! TODO(pts): Add support for io.sys with MSDCM (by not changing many header fields here to 0. MSDCM must be appended unpacked (or separately packed: first unpack EXEPACK).
  my $hdrsize = ($outsize + 0xf) >> 4;
  my $image_size = ($hdrsize << 4) + length($msdcm_image);
  my $nblocks = ($image_size + 0x1ff) >> 9;
  my $minalloc = $msdcm_minallocx - ($nblocks << 5) + $hdrsize;
  $minalloc = 1 if $minalloc < 1;
  my $lastsize = $image_size & 0x1ff;
  my($signature, $nreloc, $maxalloc, $checksum) = ("MZ", 0, 0xffff, 0);
  substr($_, 0, $apack_hdrsize << 4) = $msload;
  substr($_, 0, 0x18) = pack("a2v11", $signature, $lastsize, $nblocks, $nreloc, $hdrsize, $minalloc, $maxalloc, $msdcm_ss, $msdcm_sp, $checksum, $msdcm_ip, $msdcm_cs);
  die "fatal: assert: bad outsize\n" if length($_) != $outsize;
  if (length($msdcm_image)) { $_ .= "\0" x (-length($_) & 0xf); $_ .= $msdcm_image; $outsize = length($_) }
  write_file($outfn, $_);
  $_ = undef;  # Save memory.
}

printf(STDERR "info: compressed io.sys %s (%d bytes) to %s (%d bytes)\n", $infn, $insize, $outfn, $outsize);

__END__
