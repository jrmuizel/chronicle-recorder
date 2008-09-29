#!/usr/bin/perl -w

my %data = ();

my $total_instrs = 0;
my $total_log = 0;

while (<>) {
  if (/DEFINE_CODE: #(\d+) instrs=(\d+) reglog=(\d+)/) {
    $data{$1}->{instrs} = $2;
  } elsif (/EXEC#(\d+): (\d+) retired/) {
    $total_instrs += $2;
    if ($data{$1}->{instrs} ne $2) {
      print "abort at $1: got $2, expected $data{$1}->{instrs}\n";
    }
  }
}

print "total_instrs: $total_instrs\n";
