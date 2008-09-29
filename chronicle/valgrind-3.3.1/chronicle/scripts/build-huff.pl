#!/usr/bin/perl -w

undef($/);

my $do_words = 0;

my %byte_table = ();
my @word_tables = ();
foreach my $f (@ARGV) {
  open(F, "<$f") || die;
  my $data = <F>;
  close(F);

  my @vals = unpack("L(SC)*", $data);
  my $len = shift(@vals);
  my $i = 1;
  while (@vals) {
    my $w = shift(@vals);
    my $b = shift(@vals);
    if (!defined($w) || !defined($b)) {
      print "ERR in file $f; len=$len, at $i\n";
    }
    $byte_table{$b}++;
    if ($do_words) {
      foreach my $j (0..16) {
	my $max=1<<$j;
	if ($i > ($max-1)/2 && $i <= $max) {
	  $word_tables[$j]->{$w}++;
	}
      }
      ++$i;
      if ($i > 1<<16) {
	$i = 1;
      }
    }
  }
}

my %parents;
my %digits;

sub build {
  my %freqs = @_;

  my $gensym = 0;

  my @orig = keys(%freqs);

  my @worklist = sort {$freqs{$a}<=>$freqs{$b};} keys(%freqs);
  %parents = ();
  %digits = ();

  while (scalar(keys(%freqs)) >= 2) {
    my $min1_k = shift(@worklist);
    my $min2_k = shift(@worklist);
    my $min1 = $freqs{$min1_k};
    my $min2 = $freqs{$min2_k};

    my $sym = "g".($gensym++);
    $parents{$min1_k} = $sym;
    $digits{$min1_k} = 0;
    $parents{$min2_k} = $sym;
    $digits{$min2_k} = 1;

    $freqs{$sym} = $freqs{$min1_k} + $freqs{$min2_k};
    my $f = $freqs{$sym};
    delete($freqs{$min1_k});
    delete($freqs{$min2_k});

    # binary search
    my $start = 0;
    my $end = @worklist;
    while ($end - $start >= 2) {
      my $mid = ($end - $start)/2 + $start;
      if ($f < $freqs{$worklist[$mid]}) {
	$end = $mid;
      } else {
	$start = $mid;
      }
    }
    if ($start < scalar(@worklist) && $f > $freqs{$worklist[$start]}) {
      $start++;
    }
    splice(@worklist, $start, 0, $sym);
  }

  sub build_string {
    my ($k) = @_;
    if (defined($parents{$k})) {
      return &build_string($parents{$k}).$digits{$k};
    } else {
      return "";
    }
  }

  my %result = ();
  foreach my $k (@orig) {
    $result{$k} = build_string($k);
  }
  return %result;
}

sub to_binary {
  my ($v) = @_;
  my $r = 0;
  my @digits = split(//, $v);
  foreach my $d (@digits) {
    $r *= 2;
    if ($d eq '1') {
      $r++;
    }
  }
  return $r;
}

sub compute_saving {
  my ($orig_bits, $rtable, $ftable) = @_;

  my $orig_sum = 0;
  my $new_sum = 0;
  foreach my $k (keys(%$rtable)) {
    my $new_bits = length($rtable->{$k});
    my $freq = $ftable->{$k};
    $orig_sum += $orig_bits*$freq;
    $new_sum += $new_bits*$freq;
  }
  $orig_sum /= 8;
  $new_sum /= 8;
  my $ratio = $new_sum/$orig_sum*100;
  print "Old size $orig_sum, new size $new_sum, ratio=$ratio%\n";
}

if (1) {
  my %bresult = &build(%byte_table);

  foreach my $b (sort {$a <=> $b;} keys(%byte_table)) {
    my $r = $bresult{$b};
    print "HUFFVAL_BYTE($b, 0x";
    printf('%x', &to_binary($r));
    print ", ", length($r), ") /* $byte_table{$b}, $r */\n";
  }
  if (0) {
    &compute_saving(8, \%bresult, \%byte_table);
  }
}

if ($do_words) {
  foreach my $i (0..16) {
    printf("\n$i-bit words\n");
    my %tmp_table = %{$word_tables[$i]};
    my %wresult = &build(%tmp_table);

    if ($i > 0) {
      &compute_saving($i, \%wresult, \%tmp_table);
    }
    foreach my $b (sort {$a <=> $b;} keys(%tmp_table)) {
      my $r = $wresult{$b};
      print "$b\t0x";
      printf('%x', &to_binary($r));
      print "\t", length($r), "\t$tmp_table{$b}\t$r\n";
    }
  }
}
