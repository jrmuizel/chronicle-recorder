#
#    Copyright (c) 2006 Novell and contributors:
#        robert@ocallahan.org
#    
#    Permission is hereby granted, free of charge, to any person
#    obtaining a copy of this software and associated documentation
#    files (the "Software"), to deal in the Software without
#    restriction, including without limitation the rights to use,
#    copy, modify, merge, publish, distribute, sublicense, and/or sell
#    copies of the Software, and to permit persons to whom the
#    Software is furnished to do so, subject to the following
#    conditions:
#    
#    The above copyright notice and this permission notice shall be
#    included in all copies or substantial portions of the Software.
#    
#    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
#    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
#    OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
#    NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
#    HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
#    WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
#    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
#    OTHER DEALINGS IN THE SOFTWARE.
#

use IPC::Open2;

sub to_JSON {
  my ($ref) = @_;
  my $kind = ref($ref);
  if (!$kind) {
    if ($ref =~ /^[0-9]+$/) {
      return $ref;
    }
    return '"'.$ref.'"';
  } elsif ($kind eq "HASH") {
    my $str = "{";
    foreach my $k (sort(keys(%$ref))) {
      my $v = $ref->{$k};
      if (length($str) > 1) {
        $str .= ",";
      }
      $str .= '"'.$k.'":'.&to_JSON($v);
    }
    return $str."}";
  } elsif ($kind eq "ARRAY") {
    my $str = "[";
    foreach my $v (@$ref) {
      if (length($str) > 1) {
        $str .= ",";
      }
      $str .= &to_JSON($v);
    }
    return $str."]";
  } else {
    die "Unknown parameter type $kind\n";
  }
}

sub convert_unquoted_JSON {
  my ($str) = @_;
  $str =~ s/:/=>/g;
  $str =~ s/\btrue\b/1/g;
  $str =~ s/\bfalse\b/0/g;
  return $str;  
}

sub from_JSON {
  my ($str) = @_;
  my @parts = split(/"/, $str);
  my $s = "";
  while (@parts) {
    # remove unquoted text
    $s .= &convert_unquoted_JSON(shift(@parts));
    # remove quoted text
    if (@parts) {
      $s .= '"';
      while (1) {
        $s .= shift(@parts).'"';
        if ($s !~ /\\"$/) {
          # it's an unquoted double-quotes, stop
          last;
        }
        die "Missing trailing quote\n" unless @parts;
      }
    }
  }
  # This is awful and it would be a disaster if input was untrusted, but
  # it'll have to do for now.
  return eval($s);
}

my $id = 1;

sub do_query {
  my ($q) = @_;
  $q->{id} = $id;
  my $query = &to_JSON($q);
  print STDERR "SENDING: $query\n";
  print OUT "$query\n";
  my @result = ();
  while (<IN>) {
    print STDERR "GOT: $_";
    my $response = &from_JSON($_);
    if ($response->{id} && $response->{id} eq $id) {
      if (!$response->{message}) {
        push(@result, $response);
      }
      last if $response->{terminated};
    }
  }
  ++$id;
  return @result;
}

open(DB, "<".$ENV{CHRONICLE_DB});
my $retries = 0;
while (1) {
  seek(DB, 14, 0);
  read(DB, $_, 2);
  my @bytes = split(//, $_);
  if (ord($bytes[0]) || ord($bytes[1])) {
    last;
  }
  ++$retries;
  if ($retries >= 50) {
    die;
  }
  sleep(1);
}
close(DB);

open2(\*IN, \*OUT, './chronicle-query');

