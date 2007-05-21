#!/usr/bin/perl -w

use Socket;

my @opts = ();
my $port;

while ($_ = shift(@ARGV)) {
  if (/^--port$/) {
    $port = shift(@ARGV);
    if (!defined($port)) {
      die "Need port parameter after --port";
    }
  } else {
    push(@opts, $_);
  }
}
if (!defined($port)) {
  die "Need --port parameter";
}

my $proto = getprotobyname('tcp');
socket(Server, PF_INET, SOCK_STREAM, $proto) || die "socket: $!";
setsockopt(Server, SOL_SOCKET, SO_REUSEADDR, pack("l", 1)) || die "setsockopt: $!";
bind(Server, sockaddr_in($port, INADDR_LOOPBACK)) || die "bind: $!";
listen(Server, 1) || die "listen: $!";

# Daemonize once we've started listening
if (fork()) {
  exit(0);
}

my $paddr = accept(Client, Server);
open(STDIN, "<&Client") || die "Cannot reopen STDIN: $!";
open(STDOUT, ">&Client") || die "Cannot reopen STDOUT: $!";

close(Server);
close(Client);

exec("/home/roc/shared/chronicle/chronicle-query", @opts) || die "Bad exec: $!";
