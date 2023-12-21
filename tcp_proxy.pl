#! /usr/bin/perl

use warnings;
use strict;

my $ssl=$ENV{"SSL"};
$ssl=0 if (! defined $ssl );

use IO::Socket::INET;
use IO::Select;
if($ssl) {
  require IO::Socket::SSL;
  IO::Socket::SSL->import;
}

my @allowed_ips = ('all', '127.0.0.1');
my $ioset = IO::Select->new;
my $socket_map = {};
my $debug = 0;

sub new_conn {
    my ($host, $port) = @_;
    return IO::Socket::INET->new(
        PeerAddr => $host,
        PeerPort => $port
    ) || die "Unable to connect to $host:$port: $!"; }

sub new_server {
  my ($host, $port) = @_;
  my $server;
  if($ssl) {
    if ( ! -f "server.key" && ! -f "server.crt" ) {
       `openssl req -x509 -newkey rsa:4096 -nodes -keyout server.key -out server.crt -days 365 -subj "/CN=$host/O=AutoSigned httpd trocon/C=FR"`;
        chmod 0600, "server.key";
    }
    $server = IO::Socket::SSL->new(
	LocalAddr => $host,
	LocalPort => $port,
	Listen => 100,
	ReuseAddr => 1,
	SSL_cert_file => 'server.crt',
	SSL_key_file => 'server.key'
    );
  }
  else {
    $server = IO::Socket::INET->new(
        LocalAddr => $host,
        LocalPort => $port,
        ReuseAddr => 1,
        Listen    => 100
    );
  }
  die "Unable to listen on $host:$port: $!" if (!defined $server);
  return $server;
}

sub new_connection {
    my $server = shift;
    my $remote_host = shift;
    my $remote_port = shift;
    my $client = $server->accept;

    if (defined $client) {
      my $client_ip = $client->sockhost;

      if (!client_allowed($client_ip)) {
        print "Connection from $client_ip denied.\n";
        $client->close;
        return;
      }
      print "Connection from $client_ip accepted.\n";

      my $remote = new_conn($remote_host, $remote_port);
      $ioset->add($client);
      $ioset->add($remote);

      $socket_map->{$client} = $remote;
      $socket_map->{$remote} = $client;
    }
    else {
      print "ERROR=$!";
    }
}

sub close_connection {
    my $client = shift;
    my $client_ip = $client->sockhost;
    my $remote = $socket_map->{$client};
    
    $ioset->remove($client);
    $ioset->remove($remote);

    delete $socket_map->{$client};
    delete $socket_map->{$remote};

    $client->close;
    $remote->close;

    print "Connection from $client_ip closed.\n"; }

sub client_allowed {
    my $client_ip = shift;
    return grep { $_ eq $client_ip || $_ eq 'all' } @allowed_ips;
}

sub find_port {
   my ($host, $port) = @_;
   my $encore=1;
   while($encore) {
      my $server = IO::Socket::INET->new(LocalAddr => $host, LocalPort => $port, ReuseAddr => 1);
      if (!defined $server) {
         $port++;
      }
      else {
	 $encore=0;
	 $server->close;
      }
   }
   return $port
}

if ($#ARGV lt 0 || $#ARGV gt 1) {
  print "Usage:\n$0 <local port> <remote_host:remote_port>\n$0 <local_ip:local port> <remote_host:remote_port>\n$0 <remote_host:remote_port>\n";
  print "export SSL=1 to binding with a secure socket.\n";
  exit 12;
}

my ($local_host, $local_port) = split ':', shift() if ($#ARGV eq 2);
my ($remote_host, $remote_port) = split ':', shift();

if (! defined $local_port) {
  $local_host="0.0.0.0";
  $local_port=find_port($local_host,4096);
}
$local_host="0.0.0.0" if $local_host eq "";

print "Starting a server on ${local_host}:$local_port\n";
my $server = new_server(${local_host}, $local_port);
$ioset->add($server);

while (1) {
    for my $socket ($ioset->can_read) {
        if ($socket == $server) {
            new_connection($server, $remote_host, $remote_port);
        }
        else {
            next if ! exists $socket_map->{$socket};
            my $remote = $socket_map->{$socket};
            my $buffer;
            my $read = $socket->sysread($buffer, 4096);
            print $socket->sockhost.":".$socket->sockport ."\t<-\t".$socket->peerhost.":".$socket->peerport ."\tREAD\t$read\n" if $debug;
            if ($read) {
                my $nb = $remote->syswrite($buffer);
                print $remote->sockhost.":".$remote->sockport ."\t->\t".$remote->peerhost.":".$remote->peerport ."\tWRITE\t$nb\n" if $debug;
            }
            else {
              close_connection($socket);
            }
        }
    }
}

