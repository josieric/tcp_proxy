#! /usr/bin/perl

use warnings;
use strict;
use IO::Socket::INET;
use IO::Select;

# Get param in env
my $ssl=$ENV{"SSL"};
$ssl=0 if (! defined $ssl );
my $sslbg=$ENV{"SSLBG"};
$sslbg=0 if (! defined $sslbg );
my $remote_host_ssh=$ENV{"RHOST_SSH"};
$remote_host_ssh="" if (! defined $remote_host_ssh );
my $remote_port_ssh=$ENV{"RPORT_SSH"};
$remote_port_ssh="" if (! defined $remote_port_ssh );
my $debug=$ENV{"DEBUG"};
$debug=0 if (! defined $debug );

# Load SSL module if need
if($ssl || $sslbg) {
  require IO::Socket::SSL;
  IO::Socket::SSL->import;
}

# Constants and working variables
my @allowed_ips = ('all', '127.0.0.1');
my $ioset = IO::Select->new;
my $socket_map = {};
my $socket_cli = {};
my $SSL_ERROR;

## Manage command line args OR usage
if ($#ARGV lt 0 || $#ARGV gt 1) {
  print "Usage:\n\t$0 <local port> <remote_host:remote_port>\n\t$0 <local_ip:local port> <remote_host:remote_port>\n\t$0 <remote_host:remote_port>\n";
  print "\texport SSL=1 to binding with a secure socket.\n";
  print "Specials/Advanced (to use when you understand well):\n";
  print "\texport SSLBG=1 to decrypt background SSL.\n";
  print "\tProxy-ssh is triggered when variable RPORT_SSH is set (and optionally RHOST_SSH=hostname else remote_host is used).\n";
  exit 12;
}

my ($local_host, $local_port);
if ($#ARGV eq 1) { # IE: 2 param ;-)
  ($local_host, $local_port) = split ':', shift();
  if (! defined $local_port ) {
    if ( $local_host =~ /^[0-9]*$/ ) {
       $local_port = $local_host;
       $local_host = "localhost";
    }
    else {
      $local_port = find_port($local_host,4096);
    }
  }
}
else {
  $local_host = "localhost";
  $local_port=find_port($local_host,4096);
}
my ($remote_host, $remote_port) = split ':', shift();

print("$local_host:$local_port $remote_host:$remote_port $remote_host_ssh:$remote_port_ssh\n") if $debug;
start_proxy($local_host, $local_port,$remote_host, $remote_port, $remote_host_ssh, $remote_port_ssh);

### Functions
##############
sub new_conn {
    my ($host, $port) = @_;
    print("\tconnect to $host:$port\n");
    my $sock = IO::Socket::INET->new(
        PeerAddr => $host,
        PeerPort => $port
    );
    if (! $sock) {
      print "Unable to connect to $host:$port: $!";
    }
    return $sock;
}

sub new_conn_ssl {
    my ($host, $port) = @_;
    print("\tSSLconnect to $host:$port\n");
    my $sock = IO::Socket::SSL->new(
        PeerAddr => $host,
        PeerPort => $port,
        SSL_verify_mode => 0
    );
    if (! $sock) {
      print "Unable to connect to $host:$port: $!\n";
      print "ssl_error=$SSL_ERROR\n" if defined $SSL_ERROR;
    }
    return $sock;
}
## SSL_verify_mode=VERIFY_NONE ??
## maybe use SSL_ca_file or SSL_ca_path to specify a different CA store !!!

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
    my $remote_host_ssh = shift;
    my $remote_port_ssh = shift;
    my $client = $server->accept;

    if (defined $client) {
      my $client_ip = $client->peerhost;
      my $client_port = $client->peerport;
      if (!client_allowed($client_ip)) {
        print "Connection from $client_ip:$client_port denied.\n";
        $client->close;
        return;
      }
      print "Connection from $client_ip:$client_port accepted.\n";
      ## Detect client protocol (read 3 bytes from client to detect)
      my $buffer;
      my $read = $client->sysread($buffer, 3);
      print $client->sockhost.":".$client->sockport ."\t<-\t".$client->peerhost.":".$client->peerport ."\tREAD\t$read\n" if $debug;
      my $action;
      if ($read) {
         $action = detect_client_protocol($buffer);
	 if ($action eq "SSH") {
           print("\tSSH !! ");
	   if ($remote_port_ssh ne "") {
             $remote_host = $remote_host_ssh if $remote_host_ssh ne "";
             $remote_port = $remote_port_ssh;
	   }
         }
         elsif ($action eq "SSL") {
           print("\tSSL !!");
         }
	 else {
	   $action="";
           print("\tProtocol is not SSL & not SSH !! ");
	 }
      }
      my $remote;
      if ($sslbg) {
          $remote = new_conn_ssl($remote_host, $remote_port);
      }
      else {
          $remote = new_conn($remote_host, $remote_port);
      }
      if ($remote) {
        $ioset->add($client);
        $ioset->add($remote);
        $socket_cli->{$client} = $remote->peerhost.":".$remote->peerport;
        $socket_map->{$client} = $remote;
        $socket_map->{$remote} = $client;
        if ($read) {
           my $nb = $remote->syswrite($buffer);
           print $remote->sockhost.":".$remote->sockport ."\t->\t".$remote->peerhost.":".$remote->peerport ."\tWRITE\t$nb\n" if $debug;
           read_write($client,$remote,4096);
        }
      }
      else {
	 print "WARN: Did you have connect a SSH port with a SSLconnect ? (Cf RPORT_SSH & SSLBG)" if ($action eq "SSH" && $sslbg);
         print "ERROR when connecting to $remote_host:$remote_port=$!\n";
      }
    }
    else {
      print "ERROR when adding connection=$!";
    }
}

sub detect_client_protocol {
  my $head= shift;
  my $hex=hex_str($head);
  print "ACTION=$head $hex " if $debug;
  $head="SSL" if ($hex eq "160301");
  return $head;
}

sub hex_str {
  my $str=shift;
  my $hex="";
  foreach(split(//,$str)) {
    $hex .= sprintf("%02X",ord($_));
  }
  return $hex;
}

sub close_connection {
    my $connect = shift;
    my ($client,$remote);
    my $cli_first=0;
    if (defined $socket_cli->{$connect}) {
      $cli_first=1;
      $client = $connect;
      $remote = $socket_map->{$connect};
    }
    else {
      $remote = $connect;
      $client = $socket_map->{$connect};
    }
    my $client_ip = $client->peerhost;
    my $client_port = $client->peerport;
    my $remote_ip = $remote->peerhost;
    my $remote_port = $remote->peerport;
    my ($clientaff,$remoteaff);
    if (! defined $client_ip) {
       $clientaff = "already";
    }
    else {
       $clientaff = "$client_ip:$client_port";
    }
    if (! defined $remote_ip) {
       $remoteaff = $socket_cli->{$client}. " already";
    }
    else {
       $remoteaff = "$remote_ip:$remote_port";
    }

    $ioset->remove($client);
    $ioset->remove($remote);
    delete $socket_map->{$client};
    delete $socket_map->{$remote};
    $client->close;
    $remote->close;
    if ($cli_first) {
      print "Connection from $clientaff closed.\n";
      print "Connection to $remoteaff closed.\n";
    }
    else {
      print "Connection to $remoteaff closed.\n";
      print "Connection from $clientaff closed.\n";
    }
}

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

sub read_write {
  my $reader = shift;
  my $writer = shift;
  my $size = shift;
  my $buffer;
  my $read = $reader->sysread($buffer, $size);
  if ($read) {
     print $reader->sockhost.":".$reader->sockport ."\t<-\t".$reader->peerhost.":".$reader->peerport ."\tREAD\t$read\n" if $debug;
     my $nb = $writer->syswrite($buffer);
     print $writer->sockhost.":".$writer->sockport ."\t->\t".$writer->peerhost.":".$writer->peerport ."\tWRITE\t$nb\n" if $debug;
     if ($debug gt 2) {
        print("BUF=\n$buffer\n".hex_str($buffer)."\n");
     }
  }
  else {
     if (! defined $read) {
       print "\tERROR when reading : $!\n";
     }
     else {
       print "Reading $read (0?) octets from ".$reader->peerhost.":".$reader->peerport.": close connection\n" if $debug gt 1;
     }
     close_connection($reader);
  }
}

sub start_proxy {
  my ($local_host, $local_port,$remote_host, $remote_port, $remote_host_ssh, $remote_port_ssh) = @_;
  print "Starting a server on ${local_host}:$local_port\n";
  my $server = new_server(${local_host}, $local_port);
  $ioset->add($server);

   while (1) {
      ##print "##########".join(" ",$ioset->handles()) ."\n";
      for my $socket ($ioset->can_read) {
         if ($socket == $server) {
            new_connection($server, $remote_host, $remote_port, $remote_host_ssh, $remote_port_ssh);
         }
         else {
            next if ! exists $socket_map->{$socket};
	    read_write($socket, $socket_map->{$socket},4096);
         }
      }
   }
}

