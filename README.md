# tcp_proxy
TCP proxy with optional SSL

* Syntaxe  
./tcp_proxy.pl <local port> <remote_host:remote_port>  
./tcp_proxy.pl <local_ip:local port> <remote_host:remote_port>  

* With SSL support  
export SSL=1 ; ./tcp_proxy.pl <local port> <remote_host:remote_port>  
OR  
SSL=1 ./tcp_proxy.pl <local port> <remote_host:remote_port>  

* Need perl modules:  
IO::Socket::INET  
IO::Select  
* If ssl is enable :  
IO::Socket::SSL  

# tcp_proxy2
* Specials/Advanced (to use when you understand well):  
export SSLBG=1 to decrypt background SSL.  
Proxy-ssh is triggered when variable RPORT_SSH is set (and optionally RHOST_SSH=hostname else remote_host is used).  


