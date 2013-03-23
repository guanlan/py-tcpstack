A user-level tcp stack.

Require root privileges to create raw socket.

Also need add a rule in iptables
iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
