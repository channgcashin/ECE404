#remove all rules or chains
sudo iptables -F
sudo iptables -X
sudo iptables -t nat -F
sudo iptables -t nat -X
sudo iptables -t raw -F
sudo iptables -t raw -X
sudo iptables -t mangle -F
sudo iptables -t mangle -X
sudo iptables -t filter -F
sudo iptables -t filter -X

#accept packets from f1.com
iptables -A INPUT -p all -s f1.com -j ACCEPT

#change source IP to own for all outgoing packets
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

#block scanning
iptables -A FORWARD -p tcp --tcp-flags ACK,FIN,RST SYN -m limit --limit 1/s -j ACCEPT

#SYN-flood protection
iptables -A FORWARD -p tcp --syn -m limit --limit 1/s -j ACCEPT

#allow full loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -j REJECT

#port forwarding
iptables -t nat -A PREROUTING -p tcp --dport 8888 -j DNAT --to-destination :25565
iptables -A FORWARD -p tcp --dport 25565 -j ACCEPT

#allow ssh connections
iptables -A INPUT -p tcp -s engineering.purdue.edu --dport 22 -j DROP
iptables -A OUTPUT -p tcp -d engineering.purdue.edu --sport 22 -j DROP

#drop packets that don't follow above rules
iptables -A INPUT -p all -j REJECT --reject-with icmp-host-prohibited  
