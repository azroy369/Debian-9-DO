#!/bin/sh
# Modified by AzRoY

#Requirement
export DEBIAN_FRONTEND=noninteractive
OS=`uname -m`;
MYIP=$(wget -qO- ipv4.icanhazip.com);
MYIP2="s/xxxxxxxxx/$MYIP/g";

# root
cd

# disable ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6

# Set DNS
echo "nameserver 1.1.1.1" > /etc/resolv.conf
echo "nameserver 1.0.0.1" >> /etc/resolv.conf

# update & upgrade & install wget curl
apt-get update;apt-get -y install wget curl;

# set time GMT +8
ln -sf /usr/share/zoneinfo/Asia/Kuala_Lumpur /etc/localtime

# set repo
cat > /etc/apt/sources.list <<END2
deb http://http.us.debian.org/debian/ stretch main
deb-src http://http.us.debian.org/debian/ stretch main
deb http://security.debian.org/debian-security stretch/updates main
deb-src http://security.debian.org/debian-security stretch/updates main
deb http://http.us.debian.org/debian/ stretch-updates main
deb-src http://http.us.debian.org/debian/ stretch-updates main
deb http://download.webmin.com/download/repository sarge contrib
deb http://webmin.mirror.somersettechsolutions.co.uk/repository sarge contrib
deb https://packages.sury.org/php/ stretch main
END2
wget "http://www.dotdeb.org/dotdeb.gpg"
cat dotdeb.gpg | apt-key add -;rm dotdeb.gpg

# Remove
apt-get -y --purge remove samba*;
apt-get -y --purge remove apache2*;
apt-get -y --purge remove sendmail*;
apt-get -y --purge remove bind9*;
apt-get -y purge sendmail*;
apt-get -y remove sendmail*;

# update
apt-get update; apt-get -y upgrade;

# Install
apt-get -y install build-essential libio-pty-perl libauthen-pam-perl apt-show-versions pptpd dsniff ufw nginx fail2ban bmon iftop htop nmap axel nano iptables traceroute sysv-rc-conf dnsutils bc nethogs openvpn squid3 dropbear stunnel4 vnstat openssl less screen psmisc apt-file whois ptunnel ngrep mtr git zsh mrtg snmp snmpd  unzip  rsyslog debsums rkhunter -y


# disable exim
service exim4 stop
sysv-rc-conf exim4 off

# update apt-file
apt-file update

# setting vnstat
vnstat -u -i venet0
service vnstat restart

# install screenfetch
cd
wget https://github.com/KittyKatt/screenFetch/raw/master/screenfetch-dev
mv screenfetch-dev /usr/bin/screenfetch
chmod +x /usr/bin/screenfetch
echo "clear" >> .profile
echo "screenfetch" >> .profile
cd

# WebServer Configuration
cd
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
wget -O /etc/nginx/nginx.conf "https://raw.githubusercontent.com/Dreyannz/AutoScriptVPS/master/Files/Nginx/nginx.conf"
mkdir -p /home/vps/public_html
echo "<h1><center>AutoScriptVPS by _Dreyannz_</center></h1>" > /home/vps/public_html/index.html
echo "<h3><center>For More Info Visit My <a href="https://github.com/Dreyannz">Github Repositories</a></center><h3>" >> /home/vps/public_html/index.html
echo "<h3><center>You Can Also Contact Me at <a href="https://www.facebook.com/Dreyannz">Facebook</a> and <a href="https://twitter.com/Dreyannz">Twitter</a></center></h3>" >> /home/vps/public_html/index.html
wget -O /etc/nginx/conf.d/vps.conf "https://raw.githubusercontent.com/Dreyannz/AutoScriptVPS/master/Files/Nginx/vps.conf"
service nginx restart

# SSH Configuration
cd
sed -i '/Port 22/a Port 143' /etc/ssh/sshd_config
sed -i '/Port 22/a Port  81' /etc/ssh/sshd_config
sed -i 's/Port 22/Port  22/g' /etc/ssh/sshd_config
sed -i 's/Port 22/Port  442/g' /etc/ssh/sshd_config
service ssh restart
cd
# Setting dropbear
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=442/g' /etc/default/dropbear
sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 109 -p 110"/g' /etc/default/dropbear
echo "/bin/false" >> /etc/shells
/etc/init.d/dropbear restart

# Restart fail2ban
service fail2ban restart

cat > /etc/squid/squid.conf <<-END
acl localhost src 127.0.0.1/32 ::1
acl to_localhost dst 127.0.0.0/8 0.0.0.0/32 ::1
acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 21
acl Safe_ports port 443
acl Safe_ports port 70
acl Safe_ports port 210
acl Safe_ports port 1025-65535
acl Safe_ports port 280
acl Safe_ports port 488
acl Safe_ports port 591
acl Safe_ports port 777
acl CONNECT method CONNECT
acl SSH dst xxxxxxxxxxxxx-xxxxxxxxxxxxx/32
http_access allow SSH
http_access allow manager localhost
http_access deny manager
http_access allow localhost
http_access deny all
http_port 8080
http_port 8000
http_port 80
http_port 3128
coredump_dir /var/spool/squid3
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
visible_hostname proxy.azroyvpn.com
END
sed -i $MYIP2 /etc/squid/squid.conf;
service squid restart

# install stunnel4
apt-get install stunnel4 -y
cat > /etc/stunnel/stunnel.conf <<-END
cert = /etc/stunnel/stunnel.pem
pid = /stunnel.pid
client = no	
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
[dropbear]
accept = 443
connect = 127.0.0.1:442
connect = 127.0.0.1:109
connect = 127.0.0.1:110
;[squid]
;accept = 8000
;connect = 127.0.0.1:3128
;connect = 127.0.0.1:80
;connect = 127.0.0.1:8080
END
openssl genrsa -out key.pem 2048
openssl req -new -x509 -key key.pem -out cert.pem -days 1095 \
-subj "/C=$country/ST=$state/L=$locality/O=$organization/OU=$organizationalunit/CN=$commonname/emailAddress=$email"
cat key.pem cert.pem >> /etc/stunnel/stunnel.pem
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
/etc/init.d/stunnel4 restart

# install webmin
cd
wget "http://script.hostingtermurah.net/repo/webmin_1.801_all.deb"
dpkg --install webmin_1.801_all.deb;
apt-get -y -f install;
sed -i 's/ssl=1/ssl=0/g' /etc/webmin/miniserv.conf
rm /root/webmin_1.801_all.deb
service webmin restart
service vnstat restart

#install PPTP
cat > /etc/ppp/pptpd-options <<END
name pptpd
refuse-pap
refuse-chap
refuse-mschap
require-mschap-v2
require-mppe-128
ms-dns 1.1.1.1
ms-dns 1.0.0.1
proxyarp
nodefaultroute
lock
nobsdcomp
END
echo "option /etc/ppp/pptpd-options" > /etc/pptpd.conf
echo "logwtmp" >> /etc/pptpd.conf
echo "localip 10.1.0.1" >> /etc/pptpd.conf
echo "remoteip 10.1.0.5-100" >> /etc/pptpd.conf
cat >> /etc/ppp/ip-up <<END
ifconfig ppp0 mtu 1400
END
mkdir /var/lib/premium-script
/etc/init.d/pptpd restart

# install mrtg
wget -O /etc/snmp/snmpd.conf $source/snmpd.conf
wget -O /root/mrtg-mem.sh $source/mrtg-mem.sh
chmod +x /root/mrtg-mem.sh
cd /etc/snmp/
sed -i 's/TRAPDRUN=no/TRAPDRUN=yes/g' /etc/default/snmpd
service snmpd restart
snmpwalk -v 1 -c public localhost 1.3.6.1.4.1.2021.10.1.3.1
mkdir -p /home/vps/public_html/mrtg
cfgmaker --zero-speed 100000000 --global 'WorkDir: /home/vps/public_html/mrtg' --output /etc/mrtg.cfg public@localhost
curl "$source/mrtg.conf" >> /etc/mrtg.cfg
sed -i 's/WorkDir: \/var\/www\/mrtg/# WorkDir: \/var\/www\/mrtg/g' /etc/mrtg.cfg
sed -i 's/# Options\[_\]: growright, bits/Options\[_\]: growright/g' /etc/mrtg.cfg
indexmaker --output=/home/vps/public_html/mrtg/index.html /etc/mrtg.cfg
if [ -x /usr/bin/mrtg ] && [ -r /etc/mrtg.cfg ]; then mkdir -p /var/log/mrtg ; env LANG=C /usr/bin/mrtg /etc/mrtg.cfg 2>&1 | tee -a /var/log/mrtg/mrtg.log ; fi
if [ -x /usr/bin/mrtg ] && [ -r /etc/mrtg.cfg ]; then mkdir -p /var/log/mrtg ; env LANG=C /usr/bin/mrtg /etc/mrtg.cfg 2>&1 | tee -a /var/log/mrtg/mrtg.log ; fi
if [ -x /usr/bin/mrtg ] && [ -r /etc/mrtg.cfg ]; then mkdir -p /var/log/mrtg ; env LANG=C /usr/bin/mrtg /etc/mrtg.cfg 2>&1 | tee -a /var/log/mrtg/mrtg.log ; fi
cd

# OpenVPN
cp -r /usr/share/easy-rsa/ /etc/openvpn
mkdir /etc/openvpn/easy-rsa/keys
# replace bits
sed -i 's|export KEY_COUNTRY="US"|export KEY_COUNTRY="MY"|' /etc/openvpn/easy-rsa/vars
sed -i 's|export KEY_PROVINCE="CA"|export KEY_PROVINCE="AZROY"|' /etc/openvpn/easy-rsa/vars
sed -i 's|export KEY_CITY="SanFrancisco"|export KEY_CITY="AZROY"|' /etc/openvpn/easy-rsa/vars
sed -i 's|export KEY_ORG="Fort-Funston"|export KEY_ORG="AZROY"|' /etc/openvpn/easy-rsa/vars
sed -i 's|export KEY_EMAIL="me@myhost.mydomain"|export KEY_EMAIL="faizkapak369@gmail.com"|' /etc/openvpn/easy-rsa/vars
sed -i 's|export KEY_OU="MyOrganizationalUnit"|export KEY_OU="AZROY"|' /etc/openvpn/easy-rsa/vars
sed -i 's|export KEY_NAME="EasyRSA"|export KEY_NAME="AZROY"|' /etc/openvpn/easy-rsa/vars
sed -i 's|export KEY_OU=changeme|export KEY_OU=AZROY|' /etc/openvpn/easy-rsa/vars
#Create Diffie-Helman Pem
openssl dhparam -out /etc/openvpn/dh2048.pem 2048
# Create PKI
cd /etc/openvpn/easy-rsa
cp openssl-1.0.0.cnf openssl.cnf
. ./vars
./clean-all
export EASY_RSA="${EASY_RSA:-.}"
"$EASY_RSA/pkitool" --initca $*
# create key server
export EASY_RSA="${EASY_RSA:-.}"
"$EASY_RSA/pkitool" --server server
# setting KEY CN
export EASY_RSA="${EASY_RSA:-.}"
"$EASY_RSA/pkitool" client
cd
#cp /etc/openvpn/easy-rsa/keys/{server.crt,server.key,ca.crt} /etc/openvpn
cp /etc/openvpn/easy-rsa/keys/server.crt /etc/openvpn/server.crt
cp /etc/openvpn/easy-rsa/keys/server.key /etc/openvpn/server.key
cp /etc/openvpn/easy-rsa/keys/ca.crt /etc/openvpn/ca.crt
# Setting Server
cat > /etc/openvpn/server.conf <<-END
port 1194
proto tcp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh2048.pem
client-cert-not-required
username-as-common-name
plugin /usr/lib/openvpn/openvpn-plugin-auth-pam.so login
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 1.0.0.1"
push "route-method exe"
push "route-delay 2"
duplicate-cn
push "route-method exe"
push "route-delay 2"
keepalive 10 120
comp-lzo
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
log         openvpn.log
verb 3
cipher AES-128-CBC
END

#Create OpenVPN Config
mkdir -p /home/vps/public_html
cat > /home/vps/public_html/client.ovpn <<-END
client
dev tun
proto tcp
remote $MYIP 1194
persist-key
persist-tun
dev tun
pull
resolv-retry infinite
nobind
user nobody
group nogroup
comp-lzo
ns-cert-type server
verb 3
mute 2
mute-replay-warnings
auth-user-pass
redirect-gateway def1
script-security 2
route 0.0.0.0 0.0.0.0
route-method exe
route-delay 2
cipher AES-128-CBC
http-proxy $MYIP 8080
http-proxy-retry
END
echo '<ca>' >> /home/vps/public_html/client.ovpn
cat /etc/openvpn/ca.crt >> /home/vps/public_html/client.ovpn
echo '</ca>' >> /home/vps/public_html/client.ovpn
cd /home/vps/public_html/
tar -czf /home/vps/public_html/openvpn.tar.gz client.ovpn
tar -czf /home/vps/public_html/client.tar.gz client.ovpn
cd

# Restart openvpn
/etc/init.d/openvpn restart
service openvpn start
service openvpn status

#Setting USW
ufw allow ssh
ufw allow 1194/tcp
sed -i 's|DEFAULT_INPUT_POLICY="DROP"|DEFAULT_INPUT_POLICY="ACCEPT"|' /etc/default/ufw
sed -i 's|DEFAULT_FORWARD_POLICY="DROP"|DEFAULT_FORWARD_POLICY="ACCEPT"|' /etc/default/ufw
cat > /etc/ufw/before.rules <<-END
# START OPENVPN RULES
# NAT table rules
*nat
:POSTROUTING ACCEPT [0:0]
# Allow traffic from OpenVPN client to eth0
-A POSTROUTING -s 10.8.0.0/8 -o eth0 -j MASQUERADE
COMMIT
# END OPENVPN RULES
END
ufw enable 
yes
ufw status
ufw disable
cd

# set ipv4 forward
echo 1 > /proc/sys/net/ipv4/ip_forward
sed -i 's|#net.ipv4.ip_forward=1|net.ipv4.ip_forward=1|' /etc/sysctl.conf

# install badvpn
wget -O /usr/bin/badvpn-udpgw "https://raw.githubusercontent.com/azroy369/autoinstall/master/badvpn-udpgw"
if [ "$OS" == "x86_64" ]; then
  wget -O /usr/bin/badvpn-udpgw "https://raw.githubusercontent.com/azroy369/autoinstall/master/badvpn-udpgw64"
fi
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300' /etc/rc.local
chmod +x /usr/bin/badvpn-udpgw
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:730
cd

# install ddos deflate
cd
wget https://github.com/jgmdev/ddos-deflate/archive/master.zip
unzip master.zip
cd ddos-deflate-master
./install.sh
chmod 0755 /usr/local/ddos/ddos.sh
./ddos.sh --start
rm -rf /root/master.zip

# setting banner
rm /etc/issue.net
wget -O /etc/issue.net "https://raw.githubusercontent.com/azroy369/autoinstall/master/issue.net"
sed -i 's@#Banner@Banner@g' /etc/ssh/sshd_config
sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/issue.net"@g' /etc/default/dropbear
service ssh restart
service dropbear restart

cat > /etc/systemd/system/rc-local.service <<-END
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local

[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99

[Install]
WantedBy=multi-user.target
END

cat > /etc/rc.local <<-END
#!/bin/sh -e
#
# rc.local
#
# This script is executed at the end of each multiuser runlevel.
# Make sure that the script will "exit 0" on success or any other
# value on error.
#
# In order to enable or disable this script just change the execution
# bits.
#
# By default this script does nothing.

exit 0
END
chmod +x /etc/rc.local
systemctl enable rc-local
systemctl start rc-local.service
systemctl status rc-local.service

#Setting IPtables
cat > /etc/iptables.up.rules <<-END
*nat
:PREROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -j SNAT --to-source xxxxxxxxx
-A POSTROUTING -o eth0 -j MASQUERADE
-A POSTROUTING -s 192.168.100.0/24 -o eth0 -j MASQUERADE
-A POSTROUTING -s 10.1.0.0/24 -o eth0 -j MASQUERADE
-A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
COMMIT
*filter
:INPUT ACCEPT [19406:27313311]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [9393:434129]
:fail2ban-ssh - [0:0]
-A FORWARD -i eth0 -o ppp0 -m state --state RELATED,ESTABLISHED -j ACCEPT
-A FORWARD -i ppp0 -o eth0 -j ACCEPT
-A INPUT -p tcp -m multiport --dports 22 -j fail2ban-ssh
-A INPUT -p ICMP --icmp-type 8 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 53 -j ACCEPT
-A INPUT -p tcp --dport 22  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 80  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 85  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 80  -m state --state NEW -j ACCEPT
-A INPUT -p udp --dport 80  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 142  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 143  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 109  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 110  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 443  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 1194  -m state --state NEW -j ACCEPT
-A INPUT -p udp --dport 1194  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 1732  -m state --state NEW -j ACCEPT
-A INPUT -p udp --dport 1732  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 3128  -m state --state NEW -j ACCEPT
-A INPUT -p udp --dport 3128  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 7300  -m state --state NEW -j ACCEPT
-A INPUT -p udp --dport 7300  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 8000  -m state --state NEW -j ACCEPT
-A INPUT -p udp --dport 8000  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 8080  -m state --state NEW -j ACCEPT
-A INPUT -p udp --dport 8080  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 10000  -m state --state NEW -j ACCEPT
-A INPUT -p tcp -m tcp --dport 3127 -j ACCEPT
-A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --set 
-A OUTPUT -p tcp --dport 6881:6889 -j DROP
-A OUTPUT -p udp --dport 1024:65534 -j DROP
-A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 10 -j DROP  
-A INPUT -m string --algo bm --string "BitTorrent" -j REJECT
-A INPUT -m string --algo bm --string "BitTorrent protocol" -j REJECT
-A INPUT -m string --algo bm --string "peer_id=" -j REJECT
-A INPUT -m string --algo bm --string ".torrent" -j REJECT
-A INPUT -m string --algo bm --string "announce.php?passkey=" -j REJECT
-A INPUT -m string --algo bm --string "torrent" -j REJECT
-A INPUT -m string --algo bm --string "info_hash" -j REJECT
-A INPUT -m string --algo bm --string "/default.ida?" -j REJECT
-A INPUT -m string --algo bm --string ".exe?/c+dir" -j REJECT
-A INPUT -m string --algo bm --string ".exe?/c_tftp" -j REJECT
-A INPUT -m string --string "peer_id" --algo kmp -j REJECT
-A INPUT -m string --string "BitTorrent" --algo kmp -j REJECT
-A INPUT -m string --string "BitTorrent protocol" --algo kmp -j REJECT
-A INPUT -m string --string "bittorrent-announce" --algo kmp -j REJECT
-A INPUT -m string --string "announce.php?passkey=" --algo kmp -j REJECT
-A INPUT -m string --string "find_node" --algo kmp -j REJECT
-A INPUT -m string --string "info_hash" --algo kmp -j REJECT
-A INPUT -m string --string "get_peers" --algo kmp -j REJECT
-A FORWARD -m string --algo bm --string "BitTorrent" -j REJECT
-A FORWARD -m string --algo bm --string "BitTorrent protocol" -j REJECT
-A FORWARD -m string --algo bm --string "peer_id=" -j REJECT
-A FORWARD -m string --algo bm --string ".torrent" -j REJECT
-A FORWARD -m string --algo bm --string "announce.php?passkey=" -j REJECT
-A FORWARD -m string --algo bm --string "torrent" -j REJECT
-A FORWARD -m string --algo bm --string "info_hash" -j REJECT
-A FORWARD -m string --algo bm --string "/default.ida?" -j REJECT
-A FORWARD -m string --algo bm --string ".exe?/c+dir" -j REJECT
-A FORWARD -m string --algo bm --string ".exe?/c_tftp" -j REJECT
-A FORWARD -m string --string "peer_id" --algo kmp -j REJECT
-A FORWARD -m string --string "BitTorrent" --algo kmp -j REJECT
-A FORWARD -m string --string "BitTorrent protocol" --algo kmp -j REJECT
-A FORWARD -m string --string "bittorrent-announce" --algo kmp -j REJECT
-A FORWARD -m string --string "announce.php?passkey=" --algo kmp -j REJECT
-A FORWARD -m string --string "find_node" --algo kmp -j REJECT
-A FORWARD -m string --string "info_hash" --algo kmp -j REJECT
-A FORWARD -m string --string "get_peers" --algo kmp -j REJECT
-A OUTPUT -m string --algo bm --string "BitTorrent" -j REJECT
-A OUTPUT -m string --algo bm --string "BitTorrent protocol" -j REJECT
-A OUTPUT -m string --algo bm --string "peer_id=" -j REJECT
-A OUTPUT -m string --algo bm --string ".torrent" -j REJECT
-A OUTPUT -m string --algo bm --string "announce.php?passkey=" -j REJECT
-A OUTPUT -m string --algo bm --string "torrent" -j REJECT
-A OUTPUT -m string --algo bm --string "info_hash" -j REJECT
-A OUTPUT -m string --algo bm --string "/default.ida?" -j REJECT
-A OUTPUT -m string --algo bm --string ".exe?/c+dir" -j REJECT
-A OUTPUT -m string --algo bm --string ".exe?/c_tftp" -j REJECT
-A OUTPUT -m string --string "peer_id" --algo kmp -j REJECT
-A OUTPUT -m string --string "BitTorrent" --algo kmp -j REJECT
-A OUTPUT -m string --string "BitTorrent protocol" --algo kmp -j REJECT
-A OUTPUT -m string --string "bittorrent-announce" --algo kmp -j REJECT
-A OUTPUT -m string --string "announce.php?passkey=" --algo kmp -j REJECT
-A OUTPUT -m string --string "find_node" --algo kmp -j REJECT
-A OUTPUT -m string --string "info_hash" --algo kmp -j REJECT
-A OUTPUT -m string --string "get_peers" --algo kmp -j REJECT
-A INPUT -p tcp --dport 25 -j REJECT   
-A FORWARD -p tcp --dport 25 -j REJECT 
-A OUTPUT -p tcp --dport 25 -j REJECT 
-N port-scanning 
-A port-scanning -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j RETURN 
-A fail2ban-ssh -j RETURN
COMMIT
*raw
:PREROUTING ACCEPT [158575:227800758]
:OUTPUT ACCEPT [46145:2312668]
COMMIT
*mangle
:PREROUTING ACCEPT [158575:227800758]
:INPUT ACCEPT [158575:227800758]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [46145:2312668]
:POSTROUTING ACCEPT [46145:2312668]
COMMIT
END
sed -i '$ i\iptables-restore < /etc/iptables.up.rules' /etc/rc.local
sed -i $MYIP2 /etc/iptables.up.rules;
iptables-restore < /etc/iptables.up.rules


# download script
cd
sed -i '$ i\screen -AmdS limit /root/limit.sh' /etc/rc.local
sed -i '$ i\screen -AmdS ban /root/ban.sh' /etc/rc.local
sed -i '$ i\screen -AmdS limit /root/limit.sh' /etc/rc.local
sed -i '$ i\screen -AmdS ban /root/ban.sh' /etc/rc.local
echo "0 0 * * * root /usr/local/bin/user-expire" > /etc/cron.d/user-expire
echo "0 0 * * * root /usr/local/bin/user-expire-pptp" > /etc/cron.d/user-expire-pptp

cat > /root/ban.sh <<END3
#!/bin/bash
#/usr/local/bin/user-ban
END3

cat > /root/limit.sh <<END3
#!/bin/bash
#/usr/local/bin/user-limit
END3

ed -i '$ i\screen -AmdS limit /root/limit.sh' /etc/rc.local
sed -i '$ i\screen -AmdS ban /root/ban.sh' /etc/rc.local
sed -i '$ i\screen -AmdS limit /root/limit.sh' /etc/rc.d/rc.local
sed -i '$ i\screen -AmdS ban /root/ban.sh' /etc/rc.d/rc.local
echo "0 0 * * * root /usr/local/bin/user-expire" > /etc/cron.d/user-expire
echo "0 0 * * * root /usr/local/bin/user-expire-pptp" > /etc/cron.d/user-expire-pptp

cat > /root/ban.sh <<END3
#!/bin/bash
#/usr/local/bin/user-ban
END3

cat > /root/limit.sh <<END3
#!/bin/bash
#/usr/local/bin/user-limit
END3

cd /usr/local/bin
wget -O premium-script.tar.gz "https://raw.githubusercontent.com/ZENON-VPN/autoscript/master/updates/premium-script.tar.gz"
tar -xvf premium-script.tar.gz
rm -f premium-script.tar.gz

cp /usr/local/bin/premium-script /usr/local/bin/menu

chmod +x /usr/local/bin/trial
chmod +x /usr/local/bin/user-add
chmod +x /usr/local/bin/user-aktif
chmod +x /usr/local/bin/user-ban
chmod +x /usr/local/bin/user-delete
chmod +x /usr/local/bin/user-detail
chmod +x /usr/local/bin/user-expire
chmod +x /usr/local/bin/user-limit
chmod +x /usr/local/bin/user-lock
chmod +x /usr/local/bin/user-login
chmod +x /usr/local/bin/user-unban
chmod +x /usr/local/bin/user-unlock
chmod +x /usr/local/bin/user-password
chmod +x /usr/local/bin/user-log
chmod +x /usr/local/bin/user-add-pptp
chmod +x /usr/local/bin/user-delete-pptp
chmod +x /usr/local/bin/alluser-pptp
chmod +x /usr/local/bin/user-login-pptp
chmod +x /usr/local/bin/user-expire-pptp
chmod +x /usr/local/bin/user-detail-pptp
chmod +x /usr/local/bin/bench-network
chmod +x /usr/local/bin/speedtest
chmod +x /usr/local/bin/ram
chmod +x /usr/local/bin/log-limit
chmod +x /usr/local/bin/log-ban
chmod +x /usr/local/bin/user-generate
chmod +x /usr/local/bin/user-list
chmod +x /usr/local/bin/diagnosa
chmod +x /usr/local/bin/premium-script
chmod +x /usr/local/bin/user-delete-expired
chmod +x /usr/local/bin/auto-reboot
chmod +x /usr/local/bin/log-install
chmod +x /usr/local/bin/menu
chmod +x /usr/local/bin/user-auto-limit
chmod +x /usr/local/bin/user-auto-limit-script
chmod +x /usr/local/bin/edit-port
chmod +x /usr/local/bin/edit-port-squid
chmod +x /usr/local/bin/edit-port-openvpn
chmod +x /usr/local/bin/edit-port-openssh
chmod +x /usr/local/bin/edit-port-dropbear
chmod +x /usr/local/bin/autokill
chmod +x /root/limit.sh
chmod +x /root/ban.sh
screen -AmdS limit /root/limit.sh
screen -AmdS ban /root/ban.sh
clear
cd
echo " "
echo " "
echo "Premium Script Successfully Update!"
echo "AutoScriptVPS By AzRoY"
echo " "
echo " "

# finalizing
apt-get -y autoremove
chown -R www-data:www-data /home/vps/public_html
service nginx start
service vnstat restart
service openvpn restart
service snmpd restart
service ssh restart
service dropbear restart
service fail2ban restart
service squid restart
service webmin restart
service pptpd restart
sysv-rc-conf rc.local on
cd
#clearing history
history -c

# info
clear
echo " "
echo "Installation has been completed!!"
echo " "
echo "--------------------------- Configuration Setup Server -------------------------"
echo "                                Copyright AzRoY                                 "
echo "                              https://t.me/VPNBYAZROY                           "
echo "                 Created By AzRoY(Telegram : https://t.me/VPNBYAZROY)           "
echo "                                Modified by : AzRoY                             "
echo "--------------------------------------------------------------------------------"
echo ""  | tee -a log-install.txt
echo "Server Information"  | tee -a log-install.txt
echo "   - Timezone    : Asia/Kuala_Lumpur (GMT +8)"  | tee -a log-install.txt
echo "   - Fail2Ban    : [ON]"  | tee -a log-install.txt
echo "   - Dflate      : [ON]"  | tee -a log-install.txt
echo "   - IPtables    : [ON]"  | tee -a log-install.txt
echo "   - Torrent     : [ON]"	| tee -a log-install.txt
echo "   - Auto-Reboot : [OFF]"  | tee -a log-install.txt
echo "   - IPv6        : [OFF]"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "Application & Port Information"  | tee -a log-install.txt
echo "   - OpenVPN     : TCP 1194 "  | tee -a log-install.txt
echo "   - OpenSSH     : 22, 443"  | tee -a log-install.txt
echo "   - Stunnel4    : 443"  | tee -a log-install.txt
echo "   - Dropbear    : 109, 110, 442"  | tee -a log-install.txt
echo "   - Squid Proxy : 80, 3128, 8000, 8080 (limit to IP Server)"  | tee -a log-install.txt
echo "   - Badvpn      : 7300"  | tee -a log-install.txt
echo "   - Nginx       : 80"  | tee -a log-install.txt
echo "   - PPTP VPN    : 1732"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "Server Tools"  | tee -a log-install.txt
echo "   - htop"  | tee -a log-install.txt
echo "   - iftop"  | tee -a log-install.txt
echo "   - mtr"  | tee -a log-install.txt
echo "   - nethogs"  | tee -a log-install.txt
echo "   - screenfetch"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "Premium Script Information"  | tee -a log-install.txt
echo "   To display list of commands: menu"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "   Explanation of scripts and VPS setup" | tee -a log-install.txt
echo "   follow this link: https://t.me/VPNBYAZROY"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "Important Information"  | tee -a log-install.txt
echo "   - Download Config OpenVPN : http://$MYIP/client.ovpn"  | tee -a log-install.txt
echo "     Mirror (*.tar.gz)       : http://$MYIP/openvpn.tar.gz"  | tee -a log-install.txt
echo "   - Webmin                  : http://$MYIP:10000/"  | tee -a log-install.txt
echo "   - Vnstat                  : http://$MYIP/vnstat/"  | tee -a log-install.txt
echo "   - MRTG                    : http://$MYIP/mrtg/"  | tee -a log-install.txt
echo "   - Installation Log        : cat /root/log-install.txt"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "----------- Script Created By AzRoY(Telegram : @AzRoY369) ------------"
echo "-------------------- Modified by FB : AzRoY -------------------"

