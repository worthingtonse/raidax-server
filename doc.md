## Steps to Add RAIDAX to LegacyRAIDA


### Create root folder for RAIDAX
```
mkdir /opt/raidax
```


### Install dev tools (Debian/Ubuntu)
```
apt install git gcc libmysqlclient-dev build-essential
```


### Install dev tools (RHEL/Centos)
```
yum install gcc mariadb-devel git
```


### Clone the main repo 
```
cd /root
git clone git@gitlab.shurafom.eu:superraida/raidax.git
cd /root/raidax
```
NOTE: If you get a "don't have permission to view" run the following command to see your username and then contact Fomichev:

```
ssh -T git@gitlab.shurafom.eu
```

### Compile
```
cd /root/raidax
make
make install
```

### Install systemd service
```
cp raidax_server.service /etc/systemd/system
systemctl daemon-reload
systemctl enable raidax_server
```


### Obtain your database. Contact Alexander Miroch and tell him your RAIDA Number. Upload it to your server
```
scp -P 2222 D:\raidaXX.tar.gz your_account@your_raida.ddns.net:/home/your_account
```
Your port (-P will be different)
### Extract the database
```
cp db.tar.gz /opt/raidax
cd /opt/raidax
tar xvzf db.tar.gz
```

### Start the binary
```
systemctl start raidax_server
```

### Make sure the port is being listened. There sould be a 'LISTEN' line
```
ss -nlpt |grep raidax_server
```

### Setup the cronjob
```
cd /root/raidax
crontab -e
```

### Add this line
```
0 3 * * * /root/raidax/raidaxsync.sh
```

### Update Firewall rules (NFT version)
### !!! Your port number is 50000 + RAIDANUMBER. If you RAIDA is 8, the port number would be 50008
```
nft add rule ip filter INPUT udp dport 50008 accept comment "RAIDAXUDP"
nft add rule ip filter INPUT tcp dport 50008 accept comment "RAIDAXTCP"
nft list ruleset > /etc/sysconfig/nftables.conf
```

### Update Firewall rules (Iptables version)
NOTE: depending on your OS and firewall rules the commands below may differ. You need to figure it our yourself.
```
iptables -A INPUT -p tcp --dport 50008 -j ACCEPT
iptables -A INPUT -p udp --dport 50008 -j ACCEPT
iptables-save > /etc/sysconfig/iptables.conf
```
If there is no /etc/sysconfig/iptables.conf on your system the rules need to be saved in another file
```
iptables-save > /etc/iptables/rules.v4
```


### (Optional) Update your router configuration
Open TCP/UDP ports 50000 + RAIDANUMBER on your router to let traffic go through it


### Run this webservice to check that everything is running properly
```
https://miroch.ru/convstatus.php
```



