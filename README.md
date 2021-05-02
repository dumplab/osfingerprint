# osfingerprint
Basic passive OS Fingerprinting - because OS detection matters

osfingerprint is very simple and therefore can result in false positives.

### Prerequisites

python 3, mysqlconnector and scapy

### Installing

osfingerprint can run on any system with python.

Install packages

```
pip3 install mysql-connector-python
pip3 install scapy
alternatives --set python /usr/bin/python3
```

### Configuring osfingerprint

Edit osfingerprint.py. First enter the interface and capture filter you want osfingerprint to listen to traffic.

```
# default capture settings
captureInterface   = ["ens1f5"] # nic
captureFilter      = "(tcp[13]==0x02) or (tcp[13]==0x12) or udp port 67" # example filter to start, TCP SYN&SYN/ACK and UDP 67
```

It is possible to just listen to DHCP messages, or TCP SYN and SYN/ACKs or both.

```
# enable or disable fingerprint methods
tcpFingerprinting  = True
dhcpFingerprinting = True
```

If you intend to send OS information to NeDi, just enable it and enter your sql credentials.

```
# Write OS to NeDi Database
nedienabled        = True            # set this to true if you want to update NeDi nodes
nedihost           = "nedi.acme"     # NeDi DB host
nediuser           = "nedi"          # NeDi DB user
nedipassword       = "password"      # NeDi DB password
nedidatabase       = "nedi"          # NeDi DB name
```

done

### Running osfingerprint

python3 osfingerprint.py

Example output

```
[root@host dumplab]# python3 osfingerprint.py
********************************************************
* Starting passive OS fingerprint                      *
********************************************************
* Capture interface: ['eth0','ens1f5']
* Capture filter:    (tcp[13]==0x02) or (tcp[13]==0x12) or udp port 67
* DHCP FP module     True
* TCP FP module:     True
* Timers DB/Output:   >5000 in queue or every 5s
* Update Nedi db:    False
* Update NetOps db:  False
********************************************************
READY... processing packets
********************************************************
module=tcp;os=Microsoft Windows 10;ip=172.20.20.207;mac=;signature=S:64240:128:0:13:M1460,N,W8,N,N,S:D
module=dhcp;os=RedHat or CentOS Linux;ip=172.17.3.174;mac=00c08aaaaaa;signature=1,28,2,121,15,6,12,40,41,42,26,119,3
module=tcp;os=RedHat,Raspbian or Fedora Linux;ip=172.20.20.60;mac=;signature=S:29200:64:0:15:M1460,S,T,N,W7:D
module=dhcp;os=Android 7.x or 8.0;ip=10.65.67.212;mac=eec6196a431b;signature=1,3,6,15,26,28,51,58,59,43
module=tcp;os=Microsoft Windows 10;ip=172.20.20.207;mac=;signature=S:64240:128:0:13:M1460,N,W8,N,N,S:D
module=dhcp;os=HP iLO Agent;ip=192.168.19.227;mac=08f1e493447b;signature=1,2,3,4,6,15,28,33,42,43,44,58,59,100,101
module=dhcp;os=NetApp ONTAP;ip=192.168.19.31;mac=0080e524a7a1;signature=1,3,6,12,15,42,43,50,51,53,54,56,57,58,59
module=tcp;os=Microsoft Windows Server 20xx;ip=10.17.190.4;mac=;signature=SA:8192:128:0:15:M1460,N,W8,S,T:DAT
module=dhcp;os=Generic Linux;ip=172.20.3.155;mac=0090b82abcee;signature=1,3,6,15,44,46,47
module=dhcp;os=Microsoft Windows 10 SAC 1909;ip=10.104.240.163;mac=aafff5fdb76a;signature=1,3,6,15,31,33,43,44,46,47,119,121,249,252
module=dhcp;os=MOXA GPIB or similar Embedded Linux;ip=10.67.110.108;mac=accc8ec5ab2c;signature=1,3,6,12,15,28,42
module=dhcp;os=NetApp ONTAP;ip=192.168.1.54;mac=0080ea47431a;signature=1,3,6,12,15,42,43,50,51,53,54,56,57,58,59
module=dhcp;os=Microsoft Windows 10 SAC 1909;ip=10.30.50.93;mac=4ccc6a445566;signature=1,3,6,15,31,33,43,44,46,47,119,121,249,252
```
