#!/usr/bin/python
"""Basic passive OS Fingerprinting - because OS detection matters

Requires scapy and mysqlconnector. To capture traffic on multiple interfaces scapy 2.3.3 or higher is
required. osfingerprinting.py captures traffic such as DHCP traffic, TCP SYN or SYN/ACK and optionally updates
your NeDi database (https://www.nedi.ch/) or NetOps database.

Some code and ideas for TCP fingerprinting has been taken from Satori and p0f. It is not as accurate as the DHCP
method and could be improved.

Requires:
pip3 install mysql-connector-python
pip3 install scapy

Other sources:
* https://www.giac.org/paper/gsec/8496/os-application-fingerprinting-techniques/113048
"""
__author__    = "dumplab"
__copyright__ = "2021 dumplab"
__license__   = "MIT"
__version__   = "1.0"

from scapy.all import *
import mysql.connector as mariadb
import re
import sys
import time

# default capture settings
captureInterface   = ["ens1f5"] # nic
#captureInterface   = ["enp7s0","enp6s0","enp13s0f1"] # if you have multiple nics
captureFilter      = "(tcp[13]==0x02) or (tcp[13]==0x12) or udp port 67" # example filter to start, TCP SYN&SYN/ACK and UDP 67
# other examples
#captureFilter      = "((tcp[13]==0x02) or (tcp[13]==0x12) or udp port 67) and net 172.27.32.0/24" # example filter for specific network, TCP SYN&SYN/ACK and UDP 67
# other capture example for a specific endpoint
#captureFilter      = "((tcp[13]==0x02) or (tcp[13]==0x12) or udp port 67) and host 172.20.20.17"

# enable or disable fingerprint methods
tcpFingerprinting  = True
dhcpFingerprinting = True
# Write OS to NeDi Database
nedienabled        = False           # set this to true if you want to update NeDi nodes
nedihost           = "nedi.acme"     # NeDi DB host
nediuser           = "nedi"          # NeDi DB user
nedipassword       = "password"      # NeDi DB password
nedidatabase       = "nedi"          # NeDi DB name
# Write OS to NetOps Database
netopsenabled      = False           # set this to true if you want to update NetOps
netopshost         = "netops.acme"   # NetOps DB host
netopsuser         = "netops"        # NetOps DB user
netopspassword     = "password"      # NetOps DB password
netopsdatabase     = "netops"        # NetOps DB name
# Flow settings
flowsmaxqueue      = 5000            # number of dhcp transactions or flows in queue before we print or save into db
flowsmaxtime       = 5               # OR seconds we wait between saving queue into db or output
debug              = False           # debug or verbose output
# internals do not change
timer              = int(time.time())
cursornedi         = None    # nedi database
cursornetops       = None    # netops database
flows              = []      # list

class cFlowRecord(object):
	def __init__(self,module=0,txid=0,mac="",ip="",relayagentip="",leasetime=0,lastdhcpack=0,dhcpfingerprint="",dhcpvendor="",deviceclass="",hostname="",hostos="",tcpsignature=0,internalts=0):
		"""Set default attribute values only

		Keyword arguments:
		module -- 0=dhcp 1=tcp will be extended in future
		txid -- transaction id (mandatory integer)
		mac -- Client MAC address (default "")
		ip -- client ip address (default "")
		relayagentip -- ip of relay agent (default "")
		leasetime -- submited leasetime (default 0)
		lastdhcpack -- last timestamp of dhcp ack (default 0)
		dhcpfingerprint -- dhcpfingerprint
		dhcpvendor -- dehcp vendor
		deviceclass -- this is internal only
		hostname -- hostname
		hostos -- operating system
		tcpsignature -- tcpsignature
		"""
		self.module          = module          # source module (0=dhcp,1=tcp)
		self.txid            = txid            # dhcp transcaction id
		self.mac             = mac             # dhcp mac
		self.ip              = ip	       # ipv4address
		self.relayagentip    = relayagentip    # dhcp replay
		self.leasetime       = leasetime       # dhcp leasetime
		self.lastdhcpack     = lastdhcpack     # dhcp last acknowledge
		self.dhcpfingerprint = dhcpfingerprint # dhcp fp signature
		self.dhcpvendor      = dhcpvendor      # dhcp vendor
		self.deviceclass     = deviceclass     # dhcp device class
		self.hostname        = hostname        # dhcp hostname
		self.hostos          = hostos          # operating system
		self.tcpsignature    = tcpsignature    # tcp fp signature
		self.internalts      = internalts      # an internal timestamp to delete obsolete requests without an reply or timer expired

	def printFlow(self):
		"""output human readable string on one line
		"""
		dc = ";" # delimiter char to use
		# dhcp
		if self.module==0:
			outString = dc + "os=" + self.hostos + dc + "ip=" + self.ip + dc + "mac=" + self.mac + dc + "signature=" + self.dhcpfingerprint
			print("module=dhcp" + outString)
			return
		# tcp
		if self.module==1:
			outString = dc + "os=" + self.hostos + dc + "ip=" + self.ip + dc + "mac=" + self.mac + dc + "signature=" + self.tcpsignature
			print("module=tcp" + outString)
			return

# DHCP opt55 database
dhcpfpDB = {
	'1,33,3,6,15,26,28,51,58,59':                              ['Android OS'],
	'1,3,6,15,26,28,51,58,59,43,66,150':                       ['Android OS'],
	'1,121,33,3,6,28,51,58,59':                                ['Android 2.2'],
	'1,121,33,3,6,15,28,51,58,59,119':                         ['Android 2.3'],
	'1,33,3,6,15,28,51,58,59':                                 ['Android 4.1'],
	'1,3,6,15,26,28,51,58,59,43':                              ['Android 7.x or 8.0'],
	'1,3,6,15,26,28,51,58,59,43,114':                          ['Android 10.x'],
	'1,2,3,15,6,12,44':                                        ['Apple Airport'],
	'1,28,3,6,15':                                             ['Apple Airport'],
	'28,3,6,15':                                               ['Apple Airport'],
	'1,3,6,15,119,78,79,95,252' :                              ['Apple iOS'],
	'1,3,6,15,119,252' :                                       ['Apple iOS'],
	'1,3,6,15,119,252,46,208,92' :                             ['Apple iOS'],
	'1,3,6,15,119,252,67,52,13' :                              ['Apple iOS'],
	'1,121,3,6,15,119,252' :                                   ['Apple iOS'],
	'1,121,3,6,15,114,119,252' :                               ['Apple iOS'],
	'1,3,6,15,112,113,78,79,95' :                              ['Apple macOS'],
	'1,3,6,15,112,113,78,79,95,252' :                          ['Apple macOS'],
	'3,6,15,112,113,78,79,95,252' :                            ['Apple macOS'],
	'3,6,15,112,113,78,79,95' :                                ['Apple macOS'],
	'3,6,15,112,113,78,79,95,44,47' :                          ['Apple macOS'],
	'1,3,6,15,112,113,78,79,95,44,47' :                        ['Apple macOS'],
	'1,3,6,15,112,113,78,79' :                                 ['Apple macOS'],
	'1,3,6,15,119,95,252,44,46,101' :                          ['Apple macOS'],
	'1,3,6,15,119,112,113,78,79,95,252' :                      ['Apple macOS'],
	'3,6,15,112,113,78,79,95,252,44,47' :                      ['Apple macOS'],
	'1,3,6,15,112,113,78,79,95,252,44,47' :                    ['Apple macOS'],
	'1,3,12,6,15,112,113,78,79' :                              ['Apple macOS'],
	'1,121,3,6,15,119,252,95,44,46' :                          ['Apple macOS'],
	'60,43' :                                                  ['Apple macOS'],
	'43,60' :                                                  ['Apple macOS'],
	'1,3,6,15,119,95,252,44,46,47' :                           ['Apple macOS'],
	'1,3,6,15,119,95,252,44,46,47,101' :                       ['Apple macOS'],
	'1,121,3,6,15,114,119,252,95,44,46' :                      ['Apple macOS 11'],
	'1,33,3,6,15,28,51,58,59' :                                ['Chrome OS'],
	'1,66,6,3,15,150,35' :                                     ['Cisco IP Phone'],
	'1,3,6,12,15,28,40,41,42' :                                ['Crestron Home OS'],
	'91,49,44,32,50,56,44,32,50,44,32,51,44,32,49,53,44,32,54,44,32,49,49,57,44,32,49,50,44,32,52,52,44,32,52,55,44,32,50,54,44,32,49,50,49,44,32,52,50,93' : ['Debian Linux'],
	'1,28,2,121,15,6,12,40,41,42,26,119,3,121,249,33,252,42,17':['Fedora Linux'],
	'1,28,2,121,3,15,6,12,119,26' :                            ['FreeBSD'],
	'1,3,6,15' :                                               ['Generic IOT'],
	'1,28,2,121,15,6,12,40,41,42,26,119,3,121,249,33,252,42' : ['Generic Linux'],
	'1,121,33,3,6,12,15,28,42,51,54,58,59,119' :               ['Generic Linux'],
	'3,6,12,15,17,23,28,29,31,33,40,41,42,119' :               ['Generic Linux'],
	'1,3,6,12,15,23,28,29,31,33,40,41,42' :                    ['Generic Linux'],
	'3,6,12,15,17,23,28,29,31,33,40,41,42,9,7,200,44' :        ['Generic Linux'],
	'1,3,6,12,15,23,28,29,31,33,40,41,42,9,7,200,44' :         ['Generic Linux'],
	'1,28,2,3,15,6,12,121,249,252,42' :                        ['Generic Linux'],
	'1,121,33,3,6,12,15,26,28,42,51,54,58,59,119' :            ['Generic Linux'],
	'1,2,6,12,15,26,28,121,3,33,40,41,42,119,249,252,17' :     ['Generic Linux'],
	'1,28,2,3,15,6,119,12,17,26,121,121,249,33,252,42' :       ['Generic Linux'],
	'1,3,6,15,44,46,47' :                                      ['Generic Linux'],
	'1,3,6,51,54,58,59,12,15' :                                ['Generic Linux or VxWorks'],
	'1,6,3,66,67,15' :                                         ['Generic Linux or VxWorks'],
	'1,3,6,51,58,59' :                                         ['Generic Linux or VxWorks'],
	'1,121,33,3,6,12,15,26,28,51,54,58,59,119' :               ['Raspberry PI Linux or Chrome OS'],
	'1,3,12,15,6,26,33,121,119,42,120' :                       ['Raspberry PI Linux or Chrome OS'],
	'1,28,2,3,15,6,12' :                                       ['Generic Linux Synology'],
	'1,3,6,12,15,17,23,28,29,31,33,40,41,42,44' :              ['Generic Linux Synology'],
	'1,3,28,6' :                                               ['Generic Linux DPC'],
	'1,2,3,4,6,15,28,33,42,43,44,58,59,100,101' :              ['HP iLO Agent'],
	'1,3,42,4,6,12,15,26,44,51,54,58,59,190' :                 ['Lexmark Printer OS'],
	'1,28,2,3,15,6,119,12,44,47,26,121,42,249,33,252,17' :     ['Linux Ubuntu'],
	'1,15,3,6,44,46,47,31,33,249,43' :                         ['Microsoft Windows XP'],
	'1,15,3,6,44,46,47,31,33,249,43,252' :                     ['Microsoft Windows XP'],
	'1,15,3,6,44,46,47,31,33,249,43,252,12' :                  ['Microsoft Windows XP'],
	'15,3,6,44,46,47,31,33,249,43' :                           ['Microsoft Windows XP'],
	'15,3,6,44,46,47,31,33,249,43,252' :                       ['Microsoft Windows XP'],
	'15,3,6,44,46,47,31,33,249,43,252,12' :                    ['Microsoft Windows XP'],
	'28,2,3,15,6,12,44,47' :                                   ['Microsoft Windows XP'],
	'1,15,3,6,44,46,47,31,33,121,249,43,252' :                 ['Microsoft Windows 7'],
	'1,15,3,6,44,46,47,31,33,121,249,43' :                     ['Microsoft Windows 7'],
	'1,15,3,6,44,46,47,31,33,121,249,43,0,32,176,67' :         ['Microsoft Windows 7'],
	'1,15,3,6,44,46,47,31,33,121,249,43,0,176,67' :            ['Microsoft Windows 7'],
	'1,15,3,6,44,46,47,31,33,121,249,43,252' :                 ['Microsoft Windows 7'],
	'1,15,3,6,44,46,47,31,33,121,249,43,195' :                 ['Microsoft Windows 7'],
	'1,15,3,6,44,46,47,31,33,121,249,43,0,112,64' :            ['Microsoft Windows 7'],
	'1,15,3,6,44,46,47,31,33,121,249,43,0,128,64' :            ['Microsoft Windows 7'],
	'1,15,3,6,44,46,47,31,33,121,249,43,0,168,112,64]' :       ['Microsoft Windows 7'],
	'1,15,3,6,44,46,47,31,33,121,249,43,0,188,67' :            ['Microsoft Windows 7'],
	'1,15,3,6,44,46,47,31,33,121,249,43,0,64,112' :            ['Microsoft Windows 7'],
	'1,3,6,15,31,33,43,44,46,47,121,249,252' :                 ['Microsoft Windows 10'],
	'1,3,6,15,31,33,43,44,46,47,119,121,249,252' :             ['Microsoft Windows 10 SAC 1909'],
	'1,15,3,6,44,46,47,31,33,43' :                             ['Microsoft Windows 2000'],
	'1,15,3,6,44,46,47,31,33,43,252' :                         ['Microsoft Windows 2000'],
	'1,15,3,6,44,46,47,31,33,43,252,12' :                      ['Microsoft Windows 2000'],
	'15,3,6,44,46,47,31,33,43' :                               ['Microsoft Windows 2000'],
	'15,3,6,44,46,47,31,33,43,252' :                           ['Microsoft Windows 2000'],
	'1,15,3,6,44,46,47,31,33,43,77' :                          ['Microsoft Windows ME'],
	'15,3,6,44,46,47,31,33,43,77' :                            ['Microsoft Windows ME'],
	'1,3,6,15,44,46,47,57' :                                   ['Microsoft Windows 98'],
	'15,3,6,44,46,47,43,77' :                                  ['Microsoft Windows 98SE'],
	'1,15,3,6,44,46,47,43,77' :                                ['Microsoft Windows 98SE'],
	'15,3,6,44,46,47,43,77,252' :                              ['Microsoft Windows 98SE'],
	'1,15,3,6,44,46,47,43,77,252' :                            ['Microsoft Windows 98SE'],
	'1,3,15,6,44,46,47' :                                      ['Microsoft Windows 95'],
	'1,2,3,6,12,15,26,28,85,86,87,88,44,45,46,47,70,69,78,79' :['Microsoft Windows NT 4'],
	'1,15,3,44,46,47,6' :                                      ['Microsoft Windows NT 4'],
	'1,3,6,12,15,28,42':                                       ['MOXA GPIB or similar Embedded Linux'],
	'1,3,6,12,15,17,23,28,29,31,33,40,41,42':                  ['MOXA GPIB or similar Embedded Linux'],
	'1,3,6,12,15,42,43,50,51,53,54,56,57,58,59' :              ['NetApp ONTAP'],
	'1,28,2,3,15,6,119,12,44,47,26,121,42':                    ['PowerBrick LV IMS Embedded Linux'],
	'1,28,2,3,15,6,12,40,41,42' :                              ['RedHat or Fedora Linux'],
	'28,2,3,15,6,12,40,41,42' :                                ['RedHat or Fedora Linux'],
	'1,28,2,3,15,6,12,40,41,42,26,119' :                       ['RedHat or Fedora Linux'],
	'1,28,2,3,15,6,12,40,41,42,26' :                           ['RedHat or Fedora Linux'],
	'1,28,2,121,15,6,12,40,41,42,26,119,3' :                   ['RedHat or CentOS Linux'],
	'1,28,2,121,15,6,12,40,41,42,26,119,3,121,249,42' :        ['RedHat or CentOS Linux'],
	'1,28,2,121,15,6,12,40,41,42,26,119,3,121,249,33,42' :     ['Scientific Linux'],
	'1,28,2,3,15,6,119,12,44,47,26,121,42,121,249,33,252,42' : ['Debian or Kali Linux'],
	'53,54,1,51,52,3,6,31' :                                   ['VxWorks'],
	'12,1,3,33,28,6,15,4,2' :                                  ['VxWorks'],
}

# TCP signatures
tcpfpDB = {
	'SA:29200:64:0:13:M1460,N,N,S,N,W5:ZDA':                   ['Axis Cam'],
	'S:65535:64:1:60:M1460,S,T,N,W7:.':                        ['Android 7.0'],
	'S:65535:64:1:60:M1460,S,T,N,W8:.':                        ['Android 8.0'],
	'S:65535:64:0:15:M1460,S,T,N,W8:D':                        ['Android'],
	'S:65535:60:0:15:M1460,S,T,N,W8:D':                        ['Android'],
	'S:65535:64:0:15:M1360,S,T,N,W6:D':                        ['Huawei Android'],
	'A:32806:64:1:52:N,N,T:.':                                 ['Apple iOS'],
	'S:65535:64:0:16:M1460,N,W6,N,N,T,S,E:ZD':                 ['Apple macOS or iOS'],
	'S:65535:64:0:18:M1460,N,W6,N,N,T,S:ZD':                   ['Apple macOS'],
	'S:65535:64:0:75:M1460,N,W6,N,N,T,S,E':                    ['Apple macOS'],
	'S:65535:64:1:60:M1460,N,W2,N,N,T:.':                      ['Apple macOS'],
	'S:65535:64:0:16:M1460,N,W5,N,N,T,S,E:ZD':                 ['Apple macOS'],
	'SA:8688:64:0:15:M1460,N,W0,N,N,T:DAT':                    ['Epson NetConfig PrintOS'],
	'SA:13032:64:0:16:M1460,N,W0,N,N,S,N,N,T:DAT':             ['iLO OS'],
	'SA:14480:64:0:15:M1460,S,T,N,W0:ZDAT':                    ['Konica Minolta PrintOS'],
	'SA:31856:64:1:60:M1460,S,T,N,W0:ZAT':                     ['Linux 2.4'],
	'SA:16060:64:1:60:M1460,S,T,N,W0:AT':                      ['Linux 2.4'],
	'SA:5840:64:1:52:M1460,N,N,S,N,W0:ZA':                     ['Linux 2.4'],
	'SA:5840:64:1:48:M1460,N,N,S:ZA':                          ['Linux 2.4'],
	'SA:14600:64:1:52:M1380,N,N,S,N,W7:ZA':                    ['Linux 3.10.'],
	'A:32374:128:1:52:N,N,K:.':                                ['Microsoft Windows XP'],
	'A:32367:128:1:52:N,N,K:.':                                ['Microsoft Windows XP'],
	'S:65535:64:0:12:M1460,N,N,S:D':                           ['Microsoft Windows XP'],
#	'S:8192:128:0:13:M1260,N,W8,N,N,S:D':                      ['Microsoft Windows 7'],
#	'S:8192:128:0:13:M1460,N,W8,N,N,S:D':                      ['Microsoft Windows 7'], duplicate with win 10 see below
#	'SA:8192:128:0:13:M1460,N,W8,N,N,S:DA':                    ['Microsoft Windows 7 or server 2008'], # does not reflect reality, sometimes is server 2016
#	'S:65535:128:0:13:M1460,N,W3,N,N,S:D':                     ['Microsoft Windows 10'],
#	'S:8192:128:0:13:M1460,N,W8,N,N,S:D':                      ['Microsoft Windows 10'],
#	'S:8192:125:0:60:M1460,N,W8,N,N,S':                        ['Microsoft Windows 10'],
#	'S:64240:128:1:48:M1460,N,N,S:T':                          ['Microsoft Windows 10'],
#	'S:8192:128:0:60:M1460,N,W8,N,N,S':                        ['Microsoft Windows 10'],
#	'SA:60720:128:0:60:M1380,N,N,S,N,W8':                      ['Microsoft Windows 10'],
	'S:64240:128:0:13:M1460,N,W8,N,N,S:D':                     ['Microsoft Windows 10'],
	'SA:8192:128:0:15:M1460,N,W8,S,T:DAT':                     ['Microsoft Windows Server 20xx'],
	'SA:14480:64:0:15:M1460,S,T,N,W2:ZDAT':                    ['MOXA GPIB or similar Embedded Linux'],
	'SA:5792:64:0:15:M1460,S,T,N,W2:ZDAT':                     ['MOXA Embedded Linux'],
	'S:65228:64:0:15:M1460,N,W7,S,T:ZD':                       ['pfSense FreeBSD'],
	'SA:14480:64:0:15:M1460,S,T,N,W3:ZDAT':                    ['PowerBrick LV IMS Embedded Linux'],
	'S:29200:64:1:60:M1460,S,T,N,W7:.':                        ['Ubuntu Linux'],
	'SA:33304:64:0:16:M1460,N,W0,N,N,S,N,N,T:DAT':             ['RTOS Linux - closed embedded Realtime Tektronix'],
	'S:14600:64:0:15:M1460,S,T,N,W7:D':                        ['Scientific Linux'],
	'S:14600:60:0:15:M1460,S,T,N,W7:D':                        ['Scientific Linux'],
	'SA:14600:64:0:13:M1460,N,N,S,N,W7:ZDA':                   ['Scientific Linux'],
	'SA:14480:64:0:15:M1460,S,T,N,W7:ZDAT':                    ['Scientific Linux'],
	'SA:4096:30:0:44:M1460:':                                  ['Siemens SIMATIC S7'],
	'SA:8192:30:0:44:M1460:.':                                 ['Siemens SIMATIC S7'],
	'S:29200:64:0:15:M1460,S,T,N,W7:D':                        ['RedHat,Raspbian or Fedora Linux'],
	'S:29200:60:0:13:M1460,N,N,S,N,W7:D':                      ['RedHat or Fedora Linux'],
	'SA:28960:64:0:15:M1460,S,T,N,W7:ZDAT':                    ['RedHat or Fedora Linux'],
	'SA:4096:30:0:44:M1460:.':                                 ['Siemens SIMATIC S7'],
	'SA:8192:30:0:44:M1460:.':                                 ['Siemens SIMATIC S7'],
	'S:8192:128:0:12:M1454,N,N,S:D':                           ['Siemens SIMATIC S7'],
	'SA:4096:32:0:11:M1460:DA':                                ['VxWorks RTOS'],
	'SA:60000:64:0:12:M1460,N,W0:DA':                          ['VxWorks RTOS'],
	'SA:16000:64:0:11:M1460:DA':                               ['WAGO Embedded Linux'],
	'SA:16000:128:0:11:M1460:DA':                              ['WAGO Embedded Linux'],
	'SA:16000:64:0:11:M1460:DA':                               ['WAGO Embedded Linux'],
}

# callback function to process packets
def procpackets(pkt):
	global flows
	global timer
	global cursornedi
	global cursornetops

	# *****************************************
	# * process packets                       *
	# *****************************************
	if pkt.haslayer(TCP):
		# tcp module
		if tcpFingerprinting:
			proctcp(pkt)

	if pkt.haslayer(UDP):
		# possible DHCP request or response
		if dhcpFingerprinting:
			procdhcp(pkt)

	# *****************************************
	# * process queue, print and update db    *
	# *****************************************
	if (len(flows) >= flowsmaxqueue or (timer+flowsmaxtime < int(time.time()))): # timer expired or len of list exceeded
		if debug:
			print("procpackets::processing flows queue .... " + str(len(flows)) + " objects")
		# timer to measure the time we need to flush the queue to the database
		mm = time.time()
		for myRequest in flows:
			release = False
			# TCP
			if myRequest.module==1:
				release = True

			# DHCP
			if myRequest.module==0:
				# see if the ACK timestamp was updated, indicates there was a successfully transaction
				if myRequest.lastdhcpack>0:
					if debug:
						print("procdhcp::release txid " + str(myRequest.txid))
					release = True
				else:
					if myRequest.internalts+5 < int(time.time()):
						if debug:
							print("procdhcp::release txid " + str(myRequest.txid)+ " no answer within 5s")
						flows.remove(myRequest)
						del myRequest
					else:
						if debug:
							print("procdhcp::txid " + str(myRequest.txid) + " not released no answer so far")

			if release==True:
				# print our flow
				myRequest.printFlow()
				# netops check if we already know this MAC (primary key)
				if netopsenabled:
					# DHCP Fingerprint
					if myRequest.module==0:
						# ip clean up, we delete entries with the same ip but different mac
						rows = []
						cursornetops.execute("SELECT mac FROM networknodes WHERE ipv4address = INET_ATON('" + myRequest.ip + "')")
						rows = cursornetops.fetchall()
						if rows:
							# insert
							delMac = []
							nDel = False
							for host in rows:
								if host[0]!=myRequest.mac:
									nDel = True
									delMac.append("DELETE FROM networknodes WHERE mac = '" + host[0] + "'")
							if nDel:
								if debug:
									print("Need to delete some macs")
								for q in delMac:
									if debug:
										print("Query:" + q)
									cursornetops.execute(q)
									mariadb_connection_no.commit()
						# see if it exists
						rows = []
						cursornetops.execute("SELECT mac FROM networknodes WHERE mac = '" + myRequest.mac + "'")
						rows = cursornetops.fetchall()
						if not rows:
							# insert
							if debug:
								print("mac " + myRequest.mac + " does not exist in db")
		                                        # update current record
							updateQuery = "INSERT INTO networknodes (mac,ipv4address,dhcptxid,dhcprelay,dhcpleasetime,dhcpfingerprint,dhcphostname,dhcplastdhcpack,os,lastupdate,lastupdateby,created,device) VALUES ("
							updateQuery += "'" + myRequest.mac + "',"
							updateQuery += "INET_ATON('" + myRequest.ip + "'),"
							updateQuery += "'" + str(myRequest.txid) + "',"
							updateQuery += "INET_ATON('" + str(myRequest.relayagentip) + "'),"
							updateQuery += "'" + str(myRequest.leasetime) + "',"
							updateQuery += "'" + str(myRequest.dhcpfingerprint) + "',"
							updateQuery += "'" + str(myRequest.hostname) + "',"
							updateQuery += "'" + str(myRequest.lastdhcpack) + "',"
							updateQuery += "'" + str(myRequest.hostos) + "',"
							updateQuery += "'" + str(int(time.time())) + "',"
							updateQuery += "'OS Fingerprint (DHCP)',"
							updateQuery += "'" + str(int(time.time())) + "',"
							updateQuery += "'')"
							try:
								cursornetops.execute(updateQuery)
								mariadb_connection_no.commit()
							except:
								print("Error on writing to database")
								print("QUERY:" + updateQuery)
						else:
							# update	
							if debug:
								print("mac " + myRequest.mac + " exist in db, update DHCP")
		                                        # update current record
							updateQuery = "UPDATE networknodes SET "
							updateQuery += "ipv4address = INET_ATON('" + myRequest.ip + "'),"
							updateQuery += "dhcptxid = '" + str(myRequest.txid) + "',"
							updateQuery += "dhcprelay = INET_ATON('" + str(myRequest.relayagentip) + "'),"
							updateQuery += "dhcpleasetime = '" + str(myRequest.leasetime) + "',"
							updateQuery += "dhcpfingerprint = '" + str(myRequest.dhcpfingerprint) + "',"
							updateQuery += "dhcphostname = '" + str(myRequest.hostname) + "',"
							updateQuery += "dhcplastdhcpack = '" + str(myRequest.lastdhcpack) + "',"
							updateQuery += "os = '" + str(myRequest.hostos) + "',"
							updateQuery += "lastupdate = '" + str(int(time.time())) + "',"
							updateQuery += "lastupdateby = 'OS Fingerprint (DHCP)' "
							updateQuery += "WHERE mac = '" + myRequest.mac + "'"
							try:
								cursornetops.execute(updateQuery)
								mariadb_connection_no.commit()
							except:
								print("Error on writing to database")
								print("QUERY:" + updateQuery)

					# TCP Fingerprint
					if myRequest.module==1:
						rows = []
						cursornetops.execute("SELECT mac FROM networknodes WHERE ipv4address = INET_ATON('" + myRequest.ip + "')")
						rows = cursornetops.fetchall()
						if not rows:
							# insert, at the moment we do not insert as we have not enough useful data for NetOps
							if debug:
								print("IP " + myRequest.ip + " does not exist in db or DHCPFP not empty, updating TCP signature field only")
						else:
							rows = []
							cursornetops.execute("SELECT mac FROM networknodes WHERE ipv4address = INET_ATON('" + myRequest.ip + "') AND dhcpfingerprint <> ''")
							rows = cursornetops.fetchall()
							# has no DHCP information
							if not rows:
								# update
								if debug:
									print("IP " + myRequest.ip + " found in db with no DHCPFP, updating TCP signature and OS field")
			                                        # update current record
								updateQuery = "UPDATE networknodes SET "
								updateQuery += "tcpfingerprint = '" + str(myRequest.tcpsignature) + "',"
								updateQuery += "os = '" + str(myRequest.hostos) + "',"
								updateQuery += "lastupdate = '" + str(int(time.time())) + "',"
								updateQuery += "lastupdateby = 'OS Fingerprint (TCP)' "
								updateQuery += "WHERE ipv4address = INET_ATON('" + myRequest.ip + "')"
								cursornetops.execute(updateQuery)
								mariadb_connection_no.commit()
							# has already DHCP info, so we do not update on that
							else:
								if debug:
									print("IP " + myRequest.ip + " found in db but DHCPFP not empty, updating TCP signature field only")
			                                        # update current record
								updateQuery = "UPDATE networknodes SET "
								updateQuery += "tcpfingerprint = '" + str(myRequest.tcpsignature) + "',"
								updateQuery += "lastupdate = '" + str(int(time.time())) + "',"
								updateQuery += "lastupdateby = 'OS Fingerprint (TCP)' "
								updateQuery += "WHERE ipv4address = INET_ATON('" + myRequest.ip + "')"
								try:
									cursornetops.execute(updateQuery)
									mariadb_connection_no.commit()
								except:
									print("Query failed:" + q)
				# nedi update db
				if nedienabled:
					if myRequest.module==0:
						cursornedi.execute("UPDATE nodarp SET srvos='" + myRequest.hostos + "' WHERE mac='" + myRequest.mac + "'")
						try:
							mariadb_connection_ne.commit()
						except:
							print("Query failed:" + q)
					if myRequest.module==1:
						# update NeDi but using the ipv4address
						cursornedi.execute("UPDATE nodarp SET srvos='" + myRequest.hostos + "' WHERE nodip=INET_ATON('" + myRequest.ip + "') AND (srvos != '' OR srvos IS NOT NULL)")
						try:
							mariadb_connection_ne.commit()
						except:
							print("Query failed:" + q)
				# empty set returned
				flows.remove(myRequest)
				del myRequest
		# reset timer
		timer = int(time.time())
		# measurement
		xx = time.time() - mm
		if debug:
			print("procpackets::objects remaining in queue:" + str(len(flows)) + " processing queue took " + str(xx) + "s" )

# callback function process TCP
def proctcp(pkt):
	global flows
	global timer
	global cursornedi
	global cursornetops

	# ignore everything without a SYN or SYN&ACK only flag set
	if not (pkt[TCP].flags==2 or pkt[TCP].flags==18):
		return

	# init few things
	ipttl      = pkt[IP].ttl                # will be normalized later
	tcpwinsize = pkt[TCP].window
	tcpflags   = pkt.sprintf("%TCP.flags%") # not as integer but string
	ipdf       = pkt[IP].frag               #
	iphdrlen   = pkt[IP].ihl                # see detectOddities and tcpSignature
	tcphdrlen  = pkt[TCP].dataofs           # see detectOddities and tcpSignature
	tcpOpts    = pkt[TCP].options           # list of options will be parsed
	tcpOptTSR  = 0                          # see detectOddities, TCP option timestamp replyecho
	tcpOptions = str()                      # empty string will be filled later

	# read TCP options used to create signature string
	for opt in tcpOpts:
		if re.search("MSS",str(opt[0])):
			tcpOptions += "M" + str(opt[1])
		if re.search("NOP",str(opt[0])):
			tcpOptions += ",N"
		if re.search("SAckOK",str(opt[0])):
			tcpOptions += ",S"
		if re.search("WScale",str(opt[0])):
			tcpOptions += ",W" + str(opt[1])
		if re.search("Timestamp",str(opt[0])):
			tcpOptions += ",T"
			try:
				tmptcpOptTSR = opt[1]
				tcpOptTSR = tmptcpOptTSR[1] # timestamp as tuple, we need the echoreply
			except:
				tcpOptTSR = 0
		if re.search("EOL",str(opt[0])):
			tcpOptions += ",E"
	# odd value
	odd = detectOddities(pkt[IP].id,pkt[IP].len,iphdrlen,pkt[IP].version,tcphdrlen,tcpflags,pkt[TCP].ack,tcpOptions,tcpOptTSR) #, _options_er):

	# assemble tcp signature for the db lookup
	tcpSignature = tcpflags + ":" + str(tcpwinsize) + ":" + str(normalizeTTL(ipttl)) + ":" + str(ipdf) + ":" + str(iphdrlen + tcphdrlen) + ":" + tcpOptions + ":" + odd
	if debug:
		print("IP:" + pkt[IP].src + " tcpSignature:" + tcpSignature)

	# compare with TCP fingerbank
	os = tcpfpDB.get(tcpSignature,[])
	if not any(os):
		hostos = ""
		if debug:
			print("IP:" + pkt[IP].src + " has no entry in DB tcpSignature:" + tcpSignature)
	else:
		hostos = str(os[0])
		new = True
		# see if this is new
		for myRequest in flows:
			if re.search("^" + pkt[IP].src + "$",myRequest.ip): # exists already in our small list
				new = False
				# update
				if hostos!="":
					myRequest.hostos   = hostos
				if debug:
					print("proctcp::ip known already IP:" + pkt[IP].src + " tcpSignature:" + tcpSignature + " OS:" + hostos)
		# we only add if the client requested parameters
		if new==True:
			# we got a new flow, create object and add to list
			flows.append(cFlowRecord(1,"","",pkt[IP].src,"",0,0,"","","","",hostos,tcpSignature,time.time()))
			if debug:
				print("proctcp::os detected IP:" + pkt[IP].src + " tcpSignature:" + tcpSignature + " OS:" + hostos)

# callback function process DHCP
def procdhcp(pkt):
	global flows
	global timer
	global cursornedi
	global cursornetops

	opt55 = hostos = hostname = dhcpvendor = deviceclass = tcpsignature = ""
	# check for index issue
	try:
		if pkt[BOOTP].op==1:
			x = 1
	except:
		print("got issues with BOOTP dissector")
		return

	# BOOTP op 1= discover/request, 2 = reply
	if pkt[BOOTP].op==1:
#		if debug:
#			pkt.show()
		# get transaction id
		txid = int(pkt[BOOTP].xid)
		# go throupgh options
		tmpOptions = pkt[DHCP].options
		for dhcpOptions in tmpOptions:
			# looking for tuple ('param_req_list', '\x01\x0f\x03\x06,./\x1f!y\xf9+\xfc')
			if re.search("param_req_list",str(dhcpOptions)):
				params    = str(dhcpOptions[1]).encode("HEX")
				# create empty string
				opt55     = "" 
				for i in xrange(0,len(params),2):
					byte = params[i:i+2]
					# conc string, hex to int
					if i==0:
						opt55 = str(int(byte, 16))
					else:
						opt55 += "," + str(int(byte, 16))
				# compare with fingerbank
				os = dhcpfpDB.get(opt55,[])
				if not any(os):
					hostos = ""
				else:
					hostos = str(os[0])
			# looking for tuple ('hostname', 'mylinux')
			if re.search("hostname",str(dhcpOptions)):
				#get message type
				hostname = str(dhcpOptions[1])
#			if re.search("message-type",str(dhcpOptions)):
#				print("TXID:" + str(txid) + " got " + str(dhcpOptions[1]))

		# get Client hardware address
		tmpsrcMac = str(pkt[BOOTP].chaddr).encode("HEX")
		srcMac    = tmpsrcMac[:12]
		# get ip
		ip   = str(pkt[BOOTP].ciaddr)
		# get relay ip
		rip  = str(pkt[BOOTP].giaddr)
		new = True
		for myRequest in flows:
#			if re.search("^" + str(txid) + "$",str(myRequest.txid)):
			if txid==myRequest.txid:
				new = False
				# update
				myRequest.hostname = hostname
				if hostos!="":
					myRequest.hostos   = hostos
				if str(opt55)!="":
					myRequest.dhcpfingerprint = str(opt55)
		# we only add if the client requested parameters
		if new==True and opt55!="":
			# we got a dhcp transaction, create object and add to list
			flows.append(cFlowRecord(0,txid,srcMac,ip,rip,0,0,str(opt55),dhcpvendor,deviceclass,hostname,hostos,tcpsignature,time.time()))
			if debug:
				print("procdhcp::Got REQ. Added new Transaction ID " + str(txid) + " IP:" + ip + " Relay:" + rip + " MAC:" + srcMac + " Hostname: " + hostname + " Opt55:" + str(opt55))

	# BOOTP op 2 = reply
	if pkt[BOOTP].op==2:
		leasetime = 0
#		if debug:
#			pkt.show()
		# go throupgh options
		gotAck = False
		# get transaction id
		txid = int(pkt[BOOTP].xid)
		# go throupgh options
		tmpOptions = pkt[DHCP].options
		for dhcpOptions in tmpOptions:
			if re.search("message-type",str(dhcpOptions)):
				# message-type 2 = OFFER
				# message-type 5 = ACK
				# message-type 6 = NAK
				#get message type
				if dhcpOptions[1]==5:
					gotAck = True
				if dhcpOptions[1]==6:
					for myRequest in flows:
						if txid==myRequest.txid:
							if debug:
								print("procdhcp::Got NAK delete " + str(myRequest.txid))
							# delete object and clean in list
							flows.remove(myRequest)
							del myRequest
			if re.search("lease_time",str(dhcpOptions)):
				leasetime = int(dhcpOptions[1])

		# only update on ACK from DHCP Server
		if gotAck:
			# get Client hardware address
			tmpsrcMac = str(pkt[BOOTP].chaddr).encode("HEX")
			srcMac    = tmpsrcMac[:12]
			# get ip
			ip   = str(pkt[BOOTP].ciaddr)
			if re.search("^0.0.0.0$",ip):
				ip = str(pkt[BOOTP].yiaddr)
			# get relay ip
			rip  = str(pkt[BOOTP].giaddr)
			new = True
			for myRequest in flows:
				#if re.search("^" + str(txid) + "$",str(myRequest.txid)):
				if txid==myRequest.txid:
					# update
					myRequest.mac          = srcMac
					myRequest.ip           = ip
					myRequest.relayagentip = rip
					myRequest.leasetime    = leasetime
					myRequest.lastdhcpack  = int(time.time())
					if debug:
						print("procdhcp::Got ACK. Updated Transaction ID " + str(txid) + " IP:" + ip + " Relay:" + rip + " MAC:" + srcMac + " Hostname: " + myRequest.hostname + " LeaseTime: " + str(leasetime) + " Params:" + myRequest.dhcpfingerprint + " Fingerbank:" + myRequest.hostos)
			# lease time of 0 means there was no leasetime information from dhcp server request was inform

def normalizeTTL(info):
	if (info>0) and (info<=16):
		ttl = 16
	elif (info>16) and (info<=32):
		ttl = 32 
	elif (info>32) and (info<=60):
		ttl = 60 #unlikely to find many of these anymore
	elif (info>60) and (info<=64):
		ttl = 64
	elif (info>64) and (info<=128):
		ttl = 128
	elif (info>128):
		ttl = 255
	else:
		ttl = info
	return ttl

def detectOddities(_ipid, _iplen, _ip_hlen, _ip_type, _tcp_hlen, _tcp_flags, _tcp_ack, _tcp_options, _options_er):
	odd = ''
	if _tcp_options[:-1] == 'E':
		odd = odd + 'P'
	if _ipid == 0:
		odd = odd + 'Z'
	if _ip_hlen > 20:
		odd = odd + 'I'
	if _ip_type == 4:
		mylen = _iplen - _tcp_hlen - _ip_hlen
	if mylen > 0:
		odd = odd + 'D'
	if ('U' in _tcp_flags):
		odd = odd + 'U'

	if ((_tcp_flags == 'S' or _tcp_flags == 'SA')  and _tcp_ack != 0):
		odd = odd + 'A'

	if (_tcp_flags == 'S' and _options_er != 0):
		odd = odd + 'T'

	if _tcp_flags == 'SA':
		if ('T' in _tcp_options):
			odd = odd + 'T'
	temp = _tcp_flags
	temp = temp.replace('S', '')
	temp = temp.replace('A', '')
	if (temp != ''):
		odd = odd + 'F'
	if odd == '':
		odd = '.'
	return odd

print("********************************************************")
print("* Starting passive OS fingerprint                      *")
print("********************************************************")
print("* Capture interface: " + str(captureInterface))
print("* Capture filter:    " + captureFilter)
print("* DHCP FP module     " + str(dhcpFingerprinting))
print("* TCP FP module:     " + str(tcpFingerprinting))
print("* Timers DB/Output:  >" + str(flowsmaxqueue) + " in queue or every " + str(flowsmaxtime) + "s")
if nedienabled:
	try:
		mariadb_connection_ne = mariadb.connect(host=nedihost, user=nediuser, password=nedipassword, database=nedidatabase)
		cursornedi   = mariadb_connection_ne.cursor()
		print("* Update Nedi db:    " + str(nedienabled) + ",connected")
	except:
		print("* Update Nedi db:    " + str(nedienabled) + ",could not connect, check settings")
else:
		print("* Update Nedi db:    " + str(nedienabled))
if netopsenabled:
	try:
		mariadb_connection_no = mariadb.connect(host=netopshost, user=netopsuser, password=netopspassword, database=netopsdatabase)
		cursornetops = mariadb_connection_no.cursor()
		print("* Update NetOps db:  " + str(netopsenabled) + ",connected")
	except:
		print("* Update NetOps db:  " + str(netopsenabled) + ",could not connect, check settings")
else:
	print("* Update NetOps db:  " + str(netopsenabled))

print("********************************************************")
print("READY... processing packets")
print("********************************************************")
# call scapy sniff function
pkts = sniff(iface=captureInterface,filter=captureFilter, count=0 ,prn=procpackets, store=0)

if nedienabled:
	mariadb_connection_ne.close()
if netopsenabled:
	mariadb_connection_no.close()
