from scapy.all import *
import sys


def TCPPing(host, port):
	ans,unans=sr( IP(dst=host)/TCP(dport=port,flags="S"), timeout = 1)
	ans.summary(lambda(s,r) : r.sprintf(":%IP.src% is alive"))
	return

def ICMPPing(host):
	ans,unans=sr(IP(dst=host)/ICMP(), timeout = 1)
	ans.summary(lambda (s,r): r.sprintf("%IP.src% is alive"))
	return
def UDPPing(host,port):
	ans,unans=sr( IP(dst=host)/UDP(dport=port), timeout = 1)
	ans.summary( lambda(s,r) : r.sprintf("%IP.src% is alive"))
	return

def runScan(host, port,scantype):
	if scantype == 0:
		TCPPing(host,port)
	elif scantype == 1:
		UDPPing(host,port)
	elif scantype == 2:
		ICMPPing(host)

args = sys.argv
place = 0
arglength = len(args)
host = "127.0.0.1"
port = 0
scantype = 0
while place < arglength:
	eval = args[place]
	if eval == "-H":
		place = place + 1
		host = args[place]
	elif eval =="-P":
		place = place + 1
		port = args[place]
	elif eval.lower() == "tcp":
		scantype = 0
	elif eval.lower() == "udp":
		scantype = 1
	elif eval.lower() == "icmp":
		scantype = 0

	place = place + 1

runScan(host,port, scantype)