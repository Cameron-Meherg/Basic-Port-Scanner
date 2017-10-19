from scapy.all import *
import sys
import argparse

def getHosts(file):
	hosts = []
	f = open(file)
	for word in f.read().split():
		hosts.append(word)
	return hosts

def TCPPing(host, port):
	ans,unans=sr( IP(dst=host)/TCP(dport=port,flags="S"), timeout = 1)
	ans.summary(lambda(s,r) : r.sprintf("%IP.src% %port% is up"))
	return

def ICMPPing(host):
	ans,unans=sr(IP(dst=host)/ICMP(), timeout = 1)
	ans.summary(lambda (s,r): r.sprintf("%IP.src% is alive"))
	return
def UDPPing(host,port):
	ans,unans=sr( IP(dst=host)/UDP(dport=port), timeout = 1)
	ans.summary( lambda(s,r) : r.sprintf("%IP.src% %port% is up"))
	return

def runScan(host, port,scantype):
	if scantype == 0:
		TCPPing(host,port)
	elif scantype == 1:
		UDPPing(host,port)
	elif scantype == 2:
		ICMPPing(host)
def multiScan(hostArray, port,scantype):
	for host in hostArray:
		runScan(host, port, scantype)
	return
	ping

multiplehosts = 0

parser = argparse.ArgumentParser(description='Preform simple port scanning')
parser.add_argument('-H', dest='host', help='a single host to check')
parser.add_argument('-P', dest='port', help='the port to scan')
parser.add_argument('-F', dest='filename', help='the file to load hostnames from')
parser.add_argument('-tcp', dest='scantype', action='store_const', const=0, help='send a tcp packet')
parser.add_argument('-udp', dest='scantype', action='store_const', const=1, help='send a udp packet')
parser.add_argument('-icmp', dest='scantype', action='store_const', const=2, help='send a icmp packet')


args = parser.parse_args()

hosts = []
port = 0
scantype = 0



if args.host != None:
	host = args.host

	if args.port != 'None':
		port = int(args.port)
	if args.scantype != 'None':
		scantype = args.scantype
		print 'should not be here'
	runScan(host, port,scantype)

elif args.filename != 'None':
	hosts = getHosts(args.filename)

	if args.port != None:
		port = int(args.port)
	if args.scantype != 'None':
		scantype = args.scantype
	print port
	multiScan(hosts, port, scantype) 
	


