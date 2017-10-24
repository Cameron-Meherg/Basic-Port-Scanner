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
	ans = sr1( IP(dst=host)/TCP(sport=400,dport=port,flags="S"), timeout = 1)
	if ans != None:
		return host + ": TCP Port " + str(port) + " is up"
	elif ans == None:
		return host + ": TCP Port " + str(port) + " did not respond"

def printResultArray(results):
	for result in results:
		print result

def printMultiHostResultArray(results):
	for result in results:
		printResultArray(result)

def ICMPPing(host):
	ans =sr1(IP(dst=host)/ICMP(), timeout = 1)
	if ans != None:
		return host + " is up"
	elif ans == None:
		return host + " did not respond"

def UDPPing(host,port):
	ans =sr( IP(dst=host)/UDP(dport=port), timeout = 1)
	if ans != None:
		return host + ": UDP Port " + str(port) + " is up"
	elif ans == None:
		return host + ": UDP Port " + str(port) + " did not respond"

def runScan(host, port,scantype):
	if scantype == 0:
		return TCPPing(host,port)
	elif scantype == 1:
		return UDPPing(host,port)
	elif scantype == 2:
		return ICMPPing(host)

def runPortScan(host, ports, scantype):
	results = []
	for port in ports:
		if scantype == 0:
			results.append(TCPPing(host,port))
		elif scantype == 1:
			results.append(UDPPing(host,port))
		elif scantype == 2:
			results.append(ICMPPing(host))
	
	return results

def multiScan(hostArray, port,scantype):
	result = []
	for host in hostArray:
		result.append(runScan(host, port, scantype))
	return result
	

def multiPortScan(hostArray,ports,scantype):
	results = []
	for host in hostArray:
		results.append(runPortScan(host, ports, scantype))
	
	return results



parser = argparse.ArgumentParser(description='Preform simple port scanning')
parser.add_argument('-H', dest='host', help='a single host to check')
parser.add_argument('-P', dest='port', help='the port to scan')
parser.add_argument('-Mp', dest='ports', help='the ports to scan seperated by commas')
parser.add_argument('-F', dest='filename', help='the file to load hostnames from')
parser.add_argument('-tcp', dest='scantype', action='store_const', const=0, help='send a tcp packet')
parser.add_argument('-udp', dest='scantype', action='store_const', const=1, help='send a udp packet')
parser.add_argument('-icmp', dest='scantype', action='store_const', const=2, help='send a icmp packet')


args = parser.parse_args()

hosts = []
port = 0
scantype = 0
multiplehosts = 0
multipleports = 0

if args.host != None:
	host = args.host

	if args.port != None:
		port = int(args.port)
	if args.ports != None:
		ports = args.ports.split(',')
		ports = map(int, ports)
		multipleports = 1
	if args.scantype != None:
		scantype = args.scantype
		
	if not multipleports:
		print runScan(host, port,scantype)
	elif multipleports:
		res = runPortScan(host, ports,scantype)
		printResultArray(res)

elif args.filename != None:
	hosts = getHosts(args.filename)

	if args.port != None:
		port = int(args.port)
	if args.ports != None:
		ports = args.ports.split(',')
		ports = map(int, ports)
		multipleports = 1
	if args.scantype != None:
		scantype = args.scantype
	if not multipleports:
		res = multiScan(hosts, port, scantype) 
		printResultArray(res)
	elif multipleports:
		res = multiPortScan(hosts, ports,scantype)
		printMultiHostResultArray(res)
	
	


