#!/usr/bin/python

import socket, os, struct, binascii

def analyze_tcp_header(data, data_length):
	tcp_hdr = struct.unpack("!2H2I4H", data[:20]) 
	src_port = tcp_hdr[0]
	dst_port = tcp_hdr[1]
	seq_num = tcp_hdr[2]
	ack_num = tcp_hdr[3]
	
	data_offset = tcp_hdr[4] >> 12
		
	tcp_data =  data[data_offset*4:data_length]
	
	reserved = (tcp_hdr[4] >> 6) & 0x03ff #MUST BE ZERO
	flags = tcp_hdr[4] & 0x003f
	
	urg = flags & 0x0020
	ack = flags & 0x0010
	psh = flags & 0x0008
	rst = flags & 0x0004
	syn = flags & 0x0002
	fin = flags & 0x0001

	window  = tcp_hdr[5]
	checksum = tcp_hdr[6]
	urg_ptr = tcp_hdr[7]
	
	print "|============== TCP  HEADER ==============|"
	print "\tSource Port:\t%hu"	% src_port
	print "\tDest Port:\t%hu"	% dst_port
	print "\tSeq Number:\t%hu"	% seq_num
	print "\tAck Number:\t%hu"	% ack_num
	print "\tFlags:"
	print "\t\tURG: %d"			% urg
	print "\t\tACK: %d"			% ack
	print "\t\tPSH: %d"			% psh
	print "\t\tRST: %d"			% rst
	print "\t\tSYN: %d"			% syn
	print "\t\tFIN: %d"			% fin
	print "\tWindow Size:\t%hu"	% window
	print "\tChecksum:\t%hu"	% checksum
	print "\tUrgent:\t\t%hu"	% reserved
	print "\tPayload:\n%s"		% tcp_data


	data = data[data_offset*4:]
	
	return data

def analyze_udp_header(data, data_length):
	udp_hdr = struct.unpack("!4H", data[:8]) 
	src_port = udp_hdr[0]
	dst_port = udp_hdr[1]
	length   = udp_hdr[2]
	checksum = udp_hdr[3]
	
	data = data[8:]
	
	udp_data = data[:length*4-20]
	
	print "|============== UDP  HEADER ==============|"
	print "\tSource Port:\t%hu"	% src_port
	print "\tDest Port:\t%hu"	% dst_port
	print "\tLength:\t\t%hu"	% length
	print "\tChecksum:\t%hu"	% checksum
	print "\tPayload:\n%s"		% udp_data

	
	

	return data

def analyze_ip_header(data):
	ip_hdr = struct.unpack("!6H4s4s", data[:20]) 
	
	version     = ip_hdr[0] >> 12
	ihl         = (ip_hdr[0] >> 8) & 0x0f #00001111
	tos 	    = ip_hdr[0] & 0x00ff
	
	length      = ip_hdr[1]
	
	ip_id       = ip_hdr[2]
	
	flags       = ip_hdr[3]	>> 13
	frag_offset = ip_hdr[3] & 0x1fff
	
	ip_ttl      = ip_hdr[4] >> 8
	ip_protocol = ip_hdr[4] & 0x00ff
	
	chksum      = ip_hdr[5]
	
	src_addr    = socket.inet_ntoa(ip_hdr[6])
	dst_addr   = socket.inet_ntoa(ip_hdr[7])
	
	
	no_frag = flags >> 1
	more_frag = flags & 0x1
	#Portocol table
	table = {num:name[8:] for name,num in vars(socket).items() if name.startswith("IPPROTO")}
	try:
		proto_name = "(%s)" % table[ip_protocol]
	except:
		proto_name = ""
	
	print "|=============== IP HEADER ===============|"
	
	print "\tVersion:\t%hu" 	% version
	print "\tIHL:\t\t%hu" 		% ihl
	print "\tTOS:\t\t%hu" 		% tos
	print "\tID:\t\t%hu" 		% ip_id
	print "\tNo Frag:\t%hu"		% no_frag
	print "\tMore frag:\t%hu"	% more_frag
	print "\tOffset:\t\t%hu"		% frag_offset
	print "\tTTL:\t\t%hu"		% ip_ttl
	print "\tNext protocol:\t%hu%s"	% (ip_protocol, proto_name)
	print "\tChecksum:\t%hu"	% chksum
	print "\tSource IP:\t%s"	% src_addr
	print "\tDest IP:\t%s"	% dst_addr
	
	
	
	if(ip_protocol == 6): #TCP magic number
		next_proto = "TCP"
	elif (ip_protocol == 17): #UDP magic number
		next_proto = "UDP"
	else:
		next_proto = "OTHER"

	data_length = length-(ihl*32)/8
	data = data[(ihl*32)/8:]
	return data, data_length, next_proto
	
def analyze_ether_data(data):
	ip_bool = False
	
	eth_hdr = struct.unpack("!6s6sH", data[:14]) 
	dest_mac = binascii.hexlify(eth_hdr[0]) # Destination address
	src_mac  = binascii.hexlify(eth_hdr[1]) # Source address
	protocol  = eth_hdr[2] >> 8 # Next Protocol 
	
	print "|============ ETHERNET HEADER ============|"
	print "|Destination MAC:\t%s:%s:%s:%s:%s:%s" % (dest_mac[0:2],
	dest_mac[2:4],dest_mac[4:6],dest_mac[6:8],dest_mac[8:10],dest_mac[10:12])
		
	print "|Source MAC:\t\t%s:%s:%s:%s:%s:%s" % (src_mac[0:2],
	src_mac[2:4],src_mac[4:6],src_mac[6:8],src_mac[8:10],src_mac[10:12])
		
	print "|Protocol:\t\t%hu" % protocol
	
	if(protocol == 8): #IPv4 = 0x0800
		ip_bool = True
	data = data[14:]
	return data, ip_bool

def main():
	
	sniffer_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
	while (True):
		sniffed_data = sniffer_socket.recv(2048)
		print
		print
		os.system("clear")
		data, ip_bool = analyze_ether_data(sniffed_data)
		if ip_bool:
			data, data_length, next_proto = analyze_ip_header(data)
			if next_proto == "TCP":
				data = analyze_tcp_header(data, data_length)
			elif next_proto == "UDP":
				data = analyze_udp_header(data, data_length)
main()
