#Primary Sniffer for the Hradar Project.
=begin
Version : 0.2
Change Log
==========
V 0.2 - Added redis connection. 
Now logs ip_src & ip_dst to Redis db on local host.
Added detailed comments.

V 0.1 - Primary Script
Captures packets using paacketfu gem. Displays all TCP packets with corresponding MAC addresses in different colors
Colorize gem enables colorized output.

=end
#Gems
require 'rubygems'
require 'socket'
require 'pcaprub'
require 'packetfu'
require 'colorize'
require 'redis'

redis = Redis.new(:host => "127.0.0.1", :port => "6379") #Redis connection, object => redis
capture = PacketFu::Capture.new(:iface => 'enp3s0', :start => true, :promiscus => true) #Capture from network interface enp3s0 in promiscous mode
capture.stream.each	do	|pkt|
	packet	=	PacketFu::Packet.parse(pkt) #Parse details from raw capture
	if packet.is_ip? and packet.is_tcp?
		print "#{Time.now}:"
		print " #{packet.ip_saddr}:#{packet.tcp_sport}".green 
		print " #{packet.eth_saddr}".cyan 
		print "  -->  "
		print " #{packet.ip_daddr}:#{packet.tcp_dport}".red
		print " #{packet.eth_daddr}".magenta
		print " #{packet.tcp_seq}"
		print " Flags: #{packet.tcp_flags.syn} #{packet.tcp_flags.ack} #{packet.tcp_flags.urg} #{packet.tcp_flags.psh} #{packet.tcp_flags.rst} #{packet.tcp_flags.fin}".blue
		print " TCP Options: #{packet.tcp_options}\n\n".yellow
		#Prints in format [time: ip_src:sport eth_src  -->  ip_dst:dport eth_dst tcp-sequence-no flags "S A U P R F" tcp-options ]
		redis.hmset("stream-#{packet.tcp_seq}", "ip_src", "#{packet.ip_saddr}", "ip_dst", "#{packet.ip_daddr}") #Writes ip_src & ip_dst to redisdb as hashes with "stream-#tcp-seq-no" as key.
		#redis.expire("stream-#{packet.tcp_seq}", "10") #Optional TTL for each key. To be set to 1 hr when live.
	end

end

