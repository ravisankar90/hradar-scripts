require 'rubygems'
require 'socket'
require 'pcaprub'
require 'packetfu'
require 'colorize'

capture = PacketFu::Capture.new(:iface => 'enp3s0', :start => true,)
#capture.show_live
#capture.stream.each do |p|
#  pkt = PacketFu::Packet.parse(p)
#  if pkt.is_ip? and pkt.is_tcp? 
#    if pkt.tcp_flags.syn == 1 and pkt.tcp_flags.ack == 0
#      print "Source Addr: #{pkt.ip_saddr}\n"
#      print "Destination Addr: #{pkt.ip_daddr}\n"
#      print "Destination Port: #{pkt.tcp_dport}\n"
#      print "TCP Options: #{pkt.tcp_options}\n"
#      print "TCP SYN?: #{pkt.tcp_flags.syn}\n"
#      print "TCP ACK?: #{pkt.tcp_flags.ack}\n"
#    end
#  end
#end


capture.stream.each	do	|pkt|
	packet	=	PacketFu::Packet.parse(pkt)
	if packet.is_ip? and packet.is_tcp?
		#print	"#{Time.now}: "	+ "  Source IP: #{packet.ip_saddr}" + "   -->   " + "Destination IP: #{packet.ip_daddr}" + ":#{packet.tcp_dport}"
		print "#{Time.now}:"
		print " #{packet.ip_saddr}:#{packet.tcp_sport}".green  
		print " -->   "
		print "#{packet.ip_daddr}:#{packet.tcp_dport}   ".red	
		print "Flags: #{packet.tcp_flags.syn} #{packet.tcp_flags.ack} #{packet.tcp_flags.urg} #{packet.tcp_flags.psh} #{packet.tcp_flags.rst} #{packet.tcp_flags.fin}".blue
		print "   TCP Options: #{packet.tcp_options}\n".yellow
	end

end

