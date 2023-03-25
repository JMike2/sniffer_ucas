package cn.ac.ucas.sniffer;

import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import cn.ac.ucas.sniffer.NetworkCard;
import jpcap.packet.EthernetPacket;
import jpcap.packet.ICMPPacket;
import jpcap.packet.IPPacket;
import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;
import jpcap.packet.UDPPacket;

//抓包分析：将各类包的数据放入对应键值的哈希表中；再根据包的类别获得相应的哈希表
public class PacketAnalyze {
	static Packet packet;
	static HashMap<String,String> map,map1;
	public PacketAnalyze(Packet packet) {
		this.packet=packet;
	}
	
	public HashMap<String,String> TCPAnalyze(){
		map=new HashMap<String,String>(); 
		TCPPacket tcppacket = (TCPPacket) packet;
		EthernetPacket ethernetpacket = (EthernetPacket) packet.datalink;
		map.put("协议", "TCP");
		map.put("源IP", tcppacket.src_ip.toString().substring(1,tcppacket.src_ip.toString().length()));
		map.put("目的IP", tcppacket.dst_ip.toString().substring(1,tcppacket.dst_ip.toString().length()));
		map.put("源端口", String.valueOf(tcppacket.src_port) );
		map.put("目的端口", String.valueOf(tcppacket.dst_port));
		map.put("源Mac地址",ethernetpacket.getSourceAddress());
		map.put("目的Mac地址", ethernetpacket.getDestinationAddress());
		try {
			map.put("数据",new String(tcppacket.data,"utf8"));
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return map;
	}
	public HashMap<String,String> UDPAnalyze(){
		map=new HashMap<String,String>();
		UDPPacket udppacket = (UDPPacket)packet;
		EthernetPacket ethernetpacket = (EthernetPacket)packet.datalink;
		map.put("协议", "UDP");
		map.put("源IP", udppacket.src_ip.toString().substring(1,udppacket.src_ip.toString().length()));
		map.put("目的IP", udppacket.dst_ip.toString().substring(1,udppacket.dst_ip.toString().length()));
		map.put("源端口", String.valueOf(udppacket.src_port));
		map.put("目的端口", String.valueOf(udppacket.dst_port));
		map.put("源Mac地址",ethernetpacket.getSourceAddress());
		map.put("目的Mac地址", ethernetpacket.getDestinationAddress());
		try {
			map.put("数据", new String(udppacket.data,"utf8"));
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return map;
	}
	
	public HashMap<String,String> ICMPAnalyze(){
		map = new HashMap<String,String>();
		ICMPPacket icmppacket = (ICMPPacket)packet;
		map.put("协议","ICMP");
		map.put("源IP", icmppacket.src_ip.toString().substring(1,icmppacket.src_ip.toString().length()));
		map.put("目的IP", icmppacket.dst_ip.toString().substring(1,icmppacket.dst_ip.toString().length()));
		map.put("ICMP报文首部" ,icmppacket.toString());
		map.put("标志位DF:是否允许分片" , String.valueOf(icmppacket.dont_frag));
		map.put("标志位MF:后面是否还有分片" , String.valueOf(icmppacket.more_frag));
		map.put("片偏移offset" , String.valueOf(icmppacket.offset));
		map.put("标识ident" ,String.valueOf(icmppacket.ident));
		map.put("ICMP报文类型type" , String.valueOf(icmppacket.type));
		map.put("ICMP报文代码code" , String.valueOf(icmppacket.code) );
		return map;
	}
	public HashMap<String,String> IPAnalyze(){
		map = new HashMap<String,String>();
		if(packet instanceof IPPacket) {
			IPPacket ippacket = (IPPacket) packet;
			map.put("协议", "IP");
			map.put("源IP",ippacket.src_ip.toString().substring(1,ippacket.src_ip.toString().length()));
			map.put("目的IP", ippacket.dst_ip.toString().substring(1,ippacket.dst_ip.toString().length()));
		}
		
		return map;
	}
	public HashMap<String, String> Packet_in_Class(){
		map1 = new HashMap<String,String>();
		if(packet.getClass().equals(ICMPPacket.class)) {
			map1=ICMPAnalyze();
		}else if(packet.getClass().equals(UDPPacket.class)) {
			map1=UDPAnalyze();
		}else if(packet.getClass().equals(TCPPacket.class)) {
			map1=TCPAnalyze();
		}
		return map1;
	}
}
