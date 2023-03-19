package cn.ac.ucas.sniffer;

import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import cn.ac.ucas.sniffer.NetworkCard;
import jpcap.packet.ICMPPacket;
import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;
import jpcap.packet.UDPPacket;

public class PacketAnalyze {
	static Packet packet;
	static HashMap<String,String> map;
	static HashMap<String,String> map1;
	public PacketAnalyze(Packet packet) {
		this.packet=packet;
	}
	//将UDP包的数据存在哈希表对应键值中
	public static HashMap<String,String> UDPAnalyze(){
		map=new HashMap<String,String>();
		UDPPacket udppacket = (UDPPacket)packet;
		map.put("协议", "UDP");
		map.put("源IP", udppacket.src_ip.toString());//udp包的源IP地址
		map.put("源端口", String.valueOf(udppacket.src_port));//udp包的源端口
		map.put("目的IP", udppacket.dst_ip.toString());//udp包的目的IP地址
		map.put("目的端口", String.valueOf(udppacket.dst_port));//udp包的目的端口
		try {
			map.put("数据", new String(udppacket.data,"gbk"));
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return map;
		
	}
	public static HashMap<String,String> TCPAnalyze(){
		map=new HashMap<String,String>();
		TCPPacket tcppacket = (TCPPacket)packet;
		map.put("协议", "TCP");
		map.put("源IP", tcppacket.src_ip.toString());//tcp包的源IP地址
		map.put("源端口", String.valueOf(tcppacket.src_port));//tcp包的源端口
		map.put("目的IP", tcppacket.dst_ip.toString());//tcp包的目的IP地址
		map.put("目的端口", String.valueOf(tcppacket.dst_port));//tcp包的目的端口
		try {
			map.put("数据", new String(tcppacket.data,"gbk"));
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return map;
	}
	public static HashMap<String,String> ICMPAnalyze(){
		map=new HashMap<String,String>();
		ICMPPacket icmppacket = (ICMPPacket)packet;
		map.put("协议", "ICMP");
		map.put("源IP", icmppacket.src_ip.toString());//ICMP包的源IP地址
		map.put("目的IP",icmppacket.dst_ip.toString());//ICMP包的目的IP地址
		try {
			map.put("数据", new String(icmppacket.data,"gbk"));
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return map;
	}
	//根据不同种类的报文选择相应的分析类别
	public static HashMap<String,String> Packet_in_Class(){
		map1=new HashMap<String,String>();
		if(packet.getClass().equals(TCPPacket.class)) {
			map1=TCPAnalyze();
		}else if(packet.getClass().equals(UDPPacket.class)) {
			map1=UDPAnalyze();
		}else if(packet.getClass().equals(ICMPPacket.class)) {
			map1=ICMPAnalyze();
		}
		return map1;
	}
}
