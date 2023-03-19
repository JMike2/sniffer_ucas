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
	//��UDP�������ݴ��ڹ�ϣ���Ӧ��ֵ��
	public static HashMap<String,String> UDPAnalyze(){
		map=new HashMap<String,String>();
		UDPPacket udppacket = (UDPPacket)packet;
		map.put("Э��", "UDP");
		map.put("ԴIP", udppacket.src_ip.toString());//udp����ԴIP��ַ
		map.put("Դ�˿�", String.valueOf(udppacket.src_port));//udp����Դ�˿�
		map.put("Ŀ��IP", udppacket.dst_ip.toString());//udp����Ŀ��IP��ַ
		map.put("Ŀ�Ķ˿�", String.valueOf(udppacket.dst_port));//udp����Ŀ�Ķ˿�
		try {
			map.put("����", new String(udppacket.data,"gbk"));
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return map;
		
	}
	public static HashMap<String,String> TCPAnalyze(){
		map=new HashMap<String,String>();
		TCPPacket tcppacket = (TCPPacket)packet;
		map.put("Э��", "TCP");
		map.put("ԴIP", tcppacket.src_ip.toString());//tcp����ԴIP��ַ
		map.put("Դ�˿�", String.valueOf(tcppacket.src_port));//tcp����Դ�˿�
		map.put("Ŀ��IP", tcppacket.dst_ip.toString());//tcp����Ŀ��IP��ַ
		map.put("Ŀ�Ķ˿�", String.valueOf(tcppacket.dst_port));//tcp����Ŀ�Ķ˿�
		try {
			map.put("����", new String(tcppacket.data,"gbk"));
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return map;
	}
	public static HashMap<String,String> ICMPAnalyze(){
		map=new HashMap<String,String>();
		ICMPPacket icmppacket = (ICMPPacket)packet;
		map.put("Э��", "ICMP");
		map.put("ԴIP", icmppacket.src_ip.toString());//ICMP����ԴIP��ַ
		map.put("Ŀ��IP",icmppacket.dst_ip.toString());//ICMP����Ŀ��IP��ַ
		try {
			map.put("����", new String(icmppacket.data,"gbk"));
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return map;
	}
	//���ݲ�ͬ����ı���ѡ����Ӧ�ķ������
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
