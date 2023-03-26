package cn.ac.ucas.sniffer;

import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import cn.ac.ucas.sniffer.NetworkCard;
import jpcap.packet.ARPPacket;
import jpcap.packet.EthernetPacket;
import jpcap.packet.ICMPPacket;
import jpcap.packet.IPPacket;
import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;
import jpcap.packet.UDPPacket;

//ץ��������������������ݷ����Ӧ��ֵ�Ĺ�ϣ���У��ٸ��ݰ����������Ӧ�Ĺ�ϣ��
public class PacketAnalyze {
	static Packet packet;
	static HashMap<String,String> map,map1;
	public PacketAnalyze(Packet packet) {
		this.packet=packet;
	}
	public static String toHexString(byte[] req) {
        // ���б���ת�� byte --> hexString (��ĸ��д)
        String str = "";
        for (int i = 0; i < req.length; i++ ) {
            String hex = Integer.toHexString(req[i] & 0xFF);
            if (hex.length() == 1) {
                hex = "0" + hex;
            }
            str += hex.toUpperCase();
        }
        return str;
    }


	public HashMap<String,String> TCPAnalyze(){
		map=new HashMap<String,String>(); 
		TCPPacket tcppacket = (TCPPacket) packet;
		EthernetPacket ethernetpacket = (EthernetPacket) packet.datalink;
		map.put("Э��", "TCP");
		map.put("ԴIP", tcppacket.src_ip.toString().substring(1,tcppacket.src_ip.toString().length()));
		map.put("Ŀ��IP", tcppacket.dst_ip.toString().substring(1,tcppacket.dst_ip.toString().length()));
		map.put("Դ�˿�", String.valueOf(tcppacket.src_port) );
		map.put("Ŀ�Ķ˿�", String.valueOf(tcppacket.dst_port));
		map.put("ԴMac��ַ",ethernetpacket.getSourceAddress());
		map.put("Ŀ��Mac��ַ", ethernetpacket.getDestinationAddress());
		map.put("����",toHexString(tcppacket.data));
		try {
			map.put("����utf8", new String(tcppacket.data,"utf8"));
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return map;
	}
	public HashMap<String,String> HTTPAnalyze(){
		map=new HashMap<String,String>(); 
		TCPPacket tcppacket = (TCPPacket) packet;
		EthernetPacket ethernetpacket = (EthernetPacket) packet.datalink;
		map.put("Э��", "HTTP");
		map.put("ԴIP", tcppacket.src_ip.toString().substring(1,tcppacket.src_ip.toString().length()));
		map.put("Ŀ��IP", tcppacket.dst_ip.toString().substring(1,tcppacket.dst_ip.toString().length()));
		map.put("Դ�˿�", String.valueOf(tcppacket.src_port) );
		map.put("Ŀ�Ķ˿�", String.valueOf(tcppacket.dst_port));
		map.put("ԴMac��ַ",ethernetpacket.getSourceAddress());
		map.put("Ŀ��Mac��ַ", ethernetpacket.getDestinationAddress());
		map.put("����",toHexString(tcppacket.data));
		try {
			map.put("����utf8", new String(tcppacket.data,"utf8"));
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return map;
	}
	public HashMap<String,String> TLSAnalyze(){
		map=new HashMap<String,String>(); 
		TCPPacket tcppacket = (TCPPacket) packet;
		EthernetPacket ethernetpacket = (EthernetPacket) packet.datalink;
		map.put("Э��", "TLS");
		map.put("ԴIP", tcppacket.src_ip.toString().substring(1,tcppacket.src_ip.toString().length()));
		map.put("Ŀ��IP", tcppacket.dst_ip.toString().substring(1,tcppacket.dst_ip.toString().length()));
		map.put("Դ�˿�", String.valueOf(tcppacket.src_port) );
		map.put("Ŀ�Ķ˿�", String.valueOf(tcppacket.dst_port));
		map.put("ԴMac��ַ",ethernetpacket.getSourceAddress());
		map.put("Ŀ��Mac��ַ", ethernetpacket.getDestinationAddress());
		map.put("����",toHexString(tcppacket.data));
		try {
			map.put("����utf8", new String(tcppacket.data,"utf8"));
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
		map.put("Э��", "UDP");
		map.put("ԴIP", udppacket.src_ip.toString().substring(1,udppacket.src_ip.toString().length()));
		map.put("Ŀ��IP", udppacket.dst_ip.toString().substring(1,udppacket.dst_ip.toString().length()));
		map.put("Դ�˿�", String.valueOf(udppacket.src_port));
		map.put("Ŀ�Ķ˿�", String.valueOf(udppacket.dst_port));
		map.put("ԴMac��ַ",ethernetpacket.getSourceAddress());
		map.put("Ŀ��Mac��ַ", ethernetpacket.getDestinationAddress());
		map.put("����", toHexString(udppacket.data));
		try {
			map.put("����utf8", new String(udppacket.data,"utf8"));
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return map;
	}
	
	public HashMap<String,String> ICMPAnalyze(){
		map = new HashMap<String,String>();
		ICMPPacket icmppacket = (ICMPPacket)packet;
		map.put("Э��","ICMP");
		map.put("ԴIP", icmppacket.src_ip.toString().substring(1,icmppacket.src_ip.toString().length()));
		map.put("Ŀ��IP", icmppacket.dst_ip.toString().substring(1,icmppacket.dst_ip.toString().length()));
		map.put("ICMP�����ײ�" ,icmppacket.toString());
		map.put("��־λDF:�Ƿ������Ƭ" , String.valueOf(icmppacket.dont_frag));
		map.put("��־λMF:�����Ƿ��з�Ƭ" , String.valueOf(icmppacket.more_frag));
		map.put("Ƭƫ��offset" , String.valueOf(icmppacket.offset));
		map.put("��ʶident" ,String.valueOf(icmppacket.ident));
		map.put("ICMP��������type" , String.valueOf(icmppacket.type));
		map.put("ICMP���Ĵ���code" , String.valueOf(icmppacket.code) );
		return map;
	}
	public HashMap<String,String> IPAnalyze(){
		map = new HashMap<String,String>();
		if(packet instanceof IPPacket) {
			IPPacket ippacket = (IPPacket) packet;
			map.put("Э��", "IP");
			map.put("ԴIP",ippacket.src_ip.toString().substring(1,ippacket.src_ip.toString().length()));
			map.put("Ŀ��IP", ippacket.dst_ip.toString().substring(1,ippacket.dst_ip.toString().length()));
			map.put("IP�����ײ�" , ippacket.toString());
			map.put("�汾version" , String.valueOf(ippacket.version));
			map.put("ʱ���sec(��) " , String.valueOf(ippacket.sec));
			map.put("Э��protocol" ,String.valueOf(ippacket.protocol));
			map.put("����Ȩpriority", String.valueOf(ippacket.priority));
			map.put("����ʱ��hop", String.valueOf(ippacket.hop_limit));
			map.put("��־λRF:����λ����Ϊfalse", String.valueOf(ippacket.rsv_frag));
			map.put("��־λDF:�Ƿ������Ƭ", String.valueOf(ippacket.dont_frag));
			map.put("��־λMF:�����Ƿ��з�Ƭ", String.valueOf(ippacket.more_frag));
			map.put("Ƭƫ��offset", String.valueOf(ippacket.offset));	
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
			TCPPacket tcppacket = (TCPPacket)packet;
			if(tcppacket.src_port==80||tcppacket.dst_port==80) {
				map1=HTTPAnalyze();
			}else if(tcppacket.src_port==443||tcppacket.dst_port==443) {
				map1=TLSAnalyze();
			}else {
				map1=TCPAnalyze();
			}
			
		}
		return map1;
	}
}
