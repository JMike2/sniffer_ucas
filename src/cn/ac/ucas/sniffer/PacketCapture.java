package cn.ac.ucas.sniffer;
import cn.ac.ucas.sniffer.PacketAnalyze;
import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;
import jpcap.packet.ARPPacket;
import jpcap.packet.ICMPPacket;
import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;
import jpcap.packet.UDPPacket;

import java.io.IOException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;

import javax.swing.table.DefaultTableModel;

import cn.ac.ucas.sniffer.NetworkCard;
//ץ���߳�
public class PacketCapture implements Runnable{
	static NetworkInterface device;//Ҫץȡ������
	static DefaultTableModel dt;
	static String filter = "";
	static ArrayList<Packet> packetlist = new ArrayList<>(); 
	static boolean action = true;
	static String str="";
	static String str1="";
	public PacketCapture() {
		
	}
	public void setDevice(NetworkInterface device) {
		this.device =device;
	}
	public void setFilter(String filter) {
		this.filter = filter;
	}
	public void setTable(DefaultTableModel dt) {
		this.dt = dt;
	}
	public static void packetclear() {
		packetlist.clear();
	}
	public static ArrayList<Packet> getPacketList(){
		return packetlist;
	}
	public void run() {
		Packet packet;
		try {
			//����һ:ѡ��һ������������ JpcapCaptor.openDevice()���ӣ�����һ�� JpcapCaptor��Ķ��� jpcap;
	         // ������:��������ֽ�
	         // ������:����Ϊ�ǻ���ģʽ,�ſ���ʹ������Ĳ������������;
	         // ������:ָ����ʱ��ʱ��;
			JpcapCaptor jpcap = JpcapCaptor.openDevice(device, 65535, false, 20);
			while(action) {
				long time = System.currentTimeMillis();
				if(time+600>=time) {
					packet = jpcap.getPacket();
					if(packet!=null&&testFilter(packet)) {
						packetlist.add(packet);
						joinTable(packet);
					}
				}
				
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	public static String[] getInfo(Packet packet) {
		String[] data = new String[6];
		Date date =new Date();
		DateFormat df = new SimpleDateFormat("HH:mm:ss");
		
		//���˿հ�
		if(packet!=null&&new PacketAnalyze(packet).Packet_in_Class().size()>=3) {
			data[0]=df.format(date);
			data[1]=new PacketAnalyze(packet).Packet_in_Class().get("ԴIP");
			data[2]=new PacketAnalyze(packet).Packet_in_Class().get("Ŀ��IP");
			data[3]=new PacketAnalyze(packet).Packet_in_Class().get("Э��");
			data[4]=String.valueOf(packet.len);
		}
		
		return data;
	}
	public static void joinTable(Packet packet) {
		String[] rowdata = getInfo(packet);
		dt.addRow(rowdata);		
	}
	public static boolean testFilter(Packet packet) {
		if(filter.contains("ICMP")) {
			if(packet.getClass().equals(ICMPPacket.class)) return true;
		}
		if(filter.contains("TCP")) {
			if(packet.getClass().equals(TCPPacket.class)) return true;
		}
		if(filter.contains("UDP")) {
			if(packet.getClass().equals(UDPPacket.class)) return true;
		}
		if(filter.contains("HTTP")) {
			if(packet.getClass().equals(TCPPacket.class)) {
				TCPPacket tcppacket = (TCPPacket)packet;
				if(tcppacket.src_port==80||tcppacket.dst_port==80) {
					return true;
				}
			
			} 
		}
		if(filter.contains("TLS")) {
			if(packet.getClass().equals(TCPPacket.class)) {
				TCPPacket tcppacket = (TCPPacket)packet;
				if(tcppacket.src_port==443||tcppacket.dst_port==443) {
					return true;
				}
				
			} 
		}
		if(filter.contains("key")) {
			String sip = GUI.str;
			String dip = GUI.str1;
			HashMap<String,String> p = new PacketAnalyze(packet).Packet_in_Class();
			//System.out.println(p.toString());
			if((p.get("ԴIP").equals(sip)&&p.get("Ŀ��IP").equals(dip))||
					(p.get("ԴIP").equals(dip)&&p.get("Ŀ��IP").equals(sip))) {
					return true;
			}
		}
		if(filter.equals("")) {
			return true;
		}
		return false;
	}
	
}
