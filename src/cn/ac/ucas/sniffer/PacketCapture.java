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
//抓包线程
public class PacketCapture implements Runnable{
	static NetworkInterface device;//要抓取的网卡
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
			//参数一:选择一个网卡，调用 JpcapCaptor.openDevice()连接，返回一个 JpcapCaptor类的对象 jpcap;
	         // 参数二:设置最大字节
	         // 参数三:设置为非混杂模式,才可以使用下面的捕获过滤器方法;
	         // 参数四:指定超时的时间;
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
		
		//过滤空包
		if(packet!=null&&new PacketAnalyze(packet).Packet_in_Class().size()>=3) {
			data[0]=df.format(date);
			data[1]=new PacketAnalyze(packet).Packet_in_Class().get("源IP");
			data[2]=new PacketAnalyze(packet).Packet_in_Class().get("目的IP");
			data[3]=new PacketAnalyze(packet).Packet_in_Class().get("协议");
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
			if((p.get("源IP").equals(sip)&&p.get("目的IP").equals(dip))||
					(p.get("源IP").equals(dip)&&p.get("目的IP").equals(sip))) {
					return true;
			}
		}
		if(filter.equals("")) {
			return true;
		}
		return false;
	}
	
}
