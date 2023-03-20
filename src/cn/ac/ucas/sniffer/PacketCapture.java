package cn.ac.ucas.sniffer;
import cn.ac.ucas.sniffer.PacketAnalyze;
import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;
import jpcap.packet.Packet;

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;

import javax.swing.table.DefaultTableModel;

import cn.ac.ucas.sniffer.NetworkCard;
//抓包线程
public class PacketCapture implements Runnable{
	NetworkInterface device;
	static DefaultTableModel tablemodle;
	static String filter ="";
	static ArrayList<Packet> PacketList ;
	public PacketCapture() {
		
	}
	public void setFilter(String filter) {
		this.filter=filter;
	}
	public void setDivices(NetworkInterface device) {
		this.device=device;
	}
	public static ArrayList<Packet> getpacketList(){
		return PacketList;
	}
	public void clearPacket() {
		PacketList.clear();
	}
	//将抓到的包添加进表里
	public static String[] getInfo(Packet packet) {
		String[] data = new String[10];
		PacketAnalyze pa = new PacketAnalyze(packet);
		if(packet!=null&&pa.Packet_in_Class().size()>=1) {
			Date date= new Date();
			SimpleDateFormat df = new SimpleDateFormat("hh:mm:ss");
			data[0] = df.format(date);
			data[1] = pa.Packet_in_Class().get("源IP");
			data[2] = pa.Packet_in_Class().get("目的IP");
			data[3] = pa.Packet_in_Class().get("协议");
			data[4] = String.valueOf(packet.len);
		}
		return data;
	}
	//将抓到的包添加进表里
	public void joinTable(Packet packet) {
		tablemodle.addRow(getInfo(packet));
	}
	
	public void run() {
		Packet packet;
		try {
			//参数一:选择一个网卡，调用 JpcapCaptor.openDevice()连接，返回一个 JpcapCaptor类的对象 jpcap;
	         // 参数二:提取该数据包中前65535个字节;
	         // 参数三:设置为混杂模式；
	         // 参数四:指定超时的时间;
			JpcapCaptor jpcap = JpcapCaptor.openDevice(device, 65535, true, 20);
			while(true) {
				long StartTime = System.currentTimeMillis();
				while(StartTime+300>StartTime) {
					packet=jpcap.getPacket();
					PacketList.add(packet);				
				}
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
