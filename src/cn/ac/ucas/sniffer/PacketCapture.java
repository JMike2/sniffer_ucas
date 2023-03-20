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
//ץ���߳�
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
	//��ץ���İ���ӽ�����
	public static String[] getInfo(Packet packet) {
		String[] data = new String[10];
		PacketAnalyze pa = new PacketAnalyze(packet);
		if(packet!=null&&pa.Packet_in_Class().size()>=1) {
			Date date= new Date();
			SimpleDateFormat df = new SimpleDateFormat("hh:mm:ss");
			data[0] = df.format(date);
			data[1] = pa.Packet_in_Class().get("ԴIP");
			data[2] = pa.Packet_in_Class().get("Ŀ��IP");
			data[3] = pa.Packet_in_Class().get("Э��");
			data[4] = String.valueOf(packet.len);
		}
		return data;
	}
	//��ץ���İ���ӽ�����
	public void joinTable(Packet packet) {
		tablemodle.addRow(getInfo(packet));
	}
	
	public void run() {
		Packet packet;
		try {
			//����һ:ѡ��һ������������ JpcapCaptor.openDevice()���ӣ�����һ�� JpcapCaptor��Ķ��� jpcap;
	         // ������:��ȡ�����ݰ���ǰ65535���ֽ�;
	         // ������:����Ϊ����ģʽ��
	         // ������:ָ����ʱ��ʱ��;
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
