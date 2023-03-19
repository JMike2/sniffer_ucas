package cn.ac.ucas.sniffer;
import cn.ac.ucas.sniffer.PacketAnalyze;
import jpcap.packet.Packet;

import javax.swing.table.DefaultTableModel;

import cn.ac.ucas.sniffer.NetworkCard;
//抓包线程
public class PacketCapture implements Runnable{
	static NetworkCard device;
	static DefaultTableModel tablemodle;
	static String filter ="";
	public PacketCapture() {
		
	}
	public void setFilter(String filter) {
		this.filter=filter;
	}
	public void setDivices(NetworkCard device) {
		this.device=device;
	}
	public void run() {
		Packet packet;
	}
}
