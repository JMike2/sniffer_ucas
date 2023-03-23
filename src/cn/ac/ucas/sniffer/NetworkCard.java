package cn.ac.ucas.sniffer;
import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;

public class NetworkCard {
//获取网卡列表	
	public static NetworkInterface[] getDevices() {
		NetworkInterface[] devices=JpcapCaptor.getDeviceList();
		return devices;
	}	
}
