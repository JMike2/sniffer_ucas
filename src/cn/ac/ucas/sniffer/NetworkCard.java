package cn.ac.ucas.sniffer;
import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;

public class NetworkCard {
//��ȡ�����б�	
	public static NetworkInterface[] getDevices() {
		NetworkInterface[] devices=JpcapCaptor.getDeviceList();
		return devices;
	}	
}
