package cn.ac.ucas.sniffer;

import java.util.Scanner;

import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;

public class NetworkCard {
	
		//��ȡ�����豸�б�
		public static NetworkInterface[] getDevices(){
			NetworkInterface[] devices = JpcapCaptor.getDeviceList();
			return devices;
		}
		
	
		
		
	
}
