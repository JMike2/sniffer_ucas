package cn.ac.ucas.sniffer;

import java.util.Scanner;

import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;

public class NetworkCard {
	
		//获取网卡设备列表
		public static NetworkInterface[] getDevices(){
			NetworkInterface[] devices = JpcapCaptor.getDeviceList();
			return devices;
		}
		
	
		
		
	
}
