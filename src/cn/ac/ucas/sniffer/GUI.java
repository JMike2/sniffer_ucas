package cn.ac.ucas.sniffer;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JFrame;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.table.DefaultTableModel;

import cn.ac.ucas.*;
import jpcap.NetworkInterface;

public class GUI extends JFrame{
	PacketCapture allpacket;
	JMenuBar menubar;//�˵���
	JMenu menu1,menu2;//�˵�
	JMenuItem[] item;//�˵���
	JMenuItem item1,item2,item3;
	JTextField  tf;
	JTable table;
	DefaultTableModel dt;
	final String[] head = {"ʱ��","ԴIP","Ŀ��IP","Э��","����"};
	NetworkInterface[] devices;
	//������ָ���ʼץ��
	private class NetcardListener implements ActionListener{
		NetworkInterface device;
		NetcardListener(NetworkInterface device){
			this.device=device;
		}
		public void actionPerformed(ActionEvent e) {
			allpacket.setDivices(device);
			allpacket.setFilter("");
			new Thread(allpacket).start();
		}
	}
	public GUI(){
		allpacket = new PacketCapture();
		this.setTitle("Sniffer_UCAS");
		this.setBounds(20,50,600,600);
		menubar= new JMenuBar();
		//������������˵�ѡ��
		menu1=new JMenu("����");
		devices = new NetworkCard().getDevices();
		item = new JMenuItem[devices.length];
		for(int i =0;i<devices.length;i++) {
			item[i]=new JMenuItem("���"+i+devices[i].name+"("+devices[i].description+")");
			item[i].addActionListener(new NetcardListener(devices[i]));
			menu1.add(item[i]);
		}
		//����Э�����ɸѡ
		menu2=new JMenu("Э��");
		item1=new JMenuItem("TCP");
		item2=new JMenuItem("UDP");
		item3=new JMenuItem("ICMP");
		item1.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				//����������ΪTCP�������б����
				allpacket.setFilter("TCP");
				allpacket.clearPacket();
				//��ձ�defaulttable
				while(dt.getColumnCount()>0) {
					dt.removeRow(dt.getRowCount()-1);
				}
			}
		});
	}
	
}

