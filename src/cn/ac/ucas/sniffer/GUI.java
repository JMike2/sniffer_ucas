package cn.ac.ucas.sniffer;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JFrame;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.plaf.basic.DefaultMenuLayout;
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
	JScrollPane pane;
	final String[] head = {"ʱ��","ԴIP","Ŀ��IP","Э��","����"};
	NetworkInterface[] devices;
	Object[][] datalist;
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
		item2.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				//����������ΪUDP�������б����
				allpacket.setFilter("UDP");
				allpacket.clearPacket();
				//��ձ�defaulttable
				while(dt.getColumnCount()>0) {
					dt.removeRow(dt.getRowCount()-1);
				}
			}
		});
		item3.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				//����������ΪICMP�������б����
				allpacket.setFilter("ICMP");
				allpacket.clearPacket();
				//��ձ�defaulttable
				while(dt.getColumnCount()>0) {
					dt.removeRow(dt.getRowCount()-1);
				}
			}
		});
		//��ɸѡЭ��˵������˵���
		menu2.add(item1);
		menu2.add(item2);
		menu2.add(item3);
		//���˵�����˵�����
		menubar.add(menu1);
		menubar.add(menu2);
		setJMenuBar(menubar);
		dt=new DefaultTableModel(datalist,head);
		allpacket.setTable(dt);
		table = new JTable(dt) {
			//�������в��ɱ༭
			public boolean isCellEditable(int row,int cloumn) {
				return false;
			}
		};
		table.setPreferredScrollableViewportSize(new Dimension(600,50));//���ñ��Ĵ�С
		table.setRowHeight(30);
		table.setRowMargin(5);
		table.setShowGrid(true);
		table.doLayout();
		pane = new JScrollPane(table);
		setContentPane(pane);
		pack();
		setVisible(true);
	}
	public static void main(String[] args) {
		new GUI();
	}
	
}

