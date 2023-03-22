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
	JMenuBar menubar;//菜单条
	JMenu menu1,menu2;//菜单
	JMenuItem[] item;//菜单项
	JMenuItem item1,item2,item3;
	JTextField  tf;
	JTable table;
	DefaultTableModel dt;
	JScrollPane pane;
	final String[] head = {"时间","源IP","目的IP","协议","长度"};
	NetworkInterface[] devices;
	Object[][] datalist;
	//监听到指令后开始抓包
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
		//将各网卡放入菜单选择
		menu1=new JMenu("网卡");
		devices = new NetworkCard().getDevices();
		item = new JMenuItem[devices.length];
		for(int i =0;i<devices.length;i++) {
			item[i]=new JMenuItem("序号"+i+devices[i].name+"("+devices[i].description+")");
			item[i].addActionListener(new NetcardListener(devices[i]));
			menu1.add(item[i]);
		}
		//根据协议进行筛选
		menu2=new JMenu("协议");
		item1=new JMenuItem("TCP");
		item2=new JMenuItem("UDP");
		item3=new JMenuItem("ICMP");
		item1.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				//过滤器设置为TCP并将包列表清空
				allpacket.setFilter("TCP");
				allpacket.clearPacket();
				//清空表defaulttable
				while(dt.getColumnCount()>0) {
					dt.removeRow(dt.getRowCount()-1);
				}
			}
		});
		item2.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				//过滤器设置为UDP并将包列表清空
				allpacket.setFilter("UDP");
				allpacket.clearPacket();
				//清空表defaulttable
				while(dt.getColumnCount()>0) {
					dt.removeRow(dt.getRowCount()-1);
				}
			}
		});
		item3.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				//过滤器设置为ICMP并将包列表清空
				allpacket.setFilter("ICMP");
				allpacket.clearPacket();
				//清空表defaulttable
				while(dt.getColumnCount()>0) {
					dt.removeRow(dt.getRowCount()-1);
				}
			}
		});
		//将筛选协议菜单项加入菜单中
		menu2.add(item1);
		menu2.add(item2);
		menu2.add(item3);
		//将菜单加入菜单条中
		menubar.add(menu1);
		menubar.add(menu2);
		setJMenuBar(menubar);
		dt=new DefaultTableModel(datalist,head);
		allpacket.setTable(dt);
		table = new JTable(dt) {
			//设置行列不可编辑
			public boolean isCellEditable(int row,int cloumn) {
				return false;
			}
		};
		table.setPreferredScrollableViewportSize(new Dimension(600,50));//设置表格的大小
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

