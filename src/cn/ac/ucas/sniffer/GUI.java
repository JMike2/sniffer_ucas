package cn.ac.ucas.sniffer;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.GridLayout;
import java.awt.TextArea;
import java.awt.TextField;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.plaf.basic.DefaultMenuLayout;
import javax.swing.table.DefaultTableModel;

import cn.ac.ucas.*;
import jpcap.NetworkInterface;
import jpcap.packet.Packet;

public class GUI extends JFrame{
	PacketCapture allpacket;
	JMenuBar menubar;//菜单条
	JMenu menu1,menu2;//菜单
	JMenuItem[] item;//菜单项
	JMenuItem item1,item2,item3;
	JButton stop;
	JTable table;
	DefaultTableModel dt;
	JScrollPane pane;
	JPanel panel;
	JTextArea ta;
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
			allpacket.setDevice(device);
			allpacket.setFilter("");
			new Thread(allpacket).start();
		}
	}
	public GUI(){
		allpacket = new PacketCapture();
		this.setTitle("Sniffer_UCAS");
		this.setBounds(200,100,400,400);
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
				allpacket.packetclear();
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
				allpacket.packetclear();
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
				allpacket.packetclear();
				//清空表defaulttable
				while(dt.getColumnCount()>0) {
					dt.removeRow(dt.getRowCount()-1);
				}
			}
		});
		stop = new JButton("开始/停止");
		stop.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if(allpacket.action==false) {
					allpacket.action=true;
					new Thread(allpacket).start();
				}else {
					allpacket.action=false;
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
		menubar.add(stop);
		setJMenuBar(menubar);
		dt=new DefaultTableModel(datalist,head);
		allpacket.setTable(dt);
		table = new JTable(dt) {
			//设置行列不可编辑
			public boolean isCellEditable(int row,int cloumn) {
				return false;
			}
		};
		table.setPreferredScrollableViewportSize(new Dimension(400,500));//设置表格的大小
		table.setRowHeight(30);
		table.setRowMargin(5);
		table.setShowGrid(true);
		table.setRowSelectionAllowed(true);// 设置可否被选择.默认为false  
		table.doLayout();
		pane = new JScrollPane(table);
		panel = new JPanel(new GridLayout(0, 1));  
		panel.setPreferredSize(new Dimension(600, 300));  
		panel.setBackground(Color.black);  
		panel.add(pane); 
		add(panel,BorderLayout.WEST);
		ta=new JTextArea(40,40);
		ta.setEditable(false);//不可编辑
		ta.setLineWrap(true);//满一行自动换行
		ta.setWrapStyleWord(true);
		JPanel p = new JPanel();
		p.add(new JScrollPane(ta));
		add(p,BorderLayout.EAST);
		table.addMouseListener(new MouseAdapter() {
			public void mouseClicked(MouseEvent e) {
				if(e.getClickCount()==2) {
					ta.setText(null);
					int row = table.getSelectedRow();
					ArrayList<Packet> packetlist = allpacket.getPacketList();
					System.out.println("1");
					Map<String,String> m1 = new HashMap<String,String>();
					Map<String,String> m2 = new HashMap<String,String>();
					Packet packet = packetlist.get(row);
					ta.append("********************************************"+"\n");
					ta.append("***************IP头信息*********************"+"\n");
					ta.append("********************************************"+"\n");
					m1=new PacketAnalyze(packet).IPAnalyze();
					for(Map.Entry<String,String>me1:m1.entrySet()) {
						ta.append(me1.getKey()+":"+me1.getValue()+"\n");
					}
					m2=new PacketAnalyze(packet).Packet_in_Class();
					ta.append("********************************************"+"\n");
					ta.append("***************"+m2.get("协议")+"报头"+"************"+"\n");
					ta.append("*********************************************"+"\n");
					for(Map.Entry<String, String>me2:m2.entrySet()) {
						ta.append(me2.getKey()+":"+me2.getValue()+"\n");
					}
				}
			}
		});
		
		pack();
		setVisible(true);
		addWindowListener(new WindowAdapter() {  
			public void windowClosing(WindowEvent e) {  
				System.exit(0);
			}
		});  

	}
	public static void main(String[] args) {
		new GUI();
	}
	
}

