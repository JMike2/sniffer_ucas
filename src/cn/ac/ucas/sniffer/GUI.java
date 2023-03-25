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
	JMenuBar menubar;//�˵���
	JMenu menu1,menu2;//�˵�
	JMenuItem[] item;//�˵���
	JMenuItem item1,item2,item3;
	JButton stop;
	JTable table;
	DefaultTableModel dt;
	JScrollPane pane;
	JPanel panel;
	JTextArea ta;
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
				allpacket.packetclear();
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
				allpacket.packetclear();
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
				allpacket.packetclear();
				//��ձ�defaulttable
				while(dt.getColumnCount()>0) {
					dt.removeRow(dt.getRowCount()-1);
				}
			}
		});
		stop = new JButton("��ʼ/ֹͣ");
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
		//��ɸѡЭ��˵������˵���
		menu2.add(item1);
		menu2.add(item2);
		menu2.add(item3);
		//���˵�����˵�����
		menubar.add(menu1);
		menubar.add(menu2);
		menubar.add(stop);
		setJMenuBar(menubar);
		dt=new DefaultTableModel(datalist,head);
		allpacket.setTable(dt);
		table = new JTable(dt) {
			//�������в��ɱ༭
			public boolean isCellEditable(int row,int cloumn) {
				return false;
			}
		};
		table.setPreferredScrollableViewportSize(new Dimension(400,500));//���ñ��Ĵ�С
		table.setRowHeight(30);
		table.setRowMargin(5);
		table.setShowGrid(true);
		table.setRowSelectionAllowed(true);// ���ÿɷ�ѡ��.Ĭ��Ϊfalse  
		table.doLayout();
		pane = new JScrollPane(table);
		panel = new JPanel(new GridLayout(0, 1));  
		panel.setPreferredSize(new Dimension(600, 300));  
		panel.setBackground(Color.black);  
		panel.add(pane); 
		add(panel,BorderLayout.WEST);
		ta=new JTextArea(40,40);
		ta.setEditable(false);//���ɱ༭
		ta.setLineWrap(true);//��һ���Զ�����
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
					ta.append("***************IPͷ��Ϣ*********************"+"\n");
					ta.append("********************************************"+"\n");
					m1=new PacketAnalyze(packet).IPAnalyze();
					for(Map.Entry<String,String>me1:m1.entrySet()) {
						ta.append(me1.getKey()+":"+me1.getValue()+"\n");
					}
					m2=new PacketAnalyze(packet).Packet_in_Class();
					ta.append("********************************************"+"\n");
					ta.append("***************"+m2.get("Э��")+"��ͷ"+"************"+"\n");
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

