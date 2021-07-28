#include "enc28j60.h"
#include "prohead.h"
#include "driver.h" 
#include "lcdlib.h"
#include "file.h"
#include "delay.h"
#include <string.h>
#include "stm32f10x_tim.h"
u16 dstimes=0;
u16 dstimes2=0;
u8 num=250;
u16 times =0;
u16 times2 =0;
u8 up[26] ={0x00,0x1a,0x02,0x41,0x01,0x4c,0xbb,0xb7,0xfa,0x38,0x38,0x64,0x38,0x36,0x65,0x33,0x35,0x64,0x34,0x62,0x61,0x62,0x61,0x38,0x33,0x05};
	//,
u8 callback[32] ={0x00,0x20,0x02,0x41,0x09,0x3c,0xd2,0x23,0xd4,0x4c,0xbb,0xb7,0xfa,0x38,0x38,0x64,0x38,0x36,0x65,0x33,0x35,0x64,0x34,0x62,0x61,0x62,0x61,0x38,0x33,0x6f,0x6b,0x05};
u8 back[41] ={0x00,0x29,0x02,0x41,0x09,0x3c,0xd2,0x23,0xd4,0x4c,0xbb,0xb7,0xfa,0x38,0x38,0x64,0x38,0x36,0x65,0x33,0x35,0x64,0x34,0x62,0x61,0x62,0x61,0x38,0x33,0x6f,0x6b,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x05};
u8 cg[32] ={0x00,0x20,0x02,0x41,0x0b,0x4c,0xbb,0xb7,0xfa,0x38,0x38,0x64,0x38,0x36,0x65,0x33,0x35,0x64,0x34,0x62,0x61,0x62,0x61,0x38,0x33,0x00,0xc8,0x01,0x02,0x31,0x30,0x05};
u8 br_ip[4]={115,28,93,201};
u8 GW_ip[4]={192,168,137,1};//网卡
u8 ga_MAC[6]={0x00,0x00,0X66,0X18,0X3B,0X44};//MAC  08-62-66-18-3B-44

u16 len;
//本地参数
u8 local_ip[4]={192,168,137,150};
u8 local_MAC[6]={0x00,0x12,0X34,0X56,0X78,0X90};//MAC

//缓冲数据报中的源ip地址和物理地址
u8 source_ip[4]={0};
u8 source_MAC[6]={0};

//缓冲数据包中的目的ip地址和物理地址
u8 dt_ip[4]={0};
u8 dt_MAC[6]={0};//destination

//定义arp缓冲区
u8 ARP_DATA[28]={0,1,8,0,6,4,0,1};

//以太网首部
u8 en_head[14]={0};

//定义数据缓冲区
u8 DATA[net_len]={0};

//定义IP首部
u8 IP_Head[20]={0};

//IP首部的标识字段
u16 IP_Mark=0x1200;

//定义ICMP报文缓冲区
u8 ICMP[40]={0,0,0,0};

//定义UDP首部和伪首部缓冲区
u8 UDP_head[8]={0};
u8 UDP_false_head[12]={0};

//定义UDP源端口和目的端口缓冲区
u16 UDP_source_port;
u16 UDP_dt_port;

//定义TCP首部和伪首部缓冲区
u8 TCP_head[20]={0};
u8 TCP_false_head[12]={0};

//定义TCP源端口和目的端口缓冲区
u16 TCP_source_port;
u16 TCP_dt_port;

//定义TCP变量缓冲区
u32 TCP_seq_num;	//order_number tcp序号 4字节
u32 TCP_ack_num;//Confirmation_number tcp确认号	 4字节
u8  TCP_URG;//紧急URG(URGent)
u8  TCP_ACK;//ACKnowlegment 确认号字段
u8  TCP_PSH;//推送PSH (PuSH)
u8  TCP_RST;//复位RST(ReSeT)	重置位
u8  TCP_SYN;//同步SYN 同步位
u8  TCP_FIN;//终止FIN (FINis 终止位)

//定义TCP变量判断缓冲区
u32 TCP_l_seq_num;	//order_number tcp序号 4字节
u32 TCP_l_ack_num;//Confirmation_number tcp确认号	 4字节

//定义TCP变量判断缓冲区
u8 TCP_conneted_state=0;
u8 TCP_data_send_state=0;
u32 TCP_data_send_num=0;
//发送中的order_number
u32 TCP_n_seq_num[5];	//发送中的order_number tcp序号 4字节

//tcp_web数据
u8 now_tcp_packet=0x00;
/***************************************************************
计算  校检和  
**************************************************************/
 
u16 Check_Code_creat1(u16 len,u8 *packet)
{
u8 i,tlen;
u16 num;
u32 checkcode=0;
	 tlen=len%2;
    if(tlen != 0)
	{
	 tlen=len-1;
	}else{
	tlen=len;
	}
	
	for(i=0;i<tlen;i=i+2)
	{
	 num=packet[i]*256;
	  checkcode+=num+packet[i+1]; 
	}
	
	if(tlen != len)
	{ num=packet[tlen]*256;
	   checkcode+=num+0x00;
	}

	if(checkcode>0xFFFF)
	{
	  num=(u16)(checkcode>>16);
	  checkcode=checkcode&0xFFFF;
      checkcode=checkcode+num;

	  num=(u16)(checkcode>>16);
      checkcode=checkcode+num;
	}
	num=(u16)checkcode;
    num=~num;
    return num;
} 

u16 Check_Code_creat2(u16 len1,u8 *packet1,u16 len2,u8 *packet2)
{
u8 i,tlen;
u16 num;
u32 checkcode=0;
    tlen=len1%2;
    if(tlen != 0)
	{
	 tlen=len1-1;
	}else{
	 tlen=len1;
	}

	for(i=0;i<tlen;i=i+2)
	{
	 num=packet1[i]*256;
	 checkcode+=num+packet1[i+1]; 
	}
	
    if(tlen != len1){num=packet1[tlen]*256;
	 checkcode+=num+0x00;}

	 tlen=len2%2;
    if(tlen != 0)
	{
	 tlen=len2-1;
	}else{
	 tlen=len2;
	}
	for(i=0;i<tlen;i=i+2)
	{
	 num=packet2[i]*256;
	 checkcode+=num+packet2[i+1]; 
	}

	if(tlen != len2){num=packet2[tlen]*256;
	 checkcode+=num+0x00;}

	if(checkcode>0xFFFF)
	{
	 num=(u16)(checkcode>>16);
	 checkcode=checkcode&0xFFFF;
     checkcode=checkcode+num;

	 num=(u16)(checkcode>>16);
     checkcode=checkcode+num;
	}
	
	num=(u16)checkcode;
	
	num=~num;
    return num;
} 

u16 Check_Code_creat3(u16 len1,u8 *packet1,u16 len2,u8 *packet2,u16 len3,u8 *packet3)
{
u8 i,tlen;
u16 num;
u32 checkcode=0;

    tlen=len1%2;
    if(tlen != 0)
	{
	 tlen=len1-1;
	}else{
	 tlen=len1;
	}
	for(i=0;i<tlen;i=i+2)
	{
	 num=packet1[i]*256;
	 checkcode+=num+packet1[i+1]; 
	}
	
    if(tlen != len1)
	{
	 num=packet1[tlen]*256;
	 checkcode+=num+0x00;
	}

	 tlen=len2%2;
    if(tlen != 0)
	{
	 tlen=len2-1;
	}else{
	 tlen=len2;
	}
    for(i=0;i<tlen;i=i+2)
	{  
	 num=packet2[i]*256;
	 checkcode+=num+packet2[i+1]; 
	}

	if(tlen != len2){num=packet2[tlen]*256;
	checkcode+=num+0x00;}
    tlen=len3%2;
    //	Uart_Send_Byte(tlen);//tlen
    if(tlen != 0)
	{
	 tlen=len3-1;
	}else{
	 tlen=len3;
	}
//		Uart_Send_Byte(tlen);//tlen
	for(i=0;i<tlen;i=i+2)
	{ // Uart_Send_Byte(i);//i
   	 num=packet3[i]*256;
	 checkcode+=num+packet3[i+1]; 
	}

	if(tlen != len3)
	{
	 num=packet3[tlen]*256;
	 checkcode+=num+0x00;
//	Uart_Send_Byte(tlen);//tlen
	}
	if(checkcode>0xFFFF)
	{
	 num=(u16)(checkcode>>16);
	 checkcode=checkcode&0xFFFF;
     checkcode=checkcode+num;

	 num=(u16)(checkcode>>16);
     checkcode=checkcode+num;
	}
	
	num=(u16)checkcode;
	num=~num;
    return num;
} 
 /*************************************************************
       
 TPID（Tag Protocol Identifier，标签协议标识）VLAN Tag中的一个字段

协议类型       对应取值
 
ARP             0x0806
 
IP              0x0800
 
MPLS            0x8847/0x8848
 
IPX             0x8137
 
IS-IS            0x8000
 
LACP             0x8809
 
802.1x            0x888E 

 */

 /************************************************************
 创建以太网协议头
 *************************************************************/
 void creat_en_head(u8 *en_dt_mac, u8 *en_local_mac,u8 en_tpid1,u8 en_tpid2)  {
	u16 i;
 	//EN以太网头，1 ARP类型
	for(i=0;i<6;i++)
 	{
	 en_head[i]=en_dt_mac[i]; //写入 对方的 mac到以太网首部
	}

	for(i=0;i<6;i++)
	{
	 en_head[6+i]=en_local_mac[i];//复制源MAC 
	}
	 en_head[12]=en_tpid1;
	 en_head[13]=en_tpid2;
}
/***************************************************************
填充 ip协议头
*************************************************************/
 void creat_IP_Head(u8 ip_xieyi,u8 ip_len,u8 *ip_source_ip,u8 *ip_dt_ip,u16 ip_mf,u16 pianyi,u16 ip_ttl)
{

u8 i;
u16 num;
IP_Head[0]=0x45;//版本 首部长度
IP_Head[1]=0;//TOS 一般服务
IP_Head[2]=ip_len/256;
IP_Head[3]=ip_len%256;//首部和数据长度之和
IP_Mark++;//标示字段+1，唯一字段
if(IP_Mark==0xffff)
IP_Mark=0x1200;	
IP_Head[4]=IP_Mark/256;	//标识 16位
IP_Head[5]=IP_Mark%256;	//标识 16位
IP_Head[6]=ip_mf; //1为分片
IP_Head[7]=pianyi;//偏移
IP_Head[8]=ip_ttl;//生存周期
 /* IP_Head[9] 是ip首部的协议字段
 	常用协议定义：
	ICMP   1
	IGMP   2
	IP     4
	TCP    6
	EGP    8
	IGP    9
	UDP    17
	IPv6   41
 	ESP    50
	OSPF   89
  */
IP_Head[9]=ip_xieyi;//协议字段
IP_Head[10]=0;
IP_Head[11]=0;//检验和
   for(i=0;i<4;i++)//源IP
   {
	IP_Head[12+i]=ip_source_ip[i];
	 //Uart_Send_Byte(ip_source_IP[i]);
   }

   for(i=0;i<4;i++)//目的IP
   {
	 IP_Head[16+i]=ip_dt_ip[i];
	//Uart_Send_Byte(dt_IP[i]);
   }
    num=Check_Code_creat1(20,IP_Head);//IP首部检验和
IP_Head[10]=num/256;
IP_Head[11]=num%256;
}

/***************************************************************
填充icmp应答包
***************************************************************/
void creat_ICMP_answer_packet(void){
 u8 i;
 u16 num;
for(i=0;i<40;i++)
 {
  ICMP[i]=DATA[34+i];//ping
 }
ICMP[0]=0;//回ping标志
ICMP[2]=0;
ICMP[3]=0;//检验和
num= Check_Code_creat1(40,ICMP);

ICMP[2]=num/256;
 ICMP[3]=num%256;//ICMP检验和
}
 
 /************************************************************
 处理arp请求 所有
 *************************************************************/
 void ARP()
{
  u16 flag=0,i;
    // Uart_Send_Byte(DATA[i]);
	 if(DATA[21]==1) //这是 请求包
	 {
		 //Printf_String("This is a arp request packet!! \r\n");	
        for(i=0;i<4;i++)
	 	{ 	
		   //Uart_Send_Byte(DATA[38+i]);
		   if(local_ip[i]!=dt_ip[i])
		   {
		     flag=1;
		    }//不是问本机IP
	 	}
         //如果是问本机，则应答
		 if(flag==0)
		 {   
		   //	Printf_String("The arp request packet call me!! \r\n");
           ARP_DATA[7]=2;//1请求	2应答
            //发送端MAC
	       for(i=0;i<6;i++)
	       {
	        ARP_DATA[8+i]=local_MAC[i];
	       }
	       //发送端IP
	       for(i=0;i<4;i++)
	        {
	         ARP_DATA[14+i]=local_ip[i];
	        }
	 	    for(i=0;i<6;i++)
	        {
	         source_MAC[i]=DATA[6+i];
	        }
	        creat_en_head(source_MAC,local_MAC,0x08,0x06) ;
	        ARP_Packet_Send();//发送ARP包	Printf_String("EN HEAD OK!! \r\n");
	}
	  	
	 }
  flag=0;
	 if(DATA[21]==2) //这是 应答包
	 {	 
        for(i=0;i<4;i++)
	 	{ 	
		   //Uart_Send_Byte(DATA[38+i]);
		   if(DATA[38+i]!=local_ip[i])
		   {
		     flag=1;
		    }//不是问本机IP
	 	}
		for(i=0;i<4;i++)
	        {
	        if(DATA[28+i]!=GW_ip[i])
					{
					  flag=1;
					}
	        }
				 if(flag==0)
		 {  
			  for(i=0;i<6;i++)
	        {
	         ga_MAC[i]=DATA[22+i];
	        }
			//sprintf(STRR,"gw%d.%d.%d.%d.%d.%d\n",ga_MAC[0],ga_MAC[1],ga_MAC[2],ga_MAC[3],ga_MAC[4],ga_MAC[5]);
			//Printf_String(STRR); 
			IP_Head[0]=3;	
		 }
	 }	
 }
 /********************************************************************
 处理 icmp ping包
 *********************************************************************/
 void icmp_anwser(u8 *icmp_dt_MAC,u8 *icmp_local_MAC,u8 *icmp_dt_ip,u8 *icmp_local_ip)
         {//led=0x00;
			u16 num; 
			   // u8 STRR[21];
					//sprintf(STRR,"icmp %d.%d.%d.%d\n",icmp_dt_ip[0],icmp_dt_ip[1],icmp_dt_ip[2],icmp_dt_ip[3]);
					//Printf_String(STRR); 
			  //Printf_String("This is a ping packet what the ip same with me!! \r\n");
			   creat_en_head(icmp_dt_MAC,icmp_local_MAC,0x08,0x00);
			   creat_IP_Head(1,60,icmp_local_ip,icmp_dt_ip,0,0,255);
			   IP_Head[4]=DATA[18];
               IP_Head[5]=DATA[19];//回复Ping要跟发送的Ping一样
			   IP_Head[10]=0;
               IP_Head[11]=0;//检验和
			    num=Check_Code_creat1(20,IP_Head);//IP首部检验和

                IP_Head[10]=num/256;
                IP_Head[11]=num%256;
	            creat_ICMP_answer_packet();
              /*  for(i=0;i<40;i++)
		 	         { 		Uart_Send_Byte(ICMP[i]);
	
			         }	 */
			   ICMP_Ping_Packet_Send();
			   }

/***************************************************************
   处理UDP包
****************************************************************/
  void udp_send(u8 *udp_dt_MAC,u8 *udp_local_MAC,u8 *udp_dt_ip,u8 *udp_local_ip,u16 udp_local_port,u16 udp_dt_port,u16 udp_data_length,u8 *packet)
  {	 //u16 udp_data_length;
      u16 num;
			//填充数据包
			//udp_data_length=10;
			//DATA[0]=0X00;
			//填充数据包结束

			//创建以太网首部
			 creat_en_head(udp_dt_MAC,udp_local_MAC,0x08,0x00);
			 creat_IP_Head(17,28+udp_data_length,udp_local_ip,udp_dt_ip,0,0,255);
			   //开始填充udp伪首部
			UDP_false_head[0]=udp_local_ip[0];	//填写源ip地址
			UDP_false_head[1]=udp_local_ip[1];
			UDP_false_head[2]=udp_local_ip[2];
			UDP_false_head[3]=udp_local_ip[3];

			UDP_false_head[4]=udp_dt_ip[0];//填写目的ip地址
			UDP_false_head[5]=udp_dt_ip[1];
			UDP_false_head[6]=udp_dt_ip[2];
			UDP_false_head[7]=udp_dt_ip[3];

			UDP_false_head[8]=0x00; // 未知字段

			UDP_false_head[9]=0x11;//17=0x11,udp为17 填写ip首部的协议字段

			UDP_false_head[10]=(udp_data_length+8)/256;//填写udp数据长度
			UDP_false_head[11]=(udp_data_length+8)%256;
			//填充udp伪首部结束

			//开始填充udp首部
			UDP_head[0]= udp_local_port/256; //填写源端口
			UDP_head[1]= udp_local_port%256;

			UDP_head[2]= udp_dt_port/256; //填写目的端口
			UDP_head[3]= udp_dt_port%256;

  			UDP_head[4]= (udp_data_length+8)/256;//填写udp数据长度
			UDP_head[5]= (udp_data_length+8)%256;

  			UDP_head[6]= 0x00;//填写udp检验和
			UDP_head[7]= 0x00;
			//填充udp首部结束

			//计算udp检验和
			num=Check_Code_creat3(12,UDP_false_head,8,UDP_head,udp_data_length,packet);

			//填写udp检验和
			UDP_head[6]= num/256;//填写udp检验和
			UDP_head[7]= num%256;

			 UDP_Packet_Send(udp_data_length);
  }

/***************************************************************
   创建TCP首部
****************************************************************/
 void creat_tcp_head(u8 *tcp_dt_MAC,u8 *tcp_local_MAC,u8 *tcp_dt_ip,u8 *tcp_local_ip,u16 tcp_source_port,u16 tcp_dt_port,u32 tcp_seq,u32 tcp_ack_n,u8 head_pianyi,u8 URG,u8 ACK,u8 PSH,u8 RST,u8 SYN,u8 FIN,u16 windows,u16 data_length,u8 *packet){
	 u8 tnum=0X00;
	 u16 num;
	 creat_en_head(tcp_dt_MAC,tcp_local_MAC,0x08,0x00);
     creat_IP_Head(6,40+data_length,tcp_local_ip,tcp_dt_ip,0,0,255);
	        //开始填充tcp伪首部
			TCP_false_head[0]=tcp_local_ip[0];	//填写源ip地址
			TCP_false_head[1]=tcp_local_ip[1];
			TCP_false_head[2]=tcp_local_ip[2];
			TCP_false_head[3]=tcp_local_ip[3];

			TCP_false_head[4]=tcp_dt_ip[0];//填写目的ip地址
			TCP_false_head[5]=tcp_dt_ip[1];
			TCP_false_head[6]=tcp_dt_ip[2];
			TCP_false_head[7]=tcp_dt_ip[3];

			TCP_false_head[8]=0x00; // 未知字段

			TCP_false_head[9]=0x06;//6=0x06,tcp为6 填写ip首部的协议字段

			TCP_false_head[10]=(data_length+20)/256;//填写tcp数据长度
			TCP_false_head[11]=(data_length+20)%256;
			//填充tcp伪首部结束
	    //开始填充tcp首部
	 TCP_head[0] = tcp_source_port/256;
     TCP_head[1] = tcp_source_port%256;//源端口
     TCP_head[2] = tcp_dt_port/256;
     TCP_head[3] = tcp_dt_port%256;//目的端口
	   //填充 tcp seq number
     TCP_head[4] = tcp_seq >> 24;
     TCP_head[5] = tcp_seq >> 16;
     TCP_head[6] = tcp_seq >> 8;
     TCP_head[7] = tcp_seq;//TCP seq序号
	    //填充 tcp ack number
     TCP_head[8] = tcp_ack_n >> 24;
     TCP_head[9] = tcp_ack_n >> 16;
     TCP_head[10] = tcp_ack_n >> 8;
     TCP_head[11] = tcp_ack_n;//TCP ACK NUM确认序号
     TCP_head[12] = head_pianyi;//TCP首部长 动态
	 tnum+= URG << 5;
	 tnum+= ACK << 4;
	 tnum+= PSH << 3;
	 tnum+= RST << 2;
	 tnum+= SYN << 1;
	 tnum+= FIN;
     TCP_head[13] = tnum;//TCP6个位标志
     TCP_head[14] = windows/256;
     TCP_head[15] = windows%256;//TCP窗口大小 最大能收的TCP数据
     TCP_head[16] = 0;
     TCP_head[17] = 0;//检验和
     TCP_head[18] = 0;
     TCP_head[19] = 0;//紧急指针

	 num=Check_Code_creat3(12,TCP_false_head,20,TCP_head,data_length,packet);
	 TCP_head[16] = num/256;
     TCP_head[17] = num%256;//检验和

    TCP_Packet_Send(data_length,packet);
		
   }
/***************************************************************
   处理TCP包
****************************************************************/
 void tcp_deal(u8 *tcpsource_MAC,u8 *tcplocal_MAC,u8 *tcpsource_ip,u8 *tcplocal_ip,u16 tcplocal_port,u16 tcpdt_port,u16 data_length)
	 {
//被连接1
	   //u16 i;
		 u32 mbr;
	    if(TCP_SYN == 1) 
        {   
	        TCP_conneted_state=0x01;//第一次握手到达
	        creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,0x2340-1,TCP_seq_num+1,0X50,0,1,0,0,1,0,net_len-58,0,DATA);//发送第二次握手
	      } 
	 
	    if(TCP_ACK == 1 && data_length <= 40)//第三次握手到达 或 数据已接收应答
	      { 
          if(TCP_conneted_state == 0x03)
		        {
		          if(TCP_data_send_state == 0x02)			 
				        {
					       creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num,0X50,0,1,0,0,0,1,net_len-58,0,DATA);//发送主动断开 
					       TCP_data_send_state = 0x00;
				        }
		        }
		
		      if(TCP_conneted_state == 0x02)
		        {
		    //creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num+data_length-40,0X50,0,1,0,0,0,0,net_len-58,0,DATA);//发送收到数据的确认
              if(TCP_data_send_state == 0x01)
			          { 
								  if(now_tcp_packet == 0x01)
									 { mbr=sizeof(index_html);
										//Uart_Send_Byte(mbr);
					          TCP_data_send_num+=255;
			                if(TCP_data_send_num <= mbr-(mbr%255)-255)
				              { //Printf_String("logo png two!! \r\n");
						            memcpy(DATA,index_html+TCP_data_send_num,255);
			                  creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num,0X50,0,1,0,0,0,0,net_len-58,255,DATA);//发送数据
				              }else{
					             if(mbr%255 == 0)
                        {
							            TCP_conneted_state=0x03;
						              TCP_data_send_state = 0x02;
													now_tcp_packet = 0x00;
						             }else{
													 //Printf_String("logo png thire!! \r\n");
						              TCP_data_send_num = mbr-(mbr%255);
							            memcpy(DATA,index_html+TCP_data_send_num,mbr%255);
			                    creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num,0X50,0,1,0,0,0,0,net_len-58,mbr%255,DATA);//发送数据
						              TCP_conneted_state=0x03;
							            TCP_data_send_state = 0x02;
													 now_tcp_packet = 0x00;
						              }
												 }
												}			

                    if(now_tcp_packet == 0x02)
									{ mbr=sizeof(logo_png);
										//Uart_Send_Byte(mbr);
					          TCP_data_send_num+=255;
			                if(TCP_data_send_num <= mbr-(mbr%255)-255)
				              { //Printf_String("logo png two!! \r\n");
						            memcpy(DATA,logo_png+TCP_data_send_num,255);
			                  creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num,0X50,0,1,0,0,0,0,net_len-58,255,DATA);//发送数据
				              }else{
					             if(mbr%255 == 0)
                        {
							            TCP_conneted_state=0x03;
						              TCP_data_send_state = 0x02;
													now_tcp_packet = 0x00;
						             }else{
													 //Printf_String("logo png thire!! \r\n");
						              TCP_data_send_num = mbr-(mbr%255);
							            memcpy(DATA,logo_png+TCP_data_send_num,mbr%255);
			                    creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num,0X50,0,1,0,0,0,0,net_len-58,mbr%255,DATA);//发送数据
						              TCP_conneted_state=0x03;
							            TCP_data_send_state = 0x02;
													 now_tcp_packet = 0x00;
						              }
												 }
												}	
	                 if(now_tcp_packet == 0x03)
									 { mbr=sizeof(error_html);
										//Uart_Send_Byte(mbr);
					          TCP_data_send_num+=255;
			                if(TCP_data_send_num <= mbr-(mbr%255)-255)
				              { //Printf_String("logo png two!! \r\n");
						            memcpy(DATA,error_html+TCP_data_send_num,255);
			                  creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num,0X50,0,1,0,0,0,0,net_len-58,255,DATA);//发送数据
				              }else{
					             if(mbr%255 == 0)
                        {
							            TCP_conneted_state=0x03;
						              TCP_data_send_state = 0x02;
													now_tcp_packet = 0x00;
						             }else{
													 //Printf_String("logo png thire!! \r\n");
						              TCP_data_send_num = mbr-(mbr%255);
							            memcpy(DATA,error_html+TCP_data_send_num,mbr%255);
			                    creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num,0X50,0,1,0,0,0,0,net_len-58,mbr%255,DATA);//发送数据
						              TCP_conneted_state=0x03;
							            TCP_data_send_state = 0x02;
													 now_tcp_packet = 0x00;
						              }
												 }
												}	

                  if(now_tcp_packet == 0x04)
									 { mbr=sizeof(zntlogo_png);
										//Uart_Send_Byte(mbr);
					          TCP_data_send_num+=255;
			                if(TCP_data_send_num <= mbr-(mbr%255)-255)
				              { //Printf_String("logo png two!! \r\n");
						            memcpy(DATA,zntlogo_png+TCP_data_send_num,255);
			                  creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num,0X50,0,1,0,0,0,0,net_len-58,255,DATA);//发送数据
				              }else{
					             if(mbr%255 == 0)
                        {
							            TCP_conneted_state=0x03;
						              TCP_data_send_state = 0x02;
													now_tcp_packet = 0x00;
						             }else{
													 //Printf_String("logo png thire!! \r\n");
						              TCP_data_send_num = mbr-(mbr%255);
							            memcpy(DATA,zntlogo_png+TCP_data_send_num,mbr%255);
			                    creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num,0X50,0,1,0,0,0,0,net_len-58,mbr%255,DATA);//发送数据
						              TCP_conneted_state=0x03;
							            TCP_data_send_state = 0x02;
													 now_tcp_packet = 0x00;
						              }
												 }
												}	

                     if(now_tcp_packet == 0x05)
									 { mbr=sizeof(col_html);
										//Uart_Send_Byte(mbr);
					          TCP_data_send_num+=255;
			                if(TCP_data_send_num <= mbr-(mbr%255)-255)
				              { //Printf_String("logo png two!! \r\n");
						            memcpy(DATA,col_html+TCP_data_send_num,255);
			                  creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num,0X50,0,1,0,0,0,0,net_len-58,255,DATA);//发送数据
				              }else{
					             if(mbr%255 == 0)
                        {
							            TCP_conneted_state=0x03;
						              TCP_data_send_state = 0x02;
													now_tcp_packet = 0x00;
						             }else{
													 //Printf_String("logo png thire!! \r\n");
						              TCP_data_send_num = mbr-(mbr%255);
							            memcpy(DATA,col_html+TCP_data_send_num,mbr%255);
			                    creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num,0X50,0,1,0,0,0,0,net_len-58,mbr%255,DATA);//发送数据
						              TCP_conneted_state=0x03;
							            TCP_data_send_state = 0x02;
													 now_tcp_packet = 0x00;
						              
												 }
												 }
												}	

                    											
                      											
				       }				
		         }
		 
		 if(TCP_conneted_state == 0x01)
		 {
			 TCP_conneted_state=0x02;//已收到第三次握手
		 } 
		 
	 }
	 
	 	 if(TCP_ACK == 1 && data_length > 40 && TCP_PSH == 0)//客户端数据到达
	 { 
		 if(TCP_conneted_state == 0x02)
		 {
			 
		   creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num+data_length-40,0X50,0,1,0,0,0,0,net_len-58,0,DATA);//发送收到数据的确认

			 
		 } 
	 }
	 
	   if(TCP_ACK == 1 && TCP_PSH == 1)//客户端的最后一个数据包到达
		 {  
			 //if(TCP_conneted_state == 0x02 && TCP_data_send_state == 0x00)//已收到最后一个数据包
		   //{
				 if (memcmp(&DATA[54],"GET / ",6) ==0)
           {  
						 //Printf_String("idex one!! \r\n");
						 now_tcp_packet=0x01;
					    creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num+data_length-40,0X50,0,1,0,0,0,0,net_len-58,0,DATA);//发送收到数据的确认
				      memcpy(DATA,index_html,255);
			        creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num,0X50,0,1,0,0,0,0,net_len-58,255,DATA);//发送数据
				      TCP_data_send_num =0;
					    TCP_data_send_state = 0x01;
				   } else{
					 
				if (memcmp(&DATA[54],"GET /logo.png",13) ==0)
           {  
						  
						  now_tcp_packet=0x02;
					    creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num+data_length-40,0X50,0,1,0,0,0,0,net_len-58,0,DATA);//发送收到数据的确认
				      memcpy(DATA,logo_png,255);
			        creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num,0X50,0,1,0,0,0,0,net_len-58,255,DATA);//发送数据
				      TCP_data_send_num =0;
					    TCP_data_send_state = 0x01;
				   }else{
						 
						 if (memcmp(&DATA[54],"GET /zntlogo.png",16) ==0)
           {  
						  
						  now_tcp_packet=0x04;
					    creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num+data_length-40,0X50,0,1,0,0,0,0,net_len-58,0,DATA);//发送收到数据的确认
				      memcpy(DATA,zntlogo_png,255);
			        creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num,0X50,0,1,0,0,0,0,net_len-58,255,DATA);//发送数据
				      TCP_data_send_num =0;
					    TCP_data_send_state = 0x01;
				   }else{
						 
						 if (memcmp(&DATA[54],"GET /col",8) ==0)
           {  
						  
						  now_tcp_packet=0x05;
					    creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num+data_length-40,0X50,0,1,0,0,0,0,net_len-58,0,DATA);//发送收到数据的确认
				      memcpy(DATA,col_html,255);
			        creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num,0X50,0,1,0,0,0,0,net_len-58,255,DATA);//发送数据
				      TCP_data_send_num =0;
					    TCP_data_send_state = 0x01;
				   }else{
						 
						 if (memcmp(&DATA[54],"GET /?run",9) ==0)
           { 
						  now_tcp_packet=0x06;
					    creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num+data_length-40,0X50,0,1,0,0,0,0,net_len-58,0,DATA);//发送收到数据的确认
				      memcpy(DATA,"ok",2);
			        creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num,0X50,0,1,0,0,0,0,net_len-58,2,DATA);//发送数据
				      TCP_conneted_state=0x03;
						  TCP_data_send_state = 0x02;
							now_tcp_packet = 0x00;
				   }else{
						 
						  if (memcmp(&DATA[54],"GET /?close",11) ==0)
           {  
						  now_tcp_packet=0x06;
					    creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num+data_length-40,0X50,0,1,0,0,0,0,net_len-58,0,DATA);//发送收到数据的确认
				      memcpy(DATA,"ok",2);
			        creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num,0X50,0,1,0,0,0,0,net_len-58,2,DATA);//发送数据
              TCP_conneted_state=0x03;
						  TCP_data_send_state = 0x02;
							now_tcp_packet = 0x00;
				   }else{
					    now_tcp_packet=0x03;
					    creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num+data_length-40,0X50,0,1,0,0,0,0,net_len-58,0,DATA);//发送收到数据的确认
				      memcpy(DATA,error_html,255);
			        creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num,0X50,0,1,0,0,0,0,net_len-58,255,DATA);//发送数据
				      TCP_data_send_num =0;
					    TCP_data_send_state = 0x01;
					         }
					       }
					     }
						}
					 }
				 
				 }					 
		   //} 

		 }
			if(TCP_ACK == 1 && TCP_FIN == 1 && TCP_conneted_state == 0x03)//服务端主动断开  
	    {  
				creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num + 1,0X50,0,1,0,0,0,0,net_len-58,0,DATA);//发送收到数据的确认
			  TCP_conneted_state = 0x04; 
			}
			
			if(TCP_ACK == 1 && TCP_FIN == 1 && TCP_conneted_state == 0x02)//客户主动断开 
	    {  
				creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num + 1,0X50,0,1,0,0,0,0,net_len-58,0,DATA);//发送收到数据的确认
				creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num + 1,0X50,0,1,0,0,0,1,net_len-58,0,DATA); //发送主动断开
			  TCP_conneted_state = 0x04;
			}
	 
   }
 /************************************************************
 发送arp请求 所有
 *************************************************************/
 void ARP_ask()
{
  u16 i;  
		   //	Printf_String("The arp request packet call me!! \r\n");
           ARP_DATA[7]=1;//1请求	2应答
            //发送端MAC
	       for(i=0;i<6;i++)
	       {
	        ARP_DATA[8+i]=local_MAC[i];
	       }
	       //发送端IP
	       for(i=0;i<4;i++)
	        {
	         ARP_DATA[14+i]=local_ip[i];
	        }
					for(i=0;i<4;i++)
		      {
		       ARP_DATA[24+i]=GW_ip[i];
		       }
	 	    for(i=0;i<6;i++)
	        {
	         source_MAC[i]=0xff;
	        }
					
	        creat_en_head(source_MAC,local_MAC,0x08,0x06) ;
	        ARP_Packet_Send();//发送ARP包	Printf_String("EN HEAD OK!! \r\n");

	  	
	 }

/***************************************************************
   主程序
****************************************************************/

void init(void)
{	
		//--------------------------- CLK INIT, HSE PLL ----------------------------
		ErrorStatus HSEStartUpStatus;
		//RCC reset
		RCC_DeInit();
		//开启外部时钟 并执行初始化
		RCC_HSEConfig(RCC_HSE_ON); 
		//等待外部时钟准备好
		HSEStartUpStatus = RCC_WaitForHSEStartUp();
		//启动失败 在这里等待
		while(HSEStartUpStatus == ERROR);
		//设置内部总线时钟
		RCC_HCLKConfig(RCC_SYSCLK_Div1);
		RCC_PCLK1Config(RCC_HCLK_Div1);
		RCC_PCLK2Config(RCC_HCLK_Div1);
		//外部时钟为8M 这里倍频到72M
		RCC_PLLConfig(RCC_PLLSource_HSE_Div1, RCC_PLLMul_9);
		RCC_PLLCmd(ENABLE); 
		while(RCC_GetFlagStatus(RCC_FLAG_PLLRDY) == RESET);
		RCC_SYSCLKConfig(RCC_SYSCLKSource_PLLCLK);
		while(RCC_GetSYSCLKSource() != 0x08);

		//----------------------------- CLOSE HSI ---------------------------
		//关闭内部时钟HSI
		RCC_HSICmd(DISABLE);	

		//--------------------------- OPEN GPIO CLK -------------------------
		RCC_APB2PeriphClockCmd(RCC_APB2Periph_GPIOA, ENABLE);
		RCC_APB2PeriphClockCmd(RCC_APB2Periph_GPIOB, ENABLE);
		RCC_APB2PeriphClockCmd(RCC_APB2Periph_GPIOC, ENABLE);
		RCC_APB2PeriphClockCmd(RCC_APB2Periph_GPIOD, ENABLE);
		//开启SPI接口
		SPION();
}
	//定时器配置并开启 使用定时器3
void TimeON(void)
{
		TIM_TimeBaseInitTypeDef TIM_TimeBaseStructure;
		NVIC_InitTypeDef NVIC_InitStructure;
		//开启定时器外设时钟
		RCC_APB1PeriphClockCmd(RCC_APB1Periph_TIM3, ENABLE);
		//配置定时器参数
		TIM_DeInit(TIM3); 
		TIM_TimeBaseStructure.TIM_Period = 50000; 								 	//50ms定时 20s=20000us=50ms*400			 
		TIM_TimeBaseStructure.TIM_Prescaler = (72000000/1000000 - 1);              
		TIM_TimeBaseStructure.TIM_ClockDivision = TIM_CKD_DIV1;     
		TIM_TimeBaseStructure.TIM_CounterMode = TIM_CounterMode_Up; 
		TIM_TimeBaseStructure.TIM_RepetitionCounter = 0;
		TIM_TimeBaseInit(TIM3, &TIM_TimeBaseStructure);	
		//中断配置
		NVIC_InitStructure.NVIC_IRQChannel = TIM3_IRQn;
		NVIC_InitStructure.NVIC_IRQChannelPreemptionPriority = 2;  //抢占优先级2 低优先级别中断 
		NVIC_InitStructure.NVIC_IRQChannelSubPriority = 0;		  	 //响应优先级0 高级别的响应中断
		NVIC_InitStructure.NVIC_IRQChannelCmd = ENABLE;	
		NVIC_Init(&NVIC_InitStructure);	  
		//开中断
		TIM_ClearFlag(TIM3, TIM_FLAG_Update);					  
		TIM_ITConfig(TIM3, TIM_IT_Update, ENABLE); 
		//开启定时器			 
		TIM_Cmd(TIM3, ENABLE); 
}

//定时器中断处理 从stm32f10x_it.c添加
void Time_IntHandle(void)
{
		//清中断标识
		TIM_ClearFlag(TIM3, TIM_FLAG_Update);
		//---------------- 中断处理  ---------------------
dstimes++;
}	
int main()
{	u8 wz;
	u16 i;		 //循环变量
	u16 flag=0;	 //临时标志
	u16 tpid; //tpid （Tag Protocol Identifier，标签协议标识）VLAN Tag中的一个字段
	char STRR[50];
	//SystemInit();
	init();
	delay_init();
  	//TFT初始化
	LCD_Init();
	//开背光 清屏
	Driver_LcdBacklight(True);
	LCD_ClrScr(BLUE);
	//开机LOGO
	LCD_DisASCString16x8(3, 10, "IT", ORANGE, BLUE);
	LCD_DisGB2312String16x16(19, 10, "知识库论坛", ORANGE, BLUE);
  LCD_DisGB2312String16x16(50, 26, "硬件初始化中..", WHITE, BLUE);
		LCD_DisASCString16x8(50, 200, "WWW.ITZHISHIKU.COM", PURPLE, BLUE);
	enc28j60_init();
		//中断配置 2-level interrupt 
		NVIC_PriorityGroupConfig(NVIC_PriorityGroup_2);
			LCD_ClrScr(BLUE);
		LCD_DisASCString16x8(3, 10, "IT", ORANGE, BLUE);
	  LCD_DisGB2312String16x16(19, 10, "知识库论坛", ORANGE, BLUE);
	LCD_DisGB2312String16x16(50, 26, "硬件初始化完成", WHITE, BLUE);
			LCD_DisASCString16x8(50, 200, "WWW.ITZHISHIKU.COM", PURPLE, BLUE);
		//开总中断
		__enable_irq(); 
		
		//开定时器
		TimeON();
		LCD_ClrScr(BLUE);
		LCD_DisASCString16x8(3, 10, "IT", ORANGE, BLUE);
	  LCD_DisGB2312String16x16(19, 10, "知识库论坛", ORANGE, BLUE);
		LCD_DisGB2312String16x16(50, 26, "网络初始化中...", WHITE, BLUE);
	 	LCD_DisASCString16x8(50, 200, "WWW.ITZHISHIKU.COM", PURPLE, BLUE);
  //TIM3_Int_Init(2-1,8400-1);	
  ARP_ask();
	dstimes2=0;

	while(IP_Head[0]==0 &&  dstimes<400)
     {  
			 ARP_ask();
			  delay_ms(5);
		   len=enc28j60PacketReceive(net_len, DATA);
			 if(len >= 18)
         {
				   if(DATA[13]==0x06){
	                 //arp data
	                   ARP();	  //下次考虑把数据都串口输出，观察是否数据判断出错!!
	                   }
				 }
		 }
		LCD_ClrScr(BLUE);
		LCD_DisASCString16x8(3, 10, "IT", ORANGE, BLUE);
	  LCD_DisGB2312String16x16(19, 10, "知识库论坛", ORANGE, BLUE);
		LCD_DisGB2312String16x16(50, 26, "网络初始化完成", WHITE, BLUE);
		LCD_DisASCString16x8(50, 200, "WWW.ITZHISHIKU.COM", BLACK, BLUE);
		 dstimes=0;
				 memcpy(DATA,up,26);
					udp_send(ga_MAC,local_MAC,br_ip,local_ip,7001,7001,26,DATA);
					
while(1)
			{ 
				//icmp_anwser(ga_MAC,local_MAC,GW_ip,local_ip);	
				
				//delay_ms(300);		
				if(dstimes>=400)
          { 
					 memcpy(DATA,up,26);
					 udp_send(ga_MAC,local_MAC,br_ip,local_ip,7001,7001,26,DATA);
						dstimes=0;
					 }
					 //memcpy(DATA,up,26);
					 //udp_send(ga_MAC,local_MAC,br_ip,local_ip,7001,1001,26,DATA);
        //Printf_String("working!! \r\n");
       /**************获取数据开始*****************/  
	   len=enc28j60PacketReceive(net_len, DATA);
        /**************获取数据尾部*****************/
	         if(len >= 18){
						 //LCD_DisGB2312String16x16(80, 12, "数据", WHITE, GREEN);
						       //memcpy(DATA,up,26);
					         //udp_send(ga_MAC,local_MAC,br_ip,local_ip,4001,4001,26,DATA);
               /**************大于18的数据处理开始*****************/
          	  /*
                TPID（Tag Protocol Identifier，标签协议标识）VLAN Tag中的一个字段
                协议类型       对应取值
                 ARP             0x0806
                 IP              0x0800
                 MPLS            0x8847/0x8848
                 IPX             0x8137
                 IS-IS            0x8000
                 LACP             0x8809
                 802.1x            0x888E 
                                         */
                /****************获取包类型开始**********/
                tpid = DATA[13];
						 						 

               /***************获取包类型尾部***********/
                   /***************arp包数据判断开始***************************/
                    if(tpid==0x06){
	                 //arp data
	                 //Printf_String("This is a arp packet!! \r\n");
	 	               for(i=0;i<4;i++)
	 	                  {
		                   dt_ip[i]=DATA[38+i]; //save packet mac
	 	                   }
	                   ARP();	  //下次考虑把数据都串口输出，观察是否数据判断出错!!
	                   }
                     /***************arp包数据判断结尾**************************/

                    /***************ip包处理开始***************************/
                     if(tpid==0x00){
	                      //ip data
	                      //Printf_String("This is a ip packet!! \r\n");
				       	  /***************ip地址和物理地址缓存开始***************************/
                          for(i=0;i<6;i++)
	 	                   { 	
	                        dt_MAC[i]=DATA[i]; //save packet mac
					       }
	  		 		      for(i=0;i<6;i++)
	                       {
	                        source_MAC[i]=DATA[6+i];
                           }
	 	                  for(i=0;i<4;i++)
	 	                   {
		                    dt_ip[i]=DATA[30+i]; //save packet ip
	 	                   }
                          for(i=0;i<4;i++)
	 	                   {
		                    source_ip[i]=DATA[26+i]; //save packet ip
	 	                    }

							
				    		/***************ip地址和物理地址缓存尾部***************************/	
                           flag=0;
	                       for(i=0;i<6;i++)
	 	                    { 	
		                       if(dt_MAC[i]!=local_MAC[i])
			    		        {
		                          flag=1;
	                              //Printf_String("the mac not same with me!! \r\n");
		                         }//不是问本机mac
	                        }

	 	                    for(i=0;i<4;i++)
	 	                     {
		                       if(dt_ip[i]!=local_ip[i]) 
							     {
		                             flag=1;//不是问本机IP
			                         //Printf_String("the ip not same with me!! \r\n");	
			                       }
	 	                      }
                            /***************ip包数据判断尾部***************************/

                                 /***************ip包数据处理开始***************************/
	                            	if(flag==0)  {
																	
																	            
		                                           //Printf_String("This is a ip packet what the ip same with me!! \r\n");
			 
			                                       /***************icmp包数据判断与处理开始***************************/
					                                 //ICMP(仅ping请求) 
			                                        if(DATA[23]==0x01&&DATA[34]==0x08)
			                                           {    //Printf_String("This is a icmp packet!! \r\n");
		                                                	icmp_anwser(source_MAC,local_MAC,source_ip,local_ip);	
                                                       if(wz>=9){wz=0;}
						                                           sprintf(STRR,"ICMP %d.%d.%d.%d \n",source_ip[0],source_ip[1],source_ip[2],source_ip[3]);
			 							                               		 LCD_DisASCString16x8(31, 50+wz*16+1, (u8 *)STRR, WHITE, BLUE);
						                                           wz++;		                                          
																								 }
		                                          	/***************icmp包数据判断与处理尾部***************************/

		                                        	/***************udp包数据判断与处理开始***************************/
			                                         //UDP 
			                                         if(DATA[23]==0x11)
		                                              	{
														                          UDP_source_port=DATA[34]*256+DATA[35];//来源Port
				                                              UDP_dt_port=DATA[36]*256+DATA[37];//目的Port
														                          if(memcmp(&DATA[55],"open",4) ==0)
                                                         {
																																memcpy(DATA,callback,32);
					                                                      udp_send(ga_MAC,local_MAC,br_ip,local_ip,7001,7001,32,DATA);
																												 }
																												if(memcmp(&DATA[55],"close",5) ==0)
                                                         {
																																memcpy(DATA,callback,32);
														                                    //udp_send(source_MAC,local_MAC,source_ip,local_ip,UDP_dt_port,UDP_source_port,32,DATA);
			                                                          	udp_send(ga_MAC,local_MAC,br_ip,local_ip,7001,7001,32,DATA);
																												 }
																												 
																												 
														                          if (memcmp(&DATA[42],"open",4) ==0)
                                                              {
																																memcpy(DATA,"the light has been opened\r\n",27);
														                                    udp_send(source_MAC,local_MAC,source_ip,local_ip,UDP_dt_port,UDP_source_port,27,DATA);
		                                                      	    
	                                                           		 }
                                                           	if (memcmp(&DATA[42],"close",4) ==0)
                                                              {
																																memcpy(DATA,"the light is off \r\n",21);
														                                    udp_send(source_MAC,local_MAC,source_ip,local_ip,UDP_dt_port,UDP_source_port,21,DATA);
			                                                   }			  	 
				                                        // udp
                                                               if(wz>=9){wz=0;}
						                                                    sprintf(STRR,"UDP %d.%d.%d.%d \n",source_ip[0],source_ip[1],source_ip[2],source_ip[3]);
			 									                                        LCD_DisASCString16x8(31, 50+wz*16+1, (u8 *)STRR, WHITE, BLUE);
						                                                    wz++;
					                                 /***************UDP包数据判断与处理尾部***************************/
                                                      }//UDP结束

													  /***************tcp包数据判断与处理开始***************************/
                  									  //tcp
													   if(DATA[23]==0x06)
		                                              	{ TCP_source_port=DATA[34]*256+DATA[35];//来源Port
				                                          TCP_dt_port=DATA[36]*256+DATA[37];//目的Port
			                                     //Printf_String(STRR); 
														  //开始缓存tcp序号
														  TCP_seq_num=(u32)(DATA[38])<<24;
				                                          TCP_seq_num+=(u32)(DATA[39])<<16;
				                                          TCP_seq_num+=(u32)(DATA[40])<<8;
				                                          TCP_seq_num+=(u32)(DATA[41]);
														  // 缓存tcp序号结束

														  //开始缓存tcp确认号
														  TCP_ack_num=(u32)(DATA[42])<<24;
				                                          TCP_ack_num+=(u32)(DATA[43])<<16;
				                                          TCP_ack_num+=(u32)(DATA[44])<<8;
				                                          TCP_ack_num+=(u32)(DATA[45]);
														  //缓存tcp确认号结束
														   
														  //开始缓存各类字段位
														  TCP_URG=((u8)(DATA[47]<<2))>>7;//紧急
														  TCP_ACK=((u8)(DATA[47]<<3))>>7;//确认字段位
														  TCP_PSH=((u8)(DATA[47]<<4))>>7;//推送
														  TCP_RST=((u8)(DATA[47]<<5))>>7;//复位
														  TCP_SYN=((u8)(DATA[47]<<6))>>7;//同步
														  TCP_FIN=((u8)(DATA[47]<<7))>>7;//终止
														  //缓存各类字段位结束
														   /*Uart_Send_Byte(TCP_URG);
														   Uart_Send_Byte(TCP_ACK);
														   Uart_Send_Byte(TCP_PSH);
														   Uart_Send_Byte(TCP_RST);
														   Uart_Send_Byte(TCP_SYN);
														   Uart_Send_Byte(TCP_FIN);
														   */
														   tcp_deal(source_MAC,local_MAC,source_ip,local_ip,TCP_dt_port,TCP_source_port,DATA[16]*256+DATA[17]);
                                                           
														     if(wz>=9){wz=0;}
						                       sprintf(STRR,"TCP %d.%d.%d.%d \n",source_ip[0],source_ip[1],source_ip[2],source_ip[3]);
			 									           LCD_DisASCString16x8(31, 50+wz*16+1, (u8 *)STRR, WHITE, BLUE);
						                       wz++;
														     
              											   }
	
		              /***************ip包数据处理尾部***************************/ 
		              }
		             /***************ip包处理尾部***************************/
		             }
	           /**************数据大于18尾部 len>=18的}*****************/
	          }
	 /**************数据处理尾部 while的}*****************/ 
							
			}
}


