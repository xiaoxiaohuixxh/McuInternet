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
u8 GW_ip[4]={192,168,137,1};//����
u8 ga_MAC[6]={0x00,0x00,0X66,0X18,0X3B,0X44};//MAC  08-62-66-18-3B-44

u16 len;
//���ز���
u8 local_ip[4]={192,168,137,150};
u8 local_MAC[6]={0x00,0x12,0X34,0X56,0X78,0X90};//MAC

//�������ݱ��е�Դip��ַ�������ַ
u8 source_ip[4]={0};
u8 source_MAC[6]={0};

//�������ݰ��е�Ŀ��ip��ַ�������ַ
u8 dt_ip[4]={0};
u8 dt_MAC[6]={0};//destination

//����arp������
u8 ARP_DATA[28]={0,1,8,0,6,4,0,1};

//��̫���ײ�
u8 en_head[14]={0};

//�������ݻ�����
u8 DATA[net_len]={0};

//����IP�ײ�
u8 IP_Head[20]={0};

//IP�ײ��ı�ʶ�ֶ�
u16 IP_Mark=0x1200;

//����ICMP���Ļ�����
u8 ICMP[40]={0,0,0,0};

//����UDP�ײ���α�ײ�������
u8 UDP_head[8]={0};
u8 UDP_false_head[12]={0};

//����UDPԴ�˿ں�Ŀ�Ķ˿ڻ�����
u16 UDP_source_port;
u16 UDP_dt_port;

//����TCP�ײ���α�ײ�������
u8 TCP_head[20]={0};
u8 TCP_false_head[12]={0};

//����TCPԴ�˿ں�Ŀ�Ķ˿ڻ�����
u16 TCP_source_port;
u16 TCP_dt_port;

//����TCP����������
u32 TCP_seq_num;	//order_number tcp��� 4�ֽ�
u32 TCP_ack_num;//Confirmation_number tcpȷ�Ϻ�	 4�ֽ�
u8  TCP_URG;//����URG(URGent)
u8  TCP_ACK;//ACKnowlegment ȷ�Ϻ��ֶ�
u8  TCP_PSH;//����PSH (PuSH)
u8  TCP_RST;//��λRST(ReSeT)	����λ
u8  TCP_SYN;//ͬ��SYN ͬ��λ
u8  TCP_FIN;//��ֹFIN (FINis ��ֹλ)

//����TCP�����жϻ�����
u32 TCP_l_seq_num;	//order_number tcp��� 4�ֽ�
u32 TCP_l_ack_num;//Confirmation_number tcpȷ�Ϻ�	 4�ֽ�

//����TCP�����жϻ�����
u8 TCP_conneted_state=0;
u8 TCP_data_send_state=0;
u32 TCP_data_send_num=0;
//�����е�order_number
u32 TCP_n_seq_num[5];	//�����е�order_number tcp��� 4�ֽ�

//tcp_web����
u8 now_tcp_packet=0x00;
/***************************************************************
����  У���  
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
       
 TPID��Tag Protocol Identifier����ǩЭ���ʶ��VLAN Tag�е�һ���ֶ�

Э������       ��Ӧȡֵ
 
ARP             0x0806
 
IP              0x0800
 
MPLS            0x8847/0x8848
 
IPX             0x8137
 
IS-IS            0x8000
 
LACP             0x8809
 
802.1x            0x888E 

 */

 /************************************************************
 ������̫��Э��ͷ
 *************************************************************/
 void creat_en_head(u8 *en_dt_mac, u8 *en_local_mac,u8 en_tpid1,u8 en_tpid2)  {
	u16 i;
 	//EN��̫��ͷ��1 ARP����
	for(i=0;i<6;i++)
 	{
	 en_head[i]=en_dt_mac[i]; //д�� �Է��� mac����̫���ײ�
	}

	for(i=0;i<6;i++)
	{
	 en_head[6+i]=en_local_mac[i];//����ԴMAC 
	}
	 en_head[12]=en_tpid1;
	 en_head[13]=en_tpid2;
}
/***************************************************************
��� ipЭ��ͷ
*************************************************************/
 void creat_IP_Head(u8 ip_xieyi,u8 ip_len,u8 *ip_source_ip,u8 *ip_dt_ip,u16 ip_mf,u16 pianyi,u16 ip_ttl)
{

u8 i;
u16 num;
IP_Head[0]=0x45;//�汾 �ײ�����
IP_Head[1]=0;//TOS һ�����
IP_Head[2]=ip_len/256;
IP_Head[3]=ip_len%256;//�ײ������ݳ���֮��
IP_Mark++;//��ʾ�ֶ�+1��Ψһ�ֶ�
if(IP_Mark==0xffff)
IP_Mark=0x1200;	
IP_Head[4]=IP_Mark/256;	//��ʶ 16λ
IP_Head[5]=IP_Mark%256;	//��ʶ 16λ
IP_Head[6]=ip_mf; //1Ϊ��Ƭ
IP_Head[7]=pianyi;//ƫ��
IP_Head[8]=ip_ttl;//��������
 /* IP_Head[9] ��ip�ײ���Э���ֶ�
 	����Э�鶨�壺
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
IP_Head[9]=ip_xieyi;//Э���ֶ�
IP_Head[10]=0;
IP_Head[11]=0;//�����
   for(i=0;i<4;i++)//ԴIP
   {
	IP_Head[12+i]=ip_source_ip[i];
	 //Uart_Send_Byte(ip_source_IP[i]);
   }

   for(i=0;i<4;i++)//Ŀ��IP
   {
	 IP_Head[16+i]=ip_dt_ip[i];
	//Uart_Send_Byte(dt_IP[i]);
   }
    num=Check_Code_creat1(20,IP_Head);//IP�ײ������
IP_Head[10]=num/256;
IP_Head[11]=num%256;
}

/***************************************************************
���icmpӦ���
***************************************************************/
void creat_ICMP_answer_packet(void){
 u8 i;
 u16 num;
for(i=0;i<40;i++)
 {
  ICMP[i]=DATA[34+i];//ping
 }
ICMP[0]=0;//��ping��־
ICMP[2]=0;
ICMP[3]=0;//�����
num= Check_Code_creat1(40,ICMP);

ICMP[2]=num/256;
 ICMP[3]=num%256;//ICMP�����
}
 
 /************************************************************
 ����arp���� ����
 *************************************************************/
 void ARP()
{
  u16 flag=0,i;
    // Uart_Send_Byte(DATA[i]);
	 if(DATA[21]==1) //���� �����
	 {
		 //Printf_String("This is a arp request packet!! \r\n");	
        for(i=0;i<4;i++)
	 	{ 	
		   //Uart_Send_Byte(DATA[38+i]);
		   if(local_ip[i]!=dt_ip[i])
		   {
		     flag=1;
		    }//�����ʱ���IP
	 	}
         //������ʱ�������Ӧ��
		 if(flag==0)
		 {   
		   //	Printf_String("The arp request packet call me!! \r\n");
           ARP_DATA[7]=2;//1����	2Ӧ��
            //���Ͷ�MAC
	       for(i=0;i<6;i++)
	       {
	        ARP_DATA[8+i]=local_MAC[i];
	       }
	       //���Ͷ�IP
	       for(i=0;i<4;i++)
	        {
	         ARP_DATA[14+i]=local_ip[i];
	        }
	 	    for(i=0;i<6;i++)
	        {
	         source_MAC[i]=DATA[6+i];
	        }
	        creat_en_head(source_MAC,local_MAC,0x08,0x06) ;
	        ARP_Packet_Send();//����ARP��	Printf_String("EN HEAD OK!! \r\n");
	}
	  	
	 }
  flag=0;
	 if(DATA[21]==2) //���� Ӧ���
	 {	 
        for(i=0;i<4;i++)
	 	{ 	
		   //Uart_Send_Byte(DATA[38+i]);
		   if(DATA[38+i]!=local_ip[i])
		   {
		     flag=1;
		    }//�����ʱ���IP
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
 ���� icmp ping��
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
               IP_Head[5]=DATA[19];//�ظ�PingҪ�����͵�Pingһ��
			   IP_Head[10]=0;
               IP_Head[11]=0;//�����
			    num=Check_Code_creat1(20,IP_Head);//IP�ײ������

                IP_Head[10]=num/256;
                IP_Head[11]=num%256;
	            creat_ICMP_answer_packet();
              /*  for(i=0;i<40;i++)
		 	         { 		Uart_Send_Byte(ICMP[i]);
	
			         }	 */
			   ICMP_Ping_Packet_Send();
			   }

/***************************************************************
   ����UDP��
****************************************************************/
  void udp_send(u8 *udp_dt_MAC,u8 *udp_local_MAC,u8 *udp_dt_ip,u8 *udp_local_ip,u16 udp_local_port,u16 udp_dt_port,u16 udp_data_length,u8 *packet)
  {	 //u16 udp_data_length;
      u16 num;
			//������ݰ�
			//udp_data_length=10;
			//DATA[0]=0X00;
			//������ݰ�����

			//������̫���ײ�
			 creat_en_head(udp_dt_MAC,udp_local_MAC,0x08,0x00);
			 creat_IP_Head(17,28+udp_data_length,udp_local_ip,udp_dt_ip,0,0,255);
			   //��ʼ���udpα�ײ�
			UDP_false_head[0]=udp_local_ip[0];	//��дԴip��ַ
			UDP_false_head[1]=udp_local_ip[1];
			UDP_false_head[2]=udp_local_ip[2];
			UDP_false_head[3]=udp_local_ip[3];

			UDP_false_head[4]=udp_dt_ip[0];//��дĿ��ip��ַ
			UDP_false_head[5]=udp_dt_ip[1];
			UDP_false_head[6]=udp_dt_ip[2];
			UDP_false_head[7]=udp_dt_ip[3];

			UDP_false_head[8]=0x00; // δ֪�ֶ�

			UDP_false_head[9]=0x11;//17=0x11,udpΪ17 ��дip�ײ���Э���ֶ�

			UDP_false_head[10]=(udp_data_length+8)/256;//��дudp���ݳ���
			UDP_false_head[11]=(udp_data_length+8)%256;
			//���udpα�ײ�����

			//��ʼ���udp�ײ�
			UDP_head[0]= udp_local_port/256; //��дԴ�˿�
			UDP_head[1]= udp_local_port%256;

			UDP_head[2]= udp_dt_port/256; //��дĿ�Ķ˿�
			UDP_head[3]= udp_dt_port%256;

  			UDP_head[4]= (udp_data_length+8)/256;//��дudp���ݳ���
			UDP_head[5]= (udp_data_length+8)%256;

  			UDP_head[6]= 0x00;//��дudp�����
			UDP_head[7]= 0x00;
			//���udp�ײ�����

			//����udp�����
			num=Check_Code_creat3(12,UDP_false_head,8,UDP_head,udp_data_length,packet);

			//��дudp�����
			UDP_head[6]= num/256;//��дudp�����
			UDP_head[7]= num%256;

			 UDP_Packet_Send(udp_data_length);
  }

/***************************************************************
   ����TCP�ײ�
****************************************************************/
 void creat_tcp_head(u8 *tcp_dt_MAC,u8 *tcp_local_MAC,u8 *tcp_dt_ip,u8 *tcp_local_ip,u16 tcp_source_port,u16 tcp_dt_port,u32 tcp_seq,u32 tcp_ack_n,u8 head_pianyi,u8 URG,u8 ACK,u8 PSH,u8 RST,u8 SYN,u8 FIN,u16 windows,u16 data_length,u8 *packet){
	 u8 tnum=0X00;
	 u16 num;
	 creat_en_head(tcp_dt_MAC,tcp_local_MAC,0x08,0x00);
     creat_IP_Head(6,40+data_length,tcp_local_ip,tcp_dt_ip,0,0,255);
	        //��ʼ���tcpα�ײ�
			TCP_false_head[0]=tcp_local_ip[0];	//��дԴip��ַ
			TCP_false_head[1]=tcp_local_ip[1];
			TCP_false_head[2]=tcp_local_ip[2];
			TCP_false_head[3]=tcp_local_ip[3];

			TCP_false_head[4]=tcp_dt_ip[0];//��дĿ��ip��ַ
			TCP_false_head[5]=tcp_dt_ip[1];
			TCP_false_head[6]=tcp_dt_ip[2];
			TCP_false_head[7]=tcp_dt_ip[3];

			TCP_false_head[8]=0x00; // δ֪�ֶ�

			TCP_false_head[9]=0x06;//6=0x06,tcpΪ6 ��дip�ײ���Э���ֶ�

			TCP_false_head[10]=(data_length+20)/256;//��дtcp���ݳ���
			TCP_false_head[11]=(data_length+20)%256;
			//���tcpα�ײ�����
	    //��ʼ���tcp�ײ�
	 TCP_head[0] = tcp_source_port/256;
     TCP_head[1] = tcp_source_port%256;//Դ�˿�
     TCP_head[2] = tcp_dt_port/256;
     TCP_head[3] = tcp_dt_port%256;//Ŀ�Ķ˿�
	   //��� tcp seq number
     TCP_head[4] = tcp_seq >> 24;
     TCP_head[5] = tcp_seq >> 16;
     TCP_head[6] = tcp_seq >> 8;
     TCP_head[7] = tcp_seq;//TCP seq���
	    //��� tcp ack number
     TCP_head[8] = tcp_ack_n >> 24;
     TCP_head[9] = tcp_ack_n >> 16;
     TCP_head[10] = tcp_ack_n >> 8;
     TCP_head[11] = tcp_ack_n;//TCP ACK NUMȷ�����
     TCP_head[12] = head_pianyi;//TCP�ײ��� ��̬
	 tnum+= URG << 5;
	 tnum+= ACK << 4;
	 tnum+= PSH << 3;
	 tnum+= RST << 2;
	 tnum+= SYN << 1;
	 tnum+= FIN;
     TCP_head[13] = tnum;//TCP6��λ��־
     TCP_head[14] = windows/256;
     TCP_head[15] = windows%256;//TCP���ڴ�С ������յ�TCP����
     TCP_head[16] = 0;
     TCP_head[17] = 0;//�����
     TCP_head[18] = 0;
     TCP_head[19] = 0;//����ָ��

	 num=Check_Code_creat3(12,TCP_false_head,20,TCP_head,data_length,packet);
	 TCP_head[16] = num/256;
     TCP_head[17] = num%256;//�����

    TCP_Packet_Send(data_length,packet);
		
   }
/***************************************************************
   ����TCP��
****************************************************************/
 void tcp_deal(u8 *tcpsource_MAC,u8 *tcplocal_MAC,u8 *tcpsource_ip,u8 *tcplocal_ip,u16 tcplocal_port,u16 tcpdt_port,u16 data_length)
	 {
//������1
	   //u16 i;
		 u32 mbr;
	    if(TCP_SYN == 1) 
        {   
	        TCP_conneted_state=0x01;//��һ�����ֵ���
	        creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,0x2340-1,TCP_seq_num+1,0X50,0,1,0,0,1,0,net_len-58,0,DATA);//���͵ڶ�������
	      } 
	 
	    if(TCP_ACK == 1 && data_length <= 40)//���������ֵ��� �� �����ѽ���Ӧ��
	      { 
          if(TCP_conneted_state == 0x03)
		        {
		          if(TCP_data_send_state == 0x02)			 
				        {
					       creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num,0X50,0,1,0,0,0,1,net_len-58,0,DATA);//���������Ͽ� 
					       TCP_data_send_state = 0x00;
				        }
		        }
		
		      if(TCP_conneted_state == 0x02)
		        {
		    //creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num+data_length-40,0X50,0,1,0,0,0,0,net_len-58,0,DATA);//�����յ����ݵ�ȷ��
              if(TCP_data_send_state == 0x01)
			          { 
								  if(now_tcp_packet == 0x01)
									 { mbr=sizeof(index_html);
										//Uart_Send_Byte(mbr);
					          TCP_data_send_num+=255;
			                if(TCP_data_send_num <= mbr-(mbr%255)-255)
				              { //Printf_String("logo png two!! \r\n");
						            memcpy(DATA,index_html+TCP_data_send_num,255);
			                  creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num,0X50,0,1,0,0,0,0,net_len-58,255,DATA);//��������
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
			                    creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num,0X50,0,1,0,0,0,0,net_len-58,mbr%255,DATA);//��������
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
			                  creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num,0X50,0,1,0,0,0,0,net_len-58,255,DATA);//��������
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
			                    creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num,0X50,0,1,0,0,0,0,net_len-58,mbr%255,DATA);//��������
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
			                  creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num,0X50,0,1,0,0,0,0,net_len-58,255,DATA);//��������
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
			                    creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num,0X50,0,1,0,0,0,0,net_len-58,mbr%255,DATA);//��������
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
			                  creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num,0X50,0,1,0,0,0,0,net_len-58,255,DATA);//��������
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
			                    creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num,0X50,0,1,0,0,0,0,net_len-58,mbr%255,DATA);//��������
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
			                  creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num,0X50,0,1,0,0,0,0,net_len-58,255,DATA);//��������
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
			                    creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num,0X50,0,1,0,0,0,0,net_len-58,mbr%255,DATA);//��������
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
			 TCP_conneted_state=0x02;//���յ�����������
		 } 
		 
	 }
	 
	 	 if(TCP_ACK == 1 && data_length > 40 && TCP_PSH == 0)//�ͻ������ݵ���
	 { 
		 if(TCP_conneted_state == 0x02)
		 {
			 
		   creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num+data_length-40,0X50,0,1,0,0,0,0,net_len-58,0,DATA);//�����յ����ݵ�ȷ��

			 
		 } 
	 }
	 
	   if(TCP_ACK == 1 && TCP_PSH == 1)//�ͻ��˵����һ�����ݰ�����
		 {  
			 //if(TCP_conneted_state == 0x02 && TCP_data_send_state == 0x00)//���յ����һ�����ݰ�
		   //{
				 if (memcmp(&DATA[54],"GET / ",6) ==0)
           {  
						 //Printf_String("idex one!! \r\n");
						 now_tcp_packet=0x01;
					    creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num+data_length-40,0X50,0,1,0,0,0,0,net_len-58,0,DATA);//�����յ����ݵ�ȷ��
				      memcpy(DATA,index_html,255);
			        creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num,0X50,0,1,0,0,0,0,net_len-58,255,DATA);//��������
				      TCP_data_send_num =0;
					    TCP_data_send_state = 0x01;
				   } else{
					 
				if (memcmp(&DATA[54],"GET /logo.png",13) ==0)
           {  
						  
						  now_tcp_packet=0x02;
					    creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num+data_length-40,0X50,0,1,0,0,0,0,net_len-58,0,DATA);//�����յ����ݵ�ȷ��
				      memcpy(DATA,logo_png,255);
			        creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num,0X50,0,1,0,0,0,0,net_len-58,255,DATA);//��������
				      TCP_data_send_num =0;
					    TCP_data_send_state = 0x01;
				   }else{
						 
						 if (memcmp(&DATA[54],"GET /zntlogo.png",16) ==0)
           {  
						  
						  now_tcp_packet=0x04;
					    creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num+data_length-40,0X50,0,1,0,0,0,0,net_len-58,0,DATA);//�����յ����ݵ�ȷ��
				      memcpy(DATA,zntlogo_png,255);
			        creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num,0X50,0,1,0,0,0,0,net_len-58,255,DATA);//��������
				      TCP_data_send_num =0;
					    TCP_data_send_state = 0x01;
				   }else{
						 
						 if (memcmp(&DATA[54],"GET /col",8) ==0)
           {  
						  
						  now_tcp_packet=0x05;
					    creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num+data_length-40,0X50,0,1,0,0,0,0,net_len-58,0,DATA);//�����յ����ݵ�ȷ��
				      memcpy(DATA,col_html,255);
			        creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num,0X50,0,1,0,0,0,0,net_len-58,255,DATA);//��������
				      TCP_data_send_num =0;
					    TCP_data_send_state = 0x01;
				   }else{
						 
						 if (memcmp(&DATA[54],"GET /?run",9) ==0)
           { 
						  now_tcp_packet=0x06;
					    creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num+data_length-40,0X50,0,1,0,0,0,0,net_len-58,0,DATA);//�����յ����ݵ�ȷ��
				      memcpy(DATA,"ok",2);
			        creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num,0X50,0,1,0,0,0,0,net_len-58,2,DATA);//��������
				      TCP_conneted_state=0x03;
						  TCP_data_send_state = 0x02;
							now_tcp_packet = 0x00;
				   }else{
						 
						  if (memcmp(&DATA[54],"GET /?close",11) ==0)
           {  
						  now_tcp_packet=0x06;
					    creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num+data_length-40,0X50,0,1,0,0,0,0,net_len-58,0,DATA);//�����յ����ݵ�ȷ��
				      memcpy(DATA,"ok",2);
			        creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num,0X50,0,1,0,0,0,0,net_len-58,2,DATA);//��������
              TCP_conneted_state=0x03;
						  TCP_data_send_state = 0x02;
							now_tcp_packet = 0x00;
				   }else{
					    now_tcp_packet=0x03;
					    creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num+data_length-40,0X50,0,1,0,0,0,0,net_len-58,0,DATA);//�����յ����ݵ�ȷ��
				      memcpy(DATA,error_html,255);
			        creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num,0X50,0,1,0,0,0,0,net_len-58,255,DATA);//��������
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
			if(TCP_ACK == 1 && TCP_FIN == 1 && TCP_conneted_state == 0x03)//����������Ͽ�  
	    {  
				creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num + 1,0X50,0,1,0,0,0,0,net_len-58,0,DATA);//�����յ����ݵ�ȷ��
			  TCP_conneted_state = 0x04; 
			}
			
			if(TCP_ACK == 1 && TCP_FIN == 1 && TCP_conneted_state == 0x02)//�ͻ������Ͽ� 
	    {  
				creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num + 1,0X50,0,1,0,0,0,0,net_len-58,0,DATA);//�����յ����ݵ�ȷ��
				creat_tcp_head(tcpsource_MAC,tcplocal_MAC,tcpsource_ip,tcplocal_ip,tcplocal_port,tcpdt_port,TCP_ack_num,TCP_seq_num + 1,0X50,0,1,0,0,0,1,net_len-58,0,DATA); //���������Ͽ�
			  TCP_conneted_state = 0x04;
			}
	 
   }
 /************************************************************
 ����arp���� ����
 *************************************************************/
 void ARP_ask()
{
  u16 i;  
		   //	Printf_String("The arp request packet call me!! \r\n");
           ARP_DATA[7]=1;//1����	2Ӧ��
            //���Ͷ�MAC
	       for(i=0;i<6;i++)
	       {
	        ARP_DATA[8+i]=local_MAC[i];
	       }
	       //���Ͷ�IP
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
	        ARP_Packet_Send();//����ARP��	Printf_String("EN HEAD OK!! \r\n");

	  	
	 }

/***************************************************************
   ������
****************************************************************/

void init(void)
{	
		//--------------------------- CLK INIT, HSE PLL ----------------------------
		ErrorStatus HSEStartUpStatus;
		//RCC reset
		RCC_DeInit();
		//�����ⲿʱ�� ��ִ�г�ʼ��
		RCC_HSEConfig(RCC_HSE_ON); 
		//�ȴ��ⲿʱ��׼����
		HSEStartUpStatus = RCC_WaitForHSEStartUp();
		//����ʧ�� ������ȴ�
		while(HSEStartUpStatus == ERROR);
		//�����ڲ�����ʱ��
		RCC_HCLKConfig(RCC_SYSCLK_Div1);
		RCC_PCLK1Config(RCC_HCLK_Div1);
		RCC_PCLK2Config(RCC_HCLK_Div1);
		//�ⲿʱ��Ϊ8M ���ﱶƵ��72M
		RCC_PLLConfig(RCC_PLLSource_HSE_Div1, RCC_PLLMul_9);
		RCC_PLLCmd(ENABLE); 
		while(RCC_GetFlagStatus(RCC_FLAG_PLLRDY) == RESET);
		RCC_SYSCLKConfig(RCC_SYSCLKSource_PLLCLK);
		while(RCC_GetSYSCLKSource() != 0x08);

		//----------------------------- CLOSE HSI ---------------------------
		//�ر��ڲ�ʱ��HSI
		RCC_HSICmd(DISABLE);	

		//--------------------------- OPEN GPIO CLK -------------------------
		RCC_APB2PeriphClockCmd(RCC_APB2Periph_GPIOA, ENABLE);
		RCC_APB2PeriphClockCmd(RCC_APB2Periph_GPIOB, ENABLE);
		RCC_APB2PeriphClockCmd(RCC_APB2Periph_GPIOC, ENABLE);
		RCC_APB2PeriphClockCmd(RCC_APB2Periph_GPIOD, ENABLE);
		//����SPI�ӿ�
		SPION();
}
	//��ʱ�����ò����� ʹ�ö�ʱ��3
void TimeON(void)
{
		TIM_TimeBaseInitTypeDef TIM_TimeBaseStructure;
		NVIC_InitTypeDef NVIC_InitStructure;
		//������ʱ������ʱ��
		RCC_APB1PeriphClockCmd(RCC_APB1Periph_TIM3, ENABLE);
		//���ö�ʱ������
		TIM_DeInit(TIM3); 
		TIM_TimeBaseStructure.TIM_Period = 50000; 								 	//50ms��ʱ 20s=20000us=50ms*400			 
		TIM_TimeBaseStructure.TIM_Prescaler = (72000000/1000000 - 1);              
		TIM_TimeBaseStructure.TIM_ClockDivision = TIM_CKD_DIV1;     
		TIM_TimeBaseStructure.TIM_CounterMode = TIM_CounterMode_Up; 
		TIM_TimeBaseStructure.TIM_RepetitionCounter = 0;
		TIM_TimeBaseInit(TIM3, &TIM_TimeBaseStructure);	
		//�ж�����
		NVIC_InitStructure.NVIC_IRQChannel = TIM3_IRQn;
		NVIC_InitStructure.NVIC_IRQChannelPreemptionPriority = 2;  //��ռ���ȼ�2 �����ȼ����ж� 
		NVIC_InitStructure.NVIC_IRQChannelSubPriority = 0;		  	 //��Ӧ���ȼ�0 �߼������Ӧ�ж�
		NVIC_InitStructure.NVIC_IRQChannelCmd = ENABLE;	
		NVIC_Init(&NVIC_InitStructure);	  
		//���ж�
		TIM_ClearFlag(TIM3, TIM_FLAG_Update);					  
		TIM_ITConfig(TIM3, TIM_IT_Update, ENABLE); 
		//������ʱ��			 
		TIM_Cmd(TIM3, ENABLE); 
}

//��ʱ���жϴ��� ��stm32f10x_it.c���
void Time_IntHandle(void)
{
		//���жϱ�ʶ
		TIM_ClearFlag(TIM3, TIM_FLAG_Update);
		//---------------- �жϴ���  ---------------------
dstimes++;
}	
int main()
{	u8 wz;
	u16 i;		 //ѭ������
	u16 flag=0;	 //��ʱ��־
	u16 tpid; //tpid ��Tag Protocol Identifier����ǩЭ���ʶ��VLAN Tag�е�һ���ֶ�
	char STRR[50];
	//SystemInit();
	init();
	delay_init();
  	//TFT��ʼ��
	LCD_Init();
	//������ ����
	Driver_LcdBacklight(True);
	LCD_ClrScr(BLUE);
	//����LOGO
	LCD_DisASCString16x8(3, 10, "IT", ORANGE, BLUE);
	LCD_DisGB2312String16x16(19, 10, "֪ʶ����̳", ORANGE, BLUE);
  LCD_DisGB2312String16x16(50, 26, "Ӳ����ʼ����..", WHITE, BLUE);
		LCD_DisASCString16x8(50, 200, "WWW.ITZHISHIKU.COM", PURPLE, BLUE);
	enc28j60_init();
		//�ж����� 2-level interrupt 
		NVIC_PriorityGroupConfig(NVIC_PriorityGroup_2);
			LCD_ClrScr(BLUE);
		LCD_DisASCString16x8(3, 10, "IT", ORANGE, BLUE);
	  LCD_DisGB2312String16x16(19, 10, "֪ʶ����̳", ORANGE, BLUE);
	LCD_DisGB2312String16x16(50, 26, "Ӳ����ʼ�����", WHITE, BLUE);
			LCD_DisASCString16x8(50, 200, "WWW.ITZHISHIKU.COM", PURPLE, BLUE);
		//�����ж�
		__enable_irq(); 
		
		//����ʱ��
		TimeON();
		LCD_ClrScr(BLUE);
		LCD_DisASCString16x8(3, 10, "IT", ORANGE, BLUE);
	  LCD_DisGB2312String16x16(19, 10, "֪ʶ����̳", ORANGE, BLUE);
		LCD_DisGB2312String16x16(50, 26, "�����ʼ����...", WHITE, BLUE);
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
	                   ARP();	  //�´ο��ǰ����ݶ�����������۲��Ƿ������жϳ���!!
	                   }
				 }
		 }
		LCD_ClrScr(BLUE);
		LCD_DisASCString16x8(3, 10, "IT", ORANGE, BLUE);
	  LCD_DisGB2312String16x16(19, 10, "֪ʶ����̳", ORANGE, BLUE);
		LCD_DisGB2312String16x16(50, 26, "�����ʼ�����", WHITE, BLUE);
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
       /**************��ȡ���ݿ�ʼ*****************/  
	   len=enc28j60PacketReceive(net_len, DATA);
        /**************��ȡ����β��*****************/
	         if(len >= 18){
						 //LCD_DisGB2312String16x16(80, 12, "����", WHITE, GREEN);
						       //memcpy(DATA,up,26);
					         //udp_send(ga_MAC,local_MAC,br_ip,local_ip,4001,4001,26,DATA);
               /**************����18�����ݴ���ʼ*****************/
          	  /*
                TPID��Tag Protocol Identifier����ǩЭ���ʶ��VLAN Tag�е�һ���ֶ�
                Э������       ��Ӧȡֵ
                 ARP             0x0806
                 IP              0x0800
                 MPLS            0x8847/0x8848
                 IPX             0x8137
                 IS-IS            0x8000
                 LACP             0x8809
                 802.1x            0x888E 
                                         */
                /****************��ȡ�����Ϳ�ʼ**********/
                tpid = DATA[13];
						 						 

               /***************��ȡ������β��***********/
                   /***************arp�������жϿ�ʼ***************************/
                    if(tpid==0x06){
	                 //arp data
	                 //Printf_String("This is a arp packet!! \r\n");
	 	               for(i=0;i<4;i++)
	 	                  {
		                   dt_ip[i]=DATA[38+i]; //save packet mac
	 	                   }
	                   ARP();	  //�´ο��ǰ����ݶ�����������۲��Ƿ������жϳ���!!
	                   }
                     /***************arp�������жϽ�β**************************/

                    /***************ip������ʼ***************************/
                     if(tpid==0x00){
	                      //ip data
	                      //Printf_String("This is a ip packet!! \r\n");
				       	  /***************ip��ַ�������ַ���濪ʼ***************************/
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

							
				    		/***************ip��ַ�������ַ����β��***************************/	
                           flag=0;
	                       for(i=0;i<6;i++)
	 	                    { 	
		                       if(dt_MAC[i]!=local_MAC[i])
			    		        {
		                          flag=1;
	                              //Printf_String("the mac not same with me!! \r\n");
		                         }//�����ʱ���mac
	                        }

	 	                    for(i=0;i<4;i++)
	 	                     {
		                       if(dt_ip[i]!=local_ip[i]) 
							     {
		                             flag=1;//�����ʱ���IP
			                         //Printf_String("the ip not same with me!! \r\n");	
			                       }
	 	                      }
                            /***************ip�������ж�β��***************************/

                                 /***************ip�����ݴ���ʼ***************************/
	                            	if(flag==0)  {
																	
																	            
		                                           //Printf_String("This is a ip packet what the ip same with me!! \r\n");
			 
			                                       /***************icmp�������ж��봦��ʼ***************************/
					                                 //ICMP(��ping����) 
			                                        if(DATA[23]==0x01&&DATA[34]==0x08)
			                                           {    //Printf_String("This is a icmp packet!! \r\n");
		                                                	icmp_anwser(source_MAC,local_MAC,source_ip,local_ip);	
                                                       if(wz>=9){wz=0;}
						                                           sprintf(STRR,"ICMP %d.%d.%d.%d \n",source_ip[0],source_ip[1],source_ip[2],source_ip[3]);
			 							                               		 LCD_DisASCString16x8(31, 50+wz*16+1, (u8 *)STRR, WHITE, BLUE);
						                                           wz++;		                                          
																								 }
		                                          	/***************icmp�������ж��봦��β��***************************/

		                                        	/***************udp�������ж��봦��ʼ***************************/
			                                         //UDP 
			                                         if(DATA[23]==0x11)
		                                              	{
														                          UDP_source_port=DATA[34]*256+DATA[35];//��ԴPort
				                                              UDP_dt_port=DATA[36]*256+DATA[37];//Ŀ��Port
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
					                                 /***************UDP�������ж��봦��β��***************************/
                                                      }//UDP����

													  /***************tcp�������ж��봦��ʼ***************************/
                  									  //tcp
													   if(DATA[23]==0x06)
		                                              	{ TCP_source_port=DATA[34]*256+DATA[35];//��ԴPort
				                                          TCP_dt_port=DATA[36]*256+DATA[37];//Ŀ��Port
			                                     //Printf_String(STRR); 
														  //��ʼ����tcp���
														  TCP_seq_num=(u32)(DATA[38])<<24;
				                                          TCP_seq_num+=(u32)(DATA[39])<<16;
				                                          TCP_seq_num+=(u32)(DATA[40])<<8;
				                                          TCP_seq_num+=(u32)(DATA[41]);
														  // ����tcp��Ž���

														  //��ʼ����tcpȷ�Ϻ�
														  TCP_ack_num=(u32)(DATA[42])<<24;
				                                          TCP_ack_num+=(u32)(DATA[43])<<16;
				                                          TCP_ack_num+=(u32)(DATA[44])<<8;
				                                          TCP_ack_num+=(u32)(DATA[45]);
														  //����tcpȷ�ϺŽ���
														   
														  //��ʼ��������ֶ�λ
														  TCP_URG=((u8)(DATA[47]<<2))>>7;//����
														  TCP_ACK=((u8)(DATA[47]<<3))>>7;//ȷ���ֶ�λ
														  TCP_PSH=((u8)(DATA[47]<<4))>>7;//����
														  TCP_RST=((u8)(DATA[47]<<5))>>7;//��λ
														  TCP_SYN=((u8)(DATA[47]<<6))>>7;//ͬ��
														  TCP_FIN=((u8)(DATA[47]<<7))>>7;//��ֹ
														  //��������ֶ�λ����
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
	
		              /***************ip�����ݴ���β��***************************/ 
		              }
		             /***************ip������β��***************************/
		             }
	           /**************���ݴ���18β�� len>=18��}*****************/
	          }
	 /**************���ݴ���β�� while��}*****************/ 
							
			}
}


