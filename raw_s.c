/*
 Raw Sockets with LINUX
*/
#include<stdio.h>
#include<netinet/tcp.h> //Provides declarations for tcp header
#include<netinet/ip.h> //Provides declarations for ip header
#include<linux/if_ether.h>
#include<time.h>
#include<pthread.h>
#include<string.h>
#include<stdlib.h>

//#define SERVER_IP "192.168.123.100"
#define SERVER_PORT 8787

#define BUF 255
#define MAX_THREADS 2000
#define DATA_SIZE 16

void *connection_link(void *);

int success_link = 0;

pthread_t accept_thread[MAX_THREADS];
void *thread_result;

static char SERVERIP[BUF]="";
char *rdata = "Hello Welcome!";

struct connectInfo
{
	char srcip[BUF];
	int sport;
	char dstip[BUF];
	int dport;
};

struct connectInfo cInfo[MAX_THREADS];

char  *addr_to_string(void *addr, char *ip_str)
{
  unsigned char *p = NULL;
  struct sockaddr_in *sin = NULL;
  if(ip_str == NULL)
  {
    return NULL;
  }
  
  sin = (struct sockaddr_in *)addr;
  if(sin == NULL)
  {
    return NULL;
  }
  
  p = (char *)&sin->sin_addr;
  sprintf(ip_str, "%d.%d.%d.%d", *p, *(p+1), *(p+2), *(p+3));
  
  return ip_str;
}

unsigned short  get_port_number(void *addr)
{
  unsigned short port = 0; 
  struct sockaddr_in *sin = NULL;

  sin = (struct sockaddr_in *)addr;
  if(sin == NULL)
  {
    return 0;
  }
  
  port = ntohs(sin->sin_port);
  
  return port;
}   

//Checksum calculation function
unsigned short csum (unsigned short *buf, int nwords)
{
	 unsigned long sum;
	 
	 for (sum = 0; nwords > 0; nwords--)
	  sum += *buf++;
	 
	 sum = (sum >> 16) + (sum & 0xffff);
	 sum += (sum >> 16);
	 
	 return ~sum;
}

int send_syncpacket(char *sip, char *dip, int sport, int dport)
{
	 char buffer[4096];
	 int one = 1, ret = 0;
	 const int *val = &one;
	 int raw_socket = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);

	 struct iphdr *iph = (struct iphdr *) buffer;
	 struct tcphdr *tcph = (struct tcphdr *) (buffer + sizeof (struct ip));
	 struct sockaddr_in sin;

	if(raw_socket < 0)
	{
		perror("socket() error");
	        exit(-1);
	}
	else
		printf("socket() SOCK_RAW and tcp protocol is OK.\n");

	 
	 sin.sin_family = AF_INET;
	 sin.sin_port = htons(dport);
	 sin.sin_addr.s_addr = inet_addr (dip);
	 
	 memset (buffer, 0, 4096); /* zero out the buffer */
	 
	 //Fill in the IP Header
	 iph->ihl = 5;
	 iph->version = 4;
	 iph->tos = 0;
	 iph->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
	 iph->id = htonl (54321); //Id of this packet
	 iph->frag_off = 0x40;
	 iph->ttl = 255;
	 iph->protocol = 6;
	 iph->check = 0;  //Set to 0 before calculating checksum
	 iph->saddr = inet_addr (sip); //Spoof the source ip address
	 iph->daddr = sin.sin_addr.s_addr;
	 
	 //TCP Header
	 tcph->source = htons (dport);
	 tcph->dest = htons (sport);
	 tcph->seq = 0 /*random ()*/;
	 tcph->ack_seq = 0;

 	 //TCP flag
	 tcph->doff = 5;
	 tcph->syn = 1;
	 tcph->ack = 0;
	 tcph->window = htons (32767); /* maximum allowed window size */
	 tcph->check = 0;
	 tcph->urg_ptr = 0;

	 //Now the IP checksum
	 iph->check = csum ((unsigned short *) buffer, iph->tot_len >> 1);

	 
	if (setsockopt (raw_socket, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
	{
	   printf ("Warning: Cannot set HDRINCL!n");
           return -1;
	 }

	printf("Sending SYN Packet, Using  srcIP: %s:%u, dstIP: %s:%u.\n", sip, sport, dip, dport);

	 //sendto packet	 
	 while (1)
	 {
	  //Send the packet
	  if (ret = sendto (raw_socket, buffer, iph->tot_len, 0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
	  {
			perror("sendto() error");
			exit(-1);		
          }
	  else
	   break;
	 }
	printf("sendto ret = %d\n", ret);

	close(raw_socket);
	return tcph->seq;
}


int send_message(char *sip, char *dip, int sport, int dport, char *msg)
{
	 char buffer[4096];
	 int one = 1, ret = 0;
	 const int *val = &one;
	 int raw_socket = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);

	 struct iphdr *iph = (struct iphdr *) buffer;
	 struct tcphdr *tcph = (struct tcphdr *) (buffer + sizeof (struct ip));
	 char *pdata = (char *) (buffer + sizeof (struct ip) + sizeof (struct tcphdr));
	 struct sockaddr_in sin;

	if(raw_socket < 0)
	{
		perror("socket() error");
	        exit(-1);
	}
	else
		printf("socket() SOCK_RAW and tcp protocol is OK.\n");

	 
	 sin.sin_family = AF_INET;
	 sin.sin_port = htons(dport);
	 sin.sin_addr.s_addr = inet_addr (dip);
	 
	 memset (buffer, 0, 4096); /* zero out the buffer */
	 
	 //Fill in the IP Header
	 iph->ihl = 5;
	 iph->version = 4;
	 iph->tos = 0;
	 iph->tot_len = sizeof (struct ip) + sizeof (struct tcphdr) + DATA_SIZE;
	 iph->id = htonl (54321); //Id of this packet
	 iph->frag_off = 0x40;
	 iph->ttl = 255;
	 iph->protocol = 6;
	 iph->check = 0;  //Set to 0 before calculating checksum
	 iph->saddr = inet_addr (sip); //Spoof the source ip address
	 iph->daddr = sin.sin_addr.s_addr;
	 
	 //TCP Header
	 tcph->source = htons (sport);
	 tcph->dest = htons (dport);
	 tcph->seq = 0 /*random ()*/;
	 tcph->ack_seq = 0;

 	 //TCP flag
	 tcph->doff = 5;
	 tcph->syn = 0;
	 tcph->ack = 0;
	 tcph->window = htons (32767); /* maximum allowed window size */
	 tcph->check = 0;
	 tcph->urg_ptr = 0;

    	 memcpy(buffer + sizeof(struct ip) + sizeof (struct tcphdr), msg, DATA_SIZE);

	 //Now the IP checksum
	 iph->check = csum ((unsigned short *) buffer, iph->tot_len >> 1);

	 
	if (setsockopt (raw_socket, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
	{
	   printf ("Warning: Cannot set HDRINCL!n");
           return -1;
	 }

	printf("Sending message Packet, Using  srcIP: %s:%u, dstIP: %s:%u.\n", sip, sport, dip, dport);

	 //sendto packet	 
	 while (1)
	 {
	  //Send the packet
	  if (ret = sendto (raw_socket, buffer, iph->tot_len, 0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
	  {
			perror("sendto() error");
			exit(-1);		
          }
	  else
	   break;
	 }
	printf("sendto ret = %d\n", ret);

	close(raw_socket);
	return tcph->seq;
}

int waitformessage(int sport, int dport)
{
   int n;
   char buffer[2048]="";
   char sip[32]="", dip[32]="";
   unsigned char *iphead, *ethhead;

   int read_rawsock;
   int timeout = 0;
   struct iphdr *iph;
   struct tcphdr *tcph;
   char *pdata = NULL;
  
   if ( (read_rawsock=socket(PF_PACKET, SOCK_RAW,  htons(ETH_P_IP)))<0) 
   {
     perror("socket");
     exit(1);
   }

   while (1) 
  {

     n = recvfrom(read_rawsock ,buffer , 2048 , 0 , NULL, NULL);

     if (n<42) {
       perror("recvfrom():");
       //printf("Incomplete packet (errno is %d)\n", errno);
       close(read_rawsock);
       exit(0);
     }

     ethhead = buffer;
     iphead = buffer+14; /* Skip Ethernet header */

     iph = (struct iphdr *) iphead;
     tcph = (struct tcphdr *) (iphead + sizeof (struct ip));

     timeout++;
     if (timeout > 30000000000) 
	 	return 3;


     //filter not TCP
     if (*iphead!=0x45 && iph->protocol != 6)  continue;         
     
     printf("msg TCP souce port %d %d\n", ntohs(tcph->source), ntohs(tcph->dest));
     printf("want msg TCP souce port %d %d\n", dport, sport);
     //printf("msg TCP flag: synask %d %d\n", tcph->syn, tcph->ack);

     if (ntohs(tcph->source) != dport && ntohs(tcph->dest) != sport) continue;

     pdata = (char *) (iphead + sizeof (struct ip) +  sizeof (struct tcphdr));

     //match
     printf("match: souce, dest port %d, %d\n", ntohs(tcph->source), ntohs(tcph->dest));
     sprintf(sip, "%d.%d.%d.%d",
             iphead[12],iphead[13],
             iphead[14],iphead[15]);
     sprintf(dip, "%d.%d.%d.%d",
             iphead[16],iphead[17],
             iphead[18],iphead[19]);
     printf("match: souce dest %s %s\n", sip, dip);

     printf("Layer-4 protocol %d\n", iph->protocol);

     printf("recieve msg: %s\n", pdata);

     //printf("asksyn %d %d\n", tcph->syn, tcph->ack);
     break;
   }
   
   close(read_rawsock);
   return 2;

}



int toSpoofingServer(int req, char* srcaddr, char* dipaddr,  int sport, int dport)
{
    int sockfd;
    struct sockaddr_in dest;
    char spoof_info[128]="";


    printf("toSpoofingServer, Using  srcIP: %s:%u, dstIP: %s:%u.\n", srcaddr, sport, dipaddr, dport);

    sprintf(spoof_info, "%d;%s;%s;%d;%d", req, srcaddr, dipaddr, dport, sport);

    /* create socket */
    sockfd = socket(PF_INET, SOCK_STREAM, 0);

    /* initialize value in dest */
    bzero(&dest, sizeof(dest));
    dest.sin_family = PF_INET;
    dest.sin_port = htons(SERVER_PORT);
    dest.sin_addr.s_addr = inet_addr(SERVERIP);

    /* Connecting to server */
    connect(sockfd, (struct sockaddr*)&dest, sizeof(dest));
    send(sockfd, spoof_info, sizeof(spoof_info), 0);

    //Close connection
    close(sockfd);

    return 1;
}

int waitforsyncask(int sport, int dport)
{
   int n;
   char buffer[2048]="";
   char sip[32]="", dip[32]="";
   unsigned char *iphead, *ethhead;

   int read_rawsock;
   int timeout = 0;
   struct iphdr *iph;
   struct tcphdr *tcph;
  
   if ( (read_rawsock=socket(PF_PACKET, SOCK_RAW,  htons(ETH_P_IP)))<0) 
   {
     perror("socket");
     exit(1);
   }

   while (1) 
  {

     n = recvfrom(read_rawsock ,buffer , 2048 , 0 , NULL, NULL);

     if (n<42) {
       perror("recvfrom():");
       //printf("Incomplete packet (errno is %d)\n", errno);
       close(read_rawsock);
       exit(0);
     }

     ethhead = buffer;
     iphead = buffer+14; /* Skip Ethernet header */

     iph = (struct iphdr *) iphead;
     tcph = (struct tcphdr *) (iphead + sizeof (struct ip));

     //filter not TCP
     if (*iphead!=0x45 && iph->protocol != 6)  continue;         
     
     //printf("TCP souce port %d %d\n", ntohs(tcph->source), ntohs(tcph->dest));
     //printf("TCP flag: synask %d %d\n", tcph->syn, tcph->ack);

     	//SYNASK flag = 1
     if (tcph->syn != 1 && tcph->ack != 1) continue;

     timeout++;

     if (timeout > 100000000) 
	 	return 3;

     if (ntohs(tcph->source) != dport && ntohs(tcph->dest) != sport) continue;

     //match
     printf("match: souce, dest port %d, %d\n", ntohs(tcph->source), ntohs(tcph->dest));
     sprintf(sip, "%d.%d.%d.%d",
             iphead[12],iphead[13],
             iphead[14],iphead[15]);
     sprintf(dip, "%d.%d.%d.%d",
             iphead[16],iphead[17],
             iphead[18],iphead[19]);
     printf("match: souce dest %s %s\n", sip, dip);

     printf("Layer-4 protocol %d\n", iph->protocol);
     //printf("asksyn %d %d\n", tcph->syn, tcph->ack);
     break;
   }
   
   close(read_rawsock);

    //send to ask packet
    send_ackpacket(tcph, sip, dip);

    return 2;

}

int waitforack(int sport, int dport)
{
   int n;
   char buffer[2048]="";
   char sip[32]="", dip[32]="";
   unsigned char *iphead, *ethhead;

   int read_rawsock;
   int timeout = 0;
   struct iphdr *iph;
   struct tcphdr *tcph;
  
   if ( (read_rawsock=socket(PF_PACKET, SOCK_RAW,  htons(ETH_P_IP)))<0) 
   {
     perror("socket");
     exit(1);
   }

   while (1) 
  {

     n = recvfrom(read_rawsock ,buffer , 2048 , 0 , NULL, NULL);

     if (n<42) {
       perror("recvfrom():");
       //printf("Incomplete packet (errno is %d)\n", errno);
       close(read_rawsock);
       exit(0);
     }

     ethhead = buffer;
     iphead = buffer+14; /* Skip Ethernet header */

     iph = (struct iphdr *) iphead;
     tcph = (struct tcphdr *) (iphead + sizeof (struct ip));

     //filter not TCP
     if (*iphead!=0x45 && iph->protocol != 6)  continue;         
     
     //printf("TCP souce port %d %d\n", ntohs(tcph->source), ntohs(tcph->dest));
     //printf("TCP flag: synask %d %d\n", tcph->syn, tcph->ack);

    if (tcph->ack != 1) continue;
 
    timeout++;

    if (timeout > 100000000) 
		return 3;

    if (ntohs(tcph->source) != dport && ntohs(tcph->dest) != sport) continue;

     //match
     printf("match: souce, dest port %d, %d\n", ntohs(tcph->source), ntohs(tcph->dest));
     sprintf(sip, "%d.%d.%d.%d",
             iphead[12],iphead[13],
             iphead[14],iphead[15]);
     sprintf(dip, "%d.%d.%d.%d",
             iphead[16],iphead[17],
             iphead[18],iphead[19]);
     printf("match: souce dest %s %s\n", sip, dip);

     printf("Layer-4 protocol %d\n", iph->protocol);
     //printf("asksyn %d %d\n", tcph->syn, tcph->ack);
     break;
   }
   
   close(read_rawsock);

   return 2;

}

int send_ackpacket(struct tcphdr *atcph, char *sip, char *dip)
{        
	 char buffer[4096];
	 int one = 1, ret = 0;
	 const int *val = &one;
	 int raw_socket = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);

	 struct iphdr *iph = (struct iphdr *) buffer;
	 struct tcphdr *tcph = (struct tcphdr *) (buffer + sizeof (struct ip));
	 struct sockaddr_in sin;

    	printf("send_ackpacket\n");

	if(raw_socket < 0)
	{
		perror("socket() error");
	        exit(-1);
	}
	else
		printf("socket()-SOCK_RAW and tcp protocol is OK.\n");

	 
	 sin.sin_family = AF_INET;
	 sin.sin_port = htons(ntohs(atcph->source));
	 sin.sin_addr.s_addr = inet_addr (sip);
	 
	 memset (buffer, 0, 4096); /* zero out the buffer */
	 
	 //Fill in the IP Header
	 iph->ihl = 5;
	 iph->version = 4;
	 iph->tos = 0;
	 iph->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
	 iph->id = htonl (54321); //Id of this packet
	 iph->frag_off = 0x40;
	 iph->ttl = 255;
	 iph->protocol = 6;
	 iph->check = 0;  //Set to 0 before calculating checksum
	 iph->saddr = inet_addr (dip); //Spoof the source ip address
	 iph->daddr = sin.sin_addr.s_addr;
	 
	 //TCP Header
	 tcph->source = htons (ntohs(atcph->dest));
	 tcph->dest = htons (ntohs(atcph->source));
	 tcph->seq = atcph->seq + 1/*random ()*/;
	 tcph->ack_seq = 0;

 	 //TCP flag
	 tcph->doff = 5;
	 tcph->syn = 0;
	 tcph->ack = 1;
	 tcph->window = htons (32767); /* maximum allowed window size */
	 tcph->check = 0;
	 tcph->urg_ptr = 0;
	 //Now the IP checksum
	 iph->check = csum ((unsigned short *) buffer, iph->tot_len >> 1);
	 
	if (setsockopt (raw_socket, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
	{
	   printf ("Warning: Cannot set HDRINCL!n");
           return -1;
	 }

	 //sendto packet	 
	 while (1)
	 {
	  //Send the packet
	  if (ret = sendto (raw_socket, buffer, iph->tot_len, 0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
	  {
			perror("sendto() error");
			exit(-1);		
          }
	  else
	   break;
	 }

	printf("sendto ret = %d\n", ret);
	close(raw_socket);
	return 1;
}

void *connection_link(void *arg)
{
	int th_num=0, *p_th_num;
	double elapsed_tm;
     	int req=0;
     	int ret=0;

	pthread_detach(pthread_self());

	p_th_num = (int *)arg;
	th_num = *p_th_num;
    	time_t start_tm, finish_tm;
     	time(&start_tm); 

	printf("thread src: %s:%d, dst: %s:%d\n", cInfo[th_num].srcip,cInfo[th_num].sport, cInfo[th_num].dstip, cInfo[th_num].dport);

	//handler
	do
	{
		//sendto B Client for sync packets
		req = send_syncpacket(cInfo[th_num].srcip, cInfo[th_num].dstip, cInfo[th_num].sport, cInfo[th_num].dport);

		toSpoofingServer(req, cInfo[th_num].srcip, cInfo[th_num].dstip, cInfo[th_num].sport, cInfo[th_num].dport);

		//Wait ASK_SYN packet && Send ASK packet
		ret = waitforsyncask(cInfo[th_num].sport, cInfo[th_num].dport);
		//sleep(1);
	} while (ret == 3);
	
	printf("Wait SYN packet for B client");
	//Wait SYN packet for B client
	ret = waitforack(cInfo[th_num].sport, cInfo[th_num].dport);
	
	if (ret == 2)
	{
		printf("thread%d recieve asksyn packet, Connect...\n", th_num);
		//send message to client
		do
		{
			send_message(cInfo[th_num].srcip, cInfo[th_num].dstip, cInfo[th_num].sport, cInfo[th_num].dport, rdata);
			ret = waitformessage(cInfo[th_num].sport, cInfo[th_num].dport);		
		} while (ret == 3);
		success_link++;
	}

	
	//close(raw_socket[th_num]);

	time(&finish_tm);
	elapsed_tm=difftime(finish_tm,start_tm);

	printf("Link %d for %5.3f seconds\n\n\n", th_num, elapsed_tm);
	pthread_exit(0);
}

 
int main (int argc, char *argv[])
{
     int i=0, num=0;
     int *p_num = &num;
     int res=0;
     int socket_number[MAX_THREADS]={0};
     srand(time(NULL));

     if (getuid() != 0) {
		fprintf(stderr, "raw_s: Need root privileges\n");
		exit(1);
      }

     if(argc != 7)
      {
		printf("- Invalid parameters!!!\n");
		printf("- Usage: %s <link Connection>  <src hostname/IP> <src port> <dst hostname/IP> <dst port> <ServerIP>\n", argv[0]);
		exit(-1);
       }

     //sendto STUNT Server
     int sport= atoi(argv[3]);
     int dport= atoi(argv[5]);
     strcpy(SERVERIP, argv[6]);

     for (i=0; i<atoi(argv[1]); i++)
       {
		if (num > MAX_THREADS)
		{
			num = 0;
		}

		strcpy(cInfo[num].srcip, argv[2]);
		strcpy(cInfo[num].dstip, argv[4]);
		cInfo[num].sport = sport + i;
		cInfo[num].dport = dport + i;

		printf("src: %s:%d\n", cInfo[num].srcip, cInfo[num].sport);
		printf("dst: %s:%d\n", cInfo[num].dstip, cInfo[num].dport);

		socket_number[i] = num;
		p_num = &socket_number[i];
		//Create thread
		res = pthread_create( &(accept_thread[num]), NULL, connection_link, (void *)p_num );
		if (res != 0){
			printf("Thread create failed!\n");
			exit(-1);
		}
		num++;
	}

	while (1)
	{
		if (success_link == atoi(argv[1])) break;
		//printf("success %d\n", success_link);
	}

	printf("TCP all connect\n");
 	return 0;
}
