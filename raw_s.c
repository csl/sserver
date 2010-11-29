/*
 Raw Sockets with LINUX
*/
#include<stdio.h>
#include<netinet/tcp.h> //Provides declarations for tcp header
#include<netinet/ip.h> //Provides declarations for ip header

int s;
 
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

int send_syncpacket(char *argv[])
{
	 char buffer[4096];
	 int one = 1;
	 const int *val = &one;
	 s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);

	 struct iphdr *iph = (struct iphdr *) buffer;
	 struct tcphdr *tcph = (struct tcphdr *) (buffer + sizeof (struct ip));
	 struct sockaddr_in sin;

	if(s < 0)
	{
		perror("socket() error");
	        exit(-1);
	}
	else
		printf("socket()-SOCK_RAW and tcp protocol is OK.\n");

	 
	 sin.sin_family = AF_INET;
	 sin.sin_port = htons(atoi(argv[4]));
	 sin.sin_addr.s_addr = inet_addr (argv[3]);
	 
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
	 iph->saddr = inet_addr (argv[1]); //Spoof the source ip address
	 iph->daddr = sin.sin_addr.s_addr;
	 
	 //TCP Header
	 tcph->source = htons (atoi(argv[2]));
	 tcph->dest = htons (atoi(argv[4]));
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
	 
	if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
	{
	   printf ("Warning: Cannot set HDRINCL!n");
           return -1;
	 }

	printf("Using:::::Source IP: %s port: %u, Target IP: %s port: %u.\n", argv[1], atoi(argv[2]), argv[3], atoi(argv[4]));

	 //sendto packet	 
	 while (1)
	 {
	  //Send the packet
	  if (sendto (s, buffer, iph->tot_len, 0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
	  {
			perror("sendto() error");
			exit(-1);		
          }
	  else
	   break;
	 }

	return tcph->seq;
}

int toSTUNTServer(int req, char* ipaddr, int port)
{
    int sockfd;
    struct sockaddr_in dest;
    char buffer[128]="";
    char spoof_info[128]="";

    sprintf(spoof_info, "%d;%s;%d", req, ipaddr, port);

    /* create socket */
    sockfd = socket(PF_INET, SOCK_STREAM, 0);

    /* initialize value in dest */
    bzero(&dest, sizeof(dest));
    dest.sin_family = PF_INET;
    dest.sin_port = htons(8787);
    dest.sin_addr.s_addr = inet_addr("192.168.121.63");

    /* Connecting to server */
    connect(sockfd, (struct sockaddr*)&dest, sizeof(dest));
    send(sockfd, spoof_info, sizeof(spoof_info), 0);

    //Close connection
    close(sockfd);

    return 1;
}

 
int main (int argc, char *argv[])
{
	int req=0;

        if (getuid() != 0) {
		fprintf(stderr, "raw_s: Need root privileges\n");
		exit(1);
	}

	if(argc != 5)
	{
		printf("- Invalid parameters!!!\n");
		printf("- Usage: %s <source hostname/IP> <source port> <target hostname/IP> <target port>\n", argv[0]);
		exit(-1);
	}

	//sendto B Client for sync packets
	req = send_syncpacket(argv);

	//sendto STUNT Server
	int destport= atoi(argv[4]);
	toSTUNTServer(req, argv[3], destport);

	//Wait ASK_SYN packet
	

        //Send ASK packet

	close(s);
 	return 0;
}
