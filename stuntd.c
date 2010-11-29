
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <error.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <getopt.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <dlfcn.h>
#include <signal.h>
#include <stdio.h>
#include <netinet/tcp.h> //Provides declarations for tcp header
#include <netinet/ip.h> //Provides declarations for ip header


#define BUFSIZE    300

int sock_raw;
const int one = 1;
static char buffer[BUFSIZE+1]="";
static char dstip[BUFSIZE+1]="";

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
 

int send_asksynpkt (int seq, struct sockaddr_in* cli_addr, char *spoof_DestIP, int port)
{
	 char buffer[4096];
    	 char  vsip[16]="";
	 int one = 1;
	 const int *val = &one;

	printf("in send_asksynpkt\n");

    	//Set Socket Raw
    	if ((sock_raw = socket (PF_INET, SOCK_RAW, IPPROTO_TCP)) == -1) {
        	perror("socket");
        	exit(EXIT_FAILURE);
    	}

	 //Create asksyn pakcets
	 struct iphdr *iph = (struct iphdr *) buffer;
	 struct tcphdr *tcph = (struct tcphdr *) (buffer + sizeof (struct ip));
	 struct sockaddr_in sin;


	 if(sock_raw < 0)
	 {
		perror("socket() error");
	        exit(-1);
	 }
	 else
		printf("socket()-SOCK_RAW and tcp protocol is OK.\n");

	 
	 sin.sin_family = AF_INET;
	 sin.sin_port = cli_addr->sin_port;
	 sin.sin_addr.s_addr = cli_addr->sin_addr.s_addr;
	 
	 memset (buffer, 0, 4096); //zero out the buffer
	 
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
	 iph->saddr = inet_addr (spoof_DestIP); //Spoof the source ip address
	 iph->daddr = sin.sin_addr.s_addr;
	 
	 //TCP Header
	 tcph->source = htons (port);
	 tcph->dest = sin.sin_port;
	 tcph->seq = seq;
	 tcph->ack_seq = 0;

 	 //TCP flag
	 tcph->doff = 5;
	 tcph->syn = 1;
	 tcph->ack = 1;
	 tcph->window = htons (32767); // maximum allowed window size
	 tcph->check = 0;
	 tcph->urg_ptr = 0;

	 //Now the IP checksum
	 iph->check = csum ((unsigned short *) buffer, iph->tot_len >> 1);
	 
	if (setsockopt (sock_raw, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
	{
	   printf ("Warning: Cannot set HDRINCL!n");
	 }

	printf("Using:::::Source IP: %s port: %d, Target IP: %s port: %d.\n", spoof_DestIP, port, addr_to_string(cli_addr, vsip), get_port_number(cli_addr));

	 //sendto packet	 
	 while (1)
	 {
	  //Send the packet
	  if (sendto (sock_raw, buffer, iph->tot_len, 0, 
				(struct sockaddr *) &sin, sizeof (sin)) < 0)
	  {
			perror("sendto() error");
			exit(-1);		
          }
	  else
	   break;
	 }

	close(sock_raw);
 	return 0;
}

void handle_client(int fd, struct sockaddr_in* cli_addr)
{
    int req = 0, port = 0;
    long i, ret;
    char *token = NULL;

    ret = read(fd,buffer,BUFSIZE);  

    if (ret==0||ret==-1) {
        exit(3);
    }

    if (ret > 0 && ret < BUFSIZE)
        buffer[ret] = '\0';
    else
        buffer[0] = '\0';

    //split information
    i = 0;
    token = strtok(buffer, ";"); /*There are two delimiters here*/ 
    while (token != NULL)
    {
            printf("The token is:  %s\n", token);

	    switch (i)
	    {
		case 0:
			req = atoi(token);
			break;
		case 1:
			strcpy(dstip, token);
			break;
		case 2:
			port = atoi(token);
			break;
	    }
		
	    i++;
            token = strtok(NULL, ";");
    }

    printf("spoof_data: seq = %d, ip = %s, port = %d\n", req, dstip, port);

    send_asksynpkt(req, cli_addr, dstip, port);

    exit(1);
}


int main(int argc, char **argv) 
{
    int i, pid, listenfd, socketfd;
    size_t length;
    char  vsip[16]="";

    static struct sockaddr_in cli_addr;
    static struct sockaddr_in serv_addr;

    if (getuid() != 0) {
        fprintf(stderr, "stuntd: Need root privileges\n");
        exit(1);
    }

    signal(SIGPIPE, SIG_IGN);
    signal(SIGCLD, SIG_IGN);

    //set Client <--> Server
    if ((listenfd=socket(PF_INET, SOCK_STREAM, IPPROTO_TCP))<0)
        exit(3);

    serv_addr.sin_family = PF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(8787);

    if (bind(listenfd, (struct sockaddr *)&serv_addr,sizeof(serv_addr))<0)
        exit(3);

    if (listen(listenfd,64)<0)
        exit(3);

    while(1) {
        length = sizeof(cli_addr);
        if ((socketfd = accept(listenfd, (struct sockaddr *)&cli_addr, &length))<0)
            exit(3);

        if ((pid = fork()) < 0) {
            exit(3);
        } else {
            if (pid == 0) {
                close(listenfd);
                handle_client(socketfd, &cli_addr);
            } else {
                close(socketfd);
            }
        }
    }

}
