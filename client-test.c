#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <netinet/in.h>
#include <strings.h>
#include <stdio.h>
int main()
{
    int sockfd;
    struct sockaddr_in dest;
    char buffer[128];
    char resp[10]="0;192.168.123.222;90";

    /* create socket */
    sockfd = socket(PF_INET, SOCK_STREAM, 0);
clientack
    /* initialize value in dest */
    bzero(&dest, sizeof(dest));
    dest.sin_family = PF_INET;
    dest.sin_port = htons(8787);
    dest.sin_addr.s_addr = inet_addr("192.168.121.63");

    /* Connecting to server */
    connect(sockfd, (struct sockaddr*)&dest, sizeof(dest));
/*
    //Receive message from the server and print to screen
    bzero(buffer, 128);
    recv(sockfd, buffer, sizeof(buffer), 0);

    printf("receive from server: %s\n", buffer);
    send(sockfd,resp,sizeof(resp),0);
    //Close connection
*/
    close(sockfd);

    return 0;
}
