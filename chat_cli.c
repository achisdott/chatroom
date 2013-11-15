#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

int main(int argc, char * argv[]) {
    int len, rc;
    int sockfd;
    int maxfd;
    char send_buf[1024];
    char recv_buf[1024];
    struct hostent * host;
    struct sockaddr_in addr;
    struct fd_set rset;

    if(argc < 3) {
        printf("Usage: ./chat_cli <IP> <Port>\n");
        return 0;
    }

    /* GETHOSTBYNAME() */
    host = gethostbyname(argv[1]);
    if(host == NULL) {
        perror("gethostbyname() failed");
        exit(-1);
    }

    /* SOCKET() */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0) {
        perror("socket() failed");
        exit(-1);
    }

    /* CONNECT() */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    /*addr.sin_addr.s_addr = htonl(INADDR_ANY);*/
    memcpy(&addr.sin_addr, host->h_addr, host->h_length);
    addr.sin_port = htons(atoi(argv[2]));
    rc = connect(sockfd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
    if(rc < 0) {
        perror("connect() failed");
        close(sockfd);
        exit(-1);
    }

    FD_ZERO(&rset);

    while(1) {
        FD_SET(fileno(stdin), &rset);
        FD_SET(sockfd, &rset);
        maxfd = (fileno(stdin) > sockfd)? fileno(stdin): sockfd;
        rc = select(maxfd + 1, &rset, NULL, NULL, NULL);
        if(FD_ISSET(sockfd, &rset)) {
            /* RECV() */
            len = recv(sockfd, recv_buf, sizeof(recv_buf), 0);
            if(len != strlen(recv_buf) + 1) {
                if(len == 0) {
                    printf("Connection closed by server\n");
                    break;
                } else {
                    /*printf("%d\n", len);
                    printf("%s", recv_buf);*/
                    perror("recv() failed");
                    close(sockfd);
                    exit(-1);
                }
            }
            /*printf("%d\n", len);*/
            printf("%s", recv_buf);
            memset(recv_buf, 0, sizeof(recv_buf));
        }
        if(FD_ISSET(fileno(stdin), &rset)) {
            if(fgets(send_buf, 1024, stdin) == NULL) {
                printf("Bye!\n");
                break;
            } else {
                /* SEND() */
                len = send(sockfd, send_buf, strlen(send_buf) + 1, 0);
                if(len != strlen(send_buf) + 1) {
                    perror("send() failed");
                    close(sockfd);
                    exit(-1);
                }
            }
        }
    }

    /* CLOSE() */
    close(sockfd);

    return 0;
}
