#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

void show_msg(char [], int);

int main(int argc, char * argv[]) {
    int len, rc;
    int sockfd;
    int maxfd;
    char send_buf[1024];
    char recv_buf[1024];
    char * recv_tmp = recv_buf;
    struct hostent * host;
    struct sockaddr_in addr;
    fd_set rset;

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
            recv_tmp = recv_buf;
            len = recv(sockfd, recv_buf, sizeof(recv_buf), 0);
            if(len != strlen(recv_buf) + 1) {
                if(len == 0) {
                    printf("Connection closed by server\n");
                    break;
                } else if(len < 0) {
                    perror("recv() failed");
                    close(sockfd);
                    exit(-1);
                } else {
                    while((recv_tmp - recv_buf) < len) {
                        show_msg(recv_tmp, sizeof(recv_buf));
                        recv_tmp = recv_tmp + strlen(recv_tmp) + 1;
                    }
                }
            } else {
                show_msg(recv_buf, sizeof(recv_buf));
                memset(recv_buf, 0, sizeof(recv_buf));
            }
        }
        if(FD_ISSET(fileno(stdin), &rset)) {
            if(fgets(send_buf, 1024, stdin) == NULL || !strcmp("logout\n", send_buf)) {
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

void show_msg(char buf[], int size) {
    char * cmd = NULL;
    char * content = NULL;
    char * msg = NULL;
    char * tmp = NULL;

    tmp = (char *)malloc(size * sizeof(char));
    memcpy(tmp, buf, size * sizeof(char));

    cmd = strtok(tmp, " ");
    content = buf + strlen(cmd) + 1;

    msg = (char *)malloc(size * sizeof(char));
    memset(msg, 0, size);
    if(!strcmp("/serv", cmd)) {
        snprintf(msg, size, "[Server]: %s", content);
    } else if(!strcmp("/private", cmd)) {
        snprintf(msg, size, "[Private]: %s", content);
    } else if(!strcmp("/msg", cmd)) {
        snprintf(msg, size, "%s", content);
    }
    printf("%s", msg);

    free(msg);
    free(tmp);

    return ;
}

