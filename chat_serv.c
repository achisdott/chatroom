#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>

#define TRUE    1
#define FALSE   0

#define HELO        924
#define WELC        925
#define BYE         926
#define WHO         927
#define NICK_1      928
#define NICK_2      929
#define NICK_ERR_1  930
#define NICK_ERR_2  931
#define NICK_ERR_3  932
#define NICK_ERR_4  933
#define PRIV_1      934
#define PRIV_2      935
#define PRIV_ERR_1  936
#define PRIV_ERR_2  937
#define PRIV_ERR_3  938
#define CMD_ERR     939
#define BRO         940

#define MAX_USER_COUNT 20
#define MAX_NAME_LEN 20
#define BUFFER_SIZE 1024
#define MSG_SIZE 1024

struct profile {
    char name[MAX_NAME_LEN];
    char addr[INET_ADDRSTRLEN];
    char port[6];
};

void init_user(struct profile * [], int);
int buf_loader(struct profile * [], int, int, char [], int, char *);
int send_msg(int, char *, size_t, int);
int broadcast(int [], int, char [], int);
int cmd_process(struct profile * [], int , int [], char [], int);

int main(int argc, char * argv[]) {
    int i, rc, on = 1;
    int listen_sd, max_sd, new_sd;
    int desc_ready, end_server = FALSE;
    int close_conn;
    int connected[MAX_USER_COUNT] = {FALSE};
    char buffer[BUFFER_SIZE];
    struct timeval timeout;
    struct sockaddr_in addr;
    struct fd_set master_set, working_set;
    struct profile * user[MAX_USER_COUNT];

    if(argc < 2) {
        printf("Usage: ./chat_serv <Port>\n");
        return 0;
    }

    /* SOCKET */
    listen_sd = socket(AF_INET, SOCK_STREAM, 0);
    if(listen_sd < 0) {
        perror("socket() failed");
        exit(-1);
    }

    /* SETSOCKOPT */
    rc = setsockopt(listen_sd, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on));
    if(rc < 0) {
        perror("getsockopt() failed");
        close(listen_sd);
        exit(-1);
    }

    /* IOCTL() */
    rc = ioctl(listen_sd, FIONBIO, (char *)&on);
    if(rc < 0) {
        perror("ioctl() failed");
        close(listen_sd);
        exit(-1);
    }

    /* BIND */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(atoi(argv[1]));
    rc = bind(listen_sd, (struct sockaddr *)&addr, sizeof(addr));
    if(rc < 0) {
        perror("bind() failed");
        close(listen_sd);
        exit(-1);
    }

    /* LISTEN */
    rc = listen(listen_sd, 32);
    if(rc < 0) {
        perror("listen() failed");
        close(listen_sd);
        exit(-1);
    }

    FD_ZERO(&master_set);
    max_sd = listen_sd;
    FD_SET(listen_sd, &master_set);

    timeout.tv_sec = 3 * 60;
    timeout.tv_usec =  0;

    do {
        /* SELECT() */
        memcpy(&working_set, &master_set, sizeof(master_set));
        rc = select(max_sd + 1, &working_set, NULL, NULL, &timeout);
        if(rc < 0) {
            perror("select() failed");
            break;
        } else if(rc == 0) {
            printf("select() timeout. End program\n");
            break;
        }

        desc_ready = rc;
        for(i = 0; i <= max_sd && desc_ready > 0 ; i++) {
            if(FD_ISSET(i, &working_set)) {
                desc_ready -= 1;
                if(i == listen_sd) {
                    /* ACCEPT() */
                    do {
                        new_sd = accept(listen_sd, NULL, NULL);
                        if(new_sd < 0) {
                            if(errno != EWOULDBLOCK) {
                                perror("accept() failed");
                                end_server = TRUE;
                            }
                            break;
                        }
                        printf("Connection established: [%d]\n", new_sd);
                        /* HELO */
                        user[new_sd] = (struct profile *)malloc(sizeof(struct profile));
                        init_user(user, new_sd);
                        rc = buf_loader(user, new_sd, HELO, buffer, BUFFER_SIZE, NULL);
                        if(rc < 0) {
                            perror("HELO");
                            end_server = TRUE;
                            break;
                        }
                        send_msg(new_sd, buffer, rc + 1, 0);
                        FD_SET(new_sd, &master_set);
                        if(new_sd > max_sd) {
                            max_sd = new_sd;
                        }
                        connected[new_sd] = TRUE;
                        rc = buf_loader(user, new_sd, WELC, buffer, BUFFER_SIZE, NULL);
                        if(rc < 0) {
                            perror("WELC");
                            end_server = TRUE;
                            break;
                        }
                        printf("%d nick(s)\n", broadcast(connected, new_sd, buffer, rc + 1));
                    } while(TRUE);
                } else {
                    close_conn = FALSE;
                    do {
                        /* RECV() */
                        rc = recv(i, buffer, sizeof(buffer), 0);
                        if(rc < 0) {
                            if(errno != EWOULDBLOCK) {
                                perror("recv() failed");
                                close_conn = TRUE;
                            }
                            break;
                        } else if(rc == 0) {
                            printf("Connection closed: [%d]\n", i);
                            close_conn = TRUE;
                            break;
                        }
                        printf("From [%d]: %s", i, buffer);
                        /* cmd_process */
                        rc = cmd_process(user, i, connected, buffer, sizeof(buffer));
                        if(rc == 1) {
                            close_conn = TRUE;
                            break;
                        }
                    } while(TRUE);

                    /* CLOSE() */
                    if(close_conn) {
                        close(i);
                        free(user[i]);
                        connected[i] = FALSE;
                        rc = buf_loader(user, i, BYE, buffer, BUFFER_SIZE, NULL);
                        printf("%d nick(s)\n", broadcast(connected, i, buffer, rc + 1));
                        FD_CLR(i, &master_set);
                        while(FD_ISSET(max_sd, &master_set) == FALSE) {
                            max_sd -= 1;
                        }
                    }
                }
            }
        }
    } while(end_server == FALSE);

    /* CLOSE() */
    for(i = 0; i <= max_sd; i++) {
        if(FD_ISSET(i, &master_set)) {
            close(i);
        }
    }

    return 0;
}

void init_user(struct profile * user[], int itself) {
    struct sockaddr_in sin;
    socklen_t slen = sizeof(sin);
    if(getpeername(itself, (struct sockaddr *)&sin, &slen) == -1) {
        perror("getpeername()");
    } else {
        snprintf(user[itself]->name, MAX_NAME_LEN, "%s", "anonymous");
        inet_ntop(AF_INET, &(sin.sin_addr), user[itself]->addr, INET_ADDRSTRLEN);
        snprintf(user[itself]->port, 6, "%u", ntohs(sin.sin_port));
    }
    return ;
}

int buf_loader(struct profile * user[], int itself, int msg_type, char buf[], int size, char * payload) {
    int msg_len = 0;
    char ip_buf[INET_ADDRSTRLEN];
    char port_buf[6];
    struct sockaddr_in sin;
    socklen_t slen = sizeof(sin);

    switch(msg_type) {
        case HELO:
            if(getsockname(itself, (struct sockaddr *)&sin, &slen) == -1) {
                perror("getsockname()");
            }
            else {
                inet_ntop(AF_INET, &(sin.sin_addr), ip_buf, INET_ADDRSTRLEN);
                snprintf(port_buf, sizeof(port_buf), "%u", ntohs(sin.sin_port));
            }
            msg_len = snprintf(buf, size, "/serv Hello, %s! ServerIP: %s:%s\n", user[itself]->name, ip_buf, port_buf);
            break;
        case WELC:
            msg_len = snprintf(buf, size, "/serv Someone is coming!\n");
            break;
        case BYE:
            msg_len = snprintf(buf, size, "/serv %s is offline.\n", user[itself]->name);
            break;
        case WHO:
            msg_len = snprintf(buf, size, "/serv %s %s:%s\n", user[itself]->name, user[itself]->addr, user[itself]->port);
            break;
        case NICK_1:
            msg_len = snprintf(buf, size, "/serv %s is now known as %s.\n", user[itself]->name, payload);
            break;
        case NICK_2:
            msg_len = snprintf(buf, size, "/serv You're now known as %s.\n", user[itself]->name);
            break;
        case NICK_ERR_1:
            msg_len = snprintf(buf, size, "/serv ERROR: Username can only consists of 2~12 English letters.\n");
            break;
        case NICK_ERR_2:
            msg_len = snprintf(buf, size, "/serv ERROR: Username can not be anonymous.\n");
            break;
        case NICK_ERR_3:
            msg_len = snprintf(buf, size, "/serv ERROR: Username can only consists of 2~12 English letters.\n");
            break;
        case NICK_ERR_4:
            msg_len = snprintf(buf, size, "/serv ERROR: %s has been used by others.\n", user[itself]->name);
            break;
        case PRIV_1:
            msg_len = snprintf(buf, size, "/serv SUCCESS: Your message has been sent.\n");
            break;
        case PRIV_2:
            msg_len = snprintf(buf, size, "/private %s %s", user[itself]->name, payload);
            break;
        case PRIV_ERR_1:
            msg_len = snprintf(buf, size, "/serv ERROR: You are anonymous.\n");
            break;
        case PRIV_ERR_2:
            msg_len = snprintf(buf, size, "/serv ERROR: The client to which you sent is anonymous.\n");
            break;
        case PRIV_ERR_3:
            msg_len = snprintf(buf, size, "/serv ERROR: The receiver doesn't exist.\n");
            break;
        case CMD_ERR:
            msg_len = snprintf(buf, size, "/serv ERROR: Error command.\n");
            break;
        case BRO:
            msg_len = snprintf(buf, size, "/msg %s SAID: %s", user[itself]->name, payload);
            break;
        default:
            msg_len = 0;
    };

    return msg_len;
}

int send_msg(int s, char * msg, size_t len, int flags) {
    int rc = 0;
    rc = send(s, msg, len, flags);
    printf("To [%d]: %s", s, msg);

    return rc;
}

int broadcast(int connected[], int itself, char buf[], int size) {
    int i, count = 0;
    for(i = 0; i < MAX_USER_COUNT; i++) {
        if(connected[i] == TRUE) {
            if(i != itself) {
                send_msg(i, buf, size, 0);
            }
            count++;
        }
    }
    return count;
}

int cmd_process(struct profile * user[], int itself, int connected[], char buf[], int size) {
    int i, line_len = 0;
    char * cmd = NULL;
    char * content = NULL;
    char * nick = NULL;
    char * tmp = NULL;
    char msg[MSG_SIZE];

    tmp = (char *)malloc(size * sizeof(char));
    memcpy(tmp, buf, size * sizeof(char));
    cmd = strtok(tmp, " ");

    if(!strcmp("/who\n", cmd) || !strcmp("/who", cmd)) {
        for(i = 0; i < MAX_USER_COUNT; i++) {
            if(connected[i] == TRUE) {
                line_len = buf_loader(user, i, WHO, msg, MSG_SIZE, NULL);
                send_msg(itself, msg, line_len + 1, 0);
            }
        }
        return 0;
    } else if(!strcmp("/nick", cmd)) {
        content = tmp + strlen(cmd) + 1;
        nick = strtok(content, " ");
        nick[strlen(nick) - 1] = '\0';
        if(strlen(nick) < 2 || strlen(nick) > 12) {
            line_len = buf_loader(user, itself, NICK_ERR_1, msg, MSG_SIZE, NULL);
            send_msg(itself, msg, line_len + 1, 0);
            return -1;
        } else if(!strcmp("anonymous", nick)) {
            line_len = buf_loader(user, itself, NICK_ERR_2, msg, MSG_SIZE, NULL);
            send_msg(itself, msg, line_len + 1, 0);
            return -1;
        } else {
            for(i = 0; i < strlen(nick); i++) {
                if(!isalpha(nick[i])) {
                    line_len = buf_loader(user, itself, NICK_ERR_3, msg, MSG_SIZE, NULL);
                    send_msg(itself, msg, line_len + 1, 0);
                    return -1;
                }
            }
            for(i = 0; i < MAX_USER_COUNT; i++) {
                if(itself == i) {
                    continue;
                }
                if(connected[i] == TRUE) {
                    if(!strcmp(user[i]->name, nick)) {
                        line_len = buf_loader(user, i, NICK_ERR_4, msg, MSG_SIZE, NULL);
                        send_msg(itself, msg, line_len + 1, 0);
                        return -1;
                    }
                }
            }
        }
        line_len = buf_loader(user, itself, NICK_1, msg, MSG_SIZE, nick);
        broadcast(connected, itself, msg, line_len + 1);
        snprintf(user[itself]->name, MAX_NAME_LEN, "%s", nick);
        line_len = buf_loader(user, itself, NICK_2, msg, MSG_SIZE, NULL);
        send_msg(itself, msg, line_len + 1, 0);
        return 0;
    } else if(!strcmp("/private", cmd)) {
        if(!strcmp(user[itself]->name, "anonymous")) {
            line_len = buf_loader(user, itself, PRIV_ERR_1, msg, MSG_SIZE, NULL);
            send_msg(itself, msg, line_len + 1, 0);
            return -1;
        }
        content = tmp + strlen(cmd) + 1;
        nick = strtok(content, " ");
        if(!strcmp(nick, "anonymous")) {
            line_len = buf_loader(user, itself, PRIV_ERR_2, msg, MSG_SIZE, NULL);
            send_msg(itself, msg, line_len + 1, 0);
            return -1;
        }
        for(i = 0; i < MAX_USER_COUNT; i++) {
            if(connected[i] == TRUE) {
                if(!strcmp(user[i]->name, nick)) {
                    content = content + strlen(nick) + 1; /* CAUTION! MAY COREDUMP */
                    line_len = buf_loader(user, itself, PRIV_1, msg, MSG_SIZE, NULL);
                    send_msg(itself, msg, line_len + 1, 0);
                    line_len = buf_loader(user, itself, PRIV_2, msg, MSG_SIZE, content);
                    send_msg(i, msg, line_len + 1, 0);
                    return 0;
                }
            }
        }
        line_len = buf_loader(user, itself, PRIV_ERR_3, msg, MSG_SIZE, NULL);
        send_msg(itself, msg, line_len + 1, 0);
        return -1;
    } else if(cmd[0] == '/') {
        line_len = buf_loader(user, itself, CMD_ERR, msg, MSG_SIZE, NULL);
        send_msg(itself, msg, line_len + 1, 0);
        return -1;
    } else {
        line_len = buf_loader(user, itself, BRO, msg, MSG_SIZE, buf);
        broadcast(connected, itself, msg, line_len + 1);
        send_msg(itself, msg, line_len + 1, 0);
        return 0;
    }
    return 0;
}
