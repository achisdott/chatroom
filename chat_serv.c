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

#define HELO        918
#define USRNAME     919
#define USR_ERR_1   920
#define PASSWD      921
#define PASSWD_ERR  922
#define PASSWD_BLK  923
#define BLOCK       924
#define WELC        925
#define BYE         926
#define WHOELSE     927
#define WHOLASTHR_1 928
#define WHOLASTHR_2 929
#define NICK_1      930
#define NICK_2      931
#define NICK_ERR_1  932
#define NICK_ERR_2  933
#define NICK_ERR_3  934
#define NICK_ERR_4  935
#define PRIV_1      936
#define PRIV_2      937
#define PRIV_ERR_1  938
#define PRIV_ERR_2  939
#define PRIV_ERR_3  980
#define CMD_ERR     941
#define CLI_TIMEOUT 942
#define BRO         943

#define MAX_USER_COUNT 20
#define MAX_BLOCK_COUNT 20
#define MAX_NAME_LEN 20
#define BUFFER_SIZE 1024
#define MSG_SIZE 1024
#define TIME_OUT 1800  //time-out for clients in seconds
#define LAST_HOUR 3600  //an hour in seconds
#define BLOCK_TIME 60  //in seconds


struct profile {
    char name[MAX_NAME_LEN];
    char addr[INET_ADDRSTRLEN];
    char port[6];
    int  login_flag; //0: new, 1: valid username received, 2: logged in, 4: three times failed login
    int  occupy_flag; //to defermine if freed, seems necessary for clang
    int  usr_no;
    int  usr_no_prev;  //previous login username, to determine login fails
    int  failed_attempts;
    time_t login_time;
    time_t active_since; //note that inactive users include those who haven't finished logging in
};

void init_user(struct profile * [], int);
int buf_loader(struct profile * [], int, int, char [], int, char *);
int send_msg(int, char *, size_t, int);
int broadcast(int [], int, char [], int);
int cmd_process(struct profile * [], int , int [], char [], int);
int usr_process(struct profile * [], int , int [], char [], int);
int time_logout_list[MAX_USER_COUNT];
time_t time_now;
char * usrlist[MAX_USER_COUNT];
char * passlist[MAX_USER_COUNT];
char * blocklist[MAX_USER_COUNT][MAX_BLOCK_COUNT];
int blocktime[MAX_USER_COUNT][MAX_BLOCK_COUNT];
int blocksize[MAX_USER_COUNT];
struct profile * user[MAX_USER_COUNT];

int main(int argc, char * argv[]) {
    int i, j, k, rc, on = 1;
    int usr_no, usr_no_prev = -1;
    int listen_sd, max_sd, new_sd;
    int desc_ready, end_server = FALSE;
    int connected[MAX_USER_COUNT] = {FALSE};
    int close_conn = 0;
    int failed_user = FALSE;
    char buffer[BUFFER_SIZE];
    struct timeval timeout;
    struct sockaddr_in addr;
    fd_set master_set, working_set;  //struct fd_set works for clang and gcc 4.9 but not earlier versions

    for (i = 0; i < MAX_USER_COUNT; i++) {
        time_logout_list[i] = -1;
        usrlist[i] = "";
        passlist[i] = "";
        blocksize[i] = 0;
        for (j = 0; j < MAX_BLOCK_COUNT; j++) {
            blocklist[i][j] = "";
            blocktime[i][j] = 0;
        }
    }
    char **arr_lines;
    char **arr_lines_b;
    char buf_file[BUFFER_SIZE], buf_line[16], buf_line_b[16];
    int num_lines = 0;
    FILE* file = fopen("user_pass.txt", "r");
    char * pch;
    if (file) {
        while (fgets(buf_file, BUFFER_SIZE, file))
            if (!(strlen(buf_file) == BUFFER_SIZE-1 && buf_file[BUFFER_SIZE-2] != '\n'))
                num_lines++;
        arr_lines = malloc(num_lines * sizeof(char*));
        arr_lines_b = malloc(num_lines * sizeof(char*));
        rewind(file);
        i = 0;
        while (!feof(file) && i < num_lines) {
            arr_lines[i] = malloc(16 * sizeof(char));
            arr_lines_b[i] = malloc(16 * sizeof(char));
            fscanf(file, "%s %s", buf_line, buf_line_b);
            //printf("%s %s\n", buf_line, buf_line_b);
            strcpy(arr_lines[i], buf_line);
            usrlist[i] = arr_lines[i];
            //printf("%s\n", usrlist[i]);
            strcpy(arr_lines_b[i], buf_line_b);
            //printf("%s \n", arr_lines[i]);
            //pch = strtok(arr_lines[i]," ");
            //pch = strtok(NULL, " ");
            //pch[strlen(pch) - 1] = '\0';
            passlist[i] = arr_lines_b[i];
            //printf("%s\n", passlist[i]);
            //printf("Creating user %d.\n", i);
            i++;
        }
        fclose(file);
        printf("Userlist imported. %d accounts in total.\n", i);
    } else {
        printf("Userlist user_pass.txt does not exist.\n");
        return 0;
    }

    time_now = time(NULL);
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

    timeout.tv_sec = 1;
    timeout.tv_usec =  0;

    printf("Server ready. Waiting for incoming clients.\n");
    do {
        /* SELECT() */
        memcpy(&working_set, &master_set, sizeof(master_set));
        rc = select(max_sd + 1, &working_set, NULL, NULL, &timeout);
        
            for (i = 0; i < MAX_USER_COUNT; i++) {
                if (blocksize[i] > 0) {
                    for (j = 0; j < blocksize[i]; j++) {
                        if (blocktime[i][j] > 0 && (int)time(NULL) - blocktime[i][j] > BLOCK_TIME) {
                            if (blocksize[i] != MAX_BLOCK_COUNT)
                                for (k = j; k < blocksize[i]; k++) {
                                    blocklist[i][k] = blocklist[i][k+1];
                                    blocktime[i][k] = blocktime[i][k+1];
                                }
                            else {
                                blocklist[i][blocksize[i]] = "";
                                blocktime[i][blocksize[i]] = 0;
                            }
                            blocksize[i] -= 1;
                        }
                    }
                }
            }
        /* log out inactive user */
        if (max_sd > listen_sd) {
            for(i = listen_sd + 1; i <= max_sd; i++) {
                //printf("checkpoint: checking if user %d %s is active. \n",i,user[i]->name);
                time_now = time(NULL);
                //printf("checkpoint: time %d\n",(int)time_now);
                //printf("checkpoint: user %d idle time %d\n",i,(int)time_now - (int)user[i]->active_since);
                if ((int)time_now - (int)user[i]->active_since > TIME_OUT && user[i]->occupy_flag == 1) {
                    close_conn = TRUE;
                    rc = buf_loader(user, i, CLI_TIMEOUT, buffer, BUFFER_SIZE, NULL);
                    send_msg(i, buffer, rc + 1, 0);
                }
                if(close_conn) {
                    for (j = 0; j < MAX_USER_COUNT; j++) {
                        if (strcmp(user[i]->name, usrlist[j]) == 0) {
                            time_logout_list[j] = (int)time(NULL);
                            break;
                        }
                    }
                    user[i]->occupy_flag = 0;
                    if (strcmp(user[i]->name,"anonymous") != 0) {
                        rc = buf_loader(user, i, BYE, buffer, BUFFER_SIZE, NULL);
                        printf("%d nick(s)\n", broadcast(connected, i, buffer, rc + 1) - 1);
                    }
                    close(i);
                    free(user[i]);
                    connected[i] = FALSE;
                    FD_CLR(i, &master_set);
                    while(FD_ISSET(max_sd, &master_set) == FALSE) {
                        max_sd -= 1;
                    }
                    close_conn = FALSE;
                    break;
                }
            }
        }
        /* time flag            
        if ((int)time(NULL) != (int)time_now) {
        time_now = time(NULL);
        printf("Checkpoint: Time %d\n", (int)time_now);
        }
        */

        if(rc < 0) {
            perror("select() failed");
            break;
    //    } else if(rc == 0) {
    //        printf("select() timeout. End program\n");
    //        break;
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
                        //printf("checkpoint: HELO sent.\n");
                        /*rc = buf_loader(user, new_sd, USRNAME, buffer, BUFFER_SIZE, NULL);
                        if(rc < 0) {
                            perror("USRNAME");
                            end_server = TRUE;
                            break;
                        }
                        send_msg(new_sd, buffer, rc + 1, 0);
                        printf("checkpoint: USRNAME sent.\n");
                       */
                        FD_SET(new_sd, &master_set);
                        if(new_sd > max_sd) {
                            max_sd = new_sd;
                        }
                        connected[new_sd] = TRUE;

                    } while(TRUE);
                } else {
                    close_conn = FALSE;
                    //do {
                        /* RECV() */
                        //printf("checkpoint: new recv\n"); //checkpoint
                        rc = recv(i, buffer, sizeof(buffer), 0);
                        user[i]->active_since = time(NULL);
                        //printf("checkpoint: user %d idle since %d\n",i,(int)user[i]->active_since);
                        if(rc < 0) {
                            if(errno != EWOULDBLOCK) {
                                perror("recv() failed");
                                close_conn = TRUE;
                            }
                            //break;
                        } else if(rc == 0) {
                            printf("Connection closed: [%d]\n", i);
                            close_conn = TRUE;
                            //break;
                        }
                        if (rc > 0) {
                            printf("From [%d]: %s", i, buffer);
                        } else if (rc == 0){
                            printf("Close connection signal from [%d].\n", i);
                        }
                        switch (user[i]->login_flag) {
                            case 0:
                                /* usr_process */
                                //printf("checkpoint nick = %s \n", buffer);
                                if (rc > 0)
                                    usr_no = usr_process(user, i, connected, buffer, sizeof(buffer));
                                //printf("checkpoint usr_no = %d \n", usr_no);
                                break;
                            case 1:
                                /* password */
                                //printf("checkpoint pass = %s \n", buffer);
                                buffer[strlen(buffer) - 1] = '\0';
                                //printf("comparing input %s and record %s, strcmp %d, usr_no = %d \n", buffer, passlist[usr_no], strcmp(buffer, passlist[usr_no]), usr_no);
                                if (strcmp(buffer, passlist[usr_no]) == 0) {
                                    user[i]->login_flag = 2;
                                    user[i]->login_time = time(NULL);
                                    /* welc */
                                    rc = buf_loader(user, i, NICK_2, buffer, BUFFER_SIZE, NULL);
                                    send_msg(i, buffer, rc + 1, 0);
                                    rc = buf_loader(user, i, WELC, buffer, BUFFER_SIZE, NULL);
                                    /*if(rc < 0) {
                                        perror("WELC");
                                        end_server = TRUE;
                                        break;
                                    }*/
                                    printf("%d nick(s)\n", broadcast(connected, i, buffer, rc + 1));
                                } else {
                                    user[i]->login_flag = 0;
                                    if (user[i]->usr_no == user[i]->usr_no_prev)
                                        user[i]->failed_attempts++;
                                    user[i]->usr_no_prev = user[i]->usr_no;
                                    rc = buf_loader(user, i, PASSWD_ERR, buffer, BUFFER_SIZE, NULL);
                                    send_msg(i, buffer, rc + 1, 0);
                                    if (user[i]->failed_attempts == 2) {
                                        blocklist[usr_no][blocksize[usr_no]] = user[i]->addr;
                                        blocktime[usr_no][blocksize[usr_no]] = (int)time(NULL);
                                        blocksize[usr_no]++;
                                        perror("login failed");
                                        rc = buf_loader(user, i, PASSWD_BLK, buffer, BUFFER_SIZE, NULL);
                                        send_msg(i, buffer, rc + 1, 0);
                                        close_conn = TRUE;
                                        user[i]->failed_attempts = 0;
                                        break;
                                    }
                                }

                                break;

                            case 2:
                                /* cmd_process */
                                rc = cmd_process(user, i, connected, buffer, sizeof(buffer));
                                if(rc == 1) {
                                    close_conn = TRUE;
                                    //break;
                                }
                                break;
                            case 4:
                                user[i]->login_flag = 0;
                                close_conn = TRUE;
                                failed_user = TRUE;
                                break;

                        }
                    //} while(TRUE);
                    
                    //printf("Message processed.\n");
                    /* CLOSE() */
                    if(close_conn) {
                        for (j = 0; j < MAX_USER_COUNT; j++) {
                            if (strcmp(user[i]->name, usrlist[j]) == 0) {
                                time_logout_list[j] = (int)time(NULL);
                                break;
                            }
                        }
                        if (!failed_user) {
                            if (strcmp(user[i]->name,"anonymous") != 0) {
                                rc = buf_loader(user, i, BYE, buffer, BUFFER_SIZE, NULL);
                                printf("%d nick(s)\n", broadcast(connected, i, buffer, rc + 1) - 1);
                            }
                        } else {
                            failed_user = FALSE;
                        }
                        close(i);
                        free(user[i]);
                        connected[i] = FALSE;
                        FD_CLR(i, &master_set);
                        while(FD_ISSET(max_sd, &master_set) == FALSE) {
                            max_sd -= 1;
                        }
                        close_conn = FALSE;
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
        user[itself]->occupy_flag = 1;
        user[itself]->login_flag = 0;
        user[itself]->usr_no = -1;
        user[itself]->usr_no_prev = -1;
        user[itself]->failed_attempts = 0;
        user[itself]->login_time = 0;
        user[itself]->active_since = time(NULL);
        if (user[itself]->login_time == ((time_t)-1) || user[itself]->active_since == ((time_t)-1) ) {
            perror("time() failed");
            //end_server = TRUE;
            //break;
        }
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
            msg_len = snprintf(buf, size, "/serv Hello! Server IP: %s:%s. Enter username below, then press return key and enter password. \n", ip_buf, port_buf);
            break;
        case USRNAME:
            msg_len = snprintf(buf, size, "/serv Username: ");
            break;
        case USR_ERR_1:
            msg_len = snprintf(buf, size, "/serv ERROR: The username you entered does not exist. Please re-enter username and then password.\n");
            break;
        case PASSWD:
            msg_len = snprintf(buf, size, "/serv Password: ");
            break;
        case PASSWD_ERR:
            msg_len = snprintf(buf, size, "/serv ERROR: Wrong password. Please re-enter username and then password. \n");
            break;
        case PASSWD_BLK:
            msg_len = snprintf(buf, size, "/serv ERROR: 3 failed attemps to log in. Blocked from logging in as %s for %d seconds. \n", user[itself]->name, BLOCK_TIME);
            break;
        case BLOCK:
            msg_len = snprintf(buf, size, "/serv This user is temporarily blocked from this host. Press return key to quit.\n");
            break;
        case WELC:
            msg_len = snprintf(buf, size, "/serv User %s is coming!\n", user[itself]->name);
            break;
        case BYE:
            msg_len = snprintf(buf, size, "/serv %s is offline.\n", user[itself]->name);
            break;
        case WHOLASTHR_1:
            msg_len = snprintf(buf, size, "/serv %s\n", user[itself]->name);
            break;
        case WHOLASTHR_2:
            msg_len = snprintf(buf, size, "/serv %s\n", usrlist[itself]);
            break;
        case WHOELSE:
            msg_len = snprintf(buf, size, "/serv %s %s:%s\n", user[itself]->name, user[itself]->addr, user[itself]->port);
            break;
        case NICK_1:
            msg_len = snprintf(buf, size, "/serv %s is now known as %s.\n", user[itself]->name, payload);
            break;
        case NICK_2:
            msg_len = snprintf(buf, size, "/serv Welcome, %s. COMMANDS: broadcast, message, whoelse, wholasthr, logout.\n", user[itself]->name);
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
            msg_len = snprintf(buf, size, "/serv ERROR: %s has already logged in.\n", user[itself]->name);
            break;
        case PRIV_1:
            msg_len = snprintf(buf, size, "/serv SUCCESS: Your message has been sent.\n");
            break;
        case PRIV_2:
            msg_len = snprintf(buf, size, "/private %s: %s", user[itself]->name, payload);
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
        case CLI_TIMEOUT:
            msg_len = snprintf(buf, size, "/serv Client time-out. Logging off.\n");
            break;
        case BRO:
            msg_len = snprintf(buf, size, "/msg %s: %s", user[itself]->name, payload);
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
        if(connected[i] == TRUE && user[i]->login_flag == 2) {
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
    int j = -1;
    char * cmd = NULL;
    char * content = NULL;
    char * nick = NULL;
    char * tmp = NULL;
    char msg[MSG_SIZE];

    tmp = (char *)malloc(size * sizeof(char));
    memcpy(tmp, buf, size * sizeof(char));
    cmd = strtok(tmp, " ");

    if(!strcmp("whoelse\n", cmd) || !strcmp("whoelse", cmd)) {
        for(i = 0; i < MAX_USER_COUNT; i++) {
            if(connected[i] == TRUE && i != itself && (strcmp(user[i]->name,"anonymous") != 0)) {
                line_len = buf_loader(user, i, WHOELSE, msg, MSG_SIZE, NULL);
                send_msg(itself, msg, line_len + 1, 0);
            }
        }
        return 0;
    } else if(!strcmp("wholasthr\n", cmd) || !strcmp("wholasthr", cmd)) {
        time_now = time(NULL);
        for(i = 0; i < MAX_USER_COUNT; i++) {
            if(connected[i] == TRUE && i != itself) {
                if (strcmp(user[i]->name,"anonymous") != 0) {
                    line_len = buf_loader(user, i, WHOLASTHR_1, msg, MSG_SIZE, NULL);
                    send_msg(itself, msg, line_len + 1, 0);
                    j = i;
                }
            }
        }
        for(i = 0; i < MAX_USER_COUNT; i++) {
            if((int)time_now - time_logout_list[i] < LAST_HOUR && strcmp(usrlist[i], user[itself]->name) != 0) { 
                if (j < 0) {
                    line_len = buf_loader(user, i, WHOLASTHR_2, msg, MSG_SIZE, NULL);
                    send_msg(itself, msg, line_len + 1, 0);
                } else if (strcmp(usrlist[i], user[j]->name) != 0) {
                    line_len = buf_loader(user, i, WHOLASTHR_2, msg, MSG_SIZE, NULL);
                    send_msg(itself, msg, line_len + 1, 0);
                }
            }
        }
        return 0;
    } else if(!strcmp("message", cmd)) {
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
    } else if(!strcmp("broadcast", cmd)) {
        content = tmp + strlen(cmd) + 1;
        line_len = buf_loader(user, itself, BRO, msg, MSG_SIZE, content);
        broadcast(connected, itself, msg, line_len + 1);
        send_msg(itself, msg, line_len + 1, 0);
        return 0;
    } else {
        line_len = buf_loader(user, itself, CMD_ERR, msg, MSG_SIZE, NULL);
        send_msg(itself, msg, line_len + 1, 0);
        return -1;
    }
    return 0;
}
int usr_process(struct profile * user[], int itself, int connected[], char buf[], int size) {
    int i, line_len = 0;
    int usr_no = -1;
    char * content = NULL;
    char * nick = NULL;
    char * tmp = NULL;
    char msg[MSG_SIZE];

    //tmp = (char *)malloc(size * sizeof(char));
    //memcpy(tmp, buf, size * sizeof(char));
    //usr = strtok(tmp, " ");

    //content = tmp + strlen(usr) + 1;
    nick = buf;
    nick[strlen(nick) - 1] = '\0';
    if(strlen(nick) < 2 || strlen(nick) > 12) {
        line_len = buf_loader(user, itself, NICK_ERR_1, msg, MSG_SIZE, NULL);
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
    i = 0;
    while (i < MAX_USER_COUNT && usr_no == -1) {
        if (strcmp(nick, usrlist[i]) == 0)
            usr_no = i;
        //printf("comparing input %s and record %s, strcmp %d, usr_no = %d \n", nick, usrlist[i], strcmp(nick, usrlist[i]), usr_no);
        i++;
    }
    if (usr_no > -1) {
        //i = 0;
        for (i = 0; i < blocksize[usr_no]; i++) {
            printf("checking if blocked.\n");
            if (strcmp(blocklist[usr_no][i], user[itself]->addr) == 0) {
                line_len = buf_loader(user, itself, BLOCK, msg, MSG_SIZE, NULL);
                send_msg(itself, msg, line_len + 1, 0);
                user[itself]->login_flag = 4;
            }
        }
        if (user[itself]->login_flag != 4) {
            user[itself]->login_flag = 1;
            snprintf(user[itself]->name, MAX_NAME_LEN, "%s", nick);
            user[itself]->usr_no = usr_no;
            //line_len = buf_loader(user, itself, PASSWD, msg, MSG_SIZE, NULL);
            //send_msg(itself, msg, line_len + 1, 0);
        }
    } else {
        line_len = buf_loader(user, itself, USR_ERR_1, msg, MSG_SIZE, NULL);
        send_msg(itself, msg, line_len + 1, 0);
    }
    /*
    line_len = buf_loader(user, itself, NICK_1, msg, MSG_SIZE, nick);
    broadcast(connected, itself, msg, line_len + 1);
    snprintf(user[itself]->name, MAX_NAME_LEN, "%s", nick);
    line_len = buf_loader(user, itself, NICK_2, msg, MSG_SIZE, NULL);
    send_msg(itself, msg, line_len + 1, 0);
    */
    return usr_no;
}

