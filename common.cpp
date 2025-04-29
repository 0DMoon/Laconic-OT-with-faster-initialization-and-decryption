#include "common.h"

int tcp_client(char *address, int port) {
    int socket_fd;
    socket_fd = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in server_addr;
    bzero(&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, address, &server_addr.sin_addr);

    socklen_t server_len = sizeof(server_addr);
    int connect_rt = connect(socket_fd, (struct sockaddr *) &server_addr, server_len);
    if (connect_rt < 0) {
        // error(1, errno, (char*)"connect failed ");
        printf("connect failed.\n");
        return -1;
    }

    return socket_fd;
}

int tcp_server(int port) {
    int listenfd;
    listenfd = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in server_addr;
    bzero(&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(port);

    int on = 1;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    int rt1 = bind(listenfd, (struct sockaddr *) &server_addr, sizeof(server_addr));
    if (rt1 < 0) {
        // error(1, errno, (char*)"bind failed ");
        printf("bind failed.\n");
        return -1;
    }

    int rt2 = listen(listenfd, LISTENQ);
    if (rt2 < 0) {
        // error(1, errno, (char*)"listen failed ");
        printf("listen failed.\n");
        return -1;
    }

    signal(SIGPIPE, SIG_IGN);

    int connfd;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    if ((connfd = accept(listenfd, (struct sockaddr *) &client_addr, &client_len)) < 0) {
        // error(1, errno, (char*)"bind failed ");
        printf("bind failed.\n");
        return -1;
    }

    return connfd;
}
