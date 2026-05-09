#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <netdb.h>
#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>

int main(int argc, char *argv[]) {

    if (argc != 3) {
        std::cout << "wrong number of arguments\n";
    }

    std::cout << "connecting to " << argv[1] << " with port " << argv[2] << "\n";

    struct sockaddr_in server;
    struct addrinfo addr;
    char host_buf[NI_MAXHOST];
    int sd = socket(AF_INET,SOCK_STREAM,0);

    if ( sd == -1 ) {
        std::cerr << "Failed to open socket\n";
    }

    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(atoi(argv[2]));

    if ( inet_pton(AF_INET, argv[1], &server.sin_addr) <= 0 ) {
        std::cerr << "Failed to convert ip\n";
    }
    int res = connect(sd, (struct sockaddr *) &server, sizeof(server));
    if (res == -1){
        std::cerr << "Failed to connect to server";
    }

    for (;;) {
        char buf[] = "Hello!";
        send(sd, buf, strlen(buf), 0 );
        printf("Sent: %s\n", buf);
        sleep(2);
    }
}
