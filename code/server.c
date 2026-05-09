#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <iostream>

int main(int argc, char *argv[]) {

    if (argc != 2) {
        std::cout << "wrong number of arguments\n";
	return 1;
    }

    struct sockaddr_in server;
    char buf[1024];
    int sd = socket(AF_INET, SOCK_STREAM, 0);

    if ( sd == -1 ) {
        std::cerr << "Failed to open socket\n";
    }

    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;

    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(atoi(argv[1]));

    int res = bind( sd, (struct sockaddr *) &server, sizeof(server) );
    if( res == -1 ) { 
        std::cerr << "Failed to bind\n";
    }

    listen(sd,1);
    int psd = accept(sd, 0, 0);
    close(sd);

    for(;;) {
        int cc=recv(psd,buf,sizeof(buf), 0);
        if (cc == 0) exit (EXIT_SUCCESS);
        buf[cc] = '\0';
        printf("message received: %s\n", buf); 
	send(psd, buf, strlen(buf), 0);
    }
}

