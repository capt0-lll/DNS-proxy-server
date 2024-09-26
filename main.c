#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <server.h>


int main() {
    ServerConfig *serverConfig = readConfig("config.json");

    int sockfd;
    struct sockaddr_in serverAddress, clientAddress;
    socklen_t addrLen = sizeof(clientAddress);

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&serverAddress, 0, sizeof(serverAddress));
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = INADDR_ANY;
    serverAddress.sin_port = htons(serverConfig->port);

    if (bind(sockfd, (const struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) {
        perror("Bind failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("DNS proxy server is running on port %d\n", serverConfig->port);

    while (1) {
        handleDnsRequest(sockfd, &clientAddress, &addrLen, serverConfig);
    }
}