#ifndef SERVER_H
#define SERVER_H


#define MAX_IP_LENGTH 16
#define MAX_DOMAIN_LENGTH 50
#define MAX_BLOCKED_DOMAINS 10
#define MAX_BLOCKED_DOMAIN_RESPONCE_LENGTH 20

#define DNS_REQUEST_BUFFER_SIZE 512

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <cjson/cJSON.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>


typedef struct {
    char upstream_dns_ip[MAX_IP_LENGTH];
    short port;
    char blacklist[MAX_BLOCKED_DOMAINS][MAX_DOMAIN_LENGTH];
    char blacklist_response[MAX_BLOCKED_DOMAIN_RESPONCE_LENGTH];
} ServerConfig;

ServerConfig* readConfig(const char* fileName);

void handleDnsRequest(int socket, struct sockaddr_in *clientAddress, socklen_t *addrLen, ServerConfig *serverConfig);

void parseDomainName(const unsigned char* buffer, int offset, char* domainName);

unsigned char* checkDomainInBlacklist(const char* domainName, const ServerConfig* serverConfig, const unsigned char id[2]);

unsigned char* buildRedirectResponce(const char *domainName);

#endif
