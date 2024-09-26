#include <server.h>

const unsigned char REFUSED_RESPONCE[] = {
    0x00, 0x00, // ID ::Changes in actual responce
    0x81, 0x85, // Flags
    0x00, 0x00, // QDCOUNT
    0x00, 0x00, // ANCOUNT
    0x00, 0x00, // NSCOUNT
    0x00, 0x00  // ARCOUNT
};

const unsigned char NOT_FOUND_RESPONCE[] = {
    0x00, 0x00, // ID ::Changes in actual responce
    0x81, 0x83, // Flags
    0x00, 0x01, // QDCOUNT
    0x00, 0x00, // ANCOUNT
    0x00, 0x00, // NSCOUNT
    0x00, 0x00  // ARCOUNT
};

const unsigned char REDIRECT_RESPONCE_HEADER[] = {
    0x00, 0x00, // ID ::Change in actual responce
    0x81, 0x80, // Flags
    0x00, 0x01, // QDCOUNT
    0x00, 0x01, // ANCOUNT
    0x00, 0x00, // NSCOUNT
    0x00, 0x00, // ARCOUNT
};

const unsigned char REDIRECT_RESPONCE_RR_SECTION[] = {
    0xc0, 0x0c, // Domain position
    0x00, 0x01, // Reponce type
    0x00, 0x01, // Responce class
    0x00, 0x00, 0x00, 0x3c, // TTL
    0x00, 0x04, // Responce length
    0x7f, 0x00, 0x00, 0x01 // IP-address
};


ServerConfig* readConfig(const char* fileName) {
    char buffer[256];

    FILE * file = fopen(fileName, "r");
    if(file == NULL) {
        perror("Error opening file %s");
        exit(EXIT_FAILURE);
    }

    fseek(file, 0, SEEK_END);
    const long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char* json_str = calloc(file_size + 1, sizeof(char));
    while(fgets(buffer, sizeof(buffer), file) != NULL) {
        strncat(json_str, buffer,sizeof(buffer));
    }
    fclose(file);

    if(strlen(json_str) == 0) {
        perror("Error reading file");
        exit(EXIT_FAILURE);
    }

    cJSON * json = cJSON_Parse(json_str);
    free(json_str);

    if(json == NULL) {
        cJSON_Delete(json);
        perror("Error parsing JSON");
        exit(EXIT_FAILURE);
    }

    ServerConfig *config = malloc(sizeof(ServerConfig));

    cJSON *upstream_dns_ip = cJSON_GetObjectItem(json, "upstream_dns_ip");
    cJSON *port = cJSON_GetObjectItem(json, "port");
    cJSON *blacklist = cJSON_GetObjectItem(json, "blacklist");
    cJSON *blacklist_responce = cJSON_GetObjectItem(json, "blacklist_response");

    if (cJSON_IsString(upstream_dns_ip)) {
        if(strlen(upstream_dns_ip->valuestring) > MAX_IP_LENGTH) {
            printf("Error! IP of upstream DNS server can have maximum 15 characters");
            exit(EXIT_FAILURE);
        }
        strcpy(config->upstream_dns_ip, upstream_dns_ip->valuestring);
    }

    if(cJSON_IsNumber(port)) {
        if(port->valueint > 65535) {
            printf("Error! Port mus be an integer from 0 to 65535");
            exit(EXIT_FAILURE);
        }
        config->port = port->valueint;
    }

    if(cJSON_IsArray(blacklist)) {
        if(cJSON_GetArraySize(blacklist) > MAX_BLOCKED_DOMAINS) {
            printf("Error! Maximum %d domains", MAX_BLOCKED_DOMAINS);
        }

        for(int i = 0; i < cJSON_GetArraySize(blacklist); i++) {
           cJSON *domainInBlacklist = cJSON_GetArrayItem(blacklist, i);

            if(cJSON_IsString(domainInBlacklist)) {
                if(strlen(domainInBlacklist->valuestring) > MAX_DOMAIN_LENGTH) {
                    printf("Error! Domain name can have maximum %d characters", MAX_DOMAIN_LENGTH);
                    exit(EXIT_FAILURE);
                }
                strcpy(config->blacklist[i], domainInBlacklist->valuestring);
            }
        }
    }

    if(cJSON_IsString(blacklist_responce)) {
        if(strlen(blacklist_responce->valuestring) > MAX_BLOCKED_DOMAIN_RESPONCE_LENGTH) {
            printf("Error! Server responce to blacklisted domain cannot be more than %d characters",
                MAX_BLOCKED_DOMAIN_RESPONCE_LENGTH);
            exit(EXIT_FAILURE);
        }
        strcpy(config->blacklist_response, blacklist_responce->valuestring);
    }

    cJSON_Delete(json);

    return config;
}


void handleDnsRequest(const int socket, struct sockaddr_in *clientAddress, socklen_t *addrLen, ServerConfig *serverConfig) {
    char buffer[DNS_REQUEST_BUFFER_SIZE];
    ssize_t received = recvfrom(socket, buffer, DNS_REQUEST_BUFFER_SIZE, 0, (struct sockaddr *)clientAddress,
        addrLen);
    if(received < 0) {
        perror("Error receciving data");
        return;
    }

    char domainName[256];
    parseDomainName((unsigned char *)buffer, 12, domainName);

    const unsigned char id [2] = {buffer[0], buffer[1]};
    const unsigned char *blacklistResponce = checkDomainInBlacklist(domainName, serverConfig, id);
    if (blacklistResponce != NULL) {
        int blacklisted_responce_size;
        if(strcasecmp(serverConfig->blacklist_response, "redirect") == 0) {
            blacklisted_responce_size = sizeof(REDIRECT_RESPONCE_HEADER) + (strlen(domainName))
            + 6 + sizeof(REDIRECT_RESPONCE_RR_SECTION);
        }
        else if (strcasecmp(serverConfig->blacklist_response, "not found")) {
            blacklisted_responce_size = sizeof(NOT_FOUND_RESPONCE);
        } else {
            blacklisted_responce_size = sizeof(REFUSED_RESPONCE);
        }

        sendto(socket, blacklistResponce, blacklisted_responce_size, 0,(struct sockaddr*)clientAddress,
            *addrLen);
        free(blacklistResponce);
        return;
    }

    struct sockaddr_in upstreamDnsServer;
    upstreamDnsServer.sin_family = AF_INET;
    upstreamDnsServer.sin_port = htons(53);
    inet_pton(AF_INET, serverConfig->upstream_dns_ip, &upstreamDnsServer.sin_addr);

    ssize_t sent = sendto(socket, buffer, received, 0, (struct sockaddr *)&upstreamDnsServer,
        sizeof(upstreamDnsServer));

    if(sent < 0) {
        perror("Error forwading DNS request to upstream server");
    }

    ssize_t responce_size = recvfrom(socket, buffer, DNS_REQUEST_BUFFER_SIZE, 0, NULL, NULL);

    if(responce_size < 0) {
        perror("Error receiving responce from upstream DNS server");
        return;
    }
    sendto(socket, buffer, responce_size, 0,(struct  sockaddr *) clientAddress, *addrLen);
}


void parseDomainName(const unsigned char* buffer, int offset, char* domainName) {
    int length = buffer[offset];
    int pos = 0;

    while (length > 0) {
        for(int i = 0; i < length; i++) {
            domainName[pos++] = buffer[offset + i + 1];
        }
        domainName[pos++] = '.';
        offset += length + 1;
        length = buffer[offset];
    }

    domainName[pos - 1] = '\0';
}


unsigned char *checkDomainInBlacklist(const char* domainName, const ServerConfig* serverConfig, const unsigned char id[2]) {
    unsigned char *responce;
    for(short i = 0; i < MAX_BLOCKED_DOMAINS; i++) {

        if(strcmp(serverConfig->blacklist[i],domainName) == 0) {

            if(strcasecmp(serverConfig->blacklist_response, "refused") == 0) {

                responce = malloc(12 * sizeof(unsigned char));
                memcpy(responce, REFUSED_RESPONCE, 12 * sizeof(unsigned char));
            } else if(strcasecmp(serverConfig->blacklist_response, "not found") == 0) {

                responce = malloc(12 * sizeof(unsigned char));
                memcpy(responce, NOT_FOUND_RESPONCE, 12 * sizeof(unsigned char));
            } else if(strcasecmp(serverConfig->blacklist_response, "redirect") == 0){

                responce = buildRedirectResponce(domainName);
            } else {
                printf("Error! Invalid responce to blacklist to blacklisted domain");
                exit(EXIT_FAILURE);
            }

            responce[0] = id[0];
            responce[1] = id[1];
            return responce;
        }
    }
    return NULL;
}


unsigned char *buildRedirectResponce(const char *domainName) {
    char* response = malloc(sizeof(REDIRECT_RESPONCE_HEADER)
        + sizeof(char) * (strlen(domainName) + 6)
        + sizeof(REDIRECT_RESPONCE_RR_SECTION));

    memcpy(response, REDIRECT_RESPONCE_HEADER, sizeof(REDIRECT_RESPONCE_HEADER));
    int i = 12;
    char* domainNameCopy = malloc (strlen(domainName) + 1);
    strcpy(domainNameCopy,domainName);
    char* codedDomainName = malloc(sizeof(char) * (strlen(domainName) + 2));
    char *token = strtok(domainNameCopy, ".");

    int j = 0;
    while (token != NULL) {
        size_t tokenLength = strlen(token);
        codedDomainName[j] = tokenLength;
        memcpy(&codedDomainName[j + 1], token, tokenLength);
        j += tokenLength + 1;
        token = strtok(NULL, ".");
    }
    memcpy(response + i, codedDomainName, strlen(codedDomainName));

    i+=strlen(codedDomainName);
    response[i++] = 0x00; // End of domain


    response[i++] = 0x00;
    response[i++] = 0x01; // Responce type
    response[i++] = 0x00;
    response[i++] = 0x01; // Responce class

    memcpy(response + i,REDIRECT_RESPONCE_RR_SECTION, sizeof(REDIRECT_RESPONCE_RR_SECTION));

    free(domainNameCopy);
    free(codedDomainName);
    return response;
}