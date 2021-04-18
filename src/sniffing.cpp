#include "sniffing.hpp"

static int mysocket;

sniffing::sniffing(char* network_interface, const char *filename)
{
    /* For bind interface */
    struct ifreq ifr; 

    /* Socker for LLC */
    struct sockaddr_ll addr = {0};

    /* Save name of interface */
    size_t if_name_len = 0;

    /* Save index of interface */
    int ifindex = 0;

    /**
     * Initialize socket
     * Catch package from logical Link Control(LLC)
     */
    mysocket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (mysocket < 0) {
        perror("Initialize socket fail");
        exit(-1);
    }

    /* Bind network interface */
    if_name_len = strlen(network_interface);
    if (if_name_len < sizeof(ifr.ifr_name)) {
        memcpy(ifr.ifr_name, network_interface, if_name_len);
        ifr.ifr_name[if_name_len] = 0;
    } else {
        fprintf(stderr, "interface name is too long\n");
        exit(1);
    }
    if (ioctl(mysocket,SIOCGIFINDEX, &ifr) == -1) {
        perror("ioctl");
        exit(1);
    }
    ifindex = ifr.ifr_ifindex;
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = ifindex;
    addr.sll_protocol = htons(ETH_P_ALL);
    if (bind(mysocket, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        perror("bind");
        exit(1);
    }

    /* Initialize buffer */
    buffer = new uint8_t[65535];

    /* Open file */
    pFile = NULL;
    pFile = fopen(filename, "w+");
    if (pFile == NULL) {
        fprintf(stderr, "Open file fail\n");
    }
}

sniffing::~sniffing(void)
{
    /* Close socket */
    close(mysocket);

    /* Release space of buffer */
    if (buffer != NULL) {
        free(buffer);
        buffer = NULL;
    }

    /* Close file*/
    fclose(pFile);
}

void sniffing::get_tcp_package(void)
{
    /* Socket address and length*/
    struct sockaddr saddr;
    int saddr_len = sizeof(saddr);
    
    /* IP package length */
    unsigned short iphdrlen = 0;

    /* Receive size*/
    ssize_t recv_data_size = 0;
    
    /* iphdr pointer */
    struct iphdr *iph = NULL;

    /* tcp package payload information */
    uint8_t *ptr_tcp_payload = NULL;
    unsigned short tcp_paylolad_offset = 0;
    int tcp_payload_length = 0;

    while(1) {

        sleep(0.01);

        /* Receive raw data */
        recv_data_size = recvfrom(mysocket, buffer, 65536, 0, &saddr, (socklen_t *)&saddr_len);
        if (recv_data_size< 1) {
            continue;
        }

        /* Obtain ip package */
        iph = (struct iphdr *)(buffer  + sizeof(struct ethhdr));

        /* Check if protocol is tcp */
        if ((unsigned int)iph->protocol == 6) {
            iphdrlen = iph->ihl * 4;
            struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen);
            
            /**
             *  TCP payload offset = iphdrlen + length of tcp header
             *  TCP payload length = recv_data_size - length of tcp header - iphdrlen
             */
            tcp_paylolad_offset = iphdrlen + tcph->doff * 4;
            tcp_payload_length = recv_data_size - tcph->doff * 4 - iphdrlen;
            ptr_tcp_payload = buffer + tcp_paylolad_offset;
            for(int i = 0 ; i < tcp_payload_length ; i++)
            {
                if (pFile != NULL) {
                    fprintf(pFile, "%c", (unsigned int)ptr_tcp_payload[i]);
                    fflush(pFile);
                } else {
                    printf("%c", (unsigned int)ptr_tcp_payload[i]);
                }
            }
        }
    }
}