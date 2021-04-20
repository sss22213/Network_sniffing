#include "sniffing.h"

static volatile int stop_flag;

static inline void exit_program_handler(int signum)
{
    stop_flag = 1;
}

/* print data to outupt */
static inline void printdata(sniffing* sniffing_struct, uint8_t byte_data) 
{
    /**
     *  If logging is on, write log. Otherwise, write stdout.
     *  File writed is not support new line.
     */
    if (IS_LOG_ON(sniffing_struct)) {
        if (byte_data == '\n') {
            return;
        } else {
            fprintf(sniffing_struct->ptr_log_file, "%c ", byte_data);
        }
        fflush(sniffing_struct->ptr_log_file);
    } else {
        if (byte_data == '\n') {
            fprintf(stdout, "\n");
        } else {
            fprintf(stdout, "%c ", byte_data);
        }
        fflush(stdout);
    }
}


/**
 *  Open file
 *  If success, return 0.
 *  Otherwise, return -1
 */
static inline void log_file_open(sniffing* sniffing_struct)
{
    /* Check log file */
    if(IS_NULL(sniffing_struct->log_path)) {
        perror("File is not exist\n");
        exit(-1);
    }

    /* Open log file */
    sniffing_struct->ptr_log_file = fopen(sniffing_struct->log_path, "w");
    if (!sniffing_struct->ptr_log_file) {
        perror("Open file fail\n");
        exit(-1);
    }
}

static inline void bind_interface(sniffing* sniffing_struct)
{
    /* For bind interface */
    struct ifreq ifr; 

    /* Save index of interface */
    int ifindex = 0;

    /* socket for LLC */
    struct sockaddr_ll addr = {0};

    /* Length of interface name */
    size_t if_name_len = 0;

    /* Check socket is not pointer to NULL */
    if (sniffing_struct->socket < 0) {
        perror("Because socket is empty, binding interface fail.\n");
        exit(-1);
    }

    /* Configure interface name */
    if_name_len = strlen(sniffing_struct->interface);
    memcpy(ifr.ifr_name, sniffing_struct->interface, if_name_len);
    ifr.ifr_name[if_name_len] = 0;

    /* Find index of interface */
    if (ioctl(sniffing_struct->socket, SIOCGIFINDEX, &ifr) == -1) {
        perror("ioctl");
        exit(-1);
    }

    /* Bind interface to socket*/
    ifindex = ifr.ifr_ifindex;
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = ifindex;
    addr.sll_protocol = htons(ETH_P_ALL);
    if (bind(sniffing_struct->socket, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        perror("bind");
        exit(-1);
    }

}

/* Create socket */
static inline void socket_starting(sniffing* sniffing_struct)
{
    /* Configure socket */
    sniffing_struct->socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sniffing_struct->socket < 0) {
        perror("Initialize socket fail.\n");
    }

    /* Configure interface */
    if (sniffing_struct->bind_interface_flag) {
        bind_interface(sniffing_struct);
    }
}

/* Create structure of sniffing */
sniffing* create_new_sniffing(void)
{
    sniffing *new_sniffing = (struct sniffing*)calloc(1, sizeof(struct sniffing));
    if (IS_NULL(new_sniffing)) {
        return NULL;
    }

    /* Initialize */
    new_sniffing->protocol = NULL;
    new_sniffing->socket = -1;
    new_sniffing->counter = 0;
    new_sniffing->protocol_size = 0;
    new_sniffing->interface = NULL;
    new_sniffing->log_path = NULL;
    new_sniffing->ptr_log_file = NULL;

    /* If value is 1, representing use log file */
    new_sniffing->use_log_flag = 0;
    
    /* If value is 1, representing bind interface */
    new_sniffing->bind_interface_flag = 0;

    stop_flag = 0;

    return new_sniffing;
}

int8_t set_interface_name(sniffing* sniffing_struct, const char *interface_name) 
{
    int8_t status = 0;

    /* check if interface_name is not NULL */
    status = IS_NULL(interface_name);

    sniffing_struct->interface = interface_name;

    /* Set interface flag */
    BIND_INTERFACE_ON(sniffing_struct);

    return status;
}

int8_t create_log_path(sniffing* sniffing_struct, const char* log_file_path) 
{
    int8_t status = 0;
    
    /* check if interface_name is not NULL */
    status = IS_NULL(log_file_path);

    sniffing_struct->log_path = log_file_path;
    return status;
}

void sniffing_start(sniffing* sniffing_struct) 
{  
    /* Initialize buffer */
    uint8_t buffer[65535] = {0};

    /* Socket address and length*/
    struct sockaddr saddr;
    int saddr_len = sizeof(saddr);

    /* Receive size*/
    ssize_t recv_data_size = 0;
    
    /* iphdr pointer */
    struct iphdr *iph = NULL;
    uint32_t *ptr_ip = NULL;

    /* ip length */
    unsigned short ip_length = 0;

    int ip_offset = sizeof(struct ethhdr);

    /* Record protocol */
    int protocol = 0;

    /* tcp length */
    unsigned short tcp_length = 0;

    /* Get tcp offset from ip length */
    int tcp_offset = 0;

    /* pointer header of tcp */
    uint32_t *ptr_tcp = NULL;

    /* For saving tcp frame */
    struct tcphdr *tcph = NULL;

    /* Pointer to log file description*/
    if (IS_LOG_ON(sniffing_struct)) {
        log_file_open(sniffing_struct);
    }

    socket_starting(sniffing_struct);
    
    /* Configure interrupt signal*/
    signal(SIGINT, exit_program_handler);

    /* Cleaar stop flag */
    stop_flag = 0;

    while(1) {

        /* When interrupt happing, exit sniffing*/
        if (stop_flag) {
            sniffing_stop(sniffing_struct);
            exit(1);
        }

        /* Receive raw data */
        recv_data_size = recvfrom(sniffing_struct->socket, buffer, 65536, 0, &saddr, (socklen_t *)&saddr_len);
        if (recv_data_size< 1) {
            continue;
        }

        /* If list of protocol is empty */
        if (IS_NULL(sniffing_struct->protocol)) {
            continue;
        }

        /* Catch ip package */
        iph = (struct iphdr *)(buffer + ip_offset);
        ip_length = iph->ihl * 4;

        /* Get protocol from IP */
        protocol = iph->protocol;

        for(int protocol_idx = 0; protocol_idx < sniffing_struct->protocol_size; protocol_idx++) {
            switch (sniffing_struct->protocol[protocol_idx]) {
            case IP:
                ptr_ip = (uint32_t*)(buffer + ip_offset);
                if (IS_NULL(ptr_ip)) {
                    perror("Pointer ip fault\n");
                    exit(-1);
                }

                for (int ip_idx = ip_offset; ip_idx < ip_length + ip_offset; ip_idx++) {
                    printdata(sniffing_struct, buffer[ip_idx]);
                    
                    /* Add newline to 32 bits */
                    if ((ip_idx - ip_offset) > 0 && ((ip_idx - ip_offset + 1) % 12) == 0) {
                        printdata(sniffing_struct, '\n');
                    }

                    fflush(sniffing_struct->ptr_log_file);
                }
                break;
            case TCP:
                /* Verfity protocol */
                if (protocol != TCP) {
                    break;
                }

                /* Get address of tcp header over ip length */
                tcp_offset = ip_length;

                tcph = (struct tcphdr*)(buffer + tcp_offset);

                ptr_tcp = (uint32_t*)(buffer + tcp_offset);

                tcp_length = recv_data_size - tcph->doff * 4 - tcp_offset;

                if (IS_NULL(ptr_tcp)) {
                    perror("Pointer tcp fault\n");
                    exit(-1);
                }

                for (int tcp_idx = tcp_offset; tcp_idx < tcp_length + tcp_offset; tcp_idx++) {
                    printdata(sniffing_struct, buffer[tcp_idx]);
                    
                    /* Add newline to 32 bits */
                    if ((tcp_idx - tcp_offset) > 0 && ((tcp_idx - tcp_offset + 1) % 12) == 0) {
                            printdata(sniffing_struct, '\n');
                    }

                    fflush(sniffing_struct->ptr_log_file);
                }
                break;
            default:
                break;
            }
        }
        sleep(0.1);
    }

}

void sniffing_stop(sniffing* sniffing_struct)
{
    if (IS_LOG_ON(sniffing_struct)) {
        fclose(sniffing_struct->ptr_log_file);
    }
}

void set_protocol(sniffing *sniffing_struct, uint8_t *protocol_list, int32_t protocol_size)
{
    sniffing_struct->protocol = protocol_list;
    sniffing_struct->protocol_size = protocol_size;
}