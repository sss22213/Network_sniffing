#ifndef __SNIFFING_H_
#define __SNIFFING_H_
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <pthread.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <signal.h>

#define IS_NULL(X) ((X)==NULL?1:0)

/* Turn on or off log function */
#define TURN_ON_LOG(SNIFFING) do{SNIFFING->use_log_flag=1;}while(0)
#define TURN_OFF_LOG(SNIFFING) do{SNIFFING->use_log_flag=0;}while(0)
#define IS_LOG_ON(SNIFFING) (SNIFFING->use_log_flag)

/* Bind flag */
#define BIND_INTERFACE_ON(SNIFFING) do{SNIFFING->bind_interface_flag = 1;}while(0)
#define BIND_INTERFACE_OFF(SNIFFING) do{SNIFFING->bind_interface_flag = 0;}while(0)



/* Protocol */
enum portocol_type {
    TCP,
    UDP,
    ICMP
};

/* Sniffing class */
struct sniffing {
    uint8_t protocol;
    uint64_t counter;
    FILE *ptr_log_file;
    int socket;
    const char *interface;
    const char *log_path;
    uint8_t use_log_flag;
    uint8_t bind_interface_flag;
};

/* Create new sniffing */
sniffing* create_new_sniffing(void);

/* Bind interface */
int8_t setting_interface_name(sniffing*, const char*);

/* Create log path */
int8_t create_log_path(sniffing*, const char*);

/* Start sniffing */
void sniffing_start(sniffing*);

/* Stop sniffing */
void sniffing_stop(sniffing*);

#endif