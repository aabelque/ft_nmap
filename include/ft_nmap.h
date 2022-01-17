/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nmap.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: aabelque <aabelque@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/12/25 11:45:34 by aabelque          #+#    #+#             */
/*   Updated: 2022/01/17 18:49:50 by zizou            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_NMAP_H
# define FT_NMAP_H

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <bits/types.h>
#include <sys/time.h>
#include <pthread.h>
#include <pcap/pcap.h>
#include <ifaddrs.h>

/* Utils define */
#define GIT "https://github.com/aabelque/ft_nmap.git"
#define MAXHOST 1025
#define PACKET_SIZE 512
#define ERRBUF PCAP_ERRBUF_SIZE
#define OFFSET 14
/* #define for_range(i, start, end) for(uint8_t i = start; i < end; i += 1) */

/* Define error type */
#define ERR_HOSTNAME 1

/* Define scan type */
enum e_scan_type { 
        SYN = 0x1,         /* 0000 0001 */
        NUL = 0x2,         /* 0000 0010 */
        ACK = 0x4,         /* 0000 0100 */
        FIN = 0x8,         /* 0000 1000 */
        XMAS = 0x10,       /* 0001 0000 */
        UDP = 0x20,        /* 0010 0000 */
        ALL = 0x3f        /* 0011 1111 */
};

/* Define state type */
enum e_state_type { 
        S_OP = 0x1,
        S_CL = 0x2,
        S_FI = 0x4,
        S_UF = 0x8,
        S_OF = 0x10,
        S_CF = 0x20
        
};

/* packet tcp structure */
struct tcp_packet {
        struct ip       ip;
        struct tcphdr   tcp;
};

/* packet tcp structure */
struct udp_packet {
        struct ip       ip;
        struct udphdr   udp;
};

typedef struct  s_result {
        int8_t                  state;
        uint16_t                port;
        char                    *service;
        struct s_result         *next;
}               t_result;

/* Target host structure */
typedef struct  s_target {
        char                    *hname;
        char                    *rdns;
        char                    ip[INET_ADDRSTRLEN];
        struct sockaddr_in      *to;
        struct sockaddr_in      *src;
        t_result                *report;
}               t_target;

/* packet data structure */
typedef struct  s_pkt_data {
        int8_t          type;
        uint16_t        port;
        t_target        *tgt;
}               t_pkt_data;

/* environment structure */
typedef struct  s_env {
        bool                    resolve_dns;
        bool                    many_target;
        int8_t                  dot;
        int8_t                  newargc;
        uint8_t                 scan;
        uint8_t                 nb_thread;
        uint16_t                dim;
        uint16_t                pid;
        int16_t                 udp_socket;
        uint16_t                seq;
        uint16_t                ports[1025];
        char                    *hostname;
        char                    dns[MAXHOST];
        char                    ip[INET_ADDRSTRLEN];
        char                    my_ip[INET_ADDRSTRLEN];
        char                    my_mask[INET_ADDRSTRLEN];
        char                    **multiple_ip;
        struct timeval          tv;
        struct sigaction        sigalrm;
        struct sigaction        sigint;
        pcap_t                  *handle;
        /* struct sockaddr_in      *to; */
        t_target                *target;
}               t_env;

/* global variable */
t_env e;

/* nmap functions */
void ft_nmap(void);
void print_first_line(void);
void print_header(char *hname, char *ip, char *rdns);
void syn_decode(t_pkt_data *data, uint8_t code, uint8_t flags);
void null_decode(t_pkt_data *data, uint8_t code, uint8_t flags);
void ack_decode(t_pkt_data *data, uint8_t code, uint8_t flags);
void fin_decode(t_pkt_data *data, uint8_t code, uint8_t flags);
void xmas_decode(t_pkt_data *data, uint8_t code, uint8_t flags);
void udp_decode(t_pkt_data *data, uint8_t code, uint8_t flags);
/* void resolve_dns(struct sockaddr *addr, t_target *target, bool many); */
int8_t parse_arg(int argc, char **argv);
/* int resolve_host(t_target *target, bool many); */
int8_t get_my_interface(t_target *tgt, char *interface);
int8_t set_and_resolve_hosts(void);
int8_t process_scan(t_target *tgt);
int8_t send_packet(t_target *tgt, uint16_t port, int8_t type);
int8_t get_udp_response(struct udphdr *udp, t_pkt_data *pkt);
int8_t get_tcp_response(struct tcphdr *tcp, t_pkt_data *pkt);
int8_t get_icmp_response(const u_char *data, t_pkt_data *pkt);
void *nmap_scan(void *arg);
char *get_service(uint16_t port, const char *proto);

/* utils functions */
void help_menu(int8_t status);
void check_options(void);
/* int get_nb_of_comma(char *s); */
void ip_dot(char *ip);
void break_signal(int sig);
void interrupt_signal(int sig);
int8_t isdash(char *s);
int8_t get_number(char **argv, int8_t idx, int8_t dash);
int8_t get_nbip_and_alloc(char *ip);
int8_t copy_ips(char *ip);
int8_t get_my_ip_and_mask(bpf_u_int32 ip, bpf_u_int32 mask);
int8_t get_device_ip_and_mask(char *host, char **device, bpf_u_int32 *ip, bpf_u_int32 *mask);
int8_t compile_and_set_filter(t_target *tgt, pcap_t *handle, bpf_u_int32 mask, \
                uint16_t port, int8_t type);
int64_t gettimeval(struct timeval before, struct timeval after);
char *get_ip_from_file(char *file);

/* setup functions */
void environment_setup(void);
void environment_cleanup(void);
void signal_setup(void);
void udp_packet_setup(struct udp_packet *pkt, struct in_addr addr, \
                struct in_addr src, uint16_t port, int8_t hlen);
void tcp_packet_setup(struct tcp_packet *pkt, struct in_addr addr, \
                uint16_t port, int8_t hlen, int8_t type);
int8_t capture_setup(t_target *tgt, uint16_t port, int8_t type);
/* int socket_setup(void); */

/* libc functions */
int8_t ft_strcmp(const char *s1, const char *s2);
int8_t strisdigit(const char *s);
int64_t ft_atoi(const char *str);
size_t ft_strlen(const char *s);
char *ft_itoa(int n);
char *ft_strdup(const char *s);
char *ft_strcpy(char *dest, const char *src);
char *ft_strncpy(char *dest, const char *src, size_t n);
char **ft_strsplit(char const *s, char c);
void *ft_memset(void *s, int c, size_t n);
void *ft_memalloc(size_t size);
void *ft_memcpy(void *dest, const void *src, size_t n);

/* error functions */
void exit_errors(int error, char *arg);
void perror_and_exit(char *s);
int8_t check_duplicate_param(char **av, int ac);

/* list functions */
void add_node(t_result **list, t_result *new_node);
void free_list(t_result **list);
t_result *find_lastnode(t_result *list);
t_result *new_node(int8_t state, uint16_t port, char *service);

#endif
