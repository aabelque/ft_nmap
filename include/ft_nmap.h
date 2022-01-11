/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nmap.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: aabelque <aabelque@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/12/25 11:45:34 by aabelque          #+#    #+#             */
/*   Updated: 2022/01/12 00:16:19 by aabelque         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_NMAP_H
# define FT_NMAP_H

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
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

/* Utils define */
#define GIT "https://github.com/aabelque/ft_nmap.git"
#define MAXHOST 1025
#define PACKET_SIZE 512
#define ERRBUF PCAP_ERRBUF_SIZE
#define OFFSET 14

/* Define error type */
#define ERR_HOSTNAME 1

/* Define scan type */
#define SYN 0x1         /* 0000 0001 */
#define NUL 0x2         /* 0000 0010 */
#define ACK 0x4         /* 0000 0100 */
#define FIN 0x8         /* 0000 1000 */
#define XMAS 0x10       /* 0001 0000 */
#define UDP 0x20        /* 0010 0000 */
#define ALL 0x3f        /* 0011 1111 */

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

/* Target host structure */
typedef struct  s_target {
        char                    *hname;
        char                    *rdns;
        char                    ip[INET_ADDRSTRLEN];
        struct sockaddr_in      *to;
        struct sockaddr_in      *src;
}               t_target;

/* packet data structure */
typedef struct  s_pkt_data {
        int             port;
        int             type;
        t_target        tgt;
}               t_pkt_data;

/* environment structure */
typedef struct  s_env {
        bool                    resolve_dns;
        bool                    many_target;
        unsigned char           scan;
        int                     pid;
        int                     seq;
        int                     dot;
        int                     dim;
        int                     newargc;
        int                     nb_thread;
        int                     udp_socket;
        int                     ports[1025];
        char                    *hostname;
        char                    dns[MAXHOST];
        char                    ip[INET_ADDRSTRLEN];
        char                    my_ip[INET_ADDRSTRLEN];
        char                    my_mask[INET_ADDRSTRLEN];
        char                    **multiple_ip;
        struct timeval          tv;
        struct sockaddr_in      *to;
        t_target                *target;
}               t_env;

/* global variable */
t_env e;

/* nmap functions */
void ft_nmap(void);
void print_first_line(void);
void print_header(char *hname, char *ip, char *rdns);
void resolve_dns(struct sockaddr *addr, t_target *target, bool many);
int parse_arg(int argc, char **argv);
int resolve_host(t_target *target, bool many);
int set_and_resolve_hosts(void);
int process_scan(t_target tgt);
int send_packet(t_target tgt, int port, int type);
int get_udp_response(struct udphdr *udp, t_pkt_data *pkt);
int get_tcp_response(struct tcphdr *tcp, t_pkt_data *pkt);
int get_icmp_response(const u_char *data, t_pkt_data *pkt);
void *nmap_scan(void *arg);

/* utils functions */
void help_menu(int status);
void check_options(void);
int get_nb_of_comma(char *s);
int ip_dot(char *ip);
int isdash(char *s);
int get_number(char **argv, int idx, int dash);
int get_nbip_and_alloc(char *ip);
int copy_ips(char *ip);
int get_my_ip_and_mask(bpf_u_int32 ip, bpf_u_int32 mask);
int get_device_ip_and_mask(char *host, char **device, bpf_u_int32 *ip, bpf_u_int32 *mask);
int compile_and_set_filter(t_target tgt, pcap_t **handle, bpf_u_int32 mask, \
                int port, int type);
double gettimeval(struct timeval before, struct timeval after);
char *get_ip_from_file(char *file);

/* setup functions */
void environment_setup(void);
void environment_cleanup(void);
void udp_packet_setup(struct udp_packet *pkt, struct in_addr addr, \
                int port, int hlen);
void tcp_packet_setup(struct tcp_packet *pkt, struct in_addr addr, \
                int port, int hlen, int type);
int capture_setup(t_target tgt, pcap_t **handle, int port, int type);
int socket_setup(void);

/* libc functions */
int ft_strcmp(const char *s1, const char *s2);
int ft_atoi(const char *str);
int strisdigit(const char *s);
int ft_strlen(const char *s);
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
int check_duplicate_param(char **av, int ac);

#endif
