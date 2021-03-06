/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   setup.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: aabelque <aabelque@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/12/26 22:26:12 by aabelque          #+#    #+#             */
/*   Updated: 2022/02/10 13:44:04 by aabelque         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

extern t_env e;

void target_setup(void)
{
        e.target->pid = e.pid;
        e.target->seq = e.seq;
        e.target->dim = e.dim;
        e.target->scan = e.scan;
        e.target->socket = 0;
        ft_memset(e.target->ports, 0, sizeof(e.target->ports));
}

/**
 * environment_setup - initialize the environment structure
 */
void environment_setup(void)
{
        e.resolve_dns = true;
        e.many_target = false;
        e.quit = false;
        e.pid = (getpid() & 0xffff);
        e.seq = 0;
        e.dot = 0;
        e.scan = 0;
        e.dim = 0;
        e.newargc = 0;
        e.nb_thread = 0;
        e.time = 0.0;
        e.hostname = NULL;
        e.multiple_ip = NULL;
		e.iargv = NULL;
        ft_memset(&e.tv, 0, sizeof(e.tv));
        ft_memset(e.ip, 0, ft_strlen(e.ip));
        ft_memset(e.my_ip, 0, ft_strlen(e.my_ip));
        ft_memset(e.my_mask, 0, ft_strlen(e.my_mask));
        ft_memset(e.ports, 0, sizeof(e.ports));
}

/**
 * free_environment - free environment variable dynamically allocated
 */
void free_environment(void)
{
        if (e.target) {
                if (e.dim) {
                        for (int i = 0; i < e.dim; i++) {
                                if (e.target[i].hname)
                                        free(e.target[i].hname);
                                if (e.target[i].rdns)
                                        free(e.target[i].rdns);
                                if (e.target[i].to)
                                        free(e.target[i].to);
                        }
                        free(e.target);
                } else {
                        if (e.target->hname)
                                free(e.target->hname);
                        if (e.target->rdns)
                                free(e.target->rdns);
                        if (e.target->to)
                                free(e.target->to);
                        free(e.target);
                }
        }
        if (e.multiple_ip && e.dim) {
                for (int i = 0; i < e.dim; i++)
                        free(e.multiple_ip[i]);
                free(e.multiple_ip);
                e.multiple_ip = NULL;
                e.dim = 0;
        }
        
}

/**
 * environment_cleanup - clean the environment structure
 */
void environment_cleanup(void)
{
        e.resolve_dns = false;
        e.many_target = false;
        e.pid = 0;
        e.seq = 0;
        e.dot = 0;
        e.scan = 0;
        e.newargc = 0;
        e.nb_thread = 0;
        e.time = 0.0;
        e.hostname = NULL;
        ft_memset(&e.tv, 0, sizeof(e.tv));
        ft_memset(e.ip, '\0', ft_strlen(e.ip));
        ft_memset(e.my_ip, '\0', ft_strlen(e.my_ip));
        ft_memset(e.my_mask, '\0', ft_strlen(e.my_mask));
        ft_memset(e.ports, 0, sizeof(e.ports));

		if (e.iargv)
			ft_free_tab(e.iargv);

        if (e.target)
                free_list(e.target->report);
        free_environment();
}

int8_t is_loopback(char *ip, struct ifaddrs *ifa)
{
        if ((ft_strcmp(ip, "127.0.0.1") == 0) \
                        && (ifa->ifa_flags & IFF_LOOPBACK) \
                        && ifa->ifa_addr->sa_family == AF_INET) {
                return 1;
        }
        return 0;
}

int8_t is_eth_interface(struct ifaddrs *ifa)
{
        if ((ifa->ifa_flags & (IFF_RUNNING|IFF_UP|IFF_LOOPBACK)) == (IFF_RUNNING|IFF_UP) \
                        && ifa->ifa_addr->sa_family == AF_INET) {
                return 1;
        }
        return 0;
}

int8_t get_interface_name(t_target *tgt, struct ifaddrs *ifa, char **device)
{
        struct sockaddr_in *sa;

        if ((*device = ft_memalloc(ft_strlen(ifa->ifa_name) + 1)) == NULL)
                return EXIT_FAILURE;
        ft_strcpy(*device, ifa->ifa_name);
        sa = (struct sockaddr_in *)ifa->ifa_addr;
        if ((tgt->src = ft_memalloc(sizeof(*tgt->src))) == NULL)
                return EXIT_FAILURE;
        ft_memcpy(tgt->src, sa, sizeof(*sa));
        ft_strcpy(tgt->my_ip, inet_ntoa(tgt->src->sin_addr));
        return EXIT_SUCCESS;
}

int8_t fds_setup(struct pollfd *fds, pcap_t **handle, int8_t *fd)
{
        char errbuf[ERRBUF];

        if (pcap_setnonblock(*handle, 1, errbuf) == -1)
                return EXIT_FAILURE;
        if ((*fd = pcap_get_selectable_fd(*handle)) == -1)
                return EXIT_FAILURE;
        *fds = (struct pollfd){ *fd, POLLIN, 0 };
        return EXIT_SUCCESS;
}

/**
 * capture_setup - setup on which interface to capture packet, define a filter and compile it
 * @tgt: struct t_target that contain target(s) info
 * @handle: pointer t_pcap returned by pcap_open_live to obtain a packet capture handle
 * @port: port to scan
 * @type: type of scan
 * @return 0 on success or 1 on failure
 */
int8_t capture_setup(pcap_t **handle, t_target *tgt, uint16_t port, uint8_t type)
{
        int8_t to_ms = 25;
        char *device = NULL;
        char error[ERRBUF], s[ERRBUF+128];
        bpf_u_int32 ip, mask;

        ft_memset(error, '\0', sizeof(error));
        ft_memset(s, '\0', sizeof(s));

        if (get_device_ip_and_mask(tgt, &device, &ip, &mask))
                goto return_failure;
        if ((*handle = pcap_open_live(device, BUFSIZ, 0, 0, error)) == NULL)
                goto pcap_open_failure;
        if (compile_and_set_filter(tgt, handle, ip, port, type))
                goto return_failure;
        free(device);
        return EXIT_SUCCESS;

return_failure:
        free(device);
        return EXIT_FAILURE;
pcap_open_failure:
        sprintf(s, "Could not open %s - %s\n", device, error);
        fprintf(stderr, "%s", s);
        free(device);
        return EXIT_FAILURE;
}

uint16_t checksum_tcp(struct tcphdr *p, struct in_addr dst, struct in_addr src)
{
        t_psdohdr hdr;

        hdr.saddr = src.s_addr;
        hdr.daddr = dst.s_addr;
        hdr.zero = 0;
        hdr.proto = IPPROTO_TCP;
        hdr.len = htons(sizeof(struct tcphdr));

        ft_memcpy(&hdr.tcp, p, sizeof(struct tcphdr));
        return checksum(&hdr, sizeof(t_psdohdr));
}

/**
 * tcp_packet_setup - initialize tcp header for the packet
 * @pkt: packet structure that contains ip and tcp header
 * @addr: in_addr struct that contains the destination address
 * @port: port to scan
 * @hlen: size of the packet structure
 * @type: type of scan
 */
void tcp_packet_setup(struct tcp_packet *pkt, t_target *tgt, \
                uint16_t port, int8_t hlen, uint8_t type)
{

        ft_memset(pkt, 0, sizeof(*pkt));
	(pkt->ip).ip_off = 0;
	(pkt->ip).ip_hl = sizeof(pkt->ip) >> 2;
	(pkt->ip).ip_p = IPPROTO_TCP;
	(pkt->ip).ip_len = hlen;
	(pkt->ip).ip_ttl = 64;
	(pkt->ip).ip_v = IPVERSION;
	(pkt->ip).ip_id = htons(tgt->pid);
        (pkt->ip).ip_tos = 0;
	(pkt->ip).ip_dst = tgt->to->sin_addr;
	(pkt->ip).ip_src = tgt->src->sin_addr;
        (pkt->ip).ip_sum = 0;
        (pkt->ip).ip_sum = checksum(&pkt->ip, sizeof(pkt->ip));
        
        (pkt->tcp).source = htons(tgt->pid);
        (pkt->tcp).dest = htons(port);
        (pkt->tcp).seq = htons(tgt->seq);
        (pkt->tcp).ack_seq = 0;
        (pkt->tcp).doff = sizeof(struct tcphdr) >> 2;
        (pkt->tcp).fin = (type & FIN || type & XMAS) ? 1 : 0;
        (pkt->tcp).syn = (type & SYN) ? 1 : 0;
        (pkt->tcp).rst = 0;
        (pkt->tcp).psh = (type & XMAS) ? 1 : 0;
        (pkt->tcp).ack = (type & ACK) ? 1 : 0;
        (pkt->tcp).urg = (type & XMAS) ? 1 : 0;
        (pkt->tcp).window = htons(UINT16_MAX);
        (pkt->tcp).urg_ptr = 0;
        (pkt->tcp).th_sum = 0;
}

/**
 * udp_packet_setup - initialize udp header for the packet
 * @pkt: packet structure that contains ip and udp header
 * @dst: in_addr struct that contains the destination address
 * @src: in_addr struct that contains the source address
 * @port: port to scan
 * @hlen: size of the packet structure
 */
void udp_packet_setup(struct udp_packet *pkt, t_target *tgt, \
                uint16_t port, int8_t hlen)
{
        ft_memset(pkt, 0, sizeof(*pkt));
	(pkt->ip).ip_off = 0;
	(pkt->ip).ip_hl = sizeof(pkt->ip) >> 2;
	(pkt->ip).ip_p = IPPROTO_UDP;
	(pkt->ip).ip_len = hlen;
	(pkt->ip).ip_ttl = 64;
	(pkt->ip).ip_v = IPVERSION;
	(pkt->ip).ip_id = htons(tgt->pid + tgt->seq);
	(pkt->ip).ip_tos = 0;
	(pkt->ip).ip_dst = tgt->to->sin_addr;
	(pkt->ip).ip_src = tgt->src->sin_addr;

        (pkt->udp).uh_sport = htons(tgt->pid);
        (pkt->udp).uh_dport = htons(port);
        (pkt->udp).uh_ulen = htons((unsigned short)(hlen - sizeof(struct ip)));
        (pkt->udp).uh_sum = 0;
}

void signal_setup(void)
{
        int8_t cc;
        struct sigaction sig_interupt, sig_quit;

        ft_memset(&sig_interupt, 0, sizeof(sig_interupt));
        sigemptyset(&sig_interupt.sa_mask);
        sig_interupt.sa_flags = SA_RESETHAND;
        sig_interupt.sa_handler = &interrupt_signal;
        sigaction(SIGINT, &sig_interupt, NULL);

        ft_memset(&sig_quit, 0, sizeof(sig_quit));
        sigemptyset(&sig_quit.sa_mask);
        sig_quit.sa_flags = 0;
        sig_quit.sa_handler = &quit_signal;
        sigaction(SIGQUIT, &sig_quit, NULL);
}
