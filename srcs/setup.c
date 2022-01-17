/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   setup.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: aabelque <aabelque@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/12/26 22:26:12 by aabelque          #+#    #+#             */
/*   Updated: 2022/01/17 02:39:44 by aabelque         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

extern t_env e;

/**
 * environment_setup - initialize the environment structure
 */
void environment_setup(void)
{
        e.resolve_dns = true;
        e.many_target = false;
        e.pid = (getpid() & 0xffff);
        e.seq = 0;
        e.dot = 0;
        e.scan = 0;
        e.dim = 0;
        e.newargc = 0;
        e.nb_thread = 0;
        e.udp_socket = 0;
        e.hostname = NULL;
        e.multiple_ip = NULL;
        e.to = NULL;
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
                                if (e.target[i].src)
                                        free(e.target[i].src);
                        }
                        free(e.target);
                } else {
                        if (e.target->hname)
                                free(e.target->hname);
                        if (e.target->rdns)
                                free(e.target->rdns);
                        if (e.target->to)
                                free(e.target->to);
                        if (e.target->src)
                                free(e.target->src);
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
        e.udp_socket = 0;
        e.hostname = NULL;
        e.to = NULL;
        ft_memset(&e.tv, 0, sizeof(e.tv));
        ft_memset(e.ip, '\0', ft_strlen(e.ip));
        ft_memset(e.my_ip, '\0', ft_strlen(e.my_ip));
        ft_memset(e.my_mask, '\0', ft_strlen(e.my_mask));
        ft_memset(e.ports, 0, sizeof(e.ports));
        free_environment();
        free_list(&e.target->report);
}

/**
 * check_loopback - If the device is 'lo' then get the interface addr to get private ip.
 * @tgt: struct t_target that contains target info
 * @device: string that contains device name
 * @return 0 on success or 1 on failure
 */
static int8_t check_loopback(t_target *tgt, char **device)
{
        int8_t cc = 0;

        if (ft_strcmp(*device, "lo")) {
                cc = get_my_interface(tgt, *device);
                if (cc)
                        return EXIT_FAILURE;
        } else {
                ft_strcpy(e.my_ip, "127.0.0.1");
        }
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
int8_t capture_setup(t_target *tgt, pcap_t **handle, uint16_t port, int8_t type)
{
        int8_t cc = 0;
        int8_t to_ms = 25;
        char *device = NULL;
        char error[ERRBUF], s[ERRBUF];
        bpf_u_int32 ip, mask;

        ft_memset(error, '\0', sizeof(error));
        ft_memset(s, '\0', sizeof(s));

        cc = get_device_ip_and_mask(tgt->ip, &device, &ip, &mask);
        if (cc)
                return EXIT_FAILURE;

        cc = check_loopback(tgt, &device);
        if (cc)
                return EXIT_FAILURE;

        *handle = pcap_open_live(device, BUFSIZ, 0, to_ms, error);
        if (*handle == NULL) {
                sprintf(s, "Could not open %s - %s\n", device, error);
                fprintf(stderr, "%s", s);
                return EXIT_FAILURE;
        }

        cc = compile_and_set_filter(tgt, handle, ip, port, type);
        if (cc)
                return EXIT_FAILURE;
        cc = pcap_setnonblock(*handle, 1, error);
        if (cc)
                return EXIT_FAILURE;
        return EXIT_SUCCESS;
}

/**
 * tcp_packet_setup - initialize tcp header for the packet
 * @pkt: packet structure that contains ip and tcp header
 * @addr: in_addr struct that contains the destination address
 * @port: port to scan
 * @hlen: size of the packet structure
 * @type: type of scan
 */
void tcp_packet_setup(struct tcp_packet *pkt, struct in_addr addr, \
                uint16_t port, int8_t hlen, int8_t type)
{
        ft_memset(pkt, 0, sizeof(*pkt));

	(pkt->ip).ip_off = 0;
	(pkt->ip).ip_hl = sizeof(pkt->ip) >> 2;
	(pkt->ip).ip_p = IPPROTO_TCP;
	(pkt->ip).ip_len = 512;
	(pkt->ip).ip_ttl = 64;
	(pkt->ip).ip_v = IPVERSION;
	(pkt->ip).ip_id = htons(e.pid + e.seq);
	(pkt->ip).ip_tos = 0;
	(pkt->ip).ip_dst = addr;

}

/**
 * udp_packet_setup - initialize udp header for the packet
 * @pkt: packet structure that contains ip and udp header
 * @dst: in_addr struct that contains the destination address
 * @src: in_addr struct that contains the source address
 * @port: port to scan
 * @hlen: size of the packet structure
 */
void udp_packet_setup(struct udp_packet *pkt, struct in_addr dst, \
                struct in_addr src, uint16_t port, int8_t hlen)
{
        ft_memset(pkt, 0, sizeof(*pkt));

	(pkt->ip).ip_off = 0;
	(pkt->ip).ip_hl = sizeof(pkt->ip) >> 2;
	(pkt->ip).ip_p = IPPROTO_UDP;
	(pkt->ip).ip_len = 512;
	(pkt->ip).ip_ttl = 64;
	(pkt->ip).ip_v = IPVERSION;
	(pkt->ip).ip_id = htons(e.pid + e.seq);
	(pkt->ip).ip_tos = 0;
	(pkt->ip).ip_dst = dst;
	(pkt->ip).ip_src = src;

        (pkt->udp).uh_sport = htons(e.pid);
        (pkt->udp).uh_dport = htons(port);
        (pkt->udp).uh_ulen = htons((unsigned short)(PACKET_SIZE - sizeof(struct ip)));
        (pkt->udp).uh_sum = 0;
}

/* int socket_setup(void) */
/* { */
/*         e.udp_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW); */
/*         return EXIT_SUCCESS; */
/* } */
