/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   setup.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: aabelque <aabelque@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/12/26 22:26:12 by aabelque          #+#    #+#             */
/*   Updated: 2022/01/11 17:15:32 by aabelque         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

extern t_env e;

void environment_setup(void)
{
        e.resolve_dns = true;
        e.many_target = false;
        e.pid = (getpid() & 0xffff) | 0x8000;
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
        ft_memset(e.ip, 0, ft_strlen(e.ip));
        ft_memset(e.my_ip, 0, ft_strlen(e.my_ip));
        ft_memset(e.my_mask, 0, ft_strlen(e.my_mask));
        ft_memset(e.ports, 0, sizeof(e.ports));
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

int capture_setup(t_target tgt, pcap_t **handle, int port, int type)
{
        int cc = 0, to_ms = 10000;
        char *device = NULL;
        char error[ERRBUF], s[ERRBUF];
        bpf_u_int32 ip, mask;

        ft_memset(error, 0, sizeof(error));
        ft_memset(s, 0, sizeof(s));

        cc = get_device_ip_and_mask(tgt.ip, &device, &ip, &mask);
        if (cc)
                return EXIT_FAILURE;

        *handle = pcap_open_live(device, BUFSIZ, 1, to_ms, error);
        if (!handle) {
                sprintf(s, "Could not open %s - %s\n", device, error);
                fprintf(stderr, "%s", s);
                return EXIT_FAILURE;
        }

        cc = compile_and_set_filter(tgt, handle, mask, port, type);
        if (cc)
                return EXIT_FAILURE;
        return EXIT_SUCCESS;
}

void tcp_packet_setup(struct tcp_packet *pkt, struct in_addr addr, \
                int port, int hlen, int type)
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

void udp_packet_setup(struct udp_packet *pkt, struct in_addr addr, int port, int hlen)
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
	(pkt->ip).ip_dst = addr;

        (pkt->udp).uh_sport = htons(e.pid);
        (pkt->udp).uh_dport = htons(port);
        (pkt->udp).uh_ulen = htons((unsigned short)(PACKET_SIZE - sizeof(struct ip)));
        (pkt->udp).uh_sum = 0;
}

int socket_setup(void)
{
        e.udp_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        return EXIT_SUCCESS;
}
