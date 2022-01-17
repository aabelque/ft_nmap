/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   get_response.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: aabelque <aabelque@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/01/11 19:58:24 by aabelque          #+#    #+#             */
/*   Updated: 2022/01/17 02:30:21 by aabelque         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

int8_t get_udp_response(struct udphdr *udp, t_pkt_data *pkt)
{
        printf("udp\n");
        printf("dport = %d\n", ntohs(udp->uh_dport));
        printf("sport = %d\n", ntohs(udp->uh_sport));
        printf("pkt port = %d\n", pkt->port);
        printf("pkt type = %d\n", pkt->type);
        printf("pkt ip = %s\n", pkt->tgt->ip);
        return EXIT_SUCCESS;
}

int8_t get_tcp_response(struct tcphdr *tcp, t_pkt_data *pkt)
{
        return EXIT_SUCCESS;
}

/**
 * get_icmp_response -  parse icmp header, check protocol and
 *                      calls appropriate <type>_decode function
 * @data: data captured by pcap_dispatch()
 * @pkt: struct t_pkt_data that contains data info
 * @return 0 on success
 */
int8_t get_icmp_response(const u_char *data, t_pkt_data *pkt)
{
        int8_t hlen = 0;
        uint8_t type, code;
        struct ip *ip;
        struct icmp *icmp;

        ip = (struct ip *)data;
        hlen = ip->ip_hl << 2;

        icmp = (struct icmp *)(data + hlen);
        type = icmp->icmp_type;
        code = icmp->icmp_code;

        ip = &icmp->icmp_ip;
        hlen = ip->ip_hl << 2;

        if (type == ICMP_UNREACH) {
                if (ip->ip_p == IPPROTO_TCP) {
                        struct tcphdr *tcp = (struct tcphdr *)((char *)ip + hlen);
                } else if (ip->ip_p == IPPROTO_UDP) {
                        struct udphdr *udp = (struct udphdr *)((char *)ip + hlen);
                        if (ntohs(udp->uh_dport) == pkt->port && ntohs(udp->uh_sport) == e.pid)
                                udp_decode(pkt, code, 42);
                }
        }
        return EXIT_SUCCESS;
}
