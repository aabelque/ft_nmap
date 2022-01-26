/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   get_response.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: aabelque <aabelque@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/01/11 19:58:24 by aabelque          #+#    #+#             */
/*   Updated: 2022/01/26 23:25:35 by zizou            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

int8_t get_udp_response(struct udphdr *udp, t_pkt_data *pkt)
{
        uint16_t dp, sp;
        t_result *r = pkt->tgt->report;

        dp = ntohs(udp->uh_dport);
        sp = ntohs(udp->uh_sport);
        if (dp == pkt->port && sp == e.pid)
                udp_decode(pkt, -1, 42, is_node_exist(r, pkt->port));
        return EXIT_SUCCESS;
}

int8_t get_tcp_response(struct tcphdr *tcp, t_pkt_data *pkt)
{
        uint8_t type = 0, i = 0, start = 1, end = 64;
        void (*func[6])(t_pkt_data *, uint8_t, uint8_t, bool) = {&syn_decode, &null_decode,
                &ack_decode, &fin_decode, &xmas_decode, &udp_decode};
        t_result *r = pkt->tgt->report;
        
        if (pkt->port == ntohs(tcp->th_sport)) {
                if (tcp->ack && tcp->syn) {
                        for_eachtype(i, type, start, end) {
                                if (type == pkt->type)
                                        func[i](pkt, 42, 0, is_node_exist(r, pkt->port));
                        }
                } else if (tcp->rst) {
                        for_eachtype(i, type, start, end) {
                                if (type == pkt->type)
                                        func[i](pkt, 21, 0, is_node_exist(r, pkt->port));
                        }
                }
        }
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
        t_result *r = pkt->tgt->report;

        ip = (struct ip *)data;
        hlen = ip->ip_hl << 2;
        icmp = (struct icmp *)(data + hlen);
        type = icmp->icmp_type;
        code = icmp->icmp_code;
        ip = &icmp->icmp_ip;
        hlen = ip->ip_hl << 2;

        if (type == ICMP_UNREACH) {
                if (ip->ip_p == IPPROTO_TCP) {
                        printf("icmp tcp\n");
                        struct tcphdr *tcp = (struct tcphdr *)((char *)ip + hlen);
                } else if (ip->ip_p == IPPROTO_UDP) {
                        struct udphdr *udp = (struct udphdr *)((char *)ip + hlen);
                        if (ntohs(udp->uh_dport) == pkt->port && ntohs(udp->uh_sport) == e.pid)
                                udp_decode(pkt, code, 42, is_node_exist(r, pkt->port));
                }
        }
        return EXIT_SUCCESS;
}
