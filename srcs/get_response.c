/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   get_response.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: aabelque <aabelque@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/01/11 19:58:24 by aabelque          #+#    #+#             */
/*   Updated: 2022/01/11 22:59:37 by aabelque         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

int get_udp_response(struct udphdr *udp, t_pkt_data *pkt)
{
        printf("udp\n");

        printf("dport = %d\n", ntohs(udp->uh_dport));
        printf("sport = %d\n", ntohs(udp->uh_sport));
        printf("pkt port = %d\n", pkt->port);
        printf("pkt type = %d\n", pkt->type);
        printf("pkt ip = %s\n", pkt->tgt.ip);
        return EXIT_SUCCESS;
}

int get_tcp_response(struct tcphdr *tcp, t_pkt_data *pkt)
{
        return EXIT_SUCCESS;
}

int get_icmp_response(const u_char *data, t_pkt_data *pkt)
{
        int hlen = 0;
        struct ip *ip;
        struct icmp *icmp;

        ip = (struct ip *)data;
        hlen = ip->ip_hl << 2;

        icmp = (struct icmp *)(ip + hlen);

        printf("icmp\n");
        printf("icmp type = %d\n", icmp->icmp_type);
        printf("icmp code = %d\n", icmp->icmp_code);
        printf("pkt port = %d\n", pkt->port);
        printf("pkt type = %d\n", pkt->type);
        printf("pkt ip = %s\n", pkt->tgt.ip);
        return EXIT_SUCCESS;
}
