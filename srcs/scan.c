/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   scan.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: aabelque <aabelque@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/01/05 16:05:05 by aabelque          #+#    #+#             */
/*   Updated: 2022/01/11 23:45:30 by aabelque         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

extern t_env e;

static void callback(u_char *arg, const struct pcap_pkthdr *hdr, const u_char *data)
{
        int hlen = 0;
        t_pkt_data *pkt_data;
        struct ip *ip;
        struct tcphdr *tcp;
        struct icmp *icmp;
        struct udphdr *udp;

        data += OFFSET;
        pkt_data = (t_pkt_data *)arg;

        ip = (struct ip *)data;
        hlen = ip->ip_hl << 2;
        switch (ip->ip_p) {
        case IPPROTO_TCP:
                tcp = (struct tcphdr *)(data + hlen);
                /* get_tcp_response(tcp, pkt_data); */
                break;
        case IPPROTO_UDP:
                udp = (struct udphdr *)(data + hlen);
                get_udp_response(udp, pkt_data);
        case IPPROTO_ICMP:
                /* icmp = (struct icmp *)(data + hlen); */
                get_icmp_response(data, pkt_data);
                break;
        default:
                fprintf(stderr, "Protocol not supported: %u\n", ip->ip_p);
                break ;
        }

}

static int scan(t_target tgt, int type, int port)
{
        int cc = 0;
        pcap_t *handle;
        t_pkt_data data;

        data.port = port;
        data.type = type;
        data.tgt = tgt;
        cc = capture_setup(tgt, &handle, port, type);
        if (cc) {
                pcap_close(handle);
                return EXIT_FAILURE;
        }

        cc = send_packet(tgt, port, type);
        if (cc) {
                pcap_close(handle);
                return EXIT_FAILURE;
        }

        cc = pcap_dispatch(handle, 1, callback, (unsigned char *)&data);
        if (!cc) {
                printf("no packet\n");
        } else {
                pcap_close(handle);
        }
        return EXIT_SUCCESS;
}

int process_scan(t_target target)
{
        int i = 0;
        while (e.ports[i]) {
                if (e.scan & SYN)
                        if (scan(target, SYN, e.ports[i]))
                                return EXIT_FAILURE;
                if (e.scan & NUL)
                        if (scan(target, NUL, e.ports[i]))
                                return EXIT_FAILURE;
                if (e.scan & ACK)
                        if (scan(target, ACK, e.ports[i]))
                                return EXIT_FAILURE;
                if (e.scan & FIN)
                        if (scan(target, FIN, e.ports[i]))
                                return EXIT_FAILURE;
                if (e.scan & XMAS)
                        if (scan(target, XMAS, e.ports[i]))
                                return EXIT_FAILURE;
                if (e.scan & UDP)
                        if (scan(target, UDP, e.ports[i]))
                                return EXIT_FAILURE;
                i++;
        }
        return EXIT_SUCCESS;
}

