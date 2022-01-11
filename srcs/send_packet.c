/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   send_packet.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: aabelque <aabelque@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/01/09 19:26:13 by aabelque          #+#    #+#             */
/*   Updated: 2022/01/11 19:58:04 by aabelque         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static int send_tcp_packet(t_target tgt, int port, int hlen, int type)
{
        struct tcp_packet packet;
        struct sockaddr_in addr;

	ft_memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr = tgt.to->sin_addr;
	addr.sin_port = htons(port);

        tcp_packet_setup(&packet, tgt.to->sin_addr, port, hlen, type);

        // TODO
        // Setup socket and sendto
        return 0;
}

static int send_udp_packet(t_target tgt, int port, int hlen)
{
        int cc = 0, ttl = 64;
        struct udp_packet packet;
        struct sockaddr_in addr;

	ft_memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr = tgt.to->sin_addr;
	addr.sin_port = htons(port);

        udp_packet_setup(&packet, tgt.to->sin_addr, port, hlen);

        e.udp_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (e.udp_socket == -1)
                return EXIT_FAILURE;
        if (setsockopt(e.udp_socket, IPPROTO_IP, IP_TTL, &ttl, \
                                sizeof(ttl)) < 0)
                return EXIT_FAILURE;
        /* cc = socket_setup(); */
        /* if (cc) */
                /* return EXIT_FAILURE; */
        // TODO
        // Setup socket and sendto
        
        return sendto(e.udp_socket, (char *)&packet, PACKET_SIZE, \
                        0, (struct sockaddr *)&addr, sizeof(addr));
}

int send_packet(t_target tgt, int port, int type)
{
        int cc = 0, hlen = 0;

        if (type == UDP) {
                hlen = sizeof(struct udp_packet);
                cc = send_udp_packet(tgt, port, hlen);
        } else {
                hlen = sizeof(struct tcp_packet);
                cc = send_tcp_packet(tgt, port, hlen, type);
        }
        if (cc < 0 || cc != PACKET_SIZE)
                fprintf(stderr, "Error sendto\n");
        return EXIT_SUCCESS;
}
