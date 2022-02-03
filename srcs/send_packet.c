/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   send_packet.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: aabelque <aabelque@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/01/09 19:26:13 by aabelque          #+#    #+#             */
/*   Updated: 2022/02/03 19:26:00 by aabelque         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

/**
 * send_tcp_packet - initialize tcp packet and send tcp packet
 * @tgt: struct t_target that contains target(s) info
 * @port: port to scan
 * @hlen: size of the packet structure
 * @type: type of scan
 * @return the number of bytes sent on success or 1 on failure
 */
static int16_t send_tcp_packet(t_target *tgt, uint16_t port, int8_t hlen, uint8_t type)
{
        int8_t opt = 1, cc = 0;
        struct tcp_packet packet;
        struct sockaddr_in addr;

	ft_memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr = tgt->to->sin_addr;
	addr.sin_port = htons(port);

        tcp_packet_setup(&packet, tgt, port, hlen, type);
        packet.tcp.th_sum = checksum_tcp(&packet.tcp, tgt->to->sin_addr, tgt->src->sin_addr);

        if ((tgt->socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
                return EXIT_FAILURE;
        if (setsockopt(tgt->socket, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt)))
                return EXIT_FAILURE;
        return sendto(tgt->socket, (char *)&packet, hlen, \
                        0, (struct sockaddr *)&addr, sizeof(addr));
}

/**
 * send_udp_packet - initialize udp packet and send udp packet
 * @tgt: struct t_target that contains target(s) info
 * @port: port to scan
 * @hlen: size of the packet structure
 * @return the number of bytes sent on success or 1 on failure
 */
static int16_t send_udp_packet(t_target *tgt, uint16_t port, int8_t hlen)
{
        int8_t opt = 1, cc = 0;
        struct udp_packet packet;
        struct sockaddr_in addr;

	ft_memset(&addr, 0, sizeof(addr));

	addr.sin_family = AF_INET;
	addr.sin_addr = tgt->to->sin_addr;
	addr.sin_port = htons(port);
        udp_packet_setup(&packet, tgt, port, hlen);
        if ((tgt->socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1)
                return EXIT_FAILURE;
        if (setsockopt(tgt->socket, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt)))
                return EXIT_FAILURE;
        return sendto(tgt->socket, &packet, hlen, \
                        0, (struct sockaddr *)&addr, sizeof(addr));
}

/**
 * send_packet - check the type of scan and call send_<type>_packet()
 * @tgt: struct t_target that contain target(s) info
 * @port: port to scan
 * @type: type of scan
 * @return 0 on success. On failure print error and return 1
 */
int8_t send_packet(t_target *tgt, uint16_t port, uint8_t type)
{
        int8_t hlen = 0;
        int16_t cc = 0;

        if (type & UDP) {
                hlen = sizeof(struct udp_packet);
                cc = send_udp_packet(tgt, port, hlen);
                close(tgt->socket);
        } else {
                hlen = sizeof(struct tcp_packet);
                cc = send_tcp_packet(tgt, port, hlen, type);
                close(tgt->socket);
        }
        if (cc < 0 || cc != hlen)
                goto return_failure;
        return EXIT_SUCCESS;

return_failure:
        fprintf(stderr, "Error sendto, the number of bytes sent is %d\n", cc);
        return EXIT_FAILURE;
}
