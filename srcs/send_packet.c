/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   send_packet.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: aabelque <aabelque@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/01/09 19:26:13 by aabelque          #+#    #+#             */
/*   Updated: 2022/01/31 14:27:25 by aabelque         ###   ########.fr       */
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
        struct in_addr dst, src;

        /* pthread_mutex_lock(e.mutex); */
        dst = tgt->to->sin_addr;
        if (tgt->src)
                src = tgt->src->sin_addr;
        /* pthread_mutex_unlock(&e.mutex); */

	ft_memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr = dst;
	addr.sin_port = htons(port);

        /* printf("in send_tcp_packet()\n"); */
        tcp_packet_setup(&packet, tgt, port, hlen, type);
        packet.tcp.th_sum = checksum_tcp(&packet.tcp, dst, src);

        /* pthread_mutex_lock(&e.mutex); */
        if ((tgt->socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1)
                return EXIT_FAILURE;
        if (setsockopt(tgt->socket, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt)))
                return EXIT_FAILURE;
        cc = sendto(tgt->socket, (char *)&packet, hlen, \
                        0, (struct sockaddr *)&addr, sizeof(addr));
        if (cc < 0)
                perror("Sendto: ");
        /* pthread_mutex_unlock(&e.mutex); */
        return cc;
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
        int8_t cc = 0;
        struct udp_packet packet;
        struct sockaddr_in addr;
        struct in_addr dst, src;

	ft_memset(&addr, 0, sizeof(addr));
	ft_memset(&dst, 0, sizeof(dst));
	ft_memset(&src, 0, sizeof(src));

        dst = tgt->to->sin_addr;
        if (tgt->src)
                src = tgt->src->sin_addr;
	addr.sin_family = AF_INET;
	addr.sin_addr = tgt->to->sin_addr;
	addr.sin_port = htons(port);
        udp_packet_setup(&packet, tgt->to->sin_addr, src, port, hlen);
        if ((e.udp_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1)
                return EXIT_FAILURE;
        cc = sendto(e.udp_socket, &packet, hlen, \
                        0, (struct sockaddr *)&addr, sizeof(addr));
        return cc;
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
                /* close(e.udp_socket); */
        } else {
                hlen = sizeof(struct tcp_packet);
                cc = send_tcp_packet(tgt, port, hlen, type);
                /* close(e.tcp_socket); */
        }
        if (cc < 0 || cc != hlen)
                goto return_failure;
        return EXIT_SUCCESS;

return_failure:
        fprintf(stderr, "Error sendto, the number of bytes sent is %d\n", cc);
        return EXIT_FAILURE;
}
