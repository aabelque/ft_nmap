/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   decode.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: aabelque <aabelque@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/01/13 14:25:29 by aabelque          #+#    #+#             */
/*   Updated: 2022/01/17 23:06:04 by zizou            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

/**
 * syn_decode - decode the tcp response with syn flags
 * @data: struct t_pkt_data that contains data info
 * @code: tcp|icmp code response
 * @flags: flags of tcp response
 */
void syn_decode(t_pkt_data *data, uint8_t code, uint8_t flags)
{
        printf("syn - flags %d - code %d\n", flags, code);
}

/**
 * null_decode - decode the tcp response with null flags
 * @data: struct t_pkt_data that contains data info
 * @code: tcp|icmp code response
 * @flags: flags of tcp response
 */
void null_decode(t_pkt_data *data, uint8_t code, uint8_t flags)
{
        printf("null - flags %d - code %d\n", flags, code);
}

/**
 * ack_decode - decode the tcp response with ack flags
 * @data: struct t_pkt_data that contains data info
 * @code: tcp|icmp code response
 * @flags: flags of tcp response
 */
void ack_decode(t_pkt_data *data, uint8_t code, uint8_t flags)
{
        printf("ack - flags %d - code %d\n", flags, code);
}

/**
 * fin_decode - decode the tcp response with fin flags
 * @data: struct t_pkt_data that contains data info
 * @code: tcp|icmp code response
 * @flags: flags of tcp response
 */
void fin_decode(t_pkt_data *data, uint8_t code, uint8_t flags)
{
        printf("fin - flags %d - code %d\n", flags, code);
}

/**
 * xmas_decode - decode the tcp response with xmas flags
 * @data: struct t_pkt_data that contains data info
 * @code: tcp|icmp code response
 * @flags: flags of tcp response
 */
void xmas_decode(t_pkt_data *data, uint8_t code, uint8_t flags)
{
        printf("xmas - flags %d - code %d\n", flags, code);
}

/**
 * udp_decode - decode the udp response to set result
 * @data: struct t_pkt_data that contains data info
 * @code: icmp code response
 * @flags: flags of tcp response, not used. Needed for pointer function
 */
void udp_decode(t_pkt_data *data, uint8_t code, uint8_t flags)
{
        int8_t state = 0;
        uint16_t port = data->port;

        switch (code) {
        case 255:
                state |= S_OF;
                break;
        case 3:
                state |= S_CL;
                break;
        default:
                state |= S_FI;
                break;
        }
        add_node(&data->tgt->report, new_node(state, port, get_service(port, NULL)));
}
