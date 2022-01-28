/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   decode.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: aabelque <aabelque@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/01/13 14:25:29 by aabelque          #+#    #+#             */
/*   Updated: 2022/01/27 13:53:40 by aabelque         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

/**
 * syn_decode - decode the tcp response with syn flags
 * @data: struct t_pkt_data that contains data info
 * @code: tcp|icmp code response
 * @flags: flags of tcp response
 */
void syn_decode(t_pkt_data *data, uint8_t code, uint8_t flags, bool exist)
{
        uint8_t state = 0;
        uint16_t port = data->port;

        switch (code) {
        case 255:
                if (flags == 0)
                        state |= S_FI;
                break;
        case 42:
                state |= S_OP;
                break;
        case 21:
                state |= S_CL;
                break;
        default:
                state |= S_FI;
                break;
        }
        if (exist)
                update_node(data->tgt->report, SYN, state, port);
        else
                add_node(&data->tgt->report, new_node(state, SYN, port, get_service(port, NULL)));
}

/**
 * null_decode - decode the tcp response with null flags
 * @data: struct t_pkt_data that contains data info
 * @code: tcp|icmp code response
 * @flags: flags of tcp response
 */
void null_decode(t_pkt_data *data, uint8_t code, uint8_t flags, bool exist)
{
        uint8_t state = 0;
        uint16_t port = data->port;

        switch (code) {
        case 21:
                state |= S_CL;
                break;
        case 255:
                state |= S_OF;
                break;
        default:
                state |= S_FI;
                break;
        }
        if (exist)
                update_node(data->tgt->report, NUL, state, port);
        else
                add_node(&data->tgt->report, new_node(state, NUL, port, get_service(port, NULL)));
}

/**
 * ack_decode - decode the tcp response with ack flags
 * @data: struct t_pkt_data that contains data info
 * @code: tcp|icmp code response
 * @flags: flags of tcp response
 */
void ack_decode(t_pkt_data *data, uint8_t code, uint8_t flags, bool exist)
{
        uint8_t state = 0;
        uint16_t port = data->port;

        switch (code) {
        case 21:
                state |= S_UF;
                break;
        default:
                state |= S_FI;
                break;
        }
        if (exist)
                update_node(data->tgt->report, ACK, state, port);
        else
                add_node(&data->tgt->report, new_node(state, ACK, port, get_service(port, NULL)));
}

/**
 * fin_decode - decode the tcp response with fin flags
 * @data: struct t_pkt_data that contains data info
 * @code: tcp|icmp code response
 * @flags: flags of tcp response
 */
void fin_decode(t_pkt_data *data, uint8_t code, uint8_t flags, bool exist)
{
        uint8_t state = 0;
        uint16_t port = data->port;

        switch (code) {
        case 21:
                state |= S_CL;
                break;
        case 255:
                state |= S_OF;
                break;
        default:
                state |= S_FI;
                break;
        }
        if (exist)
                update_node(data->tgt->report, FIN, state, port);
        else
                add_node(&data->tgt->report, new_node(state, FIN, port, get_service(port, NULL)));
}

/**
 * xmas_decode - decode the tcp response with xmas flags
 * @data: struct t_pkt_data that contains data info
 * @code: tcp|icmp code response
 * @flags: flags of tcp response
 */
void xmas_decode(t_pkt_data *data, uint8_t code, uint8_t flags, bool exist)
{
        uint8_t state = 0;
        uint16_t port = data->port;

        switch (code) {
        case 21:
                state |= S_CL;
                break;
        case 255:
                state |= S_OF;
                break;
        default:
                state |= S_FI;
                break;
        }
        if (exist)
                update_node(data->tgt->report, XMAS, state, port);
        else
                add_node(&data->tgt->report, new_node(state, XMAS, port, get_service(port, NULL)));
}

/**
 * udp_decode - decode the udp response to set result
 * @data: struct t_pkt_data that contains data info
 * @code: icmp code response
 * @flags: flags of tcp response, not used. Needed for pointer function
 */
void udp_decode(t_pkt_data *data, uint8_t code, uint8_t flags, bool exist)
{
        uint8_t state = 0;
        uint16_t port = data->port;

        if (code != 255) {
                if (code == 3)
                        state |= S_CL;
                else
                        state |= S_FI;
        } else if (flags == 0 && code == 255) {
                state |= S_OF;
        } else {
                state |= S_OP;
        }
        if (exist)
                update_node(data->tgt->report, UDP, state, port);
        else
                add_node(&data->tgt->report, new_node(state, UDP, port, get_service(port, NULL)));
}
