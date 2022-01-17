/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   scan.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: aabelque <aabelque@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/01/05 16:05:05 by aabelque          #+#    #+#             */
/*   Updated: 2022/01/17 02:35:13 by aabelque         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

extern t_env e;

/**
 * no_packet -  checks the type of scan received and
 *              calls the appropriate <type>_decocde function
 * @data: struct t_pkt_data that contain data info
 * @return 0
 */
static int8_t no_packet(t_pkt_data *data)
{
        int8_t shift, idx;
        void (*func[6])(t_pkt_data *, uint8_t, uint8_t) = {&syn_decode, &null_decode,
                &ack_decode, &fin_decode, &xmas_decode, &udp_decode};

        for (idx = 0, shift = 1; shift < 64 && idx < 6; shift <<= 1, idx++) {
                if (data->type == shift)
                        func[idx](data, -1, 42);
        }
        return EXIT_SUCCESS;
}

/**
 * callback - function call by pcap_dispatch() - gets packet and checks ip protocol
 * @arg: struct t_pkt_data passed to the fourth argument of pcap_dispatch()
 * @hdr: struct pcap_pkthdr 
 * @data: data captured by pcap_dispatch()
 */
static void callback(u_char *arg, const struct pcap_pkthdr *hdr, const u_char *data)
{
        int8_t hlen = 0;
        t_pkt_data *pkt_data;
        struct ip *ip;
        struct tcphdr *tcp;
        struct icmp *icmp;
        struct udphdr *udp;

        pkt_data = (t_pkt_data *)arg;
        data += OFFSET;

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
                break;
        case IPPROTO_ICMP:
                get_icmp_response(data, pkt_data);
                break;
        default:
                fprintf(stderr, "Protocol not supported: %u\n", ip->ip_p);
                break ;
        }

}

/**
 * scan - process nmap scan: setup packet and pcap filter, send packet to the target and wait for incomming packet with callback function
 * @tgt: struct t_target that contain target(s) info
 * @type: type of scan
 * @port: port to scan
 * @return 0 on success or 1 on failure
 */
static int8_t scan(t_target *tgt, int8_t type, uint16_t port)
{
        int8_t cc = 0;
        int16_t wait = 500;
        int64_t time = 0.0;
        struct timeval t1, t2;
        t_pkt_data data;
        pcap_t *handle;
        
        data = (t_pkt_data){type, port, tgt};
        if (capture_setup(tgt, &handle, port, type))
                goto return_failure;
        if (send_packet(tgt, port, type))
                goto return_failure;
        gettimeofday(&t1, NULL);
        sleep(1);

        do {
                cc = pcap_dispatch(handle, 1, callback, (unsigned char *)&data);
                gettimeofday(&t2, NULL);
                time += gettimeval(t1, t2);
        } while (time < wait && cc == 0);

        if (cc == 0)
                if (no_packet(&data))
                        goto return_failure;
        /* goto return_success; */
        pcap_close(handle);
        return EXIT_FAILURE;

/* return_success: */
/*         pcap_close(handle); */
/*         return EXIT_SUCCESS; */
return_failure:
        pcap_close(handle);
        return EXIT_FAILURE;
}

/**
 * process_scan - for each port lunch scan with the appropriate type of scan
 * @target: struct t_target that contain target(s) info
 * @return 0 for success or 1 for failure
 */
int8_t process_scan(t_target *target)
{
        for (int16_t i = 0; e.ports[i]; i++) {
                for (int8_t shift = 1; shift < 64; shift <<= 1) {
                       if (e.scan & shift)
                               if (scan(target, shift, e.ports[i]))
                                       return EXIT_FAILURE;
                }
        }
        /* while (e.ports[i]) { */
        /*         if (e.scan & SYN) */
        /*                 if (scan(target, SYN, e.ports[i])) */
        /*                         return EXIT_FAILURE; */
        /*         if (e.scan & NUL) */
        /*                 if (scan(target, NUL, e.ports[i])) */
        /*                         return EXIT_FAILURE; */
        /*         if (e.scan & ACK) */
        /*                 if (scan(target, ACK, e.ports[i])) */
        /*                         return EXIT_FAILURE; */
        /*         if (e.scan & FIN) */
        /*                 if (scan(target, FIN, e.ports[i])) */
        /*                         return EXIT_FAILURE; */
        /*         if (e.scan & XMAS) */
        /*                 if (scan(target, XMAS, e.ports[i])) */
        /*                         return EXIT_FAILURE; */
        /*         if (e.scan & UDP) */
        /*                 if (scan(target, UDP, e.ports[i])) */
        /*                         return EXIT_FAILURE; */
        /*         i++; */
        /* } */
        return EXIT_SUCCESS;
}
