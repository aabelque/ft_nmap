/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   scan.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: aabelque <aabelque@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/01/05 16:05:05 by aabelque          #+#    #+#             */
/*   Updated: 2022/01/05 23:31:19 by aabelque         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

extern t_env e;

static int scan(t_target *target, int type)
{
        int cc = 0, to_ms = 10000;
        bpf_u_int32 ip, mask;
        char *device = NULL;
        char error[ERRBUF], s[ERRBUF];
        pcap_t *handle;
        struct bpf_program filter;

        device = pcap_lookupdev(error);
        if (!device)
                perror_and_exit(error);
        cc = pcap_lookupnet(device, &ip, &mask, error);
        if (cc == -1) {
                sprintf(s, "Could not get information for device: %s - %s\n", \
                                device, error);
                perror_and_exit(s);
        }
        if (get_my_ip_and_mask(ip, mask))
                perror_and_exit("Error in get_my_ip_and_mask() function");
        handle = pcap_open_live(device, BUFSIZ, 1, to_ms, error);
        if (!handle) {
                sprintf(s, "Could not open %s - %s\n", device, error);
                perror_and_exit(s);
        }
        //TODO define FILTER man pcap-filter(7)
        cc = pcap_compile(handle, &filter, FILTER, 0, ip);
        if (cc == -1) {
                sprintf(s, "Bad filter - %s\n", pcap_geterr(handle));
                perror_and_exit(s);
        }
        /* pcap_setfilter(); */
        /* pcap_dispatch(); */
        /* pcap_breakloop(); */
        pcap_close(handle);
        return EXIT_SUCCESS;
}

int run_scan(t_target *target)
{
        if (e.scan & SYN)
                if (scan(target, SYN))
                        return EXIT_FAILURE;
        if (e.scan & NUL)
                if (scan(target, NUL))
                        return EXIT_FAILURE;
        if (e.scan & ACK)
                if (scan(target, ACK))
                        return EXIT_FAILURE;
        if (e.scan & FIN)
                if (scan(target, FIN))
                        return EXIT_FAILURE;
        if (e.scan & XMAS)
                if (scan(target, XMAS))
                        return EXIT_FAILURE;
        if (e.scan & UDP)
                if (scan(target, UDP))
                        return EXIT_FAILURE;
        return EXIT_SUCCESS;
}


