/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   filter.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: zizou </var/mail/zizou>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/01/18 01:02:51 by zizou             #+#    #+#             */
/*   Updated: 2022/01/18 01:19:36 by aabelque         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

/**
 * set_filter - create the filter
 * @host: string containing address of host
 * @port: port to scan
 * @type: type of scan
 * @return the filter
 */
static char *create_filter(char *host, uint16_t port, int8_t type)
{
        char *filter;

        if ((filter = ft_memalloc(sizeof(*filter) * 256)) == NULL)
                return NULL;
        if (type == UDP)
                sprintf(filter, \
                        "(udp and src host %s and src port %u and dst host %s)" \
                        " || " \
                        "(icmp and src host %s and dst host %s)", \
                        host, port, e.my_ip, host, e.my_ip);
        else
                sprintf(filter, \
                        "(tcp and src host %s and src port %d and dst host %s)" \
                        " || " \
                        "(icmp and src host %s and dst host %s)", \
                        e.my_ip, port, host, e.my_ip, host);
        return filter;
}

/**
 * compile_and_set_filter - define, compile and set filter
 * @tgt: struct t_target that contains target(s) info
 * @handle: address of packet capture handle
 * @mask: submask of the interface
 * @port: port to scan
 * @type: type of scan
 * @return 0 on success or -1 on failure and print the error
 */
int8_t compile_and_set_filter(t_target *tgt, pcap_t *handle, bpf_u_int32 mask, \
                uint16_t port, int8_t type)
{
        char *filter;
        char s[ERRBUF];
        struct bpf_program fp;

        if ((filter = create_filter(tgt->ip, port, type)) == NULL)
                goto return_failure;
        if ((pcap_compile(handle, &fp, filter, 0, mask)) == -1)
                goto return_failure;
        if (pcap_setfilter(handle, &fp))
                goto return_failure;
        goto return_success;

return_failure:
        sprintf(s, "Bad filter - %s\n", pcap_geterr(handle));
        fprintf(stderr, "%s", s);
        pcap_freecode(&fp);
        free(filter);
        return EXIT_FAILURE;

return_success:
        pcap_freecode(&fp);
        free(filter);
        return EXIT_SUCCESS;
}
