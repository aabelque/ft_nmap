/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   filter.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: zizou </var/mail/zizou>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/01/18 01:02:51 by zizou             #+#    #+#             */
/*   Updated: 2022/01/28 18:45:41 by zizou            ###   ########.fr       */
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
static char *create_filter(char *host, uint16_t port, uint8_t type)
{
        char *filter;

        pthread_mutex_lock(e.mutex);
        if ((filter = ft_memalloc(sizeof(*filter) * 256)) == NULL)
                return NULL;
        if (type == UDP)
                sprintf(filter, \
                        "(icmp and src host %s and dst host %s)" \
                        " || " \
                        "(udp and src host %s and dst host %s)", \
                        host, e.my_ip, host, e.my_ip);
        else
                sprintf(filter, \
                        "(tcp and src host %s and dst host %s)" \
                        " || " \
                        "(icmp and src host %s and dst host %s)", \
                        host, e.my_ip, host, e.my_ip);
        pthread_mutex_unlock(e.mutex);
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
                uint16_t port, uint8_t type)
{
        char *filter;
        char s[ERRBUF];
        struct bpf_program fp;

        printf("start of compile_and_set_filter()\n");
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
