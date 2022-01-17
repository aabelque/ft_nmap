/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   utils.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: aabelque <aabelque@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/12/26 18:56:54 by aabelque          #+#    #+#             */
/*   Updated: 2022/01/17 18:50:40 by zizou            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"
#include <stdio.h>
#include <sys/cdefs.h>

extern t_env e;

/**
 * help_menu - helping menu
 * @status: set to -1 for the exit function
 */
void help_menu(int8_t status)
{
        printf("Help Screen\n"
                "Usage: ft_nmap [--ip x.x.x.x OR --file FILE OR --hostname example.fr] --ports RANGE/NUMBER --speedup NUMBER --scan TYPE\n"
                "ft_nmap [OPTIONS]\n"
                " --help\t\tPrint this help screen\n"
                " --ip\t\tIp adresses to scan in dot format\n"
                " --file\t\tFile name containing IP adresses to scan\n"
                " --hostname\thostname to scan\n"
                " --ports\tPorts to scan (eg: 1-10 or 1 2 3)\n"
                " --speedup\t[250 max] number of parallel thread to use\n"
                " --scan\t\tSYN/NULL/FIN/XMAS/ACK/UDP\n");
        exit(status);
}

/**
 * gettimeval - get the time taken by the scan
 * @before: struct timeval set before the scan
 * @after: struct timeval set after the scan
 * @return the time taken by the scan
 */
int64_t gettimeval(struct timeval before, struct timeval after)
{
        register int64_t time;

	time = (after.tv_sec - before.tv_sec) * 1000.0;
	time += (after.tv_usec - before.tv_usec) / 1000.0;
	return time;
}

/* unsigned short checksum(void *addr, int len) */
/* { */
/*         unsigned long checksum = 0; */
/*         unsigned short *buf = addr; */

/*         while (len > 1) { */
/*                 checksum += (unsigned short)*buf++; */
/*                 len -= sizeof(unsigned short); */
/*         } */
/*         if (len) */
/*                 checksum += *(unsigned char *)buf; */
/*         checksum = (checksum >> 16) + (checksum & 0xffff); */
/*         checksum = checksum + (checksum >> 16); */
/*         return (unsigned short)(~checksum); */
/* } */

/**
 * number_of_ports - get the total number of ports to scan
 * @return the total number of ports
 */
uint16_t number_of_ports(void)
{
        uint16_t ports = 0;

        for (uint16_t i = 0; e.ports[i]; i++)
                ports++;
        return ports;
}

/**
 * print_first_line - print date and schedule before nmap header
 */
void print_first_line(void)
{
        char tbuf[64];
        struct tm *info;

        info = localtime(&e.tv.tv_sec);
        strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M %Z", info);
        printf("\nStarting ft_nmap (%s) at %s\n", GIT, tbuf);
}

/**
 * print_header - print nmap header
 * @hname: target name if hostname set
 * @ip: target ip
 * @rdns: target domain name
 */
void print_header(char *hname, char *ip, char *rdns)
{
        if (!hname)
                hname = ip;
        if (e.dot && rdns)
                printf("Ft_nmap scan report for %s (%s)\n", rdns, ip);
        else
                printf("Ft_nmap scan report for %s (%s)\n", hname, ip);
        if (!e.dot && rdns)
                printf("rDNS record for %s: %s\n", hname, rdns); 
        printf("\nNumber of Ports to scan: %d\n", number_of_ports());
        printf("Number of threads: %d\n", e.nb_thread);
        printf("Scans to be performed: ");
        if (!e.scan) {
                printf("SYN NULL ACK FIN XMAS UDP");
        } else {
                if (e.scan & SYN)
                        printf("SYN ");
                if (e.scan & NUL)
                        printf("NULL ");
                if (e.scan & ACK)
                        printf("ACK ");
                if (e.scan & FIN)
                        printf("FIN ");
                if (e.scan & XMAS)
                        printf("XMAS ");
                if (e.scan & UDP)
                        printf("UDP ");
        }
        printf("\n\n");
}

/**
 * get_device_ip_and_mask - get interface name (device), ip and submask
 * @host: string containing address of host
 * @device: address of string to store interface name
 * @ip: uint32_t to store the ip
 * @mask: uint32_t to store the submask
 * @return 0 on success or -1 on failure
 */
int8_t get_device_ip_and_mask(char *host, char **device, bpf_u_int32 *ip, bpf_u_int32 *mask)
{
        int8_t cc = 0;
        char dev[3];
        char error[ERRBUF], s[ERRBUF];

        ft_memset(dev, '\0', 3);
        if (!ft_strcmp(host, "127.0.0.1")) {
                ft_strcpy(dev, "lo");
                *device = dev;
                ft_strcpy(e.my_ip, "127.0.0.1");
                return EXIT_SUCCESS;
        }
        if ((*device = pcap_lookupdev(error)) == NULL) {
                sprintf(s, "%s", error);
                goto return_failure;
        }
        if (pcap_lookupnet(*device, ip, mask, error) == -1) {
                sprintf(s, "Could not get information for device: %s - %s\n", \
                                *device, error);
                goto return_failure;
        }
        return EXIT_SUCCESS;

return_failure:
        fprintf(stderr, "%s", s);
        return EXIT_FAILURE;
}

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

        filter = ft_memalloc(sizeof(*filter) * 256);
        if (!filter)
                return NULL;
        if (type == UDP)
                sprintf(filter, "(udp and src host %s and src port %u and dst host %s)" \
                                " || " \
                                "(icmp and src host %s and dst host %s)", \
                                host, port, e.my_ip, host, e.my_ip);
        else
                sprintf(filter, "(tcp and src host %s and src port %d and dst host %s)" \
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
int8_t compile_and_set_filter(t_target *tgt, pcap_t **handle, bpf_u_int32 mask, \
                uint16_t port, int8_t type)
{
        int8_t cc = 0;
        char s[ERRBUF];
        char *filter;
        struct bpf_program fp;

        filter = create_filter(tgt->ip, port, type);
        cc = pcap_compile(*handle, &fp, filter, 0, mask);
        if (cc == -1)
                goto return_failure;

        cc = pcap_setfilter(*handle, &fp);
        if (cc)
                goto return_failure;
        goto return_success;

return_failure:
        sprintf(s, "Bad filter - %s\n", pcap_geterr(*handle));
        fprintf(stderr, "%s", s);
        pcap_freecode(&fp);
        free(filter);
        return EXIT_FAILURE;

return_success:
        pcap_freecode(&fp);
        free(filter);
        return EXIT_SUCCESS;
}

inline void break_signal(__attribute__((unused))int sig)
{
        pcap_breakloop(e.handle);
}

inline void interrupt_signal(__attribute__((unused))int sig)
{
        /*! TODO: cleanup env to exit properly */
}
