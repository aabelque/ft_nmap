/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   utils.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: aabelque <aabelque@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/12/26 18:56:54 by aabelque          #+#    #+#             */
/*   Updated: 2022/01/18 02:55:25 by aabelque         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

extern t_env e;

/**
 * gettimeval - get the time taken by the scan
 * @before: struct timeval set before the scan
 * @after: struct timeval set after the scan
 * @return the time taken by the scan
 */
double gettimeval(struct timeval before, struct timeval after)
{
        register double time;

	time = (after.tv_sec - before.tv_sec) * 1000.0;
	time += (after.tv_usec - before.tv_usec) / 1000.0;
	return time;
}

/**
 * calculate_scan_time - calculate execute time scan
 * @start: struct timeval initiate before scan
 * @end: struct timeval initiate after scan
 */
void calculate_scan_time(struct timeval start, struct timeval end)
{
        double ts, te;

        ts = (double)start.tv_sec + (double)start.tv_usec / 1000000;
        te = (double)end.tv_sec + (double)end.tv_usec / 1000000;
        e.time += te - ts;
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
 * get_device_ip_and_mask - get interface name (device), ip and submask
 * @host: string containing address of host
 * @device: address of string to store interface name
 * @ip: uint32_t to store the ip
 * @mask: uint32_t to store the submask
 * @return 0 on success or -1 on failure
 */
int8_t get_device_ip_and_mask(char *host, char **device, bpf_u_int32 *ip, bpf_u_int32 *mask)
{
        char dev[3];
        char error[ERRBUF];

        ft_memset(dev, '\0', sizeof(dev));
        ft_memset(error, '\0', sizeof(error));
        if (!ft_strcmp(host, "127.0.0.1")) {
                ft_strcpy(dev, "lo");
                *device = dev;
                ft_strcpy(e.my_ip, "127.0.0.1");
                return EXIT_SUCCESS;
        }
        if ((*device = pcap_lookupdev(error)) == NULL)
                goto return_failure;
        if (pcap_lookupnet(*device, ip, mask, error) == -1)
                goto return_failure;
        return EXIT_SUCCESS;

return_failure:
        fprintf(stderr, "%s", error);
        return EXIT_FAILURE;
}

/**
 * break_signal - when SIGALRM signal received, breaks pcap_dispatch function
 * @sig: SIGALRM signal
 */
inline void break_signal(__attribute__((unused))int sig)
{
        pcap_breakloop(e.handle);
        alarm(1);
}

/**
 * interrupt_signal - when SIGINT signal received, clean and exit program
 * @sig: SIGINT signal
 */
inline void interrupt_signal(__attribute__((unused))int sig)
{
        /*! TODO: cleanup env to exit properly */
}
