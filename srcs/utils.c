/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   utils.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: aabelque <aabelque@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/12/26 18:56:54 by aabelque          #+#    #+#             */
/*   Updated: 2022/01/05 22:43:07 by aabelque         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

extern t_env e;

void help_menu(int status)
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

double gettimeval(struct timeval before, struct timeval after)
{
        register double time;

	time = (double)(after.tv_sec - before.tv_sec) * 1000.0 +
	     (double)(after.tv_usec - before.tv_usec) / 1000.0;

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

int number_of_ports(void)
{
        int ports = 0;

        for (int i = 0; e.ports[i]; i++)
                ports++;
        return ports;
}

void print_first_line(void)
{
        char tbuf[64];
        struct tm *info;

        info = localtime(&e.tv.tv_sec);
        strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M %Z", info);
        printf("\nStarting ft_nmap (%s) at %s\n", GIT, tbuf);
}

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
        printf("Number of Ports to scan: %d\n", number_of_ports());
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
        printf("\n");
}

int get_my_ip_and_mask(bpf_u_int32 ip, bpf_u_int32 mask)
{
        struct in_addr addr;

        addr.s_addr = ip;
        ft_strcpy(e.my_ip, inet_ntoa(addr));
        if (*e.my_ip == '\0')
                return EXIT_FAILURE;
        addr.s_addr = mask;
        ft_strcpy(e.my_mask, inet_ntoa(addr));
        if (*e.my_mask == '\0')
                return EXIT_FAILURE;
        return EXIT_SUCCESS;
}
