/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   print.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: zizou </var/mail/zizou>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/01/18 00:59:28 by zizou             #+#    #+#             */
/*   Updated: 2022/01/18 01:35:12 by aabelque         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

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
 * print_last_line - print execute time scan and number of target
 */
void print_last_line(void)
{
        int8_t nb_target;
        
        nb_target = (e.dim) ? e.dim : 1;
        fprintf(stdout, "\nFt_nmap done: %d IP address ", nb_target);
        fprintf(stdout, "scanned in %.3f seconds\n", e.time);
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
                /*! TODO: refactoring this with array of scan type and for loop ?? */
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
 * help_menu - helping menu
 * @status: set to -1 for the exit function
 */
void help_menu(int8_t status)
{
        printf("Help Screen\n"
                "Usage: ft_nmap [--ip x.x.x.x OR --file file.txt OR"
                " --hostname example.fr] --ports RANGE/NUMBER --speedup NUMBER --scan TYPE\n"
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
