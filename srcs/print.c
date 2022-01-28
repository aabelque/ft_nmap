/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   print.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: aabelque <aabelque@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/01/21 16:17:29 by aabelque          #+#    #+#             */
/*   Updated: 2022/01/28 18:25:53 by zizou            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static void print_state(uint8_t state, int8_t *type, bool *first)
{
        int8_t space;

        pthread_mutex_lock(e.mutex);
        space = ft_strlen((char *)type) == 4 ? 1 : 2;
        *first = *first == true ? false : printf("%17s", "");
        if (state & S_OP)
                fprintf(stdout, "%s%*s- %s\n", type, space, "", "Open");
        else if (state & S_CL)
                fprintf(stdout, "%s%*s- %s\n", type, space, "", "Closed");
        else if (state & S_FI)
                fprintf(stdout, "%s%*s- %s\n", type, space, "", "Filtered");
        else if (state & S_UF)
                fprintf(stdout, "%s%*s- %s\n", type, space, "", "Unfiltered");
        else if (state & S_OF)
                fprintf(stdout, "%s%*s- %s\n", type, space, "", "Open|Filtered");
        else if (state & S_CF)
                fprintf(stdout, "%s%*s- %s\n", type, space, "", "Closed|Filtered");
        pthread_mutex_unlock(e.mutex);
}

static void print_each_state(t_scan *scan, bool *first)
{
        uint8_t current_type = 0, i = 0, start = 1, end = 64;
        int8_t type[6][5] = {"syn\0", "null\0",
                "ack\0", "fin\0", "xmas\0", "udp\0"};

        pthread_mutex_lock(e.mutex);
        for_eachtype(i, current_type, start, end) {
                if (scan->type & current_type) {
                        print_state(scan->state, type[i], first);
                }
        }
        pthread_mutex_unlock(e.mutex);
}

static void print_each_port(t_result *r, bool *first)
{
        pthread_mutex_lock(e.mutex);
        fprintf(stdout, "%*d", -5, r->port);
        fprintf(stdout, "%*s", -12, r->service ? r->service : "Unassigned");
        for (t_scan *s = r->scan; s; s = s->next) {
                print_each_state(s, first);
                *first = false;
        }
        pthread_mutex_unlock(e.mutex);
}

static void get_each_port(t_result *r)
{
        bool first = true;
        t_result *p = r;

        pthread_mutex_lock(e.mutex);
        while (p) {
                print_each_port(p, &first);
                first = true;
                p = p->next;
        }
        pthread_mutex_unlock(e.mutex);
}

static char *fill_dash(int8_t from, int8_t to)
{
        uint8_t size = 29;
        char *dash, *tmp;
        
        pthread_mutex_lock(e.mutex);
        dash = ft_memalloc(sizeof(char) * (size + 1));
        ft_memset(dash, '\0', ft_strlen(dash));
        tmp = dash;
        for (int i = 0; i < size; i++) {
                tmp[i] = to;
        }
        pthread_mutex_unlock(e.mutex);
        return dash;
}

void print_result(t_result *r)
{
        char *dash;
        t_result *tmp = r;

        pthread_mutex_lock(e.mutex);
        dash = fill_dash(0, '-');
        fprintf(stdout,"Scan result:\n");
        fprintf(stdout, "%s%8s%10s\n%s\n", "PORT", "SERVICE", "STATE", dash);
        get_each_port(tmp);
        free(dash);
        pthread_mutex_unlock(e.mutex);
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
        fprintf(stdout, "\nStarting ft_nmap at %s\n", tbuf);
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
        pthread_mutex_lock(e.mutex);
        if (!hname)
                hname = ip;
        if (e.dot && rdns)
                fprintf(stdout, "Ft_nmap scan report for %s (%s)\n", rdns, ip);
        else
                fprintf(stdout, "Ft_nmap scan report for %s (%s)\n", hname, ip);
        if (!e.dot && rdns)
                fprintf(stdout, "rDNS record for %s: %s\n", hname, rdns); 
        fprintf(stdout, "\nScan configurations:\n");
        fprintf(stdout, "Number of ports to scan: %d\n", number_of_ports());
        fprintf(stdout, "Number of threads: %d\n", e.nb_thread);
        fprintf(stdout, "Scans to be performed: ");
        if (!e.scan) {
                fprintf(stdout, "SYN NULL ACK FIN XMAS UDP");
        } else {
                /*! TODO: refactoring this with array of scan type and for loop or for_eachtype loop ?? */
                if (e.scan & SYN)
                        fprintf(stdout, "SYN ");
                if (e.scan & NUL)
                        fprintf(stdout, "NULL ");
                if (e.scan & ACK)
                        fprintf(stdout, "ACK ");
                if (e.scan & FIN)
                        fprintf(stdout, "FIN ");
                if (e.scan & XMAS)
                        fprintf(stdout, "XMAS ");
                if (e.scan & UDP)
                        fprintf(stdout, "UDP ");
        }
        fprintf(stdout, "\n\n");
        pthread_mutex_unlock(e.mutex);
}

/**
 * help_menu - helping menu
 * @status: set to -1 for the exit function
 */
void help_menu(int8_t status)
{
        fprintf(stdout, "Help Screen\n"
                "Usage: ft_nmap [--ip x.x.x.x OR --file file.txt OR"
                " --hostname example.fr] --ports RANGE/NUMBER --speedup NUMBER --scan TYPE\n"
                "ft_nmap [OPTIONS]\n"
                " --help\t\tPrint this help screen\n"
                " --ip\t\tIp adresses to scan in dot format\n"
                " --file\t\tFile name containing IP adresses to scan\n"
                " --hostname\thostname to scan\n"
                " --ports\tPorts to scan (eg: 1-10 or 1 2 3)\n"
                " --speedup\t[250 max] number of parallel thread to use\n"
                " --scan\t\tSYN,NULL,FIN,XMAS,ACK,UDP\n");
        exit(status);
}
