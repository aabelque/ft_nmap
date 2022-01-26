/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nmap.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: aabelque <aabelque@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/12/25 11:44:49 by aabelque          #+#    #+#             */
/*   Updated: 2022/01/25 16:12:33 by zizou            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

/*! TODO: fix error valgrind, get rid off pcap_lookupdev and use getifaddrs */
/*! TODO: handle SIGINT signal with sigaction() */
/*! TODO: handle tcp scan */
/*! TODO: description function parser_helper.c and error.c */
/*! TODO: handle speedup opt with pthread */

extern t_env e;

/**
 * nmap_scan -  Check if there is many target
 *              and call process_scan() many time or one time
 *
 * @target      struct t_target that contain target(s)
 *
 */
void *nmap_scan(void *target)
{
        uint16_t i = -1;
        t_target *tgt = (t_target *)target;

        /* print_header(tgt->hname, tgt->ip, tgt->rdns); */
        /* print_result(); */
        if (e.dim) {
                while (++i < e.dim) {
                        print_header(tgt[i].hname, tgt[i].ip, tgt[i].rdns);
                        if (process_scan(&tgt[i]))
                                return NULL;
                        /* print_result(); */
                        write(1, "\n", 1);
                }
        } else {
                print_header(tgt->hname, tgt->ip, tgt->rdns);
                if (process_scan(tgt))
                        return NULL;
                print_result(tgt->report);
        }
        return NULL;
}

/**
 * ft_nmap - Lunch nmap scan and print result
 */
void ft_nmap(void)
{
        void *target;

        target = (void *)e.target;
        /* if (!e.nb_thread) */
        nmap_scan(target);
        /* else */
        /*         create_thread(); */
}

int main(int argc, char **argv)
{
        if (argc < 3)
                help_menu(EXIT_FAILURE);
        if (getuid() != 0)
                perror_and_exit("Ft_nmap requires root privileges.\nQUITTING!");
        environment_setup();
        if (parse_arg(argc, argv))
                help_menu(EXIT_FAILURE);
        gettimeofday(&e.tv, NULL);
        if (set_and_resolve_hosts())
                exit_errors(ERR_HOSTNAME, e.hostname);
        signal_setup();
        print_first_line();
        ft_nmap();
        print_last_line();
        environment_cleanup();
        return EXIT_SUCCESS;
}
