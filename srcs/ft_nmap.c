/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nmap.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: aabelque <aabelque@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/12/25 11:44:49 by aabelque          #+#    #+#             */
/*   Updated: 2022/02/03 19:24:43 by aabelque         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

/*! TODO: handle SIGINT signal with sigaction() */

extern t_env e;

/**
 * nmap_scan -  Call process_scan()
 * @data      data send by pthread_create()
 *
 */
void *nmap_scan(void *data)
{
        t_target *tgt = (t_target *)data;

        if (process_scan(tgt, tgt->ports))
                pthread_exit(NULL);
        pthread_exit(tgt->report);
}

/**
 * ft_nmap - Check if there is many target and Lunch create_thread to scan
 */
void ft_nmap(void)
{
        uint16_t i = -1;
        struct timeval start, end;
        void *ports;

        print_first_line();
        target_setup();
        if (gettimeofday(&start, NULL))
                return ;
        if (e.dim) {
                while (++i < e.dim) {
                        print_header(e.target[i].hname, e.target[i].ip, e.target[i].rdns);
                        if (create_thread(ports))
                                return ;
                        write(1, "\n", 1);
                }
        } else {
                print_header(e.target->hname, e.target->ip, e.target->rdns);
                if (create_thread(ports))
                        return ;
        }
        if (gettimeofday(&end, NULL))
                return ;
        calculate_scan_time(start, end);
        print_last_line();
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
        ft_nmap();
        environment_cleanup();
        return EXIT_SUCCESS;
}
