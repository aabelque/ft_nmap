/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nmap.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: aabelque <aabelque@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/12/25 11:44:49 by aabelque          #+#    #+#             */
/*   Updated: 2022/01/28 18:34:36 by zizou            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

/*! TODO: handle SIGINT signal with sigaction() */
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
void *nmap_scan(void *ports)
{
        uint16_t i = -1;
        uint16_t *p = (uint16_t *)ports;
        t_target *tgt = (t_target *)e.target;

        if (e.dim) {
                while (++i < e.dim) {
                        print_header(tgt[i].hname, tgt[i].ip, tgt[i].rdns);
                        if (process_scan(&tgt[i], p))
                                return NULL;
                        print_result(tgt[i].report);
                        write(1, "\n", 1);
                }
        } else {
                if (process_scan(tgt, p))
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
        void *ports;

        /* target = (void *)e.target; */
        pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
        e.mutex = &mutex;
        print_header(e.target->hname, e.target->ip, e.target->rdns);
        if (!e.nb_thread)
                nmap_scan(e.ports);
        else
                if (create_thread(ports))
                        return ;
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
