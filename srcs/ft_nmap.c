/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nmap.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: aabelque <aabelque@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/12/25 11:44:49 by aabelque          #+#    #+#             */
/*   Updated: 2022/01/09 22:36:49 by zizou            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

extern t_env e;

void *nmap_scan(void *target)
{
        int i = -1;
        t_target *tgt = (t_target *)target;

        if (e.dim) {
                while (++i < e.dim) {
                        print_header(tgt[i].hname, tgt[i].ip, tgt[i].rdns);
                        if (process_scan(tgt[i]))
                                return NULL;
                        write(1, "\n", 1);
                }
        } else {
                print_header(tgt->hname, tgt->ip, tgt->rdns);
                if (process_scan(*tgt))
                        return NULL;
        }
        return NULL;
}

void ft_nmap(void)
{
        void *target;

        target = e.target;
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
        print_first_line();
        ft_nmap();
        environment_cleanup();
        return EXIT_SUCCESS;
}
