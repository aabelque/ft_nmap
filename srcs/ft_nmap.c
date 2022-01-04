/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nmap.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: aabelque <aabelque@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/12/25 11:44:49 by aabelque          #+#    #+#             */
/*   Updated: 2022/01/04 18:15:42 by aabelque         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

extern t_env e;

void *nmap_scan(void *arg)
{
        int i = -1;

        if (e.dim) {
                while (++i < e.dim) {
                        print_header(e.target[i].hname, e.target[i].ip, e.target[i].rdns);
                        /* run_scan(); */
                        write(1, "\n", 1);
                }
        } else {
                print_header(e.target->hname, e.target->ip, e.target->rdns);
                /* run_scan(); */
        }
        return NULL;
}

void ft_nmap(void)
{
        void *arg;

        if (!e.nb_thread)
                nmap_scan(arg);
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
