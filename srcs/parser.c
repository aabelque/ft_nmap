/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parser.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: aabelque <aabelque@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/12/25 21:00:45 by aabelque          #+#    #+#             */
/*   Updated: 2022/01/05 17:41:51 by aabelque         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

extern t_env e;

int ip_dot(char *ip)
{
        int dot = 0;
        char *s = ip;

        while (*s) {
                if (*s == '.')
                        dot++;
                s++;
        }
        if (dot > 1)
                return 1;
        return 0;
}

static int get_file(char *file)
{
        char *ip;

        ip = get_ip_from_file(file);
        if (!ip)
                return EXIT_FAILURE;
        if (get_nbip_and_alloc(ip))
                return EXIT_FAILURE;
        if (copy_ips(ip))
                return EXIT_FAILURE;
        free(ip);
        return EXIT_SUCCESS;
}

static int get_ports(char **argv, int idx)
{
        int comma = 0, dash = 0;

        dash = isdash(argv[idx]);
        if (dash == -1)
                return EXIT_FAILURE;
        if (get_number(argv, idx, dash))
                return EXIT_FAILURE;
        return EXIT_SUCCESS;
}

static int get_nbthread(char *nb_thread)
{
        if (strisdigit(nb_thread)) {
                e.nb_thread = ft_atoi(nb_thread);
        }
        if (e.nb_thread < 0 || e.nb_thread > 250)
                return EXIT_FAILURE;
        return EXIT_SUCCESS;
}

static int get_scan_type(char **argv, int *idx)
{
        while (argv[*idx]) {
                if (!ft_strcmp(argv[*idx], "SYN"))
                        e.scan |= SYN;
                else if (!ft_strcmp(argv[*idx], "NULL"))
                        e.scan |= NUL;
                else if (!ft_strcmp(argv[*idx], "ACK"))
                        e.scan |= ACK;
                else if (!ft_strcmp(argv[*idx], "FIN"))
                        e.scan |= FIN;
                else if (!ft_strcmp(argv[*idx], "XMAS"))
                        e.scan |= XMAS;
                else if (!ft_strcmp(argv[*idx], "UDP"))
                        e.scan |= UDP;
                else
                        return EXIT_SUCCESS;
                (*idx)++;
        }
        return EXIT_SUCCESS;
}

int parse_arg(int argc, char **argv)
{
        if (check_duplicate_param(argv, argc))
                perror_and_exit("You have to use --ip or --hostname or --file");
        for (int i = 1; i < argc; ++i) {
                if (!ft_strcmp("--help", argv[i])) {
                        help_menu(EXIT_SUCCESS);
                } else if (!ft_strcmp("--ip", argv[i])) {
                        e.hostname = argv[++i];
                } else if (!ft_strcmp("--hostname", argv[i])) {
                        e.hostname = argv[++i];
                } else if (!ft_strcmp("--file", argv[i])) {
                        e.many_target = true;
                        if (get_file(argv[++i]))
                                return EXIT_FAILURE;
                } else if (!ft_strcmp("--ports", argv[i])) {
                        if (get_ports(argv, ++i))
                                return EXIT_FAILURE;
                        if (e.newargc)
                                i = e.newargc;
                } else if (!ft_strcmp("--speedup", argv[i])) {
                        if (get_nbthread(argv[++i]))
                                perror_and_exit("Speedup must be between 0 and 250");
                } else if (!ft_strcmp("--scan", argv[i])) {
                        ++i;
                        if (get_scan_type(argv, &i))
                                return EXIT_FAILURE;
                        --i;
                /* else if (ft_strcmp("--os", argv[i])) */
                /*         ;// call Function */
                } else {
                        help_menu(EXIT_FAILURE);
                }
        }
        check_options();
        return EXIT_SUCCESS;
}
