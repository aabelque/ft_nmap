/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parser.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: aabelque <aabelque@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/12/25 21:00:45 by aabelque          #+#    #+#             */
/*   Updated: 2022/01/17 02:31:20 by aabelque         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

extern t_env e;

/**
 * ip_dot - check if string ip contains dot
 * @ip: string to check
 */
void ip_dot(char *ip)
{
        int8_t dot = 0;
        char *s = ip;

        while (*s) {
                if (*s == '.')
                        dot++;
                s++;
        }
        e.dot = (dot > 1) ? 1 : 0;
}

/**
 * get_file - get target ip from file
 * @file: string that contains a filename
 * @return 0 on success or 1 on failure
 */
static int8_t get_file(char *file)
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

/**
 * get_ports - get ports to scan. Checks if it's a port range or not
 * @argv: string array that contains arguments
 * @idx: position of the argument
 * @return 0 on success or 1 on failure
 */
static int8_t get_ports(char **argv, int8_t idx)
{
        int8_t dash = 0;

        dash = isdash(argv[idx]);
        if (dash == -1)
                return EXIT_FAILURE;
        if (get_number(argv, idx, dash))
                return EXIT_FAILURE;
        return EXIT_SUCCESS;
}

/**
 * get_nbthread - get the number of thread to set for scanning
 * @nb_thread: string that contains the number of thread
 * @return 0 on success or 1 on failure (if thread < 0 or thread > 250)
 */
static int8_t get_nbthread(char *nb_thread)
{
        if (strisdigit(nb_thread)) {
                e.nb_thread = ft_atoi(nb_thread);
        }
        if (e.nb_thread < 0 || e.nb_thread > 250)
                return EXIT_FAILURE;
        return EXIT_SUCCESS;
}

/**
 * get_scan_type - get all type of scan
 * @argv: string array that contains arguments
 * @idx: position of the arguments
 * @return 0 on success or 1 on failure
 */
static int8_t get_scan_type(char **argv, int8_t *idx)
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
                        return EXIT_FAILURE;
                (*idx)++;
        }
        return EXIT_SUCCESS;
}

/**
 * parse_arg - parsing arguments and get options
 * @argc: number of arguments
 * @argv: string array that contains arguments
 * @return 0 on success or 1 on failure
 */
int8_t parse_arg(int argc, char **argv)
{
        if (check_duplicate_param(argv, argc))
                perror_and_exit("You have to use --ip or --hostname or --file");
        for (int8_t i = 1; i < argc; ++i) {
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
