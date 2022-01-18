/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   errors.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: aabelque <aabelque@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/12/25 20:43:24 by aabelque          #+#    #+#             */
/*   Updated: 2022/01/18 01:19:23 by aabelque         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

/**
 * exit_errors - print the appropriate error and exit properly
 * @error: type of error
 * @arg: string that contains target name or target ip
 */
void exit_errors(int error, char *arg)
{
        double time = 0;
        struct timeval t;

        gettimeofday(&t, NULL);
        time = gettimeval(e.tv, t);
        switch (error) {
        case ERR_HOSTNAME:
                fprintf(stderr, "Failed to resolve '%s'\n" \
                "WARNING: No targets were specified, so 0 hosts scanned.\n" \
                "Ft_nmap done: 0 IP addresses (0 hosts up) scanned in %.2lf seconds\n", arg, time / 100);
        }
        environment_cleanup();
        exit(EXIT_FAILURE);
}

/**
 * perror_and_exit - print string error and exit properly
 * @s: string that contains error
 */
void perror_and_exit(char *s)
{
        fprintf(stderr, "%s\n""QUITTING\n", s);
        environment_cleanup();
        exit(EXIT_FAILURE);
}

/**
 * check_duplicate_param - check parameters if there is duplicate options
 * @av: array of strings that contains parameters
 * @ac: number of parameters
 * @return 0 on success or 1 on failure
 */
int8_t check_duplicate_param(char **av, int ac)
{
        int8_t ip = 0, hostname = 0, file = 0;

        for (int8_t i = 1; i < ac; i++){
                if (!ft_strcmp(av[i], "--ip"))
                        ip++;
                else if (!ft_strcmp(av[i], "--hostname"))
                        hostname++;
                else if (!ft_strcmp(av[i], "--file"))
                        file++;
        }
        if ((ip && hostname) || (ip && file) || (hostname && file))
                return EXIT_FAILURE;
        return EXIT_SUCCESS;
}
