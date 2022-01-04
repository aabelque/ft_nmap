/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   errors.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: aabelque <aabelque@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/12/25 20:43:24 by aabelque          #+#    #+#             */
/*   Updated: 2021/12/30 21:35:06 by zizou            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

void exit_errors(int error, char *arg)
{
        double time = 0;
        struct timeval t;

        gettimeofday(&t, NULL);
        time = gettimeval(e.tv, t);
        switch (error) {
        case ERR_HOSTNAME: fprintf(stderr, "Failed to resolve '%s'\n"
                "WARNING: No targets were specified, so 0 hosts scanned.\n"
                "Ft_nmap done: 0 IP addresses (0 hosts up) scanned in %.2lf seconds\n", arg, time / 100);
        }
        environment_cleanup();
        exit(EXIT_FAILURE);
}

void perror_and_exit(char *s)
{
        fprintf(stderr, "%s\n""QUITTING\n", s);
        environment_cleanup();
        exit(EXIT_FAILURE);
}

int check_duplicate_param(char **av, int ac)
{
        int ip = 0, hostname = 0, file = 0;

        for (int i = 1; i < ac; i++){
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
