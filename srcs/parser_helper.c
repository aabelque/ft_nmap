/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parser_helper.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: aabelque <aabelque@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/01/04 12:43:27 by aabelque          #+#    #+#             */
/*   Updated: 2022/01/04 13:21:42 by aabelque         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

char *get_ip_from_file(char *file)
{
        int fd;
        char buff[1024];

        ft_memset(buff, 0, 1024);
        if ((fd = open(file, O_RDONLY)) == -1)
                return NULL;
        if (read(fd, buff, 1024) < 0)
                return NULL;
        close(fd);
        return ft_strdup(buff);
}

int get_nbip_and_alloc(char *ip)
{
        int i = 0;

        while (ip[i]) {
                if (ip[i] == '\n')
                        e.dim++;
                i++;
        }
        e.multiple_ip = ft_memalloc(sizeof(char *) * e.dim);
        if (!e.multiple_ip)
                return EXIT_FAILURE;
        for (int i = 0; i < e.dim; i++) {
                e.multiple_ip[i] = ft_memalloc(sizeof(char) * INET_ADDRSTRLEN);
                if (!e.multiple_ip[i])
                        return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
}

int copy_ips(char *ip)
{
        for (int i = 0, j = 0, k = 0; ip[i] != '\0'; i++, k++) {
                if (ip[i] == '\n') {
                        j++;
                        k = -1;
                } else {
                        e.multiple_ip[j][k] = ip[i];
                }
        }
        if (e.multiple_ip[0][0] == '\0')
                return EXIT_FAILURE;
        return EXIT_SUCCESS;
}

int isdash(char *s)
{
        int dash = 0;

        while (*s++)
                if (*s == '-')
                        ++dash;
        if (dash > 1)
                return -1;
        return dash;
}

static int get_range(char *numbers)
{
        char **tmp = NULL;
        int first = 0, last = 0;
        
        tmp = ft_strsplit(numbers, '-');
        first = ft_atoi(tmp[0]);
        last = ft_atoi(tmp[1]);
        free(tmp[0]);
        free(tmp[1]);
        free(tmp);
        if (first > last || last + first > 1024 \
                        || last < 0 || first < 0 \
                        || last > 65535 || first > 65535)
                return EXIT_FAILURE;
        for (int i = 0; first <= last; i++, first++) {
                e.ports[i] = first;
        }
        return EXIT_SUCCESS;
}

static int get_all_ports(char **argv, int idx)
{
        int i = 0;
        while (strisdigit(argv[idx])) {
                if (i > 1023)
                        return EXIT_FAILURE;
                e.newargc = idx;
                e.ports[i] = ft_atoi(argv[idx]);
                idx++;
                i++;
        }
        for (int i = 0; e.ports[i]; i++)
                if (e.ports[i] < 0 || e.ports[i] > 65535)
                        return EXIT_FAILURE;
        return EXIT_SUCCESS;
}

int get_number(char **argv, int idx, int dash)
{
        int i = -1;

        if (dash) {
                if (get_range(argv[idx]))
                        perror_and_exit("Ports range specified must be between 1 and 1024");
        } else {
                if (get_all_ports(argv, idx))
                        return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
}
