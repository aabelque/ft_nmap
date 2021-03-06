/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parser_helper.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: aabelque <aabelque@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/01/04 12:43:27 by aabelque          #+#    #+#             */
/*   Updated: 2022/02/10 13:15:24 by fherbine         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

/**
 * get_ip_from_file - open and read file to get ip
 * @file: file that contains ip
 * @return NULL on failure or string that contains ips
 */
char *get_ip_from_file(char *file)
{
        int fd;
        char buff[4096];

        ft_memset(buff, 0, sizeof(buff));
        if ((fd = open(file, O_RDONLY)) == -1)
                return NULL;
        if (read(fd, buff, 4096) < 0)
                return NULL;
        if (*buff == 0)
                return NULL;
        close(fd);
        return ft_strdup(buff);
}

/**
 * get_nbip_and_alloc - get number of ip and alloc 2D array of ips
 * @ip: string that contains all ips
 * @return 0 on success or 1 on failure
 */
int8_t get_nbip_and_alloc(char *ip)
{
        uint16_t i = 0;

        while (ip[i]) {
                if (ip[i] == '\n')
                        e.dim++;
                i++;
        }
        if ((e.multiple_ip = ft_memalloc(sizeof(char *) * e.dim)) == NULL)
                return EXIT_FAILURE;
        for (uint16_t i = 0; i < e.dim; i++) {
                if ((e.multiple_ip[i] = ft_memalloc(sizeof(char) \
                                                * INET_ADDRSTRLEN)) == NULL)
                        return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
}

/**
 * copy_ips - copy ips into 2D array of ips
 * @ip: ip to copy
 * @return 0 on success or 1 on failure
 */
int8_t copy_ips(char *ip)
{
        for (uint16_t i = 0, j = 0, k = 0; ip[i] != '\0'; i++, k++) {
                if (k > 16)
                        return EXIT_FAILURE;
                if (ip[i] == '\n') {
                        j++; k = -1;
                } else {
                        e.multiple_ip[j][k] = ip[i];
                }
        }
        if (e.multiple_ip[0][0] == '\0')
                return EXIT_FAILURE;
        return EXIT_SUCCESS;
}

/**
 * isdash - checks if there is a dash in string s
 * @s: string s
 * @return number of dash
 */
int8_t isdash(char *s)
{
        int8_t dash = 0;

        while (*s++)
                if (*s == '-')
                        ++dash;
        if (dash > 1)
                return -1;
        return dash;
}

/**
 * get_range - get ports range to scan
 * @numbers: string that contains port range
 * @return 0 on success or 1 on failure
 *      (if more than 1024 ports, or port number < 0
 *      or port number > uint16_t max value (65535))
 */
static int8_t get_range(char *numbers)
{
        char **tmp = NULL;
        uint16_t first = 0, last = 0;
        
        tmp = ft_strsplit(numbers, '-');
        first = ft_atoi(tmp[0]);
        last = ft_atoi(tmp[1]);
        free(tmp[0]);
        free(tmp[1]);
        free(tmp);
        if (first > last || last - first > 1024 \
                        || last < 0 || first < 0 \
                        || last > UINT16_MAX || first > UINT16_MAX)
                return EXIT_FAILURE;
        for (uint16_t i = 0; first <= last && i < 1024; i++, first++) {
                e.ports[i] = first;
        }
        return EXIT_SUCCESS;
}

/**
 * get_all_ports - get all ports if it's not ports range
 * @argv: string array that contains aruments
 * @idx: position of the argument
 * @return 0 on success or 1 on failure
 *      (if more than 1024 ports, or port number < 0
 *      or port number > uint16_t max value (65535))
 */
static int8_t get_all_ports(char **argv, int8_t idx)
{
        int16_t i = 0;
        while (strisdigit(argv[idx])) {
                if (i > 1023)
                        return EXIT_FAILURE;
                e.newargc = idx;
                e.ports[i] = ft_atoi(argv[idx]);
                idx++;
                i++;
        }
        for (int16_t i = 0; e.ports[i]; i++)
                if (e.ports[i] < 0 || e.ports[i] > UINT16_MAX)
                        return EXIT_FAILURE;
        return EXIT_SUCCESS;
}

/**
 * get_number - get ports to scan
 * @argv: string array that contains aruments
 * @idx: position of the argument
 * @dash: int8_t set to 1 if there is one dash or -1 if more than one dash
 * @return 0 on success or 1 on failure
 */
int8_t get_number(char **argv, int8_t idx, int8_t dash)
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

/**
 * check_options -  checks if ports and scan type are set.
 *                  If not, set scan type (default all type) and ports to scan (default 1 to 1024)
 */
void check_options(void)
{
        if (!e.ports[0])
                for (int16_t i = 0, port = 1; port < 1025; i++, port++)
                        e.ports[i] = port;
        if (!e.scan)
                e.scan |= ALL;
}
