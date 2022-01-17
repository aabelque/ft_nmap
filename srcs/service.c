/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   service.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: aabelque <aabelque@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/01/15 17:09:54 by aabelque          #+#    #+#             */
/*   Updated: 2022/01/15 17:58:23 by aabelque         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

/**
 * get_service - get service name running in specific port
 * @port: port number
 * @proto: proto (udp or tcp or NULL)
 * @return string that contains service name
 */
char *get_service(uint16_t port, const char *proto)
{
        struct servent *serv;
        char *service;

        serv = getservbyport(htons(port), proto);
        if (!serv)
                return NULL;
        service = ft_memalloc(ft_strlen(serv->s_name));
        if (!service)
                return NULL;
        ft_strcpy(service, serv->s_name);
        return service;
}

