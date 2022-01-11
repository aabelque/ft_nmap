/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   resolve_host.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: aabelque <aabelque@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/12/29 23:08:06 by aabelque          #+#    #+#             */
/*   Updated: 2022/01/12 00:18:39 by aabelque         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

extern t_env e;

void resolve_dns(struct sockaddr *addr, t_target *target, bool many)
{
        char dns[MAXHOST];
        socklen_t len = sizeof(*addr);

        ft_memset(dns, 0, MAXHOST);
        if (!many) {
                target->hname = ft_memalloc(sizeof(char *) * ft_strlen(e.hostname));
                ft_memcpy(target->hname, e.hostname, ft_strlen(e.hostname));
        }
        if (getnameinfo(addr, len, dns, sizeof(dns), NULL, 0, NI_NAMEREQD))
                e.resolve_dns = false;
        if (e.resolve_dns) {
                target->rdns = ft_memalloc(sizeof(char *) * ft_strlen(dns));
                ft_memcpy(target->rdns, dns, ft_strlen(dns));
        } else {
                target->rdns = NULL;
        }
        e.resolve_dns = true;
}

int resolve_host(t_target *target, bool many)
{
        int ret = 0;
        struct addrinfo hints;
        struct sockaddr_in *addr;
        struct addrinfo *result;

        ft_memset(&hints, 0, sizeof(hints));
        hints.ai_flags = AI_ADDRCONFIG | AI_V4MAPPED;
        hints.ai_family = AF_INET;
        hints.ai_socktype = 0;
	hints.ai_protocol = IPPROTO_RAW;
        hints.ai_addrlen = 0;
        hints.ai_addr = NULL;
        hints.ai_canonname = NULL;
        hints.ai_next = NULL;

        if (many) {
                ret = getaddrinfo(target->ip, NULL, &hints, &result);
                if (ret)
                        return EXIT_FAILURE;
        } else {
                e.dot = ip_dot(e.hostname);
                ret = getaddrinfo(e.hostname, NULL, &hints, &result);
                if (ret)
                        return EXIT_FAILURE;
        }
        addr = (struct sockaddr_in *)result->ai_addr;
        target->to = ft_memalloc(sizeof(*addr));
        if (!target->to)
                return EXIT_FAILURE; 
        ft_memcpy(target->to, addr, sizeof(*addr));
        resolve_dns((struct sockaddr *)addr, target, many);
        inet_ntop(AF_INET, &addr->sin_addr, target->ip, INET_ADDRSTRLEN);
        freeaddrinfo(result);
        return EXIT_SUCCESS;
}

int set_and_resolve_hosts(void)
{
        if (e.many_target) {
                e.target = ft_memalloc(sizeof(*e.target) * e.dim);
                for (int i = 0; i < e.dim; i++) {
                        ft_strcpy(e.target[i].ip, e.multiple_ip[i]);
                        if (resolve_host(&e.target[i], e.many_target))
                                return EXIT_FAILURE;
                        //TODO get interface addr (getifaddrs)-> target.src
                }
        } else {
                e.target = ft_memalloc(sizeof(*e.target));
                if (resolve_host(e.target, e.many_target))
                        return EXIT_FAILURE;
                //TODO get interface addr (getifaddrs)-> target.src
        }
        return EXIT_SUCCESS;
}
