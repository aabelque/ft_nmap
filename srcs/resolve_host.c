/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   resolve_host.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: aabelque <aabelque@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/12/29 23:08:06 by aabelque          #+#    #+#             */
/*   Updated: 2022/01/30 17:29:46 by zizou            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"
#include <net/if.h>

extern t_env e;

/**
 * resolve_dns - check if we can get domain name of the target
 * @addr: struct sockaddr that contains target address info
 * @target: struct t_target that contains target(s) info
 * @many: boolean, false for one target or true for many target
 */
static void resolve_dns(struct sockaddr *addr, t_target *target, bool many)
{
        char dns[MAXHOST];
        socklen_t len = sizeof(*addr);

        ft_memset(dns, '\0', MAXHOST);
        if (!many) {
                target->hname = ft_memalloc(sizeof(char *) * (ft_strlen(e.hostname) + 1));
                ft_memcpy(target->hname, e.hostname, ft_strlen(e.hostname));
        }
        if (getnameinfo(addr, len, dns, sizeof(dns), NULL, 0, NI_NAMEREQD))
                e.resolve_dns = false;
        if (e.resolve_dns) {
                target->rdns = ft_memalloc(sizeof(char *) * (ft_strlen(dns) + 1));
                ft_memcpy(target->rdns, dns, ft_strlen(dns));
        } else {
                target->rdns = NULL;
        }
        e.resolve_dns = true;
}

/**
 * resolve_host - resolve and get target host address
 * @target: struct t_target that contains target(s) info
 * @many: boolean, false for one target or true for many target
 * @return 0 on success or 1 on failure
 */
static int8_t resolve_host(t_target *target, bool many)
{
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
                if (getaddrinfo(target->ip, NULL, &hints, &result))
                        return EXIT_FAILURE;
        } else {
                ip_dot(e.hostname);
                if (getaddrinfo(e.hostname, NULL, &hints, &result))
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

/**
 * get_my_interface - get address of my interface (struct sockaddr_in)
 * @tgt: struct t_target that contains target(s) info
 * @interface: string containing interface name
 * @return 0 on success or 1 on failure
 */
int8_t get_my_interface(t_target *tgt, char **device)
{
        struct ifaddrs *ifaddr;
        struct ifaddrs *ifa;

        if (getifaddrs(&ifaddr) == -1)
                return EXIT_FAILURE;
        for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
                /* pthread_mutex_lock(e.mutex); */
                if (is_loopback(tgt->ip, ifa)) {
                        if (get_interface_name(tgt, ifa, device))
                                goto return_failure;
                        break;
                } else if (is_eth_interface(ifa)) {
                        if (get_interface_name(tgt, ifa, device))
                                goto return_failure;
                        break;
                }
                /* pthread_mutex_unlock(e.mutex); */
        }
        freeifaddrs(ifaddr);
        return EXIT_SUCCESS;

return_failure:
        freeifaddrs(ifaddr);
        return EXIT_FAILURE;
}

/**
 * set_and_resolve_hosts - set target structure and get address of host target
 * @return 0 on success or 1 on failure
 */
int8_t set_and_resolve_hosts(void)
{
        if (e.many_target) {
                e.target = ft_memalloc(sizeof(*e.target) * e.dim);
                for (uint16_t i = 0; i < e.dim; i++) {
                        ft_strcpy(e.target[i].ip, e.multiple_ip[i]);
                        if (resolve_host(&e.target[i], e.many_target))
                                return EXIT_FAILURE;
                }
        } else {
                e.target = ft_memalloc(sizeof(*e.target));
                if (resolve_host(e.target, e.many_target))
                        return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
}
