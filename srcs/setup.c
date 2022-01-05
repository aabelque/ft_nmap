/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   setup.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: aabelque <aabelque@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/12/26 22:26:12 by aabelque          #+#    #+#             */
/*   Updated: 2022/01/05 22:34:54 by aabelque         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

extern t_env e;

void environment_setup(void)
{
        e.resolve_dns = true;
        e.many_target = false;
        e.dot = 0;
        e.scan = 0;
        e.dim = 0;
        e.newargc = 0;
        e.nb_thread = 0;
        e.hostname = NULL;
        e.multiple_ip = NULL;
        e.to = NULL;
        ft_memset(&e.tv, 0, sizeof(e.tv));
        ft_memset(e.ip, 0, ft_strlen(e.ip));
        ft_memset(e.my_ip, 0, ft_strlen(e.my_ip));
        ft_memset(e.my_mask, 0, ft_strlen(e.my_mask));
        ft_memset(e.ports, 0, sizeof(e.ports));
}

void environment_cleanup(void)
{
        e.resolve_dns = false;
        e.many_target = false;
        e.dot = 0;
        e.scan = 0;
        e.newargc = 0;
        e.nb_thread = 0;
        e.hostname = NULL;
        e.to = NULL;
        ft_memset(&e.tv, 0, sizeof(e.tv));
        ft_memset(e.ip, 0, ft_strlen(e.ip));
        ft_memset(e.my_ip, 0, ft_strlen(e.my_ip));
        ft_memset(e.my_mask, 0, ft_strlen(e.my_mask));
        ft_memset(e.ports, 0, sizeof(e.ports));
        if (e.target) {
                if (e.dim) {
                        for (int i = 0; i < e.dim; i++) {
                                if (e.target[i].hname)
                                        free(e.target[i].hname);
                                if (e.target[i].rdns)
                                        free(e.target[i].rdns);
                                if (e.target[i].to)
                                        free(e.target[i].to);
                        }
                        free(e.target);
                } else {
                        if (e.target->hname)
                                free(e.target->hname);
                        if (e.target->rdns)
                                free(e.target->rdns);
                        if (e.target->to)
                                free(e.target->to);
                        free(e.target);
                }
        }
        if (e.multiple_ip && e.dim) {
                for (int i = 0; i < e.dim; i++)
                        free(e.multiple_ip[i]);
                free(e.multiple_ip);
                e.multiple_ip = NULL;
                e.dim = 0;
        }
}

int set_and_resolve_hosts(void)
{
        if (e.many_target) {
                e.target = ft_memalloc(sizeof(*e.target) * e.dim);
                for (int i = 0; i < e.dim; i++) {
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
