/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   result.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: aabelque <aabelque@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/01/14 15:16:02 by aabelque          #+#    #+#             */
/*   Updated: 2022/01/18 02:12:14 by aabelque         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

/**
 * find_lastnode - find the last node of the linked list
 * @list: linked list
 * @return the last node
 */
t_result *find_lastnode(t_result *list)
{
        t_result **tmp = &list;
        while ((*tmp)->next)
                *tmp = (*tmp)->next;
        return *tmp;
}

/**
 * new_node - create and initialize new node
 * @state: state of the port
 * @port: port number
 * @service: service name in that port
 * @return the new node
 */
t_result *new_node(int8_t state, uint16_t port, char *service)
{
        t_result *new = NULL;

        if ((new = ft_memalloc(sizeof(*new))) == NULL)
                return NULL;
        new->state = state;
        new->port = port;
        new->service = service;
        new->next = NULL;
        return new;
}

/**
 * add_node - add node at the end of the linked list
 * @list: addr of the linked list
 * @new_node: new node to add
 */
void add_node(t_result **list, t_result *new_node)
{
        t_result *last_node;

        if (*list == NULL) {
                *list = new_node;
        } else {
                last_node = find_lastnode(*list);
                last_node->next = new_node;
        }
}

/**
 * free_list - free the all linked list
 * @list: addr of the list to free
 */
void free_list(t_result *list)
{
        t_result *tmp;

        while (list) {
                tmp = list;
                list = list->next;
                if (tmp->service)
                        free(tmp->service);
                free(tmp);
        }
}
