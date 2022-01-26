/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   result.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: aabelque <aabelque@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/01/14 15:16:02 by aabelque          #+#    #+#             */
/*   Updated: 2022/01/20 23:34:48 by zizou            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static t_scan *new_scan(uint8_t state, uint8_t type)
{
        t_scan *new = NULL;

        if ((new = ft_memalloc(sizeof(*new))) == NULL)
                return NULL;
        new->state = state;
        new->type = type;
        new->next = NULL;
        return new;
}

void add_scan(t_scan *scan, uint8_t type, uint8_t state)
{
        t_scan **tmp = &scan;

        while ((*tmp)->next) {
                *tmp = (*tmp)->next;
        }
        (*tmp)->next = new_scan(state, type);
}

void update_node(t_result *list, uint8_t type, uint8_t state, uint16_t port)
{
        t_result **tmp = &list;

        while (*tmp) {
                if (port == (*tmp)->port) {
                        add_scan((*tmp)->scan, type, state);
                        break;
                }
                *tmp = (*tmp)->next;
        }
}

bool is_node_exist(t_result *list, uint16_t port)
{
        t_result **tmp = &list;

        while (*tmp) {
                if (port == (*tmp)->port)
                        return true;
                *tmp = (*tmp)->next;
        }
        return false;
}

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
 * @type: type of scan
 * @port: port number
 * @service: service name in that port
 * @return the new node
 */
t_result *new_node(uint8_t state, uint8_t type, uint16_t port, char *service)
{
        t_result *new = NULL;

        if ((new = ft_memalloc(sizeof(*new))) == NULL)
                return NULL;
        new->port = port;
        new->service = service;
        if ((new->scan = new_scan(state, type)) == NULL)
                return NULL;
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
        t_scan *s;

        while (list) {
                tmp = list;
                list = list->next;
                if (tmp->service)
                        free(tmp->service);
                if (tmp->scan) {
                        while (tmp->scan) {
                                s = tmp->scan;
                                tmp->scan = tmp->scan->next;
                                free(s);
                        }
                }
                free(tmp);
        }
}
