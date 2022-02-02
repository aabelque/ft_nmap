/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   thread.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: aabelque <aabelque@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/01/27 14:14:24 by aabelque          #+#    #+#             */
/*   Updated: 2022/02/02 17:54:01 by zizou            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static void copy_result(t_result **final, t_result *tmp)
{
        int8_t first;

        while (tmp) {
                first = 1;
                while (tmp->scan) {
                        if (first)
                                add_node(final, new_node(tmp->scan->state, \
                                                        tmp->scan->type, tmp->port, tmp->service));
                        else
                                update_node(*final, tmp->scan->type, tmp->scan->state, tmp->port);
                        first = 0;
                        tmp->scan = tmp->scan->next;
                }
                tmp = tmp->next;
        }
}

static int8_t join_thread(pthread_t id, t_result **r)
{
        if (pthread_join(id, (void**)&e.target->report))
                return EXIT_FAILURE;
        copy_result(r, e.target->report);
        return EXIT_SUCCESS;
}

static int8_t send_thread(pthread_t *id, t_target *tgt)
{
        if (pthread_create(id, NULL, nmap_scan, tgt)) {
                return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
}

static t_target *set_ports(t_target *tgt, t_ports_per_thread p)
{
        uint16_t i;

        ft_memset(tgt->ports, 0, sizeof(tgt->ports));
        for (i = 0; i < p.ports_per_thread ; i++) {
                 tgt->ports[i] = *e.ports;
                 (*e.ports)++;
        }
        if (p.remaining_ports) {
                tgt->ports[i + 1] = (*e.ports)++;
                p.remaining_ports--;
        }
        return tgt;
}

static int8_t dispatch_thread(t_ports_per_thread p, t_result **r)
{
        uint8_t thread;
        t_target t[e.nb_thread];

        e.thr_id = ft_memalloc(sizeof(pthread_t) * e.nb_thread);
        if (e.thr_id == NULL)
                return EXIT_FAILURE;
        for (thread = 0; thread < e.nb_thread; thread++) {
                ft_memcpy(&t[thread], e.target, sizeof(*e.target));
                if (send_thread(&e.thr_id[thread], set_ports(&t[thread], p)))
                        return EXIT_FAILURE;
                if (p.remaining_ports)
                        p.remaining_ports--;
        }
        for (thread = 0; thread < e.nb_thread; thread++) {
                if (join_thread(e.thr_id[thread], r))
                        return EXIT_FAILURE;
        }
        free(e.thr_id);
        return EXIT_SUCCESS;
}

static t_ports_per_thread define_port_per_thread(void)
{
        uint16_t nb_ports = 0;
        t_ports_per_thread p = {0, 0};

        nb_ports = number_of_ports();
        if (e.nb_thread > nb_ports) { /* nb thread > nb ports */
                e.nb_thread = nb_ports;
                p.ports_per_thread = 1;
                printf("e.nb_thread = %d\n", e.nb_thread);
                /*! TODO: define number of thread */
                /* printf("thread > ports\n"); */
        } else {
                p.ports_per_thread = nb_ports / e.nb_thread;
                p.remaining_ports = nb_ports % e.nb_thread;
        }
        return p;
}

int8_t create_thread(__attribute__((unused))void *ports)
{
        t_ports_per_thread p;
        t_result *r = NULL;

        p = define_port_per_thread();
        if (dispatch_thread(p, &r))
                return EXIT_FAILURE;
        print_result(r);
        return EXIT_SUCCESS;
}
