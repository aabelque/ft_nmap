/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   thread.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: aabelque <aabelque@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/01/27 14:14:24 by aabelque          #+#    #+#             */
/*   Updated: 2022/02/06 22:26:03 by aabelque         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static void copy_result(t_result **final, t_result *tmp)
{
        int8_t first;
        t_result *t = tmp;
        t_scan *q;

        while (t) {
                first = 1;
                q = t->scan;
                while (q) {
                        if (first)
                                add_node(final, new_node(q->state, \
                                                        q->type, t->port, get_service(t->port, NULL)));
                        else
                                update_node(*final, q->type, q->state, t->port);
                        first = 0;
                        q = q->next;
                }
                t = t->next;
        }
}

static int8_t join_thread(pthread_t id, t_result **r, t_target t)
{
        t_result *tmp = NULL;

        if (pthread_join(id, (void**)&tmp))
                return EXIT_FAILURE;
        if (tmp == NULL) {
		if (e.target->src)
			free(e.target->src);
		free_list(e.target->report);
	}
        copy_result(r, tmp);
        free_list(tmp);
        return EXIT_SUCCESS;
}

static int8_t send_thread(pthread_t *id, t_target *tgt)
{
        if (pthread_create(id, NULL, nmap_scan, tgt)) {
                return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
}

static t_target *set_ports(t_target *tgt, t_ports_per_thread p, uint16_t *prt)
{
        uint16_t i;

        ft_memset(tgt->ports, 0, sizeof(tgt->ports));
        for (i = 0; i < p.ports_per_thread ; i++) {
                 tgt->ports[i] = *prt;
                 (*prt)++;
        }
        if (p.remaining_ports) {
                tgt->ports[i++] = (*prt)++;
                p.remaining_ports--;
        }
        return tgt;
}

static int8_t dispatch_thread(t_ports_per_thread p, t_result **r)
{
        uint8_t thread;
        uint16_t prt[1025];
        t_target t[e.nb_thread];

        ft_memset(prt, 0, sizeof(e.ports));
        ft_memcpy(prt, e.ports, sizeof(e.ports));
        if ((e.thr_id = ft_memalloc(sizeof(pthread_t) * e.nb_thread)) == NULL)
                return EXIT_FAILURE;
        for (thread = 0; thread < e.nb_thread; thread++) {
                ft_memcpy(&t[thread], e.target, sizeof(*e.target));
                if (send_thread(&e.thr_id[thread], set_ports(&t[thread], p, prt)))
                        goto return_failure;
                if (p.remaining_ports)
                        p.remaining_ports--;
        }
        for (thread = 0; thread < e.nb_thread; thread++) {
                if (join_thread(e.thr_id[thread], r, t[thread]))
                        goto return_failure;
        }
        free(e.thr_id);
        return EXIT_SUCCESS;

return_failure:
        free(e.thr_id);
        return EXIT_FAILURE;
}

static t_ports_per_thread define_port_per_thread(void)
{
        uint16_t nb_ports = 0;
        t_ports_per_thread p = {0, 0};

        nb_ports = number_of_ports();
        if (e.nb_thread > nb_ports) {
                e.nb_thread = nb_ports;
                p.ports_per_thread = 1;
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

        if (!e.nb_thread)
                e.nb_thread = 1;
        p = define_port_per_thread();
        if (dispatch_thread(p, &r))
                return EXIT_FAILURE;
        print_result(r);
        free_list(r);
        return EXIT_SUCCESS;
}
