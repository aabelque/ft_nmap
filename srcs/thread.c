/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   thread.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: aabelque <aabelque@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/01/27 14:14:24 by aabelque          #+#    #+#             */
/*   Updated: 2022/01/31 14:47:58 by aabelque         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static int8_t join_thread(pthread_t id)
{
        printf("id = %ld\n", id);
        if (pthread_join(id, NULL))
                return EXIT_FAILURE;
        /* printf("report[0].port = %d\n", e.target->report[0].port); */
        /* print_result(e.target->report); */
        return EXIT_SUCCESS;
}

static int8_t send_thread(pthread_t *id, t_target **tgt)
{
        t_target *data = *tgt;
        if (pthread_create(id, NULL, nmap_scan, data)) {
                return EXIT_FAILURE;
        }
        /* printf("*id = %ld\n", *id); */
        return EXIT_SUCCESS;
}

static t_target **set_ports(t_target **tgt, t_ports_per_thread p)
{
        uint16_t i;

        ft_memset((*tgt)->ports, 0, sizeof((*tgt)->ports));
        for (i = 0; i < p.ports_per_thread ; i++) {
                 (*tgt)->ports[i] = *e.ports;
                (*e.ports)++;
                /* printf("ports[i] = %d\n", ports[i]); */
        }
        /* printf("###\n"); */
        return tgt;
}

static int8_t dispatch_thread(t_ports_per_thread p)
{
        uint8_t thread;
        /* uint16_t ports[p.ports_per_thread + 1]; */

        e.thr_id = ft_memalloc(sizeof(pthread_t) * e.nb_thread);
        if (e.thr_id == NULL)
                return EXIT_FAILURE;
        for (thread = 0; thread < e.nb_thread; thread++) {
                /* ft_memset(ports, 0, sizeof(ports)); */
                if (send_thread(&e.thr_id[thread], set_ports(&e.target, p)))
                        return EXIT_FAILURE;
                sleep(1);
                /* usleep(10); */
                /* fflush(stdout); */
        }
        for (thread = 0; thread < e.nb_thread; thread++) {
                if (join_thread(e.thr_id[thread]))
                        return EXIT_FAILURE;
        }
        free(e.thr_id);
        /* printf("Success\n"); */
        return EXIT_SUCCESS;
}

static t_ports_per_thread define_port_per_thread(void)
{
        uint16_t nb_ports = 0;
        t_ports_per_thread p = {0, 0};

        nb_ports = number_of_ports();
        if (e.nb_thread == nb_ports) { /* nb thread < nb ports */
                p.ports_per_thread = 1;
                p.remaining_ports = 0;
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

        p = define_port_per_thread();
        if (dispatch_thread(p))
                return EXIT_FAILURE;
        return EXIT_SUCCESS;
}
