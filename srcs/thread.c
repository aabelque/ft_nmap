/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   thread.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: aabelque <aabelque@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/01/27 14:14:24 by aabelque          #+#    #+#             */
/*   Updated: 2022/01/28 17:17:03 by zizou            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

static int8_t join_thread(pthread_t id)
{
        if (pthread_join(id, NULL))
                return EXIT_FAILURE;
        return EXIT_SUCCESS;
}

static int8_t send_thread(pthread_t id, uint16_t *ports)
{
        if (pthread_create(&id, NULL, nmap_scan, ports))
                return EXIT_FAILURE;
        return EXIT_SUCCESS;
}

static uint16_t *set_ports(uint16_t *ports, t_ports_per_thread p)
{
        uint16_t i;

        ft_memset(ports, 0, sizeof(ports));
        for (i = 0; i < p.ports_per_thread ; i++) {
                 ports[i] = *e.ports;
                (*e.ports)++;
        }
        return ports;
}

static int8_t dispatch_thread(t_ports_per_thread p)
{
        uint8_t thread;
        uint16_t ports[p.ports_per_thread + 1];
        pthread_t id[e.nb_thread];

        ft_memset(ports, 0, sizeof(ports));
        e.thr_id = ft_memalloc(sizeof(pthread_t) * e.nb_thread);
        if (e.thr_id == NULL)
                return EXIT_FAILURE;
        for (thread = 0; thread < e.nb_thread; thread++) {
                if (send_thread(e.thr_id[thread], set_ports(ports, p)))
                        return EXIT_FAILURE;
        }
        for (thread = 0; thread < e.nb_thread; thread++) {
                if (join_thread(e.thr_id[thread]))
                        return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
}

static t_ports_per_thread define_port_per_thread(void)
{
        uint16_t nb_ports = 0;
        t_ports_per_thread p = {0, 0};

        nb_ports = number_of_ports();
        if (e.nb_thread > nb_ports)
                /*! TODO: define number of thread */
                printf("thread > ports\n");
        else {
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
