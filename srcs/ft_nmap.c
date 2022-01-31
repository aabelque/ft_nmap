/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nmap.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: aabelque <aabelque@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/12/25 11:44:49 by aabelque          #+#    #+#             */
/*   Updated: 2022/01/31 14:47:41 by aabelque         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

/*! TODO: handle SIGINT signal with sigaction() */
/*! TODO: description function parser_helper.c and error.c */
/*! TODO: handle speedup opt with pthread */

extern t_env e;

/**
 * nmap_scan -  Check if there is many target
 *              and call process_scan() many time or one time
 *
 * @target      struct t_target that contain target(s)
 *
 */
void *nmap_scan(void *data)
{
        uint16_t i = -1;
        /* uint16_t *p = (uint16_t *)ports; */
        t_target *tgt = (t_target *)data;

        printf("pthread_self() = %ld\n", pthread_self());
        /* pthread_mutex_lock(&e.mutex); */
        /* fprintf(stdout, "tgt->ip = %s\n", tgt->ip); */
        /* for (int i = 0; tgt->ports[i]; i++) { */
        /*         fprintf(stdout, "tgt->ports[i] = %d\n", tgt->ports[i]); */
        /*         fflush(stdout); */
        /* } */
        /* pthread_mutex_unlock(&e.mutex); */
        /* signal_setup(); */ 
        /* pthread_mutex_lock(&e.mutex); */
        if (tgt->dim) {
                while (++i < tgt->dim) {
                        print_header(tgt[i].hname, tgt[i].ip, tgt[i].rdns);
                        if (process_scan(&tgt[i], tgt->ports))
                                return NULL;
                        print_result(tgt[i].report);
                        write(1, "\n", 1);
                }
        } else {
                /* print_header(tgt->hname, tgt->ip, tgt->rdns); */
                if (process_scan(tgt, tgt->ports))
                        return NULL;
        }
        /* pthread_mutex_unlock(&e.mutex); */
        /* usleep(10); */
        pthread_exit(NULL);
}

/**
 * ft_nmap - Lunch nmap scan and print result
 */
void ft_nmap(void)
{
        void *ports;

        /*! TODO: implement loop here instead of in nmap_scan() */
        /*! TODO: print header here */
        /*! TODO: lock and unlock mutex with shared variable */

        /* target = (void *)e.target; */
        print_header(e.target->hname, e.target->ip, e.target->rdns);
        if (!e.nb_thread)
                nmap_scan(e.ports);
        else
                if (create_thread(ports))
                        return ;
        /* print_result(e.target->report); */
        /*! TODO: print results here */
}

int main(int argc, char **argv)
{
        if (argc < 3)
                help_menu(EXIT_FAILURE);
        if (getuid() != 0)
                perror_and_exit("Ft_nmap requires root privileges.\nQUITTING!");
        environment_setup();
        if (parse_arg(argc, argv))
                help_menu(EXIT_FAILURE);
        gettimeofday(&e.tv, NULL);
        if (set_and_resolve_hosts())
                exit_errors(ERR_HOSTNAME, e.hostname);
        /* signal_setup(); */
        target_setup();
        print_first_line();
        ft_nmap();
        /* sleep(1); */
        print_result(e.target->report);
        print_last_line();
        environment_cleanup();
        return EXIT_SUCCESS;
}
