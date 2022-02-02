/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   scan.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: aabelque <aabelque@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/01/05 16:05:05 by aabelque          #+#    #+#             */
/*   Updated: 2022/02/02 18:05:05 by zizou            ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

extern t_env e;

/**
 * no_packet -  checks the type of scan received and
 *              calls the appropriate <type>_decocde function
 * @data: struct t_pkt_data that contain data info
 * @return 0
 */
static void no_packet(t_pkt_data *data)
{
        uint8_t type  = 0, i = 0, start = 1, end = 64;
        void (*func[6])(t_pkt_data *, uint8_t, uint8_t, bool) = {&syn_decode, &null_decode,
                &ack_decode, &fin_decode, &xmas_decode, &udp_decode};

        for_eachtype(i, type, start, end) {
                if (data->type == type)
                        func[i](data, -1, 0, is_node_exist(data->tgt->report, data->port));
        }
}

/**
 * callback - function call by pcap_dispatch() - gets packet and checks ip protocol
 * @arg: struct t_pkt_data passed to the fourth argument of pcap_dispatch()
 * @hdr: struct pcap_pkthdr 
 * @data: data captured by pcap_dispatch()
 */
static void callback(u_char *arg, const struct pcap_pkthdr *hdr, const u_char *data)
{
        int8_t hlen = 0;
        t_pkt_data *pkt_data;
        struct ip *ip;
        struct tcphdr *tcp;
        struct udphdr *udp;

        /* pthread_mutex_lock(&e.mutex); */
        printf("In callback()\n");
        pkt_data = (t_pkt_data *)arg;
        data += OFFSET;
        ip = (struct ip *)data;
        hlen = ip->ip_hl << 2;
        switch (ip->ip_p) {
        case IPPROTO_TCP:
                printf("tcp\n");
                tcp = (struct tcphdr *)(data + hlen);
                get_tcp_response(tcp, pkt_data);
                break;
        case IPPROTO_UDP:
                printf("udp\n");
                udp = (struct udphdr *)(data + hlen);
                get_udp_response(udp, pkt_data);
                break;
        case IPPROTO_ICMP:
                printf("icmp\n");
                get_icmp_response(data, pkt_data);
                break;
        default:
                fprintf(stderr, "Protocol not supported: %u\n", ip->ip_p);
                break;
        }
        /* pthread_mutex_unlock(&e.mutex); */
}

void thread_breakloop(__attribute__((unused))int sig)
{
        printf("In thread_breakloop()\n");
        pcap_breakloop(*e.handle);
        alarm(1);
}

/**
 * scan - process nmap scan: setup packet and pcap filter, send packet to the target and wait for incomming packet with callback function
 * @tgt: struct t_target that contain target(s) info
 * @type: type of scan
 * @port: port to scan
 * @return 0 on success or 1 on failure
 */
static int8_t scan(t_target *tgt, uint8_t type, uint16_t port)
{
        int8_t cc = 0, cnt = 0;
        int64_t wait = 500;
        int64_t time = 0.0;
        char errbuf[ERRBUF];
        struct timeval t1, t2;
        struct pollfd fd;
        t_pkt_data data;
        pcap_t *handle;
        
        /* pthread_mutex_lock(&e.mutex); */
        /* wait *= e.nb_thread; */
        /* fflush(stdout); */
        data = (t_pkt_data){type, port, tgt};
        if (capture_setup(&handle, tgt, port, type))
                goto return_failure;
        if (send_packet(tgt, port, type))
                goto return_failure;
        e.handle = &handle;
        int f = pcap_get_selectable_fd(handle); /* in capture_setup() */
        fd = (struct pollfd){ f, POLLIN, 0 };
        cnt = ft_strcmp(tgt->ip, "127.0.0.1") ? 1 : 2;
        pcap_setnonblock(handle, 1, errbuf); /* in capture_setup() */
        gettimeofday(&t1, NULL);
        /* struct sigaction sig_alarm; */
        /* ft_memset(&sig_alarm, 0, sizeof(sig_alarm)); */
        /* sigemptyset(&sig_alarm.sa_mask); */
        /* sig_alarm.sa_flags = SA_SIGINFO; */
        /* sig_alarm.sa_handler = &thread_breakloop; */
        /* sigaction(SIGALRM, &sig_alarm, NULL); */
        /* pcap_breakloop(handle); */
        /* signal(SIGALRM, thread_breakloop); */
        /* sleep(2); */
        int8_t i = 0;
        do {
                /* printf("time = %ld\n", time); */
                /* printf(" k"); */
                if (poll(&fd, 1, wait)) {
                        if (fd.revents != 0 && fd.revents & POLLIN) {
                                if (fd.fd == f) {
                                        /* printf("Before pcap_dispatch()\n"); */
                                        cc = pcap_dispatch(handle, cnt, callback, (u_char *)&data);
                                        /* printf("After pcap_dispatch()\n"); */
                                }
                        }
                }
                i++;
                gettimeofday(&t2, NULL);
                time += gettimeval(t1, t2);
        } while (time < wait && cc == 0 && i < 6);
        /* printf("cc = %d\n", cc); */
        if (cc == -1)
                goto return_failure;
        if (cc == 0 || cc == -2)
                no_packet(&data);
        free(tgt->src);
        pcap_close(handle);
        /* pthread_mutex_unlock(&e.mutex); */
        return EXIT_SUCCESS;

return_failure:
        free(tgt->src);
        pcap_close(handle);
        close(tgt->socket);
        /* pthread_mutex_unlock(&e.mutex); */
        return EXIT_FAILURE;
}

/**
 * process_scan - for each port lunch scan with the appropriate type of scan
 * @target: struct t_target that contain target(s) info
 * @return 0 for success or 1 for failure
 */
int8_t process_scan(t_target *target, uint16_t *ports)
{
        uint8_t end_type = 64;
        /* struct timeval start, end; */

        /* if (gettimeofday(&start, NULL)) */
        /*         return EXIT_FAILURE; */
        for (int16_t i = 0; ports[i]; i++) {
                for (int8_t type = 1; type < end_type; type <<= 1) {
                       if (target->scan & type)
                               if (scan(target, type, ports[i]))
                                       return EXIT_FAILURE;
                }
        }
        /* if (gettimeofday(&end, NULL)) */
                /* return EXIT_FAILURE; */
        /* calculate_scan_time(start, end); */
        return EXIT_SUCCESS;
}
