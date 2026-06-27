#include "ft_nmap.h"

void *worker(void *arg)
{
    t_thread    *th;
    t_task      *task;
    uint8_t     buf[4096];
    int         len;
    int         result;
    pcap_t      *handle;

    th = (t_thread *)arg;
    while (1)
    {
        task = pop_task(th);
        if (!task)
            break ;
        memset(buf, 0, sizeof(buf));

        // 1. Ouvrir pcap AVANT d'envoyer
        handle = open_capture(task->dst_ip, task->dst_port, task->scan_type);

        if (g_opts.ids_evasion)
            usleep(rand() % 100000); // 0-100ms aléatoire
        // 2. Construire et envoyer le paquet
        if (task->scan_type == SCAN_UDP)
        {
            len = build_udp_packet(buf, g_opts.local_ip.s_addr,
                                   task->dst_ip, 12345, task->dst_port);
            send_packet(buf, len, task->dst_ip, RAW_PROTOCOL(IPPROTO_UDP));
        }
        else
        {
            len = build_tcp_packet(buf, g_opts.local_ip.s_addr,
                                   task->dst_ip, 12345, task->dst_port,
                                   scan_to_flags(task->scan_type));
            send_packet(buf, len, task->dst_ip, RAW_PROTOCOL(IPPROTO_TCP));
        }

        // 3. Attendre la réponse
        if (handle)
        {
            t_os_info   os_tmp;

            memset(&os_tmp, 0, sizeof(os_tmp));
            result = wait_capture(handle, task->dst_ip, task->dst_port,
                                task->scan_type, &os_tmp);
            if (os_tmp.has_data)
            {
                pthread_mutex_lock(&th->result.mutex);
                if (!th->result.os.has_data)
                    th->result.os = os_tmp;
                pthread_mutex_unlock(&th->result.mutex);
            }
        }
        else
            result = PORT_FILTERED;
        if (g_opts.verbose)
            printf("[%s:%d] %s → %s\n",
                inet_ntoa(*(struct in_addr *)&task->dst_ip),
                task->dst_port,
                scan_type_to_str(task->scan_type),
                result_to_str(result));
        set_result(th, task->dst_port, task->scan_type, result);
        free(task);
    }
    return (NULL);
}

int     thread_init(t_thread *th)
{
    memset(th, 0, sizeof(t_thread));
    if (pthread_mutex_init(&th->queue.mutex, NULL) != 0)
        return (-1);
    if (pthread_cond_init(&th->queue.cond, NULL) != 0)
        return (-1);
    if (pthread_mutex_init(&th->result.mutex, NULL) != 0)
        return (-1);
    th->n_threads = g_opts.speedup ? g_opts.speedup : 1;
    return (0);
}

void    thread_destroy(t_thread *th)
{
    pthread_mutex_destroy(&th->queue.mutex);
    pthread_cond_destroy(&th->queue.cond);
    pthread_mutex_destroy(&th->result.mutex);
}

static void shuffle_tasks(t_task **tasks, int count)
{
    int     i;
    int     j;
    t_task  *tmp;

    for (i = count - 1; i > 0; i--)
    {
        j        = rand() % (i + 1);
        tmp      = tasks[i];
        tasks[i] = tasks[j];
        tasks[j] = tmp;
    }
}

int     run_scan(t_thread *th, uint32_t dst_ip)
{
    int     i;
    int     s;
    int     count;
    t_task  *tasks[1024 * 6];
    t_task  *task;

    count = 0;

    // 1. Lancer les threads D'ABORD
    for (i = 0; i < th->n_threads; i++)
        pthread_create(&th->threads[i], NULL, worker, th);

    // 2. Construire toutes les taches
    for (i = 0; i < g_opts.port_count; i++)
    {
        for (s = 0; s < 6; s++)
        {
            if (!(g_opts.scans & (1 << s)))
                continue ;
            task = new_task(dst_ip, g_opts.ports[i], (1 << s));
            if (!task)
                return (-1);
            tasks[count++] = task;
        }
    }

    // 3. Shuffler si --ids-evasion
    if (g_opts.ids_evasion)
        shuffle_tasks(tasks, count);

    // 4. Pousser dans la queue
    for (i = 0; i < count; i++)
        push_task(th, tasks[i]);

    // 5. Signaler fin de queue
    pthread_mutex_lock(&th->queue.mutex);
    th->queue.done = 1;
    pthread_cond_broadcast(&th->queue.cond);
    pthread_mutex_unlock(&th->queue.mutex);

    // 6. Attendre tous les threads
    for (i = 0; i < th->n_threads; i++)
        pthread_join(th->threads[i], NULL);

    return (0);
}