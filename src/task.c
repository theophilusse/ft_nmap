#include "ft_nmap.h"

t_task  *new_task(uint32_t dst_ip, uint16_t dst_port, int scan_type)
{
    t_task  *task;

    task = malloc(sizeof(t_task));
    if (!task)
        return (NULL);
    task->dst_ip    = dst_ip;
    task->dst_port  = dst_port;
    task->scan_type = scan_type;
    task->next      = NULL;
    return (task);
}

void    push_task(t_thread *th, t_task *task)
{
    pthread_mutex_lock(&th->queue.mutex);
    if (!th->queue.head)
    {
        th->queue.head = task;
        th->queue.tail = task;
    }
    else
    {
        th->queue.tail->next = task;
        th->queue.tail       = task;
    }
    pthread_cond_signal(&th->queue.cond);
    pthread_mutex_unlock(&th->queue.mutex);
}

t_task  *pop_task(t_thread *th)
{
    t_task  *task;

    pthread_mutex_lock(&th->queue.mutex);
    while (!th->queue.head && !th->queue.done)
        pthread_cond_wait(&th->queue.cond, &th->queue.mutex);
    if (!th->queue.head && th->queue.done)
    {
        pthread_mutex_unlock(&th->queue.mutex);
        return (NULL);
    }
    task             = th->queue.head;
    th->queue.head   = th->queue.head->next;
    if (!th->queue.head)
        th->queue.tail = NULL;
    pthread_mutex_unlock(&th->queue.mutex);
    return (task);
}
