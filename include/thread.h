#ifndef THREAD_H
# define THREAD_H
# include <pthread.h>

typedef struct s_task {
    uint32_t        dst_ip;
    uint16_t        dst_port;
    int             scan_type;
    struct s_task   *next;
} t_task;

typedef struct s_queue {
    t_task          *head;
    t_task          *tail;
    pthread_mutex_t mutex;
    pthread_cond_t  cond;
    int             done;
} t_queue;

typedef struct s_os_info {
    uint8_t     ttl;
    uint16_t    window;
    int         has_data;
} t_os_info;

typedef struct s_result {
    int             results[UINT16_MAX][6];
    t_os_info       os;
    pthread_mutex_t mutex;
} t_result;

typedef struct s_thread {
    t_queue     queue;
    t_result    result;
    int         n_threads;
    pthread_t   threads[250];
} t_thread;

void    *worker(void *arg);
t_task  *new_task(uint32_t dst_ip, uint16_t dst_port, int scan_type);
void    push_task(t_thread *th, t_task *task);
t_task  *pop_task(t_thread *th);
int     thread_init(t_thread *th);
void    thread_destroy(t_thread *th);
int     run_scan(t_thread *th, uint32_t dst_ip);

#endif
