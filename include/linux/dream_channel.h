#ifndef _LINUX_DRAEM_CHANNEL_H
#define _LINUX_DRAEM_CHANNEL_H

/* 定义函数指针类型，供模块注册回调 */
typedef int (*dream_create_fn_t)(const char *name, uint32_t flags);
typedef int (*dream_connect_fn_t)(const char *name, uint32_t flags);
typedef int (*dream_send_fn_t)(int channel_fd, const void *buf, size_t len);
typedef int (*dream_recv_fn_t)(int channel_fd, void *buf, size_t len);
typedef int (*dream_control_fn_t)(int channel_fd, uint32_t flags);
typedef int (*dream_close_fn_t)(int channel_fd);

/* 函数声明 */
int register_dream_channel_create(dream_create_fn_t fn);
int register_dream_channel_connect(dream_connect_fn_t fn);
int register_dream_channel_send(dream_send_fn_t fn);
int register_dream_channel_recv(dream_recv_fn_t fn);
int register_dream_channel_control(dream_control_fn_t fn);
int register_dream_channel_close(dream_close_fn_t fn);

void unregister_dream_channel_create(void);
void unregister_dream_channel_connect(void);
void unregister_dream_channel_send(void);
void unregister_dream_channel_recv(void);
void unregister_dream_channel_control(void);
void unregister_dream_channel_close(void);

#endif /* _LINUX_DRAEM_CHANNEL_H */
