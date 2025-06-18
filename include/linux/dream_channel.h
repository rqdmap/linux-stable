#ifndef _LINUX_DRAEM_CHANNEL_H
#define _LINUX_DRAEM_CHANNEL_H

#include <linux/cred.h> /* 用于进程凭证检查 */
#include <linux/pid.h> /* 进程ID处理 */

/* 定义函数指针类型，供模块注册回调 */
typedef int (*dream_create_fn_t)(const char *name, uint32_t flags);
typedef int (*dream_connect_fn_t)(const char *name, uint32_t flags);
typedef int (*dream_send_fn_t)(int channel_fd, const void *buf, size_t len);
typedef int (*dream_recv_fn_t)(int channel_fd, void *buf, size_t len);
typedef int (*dream_control_fn_t)(int channel_fd, uint32_t flags, void *arg);
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

#define DREAM_CHANNEL_FLAG_RESTRICTED 0x00000100 /* 启用访问控制 */

/* 添加访问控制命令 */
#define DREAM_CHANNEL_CMD_ADD_ALLOWED 1 /* 添加允许的进程 */
#define DREAM_CHANNEL_CMD_REMOVE_ALLOWED 2 /* 移除允许的进程 */
#define DREAM_CHANNEL_CMD_CLEAR_ALLOWED 3 /* 清除允许列表 */
#define DREAM_CHANNEL_CMD_SET_RESTRICTED 4 /* 设置访问限制状态 */

/* 添加系统调用控制数据结构 */
struct dream_channel_allowed {
	pid_t pid; /* 允许访问的进程ID */
	uid_t uid; /* 允许访问的用户ID */
	gid_t gid; /* 允许访问的组ID */
};

#endif /* _LINUX_DRAEM_CHANNEL_H */
