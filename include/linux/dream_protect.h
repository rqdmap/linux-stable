#ifndef _LINUX_TEE_PROTECT_H
#define _LINUX_TEE_PROTECT_H

#include <linux/types.h>
#include <linux/pid.h>
#include <linux/list.h>
#include <linux/spinlock.h>

/* 操作码定义 */
#define TEE_ADD_PROTECTED_PROC 1
#define TEE_REMOVE_PROTECTED_PROC 2

/* 函数声明 */
bool is_process_protected(pid_t pid);
bool has_process_flag(pid_t pid, unsigned int flag);
int get_process_flags(pid_t pid, unsigned int *flags);
bool has_all_process_flags(pid_t pid, unsigned int flags);
bool has_any_process_flags(pid_t pid, unsigned int flags);

/* 保护标志枚举 */
enum dream_protection_flags {
	DREAM_FLAG_NONE = 0,				/* 无特殊标志 */
	DREAM_FLAG_HIDDEN = (1 << 0),			/* 隐藏进程 */
	DREAM_FLAG_PROTECT_EXTERN_SYSCALL = (1 << 1),	/* 保护进程隔离, 阻断外部进程访问 */
	DREAM_FLAG_FORBIDDEN_IPC_SYSCALL = (1 << 2),	/* 受保护进程禁止部分系统调用 */
	DREAM_FLAG_MEMORY_INTEGRITY = (1 << 3),		/* 开启内存代码段完整性检验 */
	DREAM_FLAG_LOADING_INTEGRITY = (1 << 4),	/* 开启文件载入时完整性检验 */
	DREAM_FLAG_ALL = 0xFF				/* 所有标志 */
};

/* 共享数据内容 */
struct dream_protected_process_t {
	struct list_head list;
	spinlock_t lock;
	pid_t pid;
	unsigned int flags;
};

extern struct dream_protected_process_t dream_protected_process;

#endif /* _LINUX_TEE_PROTECT_H */
