#ifndef _LINUX_TEE_PROTECT_H
#define _LINUX_TEE_PROTECT_H

#include <linux/types.h>
#include <linux/pid.h>

/* 操作码定义 */
#define TEE_ADD_PROTECTED_PROC 1
#define TEE_REMOVE_PROTECTED_PROC 2

/* 函数声明 */
bool is_protected_proc(pid_t pid);
int add_protected_proc(pid_t pid);
int remove_protected_proc(pid_t pid);

#endif /* _LINUX_TEE_PROTECT_H */
