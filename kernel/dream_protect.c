#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/hashtable.h>
#include <linux/dream_protect.h>
#include <linux/sched.h>

/* 全局实例 */
struct dream_protected_process_t dream_protected_process;

/*
 * 受限的IPC系统调用表
 * 这些是根据提供的x86_64系统调用表的准确系统调用号
 */
static const unsigned long restricted_ipc_syscalls[] = {
	/* Unix域套接字 */
	41, /* socket */
	42, /* connect */
	49, /* bind */
	50, /* listen */
	43, /* accept */
	288, /* accept4 */

	/* 套接字通信 */
	44, /* sendto */
	45, /* recvfrom */
	46, /* sendmsg */
	47, /* recvmsg */
	48, /* shutdown */
	51, /* getsockname */
	52, /* getpeername */
	53, /* socketpair */
	54, /* setsockopt */
	55, /* getsockopt */

	/* 共享内存 */
	29, /* shmget */
	30, /* shmat */
	31, /* shmctl */
	67, /* shmdt */

	/* 消息队列(System V) */
	68, /* msgget */
	69, /* msgsnd */
	70, /* msgrcv */
	71, /* msgctl */

	/* 消息队列(POSIX) */
	240, /* mq_open */
	241, /* mq_unlink */
	242, /* mq_timedsend */
	243, /* mq_timedreceive */
	244, /* mq_notify */
	245, /* mq_getsetattr */

	/* 信号量(System V) */
	64, /* semget */
	65, /* semop */
	66, /* semctl */
	220, /* semtimedop */

	/* 管道 */
	22, /* pipe */
	293, /* pipe2 */

	/* 进程间信号 */
	62, /* kill */
	200, /* tkill */
	234, /* tgkill */
	129, /* rt_sigqueueinfo */
	297, /* rt_tgsigqueueinfo */

	/* 其他IPC相关 */
	9, /* mmap - 可用于共享内存 */
	72, /* fcntl - 可用于文件锁 */
	73, /* flock */

	/* 事件通知机制 */
	290, /* eventfd2 */
	289, /* signalfd4 */
	283, /* timerfd_create */
	286, /* timerfd_settime */
	287, /* timerfd_gettime */

	/* 新增：安全通道系统调用 - 这些将作为例外允许 */
	463, /* dream_channel_create */
	464, /* dream_channel_connect */
	465, /* dream_channel_send */
	466, /* dream_channel_recv */
	467, /* dream_channel_control */
	468, /* dream_channel_close */

	0 /* 结束标记 */
};

/**
 * is_ipc_syscall - 检查系统调用是否是IPC相关的系统调用
 * @nr: 系统调用号
 *
 * 返回值: 如果是IPC系统调用返回true，否则返回false
 */
static bool is_ipc_syscall(unsigned long nr)
{
	int i = 0;

	/* 特殊处理：允许安全通道相关系统调用 */
	if (nr >= 463 && nr <= 468) {
		return false; /* Dream安全通道系统调用是例外，允许使用 */
	}

	while (restricted_ipc_syscalls[i] != 0) {
		if (nr == restricted_ipc_syscalls[i])
			return true;
		i++;
	}

	return false;
}

/**
 * dream_check_ipc_syscall - 检查IPC系统调用是否应该被限制
 * @task: 发起系统调用的进程
 * @syscall_nr: 系统调用号
 *
 * 返回值: 如果应该限制返回true，否则返回false
 */
static bool dream_check_ipc_syscall(struct task_struct *task, int syscall_nr)
{
	pid_t pid = task_pid_nr(task);

	/* 如果这是安全通道相关系统调用，直接允许 */
	if (syscall_nr >= 463 && syscall_nr <= 468) {
		return false;
	}

	/* 检查进程是否受保护且设置了禁止IPC标志 */
	if (is_process_protected(pid) &&
	    has_process_flag(pid, DREAM_FLAG_FORBIDDEN_IPC_SYSCALL) &&
	    is_ipc_syscall(syscall_nr)) {
		pr_debug(
			"DREAM: Blocking IPC syscall %d from protected process %d\n",
			syscall_nr, pid);
		return true;
	}

	return false;
}

/**
 * dream_syscall_intercept - 在do_syscall_64中使用的系统调用拦截函数
 * @regs: 寄存器状态
 * @nr: 系统调用号
 *
 * 返回值: 如果系统调用被拦截返回true，否则返回false
 */
bool dream_syscall_intercept(struct pt_regs *regs, int nr)
{
	/* 仅检查IPC限制，其他限制由其他函数处理 */
	return dream_check_ipc_syscall(current, nr);
}
EXPORT_SYMBOL(dream_syscall_intercept);

/* 检查进程是否受保护 */
bool is_process_protected(pid_t pid) {
  struct dream_protected_process_t *process;
  bool protected = false;
  
  spin_lock(&dream_protected_process.lock);
  
  list_for_each_entry(process, &dream_protected_process.list, list) {
    if (process->pid == pid) {
      protected = true;
      break;
    }
  }
  
  spin_unlock(&dream_protected_process.lock);
  
  return protected;
}
EXPORT_SYMBOL(is_process_protected);

/* 检查进程是否具有特定标志 */
bool has_process_flag(pid_t pid, unsigned int flag) {
  struct dream_protected_process_t *process;
  bool has_flag = false;
  
  spin_lock(&dream_protected_process.lock);
  
  list_for_each_entry(process, &dream_protected_process.list, list) {
    if (process->pid == pid) {
      has_flag = (process->flags & flag) ? true : false;
      break;
    }
  }
  
  spin_unlock(&dream_protected_process.lock);
  
  return has_flag;
}
EXPORT_SYMBOL(has_process_flag);

/* 获取进程的所有标志 */
int get_process_flags(pid_t pid, unsigned int *flags) {
  struct dream_protected_process_t *process;
  int ret = -ENOENT; // 默认返回"不存在"错误
  
  if (!flags)
    return -EINVAL; // 无效参数
  
  spin_lock(&dream_protected_process.lock);
  
  list_for_each_entry(process, &dream_protected_process.list, list) {
    if (process->pid == pid) {
      *flags = process->flags;
      ret = 0; // 成功
      break;
    }
  }
  
  spin_unlock(&dream_protected_process.lock);
  
  return ret;
}
EXPORT_SYMBOL(get_process_flags);

/* 检查进程是否具有所有指定标志 */
bool has_all_process_flags(pid_t pid, unsigned int flags) {
  unsigned int process_flags;
  int ret;
  
  ret = get_process_flags(pid, &process_flags);
  if (ret != 0)
    return false;
    
  return ((process_flags & flags) == flags);
}
EXPORT_SYMBOL(has_all_process_flags);

/* 检查进程是否具有任一指定标志 */
bool has_any_process_flags(pid_t pid, unsigned int flags) {
  unsigned int process_flags;
  int ret;
  
  ret = get_process_flags(pid, &process_flags);
  if (ret != 0)
    return false;
    
  return ((process_flags & flags) != 0);
}
EXPORT_SYMBOL(has_any_process_flags);

static int __init init_shared_data(void)
{
    INIT_LIST_HEAD(&dream_protected_process.list);
    spin_lock_init(&dream_protected_process.lock);
    return 0;
}

early_initcall(init_shared_data);
EXPORT_SYMBOL(dream_protected_process);
