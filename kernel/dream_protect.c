#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/hashtable.h>
#include <linux/dream_protect.h>

/* 全局实例 */
struct dream_protected_process_t dream_protected_process;

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
