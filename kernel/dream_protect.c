#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/hashtable.h>
#include <linux/dream_protect.h>

/* 保护进程的哈希表 */
static DEFINE_HASHTABLE(protected_procs, 8); // 2^8 = 256 个桶
static DEFINE_SPINLOCK(protected_procs_lock);

/* 保护进程的条目结构 */
struct proc_entry {
	pid_t pid;
	struct hlist_node node;
};

/* 检查进程是否被保护 */
bool is_protected_proc(pid_t pid)
{
	struct proc_entry *entry;
	bool found = false;

	spin_lock(&protected_procs_lock);
	hash_for_each_possible(protected_procs, entry, node, pid) {
		if (entry->pid == pid) {
			found = true;
			break;
		}
	}
	spin_unlock(&protected_procs_lock);

	return found;
}
EXPORT_SYMBOL(is_protected_proc);

/* 添加保护进程 */
int add_protected_proc(pid_t pid)
{
	struct proc_entry *entry;
	int ret = 0;

	spin_lock(&protected_procs_lock);

	/* 检查是否已经存在 */
	hash_for_each_possible(protected_procs, entry, node, pid) {
		if (entry->pid == pid) {
			ret = -EEXIST;
			goto out_unlock;
		}
	}

	/* 分配新条目 */
	entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
	if (!entry) {
		ret = -ENOMEM;
		goto out_unlock;
	}

	/* 初始化并添加条目 */
	entry->pid = pid;
	hash_add(protected_procs, &entry->node, pid);

	printk(KERN_INFO "TEE: 进程 %s (PID=%d) 添加进程 %d 到保护列表\n",
	       current->comm, task_pid_nr(current), pid);

out_unlock:
	spin_unlock(&protected_procs_lock);
	return ret;
}
EXPORT_SYMBOL(add_protected_proc);

/* 移除保护进程 */
int remove_protected_proc(pid_t pid)
{
	struct proc_entry *entry;
	int ret = -ENOENT;

	spin_lock(&protected_procs_lock);

	hash_for_each_possible(protected_procs, entry, node, pid) {
		if (entry->pid == pid) {
			hash_del(&entry->node);
			kfree(entry);
			printk(KERN_INFO
			       "TEE: 进程 %s (PID=%d) 从保护列表中移除进程 %d\n",
			       current->comm, task_pid_nr(current), pid);
			ret = 0;
			break;
		}
	}

	spin_unlock(&protected_procs_lock);
	return ret;
}
EXPORT_SYMBOL(remove_protected_proc);
