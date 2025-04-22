/* 
 *  * mprotect_observer.h - 内核中的观察者接口定义
 *   */
#ifndef _LINUX_MPROTECT_OBSERVER_H
#define _LINUX_MPROTECT_OBSERVER_H

#include <linux/list.h>
#include <linux/mm_types.h>

/* mprotect 观察者结构体 */
struct mprotect_observer {
	/* 在执行 mprotect 前调用 */
	void (*before_mprotect)(unsigned long start, size_t len,
				unsigned long old_prot, unsigned long new_prot,
				struct vm_area_struct *vma);

	/* 在执行 mprotect 后调用 */
	void (*after_mprotect)(unsigned long start, size_t len,
			       unsigned long old_prot, unsigned long new_prot,
			       struct vm_area_struct *vma, int result);

	struct list_head list;
};

/* 注册/注销函数声明 */
int register_mprotect_observer(struct mprotect_observer *observer);
void unregister_mprotect_observer(struct mprotect_observer *observer);

void notify_before_mprotect(unsigned long start, size_t len,
			    unsigned long old_prot, unsigned long new_prot,
			    struct vm_area_struct *vma);
void notify_after_mprotect(unsigned long start, size_t len,
			   unsigned long old_prot, unsigned long new_prot,
			   struct vm_area_struct *vma, int result);

#endif /* _LINUX_MPROTECT_OBSERVER_H */
