/*
 * mprotect_observer.c - 观察者接口实现
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/mprotect_observer.h>

/* 观察者列表和保护锁 */
static LIST_HEAD(mprotect_observer_list);
static DEFINE_SPINLOCK(mprotect_observer_lock);

/**
 * register_mprotect_observer - 注册 mprotect 观察者
 * @observer: 要注册的观察者
 *
 * 返回值: 成功返回0，失败返回错误码
 */
int register_mprotect_observer(struct mprotect_observer *observer)
{
	if (!observer)
		return -EINVAL;

	spin_lock(&mprotect_observer_lock);
	list_add(&observer->list, &mprotect_observer_list);
	spin_unlock(&mprotect_observer_lock);

	pr_info("mprotect observer registered\n");
	return 0;
}
EXPORT_SYMBOL(register_mprotect_observer);

/**
 * unregister_mprotect_observer - 注销 mprotect 观察者
 * @observer: 要注销的观察者
 */
void unregister_mprotect_observer(struct mprotect_observer *observer)
{
	if (!observer)
		return;

	spin_lock(&mprotect_observer_lock);
	list_del(&observer->list);
	spin_unlock(&mprotect_observer_lock);

	pr_info("mprotect observer unregistered\n");
}
EXPORT_SYMBOL(unregister_mprotect_observer);

/**
 * notify_before_mprotect - 通知所有观察者 mprotect 即将执行
 */
void notify_before_mprotect(unsigned long start, size_t len,
			    unsigned long old_prot, unsigned long new_prot,
			    struct vm_area_struct *vma)
{
	struct mprotect_observer *observer;

	spin_lock(&mprotect_observer_lock);
	list_for_each_entry(observer, &mprotect_observer_list, list) {
		if (observer->before_mprotect)
			observer->before_mprotect(start, len, old_prot,
						  new_prot, vma);
	}
	spin_unlock(&mprotect_observer_lock);
}
EXPORT_SYMBOL(notify_before_mprotect);

/**
 * notify_after_mprotect - 通知所有观察者 mprotect 已执行完成
 */
void notify_after_mprotect(unsigned long start, size_t len,
			   unsigned long old_prot, unsigned long new_prot,
			   struct vm_area_struct *vma, int result)
{
	struct mprotect_observer *observer;

	spin_lock(&mprotect_observer_lock);
	list_for_each_entry(observer, &mprotect_observer_list, list) {
		if (observer->after_mprotect)
			observer->after_mprotect(start, len, old_prot, new_prot,
						 vma, result);
	}
	spin_unlock(&mprotect_observer_lock);
}
EXPORT_SYMBOL(notify_after_mprotect);
