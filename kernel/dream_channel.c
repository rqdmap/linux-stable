#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/dream_channel.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

/* 定义函数指针变量，初始为NULL */
static dream_create_fn_t dream_create_fn = NULL;
static dream_connect_fn_t dream_connect_fn = NULL;
static dream_send_fn_t dream_send_fn = NULL;
static dream_recv_fn_t dream_recv_fn = NULL;
static dream_control_fn_t dream_control_fn = NULL;
static dream_close_fn_t dream_close_fn = NULL;

/* 辅助函数：分配内存 */
static inline void *dream_alloc_mem(size_t size)
{
	if (size > PAGE_SIZE)
		return vmalloc(size);
	else
		return kmalloc(size, GFP_KERNEL);
}

/* 辅助函数：释放内存 */
static inline void dream_free_mem(void *ptr, size_t size)
{
	if (size > PAGE_SIZE)
		vfree(ptr);
	else
		kfree(ptr);
}

/* 系统调用入口函数 - 创建通道 */
SYSCALL_DEFINE2(dream_channel_create, const char __user *, name, uint32_t,
		flags)
{
	char *k_name;
	size_t len;
	int ret;

	// 参数验证
	if (!name)
		return -EINVAL;

	// 安全获取字符串长度
	len = strnlen_user(name, 200);
	if (len == 0 || len > 200)
		return -EINVAL;

	// 分配内存 - 200字节以内可以用kmalloc
	k_name = kmalloc(len, GFP_KERNEL);
	if (!k_name)
		return -ENOMEM;

	// 从用户空间复制字符串
	if (copy_from_user(k_name, name, len)) {
		ret = -EFAULT;
		goto out_free;
	}

	// 确保字符串以null结尾
	k_name[len - 1] = '\0';

	// 权限检查
	if (!capable(CAP_SYS_ADMIN)) {
		ret = -EPERM;
		goto out_free;
	}

	// 如果模块已注册实现函数，则调用它
	if (dream_create_fn)
		ret = dream_create_fn(k_name, flags);
	else
		ret = -ENOSYS;

out_free:
	kfree(k_name);
	return ret;
}

/* 系统调用入口函数 - 连接通道 */
SYSCALL_DEFINE2(dream_channel_connect, const char __user *, name, uint32_t,
		flags)
{
	char *k_name;
	size_t len;
	int ret;

	// 参数验证
	if (!name)
		return -EINVAL;

	// 获取用户传递的字符串长度（限制最大长度为65536）
	len = strnlen_user(name, 65536);
	if (len == 0 || len > 65536)
		return -EINVAL;

	// 动态分配内存
	k_name = dream_alloc_mem(len);
	if (!k_name)
		return -ENOMEM;

	// 从用户空间复制字符串
	if (copy_from_user(k_name, name, len)) {
		ret = -EFAULT;
		goto out_free;
	}

	// 确保字符串以null结尾
	k_name[len - 1] = '\0';

	// 如果模块已注册实现函数，则调用它
	if (dream_connect_fn)
		ret = dream_connect_fn(k_name, flags);
	else
		ret = -ENOSYS;

out_free:
	dream_free_mem(k_name, len);
	return ret;
}

/* 系统调用入口函数 - 发送数据 */
SYSCALL_DEFINE3(dream_channel_send, int, channel_fd, const void __user *, buf,
		size_t, len)
{
	void *k_buf;
	int ret;

	// 参数验证
	if (!buf || len == 0 || len > 65536)
		return -EINVAL;

	// 动态分配内存
	k_buf = dream_alloc_mem(len);
	if (!k_buf)
		return -ENOMEM;

	// 从用户空间复制数据
	if (copy_from_user(k_buf, buf, len)) {
		ret = -EFAULT;
		goto out_free;
	}

	// 如果模块已注册实现函数，则调用它
	if (dream_send_fn)
		ret = dream_send_fn(channel_fd, k_buf, len);
	else
		ret = -ENOSYS;

out_free:
	dream_free_mem(k_buf, len);
	return ret;
}

/* 系统调用入口函数 - 接收数据 */
SYSCALL_DEFINE3(dream_channel_recv, int, channel_fd, void __user *, buf, size_t,
		len)
{
	void *k_buf;
	int ret;

	// 参数验证
	if (!buf || len == 0 || len > 65536)
		return -EINVAL;

	// 动态分配内存
	k_buf = dream_alloc_mem(len);
	if (!k_buf)
		return -ENOMEM;

	// 清零内存
	memset(k_buf, 0, len);

	// 如果模块已注册实现函数，则调用它
	if (dream_recv_fn)
		ret = dream_recv_fn(channel_fd, k_buf, len);
	else {
		ret = -ENOSYS;
		goto out_free;
	}

	// 如果接收成功，将数据复制回用户空间
	if (ret >= 0) {
		if (copy_to_user(buf, k_buf, len)) {
			ret = -EFAULT;
		}
	}

out_free:
	dream_free_mem(k_buf, len);
	return ret;
}

/* 系统调用入口函数 - 控制通道 */
SYSCALL_DEFINE2(dream_channel_control, int, channel_fd, uint32_t, flags)
{
	if (dream_control_fn)
		return dream_control_fn(channel_fd, flags);
	return -ENOSYS;
}

/* 系统调用入口函数 - 关闭通道 */
SYSCALL_DEFINE1(dream_channel_close, int, channel_fd)
{
	if (dream_close_fn)
		return dream_close_fn(channel_fd);
	return -ENOSYS;
}

/* 以下是注册/注销接口，保持不变 */
int register_dream_channel_create(dream_create_fn_t fn)
{
	dream_create_fn = fn;
	return 0;
}
EXPORT_SYMBOL(register_dream_channel_create);

int register_dream_channel_connect(dream_connect_fn_t fn)
{
	dream_connect_fn = fn;
	return 0;
}
EXPORT_SYMBOL(register_dream_channel_connect);

int register_dream_channel_send(dream_send_fn_t fn)
{
	dream_send_fn = fn;
	return 0;
}
EXPORT_SYMBOL(register_dream_channel_send);

int register_dream_channel_recv(dream_recv_fn_t fn)
{
	dream_recv_fn = fn;
	return 0;
}
EXPORT_SYMBOL(register_dream_channel_recv);

int register_dream_channel_control(dream_control_fn_t fn)
{
	dream_control_fn = fn;
	return 0;
}
EXPORT_SYMBOL(register_dream_channel_control);

int register_dream_channel_close(dream_close_fn_t fn)
{
	dream_close_fn = fn;
	return 0;
}
EXPORT_SYMBOL(register_dream_channel_close);

void unregister_dream_channel_create(void)
{
	dream_create_fn = NULL;
}
EXPORT_SYMBOL(unregister_dream_channel_create);

void unregister_dream_channel_connect(void)
{
	dream_connect_fn = NULL;
}
EXPORT_SYMBOL(unregister_dream_channel_connect);

void unregister_dream_channel_send(void)
{
	dream_send_fn = NULL;
}
EXPORT_SYMBOL(unregister_dream_channel_send);

void unregister_dream_channel_recv(void)
{
	dream_recv_fn = NULL;
}
EXPORT_SYMBOL(unregister_dream_channel_recv);

void unregister_dream_channel_control(void)
{
	dream_control_fn = NULL;
}
EXPORT_SYMBOL(unregister_dream_channel_control);

void unregister_dream_channel_close(void)
{
	dream_close_fn = NULL;
}
EXPORT_SYMBOL(unregister_dream_channel_close);
