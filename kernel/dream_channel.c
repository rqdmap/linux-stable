#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/dream_channel.h>

/* 定义函数指针变量，初始为NULL */
static dream_create_fn_t dream_create_fn = NULL;
static dream_connect_fn_t dream_connect_fn = NULL;
static dream_send_fn_t dream_send_fn = NULL;
static dream_recv_fn_t dream_recv_fn = NULL;
static dream_control_fn_t dream_control_fn = NULL;
static dream_close_fn_t dream_close_fn = NULL;

/* 系统调用入口函数 - 仅作为存根(stub) */
SYSCALL_DEFINE2(dream_channel_create, const char __user *, name, uint32_t,
		flags)
{
	char k_name[256];

	// 参数验证
	if (!name || copy_from_user(k_name, name, sizeof(k_name)))
		return -EINVAL;

	// 权限检查
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	// 如果模块已注册实现函数，则调用它
	if (dream_create_fn)
		return dream_create_fn(k_name, flags);

	// 否则返回"未实现"错误
	return -ENOSYS;
}

// 其他系统调用入口函数，逻辑类似...
SYSCALL_DEFINE2(dream_channel_connect, const char __user *, name, uint32_t,
		flags)
{
	char k_name[256];

	if (!name || copy_from_user(k_name, name, sizeof(k_name)))
		return -EINVAL;

	if (dream_connect_fn)
		return dream_connect_fn(k_name, flags);

	return -ENOSYS;
}

SYSCALL_DEFINE3(dream_channel_send, int, channel_fd, const void __user *, buf,
		size_t, len)
{
	char k_buf[256];

	if (len > sizeof(k_buf) || copy_from_user(k_buf, buf, len))
		return -EINVAL;

	if (dream_send_fn)
		return dream_send_fn(channel_fd, k_buf, len);

	return -ENOSYS;
}

SYSCALL_DEFINE3(dream_channel_recv, int, channel_fd, void __user *, buf, size_t,
		len)
{
	char k_buf[256];

	if (len > sizeof(k_buf))
		return -EINVAL;

	if (dream_recv_fn)
		return dream_recv_fn(channel_fd, k_buf, len);

	if (copy_to_user(buf, k_buf, len))
		return -EFAULT;

	return 0;
}

SYSCALL_DEFINE2(dream_channel_control, int, channel_fd, uint32_t, flags)
{
	if (dream_control_fn)
		return dream_control_fn(channel_fd, flags);

	return -ENOSYS;
}

SYSCALL_DEFINE1(dream_channel_close, int, channel_fd)
{
	if (dream_close_fn)
		return dream_close_fn(channel_fd);

	return -ENOSYS;
}

/* 注册接口 - 供模块调用 */
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

/* 注销接口 - 供模块调用 */
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
