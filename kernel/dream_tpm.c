#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/tpm.h>
#include <linux/crypto.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/file.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/path.h>
#include <crypto/hash.h>
#include <linux/dream_protect.h>

/* 定义SHA256摘要大小 */
#define SHA256_DIGEST_SIZE 32

/* 定义TPM相关常量 */
#define MASTER_KEY_SIZE 32
#define DERIVED_KEY_SIZE 32

/* 全局密钥缓存 */
static u8 *tpm_master_key;
static bool key_loaded = false;
static DEFINE_MUTEX(tpm_key_mutex);

/* 进程密钥缓存项 */
struct proc_key_cache {
	struct list_head list;
	u8 exe_hash[SHA256_DIGEST_SIZE];
	u8 key[DERIVED_KEY_SIZE];
	pid_t pid;
};

static LIST_HEAD(proc_key_cache_list);
static DEFINE_SPINLOCK(cache_lock);

/**
 * 辅助函数：将二进制数据转换为16进制字符串输出到日志
 * @param prefix 日志前缀
 * @param data 要打印的二进制数据
 * @param len 数据长度
 */
static void print_hex_dump_log(const char *prefix, const u8 *data, size_t len)
{
	char hex_str[128]; // 足够容纳32字节的密钥（每字节2个字符）加一些额外空间
	size_t str_pos = 0;
	size_t i;

	if (len > 32) {
		// 为安全起见，我们限制输出长度
		len = 32;
	}

	// 转换二进制到16进制字符串
	for (i = 0; i < len; i++) {
		str_pos += snprintf(hex_str + str_pos,
				    sizeof(hex_str) - str_pos, "%02x", data[i]);
		if (str_pos >= sizeof(hex_str) - 3) // 保留结束符和一点余量
			break;
	}

	// 打印到日志
	printk(KERN_INFO "%s: %s\n", prefix, hex_str);
}

/**
 * 从TPM解封主密钥
 * 在实际实现中，这里应与TPM设备通信，解封绑定到PCR状态的密钥
 * @param key_buffer 存储解封后密钥的缓冲区
 * @param key_size 缓冲区大小
 * @return 成功返回0，失败返回负的错误码
 */
static int tpm_unseal_master_key(u8 *key_buffer, size_t key_size)
{
	int i;

	pr_info("TPM-KEY: 开始解封主密钥操作\n");

	/* 简单实现：生成32字节的测试密钥 */
	if (key_size < MASTER_KEY_SIZE) {
		pr_err("TPM-KEY: 缓冲区大小(%zu)小于主密钥需求大小(%d)\n",
		       key_size, MASTER_KEY_SIZE);
		return -EOVERFLOW;
	}

	/* 实际应用中，这里应调用TPM2_Unseal命令 */
	/* 为了测试，生成一个简单的密钥模式 */
	for (i = 0; i < MASTER_KEY_SIZE; i++) {
		key_buffer[i] = (u8)(i + 1);
	}

	pr_info("TPM-KEY: 主密钥解封成功，大小: %d字节\n", MASTER_KEY_SIZE);

	// 打印主密钥16进制值
	print_hex_dump_log("TPM-KEY: 主密钥内容", key_buffer, MASTER_KEY_SIZE);

	return 0;
}

/**
 * 计算可执行文件的哈希值
 * @param file 文件指针
 * @param hash_out 输出哈希缓冲区
 * @return 成功返回0，失败返回负的错误码
 */
static int calculate_file_hash(struct file *file, u8 *hash_out)
{
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	int ret = 0;
	char *buf;
	loff_t pos = 0;
	size_t bytes_read;
	size_t total_bytes = 0;

	pr_info("TPM-KEY: 开始计算文件哈希\n");

	/* 分配读取缓冲区 */
	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf) {
		pr_err("TPM-KEY: 无法分配文件读取缓冲区\n");
		return -ENOMEM;
	}

	/* 创建SHA256哈希上下文 */
	tfm = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(tfm)) {
		ret = PTR_ERR(tfm);
		pr_err("TPM-KEY: 无法分配SHA256哈希算法: %d\n", ret);
		goto free_buf;
	}

	desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
	if (!desc) {
		pr_err("TPM-KEY: 无法分配哈希描述符\n");
		ret = -ENOMEM;
		goto free_tfm;
	}

	desc->tfm = tfm;

	/* 初始化哈希上下文 */
	ret = crypto_shash_init(desc);
	if (ret < 0) {
		pr_err("TPM-KEY: 哈希初始化失败: %d\n", ret);
		goto free_desc;
	}

	/* 读取文件内容并计算哈希 */
	pr_debug("TPM-KEY: 开始读取文件并计算哈希\n");
	while (1) {
		bytes_read = kernel_read(file, buf, PAGE_SIZE, &pos);
		if (bytes_read <= 0)
			break;

		total_bytes += bytes_read;

		ret = crypto_shash_update(desc, buf, bytes_read);
		if (ret < 0) {
			pr_err("TPM-KEY: 哈希更新失败: %d\n", ret);
			goto free_desc;
		}
	}

	pr_debug("TPM-KEY: 文件读取完成，总计读取: %zu 字节\n", total_bytes);

	/* 完成哈希计算 */
	ret = crypto_shash_final(desc, hash_out);
	if (ret < 0) {
		pr_err("TPM-KEY: 哈希计算最终阶段失败: %d\n", ret);
	} else {
		pr_info("TPM-KEY: 文件哈希计算成功\n");
		// 打印文件哈希值
		print_hex_dump_log("TPM-KEY: 文件哈希值", hash_out,
				   SHA256_DIGEST_SIZE);
	}

free_desc:
	kfree(desc);
free_tfm:
	crypto_free_shash(tfm);
free_buf:
	kfree(buf);
	return ret;
}

/**
 * 使用PBKDF2算法派生进程专属密钥
 * @param master_key 主密钥
 * @param master_key_size 主密钥大小
 * @param exe_hash 可执行文件哈希值
 * @param derived_key 派生密钥输出缓冲区
 * @param derived_key_size 派生密钥大小
 * @return 成功返回0，失败返回负的错误码
 */
static int derive_process_key(const u8 *master_key, size_t master_key_size,
			      const u8 *exe_hash, u8 *derived_key,
			      size_t derived_key_size)
{
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	u8 salt[SHA256_DIGEST_SIZE]; /* 使用文件哈希作为盐值 */
	u8 hash[SHA256_DIGEST_SIZE];
	u32 iter_bytes;
	int i, ret;
	unsigned int iterations = 10000; /* PBKDF2迭代次数 */

	pr_info("TPM-KEY: 开始派生进程密钥，迭代次数: %u\n", iterations);

	/* 将可执行文件哈希作为盐值 */
	memcpy(salt, exe_hash, SHA256_DIGEST_SIZE);

	/* 使用HMAC-SHA256作为PRF，实现PBKDF2 */
	tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
	if (IS_ERR(tfm)) {
		ret = PTR_ERR(tfm);
		pr_err("TPM-KEY: 无法分配HMAC-SHA256算法: %d\n", ret);
		return ret;
	}

	ret = crypto_shash_setkey(tfm, master_key, master_key_size);
	if (ret) {
		pr_err("TPM-KEY: 设置HMAC密钥失败: %d\n", ret);
		crypto_free_shash(tfm);
		return ret;
	}

	/* 分配描述符 */
	desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
	if (!desc) {
		pr_err("TPM-KEY: 无法分配HMAC描述符\n");
		crypto_free_shash(tfm);
		return -ENOMEM;
	}

	desc->tfm = tfm;

	/* 执行PBKDF2的第一步: U_1 = PRF(P, S || INT(i)) */
	ret = crypto_shash_init(desc);
	if (ret) {
		pr_err("TPM-KEY: HMAC初始化失败: %d\n", ret);
		goto free_desc;
	}

	/* 添加盐值 */
	ret = crypto_shash_update(desc, salt, sizeof(salt));
	if (ret) {
		pr_err("TPM-KEY: HMAC添加盐值失败: %d\n", ret);
		goto free_desc;
	}

	/* 添加迭代计数 */
	iter_bytes = cpu_to_be32(1); /* PBKDF2中的i=1 */
	ret = crypto_shash_update(desc, (u8 *)&iter_bytes, sizeof(iter_bytes));
	if (ret) {
		pr_err("TPM-KEY: HMAC添加迭代计数失败: %d\n", ret);
		goto free_desc;
	}

	ret = crypto_shash_final(desc, hash);
	if (ret) {
		pr_err("TPM-KEY: HMAC初始迭代计算失败: %d\n", ret);
		goto free_desc;
	}

	/* 复制U_1作为初始T_1 */
	if (derived_key_size > SHA256_DIGEST_SIZE)
		derived_key_size = SHA256_DIGEST_SIZE;
	memcpy(derived_key, hash, derived_key_size);

	/* 执行PBKDF2的迭代: U_j = PRF(P, U_{j-1}) */
	pr_debug("TPM-KEY: 开始PBKDF2迭代计算，共%u次迭代\n", iterations);
	for (i = 1; i < iterations; i++) {
		u8 temp[SHA256_DIGEST_SIZE];
		int j;

		/* U_j = PRF(P, U_{j-1}) */
		ret = crypto_shash_init(desc);
		if (ret) {
			pr_err("TPM-KEY: HMAC迭代%d初始化失败: %d\n", i, ret);
			goto free_desc;
		}

		ret = crypto_shash_update(desc, hash, SHA256_DIGEST_SIZE);
		if (ret) {
			pr_err("TPM-KEY: HMAC迭代%d更新失败: %d\n", i, ret);
			goto free_desc;
		}

		ret = crypto_shash_final(desc, temp);
		if (ret) {
			pr_err("TPM-KEY: HMAC迭代%d计算失败: %d\n", i, ret);
			goto free_desc;
		}

		/* T_i = U_1 XOR U_2 XOR ... XOR U_c */
		for (j = 0; j < derived_key_size; j++) {
			derived_key[j] ^= temp[j];
		}

		/* 保存当前U_j作为下一轮的U_{j-1} */
		memcpy(hash, temp, SHA256_DIGEST_SIZE);

		/* 每1000次迭代输出一次进度 */
		if (i % 1000 == 0) {
			pr_debug("TPM-KEY: PBKDF2已完成%d/%u次迭代\n", i,
				 iterations);
		}
	}

	pr_info("TPM-KEY: 密钥派生完成，密钥大小: %zu字节\n", derived_key_size);
	// 打印派生密钥
	print_hex_dump_log("TPM-KEY: 派生密钥内容", derived_key,
			   derived_key_size);

	/* 清理 */
	ret = 0;

free_desc:
	kfree(desc);
	crypto_free_shash(tfm);
	return ret;
}

/**
 * 查找进程密钥缓存
 * @param exe_hash 可执行文件哈希
 * @param key_out 输出密钥缓冲区
 * @return 找到返回1，否则返回0
 */
static int find_cached_key(const u8 *exe_hash, u8 *key_out)
{
	struct proc_key_cache *cache;
	int found = 0;

	pr_debug("TPM-KEY: 在缓存中查找进程(PID=%d)密钥\n", current->pid);

	spin_lock(&cache_lock);
	list_for_each_entry(cache, &proc_key_cache_list, list) {
		if (memcmp(cache->exe_hash, exe_hash, SHA256_DIGEST_SIZE) ==
			    0 &&
		    cache->pid == current->pid) {
			memcpy(key_out, cache->key, DERIVED_KEY_SIZE);
			found = 1;
			pr_debug("TPM-KEY: 在缓存中找到进程(PID=%d)密钥\n",
				 current->pid);
			// 打印找到的缓存密钥
			print_hex_dump_log("TPM-KEY: 缓存的密钥内容", key_out,
					   DERIVED_KEY_SIZE);
			break;
		}
	}
	spin_unlock(&cache_lock);

	if (!found) {
		pr_debug("TPM-KEY: 缓存中未找到进程(PID=%d)密钥\n",
			 current->pid);
	}

	return found;
}

/**
 * 添加进程密钥到缓存
 * @param exe_hash 可执行文件哈希
 * @param key 密钥数据
 */
static void add_key_to_cache(const u8 *exe_hash, const u8 *key)
{
	struct proc_key_cache *cache;

	pr_debug("TPM-KEY: 将进程(PID=%d)密钥添加到缓存\n", current->pid);

	cache = kmalloc(sizeof(*cache), GFP_KERNEL);
	if (!cache) {
		pr_err("TPM-KEY: 无法分配缓存项内存\n");
		return;
	}

	memcpy(cache->exe_hash, exe_hash, SHA256_DIGEST_SIZE);
	memcpy(cache->key, key, DERIVED_KEY_SIZE);
	cache->pid = current->pid;

	spin_lock(&cache_lock);
	list_add(&cache->list, &proc_key_cache_list);
	spin_unlock(&cache_lock);

	pr_debug("TPM-KEY: 进程(PID=%d)密钥已成功添加到缓存\n", current->pid);
}

/**
 * 获取进程专属密钥
 * @param exe_hash 可执行文件哈希
 * @param key_out 输出密钥缓冲区
 * @return 成功返回0，失败返回负的错误码
 */
static int get_process_key(const u8 *exe_hash, u8 *key_out)
{
	int ret;

	pr_debug("TPM-KEY: 获取进程(PID=%d)专属密钥\n", current->pid);

	/* 检查是否已经有缓存的密钥 */
	if (find_cached_key(exe_hash, key_out)) {
		pr_info("TPM-KEY: 使用缓存的进程(PID=%d)密钥\n", current->pid);
		return 0;
	}

	pr_debug("TPM-KEY: 需要派生新的进程密钥，锁定互斥锁\n");
	mutex_lock(&tpm_key_mutex);

	/* 延迟加载主密钥 */
	if (!key_loaded) {
		pr_info("TPM-KEY: 主密钥尚未加载，正在从TPM解封\n");
		tpm_master_key = kmalloc(MASTER_KEY_SIZE, GFP_KERNEL);
		if (!tpm_master_key) {
			pr_err("TPM-KEY: 无法分配主密钥内存\n");
			mutex_unlock(&tpm_key_mutex);
			return -ENOMEM;
		}

		ret = tpm_unseal_master_key(tpm_master_key, MASTER_KEY_SIZE);
		if (ret < 0) {
			pr_err("TPM-KEY: 解封主密钥失败: %d\n", ret);
			kfree(tpm_master_key);
			tpm_master_key = NULL;
			mutex_unlock(&tpm_key_mutex);
			return ret;
		}

		key_loaded = true;
		pr_info("TPM-KEY: 主密钥已成功加载到内存\n");
	}

	/* 派生进程专属密钥 */
	pr_debug("TPM-KEY: 使用主密钥派生进程(PID=%d)专属密钥\n", current->pid);
	ret = derive_process_key(tpm_master_key, MASTER_KEY_SIZE, exe_hash,
				 key_out, DERIVED_KEY_SIZE);

	mutex_unlock(&tpm_key_mutex);
	pr_debug("TPM-KEY: 已释放互斥锁\n");

	if (ret < 0) {
		pr_err("TPM-KEY: 派生进程(PID=%d)密钥失败: %d\n", current->pid,
		       ret);
		return ret;
	}

	pr_info("TPM-KEY: 成功派生进程(PID=%d)密钥\n", current->pid);

	/* 添加到缓存 */
	add_key_to_cache(exe_hash, key_out);

	return 0;
}

/**
 * 系统调用：获取进程TPM派生密钥
 * @param key_buffer 用户空间密钥缓冲区
 * @param buffer_size 缓冲区大小
 * @return 成功返回密钥大小，失败返回负的错误码
 */
SYSCALL_DEFINE2(get_file_tpm_key, unsigned char __user *, key_buffer, size_t,
		buffer_size)
{
	struct task_struct *task = current;
	struct file *exe_file;
	u8 exe_hash[SHA256_DIGEST_SIZE];
	u8 derived_key[DERIVED_KEY_SIZE];
	int ret;

	pr_info("TPM-KEY: 进程(PID=%d, 命令=%s)请求TPM派生密钥\n", task->pid,
		task->comm);

	/* 基本参数检查 */
	if (!key_buffer || buffer_size < DERIVED_KEY_SIZE) {
		pr_err("TPM-KEY: 无效的参数 - 缓冲区: %p, 大小: %zu (需要: %d)\n",
		       key_buffer, buffer_size, DERIVED_KEY_SIZE);
		return -EINVAL;
	}

	/* 获取可执行文件 */
	if (!task->mm || !task->mm->exe_file) {
		pr_err("TPM-KEY: 进程没有关联的可执行文件\n");
		return -EINVAL;
	}

	/* 是否是 DREAM 保护的文件 */
	if (!is_process_protected(task->pid)) {
		pr_err("TPM-KEY: 进程(PID=%d)未受 DREAM 保护，无法获取密钥\n",
		       task->pid);
		return -EPERM;
	}

	exe_file = task->mm->exe_file;
	pr_debug("TPM-KEY: 成功获取进程可执行文件\n");

	/* 计算可执行文件哈希 */
	ret = calculate_file_hash(exe_file, exe_hash);
	if (ret < 0) {
		pr_err("TPM-KEY: 计算文件哈希失败: %d\n", ret);
		return ret;
	}

	/* 获取进程专属密钥 */
	ret = get_process_key(exe_hash, derived_key);
	if (ret < 0) {
		pr_err("TPM-KEY: 获取进程密钥失败: %d\n", ret);
		return ret;
	}

	// /* 复制密钥到用户空间前打印将要传递给用户的密钥 */
	// print_hex_dump_log("TPM-KEY: 传递给用户的密钥", derived_key, DERIVED_KEY_SIZE);

	/* 复制密钥到用户空间 */
	if (copy_to_user(key_buffer, derived_key, DERIVED_KEY_SIZE)) {
		pr_err("TPM-KEY: 复制密钥到用户空间失败\n");
		memzero_explicit(derived_key, sizeof(derived_key));
		return -EFAULT;
	}

	/* 安全清除敏感数据 */
	memzero_explicit(derived_key, sizeof(derived_key));

	return DERIVED_KEY_SIZE;
}
