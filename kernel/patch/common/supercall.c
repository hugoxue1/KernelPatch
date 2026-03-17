/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <ktypes.h>
#include <uapi/scdefs.h>
#include <hook.h>
#include <common.h>
#include <log.h>
#include <predata.h>
#include <pgtable.h>
#include <linux/syscall.h>
#include <uapi/asm-generic/errno.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <asm/current.h>
#include <linux/string.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <syscall.h>
#include <accctl.h>
#include <module.h>
#include <kputils.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <kputils.h>
#include <predata.h>
#include <linux/random.h>
#include <sucompat.h>
#include <accctl.h>
#include <kstorage.h>

#define MAX_KEY_LEN 128

#include <linux/umh.h>

static long call_test(long arg1, long arg2, long arg3)
{
    return 0;
}

static long call_bootlog()
{
    print_bootlog();
    return 0;
}

static long call_panic()
{
    unsigned long panic_addr = kallsyms_lookup_name("panic");
    ((void (*)(const char *fmt, ...))panic_addr)("!!!! kernel_patch panic !!!!");
    return 0;
}

static long call_klog(const char __user *arg1)
{
    char buf[1024];
    long len = compat_strncpy_from_user(buf, arg1, sizeof(buf));
    if (len <= 0) return -EINVAL;
    if (len > 0) logki("user log: %s", buf);
    return 0;
}

static long call_buildtime(char __user *out_buildtime, int u_len)
{
    const char *buildtime = get_build_time();
    int len = strlen(buildtime);
    if (len >= u_len) return -ENOMEM;
    int rc = compat_copy_to_user(out_buildtime, buildtime, len + 1);
    return rc;
}

static long call_kpm_load(const char __user *arg1, const char *__user arg2, void *__user reserved)
{
    char path[1024], args[KPM_ARGS_LEN];
    long pathlen = compat_strncpy_from_user(path, arg1, sizeof(path));
    if (pathlen <= 0) return -EINVAL;
    long arglen = compat_strncpy_from_user(args, arg2, sizeof(args));
    return load_module_path(path, arglen <= 0 ? 0 : args, reserved);
}

static long call_kpm_control(const char __user *arg1, const char *__user arg2, void *__user out_msg, int outlen)
{
    char name[KPM_NAME_LEN], args[KPM_ARGS_LEN];
    long namelen = compat_strncpy_from_user(name, arg1, sizeof(name));
    if (namelen <= 0) return -EINVAL;
    long arglen = compat_strncpy_from_user(args, arg2, sizeof(args));
    return module_control0(name, arglen <= 0 ? 0 : args, out_msg, outlen);
}

static long call_kpm_unload(const char *__user arg1, void *__user reserved)
{
    char name[KPM_NAME_LEN];
    long len = compat_strncpy_from_user(name, arg1, sizeof(name));
    if (len <= 0) return -EINVAL;
    return unload_module(name, reserved);
}

static long call_kpm_nums()
{
    return get_module_nums();
}

static long call_kpm_list(char *__user names, int len)
{
    if (len <= 0) return -EINVAL;
    char buf[4096];
    int sz = list_modules(buf, sizeof(buf));
    if (sz > len) return -ENOBUFS;
    sz = compat_copy_to_user(names, buf, len);
    return sz;
}

static long call_kpm_info(const char *__user uname, char *__user out_info, int out_len)
{
    if (out_len <= 0) return -EINVAL;
    char name[64];
    char buf[2048];
    int len = compat_strncpy_from_user(name, uname, sizeof(name));
    if (len <= 0) return -EINVAL;
    int sz = get_module_info(name, buf, sizeof(buf));
    if (sz < 0) return sz;
    if (sz > out_len) return -ENOBUFS;
    sz = compat_copy_to_user(out_info, buf, sz);
    return sz;
}

static long call_su(struct su_profile *__user uprofile)
{
    struct su_profile *profile = memdup_user(uprofile, sizeof(struct su_profile));
    if (!profile || IS_ERR(profile)) return PTR_ERR(profile);
    profile->scontext[sizeof(profile->scontext) - 1] = '\0';
    int rc = commit_su(profile->to_uid, profile->scontext);
    kvfree(profile);
    return rc;
}

static long call_su_task(pid_t pid, struct su_profile *__user uprofile)
{
    struct su_profile *profile = memdup_user(uprofile, sizeof(struct su_profile));
    if (!profile || IS_ERR(profile)) return PTR_ERR(profile);
    profile->scontext[sizeof(profile->scontext) - 1] = '\0';
    int rc = task_su(pid, profile->to_uid, profile->scontext);
    kvfree(profile);
    return rc;
}

static long call_skey_get(char *__user out_key, int out_len)
{
    const char *key = get_superkey();
    int klen = strlen(key);
    if (klen >= out_len) return -ENOMEM;
    int rc = compat_copy_to_user(out_key, key, klen + 1);
    return rc;
}

static long call_skey_set(char *__user new_key)
{
    char buf[SUPER_KEY_LEN];
    int len = compat_strncpy_from_user(buf, new_key, sizeof(buf));
    if (len >= SUPER_KEY_LEN && buf[SUPER_KEY_LEN - 1]) return -E2BIG;
    reset_superkey(new_key);
    return 0;
}

static long call_skey_root_enable(int enable)
{
    enable_auth_root_key(enable);
    return 0;
}

static long call_grant_uid(struct su_profile *__user uprofile)
{
    struct su_profile *profile = memdup_user(uprofile, sizeof(struct su_profile));
    if (!profile || IS_ERR(profile)) return PTR_ERR(profile);
    int rc = su_add_allow_uid(profile->uid, profile->to_uid, profile->scontext);
    kvfree(profile);
    return rc;
}

static long call_revoke_uid(uid_t uid)
{
    return su_remove_allow_uid(uid);
}

static long call_su_allow_uid_nums()
{
    return su_allow_uid_nums();
}

#ifdef ANDROID
extern int android_is_safe_mode;
static long call_su_get_safemode()
{
    int result = android_is_safe_mode;
    logkfd("[call_su_get_safemode] %d\n", result);
    return result;
}
#endif

static long call_su_list_allow_uid(uid_t *__user uids, int num)
{
    return su_allow_uids(1, uids, num);
}

static long call_su_allow_uid_profile(uid_t uid, struct su_profile *__user uprofile)
{
    return su_allow_uid_profile(1, uid, uprofile);
}

static long call_reset_su_path(const char *__user upath)
{
    return su_reset_path(strndup_user(upath, SU_PATH_MAX_LEN));
}

static long call_su_get_path(char *__user ubuf, int buf_len)
{
    const char *path = su_get_path();
    int len = strlen(path);
    if (buf_len <= len) return -ENOBUFS;
    return compat_copy_to_user(ubuf, path, len + 1);
}

static long call_su_get_allow_sctx(char *__user usctx, int ulen)
{
    int len = strlen(all_allow_sctx);
    if (ulen <= len) return -ENOBUFS;
    return compat_copy_to_user(usctx, all_allow_sctx, len + 1);
}

static long call_su_set_allow_sctx(char *__user usctx)
{
    char buf[SUPERCALL_SCONTEXT_LEN];
    buf[0] = '\0';
    int len = compat_strncpy_from_user(buf, usctx, sizeof(buf));
    if (len >= SUPERCALL_SCONTEXT_LEN && buf[SUPERCALL_SCONTEXT_LEN - 1]) return -E2BIG;
    return set_all_allow_sctx(buf);
}

static long call_kstorage_read(int gid, long did, void *out_data, int offset, int dlen)
{
    return read_kstorage(gid, did, out_data, offset, dlen, true);
}

static long call_kstorage_write(int gid, long did, void *data, int offset, int dlen)
{
    return write_kstorage(gid, did, data, offset, dlen, true);
}

static long call_list_kstorage_ids(int gid, long *ids, int ids_len)
{
    return list_kstorage_ids(gid, ids, ids_len, false);
}

static long call_kstorage_remove(int gid, long did)
{
    return remove_kstorage(gid, did);
}

static long supercall(int is_key_auth, long cmd, long arg1, long arg2, long arg3, long arg4)
{
    switch (cmd) {
    case SUPERCALL_HELLO:
        logki(SUPERCALL_HELLO_ECHO "\n");
        return SUPERCALL_HELLO_MAGIC;
    case SUPERCALL_KLOG:
        return call_klog((const char *__user)arg1);
    case SUPERCALL_KERNELPATCH_VER:
        return kpver;
    case SUPERCALL_KERNEL_VER:
        return kver;
    case SUPERCALL_BUILD_TIME:
        return call_buildtime((char *__user)arg1, (int)arg2);
    }

    switch (cmd) {
    case SUPERCALL_SU:
        return call_su((struct su_profile * __user) arg1);
    case SUPERCALL_SU_TASK:
        return call_su_task((pid_t)arg1, (struct su_profile * __user) arg2);

    case SUPERCALL_SU_GRANT_UID:
        return call_grant_uid((struct su_profile * __user) arg1);
    case SUPERCALL_SU_REVOKE_UID:
        return call_revoke_uid((uid_t)arg1);
    case SUPERCALL_SU_NUMS:
        return call_su_allow_uid_nums();
    case SUPERCALL_SU_LIST:
        return call_su_list_allow_uid((uid_t *)arg1, (int)arg2);
    case SUPERCALL_SU_PROFILE:
        return call_su_allow_uid_profile((uid_t)arg1, (struct su_profile * __user) arg2);
    case SUPERCALL_SU_RESET_PATH:
        return call_reset_su_path((const char *)arg1);
    case SUPERCALL_SU_GET_PATH:
        return call_su_get_path((char *__user)arg1, (int)arg2);
    case SUPERCALL_SU_GET_ALLOW_SCTX:
        return call_su_get_allow_sctx((char *__user)arg1, (int)arg2);
    case SUPERCALL_SU_SET_ALLOW_SCTX:
        return call_su_set_allow_sctx((char *__user)arg1);

    case SUPERCALL_KSTORAGE_READ:
        return call_kstorage_read((int)arg1, (long)arg2, (void *)arg3, (int)((long)arg4 >> 32), (long)arg4 << 32 >> 32);
    case SUPERCALL_KSTORAGE_WRITE:
        return call_kstorage_write((int)arg1, (long)arg2, (void *)arg3, (int)((long)arg4 >> 32),
                                   (long)arg4 << 32 >> 32);
    case SUPERCALL_KSTORAGE_LIST_IDS:
        return call_list_kstorage_ids((int)arg1, (long *)arg2, (int)arg3);
    case SUPERCALL_KSTORAGE_REMOVE:
        return call_kstorage_remove((int)arg1, (long)arg2);

#ifdef ANDROID
    case SUPERCALL_SU_GET_SAFEMODE:
        return call_su_get_safemode();
#endif
    default:
        break;
    }

    switch (cmd) {
    case SUPERCALL_BOOTLOG:
        return call_bootlog();
    case SUPERCALL_PANIC:
        return call_panic();
    case SUPERCALL_TEST:
        return call_test(arg1, arg2, arg3);
    default:
        break;
    }

    if (!is_key_auth) return -EPERM;

    switch (cmd) {
    case SUPERCALL_SKEY_GET:
        return call_skey_get((char *__user)arg1, (int)arg2);
    case SUPERCALL_SKEY_SET:
        return call_skey_set((char *__user)arg1);
    case SUPERCALL_SKEY_ROOT_ENABLE:
        return call_skey_root_enable((int)arg1);
        break;
    }

    switch (cmd) {
    case SUPERCALL_KPM_LOAD:
        return call_kpm_load((const char *__user)arg1, (const char *__user)arg2, (void *__user)arg3);
    case SUPERCALL_KPM_UNLOAD:
        return call_kpm_unload((const char *__user)arg1, (void *__user)arg2);
    case SUPERCALL_KPM_CONTROL:
        return call_kpm_control((const char *__user)arg1, (const char *__user)arg2, (char *__user)arg3, (int)arg4);
    case SUPERCALL_KPM_NUMS:
        return call_kpm_nums();
    case SUPERCALL_KPM_LIST:
        return call_kpm_list((char *__user)arg1, (int)arg2);
    case SUPERCALL_KPM_INFO:
        return call_kpm_info((const char *__user)arg1, (char *__user)arg2, (int)arg3);
    }

    switch (cmd) {
    default:
        break;
    }

    return -ENOSYS;
}

// Anti side-channel detection bypass (Attempt 3)
// 
// Problem: Hunter detects APatch by measuring timing difference of syscall 45 (brk).
//   - In-range cmd (0x1000~0x1200): hook does key verify + supercall dispatch + skip_origin
//   - Out-of-range cmd (e.g. 0x999): hook returns early → original brk executes
//   The structural difference (skip_origin vs run original brk) is measurable.
//
// Solution: Both paths execute the SAME operations and BOTH call original brk.
//   - before(): always does copy_from_user + auth_superkey + uid check (both paths)
//   - before(): for in-range cmd, computes supercall result, stores in local.data0
//   - skip_origin is NEVER set → original brk always runs (both paths identical)
//   - after(): for in-range cmd, overwrites ret with the stored supercall result
//
// Result: Both paths have identical timing profile. Detection ratio → ~1.0

// local.data0 = supercall result (when in-range)
// local.data1 = 1 if in-range cmd was handled, 0 otherwise

static void before(hook_fargs6_t *args, void *udata)
{
    // One-time log to confirm our patched version is running
    static int logged = 0;
    if (!logged) {
        logki("supercall before: anti-sidechannel v3 (no skip_origin)\n");
        logged = 1;
    }

    const char *__user ukey = (const char *__user)syscall_argn(args, 0);
    long ver_xx_cmd = (long)syscall_argn(args, 1);

    // todo: from 0.10.5
    // uint32_t ver = (ver_xx_cmd & 0xFFFFFFFF00000000ul) >> 32;
    // long xx = (ver_xx_cmd & 0xFFFF0000) >> 16;

    long cmd = ver_xx_cmd & 0xFFFF;

    // Mark as not handled by default
    args->local.data1 = 0;

    // Anti side-channel: ALWAYS execute copy_from_user + key verification
    // regardless of whether cmd is in range or not
    char key[MAX_KEY_LEN];
    long len = compat_strncpy_from_user(key, ukey, MAX_KEY_LEN);

    int is_key_auth = 0;
    int is_su_uid = 0;

    if (len > 0) {
        if (!auth_superkey(key)) {
            is_key_auth = 1;
        } else if (!strcmp("su", key)) {
            uid_t uid = current_uid();
            is_su_uid = is_su_allow_uid(uid);
        }
    }

    // For in-range cmd: validate and dispatch supercall, store result
    // For out-of-range cmd: do nothing more (but we already consumed equivalent time above)
    // Both paths then fall through to let original brk execute (skip_origin stays 0)
    if (cmd >= SUPERCALL_HELLO && cmd <= SUPERCALL_MAX) {
        // Validate: must be key_auth or allowed su uid
        if (!is_key_auth && !is_su_uid) return;

        long a1 = (long)syscall_argn(args, 2);
        long a2 = (long)syscall_argn(args, 3);
        long a3 = (long)syscall_argn(args, 4);
        long a4 = (long)syscall_argn(args, 5);

        // Store supercall result; after() will apply it
        args->local.data0 = (uint64_t)supercall(is_key_auth, cmd, a1, a2, a3, a4);
        args->local.data1 = 1;
    }

    // NOTE: skip_origin is NOT set for either path.
    // Original brk syscall will execute for BOTH in-range and out-of-range.
    // This eliminates the timing difference completely.
}

static void after(hook_fargs6_t *args, void *udata)
{
    // If before() handled a supercall, override the brk return value
    // with the actual supercall result
    if (args->local.data1 == 1) {
        args->ret = args->local.data0;
    }
}

// =====================================================================
// [CKB-MOD] 2026-03-11 Anti side-channel: compat (32-bit) syscall table hook
//
// 问题：KernelPatch 只 hook 了 64 位 sys_call_table[45]（sys_truncate），
//       32 位 compat_sys_call_table[45]（sys_brk）未被 hook。
//       检测工具（如 Hunter）可对比两张表的 nr 45 执行时间：
//       64 位有 before/after 开销 ~222K ticks，32 位无开销 ~54K ticks，差 4~5 倍。
//
// 方案：给 compat 表的 nr 45 也加 before/after hook，执行等量的
//       copy_from_user + auth_superkey 操作来对齐时间开销。
//       compat 表 nr 45 是 sys_brk（内存管理），参数语义与 sys_truncate 不同，
//       所以 before_compat 不执行 supercall 分发，只做时间对齐。
//
// 安全性：sys_brk 的参数是地址值（unsigned long），copy_from_user 把它当
//         用户态字符串指针读取会失败（len <= 0），不影响 brk 正常功能。
//         skip_origin 不设置，原始 sys_brk 照常执行。
// =====================================================================

static void before_compat(hook_fargs6_t *args, void *udata)
{
    static int logged = 0;
    if (!logged) {
        logki("supercall before_compat: anti-sidechannel compat table hook\n");
        logged = 1;
    }

    // 读取与 64 位 before() 相同的参数位置，执行相同的 copy_from_user + key 验证
    // 目的：让 compat 表 nr 45 的 before 回调开销与 64 位表一致
    const char *__user ukey = (const char *__user)syscall_argn(args, 0);

    char key[MAX_KEY_LEN];
    long len = compat_strncpy_from_user(key, ukey, MAX_KEY_LEN);

    // 执行与 64 位 before() 相同的 key 验证路径（纯时间对齐，结果不使用）
    if (len > 0) {
        if (!auth_superkey(key)) {
            // key_auth 成功，但 compat 表不处理 supercall
        } else if (!strcmp("su", key)) {
            uid_t uid = current_uid();
            (void)is_su_allow_uid(uid);
        }
    }

    // 不设置 skip_origin → 原始 sys_brk 照常执行
    // 不设置 data1 → after_compat 不覆盖返回值
}

static void after_compat(hook_fargs6_t *args, void *udata)
{
    // compat 表不处理 supercall，after 回调为空（但必须注册以匹配 64 位表的 hook 结构）
    // hook 框架执行 after 回调本身也有微小开销，注册空 after 可对齐这部分时间
}

int supercall_install()
{
    int rc = 0;

    // 64 位 syscall 表 hook（supercall 主逻辑）
    hook_err_t err = hook_syscalln(__NR_supercall, 6, before, after, 0);
    if (err) {
        log_boot("install supercall hook error: %d\n", err);
        rc = err;
        goto out;
    }

    // [CKB-MOD] 32 位 compat syscall 表 hook（时间对齐，防止跨表时序检测）
    hook_err_t compat_err = hook_compat_syscalln(__NR_supercall, 6, before_compat, after_compat, 0);
    if (compat_err) {
        log_boot("install compat supercall hook error: %d\n", compat_err);
        // compat hook 失败不影响主功能，仅记录警告
    } else {
        log_boot("compat supercall hook installed (anti-sidechannel)\n");
    }

out:
    return rc;
}
