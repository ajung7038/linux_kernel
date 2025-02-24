// SPDX-License-Identifier: GPL-2.0
/*
 * linux/fs/ext4/acl.c
 *
 * Copyright (C) 2001-2003 Andreas Gruenbacher, <agruen@suse.de>
 */

#include <linux/quotaops.h>
#include "ext4_jbd2.h"
#include "ext4.h"
#include "xattr.h"
#include "acl.h"

/*
 * 디스크에서 읽어온 원시 ACL 데이터를 메모리에서 사용할 수 있도록 POSIX ACL 형식으로 변환
 * ext4_acl_entry -> posix_acl 형식으로 변환
 */
static struct posix_acl *
ext4_acl_from_disk(const void *value, size_t size)
{
	const char *end = (char *)value + size; // 가져온 값의 끝 (포인터 위치 이동)
	int n, count;
	struct posix_acl *acl; // ACL 구조체 포인터

	if (!value) // 값이 없다면
		return NULL;
	if (size < sizeof(ext4_acl_header)) // 구조체의 크기보다 size가 작은 경우 오류
		 return ERR_PTR(-EINVAL);
	if (((ext4_acl_header *)value)->a_version != cpu_to_le32(EXT4_ACL_VERSION)) // ACL 버전이 일치하지 않으면 오류
		return ERR_PTR(-EINVAL);

	value = (char *)value + sizeof(ext4_acl_header); // 값 시작 위치(포인터)에 acl_header 크기만큼 위치를 더하여 ACL 엔트리 목록이 시작하는 위치로 포인터 이동
	count = ext4_acl_count(size); // acl 사이즈 카운트
	if (count < 0) // 0보다 작으면 에러
		return ERR_PTR(-EINVAL);
	if (count == 0) // ACL 존재 X
		return NULL;
	acl = posix_acl_alloc(count, GFP_NOFS); // acl 메모리 할당
	if (!acl)
		return ERR_PTR(-ENOMEM);
	for (n = 0; n < count; n++) { // acl 엔트리 개수만큼 반복
		ext4_acl_entry *entry = (ext4_acl_entry *)value; // 정보 저장 엔트리에 포인터 가리키기
		if ((char *)value + sizeof(ext4_acl_entry_short) > end) // 메모리 오버플로우 (범위 초과)
			goto fail;
		acl->a_entries[n].e_tag  = le16_to_cpu(entry->e_tag); // acl_entry 값을 posix_acl 엔트리의 값으로 대입 (유형 : 사용자, 그룹 등)
		acl->a_entries[n].e_perm = le16_to_cpu(entry->e_perm); // acl_entry 값을 posix_acl 엔트리의 값으로 대입 (권한)

		switch (acl->a_entries[n].e_tag) { // 유형에 따라 분류
		case ACL_USER_OBJ: // 파일 소유자 권한
		case ACL_GROUP_OBJ: // 파일 소유 그룹 권한
		case ACL_MASK:
		case ACL_OTHER:
			value = (char *)value +
				sizeof(ext4_acl_entry_short); // 유형이 올바르다면 포인터 이동 (방금 저장된 ext4_acl_entry_short 이후 다음 시작 위치로 이동)
			break;

		// 특정 사용자나 특정 그룹 유형이라면 id가 따로 필요함. 따라 ext4_acl_entry_short 사이즈가 아닌 ext4_acl_entry 사이즈와 id를 읽어 와야 함
		case ACL_USER: // 특정 추가 사용자 유형이라면
			value = (char *)value + sizeof(ext4_acl_entry); // 추가적인 id (e_id) 처리
			if ((char *)value > end) // 메모리 오버플로우 (범위 초과)
				goto fail;
			acl->a_entries[n].e_uid = make_kuid(&init_user_ns, le32_to_cpu(entry->e_id)); // id를 추가로 읽어 저장
			break;
		case ACL_GROUP: // 특정 추가 그룹 유형이라면
			value = (char *)value + sizeof(ext4_acl_entry);
			if ((char *)value > end) // 메모리 오버플로우 (범위 초과)
				goto fail;
			acl->a_entries[n].e_gid = make_kgid(&init_user_ns, le32_to_cpu(entry->e_id)); // id를 추가로 읽어 저장
			break;

		default:
			goto fail;
		}
	}
	if (value != end)
		goto fail;
	return acl;

fail:
	posix_acl_release(acl);
	return ERR_PTR(-EINVAL);
}

/*
 * Convert from in-memory to filesystem representation.
 */
static void *
ext4_acl_to_disk(const struct posix_acl *acl, size_t *size)
{
	ext4_acl_header *ext_acl;
	char *e;
	size_t n;

	*size = ext4_acl_size(acl->a_count);
	ext_acl = kmalloc(sizeof(ext4_acl_header) + acl->a_count *
			sizeof(ext4_acl_entry), GFP_NOFS);
	if (!ext_acl)
		return ERR_PTR(-ENOMEM);
	ext_acl->a_version = cpu_to_le32(EXT4_ACL_VERSION);
	e = (char *)ext_acl + sizeof(ext4_acl_header);
	for (n = 0; n < acl->a_count; n++) {
		const struct posix_acl_entry *acl_e = &acl->a_entries[n];
		ext4_acl_entry *entry = (ext4_acl_entry *)e;
		entry->e_tag  = cpu_to_le16(acl_e->e_tag);
		entry->e_perm = cpu_to_le16(acl_e->e_perm);
		switch (acl_e->e_tag) {
		case ACL_USER:
			entry->e_id = cpu_to_le32(
				from_kuid(&init_user_ns, acl_e->e_uid));
			e += sizeof(ext4_acl_entry);
			break;
		case ACL_GROUP:
			entry->e_id = cpu_to_le32(
				from_kgid(&init_user_ns, acl_e->e_gid));
			e += sizeof(ext4_acl_entry);
			break;

		case ACL_USER_OBJ:
		case ACL_GROUP_OBJ:
		case ACL_MASK:
		case ACL_OTHER:
			e += sizeof(ext4_acl_entry_short);
			break;

		default:
			goto fail;
		}
	}
	return (char *)ext_acl;

fail:
	kfree(ext_acl);
	return ERR_PTR(-EINVAL);
}

/*
 * Inode operation get_posix_acl().
 *
 * inode->i_rwsem: don't care
 */
struct posix_acl *
ext4_get_acl(struct inode *inode, int type, bool rcu)
{
	int name_index;
	char *value = NULL;
	struct posix_acl *acl;
	int retval;

	if (rcu)
		return ERR_PTR(-ECHILD);

	switch (type) {
	case ACL_TYPE_ACCESS:
		name_index = EXT4_XATTR_INDEX_POSIX_ACL_ACCESS;
		break;
	case ACL_TYPE_DEFAULT:
		name_index = EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT;
		break;
	default:
		BUG();
	}
	retval = ext4_xattr_get(inode, name_index, "", NULL, 0);
	if (retval > 0) {
		value = kmalloc(retval, GFP_NOFS);
		if (!value)
			return ERR_PTR(-ENOMEM);
		retval = ext4_xattr_get(inode, name_index, "", value, retval);
	}
	if (retval > 0)
		acl = ext4_acl_from_disk(value, retval);
	else if (retval == -ENODATA || retval == -ENOSYS)
		acl = NULL;
	else
		acl = ERR_PTR(retval);
	kfree(value);

	return acl;
}

/*
 * Set the access or default ACL of an inode.
 *
 * inode->i_rwsem: down unless called from ext4_new_inode
 */
static int
__ext4_set_acl(handle_t *handle, struct inode *inode, int type,
	     struct posix_acl *acl, int xattr_flags)
{
	int name_index;
	void *value = NULL;
	size_t size = 0;
	int error;

	switch (type) {
	case ACL_TYPE_ACCESS:
		name_index = EXT4_XATTR_INDEX_POSIX_ACL_ACCESS;
		break;

	case ACL_TYPE_DEFAULT:
		name_index = EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT;
		if (!S_ISDIR(inode->i_mode))
			return acl ? -EACCES : 0;
		break;

	default:
		return -EINVAL;
	}
	if (acl) {
		value = ext4_acl_to_disk(acl, &size);
		if (IS_ERR(value))
			return (int)PTR_ERR(value);
	}

	error = ext4_xattr_set_handle(handle, inode, name_index, "",
				      value, size, xattr_flags);

	kfree(value);
	if (!error)
		set_cached_acl(inode, type, acl);

	return error;
}

int
ext4_set_acl(struct mnt_idmap *idmap, struct dentry *dentry,
	     struct posix_acl *acl, int type)
{
	handle_t *handle;
	int error, credits, retries = 0;
	size_t acl_size = acl ? ext4_acl_size(acl->a_count) : 0;
	struct inode *inode = d_inode(dentry);
	umode_t mode = inode->i_mode;
	int update_mode = 0;

	error = dquot_initialize(inode);
	if (error)
		return error;
retry:
	error = ext4_xattr_set_credits(inode, acl_size, false /* is_create */,
				       &credits);
	if (error)
		return error;

	handle = ext4_journal_start(inode, EXT4_HT_XATTR, credits);
	if (IS_ERR(handle))
		return PTR_ERR(handle);

	if ((type == ACL_TYPE_ACCESS) && acl) {
		error = posix_acl_update_mode(idmap, inode, &mode, &acl);
		if (error)
			goto out_stop;
		if (mode != inode->i_mode)
			update_mode = 1;
	}

	error = __ext4_set_acl(handle, inode, type, acl, 0 /* xattr_flags */);
	if (!error && update_mode) {
		inode->i_mode = mode;
		inode_set_ctime_current(inode);
		error = ext4_mark_inode_dirty(handle, inode);
	}
out_stop:
	ext4_journal_stop(handle);
	if (error == -ENOSPC && ext4_should_retry_alloc(inode->i_sb, &retries))
		goto retry;
	return error;
}

/*
 * Initialize the ACLs of a new inode. Called from ext4_new_inode.
 *
 * dir->i_rwsem: down
 * inode->i_rwsem: up (access to inode is still exclusive)
 */
int
ext4_init_acl(handle_t *handle, struct inode *inode, struct inode *dir)
{
	struct posix_acl *default_acl, *acl;
	int error;

	error = posix_acl_create(dir, &inode->i_mode, &default_acl, &acl);
	if (error)
		return error;

	if (default_acl) {
		error = __ext4_set_acl(handle, inode, ACL_TYPE_DEFAULT,
				       default_acl, XATTR_CREATE);
		posix_acl_release(default_acl);
	} else {
		inode->i_default_acl = NULL;
	}
	if (acl) {
		if (!error)
			error = __ext4_set_acl(handle, inode, ACL_TYPE_ACCESS,
					       acl, XATTR_CREATE);
		posix_acl_release(acl);
	} else {
		inode->i_acl = NULL;
	}
	return error;
}
