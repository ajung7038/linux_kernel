// SPDX-License-Identifier: GPL-2.0
/*
  File: fs/ext4/acl.h

  (C) 2001 Andreas Gruenbacher, <a.gruenbacher@computer.org>
*/

#include <linux/posix_acl_xattr.h>

#define EXT4_ACL_VERSION	0x0001

typedef struct { // acl 정보 저장 엔트리 구조체
	__le16		e_tag; // ACL 엔트리 타입 (사용자, 그룹 등)
	__le16		e_perm; // 해당 항목 권한
	__le32		e_id; // 사용자 or 그룹 ID
} ext4_acl_entry;

typedef struct { // acl 정보 저장 엔트리 구조체 (타입 & 권한)
	__le16		e_tag; // ACL 엔트리 타입 (사용자, 그룹 등)
	__le16		e_perm; // 해당 항목 권한
} ext4_acl_entry_short;

typedef struct { // EXT4 파일 시스템에서 ACL 데이터를 식별하고 관리하는 데 필요한 버전 정보를 포함하는 구조체
	__le32		a_version; // 리틀 엔디안 형식의 32비트 정수
} ext4_acl_header;

static inline size_t ext4_acl_size(int count)
{
	if (count <= 4) {
		return sizeof(ext4_acl_header) +
		       count * sizeof(ext4_acl_entry_short);
	} else {
		return sizeof(ext4_acl_header) +
		       4 * sizeof(ext4_acl_entry_short) +
		       (count - 4) * sizeof(ext4_acl_entry);
	}
}

 // ACL 항목 수 계산 함수 (사이즈로 항목 계산)
static inline int ext4_acl_count(size_t size)
{
	ssize_t s;
	size -= sizeof(ext4_acl_header); // 기본 정보 사이즈를 제외한 나머지 크기
	s = size - 4 * sizeof(ext4_acl_entry_short); // [사용자, 그룹, 기타, 마스크] 권한 네 가지 항목은 기본적으로 존재 (그 크기를 제외한 나머지 크기 계산)
	if (s < 0) { // 기본 권한만 존재하는 경우
		if (size % sizeof(ext4_acl_entry_short)) // acl 엔트리 (간략) 사이즈로 나눠떨어지지 않으면 오류
			return -1;
		return size / sizeof(ext4_acl_entry_short); // 기본 권한 개수 (4개) 반환
	} else { // 추가 권한이 존재하는 경우
		if (s % sizeof(ext4_acl_entry)) // acl 엔트리 (간략) 사이즈로 나눠떨어지지 않으면 오류
			return -1;
		return s / sizeof(ext4_acl_entry) + 4; // 추가 권한 개수 + 기본적 항목 (사용자, 그룹, 기타, 마스크) 4개
	}
}

#ifdef CONFIG_EXT4_FS_POSIX_ACL

/* acl.c */
struct posix_acl *ext4_get_acl(struct inode *inode, int type, bool rcu);
int ext4_set_acl(struct mnt_idmap *idmap, struct dentry *dentry,
		 struct posix_acl *acl, int type);
extern int ext4_init_acl(handle_t *, struct inode *, struct inode *);

#else  /* CONFIG_EXT4_FS_POSIX_ACL */
#include <linux/sched.h>
#define ext4_get_acl NULL
#define ext4_set_acl NULL

static inline int
ext4_init_acl(handle_t *handle, struct inode *inode, struct inode *dir)
{
	return 0;
}
#endif  /* CONFIG_EXT4_FS_POSIX_ACL */

