// SPDX-License-Identifier: GPL-2.0-only
/*
 * Software encryption support for APFS read-only mounts.
 *
 * This is the kernel counterpart of the Go keybag/unlock path: the container
 * keybag names the volume keybag, the volume keybag wraps the volume key with
 * a password-derived KEK, and that volume key unwraps the volume master key
 * from the container keybag. The master key is the AES-XTS key used for the
 * file-system tree (and, on non-PFK volumes, file data).
 *
 * Only software encryption is supported. Hardware-wrapped keybags (the
 * Secure Enclave case) never decrypt, so they stay locked.
 */

#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <linux/unaligned.h>
#include <linux/minmax.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "apfs.h"

#define APFS_KEYBAG_MAGIC_KEYS	0x6b657973	/* 'keys' */
#define APFS_KEYBAG_MAGIC_RECS	0x72656373	/* 'recs' */
#define APFS_KEYBAG_TAG_VOLKEY	2
#define APFS_KEYBAG_TAG_VOLBAG	3

struct apfs_tlv {
	u8 tag;
	const u8 *val;
	u32 len;
};

struct apfs_kek {
	u8 id[16];
	u32 method;
	u32 iterations;
	u8 salt[16];
	u8 wrapped[40];
	u32 wrapped_len;
	bool have_id;
	bool have_method;
	bool have_wrapped;
	bool have_salt;
};

struct apfs_keybag_scan {
	const u8 *volume_uuid;
	const char *password;
	u64 bag_block;
	u64 bag_count;
	u8 *wrapped_vek;	/* DER of the container keybag's tag 2 */
	unsigned int wrapped_vek_len;
	u8 *kek;		/* unwrapped key-encryption key */
	unsigned int kek_len;
	bool found_bag;
	bool found_vek;
	bool found_kek;
};

/* ------------------------------------------------------------------------- */
/* AES-XTS                                                                   */

static int apfs_xts_crypt(struct crypto_skcipher *tfm, const void *src,
			  void *dst, u64 sector, size_t len, bool encrypt)
{
	struct skcipher_request *req;
	struct scatterlist src_sg, dst_sg;
	u8 iv[16] = {0};
	size_t done = 0;
	int err = 0;

	if (!tfm || !src || !dst || (len & 511))
		return -EINVAL;

	req = skcipher_request_alloc(tfm, GFP_NOFS);
	if (!req)
		return -ENOMEM;

	while (done < len) {
		put_unaligned_le64(sector, iv);
		sg_init_one(&src_sg, (const u8 *)src + done, 512);
		sg_init_one(&dst_sg, (u8 *)dst + done, 512);
		skcipher_request_set_crypt(req, &src_sg, &dst_sg, 512, iv);
		if (encrypt)
			err = crypto_skcipher_encrypt(req);
		else
			err = crypto_skcipher_decrypt(req);
		if (err)
			break;
		done += 512;
		sector++;
	}

	skcipher_request_free(req);
	return err;
}

static int apfs_xts_decrypt_key(const u8 *key, unsigned int key_len,
				const void *src, void *dst, u64 sector, size_t len)
{
	struct crypto_skcipher *tfm;
	int err;

	if (key_len != 32 && key_len != 64)
		return -EINVAL;

	tfm = crypto_alloc_skcipher("xts(aes)", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	err = crypto_skcipher_setkey(tfm, key, key_len);
	if (!err)
		err = apfs_xts_crypt(tfm, src, dst, sector, len, false);
	crypto_free_skcipher(tfm);
	return err;
}

int apfs_crypto_decrypt(struct super_block *sb, const void *src, void *dst,
			u64 sector, size_t len)
{
	struct apfs_sb_info *sbi = APFS_SB(sb);

	if (!sbi->s_xts)
		return -EOPNOTSUPP;
	return apfs_xts_crypt(sbi->s_xts, src, dst, sector, len, false);
}

bool apfs_crypto_ready(struct super_block *sb)
{
	return APFS_SB(sb)->s_xts != NULL;
}

/* ------------------------------------------------------------------------- */
/* PBKDF2-HMAC-SHA256                                                        */

struct apfs_hmac_ctx {
	struct crypto_shash *tfm;
	struct shash_desc *desc;
};

static int apfs_hmac_init(struct apfs_hmac_ctx *ctx, const u8 *key,
			  unsigned int key_len)
{
	int err;

	ctx->tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
	if (IS_ERR(ctx->tfm))
		return PTR_ERR(ctx->tfm);

	ctx->desc = kzalloc(sizeof(*ctx->desc) +
			    crypto_shash_descsize(ctx->tfm), GFP_NOFS);
	if (!ctx->desc) {
		crypto_free_shash(ctx->tfm);
		return -ENOMEM;
	}
	ctx->desc->tfm = ctx->tfm;
	err = crypto_shash_setkey(ctx->tfm, key, key_len);
	if (err) {
		kfree(ctx->desc);
		crypto_free_shash(ctx->tfm);
	}
	return err;
}

static void apfs_hmac_destroy(struct apfs_hmac_ctx *ctx)
{
	kfree(ctx->desc);
	crypto_free_shash(ctx->tfm);
}

static int apfs_hmac_once(struct apfs_hmac_ctx *ctx, const u8 *data,
			  unsigned int len, u8 out[32])
{
	int err;

	err = crypto_shash_init(ctx->desc);
	if (err)
		return err;
	if (len) {
		err = crypto_shash_update(ctx->desc, data, len);
		if (err)
			return err;
	}
	return crypto_shash_final(ctx->desc, out);
}

static int apfs_hmac_two(struct apfs_hmac_ctx *ctx, const u8 *a,
			 unsigned int alen, const u8 *b, unsigned int blen,
			 u8 out[32])
{
	int err;

	err = crypto_shash_init(ctx->desc);
	if (err)
		return err;
	if (alen) {
		err = crypto_shash_update(ctx->desc, a, alen);
		if (err)
			return err;
	}
	if (blen) {
		err = crypto_shash_update(ctx->desc, b, blen);
		if (err)
			return err;
	}
	return crypto_shash_final(ctx->desc, out);
}

static int apfs_pbkdf2(const u8 *password, unsigned int password_len,
		       const u8 *salt, unsigned int salt_len,
		       u32 iterations, u8 *out, unsigned int out_len)
{
	struct apfs_hmac_ctx ctx;
	u8 u[32], t[32], block[4];
	unsigned int produced = 0, block_index = 1;
	int err = 0;

	if (!iterations || !out_len)
		return -EINVAL;

	err = apfs_hmac_init(&ctx, password, password_len);
	if (err)
		return err;

	while (produced < out_len) {
		unsigned int take = min_t(unsigned int, 32, out_len - produced);
		u32 i;

		put_unaligned_be32(block_index, block);
		err = apfs_hmac_two(&ctx, salt, salt_len, block, sizeof(block), u);
		if (err)
			goto out;
		memcpy(t, u, 32);

		for (i = 1; i < iterations; i++) {
			err = apfs_hmac_once(&ctx, u, 32, u);
			if (err)
				goto out;
			for (int j = 0; j < 32; j++)
				t[j] ^= u[j];
		}

		memcpy(out + produced, t, take);
		produced += take;
		block_index++;
	}

out:
	memzero_explicit(u, sizeof(u));
	memzero_explicit(t, sizeof(t));
	apfs_hmac_destroy(&ctx);
	return err;
}

static int apfs_sha256(const u8 *data, unsigned int len, u8 out[32])
{
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	int err;

	tfm = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);
	desc = kzalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_NOFS);
	if (!desc) {
		crypto_free_shash(tfm);
		return -ENOMEM;
	}
	desc->tfm = tfm;
	err = crypto_shash_digest(desc, data, len, out);
	kfree(desc);
	crypto_free_shash(tfm);
	return err;
}

/* ------------------------------------------------------------------------- */
/* AES Key Wrap (RFC 3394)                                                   */

static int apfs_aes_kw_unwrap(const u8 *kek, unsigned int kek_len,
			      const u8 *wrapped, unsigned int wrapped_len,
			      u8 *out, unsigned int out_len)
{
	struct crypto_skcipher *tfm;
	struct skcipher_request *req;
	struct scatterlist sg;
	u8 block[16];
	unsigned int n, j;
	int i, err = 0;

	if (wrapped_len < 16 || (wrapped_len & 7))
		return -EINVAL;
	if (wrapped_len > out_len || wrapped_len > APFS_CP_MAX_WRAPPEDKEYSIZE)
		return -EINVAL;
	if (kek_len != 16 && kek_len != 32)
		return -EINVAL;

	/*
	 * RFC 3394 counts the wrapped payload in 64-bit blocks (n of them,
	 * plus one more block for the integrity vector) and the key-wrap
	 * counter runs t = n*j + i.  Using the ciphertext block count here
	 * would throw the counter off by one block per round.
	 */
	n = wrapped_len / 8 - 1;
	memcpy(out, wrapped, wrapped_len);

	tfm = crypto_alloc_skcipher("ecb(aes)", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);
	err = crypto_skcipher_setkey(tfm, kek, kek_len);
	if (err)
		goto out_free;
	req = skcipher_request_alloc(tfm, GFP_NOFS);
	if (!req) {
		err = -ENOMEM;
		goto out_free;
	}

	for (j = 6; j-- > 0; ) {
		for (i = n; i >= 1; i--) {
			u64 t = (u64)n * j + i;
			u64 a;

			memcpy(block, out, 8);
			a = get_unaligned_be64(block) ^ t;
			put_unaligned_be64(a, block);
			memcpy(block + 8, out + i * 8, 8);
			sg_init_one(&sg, block, sizeof(block));
			skcipher_request_set_crypt(req, &sg, &sg, sizeof(block), NULL);
			err = crypto_skcipher_decrypt(req);
			if (err)
				break;
			memcpy(out, block, 8);
			memcpy(out + i * 8, block + 8, 8);
		}
		if (err)
			break;
	}

	skcipher_request_free(req);
out_free:
	memzero_explicit(block, sizeof(block));
	crypto_free_skcipher(tfm);
	return err;
}

/* ------------------------------------------------------------------------- */
/* ASN.1 KEK records                                                         */

static int apfs_tlv_next(const u8 **p, const u8 *end, struct apfs_tlv *tlv)
{
	const u8 *cur = *p;
	u32 len;

	if (cur + 2 > end)
		return -EINVAL;
	tlv->tag = *cur++;
	if ((*cur & 0x80) == 0) {
		len = *cur++;
	} else if (*cur == 0x81) {
		cur++;
		if (cur + 1 > end)
			return -EINVAL;
		len = *cur++;
	} else if (*cur == 0x82) {
		cur++;
		if (cur + 2 > end)
			return -EINVAL;
		len = get_unaligned_be16(cur);
		cur += 2;
	} else {
		return -EINVAL;
	}
	if (cur + len > end)
		return -EINVAL;
	tlv->val = cur;
	tlv->len = len;
	*p = cur + len;
	return 0;
}

static int apfs_parse_kek(const u8 *data, unsigned int len, struct apfs_kek *kek)
{
	const u8 *p = data, *end = data + len;
	struct apfs_tlv outer, attr, nested, field;
	bool have_nested = false;
	int err;

	memset(kek, 0, sizeof(*kek));
	err = apfs_tlv_next(&p, end, &outer);
	if (err || outer.tag != 0x30)
		return -EINVAL;

	p = outer.val;
	end = outer.val + outer.len;
	while (p < end) {
		err = apfs_tlv_next(&p, end, &attr);
		if (err)
			return err;
		if (attr.tag == 0)
			break;
		if (attr.tag == 0xa3) {
			nested = attr;
			have_nested = true;
		}
	}
	if (!have_nested)
		return -EINVAL;

	p = nested.val;
	end = nested.val + nested.len;
	while (p < end) {
		err = apfs_tlv_next(&p, end, &field);
		if (err)
			return err;
		if (field.tag == 0)
			break;
		switch (field.tag) {
		case 0x81:
			if (field.len != 16)
				return -EINVAL;
			memcpy(kek->id, field.val, 16);
			kek->have_id = true;
			break;
		case 0x82:
			/*
			 * The key-info blob is a struct: flags first, then a
			 * couple of bytes and the key's UUID.  apfs-fuse
			 * accepts up to 0x16 bytes and only reads the flags,
			 * so do the same rather than insisting on one size.
			 */
			if (field.len < 4 || field.len > 0x16)
				return -EINVAL;
			kek->method = get_unaligned_le32(field.val);
			kek->have_method = true;
			break;
		case 0x83:
			if (field.len != 40 && field.len != 24)
				return -EINVAL;
			memcpy(kek->wrapped, field.val, field.len);
			kek->wrapped_len = field.len;
			kek->have_wrapped = true;
			break;
		case 0x84:
			if (!field.len || field.len > 8)
				return -EINVAL;
			for (unsigned int i = 0; i < field.len; i++)
				kek->iterations = (kek->iterations << 8) | field.val[i];
			break;
		case 0x85:
			if (field.len != 16)
				return -EINVAL;
			memcpy(kek->salt, field.val, 16);
			kek->have_salt = true;
			break;
		}
	}
	return 0;
}

/**
 * apfs_kek_unwrap - Unwrap a key record with a key-wrap key
 * @rec:	the parsed key record (KEK or VEK)
 * @key:	the wrapping key
 * @key_len:	16 or 32 bytes, independent of the wrapped record
 * @vek:	is @rec the volume's VEK record?
 * @out:	on return, the unwrapped key
 * @out_len:	on entry the size of @out, on return the key length
 *
 * The wrapped length decides how long the unwrapped key is, but not how long
 * the wrapping key is: a 128-bit KEK can wrap a 256-bit VEK.  Only the VEK
 * record uses the FileVault convention where a 128-bit method wraps half the
 * key and the other half is a hash of the first half and the record's UUID.
 *
 * Returns 0 on success or a negative error code in case of failure.
 */
static int apfs_kek_unwrap(const struct apfs_kek *rec, const u8 *key,
			   unsigned int key_len, bool vek, u8 *out,
			   unsigned int *out_len)
{
	u8 unwrapped[40];
	unsigned int capacity = *out_len;
	unsigned int used;
	int err;

	if (rec->method == 0 || rec->method == 16)
		used = 32;
	else if (rec->method == 2)
		used = 16;
	else
		return -EOPNOTSUPP;

	if (rec->wrapped_len != used + 8)
		return -EINVAL;
	if (key_len != 16 && key_len != 32)
		return -EINVAL;
	if (capacity < used || (vek && rec->method == 2 && capacity < 32))
		return -EINVAL;

	err = apfs_aes_kw_unwrap(key, key_len, rec->wrapped, rec->wrapped_len,
				 unwrapped, sizeof(unwrapped));
	if (err)
		return err;

	/* RFC 3394 leaves the integrity vector in the first eight bytes. */
	if (get_unaligned_be64(unwrapped) != 0xa6a6a6a6a6a6a6a6ULL) {
		err = -EINVAL;
		goto out;
	}

	memcpy(out, unwrapped + 8, used);
	*out_len = used;
	if (vek && rec->method == 2) {
		u8 hash_in[32];
		u8 hash[32];

		/* FileVault-converted volumes wrap only the first half */
		if (!rec->have_id) {
			err = -EINVAL;
			goto out;
		}
		memcpy(hash_in, out, 16);
		memcpy(hash_in + 16, rec->id, 16);
		err = apfs_sha256(hash_in, sizeof(hash_in), hash);
		if (err)
			goto out;
		memcpy(out + 16, hash, 16);
		*out_len = 32;
		memzero_explicit(hash, sizeof(hash));
	}

out:
	memzero_explicit(unwrapped, sizeof(unwrapped));
	return err;
}

/**
 * apfs_kek_unlock_password - Unwrap a keybag's KEK record with a password
 * @kek:	the parsed KEK record
 * @password:	the user's password
 * @out:	on return, the unwrapped KEK (16 or 32 bytes)
 * @out_len:	on entry the size of @out, on return the KEK length
 *
 * Returns 0 on success or a negative error code in case of failure.
 */
static int apfs_kek_unlock_password(const struct apfs_kek *kek,
				    const char *password, u8 *out,
				    unsigned int *out_len)
{
	u8 derived[32];
	unsigned int key_len;
	int err;

	if (!kek->have_method || !kek->have_wrapped || !kek->have_salt ||
	    !kek->iterations)
		return -EINVAL;

	if (kek->method == 0 || kek->method == 16)
		key_len = 32;
	else if (kek->method == 2)
		key_len = 16;
	else
		return -EOPNOTSUPP;

	err = apfs_pbkdf2((const u8 *)password, strlen(password), kek->salt,
			  16, kek->iterations, derived, key_len);
	if (err)
		goto out;
	err = apfs_kek_unwrap(kek, derived, key_len, false /* KEK */, out,
			      out_len);
out:
	memzero_explicit(derived, sizeof(derived));
	return err;
}

/* ------------------------------------------------------------------------- */
/* Keybag parsing                                                            */

static bool apfs_uuid_matches(const u8 *a, const u8 *b)
{
	return !memcmp(a, b, 16);
}

static void apfs_container_keybag_entry(struct apfs_keybag_scan *scan,
					const u8 *uuid, u16 tag,
					const u8 *data, unsigned int len)
{
	if (!apfs_uuid_matches(uuid, scan->volume_uuid))
		return;

	if (tag == APFS_KEYBAG_TAG_VOLBAG && len == 16) {
		scan->bag_block = get_unaligned_le64(data);
		scan->bag_count = get_unaligned_le64(data + 8);
		scan->found_bag = true;
	} else if (tag == APFS_KEYBAG_TAG_VOLKEY && len >= 24) {
		/* The tag 2 entry is the DER-encoded, wrapped VEK record */
		kfree(scan->wrapped_vek);
		scan->wrapped_vek = kmemdup(data, len, GFP_NOFS);
		if (scan->wrapped_vek) {
			scan->wrapped_vek_len = len;
			scan->found_vek = true;
		}
	}
}

static void apfs_volume_keybag_entry(struct apfs_keybag_scan *scan,
				     const u8 *uuid, u16 tag,
				     const u8 *data, unsigned int len)
{
	struct apfs_kek kek;

	(void)uuid;
	if (tag != APFS_KEYBAG_TAG_VOLBAG || !scan->password)
		return;
	if (apfs_parse_kek(data, len, &kek))
		return;
	if (!apfs_kek_unlock_password(&kek, scan->password, scan->kek,
				      &scan->kek_len))
		scan->found_kek = true;
}

static int apfs_scan_keybag(struct super_block *sb, u64 start, u64 count,
			    const u8 *uuid, int magic,
			    void (*fn)(struct apfs_keybag_scan *, const u8 *,
				       u16, const u8 *, unsigned int),
			    struct apfs_keybag_scan *scan)
{
	struct buffer_head *bh;
	u8 *cipher = NULL, *plain = NULL;
	u8 key[32];
	struct apfs_kb_locker *locker;
	unsigned int i, off;
	int err = 0;

	if (!count || count > 1024)
		return -EINVAL;

	cipher = kmalloc(count * sb->s_blocksize, GFP_NOFS);
	plain = kmalloc(count * sb->s_blocksize, GFP_NOFS);
	if (!cipher || !plain) {
		err = -ENOMEM;
		goto out;
	}
	for (i = 0; i < count; i++) {
		bh = apfs_sb_bread(sb, start + i);
		if (!bh) {
			err = -EIO;
			goto out;
		}
		memcpy(cipher + i * sb->s_blocksize, bh->b_data, sb->s_blocksize);
		brelse(bh);
	}

	memcpy(key, uuid, 16);
	memcpy(key + 16, uuid, 16);
	err = apfs_xts_decrypt_key(key, sizeof(key), cipher, plain,
				   start * sb->s_blocksize / 512,
				   count * sb->s_blocksize);
	if (err)
		goto out;

	if (get_unaligned_le32(plain + 24) != magic) {
		err = -EINVAL;
		goto out;
	}

	locker = (struct apfs_kb_locker *)(plain + 32);
	off = 32 + sizeof(*locker);
	for (i = 0; i < le16_to_cpu(locker->kl_nkeys); i++) {
		struct apfs_keybag_entry *entry;
		unsigned int total;

		if (off + sizeof(*entry) > count * sb->s_blocksize) {
			err = -EINVAL;
			goto out;
		}
		entry = (struct apfs_keybag_entry *)(plain + off);
		total = sizeof(*entry) + le16_to_cpu(entry->ke_keylen);
		if (total > count * sb->s_blocksize - off) {
			err = -EINVAL;
			goto out;
		}
		fn(scan, (const u8 *)entry->ke_uuid, le16_to_cpu(entry->ke_tag),
		   entry->ke_keydata, le16_to_cpu(entry->ke_keylen));

		off += total;
		off = ALIGN(off, 16);
	}

out:
	kfree(cipher);
	if (plain) {
		memzero_explicit(plain, count * sb->s_blocksize);
		kfree(plain);
	}
	return err;
}

int apfs_crypto_unlock(struct super_block *sb, const char *password)
{
	struct apfs_sb_info *sbi = APFS_SB(sb);
	struct apfs_nx_superblock *nx = sbi->s_nxi->nx_raw;
	struct apfs_superblock *vsb = sbi->s_vsb_raw;
	struct apfs_keybag_scan scan, vol_scan;
	struct apfs_kek vek_rec;
	u8 master[32];
	u8 kek[32];
	unsigned int master_len = sizeof(master);
	u64 start, count;
	int err;

	if (!password || !*password)
		return -EINVAL;
	if (!le64_to_cpu(nx->nx_keylocker.pr_block_count))
		return -EOPNOTSUPP;

	memset(&scan, 0, sizeof(scan));
	scan.volume_uuid = (const u8 *)vsb->apfs_vol_uuid;

	start = le64_to_cpu(nx->nx_keylocker.pr_start_paddr);
	count = le64_to_cpu(nx->nx_keylocker.pr_block_count);
	err = apfs_scan_keybag(sb, start, count, (const u8 *)nx->nx_uuid,
			       APFS_KEYBAG_MAGIC_KEYS,
			       apfs_container_keybag_entry, &scan);
	if (err || !scan.found_bag || !scan.found_vek)
		goto out;

	memset(&vol_scan, 0, sizeof(vol_scan));
	vol_scan.volume_uuid = (const u8 *)vsb->apfs_vol_uuid;
	vol_scan.password = password;
	vol_scan.kek = kek;

	err = apfs_scan_keybag(sb, scan.bag_block, scan.bag_count,
			       (const u8 *)vsb->apfs_vol_uuid,
			       APFS_KEYBAG_MAGIC_RECS,
			       apfs_volume_keybag_entry, &vol_scan);
	if (err || !vol_scan.found_kek) {
		err = err ?: -EINVAL;
		goto out;
	}

	if (apfs_parse_kek(scan.wrapped_vek, scan.wrapped_vek_len, &vek_rec)) {
		err = -EINVAL;
		goto out;
	}
	if (!vek_rec.have_wrapped || !vek_rec.have_method) {
		err = -EINVAL;
		goto out;
	}
	err = apfs_kek_unwrap(&vek_rec, vol_scan.kek, vol_scan.kek_len,
			      true /* VEK */, master, &master_len);
	if (err)
		goto out;
	if (master_len != sizeof(master)) {
		err = -EINVAL;
		goto out;
	}

	sbi->s_master_key = kmemdup(master, sizeof(master), GFP_NOFS);
	if (!sbi->s_master_key) {
		err = -ENOMEM;
		goto out;
	}
	sbi->s_master_key_len = sizeof(master);

	sbi->s_xts = crypto_alloc_skcipher("xts(aes)", 0, 0);
	if (IS_ERR(sbi->s_xts)) {
		err = PTR_ERR(sbi->s_xts);
		sbi->s_xts = NULL;
		goto out;
	}
	err = crypto_skcipher_setkey(sbi->s_xts, sbi->s_master_key,
				     sbi->s_master_key_len);
	if (err) {
		crypto_free_skcipher(sbi->s_xts);
		sbi->s_xts = NULL;
		goto out;
	}

	apfs_info(sb, "unlocked software-encrypted volume keybag");
out:
	if (scan.wrapped_vek) {
		memzero_explicit(scan.wrapped_vek, scan.wrapped_vek_len);
		kfree(scan.wrapped_vek);
	}
	memzero_explicit(kek, sizeof(kek));
	memzero_explicit(master, sizeof(master));
	return err;
}

/* ------------------------------------------------------------------------- */
/**
 * apfs_dstream_decrypt - Decrypt one block of a data stream
 * @dstream:	data stream the block belongs to
 * @ext:	the extent record that holds the block
 * @blk_off:	offset of the block within the extent, in blocks
 * @src:	ciphertext, one or more blocks
 * @dst:	where to put the plaintext (may be NULL to mean @src)
 * @len:	number of bytes, a multiple of 512
 *
 * The crypto identifier of the extent says which key decrypts the extent:
 * APFS_CRYPTO_SW_ID means the volume key, and the identifiers that mean the
 * data is in the clear are copied.  Any other identifier names a per-file key;
 * that is a hardware-encryption feature (the reference requires hardware for
 * PFK, and the crypto state records it uses are iOS-only), so it is refused
 * rather than guessed at.
 *
 * Returns 0 on success or a negative error code in case of failure.
 */
int apfs_dstream_decrypt(struct apfs_dstream_info *dstream,
			 const struct apfs_file_extent *ext, u64 blk_off,
			 const void *src, void *dst, size_t len)
{
	struct super_block *sb = dstream->ds_sb;
	struct apfs_sb_info *sbi = APFS_SB(sb);
	struct crypto_skcipher *tfm = sbi->s_xts;
	u64 crypto_id = ext->crypto_id;
	u64 tweak;

	if (!dst)
		dst = (void *)src;
	if (!tfm)
		return -EOPNOTSUPP;
	if (len & 511)
		return -EINVAL;

	switch (crypto_id) {
	case APFS_CRYPTO_NULL:
	case APFS_CRYPTO_UNENCRYPTED:
	case APFS_CRYPTO_SPARSE_BUNDLE:
		/* Stored in the clear even on a volume that is otherwise keys */
		memcpy(dst, src, len);
		return 0;
	case APFS_CRYPTO_SW_RAW:
	case APFS_CRYPTO_SW_ID:
		break;	/* the volume key encrypts this extent */
	case APFS_UNASSIGNED_CRYPTO_ID:
		return -EINVAL;
	default:
		/*
		 * A per-file key: those are wrapped by hardware, and the
		 * catalog records that name them exist only on iOS.  Do not
		 * hand back ciphertext, and do not pretend a software keybag
		 * can unwrap them.
		 */
		apfs_err(sb, "per-file encryption needs hardware keys (id 0x%llx)",
			 (unsigned long long)crypto_id);
		return -EOPNOTSUPP;
	}

	tweak = (crypto_id + blk_off) * (sb->s_blocksize / 512);
	return apfs_xts_crypt(tfm, src, dst, tweak, len, false);
}

void apfs_crypto_free(struct apfs_sb_info *sbi)
{
	if (sbi->s_xts) {
		crypto_free_skcipher(sbi->s_xts);
		sbi->s_xts = NULL;
	}
	if (sbi->s_master_key) {
		memzero_explicit(sbi->s_master_key, sbi->s_master_key_len);
		kfree(sbi->s_master_key);
		sbi->s_master_key = NULL;
		sbi->s_master_key_len = 0;
	}
}
