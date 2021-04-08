/**
 * @file t-sm2-ecdh.c
 * @author suntus (suntus.4@gmail.com)
 * @brief
 * @version 0.1
 * @date 2021-04-08
 *
 * @copyright Copyright (c) 2021
 *
 * cc -o t-sm2-ecdh -I /usr/local/openssl/111/include -L /usr/local/openssl/111/lib -lcrypto -g -O0
 * t-sm2-ecdh.c
 *
 * export LD_LIBRARY_PATH=/usr/local/openssl/111/lib
 * ./t-sm2-ecdh
 */
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>

#define CERTVRIFY_SM2_ID     "1234567812345678"
#define CERTVRIFY_SM2_ID_LEN sizeof(CERTVRIFY_SM2_ID) - 1

uint8_t msg[] = "hello world";
size_t msg_len = sizeof(msg) - 1;
uint8_t out[512];
size_t out_len = sizeof(out);
uint8_t tmp_buf[542];
size_t tmp_buf_len = sizeof(tmp_buf);

void gen_sm2_key(EVP_PKEY **sm2_pkey)
{
    EVP_PKEY_CTX *pctx = NULL;
    int ret;

    // 生成SM2密钥
    // SM2是基于ECC的，相当于先建一个壳子
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    assert(pctx);

    ret = EVP_PKEY_keygen_init(pctx);
    assert(ret > 0);

    // 设置ECC密钥生成时使用的曲线，这里指定SM2
    ret = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_sm2);
    assert(ret > 0);

    ret = EVP_PKEY_keygen(pctx, sm2_pkey);
    assert(ret > 0);

    EVP_PKEY_CTX_free(pctx);
}

void tt_sign_and_verify()
{
    int ret;
    EVP_PKEY *sm2_pkey = NULL;
    EVP_PKEY_CTX *sm2_pctx = NULL;
    EVP_PKEY_CTX *sm2_vfy_pctx = NULL;
    EVP_MD_CTX *mctx = NULL;
    EVP_MD_CTX *mvctx = NULL;
    BIO *bio;
    char *hex_str;

    bio = BIO_new_fp(stdout, BIO_NOCLOSE);

    gen_sm2_key(&sm2_pkey);

    // EVP_PKEY默认使用ECDSA，需要调用该接口设置为SM2算法
    ret = EVP_PKEY_set_alias_type(sm2_pkey, NID_sm2);
    assert(ret == 1);

    // 签名
    sm2_pctx = EVP_PKEY_CTX_new(sm2_pkey, NULL);
    assert(sm2_pctx);

    // SM2需要设置ID
    ret = EVP_PKEY_CTX_set1_id(sm2_pctx, CERTVRIFY_SM2_ID, CERTVRIFY_SM2_ID_LEN);
    assert(ret == 1);

    // openssl有分离的先hash再签名的接口，也有可以直接hash+签名的接口，这里使用单独的接口
    mctx = EVP_MD_CTX_new();
    assert(mctx);

    // 使用SM2进行签名的时候，需要提前申请 sm2_pctx，并在这里设置给 mctx，不能在使用下边的
    // EVP_DigestSignInit() 获取。
    // 主要是给EVP_DigestSignInit()和EVP_DigestVerifyInit()的调用提供一些特殊的操作。
    EVP_MD_CTX_set_pkey_ctx(mctx, sm2_pctx);

    ret = EVP_DigestSignInit(mctx, NULL, EVP_sm3(), NULL, sm2_pkey);
    assert(ret == 1);

    ret = EVP_DigestSign(mctx, out, &out_len, msg, msg_len);
    assert(ret == 1);

    hex_str = OPENSSL_buf2hexstr(out, out_len);
    BIO_printf(bio, "signed(%d):\n%s\n", out_len, hex_str);
    OPENSSL_free(hex_str);

    // verify
    sm2_vfy_pctx = EVP_PKEY_CTX_new(sm2_pkey, NULL);
    assert(sm2_vfy_pctx);

    ret = EVP_PKEY_CTX_set1_id(sm2_vfy_pctx, CERTVRIFY_SM2_ID, CERTVRIFY_SM2_ID_LEN);
    assert(ret == 1);

    mvctx = EVP_MD_CTX_new();
    assert(mvctx);

    EVP_MD_CTX_set_pkey_ctx(mvctx, sm2_vfy_pctx);

    ret = EVP_DigestVerifyInit(mvctx, NULL, EVP_sm3(), NULL, sm2_pkey);
    assert(ret == 1);

    ret = EVP_DigestVerify(mvctx, out, out_len, msg, msg_len);
    assert(ret == 1);

    BIO_printf(bio, "=============>test sign and verify success.\n");
}

void tt_enc_and_dec()
{
    int ret;
    EVP_PKEY *sm2_pkey = NULL;
    EVP_PKEY_CTX *enc_pctx = NULL;
    EVP_PKEY_CTX *dec_pctx = NULL;
    BIO *bio;
    char *hex_str;

    bio = BIO_new_fp(stdout, BIO_NOCLOSE);

    gen_sm2_key(&sm2_pkey);

    // EVP_PKEY默认使用ECDSA，需要调用该接口设置为SM2算法
    ret = EVP_PKEY_set_alias_type(sm2_pkey, NID_sm2);
    assert(ret == 1);

    enc_pctx = EVP_PKEY_CTX_new(sm2_pkey, NULL);
    assert(enc_pctx);

    ret = EVP_PKEY_encrypt_init(enc_pctx);
    assert(ret == 1);

    ret = EVP_PKEY_encrypt(enc_pctx, out, &out_len, msg, msg_len);
    assert(ret == 1);

    hex_str = OPENSSL_buf2hexstr(out, out_len);
    BIO_printf(bio, "enc(%d):\n%s\n", out_len, hex_str);
    OPENSSL_free(hex_str);

    dec_pctx = EVP_PKEY_CTX_new(sm2_pkey, NULL);
    assert(dec_pctx);

    ret = EVP_PKEY_decrypt_init(dec_pctx);
    assert(ret == 1);

    ret = EVP_PKEY_decrypt(dec_pctx, tmp_buf, &tmp_buf_len, out, out_len);
    assert(ret == 1);

    tmp_buf[tmp_buf_len] = '\0';
    BIO_printf(bio, "dec(%d):\n%s\n", tmp_buf_len, tmp_buf);

    ret = memcmp(msg, tmp_buf, tmp_buf_len);
    assert(ret == 0);

    BIO_printf(bio, "=============>test enc and dec success.\n");
}

void tt_ecdhe_over_sm2()
{
    int ret;
    BIO *bio;
    EVP_PKEY *sm2_pkey = NULL;
    EVP_PKEY *sm2_peer_pkey = NULL;
    EVP_PKEY_CTX *ecdhe_ctx = NULL;
    unsigned char *key;
    size_t key_len;
    char *hex_str;

    bio = BIO_new_fp(stdout, BIO_NOCLOSE);

    gen_sm2_key(&sm2_pkey);
    gen_sm2_key(&sm2_peer_pkey);

    // 注意这里没有调用 EVP_PKEY_set_alias_type()，使用的是基本的ECDH协商

    ecdhe_ctx = EVP_PKEY_CTX_new(sm2_pkey, NULL);
    assert(ecdhe_ctx);

    ret = EVP_PKEY_derive_init(ecdhe_ctx);
    assert(ret == 1);

    ret = EVP_PKEY_derive_set_peer(ecdhe_ctx, sm2_peer_pkey);
    assert(ret == 1);

    ret = EVP_PKEY_derive(ecdhe_ctx, NULL, &key_len);
    assert(ret == 1);

    key = OPENSSL_malloc(key_len);
    assert(key);

    ret = EVP_PKEY_derive(ecdhe_ctx, key, &key_len);
    assert(ret == 1);

    hex_str = OPENSSL_buf2hexstr(key, key_len);
    BIO_printf(bio, "derive ecdhe key(%d):\n%s\n", key_len, hex_str);
    OPENSSL_free(hex_str);

    OPENSSL_free(key);

    BIO_printf(bio, "=============>test ecdhe over sm2 success.\n");
}

int main()
{
    tt_sign_and_verify();
    tt_enc_and_dec();
    tt_ecdhe_over_sm2();

    return 0;
}
