#include "sm3.h"
#include <stdio.h>
#include<stdlib.h>
#include<string.h>
#include "miracl.h"
#include "mirdef.h"
#include <time.h>

static big p;
static big a;
static big b;
static big n;
static epoint* G;

static big k; 

struct FPECC
{
	char* p;
	char* a;
	char* b;
	char* n;
	char* x;
	char* y;
}para = {
	"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
	"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
	"28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
	"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
	"32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
	"BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",
};
//A1-A3 随机数rA的值
unsigned char randkeya[] = { 0x83,0xA2,0xC9,0xC8,0xB9,0x6E,0x5A,0xF7,0x0B,0xD4,0x80,0xB4,0x72,0x40,0x9A,0x9A,0x32,0x72,0x57,0xF1,0xEB,0xB7,0x3F,0x5B,0x07,0x33,0x54,0xB2,0x48,0x66,0x85,0x63 };
//B1-B9 随机数rB的值
unsigned char randkeyb[] = { 0x33,0xFE,0x21,0x94,0x03,0x42,0x16,0x1C,0x55,0x61,0x9C,0x4A,0x0C,0x06,0x02,0x93,0xD5,0x43,0xC8,0x0A,0xF1,0x97,0x48,0xCE,0x17,0x6D,0x83,0x47,0x7D,0xE7,0x1C,0x80 };

unsigned char enkey[32] = {
0xB1,0x6B,0xA0,0xDA,0x27,0xC5,0x24,0x9A,0xF6,0x1D,0x6E,0x6E,0x12,0xD1,0x59,0xA5,
0xB6,0x74,0x64,0x34,0xEB,0xD6,0x1B,0x62,0xEA,0xEB,0xC3,0xCC,0x31,0x5E,0x42,0x1D,
};

//明文加密成16比特密文字符串
int enrand(unsigned char* r, int rlen)
{
	aes a;
	char key[16]; //密钥
	char iv[16];
	int  i;
	memcpy(key, enkey, 16);
	memcpy(iv, enkey, 16);

	if (!aes_init(&a, MR_ECB, 16, key, iv))
	{
		return 0;
	}

	for (i = 0; i < rlen; i += 16)
	{
		aes_encrypt(&a, (char*)r + i);
	}

	aes_end(&a);
	return 0;
}
//将16比特密文字符串解密为明文
int derand(unsigned char* r, int rlen)
{
	aes a;
	char key[16];
	char iv[16];
	int i;

	memcpy(key, enkey, 16);
	memcpy(iv, enkey, 16);

	if (!aes_init(&a, MR_ECB, 16, key, iv))
	{
		return 0;
	}

	for (i = 0; i < rlen; i += 16)
	{
		aes_decrypt(&a, (char*)r + i);
	}

	aes_end(&a);
	return 0;
}

//每32项为一行输出buf
void PrintBuf(unsigned char* buf, int buflen)
{
	int i;
	printf("\n");
	printf("len = %d\n", buflen);
	for (i = 0; i < buflen; i++) {
		if (i % 32 != 31)
			printf("%02X", buf[i]);
		else
			printf("%02X\n", buf[i]);
	}
	printf("\n");
	return;
}


//公钥私钥生成
void initSM2(unsigned char* wx, int *wxlen, unsigned char* wy, int *wylen, unsigned char* privkey, int* privkeylen)
{
	struct FPECC* cfig = &para;
	big x, y, key1;
	miracl* mip = mirsys(20, 0);

	mip->IOBASE = 16;

	p = mirvar(0);
	a = mirvar(0);
	b = mirvar(0);
	n = mirvar(0);
	x = mirvar(0);
	y = mirvar(0);

	key1 = mirvar(0);

	cinstr(p, cfig->p);
	cinstr(a, cfig->a);
	cinstr(b, cfig->b);
	cinstr(n, cfig->n);
	cinstr(x, cfig->x);
	cinstr(y, cfig->y);

	ecurve_init(a, b, p, MR_AFFINE);
	G = epoint_init();
	epoint_set(x, y, 0, G);

	bigrand(n, key1);
	ecurve_mult(key1, G, G);
	epoint_get(G, x, y);

	*wxlen = big_to_bytes(32, x, (char*)wx, TRUE); //公钥x长度 设置为32位
	*wylen = big_to_bytes(32, y, (char*)wy, TRUE); //公钥y长度 设置为32位
	*privkeylen = big_to_bytes(32, key1, (char*)privkey, TRUE);//私钥长度 设置为32位
}


//根据用户ID及公钥，求密码杂凑值Z
int genZSM3(unsigned char* userid, int userid_len, unsigned char* xa, int xa_len, unsigned char* ya, int ya_len, unsigned char* z)
{
	unsigned char* buf;
	int userid_bitlen;
	
	if ((xa_len > 32) || (ya_len > 32))
		return -1;
	buf = malloc(2 + userid_len + 128 + 32 + 32);
	if (buf == NULL)
		return -1;

	userid_bitlen = userid_len << 3;
	buf[0] = (userid_bitlen >> 8) & 0xFF;
	buf[1] = userid_bitlen & 0xFF;

	memcpy(buf + 2, userid, userid_len);
	

	memset(buf + 2 + userid_len + 128, 0, 64);
	memcpy(buf + 2 + userid_len + 128 + 32 - xa_len, xa, 32);
	memcpy(buf + 2 + userid_len + 128 + 32 + 32 - ya_len, ya, 32);

	sm3(buf, 2 + userid_len + 128 + 32 + 32, z);
	free(buf);
	printf("sm3_z: ");
	PrintBuf(z, 32);
	return 0;
}

//密钥派生函数
int kdf(unsigned char* z, int zlen, int klen, unsigned char* kbuf)
{
	/*
	return 0: kbuf is 0, unusable
		   1: kbuf is OK
	*/
	unsigned char* buf;
	unsigned char digest[32];
	unsigned int ct = 0x00000001;
	int i, m, n;
	unsigned char* p;

	buf = malloc(zlen + 4);
	if (buf == NULL)
		return 0;

	memcpy(buf, z, zlen);

	m = klen / 32;
	n = klen % 32;
	p = kbuf;

	for (i = 0; i < m; i++)
	{
		buf[zlen] = (ct >> 24) & 0xFF;
		buf[zlen + 1] = (ct >> 16) & 0xFF;
		buf[zlen + 2] = (ct >> 8) & 0xFF;
		buf[zlen + 3] = ct & 0xFF;
		sm3(buf, zlen + 4, p);
		p += 32;
		ct++;
	}

	if (n != 0)
	{
		buf[zlen] = (ct >> 24) & 0xFF;
		buf[zlen + 1] = (ct >> 16) & 0xFF;
		buf[zlen + 2] = (ct >> 8) & 0xFF;
		buf[zlen + 3] = ct & 0xFF;
		sm3(buf, zlen + 4, digest);
	}
	memcpy(p, digest, n);
	free(buf);
	return 1;
}

//A产生一对临时公钥(kx1, ky1)和相应的随机数,公钥发送给对方，随机数ra自己保存
void a1_3SM2(unsigned char* kx1, int* kx1len,
	unsigned char* ky1, int* ky1len, unsigned char* ra, int* ralen)
{
	struct FPECC* cfig = &para;
	big x1, y1;
	big x, y;
	miracl* mip = mirsys(20, 0);

	mip->IOBASE = 16;
	k = mirvar(0);
	x1 = mirvar(0);
	y1 = mirvar(0);
	p = mirvar(0);
	a = mirvar(0);
	b = mirvar(0);
	n = mirvar(0);
	x = mirvar(0);
	y = mirvar(0);

	cinstr(p, cfig->p);
	cinstr(a, cfig->a);
	cinstr(b, cfig->b);
	cinstr(n, cfig->n);
	cinstr(x, cfig->x);
	cinstr(y, cfig->y);
	ecurve_init(a, b, p, MR_AFFINE);
	G = epoint_init();
	epoint_set(x, y, 0, G);

	bytes_to_big(32, (char*)randkeya, k);
	//A1
	bigrand(n, k);
	//A2
	ecurve_mult(k, G, G);
	epoint_get(G, x1, y1);
	
	*kx1len = big_to_bytes(32, x1, (char*)kx1, TRUE);
	*ky1len = big_to_bytes(32, y1, (char*)ky1, TRUE);
	*ralen = big_to_bytes(32, k, (char*)ra, TRUE);
	enrand(ra, *ralen);
}

//B产生密钥kbbuf和临时公钥(kx2, ky2),(xv, yv),sb,(kx2, ky2)和sb发送给A，kbbuf和(xv, yv)B自己保存
int b1_9SM2(
	unsigned char* kx1, int kx1len,
	unsigned char* ky1, int ky1len,
	unsigned char* pax, int paxlen,
	unsigned char* pay, int paylen,
	unsigned char* private_b, int private_b_len,
	unsigned char* pbx, int pbxlen,
	unsigned char* pby, int pbylen, 
	unsigned char* ida, int idalen,
	unsigned char* idb, int idblen,
	unsigned int  kblen,
	unsigned char* kbbuf,
	unsigned char* kx2, int* kx2len,
	unsigned char* ky2, int* ky2len,
	unsigned char* xv, int* xvlen,
	unsigned char* yv, int* yvlen,
	unsigned char* sb)
{
	struct FPECC* cfig = &para;
	big x1, y1, x2, y2, _x1, _x2, db, tb;
	big x, y;
	epoint* w;
	unsigned char kx1buf[32], ky1buf[32];
	unsigned char kx2buf[32], ky2buf[32];
	unsigned char xvbuf[32];
	unsigned char yvbuf[32];
	unsigned char paxbuf[32];
	unsigned char paybuf[32];
	unsigned char buf[256];

	unsigned char za[32];
	unsigned char zb[32];

	miracl* mip = mirsys(20, 0);
	mip->IOBASE = 16;
	k = mirvar(0);
	x1 = mirvar(0);
	y1 = mirvar(0);
	x2 = mirvar(0);
	y2 = mirvar(0);
	_x1 = mirvar(0);
	_x2 = mirvar(0);
	tb = mirvar(0);
	db = mirvar(0);

	p = mirvar(0);
	a = mirvar(0);
	b = mirvar(0);
	n = mirvar(0);
	x = mirvar(0);
	y = mirvar(0);

	cinstr(p, cfig->p);
	cinstr(a, cfig->a);
	cinstr(b, cfig->b);
	cinstr(n, cfig->n);
	cinstr(x, cfig->x);
	cinstr(y, cfig->y);
	ecurve_init(a, b, p, MR_AFFINE);
	G = epoint_init();
	w = epoint_init();
	epoint_set(x, y, 0, G);

	genZSM3(ida, idalen, pax, paxlen, pay, paylen, za);
	genZSM3(idb, idblen, pbx, pbxlen, pby, pbylen, zb);
	printf("za & zb: ");
	PrintBuf(za, 32);
	PrintBuf(zb, 32);

	bigrand(n, k); //B1 

	ecurve_mult(k, G, G); //B2
	epoint_get(G, x2, y2);

	big_to_bytes(32, x2, (char*)kx2buf, TRUE);//B3
	big_to_bytes(32, y2, (char*)ky2buf, TRUE);
	printf("RB(x2, y2): ");
	PrintBuf(kx2buf, 32);
	PrintBuf(ky2buf, 32);


	memcpy(kx2, kx2buf, 32);
	memcpy(ky2, ky2buf, 32);
	*kx2len = 32;
	*ky2len = 32;

	/*
	2^w-1是除了首位为0其他都为1与x2与运算x2首位变为0 再加2^w 表示x2首位变为1，其他位不变
	所以可以直接用异或实现_x2=2^w+(x2&(2^w-1))，以下涉及到相关运算同理
	*/
	memcpy(buf, kx2buf + 16, 16);
	buf[0] |= 0x80;
	bytes_to_big(16, (char*)buf, _x2); //_x2=2^w+(x2&(2^w-1))
	
	bytes_to_big(private_b_len, (char*)private_b, db);
	mad(_x2, k, db, n, n, tb);  //B4 tb=(db+_x2*k)modn
	
	bytes_to_big(kx1len, (char*)kx1, x1);
	bytes_to_big(ky1len, (char*)ky1, y1);

	if (!epoint_set(x1, y1, 0, G))
		return 0;

	big_to_bytes(32, x1, (char*)kx1buf, TRUE);
	big_to_bytes(32, y1, (char*)ky1buf, TRUE);

	/*
	2^w-1是除了首位为0其他都为1与x1与运算x1首位变为0 再加2^w 表示x1首位变为1，其他位不变
	所以可以直接用异或实现_x1=2^w+(x&(2^w-1))
	*/
	memcpy(buf, kx1buf + 16, 16);
	buf[0] |= 0x80; //buf第一个字节最高位为1 其他部分不变 相当于2^w-1
	bytes_to_big(16, (char*)buf, _x1); //B5 _x1=2^w+(x1&(2^w-1))

	bytes_to_big(paxlen, (char*)pax, x);
	bytes_to_big(paylen, (char*)pay, y);
	big_to_bytes(32, x, (char*)paxbuf, TRUE);
	big_to_bytes(32, y, (char*)paybuf, TRUE);

	if (!epoint_set(x, y, 0, w))
		return 0;

	ecurve_mult(_x1, G, G); //[_x1]RA
	ecurve_add(w, G); //PA+[_x1]RA
	ecurve_mult(tb, G, G); //B6 余因子h=1 tb不变 [h*tb](PA+[_x1]RA)
	if (point_at_infinity(G))
		return 0;
	
	epoint_get(G, x, y);
	big_to_bytes(32, x, (char*)xvbuf, TRUE);
	big_to_bytes(32, y, (char*)yvbuf, TRUE);

	printf("xv & yv: ");
	PrintBuf(xvbuf, 32);
	PrintBuf(yvbuf, 32);

	//B7
	memcpy(buf, xvbuf, 32);
	memcpy(buf + 32, yvbuf, 32);
	memcpy(buf + 64, za, 32);
	memcpy(buf + 96, zb, 32);
	kdf(buf, 128, kblen, kbbuf);
	printf("Kb: ");
	PrintBuf(kbbuf, kblen);

	if (sb != NULL)
	{
		memcpy(buf, xvbuf, 32);
		memcpy(buf + 32, za, 32);
		memcpy(buf + 64, zb, 32);
		memcpy(buf + 96, kx1buf, 32);
		memcpy(buf + 128, ky1buf, 32);
		memcpy(buf + 160, kx2buf, 32);
		memcpy(buf + 192, ky2buf, 32);
		sm3(buf, 32 * 7, sb);
		//B8
		buf[0] = 0x02;
		memcpy(buf + 1, yvbuf, 32);
		memcpy(buf + 33, sb, 32);
		sm3(buf, 65, sb);
	}

	if (xv != NULL)
	{
		memcpy(xv, xvbuf, 32);
		*xvlen = 32;
		enrand(xv, *xvlen);
	}

	if (yv != NULL)
	{
		memcpy(yv, yvbuf, 32);
		*yvlen = 32;
		enrand(yv, *yvlen);
	}
	//B9
	printf("Sb: ");
	PrintBuf(sb, 32);
	return 1;
}



//A协商出密钥kabuf，同时产生s1和sa，s1和kabuf自己保存，sa发送给接收方，用于确认协商过程的正确性
int a4_10SM2(unsigned char* kx1, int kx1len,
	unsigned char* ky1, int ky1len,
	unsigned char* pax, int paxlen,
	unsigned char* pay, int paylen,
	unsigned char* private_a, int private_a_len,
	unsigned char* pbx, int pbxlen,
	unsigned char* pby, int pbylen,
	unsigned char* ida, int idalen,
	unsigned char* idb, int idblen,
	unsigned char* kx2, int kx2len,
	unsigned char* ky2, int ky2len,
	unsigned char* ra, int ralen,
	unsigned int  kalen,
	unsigned char* kabuf,
	unsigned char* s1,
	unsigned char* sa)
{
	struct FPECC* cfig = &para;
	big x1, y1, x2, y2, _x1, _x2, da, ta;
	big x, y;
	epoint* w;
	unsigned char kx1buf[32], ky1buf[32];
	unsigned char kx2buf[32], ky2buf[32];
	unsigned char xubuf[32];
	unsigned char yubuf[32];
	unsigned char buf[256];

	unsigned char za[32];
	unsigned char zb[32];
	unsigned char hash[32];

	miracl* mip = mirsys(20, 0);

	mip->IOBASE = 16;
	k = mirvar(0);
	x1 = mirvar(0);
	y1 = mirvar(0);
	x2 = mirvar(0);
	y2 = mirvar(0);
	_x1 = mirvar(0);
	_x2 = mirvar(0);
	ta = mirvar(0);
	da = mirvar(0);

	p = mirvar(0);
	a = mirvar(0);
	b = mirvar(0);
	n = mirvar(0);
	x = mirvar(0);
	y = mirvar(0);

	cinstr(p, cfig->p);
	cinstr(a, cfig->a);
	cinstr(b, cfig->b);
	cinstr(n, cfig->n);
	cinstr(x, cfig->x);
	cinstr(y, cfig->y);
	ecurve_init(a, b, p, MR_AFFINE);
	G = epoint_init();
	w = epoint_init();

	genZSM3(ida, idalen, pax, paxlen, pay, paylen, za);
	genZSM3(idb, idblen, pbx, pbxlen, pby, pbylen, zb);
	printf("za & zb:");
	PrintBuf(za, 32);
	PrintBuf(zb, 32);

	bytes_to_big(kx1len, (char*)kx1, x1);
	bytes_to_big(ky1len, (char*)ky1, y1);

	if (!epoint_set(x1, y1, 0, G)) {
		return 0;
	}

	big_to_bytes(32, x1, (char*)kx1buf, TRUE); //发起方临时公钥RA
	big_to_bytes(32, y1, (char*)ky1buf, TRUE);
	memcpy(buf, kx1buf + 16, 16);
	/*2 ^ w - 1是除了首位为0其他都为1与x2与运算x1首位变为0 再加2 ^ w 表示x2首位变为1，其他位不变
		所以可以直接用异或实现_x1 = 2 ^ w + (x1 & (2 ^ w - 1))*/
	buf[0] |= 0x80;
	bytes_to_big(16, (char*)buf, _x1); //A4

	bytes_to_big(private_a_len, (char*)private_a, da);

	memcpy(buf, ra, ralen);
	derand(buf, ralen);
	bytes_to_big(ralen, (char*)buf, k);

	mad(_x1, k, da, n, n, ta); //A5 ta=(da+_x1*k)modn

	bytes_to_big(kx2len, (char*)kx2, x2); //接受方临时公钥 PB
	bytes_to_big(ky2len, (char*)ky2, y2);
	if (!epoint_set(x2, y2, 0, G))
		return 0;

	big_to_bytes(32, x2, (char*)kx2buf, TRUE);
	big_to_bytes(32, y2, (char*)ky2buf, TRUE);
	memcpy(buf, kx2buf + 16, 16);
	/*2 ^ w - 1是除了首位为0其他都为1与x2与运算x2首位变为0 再加2 ^ w 表示x2首位变为1，其他位不变
		所以可以直接用异或实现_x2 = 2 ^ w + (x2 & (2 ^ w - 1))*/
	buf[0] |= 0x80;
	bytes_to_big(16, (char*)buf, _x2); //A6

	bytes_to_big(pbxlen, (char*)pbx, x); //接收方的公钥
	bytes_to_big(pbylen, (char*)pby, y);
	if (!epoint_set(x, y, 0, w))
		return 0;

	ecurve_mult(_x2, G, G); //A7
	ecurve_add(w, G);
	ecurve_mult(ta, G, G);
	if (point_at_infinity(G))
		return 0;

	epoint_get(G, x, y);
	big_to_bytes(32, x, (char*)xubuf, TRUE);
	big_to_bytes(32, y, (char*)yubuf, TRUE);
	printf("xu & yu: ");
	PrintBuf(xubuf, 32);
	PrintBuf(yubuf, 32);

	memcpy(buf, xubuf, 32);
	memcpy(buf + 32, yubuf, 32);
	memcpy(buf + 64, za, 32);
	memcpy(buf + 96, zb, 32);
	kdf(buf, 128, kalen, kabuf);//A8
	printf("Ka: ");
	PrintBuf(kabuf, kalen);

	if ((s1 != NULL) || (sa != NULL))
	{
		memcpy(buf, xubuf, 32);
		memcpy(buf + 32, za, 32);
		memcpy(buf + 64, zb, 32);
		memcpy(buf + 96, kx1buf, 32);
		memcpy(buf + 128, ky1buf, 32);
		memcpy(buf + 160, kx2buf, 32);
		memcpy(buf + 192, ky2buf, 32);
		sm3(buf, 32 * 7, hash);

		if (s1 != NULL)
		{
			buf[0] = 0x02;
			memcpy(buf + 1, yubuf, 32);
			memcpy(buf + 33, hash, 32);
			sm3(buf, 65, s1);
			printf("S1: ");
			PrintBuf(s1, 32);//A9
		}

		if (sa != NULL)
		{
			buf[0] = 0x03;
			memcpy(buf + 1, yubuf, 32);
			memcpy(buf + 33, hash, 32);
			sm3(buf, 65, sa);
			printf("Sa: ");
			PrintBuf(sa, 32);//A10
		}
	}
}

//B产生s2，用于验证协商过程的正确性
void b10SM2(
	unsigned char* pax, int paxlen,
	unsigned char* pay, int paylen,
	unsigned char* pbx, int pbxlen,
	unsigned char* pby, int pbylen,
	unsigned char* kx1, int kx1len,
	unsigned char* ky1, int ky1len,
	unsigned char* kx2, int kx2len,
	unsigned char* ky2, int ky2len,
	unsigned char* xv, int xvlen,
	unsigned char* yv, int yvlen,
	unsigned char* ida, int idalen,
	unsigned char* idb, int idblen,
	unsigned char* s2)
{
	big x1, y1, x2, y2, x3, y3;
	unsigned char buf[256];
	unsigned char za[32];
	unsigned char zb[32];
	miracl* mip = mirsys(20, 0);

	mip->IOBASE = 16;
	x1 = mirvar(0);
	y1 = mirvar(0);
	x2 = mirvar(0);
	y2 = mirvar(0);
	x3 = mirvar(0);
	y3 = mirvar(0);

	genZSM3(ida, idalen, pax, paxlen, pay, paylen, za);
	genZSM3(idb, idblen, pbx, pbxlen, pby, pbylen, zb);

	bytes_to_big(kx1len, (char*)kx1, x1);
	bytes_to_big(ky1len, (char*)ky1, y1);
	bytes_to_big(kx2len, (char*)kx2, x2);
	bytes_to_big(ky2len, (char*)ky2, y2);

	memcpy(buf, xv, xvlen);
	derand(buf, xvlen);
	bytes_to_big(xvlen, (char*)buf, x3);
	memcpy(buf, yv, yvlen);
	derand(buf, yvlen);
	bytes_to_big(yvlen, (char*)buf, y3);

	big_to_bytes(32, x3, (char*)buf, TRUE);
	memcpy(buf + 32, za, 32);
	memcpy(buf + 32 + 32, zb, 32);
	big_to_bytes(32, x1, (char*)buf + 32 + 32 + 32, TRUE);
	big_to_bytes(32, y1, (char*)buf + 32 + 32 + 32 + 32, TRUE);
	big_to_bytes(32, x2, (char*)buf + 32 + 32 + 32 + 32 + 32, TRUE);
	big_to_bytes(32, y2, (char*)buf + 32 + 32 + 32 + 32 + 32 + 32, TRUE);
	sm3(buf, 32 * 7, s2);

	buf[0] = 0x03; //B10
	big_to_bytes(32, y3, (char*)buf + 1, TRUE);
	memcpy(buf + 1 + 32, s2, 32);
	sm3(buf, 65, s2);
	printf("s2: ");
	PrintBuf(s2, 32);
}








