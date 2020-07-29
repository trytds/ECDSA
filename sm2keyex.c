#include "sm3.h"
#include <stdio.h>
#include<stdlib.h>
#include<string.h>
#include "miracl.h"
#include "mirdef.h"
#include <time.h>

struct FPECC {
	char* p;
	char* a;
	char* b;
	char* n;
	char* x;
	char* y;
};

struct FPECC Ecc256 = {
"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
"28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
"32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
"BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",
};

unsigned char randkey[] = { 0x83,0xA2,0xC9,0xC8,0xB9,0x6E,0x5A,0xF7,0x0B,0xD4,0x80,0xB4,0x72,0x40,0x9A,0x9A,0x32,0x72,0x57,0xF1,0xEB,0xB7,0x3F,0x5B,0x07,0x33,0x54,0xB2,0x48,0x66,0x85,0x63 };
unsigned char randkeyb[] = { 0x33,0xFE,0x21,0x94,0x03,0x42,0x16,0x1C,0x55,0x61,0x9C,0x4A,0x0C,0x06,0x02,0x93,0xD5,0x43,0xC8,0x0A,0xF1,0x97,0x48,0xCE,0x17,0x6D,0x83,0x47,0x7D,0xE7,0x1C,0x80 };

unsigned char sm2_par_dig[128] = {
0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFC,
0x28,0xE9,0xFA,0x9E,0x9D,0x9F,0x5E,0x34,0x4D,0x5A,0x9E,0x4B,0xCF,0x65,0x09,0xA7,
0xF3,0x97,0x89,0xF5,0x15,0xAB,0x8F,0x92,0xDD,0xBC,0xBD,0x41,0x4D,0x94,0x0E,0x93,
0x32,0xC4,0xAE,0x2C,0x1F,0x19,0x81,0x19,0x5F,0x99,0x04,0x46,0x6A,0x39,0xC9,0x94,
0x8F,0xE3,0x0B,0xBF,0xF2,0x66,0x0B,0xE1,0x71,0x5A,0x45,0x89,0x33,0x4C,0x74,0xC7,
0xBC,0x37,0x36,0xA2,0xF4,0xF6,0x77,0x9C,0x59,0xBD,0xCE,0xE3,0x6B,0x69,0x21,0x53,
0xD0,0xA9,0x87,0x7C,0xC6,0x2A,0x47,0x40,0x02,0xDF,0x32,0xE5,0x21,0x39,0xF0,0xA0,
};




void PrintBuf(unsigned char* buf, int buflen)
{
	int i;
	printf("\n");
	printf("len = %d\n", buflen);
	for (i = 0; i < buflen; i++) {
		if (i % 32 != 31)
			printf("%02x", buf[i]);
		else
			printf("%02x\n", buf[i]);
	}
	printf("\n");
	return;
}

int sm3_z(unsigned char* userid, int userid_len, unsigned char* xa, int xa_len, unsigned char* ya, int ya_len, unsigned char* z)
{
	/*
���ܣ������û�ID����Կ����Zֵ
[����] userid�� �û�ID
[����] userid_len�� userid���ֽ���
[����] xa�� ��Կ��X����
[����] xa_len: xa���ֽ���
[����] ya�� ��Կ��Y����
[����] ya_len: ya���ֽ���
[���] z��32�ֽ�

����ֵ��
		��1���ڴ治��
		  0���ɹ�
*/

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
	memcpy(buf + 2 + userid_len, sm2_par_dig, 128);

	memset(buf + 2 + userid_len + 128, 0, 64);
	memcpy(buf + 2 + userid_len + 128 + 32 - xa_len, xa, 32);
	memcpy(buf + 2 + userid_len + 128 + 32 + 32 - ya_len, ya, 32);

	sm3(buf, 2 + userid_len + 128 + 32 + 32, z);
	free(buf);
	printf("sm3_z: ");
	PrintBuf(z, 32);
	return 0;
}

//��Կ��������
int kdf(unsigned char* zl, unsigned char* zr, int klen, unsigned char* kbuf)
{
	/*
	return 0: kbuf is 0, unusable
		   1: kbuf is OK
	*/
	unsigned char buf[70];
	unsigned char digest[32];
	unsigned int ct = 0x00000001;
	int i, m, n;
	unsigned char* p;


	memcpy(buf, zl, 32);
	memcpy(buf + 32, zr, 32);

	m = klen / 32;
	n = klen % 32;
	p = kbuf;

	for (i = 0; i < m; i++)
	{
		buf[64] = (ct >> 24) & 0xFF;
		buf[65] = (ct >> 16) & 0xFF;
		buf[66] = (ct >> 8) & 0xFF;
		buf[67] = ct & 0xFF;
		sm3(buf, 68, p);
		p += 32;
		ct++;
	}

	if (n != 0)
	{
		buf[64] = (ct >> 24) & 0xFF;
		buf[65] = (ct >> 16) & 0xFF;
		buf[66] = (ct >> 8) & 0xFF;
		buf[67] = ct & 0xFF;
		sm3(buf, 68, digest);
	}

	memcpy(p, digest, n);

	for (i = 0; i < klen; i++)
	{
		if (kbuf[i] != 0)
			break;
	}

	if (i < klen)
		return 1;
	else
		return 0;

}



void sm2_keyargeement_a1_3(unsigned char* kx1, int* kx1len,
	unsigned char* ky1, int* ky1len, unsigned char* ra, int* ralen)
{
	/*
���ܣ���ԿЭ�̵ķ��𷽵��ô˺�������һ����ʱ��Կ(kx1, ky1)����Ӧ�����������Կ���͸��Է��������ra�Լ����档
[���] kx1��   ��Կ��X���꣬����32�ֽ���ǰ���0x00
[���] kx1len��kx1���ֽ�����32
[���] ky1��   ��Կ��Y���꣬����32�ֽ���ǰ���0x00
[���] ky1len��ky1���ֽ�����32
[���] ra:     �����������32�ֽ���ǰ���0x00
[���] ralen�� ra���ֽ�����32

����ֵ����

*/
	struct FPECC* cfig = &Ecc256;
	big k, x1, y1;
	big a, b, p, n, x, y;
	epoint* G;
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

	irand(time(NULL));
	bytes_to_big(32, (char*)randkey, k);
	/**do {
		bigrand(n, k);
	} while (k->len == 0)*/
	bigrand(n, k);
	ecurve_mult(k, G, G);
	epoint_get(G, x1, y1);

	*kx1len = big_to_bytes(32, x1, (char*)kx1, TRUE);
	*ky1len = big_to_bytes(32, y1, (char*)ky1, TRUE);
	*ralen = big_to_bytes(32, k, (char*)ra, TRUE);

}


int sm2_keyagreement_b1_9(
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
	/*

���ܣ���ԿЭ�̵Ľ��շ����ô˺���Э�̳���Կkbbuf��ͬʱ����һ����ʱ��Կ(kx2, ky2)�Լ�(xv, yv)��sb��(kx2, ky2)��sb���͸��Է���kbbuf��(xv, yv)�Լ����档
˵����
[����] (kx1, ky1)�Ƿ��𷽲�������ʱ��Կ
[����] (pax, pay)�Ƿ��𷽵Ĺ�Կ
[����] private_b�ǽ��շ���˽Կ
[����] (pbx, pby)�ǽ��շ��Ĺ�Կ
[����] ida�Ƿ��𷽵��û���ʶ
[����] idb�ǽ��շ����û���ʶ
[����] kblen��ҪԼ������Կ�ֽ���

[���] kbbuf��Э����Կ���������
[���] (kx2, ky2)�ǽ��շ���������ʱ��Կ������32�ֽ���ǰ���0x00
[���] (xv, yv)�ǽ��շ��������м������Լ����棬������֤Э�̵���ȷ�ԡ�������32�ֽ���ǰ���0x00�����(xv, yv)=NULL���������
[���] sb�ǽ��շ�������32�ֽڵ�HASHֵ��Ҫ���͸����𷽣�������֤Э�̵���ȷ�ԡ����Ϊsb=NULL���������


����ֵ��0��ʧ��  1���ɹ�

*/

	struct FPECC* cfig = &Ecc256;
	big k, x1, y1, x2, y2, _x1, _x2, db, tb;
	big p, a, b, n, x, y;
	epoint* G, * w;
	int ret = 0;
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

	sm3_z(ida, idalen, pax, paxlen, pay, paylen, za);
	sm3_z(idb, idblen, pbx, pbxlen, pby, pbylen, zb);

	printf("za & zb: ");
	PrintBuf(za, 32);
	PrintBuf(zb, 32);

	bytes_to_big(32, (char*)randkeyb, k);
	bigrand(n, k);

	ecurve_mult(k, G, G);
	epoint_get(G, x2, y2);

	big_to_bytes(32, x2, (char*)kx2buf, TRUE);
	big_to_bytes(32, y2, (char*)ky2buf, TRUE);

	printf("RB(x2, y2): ");
	PrintBuf(kx2buf, 32);
	PrintBuf(ky2buf, 32);

	memcpy(kx2, kx2buf, 32);
	memcpy(ky2, ky2buf, 32);
	*kx2len = 32;
	*ky2len = 32;


	memcpy(buf, kx2buf + 16, 16);
	buf[0] |= 0x80; //�߼���
	bytes_to_big(16, (char*)buf, _x2);
	bytes_to_big(private_b_len, (char*)private_b, db);


}


int sm2_keyagreement_a4_10(unsigned char* kx1, int kx1len,
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
	/*

���ܣ���ԿЭ�̵ķ��𷽵��ô˺���Э�̳���Կkabuf��ͬʱ����s1��sa��s1��kabuf�Լ����棬sa���͸����շ�������ȷ��Э�̹��̵���ȷ�ԡ�
˵����
[����] (kx1, ky1)�Ƿ��𷽲�������ʱ��Կ
[����] (pax, pay)�Ƿ��𷽵Ĺ�Կ
[����] private_a�Ƿ��𷽵�˽Կ
[����] (pbx, pby)�ǽ��շ��Ĺ�Կ
[����] ida�Ƿ��𷽵��û���ʶ
[����] idb�ǽ��շ����û���ʶ
[����] (kx2, ky2)�ǽ��շ���������ʱ��Կ
[����] ra�Ƿ��𷽵���sm2_keyagreement_a1_3�����������
[����] kalen��ҪԼ������Կ�ֽ���

[���] kabuf��Э����Կ���������
[���] s1��sa�Ƿ��𷽲�����32�ֽڵ�HASHֵ��s1�Լ����棨Ӧ����sb����saҪ���͸����շ���������֤Э�̵���ȷ��


����ֵ��0��ʧ��  1���ɹ�

*/
	struct FPECC* cfig = &Ecc256;
	big k, x1, y1, x2, y2, _x1, _x2, da, ta;
	big p, a, b, n, x, y;
	epoint* G, * w;
	int ret = 0;
}





