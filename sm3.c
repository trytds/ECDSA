#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "sm3.h"

/*
  处理消息块
*/
void sm3_block(SM3_CTX* ctx)
{
	int j, k;
	unsigned long t;
	unsigned long ss1, ss2, tt1, tt2;
	unsigned long a, b, c, d, e, f, g, h;
	unsigned long w[132];

	/*消息扩展*/
	for (j = 0; j < 16; j++)  //消息分组Bi划分为16个字W0...W15
		w[j] = ctx->data[j];

	for (j = 16; j < 68; j++)
	{
		t = w[j - 16] ^ w[j - 9] ^ ROTATE(w[j - 3], 15);
		w[j] = P1(t) ^ ROTATE(w[j - 13], 7) ^ w[j - 6];
	}


	for (j = 0, k = 68; j < 64; j++, k++)
	{
		w[k] = w[j] ^ w[j + 4];
	}

	/*消息压缩*/
	a = ctx->h[0];
	b = ctx->h[1];
	c = ctx->h[2];
	d = ctx->h[3];
	e = ctx->h[4];
	f = ctx->h[5];
	g = ctx->h[6];
	h = ctx->h[7];

	/*压缩函数第一部分0-16*/
	for (j = 0; j < 16; j++)
	{
		ss1 = ROTATE(ROTATE(a, 12) + e + ROTATE(TH, j), 7);
		ss2 = ss1 ^ ROTATE(a, 12);
		tt1 = FFH(a, b, c) + d + ss2 + w[68 + j];
		tt2 = GGH(e, f, g) + h + ss1 + w[j];

		d = c;
		c = ROTATE(b, 9);
		b = a;
		a = tt1;

		h = g;
		g = ROTATE(f, 19);
		f = e;
		e = P0(tt2);
	}

	/*压缩函数第二部分16-33*/
	for (j = 16; j < 33; j++)
	{
		ss1 = ROTATE(ROTATE(a, 12) + e + ROTATE(TL, j), 7);
		ss2 = ss1 ^ ROTATE(a, 12);
		tt1 = FFL(a, b, c) + d + ss2 + w[68 + j];
		tt2 = GGL(e, f, g) + h + ss1 + w[j];

		d = c;
		c = ROTATE(b, 9);
		b = a;
		a = tt1;

		h = g;
		g = ROTATE(f, 19);
		f = e;
		e = P0(tt2);
	}
	/*压缩函数第三部分33-63*/
	for (j = 33; j < 64; j++)
	{
		ss1 = ROTATE(ROTATE(a, 12) + e + ROTATE(TL, (j - 32)), 7);
		ss2 = ss1 ^ ROTATE(a, 12);
		tt1 = FFL(a, b, c) + d + ss2 + w[68 + j];
		tt2 = GGL(e, f, g) + h + ss1 + w[j];

		d = c;
		c = ROTATE(b, 9);
		b = a;
		a = tt1;

		h = g;
		g = ROTATE(f, 19);
		f = e;
		e = P0(tt2);
	}

	ctx->h[0] ^= a;
	ctx->h[1] ^= b;
	ctx->h[2] ^= c;
	ctx->h[3] ^= d;
	ctx->h[4] ^= e;
	ctx->h[5] ^= f;
	ctx->h[6] ^= g;
	ctx->h[7] ^= h;

}

/*
  SM3初始化
*/
void SM3_Init(SM3_CTX* ctx)
{
	/*初始值IV*/
	ctx->h[0] = 0x7380166fUL;
	ctx->h[1] = 0x4914b2b9UL;
	ctx->h[2] = 0x172442d7UL;
	ctx->h[3] = 0xda8a0600UL;
	ctx->h[4] = 0xa96f30bcUL;
	ctx->h[5] = 0x163138aaUL;
	ctx->h[6] = 0xe38dee4dUL;
	ctx->h[7] = 0xb0fb0e4eUL;
	ctx->Nl = 0;
	ctx->Nh = 0;
	ctx->num = 0;
}

void SM3_Update(SM3_CTX* ctx, const void* data, unsigned int len)
{
	unsigned char* d;
	unsigned long l;
	int i, sw, sc;


	if (len == 0)
		return;

	l = (ctx->Nl + (len << 3)) & 0xffffffffL;
	if (l < ctx->Nl) /* overflow */
		ctx->Nh++;
	ctx->Nh += (len >> 29);
	ctx->Nl = l;


	d = (unsigned char*)data;

	while (len >= SM3_CBLOCK)
	{
		ctx->data[0] = c_2_nl(d);
		d += 4;
		ctx->data[1] = c_2_nl(d);
		d += 4;
		ctx->data[2] = c_2_nl(d);
		d += 4;
		ctx->data[3] = c_2_nl(d);
		d += 4;
		ctx->data[4] = c_2_nl(d);
		d += 4;
		ctx->data[5] = c_2_nl(d);
		d += 4;
		ctx->data[6] = c_2_nl(d);
		d += 4;
		ctx->data[7] = c_2_nl(d);
		d += 4;
		ctx->data[8] = c_2_nl(d);
		d += 4;
		ctx->data[9] = c_2_nl(d);
		d += 4;
		ctx->data[10] = c_2_nl(d);
		d += 4;
		ctx->data[11] = c_2_nl(d);
		d += 4;
		ctx->data[12] = c_2_nl(d);
		d += 4;
		ctx->data[13] = c_2_nl(d);
		d += 4;
		ctx->data[14] = c_2_nl(d);
		d += 4;
		ctx->data[15] = c_2_nl(d);
		d += 4;

		sm3_block(ctx);
		len -= SM3_CBLOCK;
	}

	if (len > 0)
	{
		memset(ctx->data, 0, 64);
		ctx->num = len + 1;
		sw = len >> 2;
		sc = len & 0x3;

		for (i = 0; i < sw; i++)
		{
			ctx->data[i] = c_2_nl(d);
			d += 4;
		}

		switch (sc)
		{
		case 0:
			ctx->data[i] = 0x80000000; 
			break;
		case 1:
			ctx->data[i] = (d[0] << 24) | 0x800000; 
			break;
		case 2:
			ctx->data[i] = (d[0] << 24) | (d[1] << 16) | 0x8000;
			break;
		case 3:
			ctx->data[i] = (d[0] << 24) | (d[1] << 16) | (d[2] << 8) | 0x80;
			break;
		}

	}


}

/*
 生成杂凑值
*/
void SM3_Final(unsigned char* md, SM3_CTX* ctx)
{

	if (ctx->num == 0)
	{
		memset(ctx->data, 0, 64);
		ctx->data[0] = 0x80000000;
		ctx->data[14] = ctx->Nh;
		ctx->data[15] = ctx->Nl;
	}
	else
	{
		if (ctx->num <= SM3_LAST_BLOCK)
		{
			ctx->data[14] = ctx->Nh;
			ctx->data[15] = ctx->Nl;
		}
		else
		{
			sm3_block(ctx);
			memset(ctx->data, 0, 56);
			ctx->data[14] = ctx->Nh;
			ctx->data[15] = ctx->Nl;
		}
	}

	sm3_block(ctx);

	nl2c(ctx->h[0], md);
	nl2c(ctx->h[1], md);
	nl2c(ctx->h[2], md);
	nl2c(ctx->h[3], md);
	nl2c(ctx->h[4], md);
	nl2c(ctx->h[5], md);
	nl2c(ctx->h[6], md);
	nl2c(ctx->h[7], md);
}

/*
  SM3算法主函数
*/
unsigned char* sm3(const unsigned char* d, unsigned int n, unsigned char* md)
{
	SM3_CTX ctx; //sm3上下文

	SM3_Init(&ctx);
	SM3_Update(&ctx, d, n);
	SM3_Final(md, &ctx);
	memset(&ctx, 0, sizeof(ctx));

	return(md);
}

