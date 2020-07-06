#include "miracl.h"
#include "mirdef.h"
#include <stdio.h>
#include <string.h>
#include "time.h"
#include <math.h>
#include "malloc.h"
#include <stdlib.h>

static miracl* mip;
static big pd, pl, ph;


typedef enum _bool
{
	false = 0, true = 1,
}bool;

#define PRIME_BITS 512

int abs(int x)
{
	if (x >= 0)
		return x;
	else return (-x);
}

//产生一个强素数
void genStrongPrime(big p, int n, long seed1, long seed2)
{
    int r, r1, r2;
    irand(seed1);        //产生一个随机数，即初始化
    bigbits(2 * n / 3, pd);   //生一个2*n/3 位（bit）的pd随机数
    nxprime(pd, pd);      //nxprime(pd,x)找到一个x大于pd的素数，返回值为BOOL
    expb2(n - 1, ph);       //ph = 2^(n-1),即2的(n-1)次方
    divide(ph, pd, ph);    //ph = ph/pd  
    expb2(n - 2, pl);
    divide(pl, pd, pl);    //pl=pl/pd
    subtract(ph, pl, ph);  //ph = ph-pl
    irand(seed2);
    bigrand(ph, ph);
    add(ph, pl, ph);
    r1 = subdiv(pd, 12, pl);   //pl=pd/12
    r2 = subdiv(ph, 12, pl);   //pl=ph/12
    r = 0;
    while ((r1 * (r2 + r)) % 12 != 5)
        r++;
    incr(ph, r, ph);          //ph=ph+r
    do
    { //find p=2*r*pd+1 = 11 mod 12 
        multiply(ph, pd, p);   //p = ph*pd
        premult(p, 2, p);      //p = p*2
        incr(p, 1, p);         //p = p+1
        incr(ph, 12, ph);      //ph = ph+12
    } while (!isprime(p));
}

//同余求逆元
void exGcd(big key_D, big key_Z, big key_E)
{
	big s0, s1, s2, zero, z1;
	s0 = mirvar(1);//初始化为1
	s1 = mirvar(0);
	s2 = mirvar(0);
	zero = mirvar(0);
	z1 = mirvar(0);
	copy(key_Z, z1);

	big q, t;
	q = mirvar(0);
	t = mirvar(0);

	while (mr_compare(key_Z, zero) > 0)
	{
		copy(key_Z, t);           //t = key_Z
		divide(key_D, key_Z, q);       //q= key_D / key_Z
		copy(key_D, key_Z);          // key_Z = key_D
		copy(t, key_D);           // key_D = t
		multiply(q, s1, t);     //t = q*s1
		subtract(s0, t, s2);   //s2 =s0 -q*s1

		copy(s1, s0);        //s0 = s1
		copy(s2, s1);        //s1 =s2
	}

	convert(1, t);//t = 1  

	if (mr_compare(t, key_D) != 0)
		convert(0, key_E);
	else
	{
		if (mr_compare(s0, zero) > 0)
			copy(s0, key_E);
		else
			add(s0, z1, key_E);
	}
	return;
}


//生成公钥和私钥
void rsaGenerateKey()
{
	int i;
	long seed[4];
	big one, key_P_Q[2], key_N, key_Z, key_D, key_E/*,key_ZR*/;

	FILE* outfile;

	mip = mirsys(100, 0);
	//初始化操作
	pd = mirvar(0);  pl = mirvar(0);  ph = mirvar(0);
	one = mirvar(0);
	key_P_Q[0] = mirvar(0); //第一个大素数
	key_P_Q[1] = mirvar(0); //第二个大素数
	key_N = mirvar(0); //大整数乘积N
	key_Z = mirvar(0);
	key_D = mirvar(0);
	key_E = mirvar(0);



	for (i = 0; i < 4; i++)
		seed[i] = abs(brand());

	printf("\t\t\n正在产生公钥和私钥，请等候……\n");
	//产生两个素数
	genStrongPrime(key_P_Q[0], PRIME_BITS, seed[0], seed[1]);
	genStrongPrime(key_P_Q[1], PRIME_BITS, seed[2], seed[3]);
	multiply(key_P_Q[0], key_P_Q[1], key_N);//key_N = key_P_Q[0] * key_P_Q[1]
	mip->IOBASE = 16;
	//写到key_P_Q.dat文件中
	outfile = fopen("key_P_Q.dat", "wt");
	cotnum(key_P_Q[0], outfile);
	cotnum(key_P_Q[1], outfile);
	fclose(outfile);

	printf("\t\t\n公钥长度key_N = key_P_Q[0] * key_P_Q[1] 有 %d 位!\n", logb2(key_N));
	printf("\n\t===========输出公钥    key_N================\n");
	cotnum(key_N, stdout);
	mip->IOBASE = 16;
	//写到key_N.dat文件中
	outfile = fopen("key_N.dat", "wt");
	cotnum(key_N, outfile);
	fclose(outfile);

	//key_Z = key_N - key_P_Q[0] - key_P_Q[1] + 1;
	convert(1, one);
	subtract(key_N, key_P_Q[0], key_Z);
	subtract(key_Z, key_P_Q[1], key_Z);
	add(key_Z, one, key_Z);
	mip->IOBASE = 16;
	//写到key_Z.dat文件中
	outfile = fopen("key_Z.dat", "w+");
	cotnum(key_Z, outfile);
	fclose(outfile);

	printf("\n\t===========输出解密密钥 key_D===============\n");
	do
	{
		bigrand(key_P_Q[0], key_D);
		subtract(key_D, one, key_D);
	} while (!isprime(key_D));
	cotnum(key_D, stdout);
	mip->IOBASE = 16;
	//写到key_D.dat文件中
	outfile = fopen("key_D.dat", "w+");
	cotnum(key_D, outfile);
	fclose(outfile);

	printf("\n\t==========-输出加密密钥 key_E===============\n");
	exGcd(key_D, key_Z, key_E);
	cotnum(key_E, stdout);
	mip->IOBASE = 16;
	//写到key_E.dat文件中
	outfile = fopen("key_E.dat", "w+");
	cotnum(key_E, outfile);
	fclose(outfile);
}

//加密
void rsaEncryptMessage()
{
	big key_N, key_E, key_P, key_C;
	char buffer[130], ifname[32];
	int buffer_length, i = 0;
	FILE* infile, * outfile;
	BOOL flag;

	key_N = mirvar(0);
	key_E = mirvar(0);
	key_P = mirvar(0);
	key_C = mirvar(0);

	if ((infile = fopen("key_N.dat", "rt")) == NULL)
	{
		printf("\n不能打开文件key_N.dat");
		return;
	}
	mip->IOBASE = 16;
	cinnum(key_N, infile);
	fclose(infile);

	if ((infile = fopen("key_E.dat", "rt")) == NULL)
	{
		printf("\n不能打开文件key_E.dat");
		return;
	}
	mip->IOBASE = 16;
	cinnum(key_E, infile);
	fclose(infile);

	printf("\t要加密的文件为 = ");
	getchar();
	gets(ifname);
	if ((infile = fopen(ifname, "rt")) == NULL)
	{
		printf("\n不能打开文件 %s\n", ifname);
		return;
	}
	else
	{
		printf("\n正在加密信息……\n");

		outfile = fopen("key_C.dat", "w+");

		if (fgets(buffer, 128, infile) == NULL)
			flag = true;
		else
			flag = false;
		while (!flag)
		{
			buffer_length = strlen(buffer);
			buffer[buffer_length] = '\0';
			mip->IOBASE = 128;
			cinstr(key_P, buffer);

			cotnum(key_P, stdout);

			powmod(key_P, key_E, key_N, key_C); //c=m^emodn  

			mip->IOBASE = 16;
			cotnum(key_C, outfile);

			if (fgets(buffer, 128, infile) == NULL)
				flag = true;
		}
		printf("\n");
		fclose(infile);
		fclose(outfile);
	}
}


//解秘
void rsaDecryptMessage()
{
	big key_N, key_D, key_C, key_P;
	big dp, dq; //CRT模式
	big_chinese ch;
	big key_P_Q[2];
	big p, q, p1, q1, m;

	/*set up for chinese theorem*/
	/**key_P_Q[0] = p;
	key_P_Q[1] = q;
	crt_init(&ch,2,key_P_Q);
	copy(key_D,dp);
	copy(key_D,dq);
	divide(dp,p1,p1);  //dp=d mod p-1
	divide(dq,q1,q1);  //dq=d mod q-1

	zero(m);
	powmod(key_C,dp,p,key_P_Q[0]);
	powmod(key_C,dq,q,key_P_Q[1]);
	crt(&ch,key_P_Q,m);
	crt_end(&ch);
	*/


	char ifname[32];
	FILE* infile, * outfile;
	key_N = mirvar(0);
	key_D = mirvar(0);
	key_C = mirvar(0);
	key_P = mirvar(0);
	dp = mirvar(0); //CRT模式
	dq = mirvar(0);
	m = mirvar(0);

	//打开key_N.dat文件，写入key_N
	if ((outfile = fopen("key_N.dat", "rt")) == NULL)
	{
		printf("不能打开key_N.dat文件\n");
		return;
	}
	mip->IOBASE = 16;
	cinnum(key_N, outfile);
	fclose(outfile);
	//打开key_D.dat文件，写入key_D
	if ((outfile = fopen("key_D.dat", "rt")) == NULL)
	{
		printf("不能打开key_D.dat文件\n");
		return;
	}
	mip->IOBASE = 16;
	cinnum(key_D, outfile);
	fclose(outfile);

	printf("\t要解密出的文件存储在 = ");
	getchar();
	gets(ifname);
	infile = fopen(ifname, "wt");
	printf("\t============解密出的明文信息===============\n");

	//打开key_C.dat文件，一段一段写入key_C
	if ((outfile = fopen("key_C.dat", "rt")) == NULL)
	{
		printf("不能打开key_C.dat文件\n");
		return;
	}

	while (1)
	{
		mip->IOBASE = 16;
		cinnum(key_C, outfile);

		if (size(key_C) == 0) break;

		powmod(key_C, key_D, key_N, key_P);//p=c^dmodn 私钥解秘

		mip->IOBASE = 128;
		cotnum(key_P, infile);
		cotnum(key_P, stdout);
	}
	printf("\t===========解密信息结束====================\n");
	fclose(outfile);
	fclose(infile);
}

//RSA原始签名
void rsaSignMessage()
{
	big key_N, key_D, key_P, key_S; //key_S为签名信息
	char buffer[130], ifname[32];
	int buffer_length, i = 0;
	FILE* infile, * outfile;
	BOOL flag;

	key_N = mirvar(0);
	key_D = mirvar(0);
	key_P = mirvar(0);
	key_S = mirvar(0);

	if ((infile = fopen("key_N.dat", "rt")) == NULL) {
		printf("\n不能打开文件key_N.dat");
		return;
	}
	mip->IOBASE = 16;
	cinnum(key_N, infile);
	fclose(infile);

	if ((infile = fopen("key_D.dat", "rt")) == NULL) {
		printf("\n不能打开文件key_D.dat");
		return;
	}
	mip->IOBASE = 16;
	cinnum(key_D, infile);
	fclose(infile);

	printf("\t要签名的文件为 = ");
	getchar();

	gets(ifname);
	if ((infile = fopen(ifname, "rt")) == NULL)
	{
		printf("\n不能打开文件 %s\n", ifname);
		return;
	}
	else {
		printf("\n正在签名信息.....\n");
		outfile = fopen("key_S.dat", "w+");

		if (fgets(buffer, 128, infile) == NULL)
			flag = true;
		else
			flag = false;
		while (!flag) {
			buffer_length = strlen(buffer);
			buffer[buffer_length] = '\0';
			mip->IOBASE = 128;
			cinstr(key_P, buffer);

			cotnum(key_P, stdout);
			powmod(key_P, key_D, key_N, key_S); //签名信息c=m^dmod n

			mip->IOBASE = 16;
			cotnum(key_S, outfile);

			if (fgets(buffer, 128, infile) == NULL);
			flag = true;
		}
		printf("\n");
		fclose(infile);
		fclose(outfile);
	}
}


/***************FDH*****************/
/**int* transform(int num, int length)
{
	int* num_vector;
	int i;
	num_vector = (int*)malloc(sizeof(int) * length);
	memset(num_vector, 0, sizeof(int) * length);

	for (i = 0; i < length && num; i++)
	{
		num_vector[i] = num % length;
		num = num / length;
	}
	return num_vector;
}

int* hash_function(int length)
{
	struct timeval t;
	int* vector;
	int i;

	gettimeofday(&t, NULL);
	srand(t.tv_usec);

	vector = (int*)malloc(sizeof(int) * length);
	for (i = 0; i < length; i++)
		vector[i] = rand() % length;
	return vector;
}

int hash_full(int* num, int* vector, int r, int m)
{
	int i;
	int slot = 0;
	for (i = 0; i < r; i++)
	{
		slot += num[i] * vector[i];
	}
	return slot % m;
}*/


//RSA-FDH签名
void rsaFdhSignMessage()
{
	big key_N, key_D, key_P, key_S2; //key_S2为签名信息
	char buffer[130], ifname[32];
	int buffer_length, i = 0;
	FILE* infile, * outfile;
	BOOL flag;

	key_N = mirvar(0);
	key_D = mirvar(0);
	key_P = mirvar(0);
	key_S2 = mirvar(0);

	if ((infile = fopen("key_N.dat", "rt")) == NULL) {
		printf("\n不能打开文件key_N.dat");
		return;
	}
	mip->IOBASE = 16;
	cinnum(key_N, infile);
	fclose(infile);

	if ((infile = fopen("key_D.dat", "rt")) == NULL) {
		printf("\n不能打开文件key_D.dat");
		return;
	}
	mip->IOBASE = 16;
	cinnum(key_D, infile);
	fclose(infile);

	printf("\t要签名的文件为 = ");
	getchar();

	gets(ifname);
	if ((infile = fopen(ifname, "rt")) == NULL)
	{
		printf("\n不能打开文件 %s\n", ifname);
		return;
	}
	else {
		printf("\n正在签名信息.....\n");
		outfile = fopen("key_S2.dat", "w+");

		if (fgets(buffer, 128, infile) == NULL)
			flag = true;
		else
			flag = false;
		while (!flag) {
			buffer_length = strlen(buffer);
			buffer[buffer_length] = '\0';
			mip->IOBASE = 128;
			cinstr(key_P, buffer);

			cotnum(key_P, stdout);  //要签名的信息 转化为数字

			sha256 sha123;
			shs256_init(&sha123);
			char szSha[32] = { 0 }; //存放hash后的结果
			
			shs_process(&sha123,key_P); //待签名的信息 key_P
			shs_hash(&sha123, szSha);
			for (int i = 0; i < 32; i++)
			{
				if (szSha[i] == 0)
					break;
			}
			big key_H = atoi(szSha);  //字符串数组转化为数字
			powmod(key_H, key_D, key_N, key_S2); //签名信息c=H(m)^dmod n

			mip->IOBASE = 16;
			cotnum(key_S2, outfile);

			if (fgets(buffer, 128, infile) == NULL);
			flag = true;
		}
		printf("\n");
		fclose(infile);
		fclose(outfile);
	}
}

//签名确认
void rsaVertifyMessage()
{
	big key_N, key_E, key_V, key_P, key_S;
	char ifname[32], buffer[130];
	FILE* infile, * outfile;
	BOOL flag;
	int buffer_length, i = 0;

	key_N = mirvar(0);
	key_E = mirvar(0);
	key_V = mirvar(0);
	key_P = mirvar(0);
	key_S = mirvar(0);


	//打开key_N.dat文件，写入key_N
	if ((outfile = fopen("key_N.dat", "rt")) == NULL)
	{
		printf("不能打开key_N.dat文件\n");
		return;
	}
	mip->IOBASE = 16;
	cinnum(key_N, outfile);
	fclose(outfile);

	//打开key_E.dat文件，写入key_E
	if ((outfile = fopen("key_E.dat", "rt")) == NULL)
	{
		printf("不能打开key_E.dat文件\n");
		return;
	}
	mip->IOBASE = 16;
	cinnum(key_E, outfile);
	fclose(outfile);


	printf("\t要验签的文件 = ");
	getchar();
	gets(ifname);
	//key_P转化
	if ((infile = fopen(ifname, "rt")) == NULL) {
		printf("\n不能打开文件 %s\n", ifname);
		return;
	}
	else
	{
		if (fgets(buffer, 128, infile) == NULL)
			flag = true;
		else
			flag = false;
		while (!flag)
		{
			buffer_length = strlen(buffer);
			buffer[buffer_length] = '\0';
			mip->IOBASE = 128;
			cinstr(key_P, buffer);
			cotnum(key_P, stdout);
			if (mr_compare(key_V, key_P) == 0) //如果签名信息代人后与原文相同 s^emodn=m 表示验证成功
				printf("Vertify");
			else
				printf("Error");
			if (fgets(buffer, 128, infile) == NULL)
				flag = true;
		}
	}


	//打开key_S.dat文件,写入key_S
	if ((outfile = fopen("key_S.dat", "rt")) == NULL)
	{
		printf("不能打开key_S.dat文件\n");
		return;
	}
	mip->IOBASE = 16;
	cinnum(key_S, outfile);
	fclose(outfile);
	while (1)
	{
		mip->IOBASE = 16;
		cinnum(key_S, outfile);
		if (size(key_S) == 0) break;

		powmod(key_S, key_E, key_N, key_V);  //v=s^emodn

		mip->IOBASE = 16;
		cotnum(key_V, outfile);

		fclose(infile);
		fclose(outfile);
	}
}

int main()
{
	clock_t begin, end;
	char ch;
	do {
		//system("cls");
		printf("\t\t==============请选择菜单!==============\n");
		printf("\t\t*             1:生成公钥和私钥        *\n");
		printf("\t\t*             2:加密信息              *\n");
		printf("\t\t*             3:解密信息              *\n");
		printf("\t\t*             4:签名信息              *\n");
		printf("\t\t*             5:FDH签名信息           *\n");
		printf("\t\t*             5:验证信息              *\n");
		printf("\t\t*=============6:退出===================\n");
		printf("\n\t\t请输入你要选择的菜单项=");

		ch = getchar();

		if (ch == '1')
		{
			rsaGenerateKey();
			system("pause");
		}
		else if (ch == '2')
		{
			begin = clock();
			rsaEncryptMessage();
			end = clock();
			printf("%lf\n", (double)(end - begin) / CLOCKS_PER_SEC);
			system("pause");
		}
		else if (ch == '3')
		{
			rsaDecryptMessage();
			system("pause");
		}
		else if (ch == '4')
		{
			// begin=clock();
			rsaSignMessage();
			// end=clock();
			// printf("%lf\n",(double)(end-begin)/CLOCKS_PER_SEC);
			system("pause");
		}
		else if (ch == '5')
		{
			rsaFdhSignMessage();
			system("pause");
		}
		else if (ch == '6')
		{
			rsaVertifyMessage();
			system("pause");
		}
	} while (ch != '7');
	return 0;
}















