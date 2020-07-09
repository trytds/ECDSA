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

//����һ��ǿ����
void genStrongPrime(big p, int n, long seed1, long seed2)
{
	int r, r1, r2;
	irand(seed1);        //����һ�������������ʼ��
	bigbits(2 * n / 3, pd);   //��һ��2*n/3 λ��bit����pd�����
	nxprime(pd, pd);      //nxprime(pd,x)�ҵ�һ��x����pd������������ֵΪBOOL
	expb2(n - 1, ph);       //ph = 2^(n-1),��2��(n-1)�η�
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

//ͬ������Ԫ
void exGcd(big key_D, big key_Z, big key_E)
{
	big s0, s1, s2, zero, z1;
	s0 = mirvar(1);//��ʼ��Ϊ1
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


//���ɹ�Կ��˽Կ
void rsaGenerateKey()
{
	int i;
	long seed[4];
	big one, key_P_Q[2], key_N, key_Z, key_D, key_E/*,key_ZR*/;

	FILE* outfile;

	mip = mirsys(100, 0);
	//��ʼ������
	pd = mirvar(0);  pl = mirvar(0);  ph = mirvar(0);
	one = mirvar(0);
	key_P_Q[0] = mirvar(0); //��һ��������
	key_P_Q[1] = mirvar(0); //�ڶ���������
	key_N = mirvar(0); //�������˻�N
	key_Z = mirvar(0);
	key_D = mirvar(0);
	key_E = mirvar(0);



	for (i = 0; i < 4; i++)
		seed[i] = abs(brand());

	printf("\t\t\n���ڲ�����Կ��˽Կ����Ⱥ򡭡�\n");
	//������������
	genStrongPrime(key_P_Q[0], PRIME_BITS, seed[0], seed[1]);
	genStrongPrime(key_P_Q[1], PRIME_BITS, seed[2], seed[3]);
	multiply(key_P_Q[0], key_P_Q[1], key_N);//key_N = key_P_Q[0] * key_P_Q[1]
	mip->IOBASE = 16;
	//д��key_P_Q.dat�ļ���
	outfile = fopen("key_P_Q.dat", "wt");
	cotnum(key_P_Q[0], outfile);
	cotnum(key_P_Q[1], outfile);
	fclose(outfile);

	printf("\t\t\n��Կ����key_N = key_P_Q[0] * key_P_Q[1] �� %d λ!\n", logb2(key_N));
	printf("\n\t===========�����Կ    key_N================\n");
	cotnum(key_N, stdout);
	mip->IOBASE = 16;
	//д��key_N.dat�ļ���
	outfile = fopen("key_N.dat", "wt");
	cotnum(key_N, outfile);
	fclose(outfile);

	//key_Z = key_N - key_P_Q[0] - key_P_Q[1] + 1;
	convert(1, one);
	subtract(key_N, key_P_Q[0], key_Z);
	subtract(key_Z, key_P_Q[1], key_Z);
	add(key_Z, one, key_Z);
	mip->IOBASE = 16;
	//д��key_Z.dat�ļ���
	outfile = fopen("key_Z.dat", "w+");
	cotnum(key_Z, outfile);
	fclose(outfile);

	printf("\n\t===========���������Կ key_D===============\n");
	do
	{
		bigrand(key_P_Q[0], key_D);
		subtract(key_D, one, key_D);
	} while (!isprime(key_D));
	cotnum(key_D, stdout);
	mip->IOBASE = 16;
	//д��key_D.dat�ļ���
	outfile = fopen("key_D.dat", "w+");
	cotnum(key_D, outfile);
	fclose(outfile);

	printf("\n\t==========-���������Կ key_E===============\n");
	exGcd(key_D, key_Z, key_E);
	cotnum(key_E, stdout);
	mip->IOBASE = 16;
	//д��key_E.dat�ļ���
	outfile = fopen("key_E.dat", "w+");
	cotnum(key_E, outfile);
	fclose(outfile);
}

//����
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
		printf("\n���ܴ��ļ�key_N.dat");
		return;
	}
	mip->IOBASE = 16;
	cinnum(key_N, infile);
	fclose(infile);

	if ((infile = fopen("key_E.dat", "rt")) == NULL)
	{
		printf("\n���ܴ��ļ�key_E.dat");
		return;
	}
	mip->IOBASE = 16;
	cinnum(key_E, infile);
	fclose(infile);

	printf("\tҪ���ܵ��ļ�Ϊ = ");
	getchar();
	gets(ifname);
	if ((infile = fopen(ifname, "rt")) == NULL)
	{
		printf("\n���ܴ��ļ� %s\n", ifname);
		return;
	}
	else
	{
		printf("\n���ڼ�����Ϣ����\n");

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


//����
void rsaDecryptMessage()
{
	big key_N, key_D, key_C, key_P;
	big dp, dq; //CRTģʽ
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
	dp = mirvar(0); //CRTģʽ
	dq = mirvar(0);
	m = mirvar(0);

	//��key_N.dat�ļ���д��key_N
	if ((outfile = fopen("key_N.dat", "rt")) == NULL)
	{
		printf("���ܴ�key_N.dat�ļ�\n");
		return;
	}
	mip->IOBASE = 16;
	cinnum(key_N, outfile);
	fclose(outfile);
	//��key_D.dat�ļ���д��key_D
	if ((outfile = fopen("key_D.dat", "rt")) == NULL)
	{
		printf("���ܴ�key_D.dat�ļ�\n");
		return;
	}
	mip->IOBASE = 16;
	cinnum(key_D, outfile);
	fclose(outfile);

	printf("\tҪ���ܳ����ļ��洢�� = ");
	getchar();
	gets(ifname);
	infile = fopen(ifname, "wt");
	printf("\t============���ܳ���������Ϣ===============\n");

	//��key_C.dat�ļ���һ��һ��д��key_C
	if ((outfile = fopen("key_C.dat", "rt")) == NULL)
	{
		printf("���ܴ�key_C.dat�ļ�\n");
		return;
	}

	while (1)
	{
		mip->IOBASE = 16;
		cinnum(key_C, outfile);

		if (size(key_C) == 0) break;

		powmod(key_C, key_D, key_N, key_P);//p=c^dmodn ˽Կ����

		mip->IOBASE = 128;
		cotnum(key_P, infile);
		cotnum(key_P, stdout);
	}
	printf("\t===========������Ϣ����====================\n");
	fclose(outfile);
	fclose(infile);
}

//RSAԭʼǩ��
void rsaSignMessage()
{
	big key_N, key_D, key_P, key_S; //key_SΪǩ����Ϣ
	char buffer[130], ifname[32];
	int buffer_length, i = 0;
	FILE* infile, * outfile;
	BOOL flag;

	key_N = mirvar(0);
	key_D = mirvar(0);
	key_P = mirvar(0);
	key_S = mirvar(0);

	if ((infile = fopen("key_N.dat", "rt")) == NULL) {
		printf("\n���ܴ��ļ�key_N.dat");
		return;
	}
	mip->IOBASE = 16;
	cinnum(key_N, infile);
	fclose(infile);

	if ((infile = fopen("key_D.dat", "rt")) == NULL) {
		printf("\n���ܴ��ļ�key_D.dat");
		return;
	}
	mip->IOBASE = 16;
	cinnum(key_D, infile);
	fclose(infile);


	printf("\tҪǩ�����ļ�Ϊ = ");
	getchar();

	gets(ifname);
	if ((infile = fopen(ifname, "rt")) == NULL)
	{
		printf("\n���ܴ��ļ� %s\n", ifname);
		return;
	}
	else {
		printf("\n����ǩ����Ϣ.....\n");
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
			powmod(key_P, key_D, key_N, key_S); //ǩ����Ϣc=m^dmod n

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


//ԭʼǩ��ȷ��
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


	//��key_N.dat�ļ���д��key_N
	if ((infile = fopen("key_N.dat", "rt")) == NULL)
	{
		printf("���ܴ�key_N.dat�ļ�\n");
		return;
	}
	mip->IOBASE = 16;
	cinnum(key_N, infile);
	fclose(infile);

	//��key_E.dat�ļ���д��key_E
	if ((infile = fopen("key_E.dat", "rt")) == NULL)
	{
		printf("���ܴ�key_E.dat�ļ�\n");
		return;
	}
	mip->IOBASE = 16;
	cinnum(key_E, infile);
	fclose(infile);


	//��key_S.dat�ļ�  д��key_S
	if ((infile = fopen("key_S.dat", "rt")) == NULL)
	{
		printf("\n���ܴ��ļ�key_S.dat");
		return;
	}
	mip->IOBASE = 16;
	cinnum(key_S, infile);
	fclose(infile);


	//��֤ǩ����ԭ��
	printf("\tҪ��ǩ���ļ� = ");
	getchar();
	gets(ifname);
	if ((infile = fopen(ifname, "rt")) == NULL) {
		printf("\n���ܴ��ļ� %s\n", ifname);
		return;
	}
	else
	{
		//ԭ��key_P
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

			if (fgets(buffer, 128, infile) == NULL)
				flag = true;
			fclose(infile);

		}
	}

	powmod(key_S, key_E, key_N, key_V); //v=s^emodn  
	mip->IOBASE = 16;
	cotnum(key_V, infile);

	if (mr_compare(key_V, key_P) == 0) //���ǩ����Ϣ���˺���ԭ����ͬ s^emodn=m ��ʾ��֤�ɹ�
		printf("\nVertify\n");
	else
		printf("\nError\n");


}


//RSA-FDHǩ��
void rsaFdhSignMessage()
{
	big key_N, key_D, key_P, key_S2, key_H; //key_S2Ϊǩ����Ϣ, key_HΪHash�����Ϣ

	char buffer[130], ifname[32];
	int buffer_length, i = 0;
	FILE* infile, * outfile;
	BOOL flag;

	sha256 sha123;
	shs256_init(&sha123);
	char szSha[32] = { 0 };

	key_N = mirvar(0);
	key_D = mirvar(0);
	key_P = mirvar(0);
	key_S2 = mirvar(0);
	key_H = mirvar(0);

	if ((infile = fopen("key_N.dat", "rt")) == NULL) {
		printf("\n���ܴ��ļ�key_N.dat");
		return;
	}
	mip->IOBASE = 16;
	cinnum(key_N, infile);
	fclose(infile);

	if ((infile = fopen("key_D.dat", "rt")) == NULL) {
		printf("\n���ܴ��ļ�key_D.dat");
		return;
	}
	mip->IOBASE = 16;
	cinnum(key_D, infile);
	fclose(infile);

	printf("\tҪǩ�����ļ�Ϊ = ");
	getchar();

	gets(ifname);
	if ((infile = fopen(ifname, "rt")) == NULL)
	{
		printf("\n���ܴ��ļ� %s\n", ifname);
		return;
	}
	else {
		printf("\n����ǩ����Ϣ.....\n");
		outfile = fopen("key_S2.dat", "w+");

		if (fgets(buffer, 128, infile) == NULL)
			flag = true;
		else
			flag = false;
		while (!flag) {
			buffer_length = strlen(buffer);
			buffer[buffer_length] = '\0';
			mip->IOBASE = 128;
			cinstr(key_P, buffer); //�����ַ���ת��Ϊ����

			cotnum(key_P, stdout);  //Ҫǩ������Ϣ ת��Ϊ����

			//char* buffer1 = buffer;
			//while (*buffer1 != 0)
			//shs_process(&sha123,*buffer1++); //��ǩ������Ϣ key_P �˴������д���
			shs_process(&sha123, key_P);
			shs_hash(&sha123, szSha);

			//cinstr(key_H, buffer1); //�����ַ���ת��Ϊ����
			cinstr(key_H, key_P);
			cotnum(key_H, stdout);

			powmod(key_H, key_D, key_N, key_S2); //ǩ����Ϣc=H(m)^dmod n

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

//FDHǩ����֤
void rsaVertifyFdhMessage()
{
	big key_N, key_E, key_V, key_P, key_S2, key_H;
	char ifname[32], buffer[130];
	FILE* infile, * outfile;
	BOOL flag;
	int buffer_length, i = 0;

	sha256 sha123;
	shs256_init(&sha123);
	char szSha[32] = { 0 };

	key_N = mirvar(0);
	key_E = mirvar(0);
	key_V = mirvar(0);
	key_P = mirvar(0);
	key_S2 = mirvar(0);
	key_H = mirvar(0);


	//��key_N.dat�ļ���д��key_N
	if ((infile = fopen("key_N.dat", "rt")) == NULL)
	{
		printf("���ܴ�key_N.dat�ļ�\n");
		return;
	}
	mip->IOBASE = 16;
	cinnum(key_N, infile);
	fclose(infile);

	//��key_E.dat�ļ���д��key_E
	if ((infile = fopen("key_E.dat", "rt")) == NULL)
	{
		printf("���ܴ�key_E.dat�ļ�\n");
		return;
	}
	mip->IOBASE = 16;
	cinnum(key_E, infile);
	fclose(infile);


	//��key_S2.dat�ļ�  д��key_S2
	if ((infile = fopen("key_S2.dat", "rt")) == NULL)
	{
		printf("\n���ܴ��ļ�key_S2.dat");
		return;
	}
	mip->IOBASE = 16;
	cinnum(key_S2, infile);
	fclose(infile);


	//��֤ǩ����ԭ��
	printf("\tҪ��ǩ���ļ� = ");
	getchar();
	gets(ifname);
	if ((infile = fopen(ifname, "rt")) == NULL) {
		printf("\n���ܴ��ļ� %s\n", ifname);
		return;
	}
	else
	{
		//ԭ��key_P
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

			shs_process(&sha123, key_P);
			shs_hash(&sha123, szSha);

			//cinstr(key_H, buffer1); //�����ַ���ת��Ϊ����
			cinstr(key_H, key_P);
			cotnum(key_H, stdout);   //FDHǩ����Hash����


			if (fgets(buffer, 128, infile) == NULL)
				flag = true;
			fclose(infile);

		}
	}

	powmod(key_S2, key_E, key_N, key_V); //H(m)=s^emodn  
	mip->IOBASE = 16;
	cotnum(key_V, infile);

	if (mr_compare(key_V, key_H) == 0) //���ǩ����Ϣ���˺���ԭ����ͬ s^emodn=m ��ʾ��֤�ɹ�
		printf("Vertify\n");
	else
		printf("Error\n");

}

int main()
{
	clock_t begin, end;
	double duration;
	char ch;
	do {
		//system("cls");
		printf("\t\t==============��ѡ��˵�!==============\n");
		printf("\t\t*             1:���ɹ�Կ��˽Կ        *\n");
		printf("\t\t*             2:������Ϣ              *\n");
		printf("\t\t*             3:������Ϣ              *\n");
		printf("\t\t*             4:ԭʼǩ����Ϣ          *\n");
		printf("\t\t*             5:ԭʼǩ����֤          *\n");
		printf("\t\t*             6:FDHǩ����Ϣ           *\n");
		printf("\t\t*             7:FDHǩ����֤           *\n");
		printf("\t\t*=============8:�˳�===================\n");
		printf("\n\t\t��������Ҫѡ��Ĳ˵���=");

		ch = getchar();

		if (ch == '1')
		{
			begin = clock();
			rsaGenerateKey();
			end = clock();
			duration = (double)(end - begin) / CLOCKS_PER_SEC;
			printf("generate: %f seconds\n", duration);
			system("pause");
		}
		else if (ch == '2')
		{
			begin = clock();
			rsaEncryptMessage();
			end = clock();
			duration = (double)(end - begin) / CLOCKS_PER_SEC;
			printf("encrypt: %f seconds\n", duration);
			system("pause");
		}
		else if (ch == '3')
		{
			begin = clock();
			rsaDecryptMessage();
			end = clock();
			duration = (double)(end - begin) / CLOCKS_PER_SEC;
			printf("decrypt: %f seconds\n", duration);
			system("pause");
		}
		else if (ch == '4')
		{
			begin=clock();
			rsaSignMessage();
			end=clock();
			duration = (double)(end - begin) / CLOCKS_PER_SEC;
			printf("sign: %f seconds\n", duration);
			system("pause");
		}
		else if (ch == '5')
		{
			begin = clock();
			rsaVertifyMessage();
			end = clock();
			duration = (double)(end - begin) / CLOCKS_PER_SEC;
			printf("vertify: %f seconds\n", duration);
			system("pause");
		}
		else if (ch == '6')
		{
			begin = clock();
			rsaFdhSignMessage();
			end = clock();
			duration = (double)(end - begin) / CLOCKS_PER_SEC;
			printf("FDHsign: %f seconds\n", duration);
			system("pause");
		}
		else if (ch == '7')
		{
			begin = clock();
			rsaVertifyFdhMessage();
			end = clock();
			duration = (double)(end - begin) / CLOCKS_PER_SEC;
			printf("FDHvertify: %f seconds\n", duration);
			system("pause");
		}
	} while (ch != '8');
	return 0;
}















