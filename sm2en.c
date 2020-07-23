#include "miracl.h"
#include "sm3.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static big p;
static big a;
static big b;
static big n;
static big db; //˽Կ
static big Pb; //��Կ
static epoint* G; //����
static miracl* pm;
char plain[5000]; //����
char msg[6000]; //����
unsigned char x2andy2_byte[64];

struct
{
	char* p;//��Բ���ߵĲ���
	char* a;
	char* b;
	char* n;  //G�Ľ�
	char* Gx;   
	char* Gy;
}para = {
	"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
	"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
	"28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
	"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
	"32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
	"BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",
};

//sm2˽Կ��Կ����
void initSM2()
{
	pm = mirsys(1000, 0);
	big Gx, Gy, x1, y1, x2, y2;
	p = mirvar(0);
	a = mirvar(0);
	b = mirvar(0);
	n = mirvar(0);
	Gx = mirvar(0);
	Gy = mirvar(0);
	db = mirvar(0);

	pm->IOBASE = 16;
	cinstr(p, para.p);
	cinstr(a, para.a);
	cinstr(b, para.b);
	cinstr(n, para.n);
	cinstr(Gx, para.Gx);
	cinstr(Gy, para.Gy);

	ecurve_init(a, b, p, MR_AFFINE); //��ʼ����Բ����

	epoint* kPb = NULL;

	G = epoint_init(); //�ڴ�����Gf(p)��Բ����һ���� ��ʼ��Ϊ�����
	Pb = epoint_init();
	kPb = epoint_init();

	//���õ����� �����ڵ�ǰ�����򷵻�true  �������򷵻�false
	if (!epoint_set(Gx, Gy, 1, G))
	{
		exit(0);
	}

	//���ɹ�Կ˽ԿPb = G*db
	printf("n:"); cotnum(n, stdout);

	bigrand(n, db);
	printf("˽Կdb="); cotnum(db, stdout); //����˽Կ
	ecurve_mult(db, G, Pb); //���ɹ�Կ
	printf("����: \np:  %s", p); cotnum(p, stdout);
	printf("a:  %s", a); cotnum(a, stdout);
	printf("b:  %s", b); cotnum(b, stdout);
	printf("n:  %s", n); cotnum(n, stdout);
	printf("Gx:  %s", Gx); cotnum(Gx, stdout);
	printf("Gy:  %s", Gy); cotnum(Gy, stdout);
}


//sm2����
void encrySM2()
{
	pm->IOBASE = 16;
	big k, x1, y1, x2, y2;
	k = mirvar(0);
	x1 = mirvar(0);
	y1 = mirvar(0);
	x2 = mirvar(0);
	y2 = mirvar(0);
	epoint* kPb = NULL;
	epoint* C1 = NULL;

	kPb = epoint_init();
	C1 = epoint_init();
	
	memset(x2andy2_byte, 0, sizeof(x2andy2_byte));
	memset(plain, 0, sizeof(plain));

	int klen;  //�����õ�����Կbyte���� ����Ҳ����Ϊȫ�ֱ���
	FILE* fp; //�������
	fopen_s(&fp, "3.txt", "r+");
	fgets(plain, 255, fp); //���Ĵ�ŵ������� ��fpָ����ļ���ȡ255���ַ���plain��
	fclose(fp);
	printf("\n����: %s\n\n", plain);

	//����
	printf("����������������������ʼ���ܡ�������������������\n");
	//����A1
	bigrand(n, k);  //k<n �������k����ӡ  
	printf("ѡȡ�����k=");
	cotnum(k, stdout);

	//����A2 ���ɵ�S����(x1,y1)=[k]G  C1 
	ecurve_mult(k, G, C1);   
	epoint_get(C1, x1, y1); //��ȡ��x1,y1����         
	printf("x1: ");  cotnum(x1, stdout);
	printf("y1: ");  cotnum(y1, stdout);
	big_to_bytes(32, x1, (char *)msg, TRUE);  
	big_to_bytes(32, y1, (char *)msg + 32, TRUE);

	//����A3   
	if (point_at_infinity(Pb)) {
		printf("ѡȡ�����������Ҫ��\n");
		return 0; //���s�������  �����˳�
	}

	//����A4
	ecurve_mult(k, Pb, kPb); //kpb=K*pb
	epoint_get(kPb, x2, y2);
	printf("x2: "); cotnum(x2, stdout);
	printf("y2: "); cotnum(y2, stdout);
	big_to_bytes(32, x2, (char*)x2andy2_byte, TRUE); //ת���ɱ��ش�
	big_to_bytes(32, y2, (char*)x2andy2_byte + 32, TRUE);

	//����A5
	klen = strlen(plain);  //��Ҫ�����õ��ĳ���
	if (kdf(x2andy2_byte, klen, (unsigned char*)msg + 64) == 0) //���tΪȫ0�ı��ش� �򷵻�
		return 0;

	//����A6 C2  ���Ĵ�65λ��ʼΪc2
	for (int i = 0; i < klen; i++)
	{
		msg[64 + i] ^= plain[i];
	}

	//����A7 C3 = msg + 64 + klen
	char temp[6000];
	memcpy(temp, x2andy2_byte, 32); 
	memcpy(temp + 32, plain, klen);
	memcpy(temp + 32 + klen, x2andy2_byte + 32, 32);
	sm3((unsigned char*)temp, 64 + klen, (unsigned char*)msg + 64 + klen);

	printf("������Ϣ��C1||C2||C3�����ɣ�������Ϣ���ȣ�%dbyte \n���ݣ�", 32 + 64 + klen);
	big m;
	m = mirvar(0);
	bytes_to_big(32 + 64 + klen, msg, m); //��32+64+klen�ַ������ģ�ת���ɴ���
	pm->IOBASE = 16;
	cotnum(m, stdout);

	printf("\n����: %x\n\n", msg);  //ʮ�����������ֹ����

}

//sm2����
void decrySM2()
{
	pm->IOBASE = 16;
	big k, x1, y1, x2, y2;
	x1 = mirvar(0);
	y1 = mirvar(0);
	x2 = mirvar(0);
	y2 = mirvar(0);
	memset(x2andy2_byte, 0, sizeof(x2andy2_byte));
	int klen;
	epoint* dbC1 = NULL;
	epoint* C1 = NULL;
	C1 = epoint_init();
	dbC1 = epoint_init();//��ʼ����
	
	//��ʼ����
	printf("����������������������ʼ���ܡ�������������������\n");

	bytes_to_big(32, (char *)msg, x1);    //��msg�зֱ�ȡ��32λ����x��y
	bytes_to_big(32, (char *)msg + 32, y1);

	//����B1 ��ʼ����C1=��x��y���Ƿ�����Բ���� ��
	if (!epoint_set(x1, y1, 0, C1)) {
		printf("C1������Բ������");
		return 0;
	}

	//����B2
	if (point_at_infinity(C1)) {
		printf("SΪ����Զ��");
		return 0; //���s������� �����˳�,hΪ1
	}

	//����B3
	ecurve_mult(db, C1, dbC1);
	epoint_get(dbC1, x2, y2);
	printf("x2:"); cotnum(x2, stdout);
	printf("y2:"); cotnum(y2, stdout);

	big_to_bytes(32, x2, (char*)x2andy2_byte, TRUE);
	big_to_bytes(32, y2, (char*)x2andy2_byte + 32, TRUE);

	big m;
	m = mirvar(0);
	//test
	bytes_to_big(64, (char*)x2andy2_byte, m);
	pm->IOBASE = 16;
	printf("x2andy2_byte: "); cotnum(m, stdout);

	//����B4                                  
	klen = strlen(plain);
	//���kdf���ص�ֵΪ0���˳�
	if (kdf(x2andy2_byte, klen, (unsigned char*)plain) == 0)
	{
		printf("tȫ0\n");
		return 0;
	}

	//����B5
	for (int i = 0; i < klen; i++)     //M'(outmsg)=C2 ^ t(outmsg)
	{
		plain[i] ^= msg[i + 64];//���Ĵ�65λ��ʼΪc2
	}

	//����B6
	char temp[6000];         
	memset(temp, 0, sizeof(temp));
	memcpy(temp, x2andy2_byte, 32);
	memcpy(temp + 32, plain, klen);
	memcpy(temp + 32 + klen, x2andy2_byte + 32, 32);
	char u[32];
	sm3((unsigned char*)temp, 64 + klen, (unsigned char*)u);
	if (memcmp(u, msg + 64 + klen, 32) != 0)//�ж�u=c3�����
	{
		printf("error��\n");
	}
	printf("\n������ģ�%s\n\n", plain);
}

int kdf(unsigned char *x2andy2_byte, int klen, unsigned char *kbuf)
{

	unsigned char buf[70];
	unsigned char digest[32];
	unsigned int ct = 0x00000001; //��ʼ��һ��32���ع��ɵļ�����ct
	int i, m, n;
	unsigned char* p;

	memcpy(buf, x2andy2_byte, 64);

	m = klen / 32;
	n = klen % 32;
	p = kbuf;

	for (i = 0; i < m; i++)       //buf 64-70
	{
		buf[64] = (ct >> 24) & 0xFF;   //ctǰ8λ
		buf[65] = (ct >> 16) & 0xFF;
		buf[66] = (ct >> 8) & 0xFF;
		buf[67] = ct & 0xFF;
		sm3(buf, 68, p);                       //sm3��������p��
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
		return 1;   //��ȫ0
	else
		return 0;  //ȫ0

}

int main()
{
	clock_t start, finish;
	double duration;

	start = clock();
	initSM2();
	finish = clock();
	duration = (double)(finish - start) / CLOCKS_PER_SEC;
	printf("KeyGen: %f seconds\n", duration);

	start = clock();
	encrySM2();
	finish = clock();
	duration = (double)(finish - start) / CLOCKS_PER_SEC;
	printf("Encrypt: %f seconds\n", duration);

	start = clock();
	decrySM2();
	finish = clock();
	duration = (double)(finish - start) / CLOCKS_PER_SEC;
	printf("Decrypt: %f seconds\n", duration);

	system("pause");
	return 0;
}

