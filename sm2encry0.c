//#include<stdlib.h>
//#include "miracl.h"
//#include<string.h>
//#include<stdio.h>
//#include"sm3.h"
//
//struct
//{
//	char* p;//��Բ���ߵĲ���
//	char* a;
//	char* b;
//	char* n;  //G�Ľ�
//	char* Gx;   //g=(x,y)
//	char* Gy;
//}para = {
//	"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
//	"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
//	"28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
//	"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
//	"32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
//	"BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",
//};
//int kdf(unsigned char* x2andy2_byte, int klen, unsigned char* kbuf);
//
//
//int main()
//{
//	char msg[6000];
//	char plain[5000];
//	//char t1[5000] = { 0 };
//	//char t2[5000] = { 0 };
//	unsigned char x2andy2_byte[64];
//	int klen;//�����õ���Կ��byte���� =strlen(plain)�����ĵ�Ҫ��ͬ��
//
//	miracl* mip = mirsys(1000, 0); //��ʼ��miraclϵͳ
//	big a, b, p, Gx, Gy, n, db, k, x1, y1, x2, y2;
//	a = mirvar(0);
//	b = mirvar(0);
//	p = mirvar(0);
//	Gx = mirvar(0);
//	Gy = mirvar(0);
//	n = mirvar(0);
//	k = mirvar(0);
//	db = mirvar(0);//���ڴ��û�˽Կ
//	x1 = mirvar(0);
//	y1 = mirvar(0);
//	x2 = mirvar(0);
//	y2 = mirvar(0);
//	mip->IOBASE = 16;//�������ζ�ȡʮ�����ƵĲ���/////////////////////
//	cinstr(p, para.p); //�������ַ���ת���ɴ���,16���Ƶ��ַ���ת������
//	cinstr(a, para.a);
//	cinstr(b, para.b);
//	cinstr(n, para.n);
//	cinstr(Gx, para.Gx);
//	cinstr(Gy, para.Gy);
//
//
//
//	ecurve_init(a, b, p, MR_PROJECTIVE);//��ʼ����Բ����
//	epoint* G = NULL;  //����G
//	epoint* Pb = NULL;
//	epoint* C1 = NULL;
//	epoint* kPb = NULL;
//	G = epoint_init();//��ʼ����
//	Pb = epoint_init();//��ʼ����
//	C1 = epoint_init();//��ʼ����
//	kPb = epoint_init();//��ʼ����
//
//						//����G��ֵ
//	epoint_set(Gx, Gy, 0, G);
//	//���ɹ�Կ˽ԿPb=G*db
//	printf("n:"); cotnum(n, stdout);
//	bigrand(n, db);           //db<n-1,�������˽Կ��Ȼ���ӡ
//	printf("˽Կdb=");
//	cotnum(db, stdout);
//	//���ɹ�Կpb=G*db
//	ecurve_mult(db, G, Pb);
//
//	//��ʾ��������ֵ������
//	printf("������\np: %s\na: %s\nb: %s\nn: %s\nxG:%s\nyG:%s\n", para.p, para.a, para.b, para.n, para.Gx, para.Gy);
//	FILE* fp;//�������
//	fopen_s(&fp, "3.txt", "r+");
//	fgets(plain, 255, fp);
//	fclose(fp);
//	printf("\n���ģ�%s\n\n", plain);
//
//	//����������������������ʼ���ܡ�������������������
//	printf("����������������������ʼ���ܡ�������������������\n");
//	bigrand(n, k);  //k<n �������k��Ȼ���ӡ
//	printf("ѡȡ�����k=");
//	cotnum(k, stdout);
//	ecurve_mult(k, G, C1);  //���ɵ�T1����(x1,y1)=[k]G
//	epoint_get(C1, x1, y1);//��ȡ��x1��y1����
//	printf("x1: "); cotnum(x1, stdout);
//	printf("y1: "); cotnum(y1, stdout);
//	big_to_bytes(32, x1, (char*)msg, TRUE);
//	big_to_bytes(32, y1, (char*)msg + 32, TRUE);
//
//	if (point_at_infinity(Pb)) {
//		printf("ѡȡ�����������Ҫ��");
//		return 0; //���s������� �����˳�
//	}
//	ecurve_mult(k, Pb, kPb);    //kpb=K*pb
//	epoint_get(kPb, x2, y2);   //��kpb�õ�x2��y2
//
//	//cotstr(x2, x2andy2_hex);
//	printf("x2: "); cotnum(x2, stdout);
//	//cotstr(y2, x2andy2_hex + 64);
//	printf("y2: "); cotnum(y2, stdout);
//	//printf("x2andy2_hex: %s\n", x2andy2_hex);
//	big_to_bytes(32, x2, (char*)x2andy2_byte, TRUE);
//	big_to_bytes(32, y2, (char*)x2andy2_byte + 32, TRUE);
//
//	klen = strlen(plain);
//	if (kdf(x2andy2_byte, klen, (unsigned char*)msg + 64) == 0)  //���kdf���ص�ֵΪ0���˳�
//		return 0;
//
//	int i;
//	for (i = 0; i < klen; i++)
//	{
//		msg[64 + i] ^= plain[i];
//	}
//
//	char temp[6000];
//	memcpy(temp, x2andy2_byte, 32);
//	memcpy(temp + 32, plain, klen);
//	memcpy(temp + 32 + klen, x2andy2_byte + 32, 32);
//	sm3((unsigned char*)temp, 64 + klen, (unsigned char*)msg + 64 + klen);
//
//	printf("������Ϣ��C1||C2||C3�����ɣ�������Ϣ���ȣ�%dbyte \n���ݣ�", 32 + 64 + klen);
//
//	big m;
//	m = mirvar(0);
//	bytes_to_big(32 + 64 + klen, msg, m);
//	mip->IOBASE = 16;
//	cotnum(m, stdout);
//
//	printf("\n���ģ�%x\n\n", msg);
//	///////////////////////////////////////////////////////////
//	x1 = mirvar(0);
//	y1 = mirvar(0);
//	C1 = epoint_init();
//	x2 = mirvar(0);
//	y2 = mirvar(0);
//	//memset(x2andy2_byte, 0, sizeof(x2andy2_byte));
//	//bzero(x2andy2_byte, sizeof(x2andy2_byte));
//	//memset(plain, 0, sizeof(plain));
//	//bzero(plain, sizeof(plain));
//	epoint* dbC1 = NULL;
//	dbC1 = epoint_init();//��ʼ����
//
//	//����������������������ʼ���ܡ�������������������
//	printf("����������������������ʼ���ܡ�������������������\n");
//
//	bytes_to_big(32, (char*)msg, x1);    //��msg�зֱ�ȡ��32λ����x��y
//	bytes_to_big(32, (char*)msg + 32, y1);
//
//
//	if (!epoint_set(x1, y1, 0, C1)) {
//		printf("C1������Բ������");
//		return 0;
//	}     //��ʼ����C1=��x��y����C1=��x��y���Ƿ�����Բ���� ��
//	if (point_at_infinity(C1)) {
//		printf("SΪ����Զ��");
//		return 0; //���s������� �����˳�,hΪ1
//	}
//	ecurve_mult(db, C1, dbC1);
//	epoint_get(dbC1, x2, y2);
//	printf("x2:"); cotnum(x2, stdout);
//	printf("y2:"); cotnum(y2, stdout);
//
//	big_to_bytes(32, x2, (char*)x2andy2_byte, TRUE);
//	big_to_bytes(32, y2, (char*)x2andy2_byte + 32, TRUE);
//
//	//test
//	bytes_to_big(64, (char*)x2andy2_byte, m);
//	mip->IOBASE = 16;
//	printf("x2andy2_byte: "); cotnum(m, stdout);
//	//
//	if (kdf(x2andy2_byte, klen, (unsigned char*)plain) == 0) { //���kdf���ص�ֵΪ0���˳�
//		printf("tȫ0");
//		return 0;
//	}
//
//	for (i = 0; i < klen; i++)     //M'(outmsg)=C2 ^ t(outmsg)
//	{
//		plain[i] ^= msg[i + 64];//���Ĵ�65λ��ʼΪc2
//	}
//
//	//	bzero(temp, sizeof(temp));
//	memset(temp, 0, sizeof(temp));
//	memcpy(temp, x2andy2_byte, 32);
//	memcpy(temp + 32, plain, klen);
//	memcpy(temp + 32 + klen, x2andy2_byte + 32, 32);
//	char u[32];
//	sm3((unsigned char*)temp, 64 + klen, (unsigned char*)u);
//	if (memcmp(u, msg + 64 + klen, 32) != 0)//�ж�u=c3�����
//	{
//		printf("error��\n");
//		//return 0;
//	}
//	printf("\n������ģ�%s\n\n", plain);
//
//
//
//	system("pause");
//	return 0;
//}
//
//int kdf(unsigned char* x2andy2_byte, int klen, unsigned char* kbuf)
//{
//
//	unsigned char buf[70];
//	unsigned char digest[32];
//	unsigned int ct = 0x00000001;
//	int i, m, n;
//	unsigned char* p;
//
//	memcpy(buf, x2andy2_byte, 64);
//
//	m = klen / 32;
//	n = klen % 32;
//	p = kbuf;
//
//	for (i = 0; i < m; i++)       //buf 64-70
//	{
//		buf[64] = (ct >> 24) & 0xFF;   //ctǰ8λ
//		buf[65] = (ct >> 16) & 0xFF;
//		buf[66] = (ct >> 8) & 0xFF;
//		buf[67] = ct & 0xFF;
//		sm3(buf, 68, p);                       //sm3��������p��
//		p += 32;
//		ct++;
//	}
//
//	if (n != 0)
//	{
//		buf[64] = (ct >> 24) & 0xFF;
//		buf[65] = (ct >> 16) & 0xFF;
//		buf[66] = (ct >> 8) & 0xFF;
//		buf[67] = ct & 0xFF;
//		sm3(buf, 68, digest);
//	}
//
//	memcpy(p, digest, n);
//
//	for (i = 0; i < klen; i++)
//	{
//		if (kbuf[i] != 0)
//			break;
//	}
//
//	if (i < klen)
//		return 1;   //��ȫ0
//	else
//		return 0;  //ȫ0
//
//
//}
