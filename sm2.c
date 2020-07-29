//#include <stdio.h>
//#include "miracl.h"
//#include "mirdef.h"
//#include "string.h"
//#include <time.h>
//#include "sm3.h"
//
//
//typedef struct
//{
//	big r;
//	big s;
//}digital_sign;
//
//static big p;
//static big a;
//static big b;
//static big n;
//static big db; //˽Կ
//static big Pb; //��Կ
//static epoint* G; //����
//
////�������
//struct
//{
//	char* p;//��Բ���ߵĲ���
//	char* a;
//	char* b;
//	char* n;  //G�Ľ�
//	char* Gx;   
//	char* Gy;
//}para = {
//	"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
//	"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
//	"28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
//	"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
//	"32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
//	"BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",
//};
//
//
//void initSM2(miracl* pm)
//{
//	big Gx, Gy;
//	pm->IOBASE = 16;
//	p = mirvar(0);
//	a = mirvar(0);
//	b = mirvar(0);
//	n = mirvar(0);
//
//	cinstr(p, para.p);
//	cinstr(a, para.a);
//	cinstr(b, para.b);
//	cinstr(n, para.n);
//
//	ecurve_init(a, b, p, MR_AFFINE);
//
//	big tmp_x = mirvar(0);
//	big tmp_y = mirvar(0);
//	cinstr(tmp_x, (char*)Gx);
//	cinstr(tmp_y, (char*)Gy);
//	G = epoint_init();//�ڴ�����gf(p)��Բ����һ���� ��ʼ��Ϊ�����
//    //���õ����� �����ڵ�ǰ���̷���true �����㷽�̷���false
//	if (!epoint_set(tmp_x, tmp_y, 1, G))
//	{
//		exit(0);
//	}
//
//	//˽Կ
//	db = mirvar(0);
//	irand(time(NULL));
//	bigbits(256, db);
//
//	while (mr_compare(db, n) >= 0)
//	{
//		bigbits(256, db);
//	}
//
//	//��Կ
//	Pb = epoint_init();
//	ecurve_mult(db, G, Pb);  //g_Q = g_nb*g_G
//}
//
////sm2ǩ��
//digital_sign signSM2(miracl* pm, big z)
//{
//	big k = mirvar(0);
//	irand(time(NULL));
//	bigrand(n, k);
//
//	epoint* p = epoint_init();
//	ecurve_mult(k, G, p); //A4 ������Բ���ߵ�(x1,y1)=[k]G
//
//	digital_sign a; //����r=(e+x1)modn r=0 or r+k=n ����3
//	a.r = mirvar(0);
//	a.s = mirvar(0);
//	pm->IOBASE = 16;
//
//	add(z, p->X, a.r); //z��Hashֵ  a.r=z+kk->X
//
//	big tmp_rk = mirvar(0); 
//	add(a.r, k, tmp_rk);
//	divide(a.r, n, g_n);
//	while (0 == a.r || tmp_rk == g_n) //����3
//	{
//		irand(time(NULL));
//		bigrand(g_n, k);
//		ecurve_mult(k, g_G, p);
//		add(z, p->X, a.r); //e+x1
//		add(a.r, k, tmp_rk); 
//		divide(a.r, g_n, g_n);//r=(e+x1)mod n
//	} //r�������
//	big tmp_rd = mirvar(0);
//	big tmp6 = mirvar(0);
//	
//	multiply(g_nb, a.r, tmp_rd);//r*dA
//	multiply(g_n, k, tmp_rk);  //k*n
//	add(tmp_rk, k, tmp_rk); //k*n+k
//	subtract(tmp_rk, tmp_rd, tmp6); //n*k+k-r*dA
//	divide(tmp6, g_n, g_n); //(n*k+k-r*dA)mod n
//	big tmp_s = mirvar(0);
//	incr(g_nb, 1, tmp_s); //dA+1
//	xgcd(tmp_s, g_n, tmp_s, tmp_s,tmp_s); //(dA+1)-1
//
//	multiply(tmp_s, tmp6, a.s); //(dA+1)-1*(k-r*dA)
//	divide(a.s, g_n, g_n);
//	while (0 == a.s)
//	{
//		irand(time(NULL));
//		bigrand(g_n, k);
//		ecurve_mult(k, g_G, p);
//		add(z, p->X, a.r);
//		add(a.r, k, tmp_rk);
//		divide(a.r, g_n, g_n);
//		while (0 == a.r || tmp_rk == g_n) //r=0 or r+k=n ����3
//		{
//			irand(time(NULL));
//			bigrand(g_n, k);
//			ecurve_mult(k, g_G, p);
//			add(z, p->X, a.r);
//			add(a.r, k, tmp_rk);
//			divide(a.r, g_n, g_n);
//		}
//		multiply(g_nb, a.r, tmp_rk);//r*dA
//		subtract(k, tmp_rk, tmp6);//k-r*dA
//		divide(tmp6, g_n, g_n);
//		add(tmp6, g_n, a.s); //������
//		divide(tmp6, g_n, g_n);
//		incr(g_nb, 1, tmp_s);
//		xgcd(tmp_s, g_n, tmp_s, tmp_s,tmp_s);//(1+dA)-1
//		multiply(tmp_s, tmp6, a.s);
//		divide(a.s, g_n, g_n);
//	}
//	add(a.s, g_n, a.s);
//	divide(a.s, g_n, g_n);
//	return a;
//}
//
////sm2��֤
//int vertifySM2(digital_sign a, miracl* pm, big z)
//{
//	if (!(a.r > 0 && mr_compare(g_n, a.r)))
//	{
//		return 0;
//	}
//	if (!(a.s > 0 && mr_compare(g_n, a.s)))
//	{
//		return 0;
//	}
//
//	big t = mirvar(0);
//	add(a.r, a.s, t);
//	divide(t, g_n, g_n);
//	if (0 == t)
//	{
//		return 0;
//	}
//	epoint* g_xy1;
//	g_xy1 = epoint_init();
//	ecurve_mult(a.s, g_G, g_xy1);
//
//	epoint* g_xy2;
//	g_xy2 = epoint_init();
//	ecurve_mult(t, g_Q, g_xy2);
//	ecurve_add(g_xy1, g_xy2);
//
//	big R = mirvar(0);
//	add(z, g_xy2->X, R);
//	divide(R, g_n, g_n);
//	if (!mr_compare(R, a.r))  //����R=(e��+x1��)mod n������R=r���Ƿ����
//	{
//		return 1;
//	}
//	return 0;
//}
//
//
//int main()
//{
//	miracl* pm = mirsys(500, 16);
//	big z = mirvar(0);
//	double duration;
//	//bigdig(32, 16, z);
//	
//	clock_t start, finish;
//
//	start = clock();
//	initSM2(pm);
//	finish = clock();
//	duration = (double)(finish - start) / CLOCKS_PER_SEC;
//	printf("KeyGen: %f seconds\n", duration);
//
//	start = clock();
//	digital_sign a;
//
//	/*
//	�ṹ��aת��Ϊ���������Ӵպ���ֵ
//	*/
//	unsigned char buf[300];
//	char md[300];
//	memset(md, 0, sizeof(md));
//	memset(buf, 0, sizeof(buf));
//	memcpy(buf, &a, sizeof(digital_sign)); //�ṹ��ת��Ϊ����
//	cotstr(z, md);  //bigת��Ϊchar
//	sm3(buf, 32, md);
//	pm->IOBASE = 16;
//	cinstr(z, md); //charת��Ϊbig
//
//	a = signSM2(pm, z);
//	finish = clock();
//	duration = (double)(finish - start) / CLOCKS_PER_SEC;
//	printf("Sign: %f seconds\n", duration);
//	printf("r:");
//	cotnum(a.r, stdout);
//	printf("s:");
//	cotnum(a.s, stdout);
//
//	start = clock();
//	int r = vertifySM2(a, pm, z);
//	finish = clock();
//	duration = (double)(finish - start) / CLOCKS_PER_SEC;
//	printf("Vertify: %f seconds\n", duration);
//	if (1 == r)
//	{
//		printf("Success\n");
//	}
//	else
//	{
//		printf("Error\n");
//	}
//	return 0;
//}