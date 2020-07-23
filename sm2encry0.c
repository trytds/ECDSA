//#include<stdlib.h>
//#include "miracl.h"
//#include<string.h>
//#include<stdio.h>
//#include"sm3.h"
//
//struct
//{
//	char* p;//椭圆曲线的参数
//	char* a;
//	char* b;
//	char* n;  //G的阶
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
//	int klen;//期望得到密钥的byte长度 =strlen(plain)（与文档要求不同）
//
//	miracl* mip = mirsys(1000, 0); //初始化miracl系统
//	big a, b, p, Gx, Gy, n, db, k, x1, y1, x2, y2;
//	a = mirvar(0);
//	b = mirvar(0);
//	p = mirvar(0);
//	Gx = mirvar(0);
//	Gy = mirvar(0);
//	n = mirvar(0);
//	k = mirvar(0);
//	db = mirvar(0);//用于存用户私钥
//	x1 = mirvar(0);
//	y1 = mirvar(0);
//	x2 = mirvar(0);
//	y2 = mirvar(0);
//	mip->IOBASE = 16;//下面依次读取十六进制的参数/////////////////////
//	cinstr(p, para.p); //将大数字符串转换成大数,16进制的字符串转换大数
//	cinstr(a, para.a);
//	cinstr(b, para.b);
//	cinstr(n, para.n);
//	cinstr(Gx, para.Gx);
//	cinstr(Gy, para.Gy);
//
//
//
//	ecurve_init(a, b, p, MR_PROJECTIVE);//初始化椭圆曲线
//	epoint* G = NULL;  //基点G
//	epoint* Pb = NULL;
//	epoint* C1 = NULL;
//	epoint* kPb = NULL;
//	G = epoint_init();//初始化点
//	Pb = epoint_init();//初始化点
//	C1 = epoint_init();//初始化点
//	kPb = epoint_init();//初始化点
//
//						//设置G点值
//	epoint_set(Gx, Gy, 0, G);
//	//生成公钥私钥Pb=G*db
//	printf("n:"); cotnum(n, stdout);
//	bigrand(n, db);           //db<n-1,随机生成私钥，然后打印
//	printf("私钥db=");
//	cotnum(db, stdout);
//	//生成公钥pb=G*db
//	ecurve_mult(db, G, Pb);
//
//	//显示各个参数值和明文
//	printf("参数：\np: %s\na: %s\nb: %s\nn: %s\nxG:%s\nyG:%s\n", para.p, para.a, para.b, para.n, para.Gx, para.Gy);
//	FILE* fp;//存放明文
//	fopen_s(&fp, "3.txt", "r+");
//	fgets(plain, 255, fp);
//	fclose(fp);
//	printf("\n明文：%s\n\n", plain);
//
//	//——————————开始加密——————————
//	printf("——————————开始加密——————————\n");
//	bigrand(n, k);  //k<n 随机生成k，然后打印
//	printf("选取随机数k=");
//	cotnum(k, stdout);
//	ecurve_mult(k, G, C1);  //生成点T1坐标(x1,y1)=[k]G
//	epoint_get(C1, x1, y1);//获取点x1、y1坐标
//	printf("x1: "); cotnum(x1, stdout);
//	printf("y1: "); cotnum(y1, stdout);
//	big_to_bytes(32, x1, (char*)msg, TRUE);
//	big_to_bytes(32, y1, (char*)msg + 32, TRUE);
//
//	if (point_at_infinity(Pb)) {
//		printf("选取随机数不符合要求");
//		return 0; //如果s是无穷点 报错退出
//	}
//	ecurve_mult(k, Pb, kPb);    //kpb=K*pb
//	epoint_get(kPb, x2, y2);   //从kpb得到x2，y2
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
//	if (kdf(x2andy2_byte, klen, (unsigned char*)msg + 64) == 0)  //如果kdf返回的值为0，退出
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
//	printf("发送消息（C1||C2||C3）生成，发送消息长度：%dbyte \n内容：", 32 + 64 + klen);
//
//	big m;
//	m = mirvar(0);
//	bytes_to_big(32 + 64 + klen, msg, m);
//	mip->IOBASE = 16;
//	cotnum(m, stdout);
//
//	printf("\n密文：%x\n\n", msg);
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
//	dbC1 = epoint_init();//初始化点
//
//	//——————————开始解密——————————
//	printf("——————————开始解密——————————\n");
//
//	bytes_to_big(32, (char*)msg, x1);    //从msg中分别取出32位放入x和y
//	bytes_to_big(32, (char*)msg + 32, y1);
//
//
//	if (!epoint_set(x1, y1, 0, C1)) {
//		printf("C1不在椭圆曲线上");
//		return 0;
//	}     //初始化点C1=（x，y）点C1=（x，y）是否在椭圆曲线 上
//	if (point_at_infinity(C1)) {
//		printf("S为无穷远点");
//		return 0; //如果s是无穷点 报错退出,h为1
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
//	if (kdf(x2andy2_byte, klen, (unsigned char*)plain) == 0) { //如果kdf返回的值为0，退出
//		printf("t全0");
//		return 0;
//	}
//
//	for (i = 0; i < klen; i++)     //M'(outmsg)=C2 ^ t(outmsg)
//	{
//		plain[i] ^= msg[i + 64];//密文从65位开始为c2
//	}
//
//	//	bzero(temp, sizeof(temp));
//	memset(temp, 0, sizeof(temp));
//	memcpy(temp, x2andy2_byte, 32);
//	memcpy(temp + 32, plain, klen);
//	memcpy(temp + 32 + klen, x2andy2_byte + 32, 32);
//	char u[32];
//	sm3((unsigned char*)temp, 64 + klen, (unsigned char*)u);
//	if (memcmp(u, msg + 64 + klen, 32) != 0)//判断u=c3则继续
//	{
//		printf("error；\n");
//		//return 0;
//	}
//	printf("\n获得明文：%s\n\n", plain);
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
//		buf[64] = (ct >> 24) & 0xFF;   //ct前8位
//		buf[65] = (ct >> 16) & 0xFF;
//		buf[66] = (ct >> 8) & 0xFF;
//		buf[67] = ct & 0xFF;
//		sm3(buf, 68, p);                       //sm3后结果放在p中
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
//		return 1;   //非全0
//	else
//		return 0;  //全0
//
//
//}
