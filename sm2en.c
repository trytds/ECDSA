#include "miracl.h"
#include "sm3.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static big p;
static big a;
static big b;
static big n;
static big db; //私钥
static big Pb; //公钥
static epoint* G; //基点

struct
{
	char* p;//椭圆曲线的参数
	char* a;
	char* b;
	char* n;  //G的阶
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

//sm2私钥公钥生成
int initSM2(miracl* pm)
{
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

	ecurve_init(a, b, p, MR_AFFINE); //初始化椭圆曲线

	epoint* kPb = NULL;

	G = epoint_init(); //内存分配给Gf(p)椭圆曲线一个点 初始化为无穷大
	Pb = epoint_init();
	kPb = epoint_init();

	//设置点坐标 若属于当前方程则返回true  不满足则返回false
	if (!epoint_set(Gx, Gy, 1, G))
	{
		exit(0);
	}

	//生成公钥私钥Pb = G*db
	printf("n:"); cotnum(n, stdout);

	bigrand(n, db);
	printf("私钥db="); cotnum(db, stdout); //生成私钥
	ecurve_mult(db, G, Pb); //生成公钥
	printf("参数: \np:  %s", p); cotnum(p, stdout);
	printf("a:  %s", a); cotnum(a, stdout);
	printf("b:  %s", b); cotnum(b, stdout);
	printf("n:  %s", n); cotnum(n, stdout);
	printf("Gx:  %s", Gx); cotnum(Gx, stdout);
	printf("Gy:  %s", Gy); cotnum(Gy, stdout);
}


//sm2加密
int encrySM2(miracl* pm,char *plain,int plainlen,char *msg)
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
	
	unsigned char x2andy2_byte[64];
	memset(x2andy2_byte, 0, sizeof(x2andy2_byte));

	//加密
	printf("——————————开始加密——————————\n");
	//进入A1
	bigrand(n, k);  //k<n 随机生成k并打印  
	printf("选取随机数k=");
	cotnum(k, stdout);

	//进入A2 生成点S坐标(x1,y1)=[k]G  C1 
	ecurve_mult(k, G, C1);   
	epoint_get(C1, x1, y1); //获取点x1,y1坐标         
	printf("x1: ");  cotnum(x1, stdout);
	printf("y1: ");  cotnum(y1, stdout);
	big_to_bytes(32, x1, (char *)msg, TRUE);  
	big_to_bytes(32, y1, (char *)msg + 32, TRUE);

	//进入A3   
	if (point_at_infinity(Pb)) {
		printf("选取随机数不符合要求\n");
		return 0; //如果s是无穷点  报错退出
	}

	//进入A4
	ecurve_mult(k, Pb, kPb); //kpb=K*pb
	epoint_get(kPb, x2, y2);
	printf("x2: "); cotnum(x2, stdout);
	printf("y2: "); cotnum(y2, stdout);
	big_to_bytes(32, x2, (char*)x2andy2_byte, TRUE); //转化成比特串
	big_to_bytes(32, y2, (char*)x2andy2_byte + 32, TRUE);

	//进入A5
	if (kdf(x2andy2_byte, plainlen, msg + 64) == 0) //如果t为全0的比特串 则返回
		return 0;

	//进入A6 C2  密文从65位开始为c2
	for (int i = 0; i < plainlen; i++)
	{
		msg[64 + i] ^= plain[i];
	}

	//进入A7 C3 = msg + 64 + klen
	char temp[6000];
	memcpy(temp, x2andy2_byte, 32); 
	memcpy(temp + 32, plain, plainlen);
	memcpy(temp + 32 + plainlen, x2andy2_byte + 32, 32);
	sm3((unsigned char*)temp, 64 + plainlen, (unsigned char*)msg + 64 + plainlen);

	printf("发送消息（C1||C2||C3）生成，发送消息长度：%dbyte \n内容：", 32 + 64 + plainlen);
	big m;
	m = mirvar(0);
	bytes_to_big(32 + 64 + plainlen, msg, m); //将32+64+klen字符的明文，转换成大数
	pm->IOBASE = 16;
	cotnum(m, stdout);

	printf("\n密文: %X\n\n", msg);  

}

//sm2解密
int decrySM2(miracl *pm,char *cipher,int plainlen,char *msg)
{
	pm->IOBASE = 16;
	big k, x1, y1, x2, y2;
	x1 = mirvar(0);
	y1 = mirvar(0);
	x2 = mirvar(0);
	y2 = mirvar(0);
	unsigned char x2andy2_byte[64];
	memset(x2andy2_byte, 0, sizeof(x2andy2_byte));
	epoint* dbC1 = NULL;
	epoint* C1 = NULL;
	C1 = epoint_init();
	dbC1 = epoint_init();//初始化点
	
	//开始解密
	printf("——————————开始解密——————————\n");

	bytes_to_big(32, (char *)cipher, x1);    //分别取出32位放入x和y
	bytes_to_big(32, (char *)cipher + 32, y1);

	//进入B1 初始化点C1=（x，y）是否在椭圆曲线 上
	if (!epoint_set(x1, y1, 0, C1)) {
		printf("C1不在椭圆曲线上");
		return 0;
	}

	//进入B2
	if (point_at_infinity(C1)) {
		printf("S为无穷远点");
		return 0; //如果s是无穷点 报错退出,h为1
	}

	//进入B3
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

	//进入B4                                  
	if (kdf(x2andy2_byte, plainlen, msg) == 0)
	{
		printf("t全0\n");
		return 0;
	}

	//进入B5
	for (int i = 0; i < plainlen; i++)     //M'(outmsg)=C2 ^ t(outmsg)
	{
		msg[i] ^= cipher[i + 64];//密文从65位开始为c2
	}

	//进入B6
	char temp[6000];         
    memset(temp, 0, sizeof(temp));
	memcpy(temp, x2andy2_byte, 32);
	memcpy(temp + 32, msg, plainlen);
	memcpy(temp + 32 + plainlen, x2andy2_byte + 32, 32);
	char u[32];
	sm3((unsigned char*)temp, 64 + plainlen, (unsigned char*)u);
	if (memcmp(u, cipher + 64 + plainlen, 32) != 0)//判断u=c3则继续
	{
		printf("error；\n");
	}
	printf("\n获得明文：%s\n\n", msg);
}

//密钥派生函数 
int kdf(unsigned char *x2andy2_byte, int klen, unsigned char *kbuf)
{

	unsigned char buf[70];
	unsigned char digest[32];
	unsigned int ct = 0x00000001; //初始化一个32比特构成的计数器ct
	int i, m, n;
	unsigned char* p;

	memcpy(buf, x2andy2_byte, 64);

	m = klen / 32;
	n = klen % 32;
	p = kbuf;

	for (i = 0; i < m; i++)       //buf 64-70
	{
		buf[64] = (ct >> 24) & 0xFF;   //ct前8位
		buf[65] = (ct >> 16) & 0xFF;
		buf[66] = (ct >> 8) & 0xFF;
		buf[67] = ct & 0xFF;
		sm3(buf, 68, p);                       //sm3后结果放在p中
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
		return 1;   //非全0
	else
		return 0;  //全0

}
