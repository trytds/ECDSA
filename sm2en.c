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
static miracl* pm;
char plain[5000]; //明文
char msg[6000]; //密文
unsigned char x2andy2_byte[64];

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

	int klen;  //期望得到的密钥byte长度 这里也设置为全局变量
	FILE* fp; //存放明文
	fopen_s(&fp, "3.txt", "r+");
	fgets(plain, 255, fp); //明文存放到数组中 从fp指向的文件读取255个字符到plain中
	fclose(fp);
	printf("\n明文: %s\n\n", plain);

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
	klen = strlen(plain);  //需要派生得到的长度
	if (kdf(x2andy2_byte, klen, (unsigned char*)msg + 64) == 0) //如果t为全0的比特串 则返回
		return 0;

	//进入A6 C2  密文从65位开始为c2
	for (int i = 0; i < klen; i++)
	{
		msg[64 + i] ^= plain[i];
	}

	//进入A7 C3 = msg + 64 + klen
	char temp[6000];
	memcpy(temp, x2andy2_byte, 32); 
	memcpy(temp + 32, plain, klen);
	memcpy(temp + 32 + klen, x2andy2_byte + 32, 32);
	sm3((unsigned char*)temp, 64 + klen, (unsigned char*)msg + 64 + klen);

	printf("发送消息（C1||C2||C3）生成，发送消息长度：%dbyte \n内容：", 32 + 64 + klen);
	big m;
	m = mirvar(0);
	bytes_to_big(32 + 64 + klen, msg, m); //将32+64+klen字符的明文，转换成大数
	pm->IOBASE = 16;
	cotnum(m, stdout);

	printf("\n密文: %x\n\n", msg);  //十六进制输出防止乱码

}

//sm2解密
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
	dbC1 = epoint_init();//初始化点
	
	//开始解密
	printf("——————————开始解密——————————\n");

	bytes_to_big(32, (char *)msg, x1);    //从msg中分别取出32位放入x和y
	bytes_to_big(32, (char *)msg + 32, y1);

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
	klen = strlen(plain);
	//如果kdf返回的值为0，退出
	if (kdf(x2andy2_byte, klen, (unsigned char*)plain) == 0)
	{
		printf("t全0\n");
		return 0;
	}

	//进入B5
	for (int i = 0; i < klen; i++)     //M'(outmsg)=C2 ^ t(outmsg)
	{
		plain[i] ^= msg[i + 64];//密文从65位开始为c2
	}

	//进入B6
	char temp[6000];         
	memset(temp, 0, sizeof(temp));
	memcpy(temp, x2andy2_byte, 32);
	memcpy(temp + 32, plain, klen);
	memcpy(temp + 32 + klen, x2andy2_byte + 32, 32);
	char u[32];
	sm3((unsigned char*)temp, 64 + klen, (unsigned char*)u);
	if (memcmp(u, msg + 64 + klen, 32) != 0)//判断u=c3则继续
	{
		printf("error；\n");
	}
	printf("\n获得明文：%s\n\n", plain);
}

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

