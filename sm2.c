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
//static big g_p;
//static big g_a;
//static big g_b;
//static big g_n;
//static big g_nb;
//static epoint* g_Q; //公钥
//static epoint* g_G; //基点
//
////素数域256位椭圆曲线定义参数
//static const char sm2_p[] = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF";
//static const char sm2_a[] = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC";
//static const char sm2_b[] = "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93";
//static const char sm2_n[] = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123";
//static const char sm2_Gx[] = "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7";
//static const char sm2_Gy[] = "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0";
//
//
//void initSM2(miracl* pm)
//{
//	pm->IOBASE = 16;
//	g_p = mirvar(0);
//	g_a = mirvar(0);
//	g_b = mirvar(0);
//	g_n = mirvar(0);
//
//	cinstr(g_p, (char*)sm2_p);
//	cinstr(g_a, (char*)sm2_a);
//	cinstr(g_b, (char*)sm2_b);
//	cinstr(g_n, (char*)sm2_n);
//
//	ecurve_init(g_a, g_b, g_p, MR_AFFINE);
//
//	big tmp_x = mirvar(0);
//	big tmp_y = mirvar(0);
//	cinstr(tmp_x, (char*)sm2_Gx);
//	cinstr(tmp_y, (char*)sm2_Gy);
//	g_G = epoint_init();//内存分配给gf(p)椭圆曲线一个点 初始化为无穷大
//	//设置点坐标 若属于当前方程返回true 不满足方程返回false
//	if (!epoint_set(tmp_x, tmp_y, 1, g_G))
//	{
//		exit(0);
//	}
//
//	//私钥
//	g_nb = mirvar(0);
//	irand(time(NULL));
//	bigbits(256, g_nb);
//
//	while (mr_compare(g_nb, g_n) >= 0)
//	{
//		bigbits(256, g_nb);
//	}
//
//	//公钥
//	g_Q = epoint_init();
//	ecurve_mult(g_nb, g_G, g_Q);  //g_Q = g_nb*g_G
//}
//
////sm2签名
//void signSM2(unsigned char* hash, int hashlen, unsigned char* privkey, int privkeylen, unsigned char* cr, int* rlen, unsigned char* cs, int* slen)
//{
//	/*
//功能：SM2签名
//[输入] hash：    sm3_e()的结果
//[输入] hashlen： hash的字节数，应为32
//[输入] privkey： 私钥
//[输入] privkeylen： privkeylen的字节数
//
//[输出] cr：  签名结果的第一部分，不足32字节在前面加0x00。
//[输出] rlen：cr的字节数，32
//[输出] cs：  签名结果的第二部分，不足32字节在前面加0x00。
//[输出] slen：cs的字节数，32
//*/
//	big e,g_nb;
//	miracl* mip = mirsys(20, 0);
//	mip->IOBASE = 16;
//	big k = mirvar(0);
//
//	e = mirvar(0);
//	g_nb = mirvar(0);
//	bytes_to_big(privkeylen, (char*)privkey, g_nb);
//	
//	irand(time(NULL));
//	bigrand(g_n, k);
//
//	epoint* p = epoint_init();
//	ecurve_mult(k, g_G, p); //A4 计算椭圆曲线点(x1,y1)=[k]G
//	bytes_to_big(hashlen, (char*)hash, e);
//
//	digital_sign a; //计算r=(e+x1)modn r=0 or r+k=n 返回3
//	a.r = mirvar(0);
//	a.s = mirvar(0);
//	
//
//	add(e, p->X, a.r); //z是Hash值  a.r=z+kk->X
//
//	big tmp_rk = mirvar(0);
//	add(a.r, k, tmp_rk);
//	divide(a.r, g_n, g_n);
//	while (0 == a.r || tmp_rk == g_n) //返回3
//	{
//		irand(time(NULL));
//		bigrand(g_n, k);
//		ecurve_mult(k, g_G, p);
//		add(e, p->X, a.r); //e+x1
//		add(a.r, k, tmp_rk);
//		divide(a.r, g_n, g_n);//r=(e+x1)mod n
//	} //r计算完毕
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
//	xgcd(tmp_s, g_n, tmp_s, tmp_s, tmp_s); //(dA+1)-1
//
//	multiply(tmp_s, tmp6, a.s); //(dA+1)-1*(k-r*dA)
//	divide(a.s, g_n, g_n);
//	while (0 == a.s)
//	{
//		irand(time(NULL));
//		bigrand(g_n, k);
//		ecurve_mult(k, g_G, p);
//		add(e, p->X, a.r);
//		add(a.r, k, tmp_rk);
//		divide(a.r, g_n, g_n);
//		while (0 == a.r || tmp_rk == g_n) //r=0 or r+k=n 返回3
//		{
//			irand(time(NULL));
//			bigrand(g_n, k);
//			ecurve_mult(k, g_G, p);
//			add(e, p->X, a.r);
//			add(a.r, k, tmp_rk);
//			divide(a.r, g_n, g_n);
//		}
//		multiply(g_nb, a.r, tmp_rk);//r*dA
//		subtract(k, tmp_rk, tmp6);//k-r*dA
//		divide(tmp6, g_n, g_n);
//		add(tmp6, g_n, a.s); //处理负号
//		divide(tmp6, g_n, g_n);
//		incr(g_nb, 1, tmp_s);
//		xgcd(tmp_s, g_n, tmp_s, tmp_s, tmp_s);//(1+dA)-1
//		multiply(tmp_s, tmp6, a.s);
//		divide(a.s, g_n, g_n);
//	}
//
//	*rlen = big_to_bytes(32, a.r, (char*)cr, TRUE);
//	*slen = big_to_bytes(32, a.s, (char*)cs, TRUE);
//
//	add(a.s, g_n, a.s);
//	divide(a.s, g_n, g_n);
//	return a;
//}
//
////sm2验证
//int vertifySM2(unsigned char* hash, int hashlen, unsigned char* cr, int rlen, unsigned char* cs, int slen, unsigned char* wx, int wxlen, unsigned char* wy, int wylen)
//{
//	digital_sign m; 
//	m.r = mirvar(0);
//	m.s = mirvar(0);
//	big e = mirvar(0);  //生成的Hash值
//	big v = mirvar(0);
//	miracl* mip = mirsys(20, 0);
//	mip->IOBASE = 16;
//	
//	big a, b, p, n, x, y;
//	p = mirvar(0);
//	a = mirvar(0);
//	b = mirvar(0);
//	n = mirvar(0);
//	x = mirvar(0);
//	y = mirvar(0);
//	cinstr(p, (char*)sm2_p);
//	cinstr(a, (char*)sm2_a);
//	cinstr(b, (char*)sm2_b);
//	cinstr(n, (char*)sm2_n);
//	cinstr(x, (char*)sm2_Gx);
//	cinstr(y, (char*)sm2_Gy);
//	ecurve_init(a, b, p, MR_PROJECTIVE);
//
//	epoint* g_xy1;
//	g_xy1 = epoint_init();
//	epoint* g_xy2;
//	g_xy2 = epoint_init();
//	g_xy1 = epoint_init(); //g_xy1  g
//	g_xy2 = epoint_init(); //g_xy2  w
//	epoint_set(x, y, 0, g_xy1);
//	bytes_to_big(wxlen, (char*)wx, x);
//	bytes_to_big(wylen, (char*)wy, y);
//	if (!epoint_set(x, y, 0, g_xy2))
//		exit(0);
//
//	bytes_to_big(hashlen, (char*)hash, e); //Hash值
//	bytes_to_big(rlen, (char*)cr, m.r); //digital_sign a.r 
//	bytes_to_big(slen, (char*)cs, m.s); //digital_sign a.s
//
//	if (!(m.r > 0 && mr_compare(g_n, m.r)))
//	{
//		return 0;
//	}
//	if (!(m.s > 0 && mr_compare(g_n, m.s)))
//	{
//		return 0;
//	}
//
//
//	add(m.s, m.r, a);
//	divide(a, n, n);
//	if (a->len == 0)
//		return 0;
//
//	ecurve_mult2(m.s, g_xy1, a, g_xy2, g_xy1);
//	epoint_get(g_xy1, v, v);
//
//	add(v, e, v);
//	divide(v, n, n);
//	if (compare(v, m.r) == 0)
//		return 0;
//	return -1;
//
//}
//
//
//void PrintBuf(unsigned char* buf, int buflen)
//{
//	int i;
//	printf("\n");
//	printf("len = %d\n", buflen);
//	for (i = 0; i < buflen; i++) {
//		if (i % 32 != 31)
//			printf("%02x", buf[i]);
//		else
//			printf("%02x\n", buf[i]);
//	}
//	printf("\n");
//	return;
//}
//
//void PrintBig(big data)
//{
//	int len = 0;
//	unsigned char buf[10240];
//
//	len = big_to_bytes(0, data, (char*)buf, 0);
//	PrintBuf(buf, len);
//}
//
//
//int sm3_e(unsigned char* userid, int userid_len, unsigned char* xa, int xa_len, unsigned char* ya, int ya_len, unsigned char* msg, int msg_len, unsigned char* e)
//{
//	/*
//	功能：根据用户ID及公钥，求用于签名或验签的消息HASH值
//	[输入] userid： 用户ID
//	[输入] userid_len： userid的字节数
//	[输入] xa： 公钥的X坐标
//	[输入] xa_len: xa的字节数
//	[输入] ya： 公钥的Y坐标
//	[输入] ya_len: ya的字节数
//	[输入] msg：要签名的消息
//	[输入] msg_len： msg的字节数
//	[输出] e：32字节，用于签名或验签
//
//	返回值：
//			－1：内存不足
//			  0：成功
//	*/
//	unsigned char* buf;
//	int userid_bitlen;
//
//	if ((xa_len > 32) || (ya_len > 32))
//		return -1;
//
//	buf = malloc(2 + userid_len + 128 + 32 + 32);
//	if (buf == NULL)
//		return -1;
//
//	userid_bitlen = userid_len << 3;
//	buf[0] = (userid_bitlen >> 8) & 0xFF;
//	buf[1] = userid_bitlen & 0xFF;
//
//	memcpy(buf + 2, userid, userid_len);
//	memset(buf + 2 + userid_len + 128, 0, 64);
//	memcpy(buf + 2 + userid_len + 128 + 32 - xa_len, xa, 32);
//	memcpy(buf + 2 + userid_len + 128 + 32 + 32 - ya_len, ya, 32);
//
//	sm3(buf, 2 + userid_len + 128 + 32 + 32, e);
//	free(buf);
//
//	printf("sm3_e: ");
//	PrintBuf(e, 32);
//
//	buf = malloc(msg_len + 32);
//	if (buf == NULL)
//		return -1;
//
//	memcpy(buf, e, 32);
//	memcpy(buf + 32, msg, msg_len);
//	sm3(buf, 32 + msg_len, e);
//	free(buf);
//	return 0;
//}
//
//int main()
//{
//	int rlen, slen;
//	unsigned char etx[256];
//	unsigned char digest_sm2[] = { 0xB5,0x24,0xF5,0x52,0xCD,0x82,0xB8,0xB0,0x28,0x47,0x6E,0x00,0x5C,0x37,0x7F,0xB1,0x9A,0x87,0xE6,0xFC,0x68,0x2D,0x48,0xBB,0x5D,0x42,0xE3,0xD9,0xB9,0xEF,0xFE,0x76 };
//	unsigned char kA_sm2[] = { 0x12,0x8B,0x2F,0xA8,0xBD,0x43,0x3C,0x6C,0x06,0x8C,0x8D,0x80,0x3D,0xFF,0x79,0x79,0x2A,0x51,0x9A,0x55,0x17,0x1B,0x1B,0x65,0x0C,0x23,0x66,0x1D,0x15,0x89,0x72,0x63 };
//	unsigned char kAx_sm2[] = { 0x0A,0xE4,0xC7,0x79,0x8A,0xA0,0xF1,0x19,0x47,0x1B,0xEE,0x11,0x82,0x5B,0xE4,0x62,0x02,0xBB,0x79,0xE2,0xA5,0x84,0x44,0x95,0xE9,0x7C,0x04,0xFF,0x4D,0xF2,0x54,0x8A };
//	unsigned char kAy_sm2[] = { 0x7C,0x02,0x40,0xF8,0x8F,0x1C,0xD4,0xE1,0x63,0x52,0xA7,0x3C,0x17,0xB7,0xF1,0x6F,0x07,0x35,0x3E,0x53,0xA1,0x76,0xD6,0x84,0xA9,0xFE,0x0C,0x6B,0xB7,0x98,0xE8,0x57 };
//	unsigned char r_sm2[] = { 0x40,0xF1,0xEC,0x59,0xF7,0x93,0xD9,0xF4,0x9E,0x09,0xDC,0xEF,0x49,0x13,0x0D,0x41,0x94,0xF7,0x9F,0xB1,0xEE,0xD2,0xCA,0xA5,0x5B,0xAC,0xDB,0x49,0xC4,0xE7,0x55,0xD1 };
//	unsigned char s_sm2[] = { 0x6F,0xC6,0xDA,0xC3,0x2C,0x5D,0x5C,0xF1,0x0C,0x77,0xDF,0xB2,0x0F,0x7C,0x2E,0xB6,0x67,0xA4,0x57,0x87,0x2F,0xB0,0x9E,0xC5,0x63,0x27,0xA6,0x7E,0xC7,0xDE,0xEB,0xE7 };
//	unsigned char userid[] = "ALICE123@YAHOO.COM";
//	unsigned char msg[] = "message digest";
//	miracl* pm = mirsys(500, 16);
//	
//	printf("sm3_e: ");
//	PrintBuf(etx, 32);
//
//	double duration;
//	clock_t start, finish;
//
//	start = clock();
//	initSM2(pm);
//	finish = clock();
//	duration = (double)(finish - start) / CLOCKS_PER_SEC;
//	printf("KeyGen: %f seconds\n", duration);
//
//	start = clock();
//	sm2_sign(digest_sm2, 32, kA_sm2, 32, r_sm2, &rlen, s_sm2, &slen);
//	finish = clock();
//	duration = (double)(finish - start) / CLOCKS_PER_SEC;
//	printf("Sign: %f seconds\n", duration);
//	/*printf("r:");
//	cotnum(m.r, stdout);
//	printf("s:");
//	cotnum(a.s, stdout);*/
//
//	start = clock();
//	int r = vertifySM2(digest_sm2, 32, r_sm2, 32, s_sm2, 32, kAx_sm2, 32, kAy_sm2, 32);
//	finish = clock();
//	duration = (double)(finish - start) / CLOCKS_PER_SEC;
//	printf("Vertify: %f seconds\n", duration);
//	if (1 == r)
//	{
//		printf("Vertify");
//	}
//	else
//	{
//		printf("No\n");
//	}
//	return 0;
//}