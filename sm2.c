#include <stdio.h>
#include "miracl.h"
#include "mirdef.h"
#include "string.h"
#include <time.h>


typedef struct
{
	big r;
	big s;
}digital_sign;

static big g_p;
static big g_a;
static big g_b;
static big g_n;
static big g_nb;
static epoint* g_Q; //公钥
static epoint* g_G; //基点

//定义参数
static const char sm2_p[] = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF";
static const char sm2_a[] = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC";
static const char sm2_b[] = "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93";
static const char sm2_n[] = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123";
static const char sm2_Gx[] = "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7";
static const char sm2_Gy[] = "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0";


void initSM2(miracl* pm)
{
	pm->IOBASE = 16;
	g_p = mirvar(0);
	g_a = mirvar(0);
	g_b = mirvar(0);
	g_n = mirvar(0);

	cinstr(g_p, (char*)sm2_p);
	cinstr(g_a, (char*)sm2_a);
	cinstr(g_b, (char*)sm2_b);
	cinstr(g_n, (char*)sm2_n);

	ecurve_init(g_a, g_b, g_p, MR_AFFINE);

	big tmp_x = mirvar(0);
	big tmp_y = mirvar(0);
	cinstr(tmp_x, (char*)sm2_Gx);
	cinstr(tmp_y, (char*)sm2_Gy);
	g_G = epoint_init();//内存分配给gf(p)椭圆曲线一个点 初始化为无穷大
    //设置点坐标 若属于当前方程返回true 不满足方程返回false
	if (!epoint_set(tmp_x, tmp_y, 1, g_G))
	{
		exit(0);
	}

	//私钥
	g_nb = mirvar(0);
	irand(time(NULL));
	bigbits(256, g_nb);

	while (mr_compare(g_nb, g_n) >= 0)
	{
		bigbits(256, g_nb);
	}

	//公钥
	g_Q = epoint_init();
	ecurve_mult(g_nb, g_G, g_Q);  //g_Q = g_nb*g_G
}

//sm2签名
digital_sign signSM2(miracl* pm, big z)
{
	big k = mirvar(0);
	irand(time(NULL));
	bigrand(g_n, k);

	epoint* p = epoint_init();
	ecurve_mult(k, g_G, p); //A4 计算椭圆曲线点(x1,y1)=[k]G

	digital_sign a; //计算r=(e+x1)modn r=0 or r+k=n 返回3
	a.r = mirvar(0);
	a.s = mirvar(0);
	pm->IOBASE = 16;

	add(z, p->X, a.r); //z是Hash值  a.r=z+kk->X

	big tmp_rk = mirvar(0); 
	add(a.r, k, tmp_rk);
	divide(a.r, g_n, g_n);
	while (0 == a.r || tmp_rk == g_n) //返回3
	{
		irand(time(NULL));
		bigrand(g_n, k);
		ecurve_mult(k, g_G, p);
		add(z, p->X, a.r); //e+x1
		add(a.r, k, tmp_rk); 
		divide(a.r, g_n, g_n);//r=(e+x1)mod n
	} //r计算完毕
	big tmp_rd = mirvar(0);
	big tmp6 = mirvar(0);
	
	multiply(g_nb, a.r, tmp_rd);//r*dA
	multiply(g_n, k, tmp_rk);  //k*n
	add(tmp_rk, k, tmp_rk); //k*n+k
	subtract(tmp_rk, tmp_rd, tmp6); //n*k+k-r*dA
	divide(tmp6, g_n, g_n); //(n*k+k-r*dA)mod n
	big tmp_s = mirvar(0);
	incr(g_nb, 1, tmp_s); //dA+1
	xgcd(tmp_s, g_n, tmp_s, tmp_s,tmp_s); //(dA+1)-1

	multiply(tmp_s, tmp6, a.s); //(dA+1)-1*(k-r*dA)
	divide(a.s, g_n, g_n);
	while (0 == a.s)
	{
		irand(time(NULL));
		bigrand(g_n, k);
		ecurve_mult(k, g_G, p);
		add(z, p->X, a.r);
		add(a.r, k, tmp_rk);
		divide(a.r, g_n, g_n);
		while (0 == a.r || tmp_rk == g_n) //r=0 or r+k=n 返回3
		{
			irand(time(NULL));
			bigrand(g_n, k);
			ecurve_mult(k, g_G, p);
			add(z, p->X, a.r);
			add(a.r, k, tmp_rk);
			divide(a.r, g_n, g_n);
		}
		multiply(g_nb, a.r, tmp_rk);//r*dA
		subtract(k, tmp_rk, tmp6);//k-r*dA
		divide(tmp6, g_n, g_n);
		add(tmp6, g_n, a.s); //处理负号
		divide(tmp6, g_n, g_n);
		incr(g_nb, 1, tmp_s);
		xgcd(tmp_s, g_n, tmp_s, tmp_s,tmp_s);//(1+dA)-1
		multiply(tmp_s, tmp6, a.s);
		divide(a.s, g_n, g_n);
	}
	add(a.s, g_n, a.s);
	divide(a.s, g_n, g_n);
	return a;
}

//sm2验证
int vertifySM2(digital_sign a, miracl* pm, big z)
{
	if (!(a.r > 0 && mr_compare(g_n, a.r)))
	{
		return 0;
	}
	if (!(a.s > 0 && mr_compare(g_n, a.s)))
	{
		return 0;
	}

	big t = mirvar(0);
	add(a.r, a.s, t);
	divide(t, g_n, g_n);
	if (0 == t)
	{
		return 0;
	}
	epoint* g_xy1;
	g_xy1 = epoint_init();
	ecurve_mult(a.s, g_G, g_xy1);

	epoint* g_xy2;
	g_xy2 = epoint_init();
	ecurve_mult(t, g_Q, g_xy2);
	ecurve_add(g_xy1, g_xy2);

	big R = mirvar(0);
	add(z, g_xy2->X, R);
	divide(R, g_n, g_n);
	if (!mr_compare(R, a.r))  //计算R=(e’+x1’)mod n，检验R=r’是否成立
	{
		return 1;
	}
	return 0;
}

int main()
{
	miracl* pm = mirsys(500, 16);
	big z = mirvar(0);
	double duration;
	bigdig(32, 16, z);
	clock_t start, finish;

	start = clock();
	initSM2(pm);
	finish = clock();
	duration = (double)(finish - start) / CLOCKS_PER_SEC;
	printf("KeyGen: %f seconds\n", duration);

	start = clock();
	digital_sign a = signSM2(pm, z);
	finish = clock();
	duration = (double)(finish - start) / CLOCKS_PER_SEC;
	printf("Sign: %f seconds\n", duration);
	printf("r:");
	cotnum(a.r, stdout);
	printf("s:");
	cotnum(a.s, stdout);

	start = clock();
	int r = vertifySM2(a, pm, z);
	finish = clock();
	duration = (double)(finish - start) / CLOCKS_PER_SEC;
	printf("Vertify: %f seconds\n", duration);
	if (1 == r)
	{
		printf("Success\n");
	}
	else
	{
		printf("Error\n");
	}
	return 0;
}