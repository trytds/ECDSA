//#include "miracl.h"
//#include "mirdef.h"
//#include "time.h"
//#include <stdlib.h>
//#include <stdio.h>
//
//
//typedef struct
//{
//    big r;
//    big s;
//}digital_sign;
//
//static big g_p;
//static big g_a;
//static big g_b;
//static big g_n;
//static big g_nb;
//static epoint* g_q;
//static epoint* g_G;
//
////定义参数  eccsecp256k1的固定参数
//static const char eccdsa_p[] = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
//static const char eccdsa_a[] = "0000000000000000000000000000000000000000000000000000000000000000";
//static const char eccdsa_b[] = "0000000000000000000000000000000000000000000000000000000000000007";
//static const char eccdsa_n[] = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
//static const char eccdsa_gx[] = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
//static const char eccdsa_gy[] = "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";
//
//void initECDSA(miracl* pm)
//{
//    pm->IOBASE = 16;
//    g_p = mirvar(0);
//    g_a = mirvar(0);
//    g_b = mirvar(0);
//    g_n = mirvar(0);
//    cinstr(g_p, (char*)eccdsa_p);
//    cinstr(g_a, (char*)eccdsa_a);
//    cinstr(g_b, (char*)eccdsa_b);
//    cinstr(g_n, (char*)eccdsa_n);
//
//    ecurve_init(g_a, g_b, g_p, MR_AFFINE);
//    big tmp_x = mirvar(0);
//    big tmp_y = mirvar(0);
//    cinstr(tmp_x, (char*)eccdsa_gx);
//    cinstr(tmp_y, (char*)eccdsa_gy);
//    g_G = epoint_init(); //内存分配给gf(p)椭圆曲线一个点 初始化为无穷大
//    //设置点坐标 若属于当前方程返回true 不满足方程返回false
//    if (!epoint_set(tmp_x, tmp_y, 1, g_G))
//    {
//        exit(0);
//    }
//
//    //私钥
//    g_nb = mirvar(0);
//    irand(time(NULL));
//    bigbits(256, g_nb); //产生一个256位的大整数
//
//    while (mr_compare(g_nb, g_n) >= 0) //私钥nb要比n小
//    {
//        bigbits(256, g_nb);
//    }
//    //公钥
//    g_q = epoint_init();
//    ecurve_mult(g_nb, g_G, g_q); //大k=q  ecurve_mult为点乘
//
//  /*  epoint_free(g_q);
//    mirexit();*/   //free又被调用了 典型错误
//}
//
//digital_sign signECDSA(miracl* pm, big z)
//{
//    big k = mirvar(0); //随机数产生器产生随机数k[1,n-1] 
//    irand(time(NULL));
//    bigrand(g_n, k); //产生一个小于g_n的大数随机数 k mz
//
//    epoint* p = epoint_init();
//    ecurve_mult(k, g_G, p); //a4 计算椭圆曲线点p(x1,y1) = kg 公开密钥 
//
//    //big r = mirvar(0);
//    //r = p->X;
//
//    digital_sign a;
//    a.r = mirvar(0);
//    a.s = mirvar(0);
//    pm->IOBASE = 16;
//    a.r = p->X;
//    divide(a.r, g_n, g_n);//r=p(x)modn
//    while (a.r == 0)  //计算椭圆曲线点r=zmodn 若r=0则返回第一步
//    {
//        irand(time(NULL));
//        bigrand(g_n, k);
//        ecurve_mult(k, g_G, p);
//        a.r = p->X;
//        divide(a.r, g_n, g_n);
//    }
//
//    //getchar();
//    big tmp_rd = mirvar(0);
//    xgcd(k, g_n, k, k, k);  //求出k(-1)
//    multiply(g_nb, a.r, tmp_rd); //计算d*r
//    add(tmp_rd, z, tmp_rd); //计算e+d*r
//    multiply(k, tmp_rd, tmp_rd); //计算k(-1)(e+dr)
//    divide(tmp_rd, g_n, g_n); //计算s=k(-1)(e+dr)modn
//    a.s = tmp_rd;
//    while (a.s==0)  //a6 若s==0 则返回a3
//    {
//        irand(time(NULL));
//        bigrand(g_n, k);
//        ecurve_mult(k, g_G, p);
//        //r = p->X;
//        a.r = p->X;
//        //divide(r, g_n, g_n);
//        divide(a.r, g_n, g_n);
//        while (a.r == 0) //计算r=zmodn 若r=0则返回第一步
//        {
//            irand(time(NULL));
//            bigrand(g_n, k);
//            ecurve_mult(k, g_G, p);
//            a.r = p->X;
//            divide(a.r, g_n, g_n);
//        }
//        multiply(g_nb, a.r, tmp_rd); //da*r
//        add(tmp_rd, z, tmp_rd); // z是hash后的z  z+da*r
//        multiply(k, tmp_rd, tmp_rd);//k(-1)*(z+da*r)
//        divide(tmp_rd, g_n, g_n); //k(-1)*(z+da*r)modn
//        a.s = tmp_rd;
//    } //(r,s)计算完毕
//      add(a.s,g_n,a.s);
//      divide(a.s,g_n,g_n); //g_n=a.s/g_n a.s=a.smodg_n
//    return a;
//}
//
//int vertifyECDSA(digital_sign a, miracl* pm, big z)
//{
//    if (!(a.r > 0 && mr_compare(g_n, a.r))) //b1 检验r'[1,n-1]是否成立
//    {
//        return 0;
//    }
//
//    if (!(a.s > 0 && mr_compare(g_n, a.s))) //b2 检验s'[1,n-1]是否成立
//    {
//        return 0;
//    }
//    big w = mirvar(0);
//    w = a.s;
//    xgcd(w, g_n, w, w, w); //s取逆 关于mod n的逆元
//    big u1 = mirvar(0);
//    multiply(z, w, u1); //u1=s(-1)z z是个hash值
//    divide(u1, g_n, g_n); //u1=s(-1)zmodn
//
//    big u2 = mirvar(0);
//    multiply(a.r, w, u2);
//    divide(u2, g_n, g_n);//u2=w(-1)rmodn
//
//    epoint* g_xy1; //计算椭圆曲线点(x'1,y'1)=[u1]g+[u2]ha 
//    g_xy1 = epoint_init();
//    ecurve_mult(u1, g_G, g_xy1);
//    epoint* g_xy2;
//    g_xy2 = epoint_init();
//    ecurve_mult(u2, g_q, g_xy2); //u2*ha   
//    ecurve_add(g_xy1, g_xy2); //g_xy2=g_xy2+g_xy1
//    big r = mirvar(0); //b7 计算r=x'1 mod n 检验r=r'是否成立 若成立则验证通过
//    r = g_xy2->X;
//    divide(r, g_n, g_n);
//    if (!mr_compare(r, a.r))
//    {
//        return 1;
//    }
//    return 0;
//}
//
//int main()
//{
//    miracl* pm = mirsys(500, 16);
//    big z = mirvar(0);
//    double duration;
//    bigdig(32, 16, z); //产生32位的16进制随机数
//    clock_t start, finish;
//    start = clock();
//    initECDSA(pm);
//    finish = clock();
//    duration = (double)(finish - start) / CLOCKS_PER_SEC;
//    printf("keygen: %f seconds\n", duration);
//    start = clock();
//    digital_sign a = signECDSA(pm, z);  //这里有毛病
//    finish = clock();
//    duration = (double)(finish - start) / CLOCKS_PER_SEC;
//    printf("sign: %f seconds\n", duration);
//    printf("r:");
//    cotnum(a.r, stdout);
//    printf("s:");
//    cotnum(a.s, stdout);
//    start = clock();
//    int r = vertifyECDSA(a, pm, z);
//    finish = clock();
//    duration = (double)(finish - start) / CLOCKS_PER_SEC;
//    printf("vertify: %f seconds\n", duration);
//    if (1 == r)
//    {
//        printf("success\n");
//    }
//    else
//    {
//        printf("error\n");
//    }
//    return 0;
//}