#include "miracl.h"
#include "mirdef.h"
#include "time.h"
#include <stdlib.h>
#include <stdio.h>



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
static epoint* g_Q;
static epoint* g_G;

//�������  ECCSecp256k1�Ĺ̶�����
static const char eccdsa_p[] = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
static const char eccdsa_a[] = "0000000000000000000000000000000000000000000000000000000000000000";
static const char eccdsa_b[] = "0000000000000000000000000000000000000000000000000000000000000007";
static const char eccdsa_n[] = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
static const char eccdsa_Gx[] = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
static const char eccdsa_Gy[] = "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";

void initECDSA(miracl* pm)
{
    pm->IOBASE = 16;
    g_p = mirvar(0);
    g_a = mirvar(0);
    g_b = mirvar(0);
    g_n = mirvar(0);
    cinstr(g_p, (char*)eccdsa_p);
    cinstr(g_a, (char*)eccdsa_a);
    cinstr(g_b, (char*)eccdsa_b);
    cinstr(g_n, (char*)eccdsa_n);

    ecurve_init(g_a, g_b, g_p, MR_AFFINE);
    big tmp_x = mirvar(0);
    big tmp_y = mirvar(0);
    cinstr(tmp_x, (char*)eccdsa_Gx);
    cinstr(tmp_y, (char*)eccdsa_Gy);
    g_G = epoint_init(); //�ڴ�����GF(p)��Բ����һ���� ��ʼ��Ϊ�����
    //���õ����� �����ڵ�ǰ���̷���true �����㷽�̷���false
    if (!epoint_set(tmp_x, tmp_y, 1, g_G))
    {
        exit(0);
    }

    //˽Կ
    g_nb = mirvar(0);
    irand(time(NULL));
    bigbits(256, g_nb); //����һ��256λ�Ĵ�����

    while (mr_compare(g_nb, g_n) >= 0) //˽ԿnbҪ��nС
    {
        bigbits(256, g_nb);
    }
    //��Կ
    g_Q = epoint_init();
    ecurve_mult(g_nb, g_G, g_Q); //��K=Q  ecurve_multΪ���

  /*  epoint_free(g_Q);
    mirexit();*/   //free�ֱ������� ���ʹ���
}

digital_sign signECDSA(miracl* pm, big z)
{
    big k = mirvar(0); //��������������������k[1,n-1] 
    irand(time(NULL));

    bigrand(g_n, k); //����һ��С��g_n�Ĵ�������� k mZ

    epoint* P = epoint_init();
    ecurve_mult(k, g_G, P); //A4 ������Բ���ߵ�P(x1,y1) = kG ������Կ 

    big r = mirvar(0);
    r = P->X;
    divide(r, g_n, g_n);//r=P(x)modn
    while (r == 0)  //������Բ���ߵ�r=zmodn ��r=0�򷵻ص�һ��
    {
        irand(time(NULL));
        bigrand(g_n, k);
        ecurve_mult(k, g_G, P);
        r = P->X;
        divide(r, g_n, g_n);
    }

    digital_sign a;
    a.r = mirvar(0);
    a.s = mirvar(0);
    pm->IOBASE = 16;
    //getchar();
    big tmp_rd = mirvar(0);
    xgcd(k, g_n, k, k, k);  //���k(-1)
    multiply(g_nb, a.r, tmp_rd); //����d*r
    add(tmp_rd, z, tmp_rd); //����e+d*r
    multiply(k, tmp_rd, tmp_rd); //����k(-1)(e+dr)
    divide(tmp_rd, g_n, g_n); //����s=k(-1)(e+dr)modn
    a.s = tmp_rd;
    while (0 == a.s)  //A6 ��s==0 �򷵻�A3
    {
        irand(time(NULL));
        bigrand(g_n, k);
        ecurve_mult(k, g_G, P);
        r = P->X;
        divide(r, g_n, g_n);
        while (r == 0) //����r=zmodn ��r=0�򷵻ص�һ��
        {
            irand(time(NULL));
            bigrand(g_n, k);
            ecurve_mult(k, g_G, P);
            r = P->X;
            divide(r, g_n, g_n);
        }
        multiply(g_nb, a.r, tmp_rd); //dA*r
        add(tmp_rd, z, tmp_rd); // z��hash���z  z+dA*r
        multiply(k, tmp_rd, tmp_rd);//k(-1)*(z+dA*r)
        divide(tmp_rd, g_n, g_n); //k(-1)*(z+dA*r)modn
        a.s = tmp_rd;
    } //(r,s)�������
      //add(a.s,g_n,a.s);
      //divide(a.s,g_n,g_n); //g_n=a.s/g_n a.s=a.smodg_n
    return a;
}

int vertifyECDSA(digital_sign a, miracl* pm, big z)
{
    if (!(a.r > 0 && mr_compare(g_n, a.r))) //B1 ����r'[1,n-1]�Ƿ����
    {
        return 0;
    }

    if (!(a.s > 0 && mr_compare(g_n, a.s))) //B2 ����s'[1,n-1]�Ƿ����
    {
        return 0;
    }
    big w = mirvar(0);
    w = a.s;
    xgcd(w, g_n, w, w, w); //sȡ�� ����mod n����Ԫ
    big u1 = mirvar(0);
    multiply(z, w, u1); //u1=s(-1)z z�Ǹ�Hashֵ
    divide(u1, g_n, g_n); //u1=s(-1)zmodn

    big u2 = mirvar(0);
    multiply(a.r, w, u2);
    divide(u2, g_n, g_n);//u2=w(-1)rmodn

    epoint* g_xy1; //������Բ���ߵ�(x'1,y'1)=[u1]G+[u2]HA 
    g_xy1 = epoint_init();
    ecurve_mult(u1, g_G, g_xy1);
    epoint* g_xy2;
    g_xy2 = epoint_init();
    ecurve_mult(u2, g_Q, g_xy2); //u2*HA   
    ecurve_add(g_xy1, g_xy2); //g_xy2=g_xy2+g_xy1
    big R = mirvar(0); //B7 ����R=x'1 mod n ����R=r'�Ƿ���� ����������֤ͨ��
    R = g_xy2->X;
    divide(R, g_n, g_n);
    if (!mr_compare(R, a.r))
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
    bigdig(32, 16, z); //����32λ��16���������
    clock_t start, finish;
    start = clock();
    initECDSA(pm);
    finish = clock();
    duration = (double)(finish - start) / CLOCKS_PER_SEC;
    printf("KeyGen: %f seconds\n", duration);
    start = clock();
    digital_sign a = signECDSA(pm, z);  //������ë��
    finish = clock();
    duration = (double)(finish - start) / CLOCKS_PER_SEC;
    printf("Sign: %f seconds\n", duration);
    printf("r:");
    cotnum(a.r, stdout);
    printf("s:");
    cotnum(a.s, stdout);
    start = clock();
    int r = vertifyECDSA(a, pm, z);
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
    //ShaTest();
    return 0;
}