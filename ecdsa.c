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
static epoint* g_q;
static epoint* g_g;

//�������  eccsecp256k1�Ĺ̶�����
static const char eccdsa_p[] = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
static const char eccdsa_a[] = "0000000000000000000000000000000000000000000000000000000000000000";
static const char eccdsa_b[] = "0000000000000000000000000000000000000000000000000000000000000007";
static const char eccdsa_n[] = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
static const char eccdsa_gx[] = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
static const char eccdsa_gy[] = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

void initecdsa(miracl* pm)
{
    pm->iobase = 16;
    g_p = mirvar(0);
    g_a = mirvar(0);
    g_b = mirvar(0);
    g_n = mirvar(0);
    cinstr(g_p, (char*)eccdsa_p);
    cinstr(g_a, (char*)eccdsa_a);
    cinstr(g_b, (char*)eccdsa_b);
    cinstr(g_n, (char*)eccdsa_n);

    ecurve_init(g_a, g_b, g_p, mr_affine);
    big tmp_x = mirvar(0);
    big tmp_y = mirvar(0);
    cinstr(tmp_x, (char*)eccdsa_gx);
    cinstr(tmp_y, (char*)eccdsa_gy);
    g_g = epoint_init(); //�ڴ�����gf(p)��Բ����һ���� ��ʼ��Ϊ�����
    //���õ����� �����ڵ�ǰ���̷���true �����㷽�̷���false
    if (!epoint_set(tmp_x, tmp_y, 1, g_g))
    {
        exit(0);
    }

    //˽Կ
    g_nb = mirvar(0);
    irand(time(null));
    bigbits(256, g_nb); //����һ��256λ�Ĵ�����

    while (mr_compare(g_nb, g_n) >= 0) //˽ԿnbҪ��nС
    {
        bigbits(256, g_nb);
    }
    //��Կ
    g_q = epoint_init();
    ecurve_mult(g_nb, g_g, g_q); //��k=q  ecurve_multΪ���

  /*  epoint_free(g_q);
    mirexit();*/   //free�ֱ������� ���ʹ���
}

digital_sign signecdsa(miracl* pm, big z)
{
    big k = mirvar(0); //��������������������k[1,n-1] 
    irand(time(null));

    bigrand(g_n, k); //����һ��С��g_n�Ĵ�������� k mz

    epoint* p = epoint_init();
    ecurve_mult(k, g_g, p); //a4 ������Բ���ߵ�p(x1,y1) = kg ������Կ 

    big r = mirvar(0);
    r = p->x;
    divide(r, g_n, g_n);//r=p(x)modn
    while (r == 0)  //������Բ���ߵ�r=zmodn ��r=0�򷵻ص�һ��
    {
        irand(time(null));
        bigrand(g_n, k);
        ecurve_mult(k, g_g, p);
        r = p->x;
        divide(r, g_n, g_n);
    }

    digital_sign a;
    a.r = mirvar(0);
    a.s = mirvar(0);
    pm->iobase = 16;
    //getchar();
    big tmp_rd = mirvar(0);
    xgcd(k, g_n, k, k, k);  //���k(-1)
    multiply(g_nb, a.r, tmp_rd); //����d*r
    add(tmp_rd, z, tmp_rd); //����e+d*r
    multiply(k, tmp_rd, tmp_rd); //����k(-1)(e+dr)
    divide(tmp_rd, g_n, g_n); //����s=k(-1)(e+dr)modn
    a.s = tmp_rd;
    while (0 == a.s)  //a6 ��s==0 �򷵻�a3
    {
        irand(time(null));
        bigrand(g_n, k);
        ecurve_mult(k, g_g, p);
        r = p->x;
        divide(r, g_n, g_n);
        while (r == 0) //����r=zmodn ��r=0�򷵻ص�һ��
        {
            irand(time(null));
            bigrand(g_n, k);
            ecurve_mult(k, g_g, p);
            r = p->x;
            divide(r, g_n, g_n);
        }
        multiply(g_nb, a.r, tmp_rd); //da*r
        add(tmp_rd, z, tmp_rd); // z��hash���z  z+da*r
        multiply(k, tmp_rd, tmp_rd);//k(-1)*(z+da*r)
        divide(tmp_rd, g_n, g_n); //k(-1)*(z+da*r)modn
        a.s = tmp_rd;
    } //(r,s)�������
      //add(a.s,g_n,a.s);
      //divide(a.s,g_n,g_n); //g_n=a.s/g_n a.s=a.smodg_n
    return a;
}

int vertifyecdsa(digital_sign a, miracl* pm, big z)
{
    if (!(a.r > 0 && mr_compare(g_n, a.r))) //b1 ����r'[1,n-1]�Ƿ����
    {
        return 0;
    }

    if (!(a.s > 0 && mr_compare(g_n, a.s))) //b2 ����s'[1,n-1]�Ƿ����
    {
        return 0;
    }
    big w = mirvar(0);
    w = a.s;
    xgcd(w, g_n, w, w, w); //sȡ�� ����mod n����Ԫ
    big u1 = mirvar(0);
    multiply(z, w, u1); //u1=s(-1)z z�Ǹ�hashֵ
    divide(u1, g_n, g_n); //u1=s(-1)zmodn

    big u2 = mirvar(0);
    multiply(a.r, w, u2);
    divide(u2, g_n, g_n);//u2=w(-1)rmodn

    epoint* g_xy1; //������Բ���ߵ�(x'1,y'1)=[u1]g+[u2]ha 
    g_xy1 = epoint_init();
    ecurve_mult(u1, g_g, g_xy1);
    epoint* g_xy2;
    g_xy2 = epoint_init();
    ecurve_mult(u2, g_q, g_xy2); //u2*ha   
    ecurve_add(g_xy1, g_xy2); //g_xy2=g_xy2+g_xy1
    big r = mirvar(0); //b7 ����r=x'1 mod n ����r=r'�Ƿ���� ����������֤ͨ��
    r = g_xy2->x;
    divide(r, g_n, g_n);
    if (!mr_compare(r, a.r))
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
    initecdsa(pm);
    finish = clock();
    duration = (double)(finish - start) / clocks_per_sec;
    printf("keygen: %f seconds\n", duration);
    start = clock();
    digital_sign a = signecdsa(pm, z);  //������ë��
    finish = clock();
    duration = (double)(finish - start) / clocks_per_sec;
    printf("sign: %f seconds\n", duration);
    printf("r:");
    cotnum(a.r, stdout);
    printf("s:");
    cotnum(a.s, stdout);
    start = clock();
    int r = vertifyecdsa(a, pm, z);
    finish = clock();
    duration = (double)(finish - start) / clocks_per_sec;
    printf("vertify: %f seconds\n", duration);
    if (1 == r)
    {
        printf("success\n");
    }
    else
    {
        printf("error\n");
    }
    //shatest();
    return 0;
}