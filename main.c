//#include <stdio.h>
//#include<time.h>
//#include<string.h>
//#include "miracl.h"
//#include"sm2.h"
//
//int main()
//{
//	unsigned char tx[5000] = "0"; //明文
//	unsigned char mtx[5000] = "0"; //解密
//	unsigned char etx[6000]; //密文
//    miracl* pm = mirsys(1000, 0);
//	clock_t start, finish;
//	double duration;
//
//	start = clock();
//	initSM2(pm);
//	finish = clock();
//	duration = (double)(finish - start) / CLOCKS_PER_SEC;
//	printf("KeyGen: %f seconds\n", duration);
//
//	FILE* fp; //存放明文
//	fopen_s(&fp, "3.txt", "r+");
//	fgets(tx, 255, fp); //明文存放到数组中 从fp指向的文件读取255个字符到plain中
//	fclose(fp);
//	printf("\n明文: %s\n\n", tx);
//	int klen = strlen(tx);
//
//	start = clock();
//	encrySM2(pm, tx, klen, etx);
//	finish = clock();
//	duration = (double)(finish - start) / CLOCKS_PER_SEC;
//	printf("Encrypt: %f seconds\n", duration);
//
//	start = clock();
//	decrySM2(pm, etx, klen, mtx);
//	finish = clock();
//	duration = (double)(finish - start) / CLOCKS_PER_SEC;
//	printf("Decrypt: %f seconds\n", duration);
//
//	system("pause");
//	return 0;
//}
//
//
//
//

#include<stdio.h>
#include<time.h>
#include<string.h>
#include "miracl.h"
#include"sm2.h"

int main()
{
	unsigned char ida[19] = "1307805140@qq.com";
	unsigned char idb[18] = "tuirng01cheng.kgf";
	unsigned char da[] = { 0x6F,0xCB,0xA2,0xEF,0x9A,0xE0,0xAB,0x90,0x2B,0xC3,0xBD,0xE3,0xFF,0x91,0x5D,0x44,0xBA,0x4C,0xC7,0x8F,0x88,0xE2,0xF8,0xE7,0xF8,0x99,0x6D,0x3B,0x8C,0xCE,0xED,0xEE };
	unsigned char xa[] = { 0x30,0x99,0x09,0x3B,0xF3,0xC1,0x37,0xD8,0xFC,0xBB,0xCD,0xF4,0xA2,0xAE,0x50,0xF3,0xB0,0xF2,0x16,0xC3,0x12,0x2D,0x79,0x42,0x5F,0xE0,0x3A,0x45,0xDB,0xFE,0x16,0x55 };
	unsigned char ya[] = { 0x3D,0xF7,0x9E,0x8D,0xAC,0x1C,0xF0,0xEC,0xBA,0xA2,0xF2,0xB4,0x9D,0x51,0xA4,0xB3,0x87,0xF2,0xEF,0xAF,0x48,0x23,0x39,0x08,0x6A,0x27,0xA8,0xE0,0x5B,0xAE,0xD9,0x8B };
	unsigned char db[] = { 0x5E,0x35,0xD7,0xD3,0xF3,0xC5,0x4D,0xBA,0xC7,0x2E,0x61,0x81,0x9E,0x73,0x0B,0x01,0x9A,0x84,0x20,0x8C,0xA3,0xA3,0x5E,0x4C,0x2E,0x35,0x3D,0xFC,0xCB,0x2A,0x3B,0x53 };
	unsigned char xb[] = { 0x24,0x54,0x93,0xD4,0x46,0xC3,0x8D,0x8C,0xC0,0xF1,0x18,0x37,0x46,0x90,0xE7,0xDF,0x63,0x3A,0x8A,0x4B,0xFB,0x33,0x29,0xB5,0xEC,0xE6,0x04,0xB2,0xB4,0xF3,0x7F,0x43 };
	unsigned char yb[] = { 0x53,0xC0,0x86,0x9F,0x4B,0x9E,0x17,0x77,0x3D,0xE6,0x8F,0xEC,0x45,0xE1,0x49,0x04,0xE0,0xDE,0xA4,0x5B,0xF6,0xCE,0xCF,0x99,0x18,0xC8,0x5E,0xA0,0x47,0xC6,0x0A,0x4C };

	unsigned char kabuf[32], sa[32];
	unsigned char kbbuf[32], sb[32], s1[32], s2[32];
	unsigned char kx2[32], ky2[32];
	int kx2len, ky2len;
	unsigned char kx1[256], ky1[256], ra[256], xv[32], yv[32];
	int kx1len, ky1len, ralen, xvlen, yvlen;


	sm2_keygen(xa, &kx1len, ya, &ky1len, da, &ralen);
	sm2_keygen(xb, &kx1len, yb, &ky1len, db, &ralen);
	
	clock_t start, finish;
	double duration;

	start = clock();
	sm2_keyagreement_a1_3(kx1, &kx1len, ky1, &ky1len, ra, &ralen);
	finish = clock();
	duration = (double)(finish - start) / CLOCKS_PER_SEC;
	printf("a1_3: %f seconds\n", duration);

	start = clock();
	sm2_keyagreement_b1_9(
		kx1, kx1len,
		ky1, ky1len,
		xa, 32,
		ya, 32,
		db, 32,
		xb, 32,
		yb, 32,
		ida, 18,
		idb, 17,
		16,
		kbbuf,
		kx2, &kx2len,
		ky2, &ky2len,
		xv, &xvlen,
		yv, &yvlen,
		sb
	);
	finish = clock();
	duration = (double)(finish - start) / CLOCKS_PER_SEC;
	printf("b1_9: %f seconds\n", duration);


	start = clock();
	sm2_keyagreement_a4_10(
		kx1, kx1len,
		ky1, ky1len,
		xa, 32,
		ya, 32,
		da, 32,
		xb, 32,
		yb, 32,
		ida, 18,
		idb, 17,
		kx2, kx2len,
		ky2, ky2len,
		ra, ralen,
		16,
		kabuf,
		s1,
		sa
	);
	finish = clock();
	duration = (double)(finish - start) / CLOCKS_PER_SEC;
	printf("a4_10: %f seconds\n", duration);


	start = clock();
	sm2_keyagreement_b10(
		xa, 32,
		ya, 32,
		xb, 32,
		yb, 32,
		kx1, 32,
		ky1, 32,
		kx2, 32,
		ky2, 32,
		xv, xvlen,
		yv, yvlen,
		ida, 18,
		idb, 17,
		s2
	);
	finish = clock();
	duration = (double)(finish - start) / CLOCKS_PER_SEC;
	printf("b10: %f seconds\n", duration);

	if (memcmp(s1, sb, 32) != 0)
	{
		printf("key_test error ! \n");
		return;
	}
	if (memcmp(kabuf, kbbuf, 16) != 0)
	{
		printf("key_test error ! \n");
		return;
	}

	if (memcmp(s2, sa, 32) != 0)
	{
		printf("key_test error ! \n");
		return;
	}

	printf("key_test OK ! \n");


}


