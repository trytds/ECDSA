//#include <stdio.h>
//#include<time.h>
//#include<string.h>
//#include "miracl.h"
//#include"sm2.h"
//
//int main()
//{
//	unsigned char tx[5000] = "0"; //����
//	unsigned char mtx[5000] = "0"; //����
//	unsigned char etx[6000]; //����
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
//	FILE* fp; //�������
//	fopen_s(&fp, "3.txt", "r+");
//	fgets(tx, 255, fp); //���Ĵ�ŵ������� ��fpָ����ļ���ȡ255���ַ���plain��
//	fclose(fp);
//	printf("\n����: %s\n\n", tx);
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

/*#include<stdio.h>
#include<time.h>
#include<string.h>
#include "miracl.h"
#include"sm2.h"

int main()
{
	miracl* pm = mirsys(1000, 0);
	initSM2(pm);
	return 0;
}*/