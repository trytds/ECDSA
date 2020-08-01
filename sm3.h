#define __SM3_HEADER__
#define  SM3_LBLOCK         16
#define  SM3_CBLOCK         64
#define  SM3_DIGEST_LENGTH  32
#define  SM3_LAST_BLOCK     56

/*
 SM3上下文
*/
typedef struct SM3state_st
{
	unsigned long h[8];
	unsigned long Nl, Nh;
	unsigned long data[SM3_LBLOCK];
	unsigned int  num;
}SM3_CTX;

void SM3_Init(SM3_CTX* ctx);
void SM3_Update(SM3_CTX* ctx, const void* data, unsigned int len);
void SM3_Final(unsigned char* md, SM3_CTX* ctx);
unsigned char* sm3(const unsigned char* d, unsigned int n, unsigned char* md);
/*
  d:  data
  n:  byte length
  md: 32 bytes digest
*/


#define nl2c(l,c)	(*((c)++) = (unsigned char)(((l) >> 24) & 0xff), \
					 *((c)++) = (unsigned char)(((l) >> 16) & 0xff), \
					 *((c)++) = (unsigned char)(((l) >> 8)  & 0xff), \
					 *((c)++) = (unsigned char)(((l)    )   & 0xff))

#define c_2_nl(c)	((*(c) << 24) | (*(c+1) << 16) | (*(c+2) << 8) | *(c+3))
#define ROTATE(X, C) (((X) << (C)) | ((X) >> (32 - (C)))) //向左循环移位

/*
   常量
*/
#define TH 0x79cc4519 //[0,15]
#define TL 0x7a879d8a //[16,63]

/*
  布尔函数
*/
#define FFH(X, Y, Z) ((X) ^ (Y) ^ (Z))
#define FFL(X, Y, Z) (((X) & (Y)) | ((X) & (Z)) | ((Y) & (Z)))
#define GGH(X, Y, Z) ((X) ^ (Y) ^ (Z))
#define GGL(X, Y, Z) (((X) & (Y)) | ((~X) & (Z)))

/*
   置换函数
*/
#define P0(X)  ((X) ^ (((X) << 9) | ((X) >> 23)) ^ (((X) << 17) | ((X) >> 15)))
#define P1(X)  ((X) ^ (((X) << 15) | ((X) >> 17)) ^ (((X) << 23) | ((X) >> 9)))

