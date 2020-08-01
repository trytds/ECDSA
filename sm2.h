void initSM2(unsigned char* wx, int* wxlen, unsigned char* wy, int* wylen, unsigned char* privkey, int* privkeylen);
int genZSM3(unsigned char* userid, int userid_len, unsigned char* xa, int xa_len, unsigned char* ya, int ya_len, unsigned char* z);
int kdf(const char* cdata, int datalen, int keylen, char* retdata);
void a1_3SM2(unsigned char* kx1, int* kx1len,
	unsigned char* ky1, int* ky1len, unsigned char* ra, int* ralen);

int b1_9SM2(
	unsigned char* kx1, int kx1len,
	unsigned char* ky1, int ky1len,
	unsigned char* pax, int paxlen,
	unsigned char* pay, int paylen,
	unsigned char* private_b, int private_b_len,
	unsigned char* pbx, int pbxlen,
	unsigned char* pby, int pbylen,
	unsigned char* ida, int idalen,
	unsigned char* idb, int idblen,
	unsigned int  kblen,
	unsigned char* kbbuf,
	unsigned char* kx2, int* kx2len,
	unsigned char* ky2, int* ky2len,
	unsigned char* xv, int* xvlen,
	unsigned char* yv, int* yvlen,
	unsigned char* sb);

int a4_10SM2(unsigned char* kx1, int kx1len,
	unsigned char* ky1, int ky1len,
	unsigned char* pax, int paxlen,
	unsigned char* pay, int paylen,
	unsigned char* private_a, int private_a_len,
	unsigned char* pbx, int pbxlen,
	unsigned char* pby, int pbylen,
	unsigned char* ida, int idalen,
	unsigned char* idb, int idblen,
	unsigned char* kx2, int kx2len,
	unsigned char* ky2, int ky2len,
	unsigned char* ra, int ralen,
	unsigned int  kalen,
	unsigned char* kabuf,
	unsigned char* s1,
	unsigned char* sa);

void b10SM2(
	unsigned char* pax, int paxlen,
	unsigned char* pay, int paylen,
	unsigned char* pbx, int pbxlen,
	unsigned char* pby, int pbylen,
	unsigned char* kx1, int kx1len,
	unsigned char* ky1, int ky1len,
	unsigned char* kx2, int kx2len,
	unsigned char* ky2, int ky2len,
	unsigned char* xv, int xvlen,
	unsigned char* yv, int yvlen,
	unsigned char* ida, int idalen,
	unsigned char* idb, int idblen,
	unsigned char* s2);

