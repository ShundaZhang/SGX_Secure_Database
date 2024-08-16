// nanomysql, a tiny MySQL client
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License. You should have
// received a copy of the GPL license along with this program; if you
// did not, you can find it at http://www.gnu.org/

#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
typedef unsigned char BYTE;
typedef unsigned int DWORD;
#define MAX_SIZE 4096

#include "tls_client_t.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>

#include <ctype.h>
#include <sgx_tseal.h>
#include <sgx_utils.h>
#include <sgx_tcrypto.h>
#include "sgx_tprotected_fs.h"

using namespace std;

#define MAX_PACKET	16777216 // bytes
#define SHA1_SIZE	20

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

void initialize_openssl() {
    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();
    ERR_load_crypto_strings();

}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        printf("Unable to create SSL context!\n");
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void load_certificate_from_memory(SSL_CTX* ctx, const char* ca_data) {
    BIO* bio = BIO_new_mem_buf((void*)ca_data, -1);
    X509* cert = PEM_read_bio_X509(bio, NULL, 0, NULL);
    if (!cert) {
        fprintf(stderr, "Error loading certificate from memory\n");
        BIO_free(bio);
        exit(EXIT_FAILURE);
    }
    BIO_free(bio);

    X509_STORE* store = SSL_CTX_get_cert_store(ctx);
    if (!X509_STORE_add_cert(store, cert)) {
        fprintf(stderr, "Error adding certificate to store\n");
        X509_free(cert);
        exit(EXIT_FAILURE);
    }
    X509_free(cert);
}

int readFileToStackArray(const char *filename, char arr[], int max_size) {
   FILE *file = fopen(filename, "r");
    if (!file) {
        printf("Error opening file: %s\n", filename);
        return -1; 
    }

    int bytesRead = fread(arr, sizeof(char), max_size - 1, file); 
    arr[bytesRead] = '\0'; 

    fclose(file);
    return bytesRead; 
}


void configure_context(SSL_CTX *ctx) {
	//1) No Verify
	// In a real application, you would set the verify paths and mode here
	//SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

	//2) Verify PEER 3306 normal mysql
	//SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

	//Read file from ca.pem, untrusted only
	//if (!SSL_CTX_load_verify_locations(ctx, "/tmp/ca.pem", NULL)) {
	//	printf("SSL CTX Load Error!\n");
	//	exit(EXIT_FAILURE);
	//}

	//const char ca[] = "-----BEGIN CERTIFICATE-----\nMIIDBjCCAe6gAwIBAgIBATANBgkqhkiG9w0BAQsFADA8MTowOAYDVQQDDDFNeVNRTF9TZXJ2ZXJfOC4wLjM2X0F1dG9fR2VuZXJhdGVkX0NBX0NlcnRpZmljYXRlMB4XDTI0MDMxOTA1MTQ1NFoXDTM0MDMxNzA1MTQ1NFowPDE6MDgGA1UEAwwxTXlTUUxfU2VydmVyXzguMC4zNl9BdXRvX0dlbmVyYXRlZF9DQV9DZXJ0aWZpY2F0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJXR2Me3HfswVEqlc24AJkhcEOey1Hu4JIsf065Gwe+7qzbttdnSdhmDHnI92fqaapW/uUxJqp8x9/xjZHUlYG4MZyV++L4ZmROlGFL1p1zjGtJFFci2J4nw/04qH+8RXSGeCGDW+7YpgEwGn0yPAfRRXP0QOknfjD3Ak9ZFhNjgySJN/hj5/wn7mPcBcfNio35erKkMpcXjtRbzwYNGT+r+xMbxXCDvcVtysRB7ttP3b8N2Gjs7CeEqQCRxF/PuwunAj+aGTgzdEqSZgROdVbp8xtZfULHCQI1JsKqYzzkMKU0rkWjMF7Sg2lTsGwhX1QnysP8pJQ1X9P/cX8U9K6MCAwEAAaMTMBEwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEARznQ44XeJJjlqQRcR/WzBICxHNozDfSOZ3sNQOPw6diX6N4BAcfaCeWCKki2YiEBOWFQ+T4Tac/DWUHC2pVr4GwQzqQPg9dtHvqk5LXv0PFwN/uWRmlv8ThNJ/VcScJOZR6wEO2LfBJezpfppNc+x6RjBZR70cXr8mt820MLrLE3OVDOSgCUYXAH6PAXqo1W2/UJtQl6yhgUxcmDH+N2gWNaXWL8IHRvHfrIKo+QWjrkmzMzYTwNoc1UI0R7XwMNb4GR8d7OSThrf6XA/9J3jP8AcoOHKH7yUghR/zZM+anoaJMvqSr9F0NfZKWs0qSQ+Wx0E9710mWUBDvhLQbppQ==\n-----END CERTIFICATE-----\n";
        //load_certificate_from_memory(ctx, ca);

	//3) ca + cert + pri-key for edb
	char ca[MAX_SIZE] = {0};
	const char *fca_name = "edb.pem";
	int bytesRead = -1;

	bytesRead = readFileToStackArray(fca_name, ca, MAX_SIZE);
	if (bytesRead == -1) {
		printf("Failed to CA file.\n");
		exit(EXIT_FAILURE);
	}

	load_certificate_from_memory(ctx, ca);

	char cert[MAX_SIZE] = {0};
	char pkey[MAX_SIZE] = {0};
	const char *fcert_name = "cert.pem";
	const char *fpkey_name = "key.pem";
	
	bytesRead = readFileToStackArray(fcert_name, cert, MAX_SIZE);
	if (bytesRead == -1) {
		printf("Failed to Cert file.\n");
		exit(EXIT_FAILURE);
	}

	bytesRead = readFileToStackArray(fpkey_name, pkey, MAX_SIZE);
	if (bytesRead == -1) {
		printf("Failed to Private Key file.\n");
		exit(EXIT_FAILURE);
	}

	BIO *cert_bio = BIO_new_mem_buf((void*)cert, -1); // -1 for null-terminated string
	X509 *cert_x509 = PEM_read_bio_X509(cert_bio, NULL, 0, NULL);
	if (!cert_x509) {
		printf("Cert handling fail!\n");
		exit(EXIT_FAILURE);
	}
	BIO_free(cert_bio);

	BIO *pkey_bio = BIO_new_mem_buf((void*)pkey, -1); // -1 for null-terminated string
	EVP_PKEY *private_key = PEM_read_bio_PrivateKey(pkey_bio, NULL, 0, NULL);
	if (!private_key) {
		// Handle error
		printf("Private Key handling fail!\n");
		exit(EXIT_FAILURE);
	}
	BIO_free(pkey_bio);


	if (SSL_CTX_use_certificate(ctx, cert_x509) <= 0) {
		// Handle error
		printf("CTX Cert handling fail!\n");
		exit(EXIT_FAILURE);
	}

	if (SSL_CTX_use_PrivateKey(ctx, private_key) <= 0) {
		// Handle error
		printf("CTX Private Key handling fail!\n");
		exit(EXIT_FAILURE);
	}

	// Verify the private key matches the certificate
	if (!SSL_CTX_check_private_key(ctx)) {
		// Handle error
		printf("Cert/Key matching fail!\n");
		exit(EXIT_FAILURE);
	}

	// Free the X509 and EVP_PKEY objects when done
	X509_free(cert_x509);
	EVP_PKEY_free(private_key);

}



void die ( const char * msg, ... )
{
	printf ( "*** error: " );
	va_list ap;
	va_start ( ap, msg );
	vprintf ( msg, ap );
	va_end ( ap );
	printf ( "\n\n" );
	exit ( 1 );
}

struct MysqlDriver_t
{
	int	m_iSock, m_iCols;
	BYTE	*m_pReadBuf, *m_pReadCur, *m_pReadMax, m_dWriteBuf[8192], *m_pWriteBuf;
	vector<string>	m_dFields, m_dRow;
	string	m_sError;
	SSL	*m_ssl;
	SSL_CTX *m_ctx;

	//MysqlDriver_t ( int iSock )
	MysqlDriver_t ()
	{ 
		m_iSock = 0;
		m_pReadBuf = m_pReadCur = m_pReadMax = new BYTE [ MAX_PACKET ];
		m_pWriteBuf = m_dWriteBuf;
		m_ssl = NULL;
		m_ctx = NULL;
	}

	MysqlDriver_t ( int iSock )
	{ 
		m_iSock = iSock;
		m_pReadBuf = m_pReadCur = m_pReadMax = new BYTE [ MAX_PACKET ];
		m_pWriteBuf = m_dWriteBuf;
		m_ssl = NULL;
		m_ctx = NULL;
	}

	void set_sock( int iSock )
	{ 
		m_iSock = iSock;
	}

	void set_ssl ( SSL *ssl, SSL_CTX *ctx )
	{
		m_ssl = ssl;
		m_ctx = ctx;
	}

	void debug_print(unsigned char *buf, int len )
	{
		for ( int i = 0; i < len; i++ )
		{
			printf("%02x", buf[i]);
		}
		printf("\n");
	}

	void ReadFrom ( int iLen, const char * sWhat )
	{
		if ( iLen>MAX_PACKET )
			die ( "packet too big while reading %s\n", sWhat );
		m_pReadCur = m_pReadBuf;
		m_pReadMax = m_pReadBuf + iLen;
		
		if (m_ssl )
		{
			if ( SSL_read ( m_ssl, (char*)m_pReadBuf, iLen )!=iLen )
				die ( "SSL Read failed while reading %s: %s", sWhat, strerror(errno) ); // strerror fails on Windows, but who cares
		}
		else
		{
			if ( recv ( m_iSock, (char*)m_pReadBuf, iLen, 0 )!=iLen )
				die ( "recv failed while reading %s: %s", sWhat, strerror(errno) ); // strerror fails on Windows, but who cares
		}
	}


	BYTE GetByte ()
	{
		if ( m_pReadCur++ < m_pReadMax )
			return m_pReadCur[-1];
		return 0;
	}

	int GetMysqlInt ()
	{
		int v = GetByte(); // 0 on error
		switch ( v )
		{
			case 251: return 0; // NULL column
			case 252: v = GetByte(); v += GetByte()<<8; return v; // 2-byte length
			case 253: v = GetByte(); v += GetByte()<<8; v += GetByte()<<16; return v; // 3-byte length
			case 254: die ( "16M+ packets not supported" ); // 8-byte length
		}
		return v;
	}

	void GetMysqlString ( string & s )
	{
		s = "";
		int iLen = GetMysqlInt();
		if ( iLen && m_pReadCur+iLen <= m_pReadMax )
			s.append ( (char*)m_pReadCur, iLen );
		m_pReadCur += iLen;
	}

	virtual			~MysqlDriver_t()	{ delete [] m_pReadBuf; }
	DWORD			GetDword()			{ int r = GetByte(); r += GetByte()<<8; r += GetByte()<<16; return r + ( GetByte()<<24 ); }
	bool			GetReadError()		{ return m_pReadCur > m_pReadMax; }
	char *			GetCur() 			{ return (char*)m_pReadCur; }
	int				PeekByte()			{ return m_pReadCur < m_pReadMax ? *m_pReadCur : -1; }
	void			SkipBytes ( int n )	{ m_pReadCur += n; }

	void SendEnsure ( int iBytes )
	{
		if ( m_pWriteBuf+iBytes > m_dWriteBuf+sizeof(m_dWriteBuf) )
			die ( "net write buffer overflow" );
	}

	void SendByte ( BYTE uValue )
	{
		SendEnsure(1);
		*m_pWriteBuf++ = uValue;
	}

	void SendDword ( DWORD v )
	{
		SendEnsure(4);
		for ( int i=0; i<4; i++, v>>=8 )
			*m_pWriteBuf++ = BYTE(v);
	}

	void SendBytes ( const void * pBuf, int iLen )
	{
		SendEnsure(iLen);
		memcpy ( m_pWriteBuf, pBuf, iLen );
		m_pWriteBuf += iLen;
	}

	void Flush()
	{
		int iLen = m_pWriteBuf - m_dWriteBuf;
		if(m_ssl)
		{
			if ( SSL_write ( m_ssl, (char*)m_dWriteBuf, iLen )!=iLen )
				die ( "SSL Write failed: %s", strerror(errno) );
		}
		else
		{
			if ( send ( m_iSock, (char*)m_dWriteBuf, iLen, 0 )!=iLen )
				die ( "send failed: %s", strerror(errno) );
		}
		m_pWriteBuf = m_dWriteBuf;
	}

	int ReadPacket()
	{
		ReadFrom ( 4, "packet header" );
		int iLen = GetDword() & 0xffffff; // byte len[3], byte packet_no
		//printf("len = %d\n", iLen);
		ReadFrom ( iLen, "packet data" );
		//debug_print((unsigned char*)m_pReadCur, iLen);
		if ( PeekByte()==255 )
		{
			m_sError = "mysql error: ";
			m_sError.append ( GetCur()+9, iLen-9 ); // 9 bytes == byte type, word errcode, byte marker, byte sqlstate[5]
			return -1;
		}
		return PeekByte();
	}

	bool Query ( const char * q )
	{
		int iLen = strlen(q); // send that query
		SendDword ( (0<<24) + iLen + 1 ); // 0 is packet id
		SendByte ( 3 ); // COM_QUERY
		SendBytes ( q, iLen );
		Flush();

		m_dFields.resize ( 0 );
		if ( ( m_iCols = ReadPacket() )<0 ) // fetch response packet
			return false;

		m_dFields.resize ( m_iCols );
		if ( m_iCols==0 ) // 0 means OK but no further packets
			return true;
		for ( int i=0; i<m_iCols; i++ ) // read and parse field packets
		{
			if ( ReadPacket()<0 )
				return false;
			for ( int j=0; j<4; j++ )
				SkipBytes ( GetMysqlInt() ); // skip 4 strings (catalog, db, table, orgtable)
			GetMysqlString ( m_dFields[i] ); // field_name
			SkipBytes ( GetMysqlInt()+14 ); // string orig_name, byte filler, word charset, dword len, byte type, word flags, byte decimals, word filler2
		}
		if ( ReadPacket()!=254 ) // eof packet expected after fields
			die ( "unexpected packet type %d after fields packets", PeekByte() );
		return true;
	}

	bool FetchRow()
	{
		if ( m_iCols<=0 )
			return false;
		int i = ReadPacket();
		if ( i<0 || i==254 ) // mysql error or eof
			return false;
		m_dRow.resize ( m_iCols );
		for ( int i=0; i<m_iCols; i++ )
			GetMysqlString ( m_dRow[i] );
		return true;
	}
};

struct SHA1_t
{
	DWORD state[5], count[2];
	BYTE buffer[64];

	void Transform ( const BYTE buf[64] )
	{
		DWORD a = state[0], b = state[1], c = state[2], d = state[3], e = state[4], block[16];
		memset ( block, 0, sizeof(block) ); // initial conversion to big-endian units
		for ( int i=0; i<64; i++ )
			block[i>>2] += buf[i] << ((3-(i & 3))*8);
		for ( int i=0; i<80; i++ ) // do hashing rounds
		{
			#define _LROT(value,bits) ( ( (value) << (bits) ) | ( (value) >> ( 32-(bits) ) ) )
			if ( i>=16 )
				block[i&15] = _LROT ( block[(i+13)&15] ^ block[(i+8)&15] ^ block[(i+2)&15] ^ block[i&15], 1 );

			if ( i<20 )			e += ((b&(c^d))^d) + 0x5A827999;
			else if ( i<40 )	e += (b^c^d) + 0x6ED9EBA1;
			else if ( i<60 )	e += (((b|c) & d) | (b & c)) + 0x8F1BBCDC;
			else				e += (b^c^d) + 0xCA62C1D6;

			e += block[i&15] + _LROT ( a, 5 );
			DWORD t = e; e = d; d = c; c = _LROT ( b, 30 ); b = a; a = t;
		}
		state[0] += a; // save state
		state[1] += b;
		state[2] += c;
		state[3] += d;
		state[4] += e;
	}

	SHA1_t & Init()
	{
		const DWORD dInit[5] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };
		memcpy ( state, dInit, sizeof(state) );
		count[0] = count[1] = 0;
		return *this;
	}

	SHA1_t & Update ( const BYTE * data, int len )
	{
		int i, j = ( count[0]>>3 ) & 63;
		count[0] += ( len<<3 );
		if ( count[0] < (DWORD)( len<<3 ) )
			count[1]++;
		count[1] += (len >> 29);
		if ( ( j+len )>63 )
		{
			i = 64-j;
			memcpy ( &buffer[j], data, i );
			Transform ( buffer );
			for ( ; i+63<len; i+=64 )
				Transform ( data+i );
			j = 0;
		} else
			i = 0;
		memcpy ( &buffer[j], &data[i], len-i );
		return *this;
	}

	void Final ( BYTE digest[SHA1_SIZE] )
	{
		BYTE finalcount[8];
		for ( int i=0; i<8; i++ )
			finalcount[i] = (BYTE)( ( count[ ( i>=4 ) ? 0 : 1 ] >> ( (3-(i & 3))*8 ) ) & 255 ); // endian independent
		Update ( (BYTE*)"\200", 1 ); // add padding
		while ( ( count[0] & 504 )!=448 )
			Update ( (BYTE*)"\0", 1 );
		Update ( finalcount, 8 ); // should cause a SHA1_Transform()
		for ( int i=0; i<SHA1_SIZE; i++ )
			digest[i] = (BYTE)((state[i>>2] >> ((3-(i & 3)) * 8) ) & 255);
	}
};

unsigned long inet_addr2(const char *str)
{
    unsigned long lHost = 0;
    char *pLong = (char *)&lHost;
    char *p = (char *)str;
    while (p)
    {
        *pLong++ = atoi(p);
        p = strchr(p, '.');
        if (p)
            ++p;
    }
    return lHost;
}


int init_db_connect(const char* server_name, const char* server_port, void **xdb)
{
	SSL_CTX *ctx;
	SSL *ssl;

	initialize_openssl();
	ctx = create_context();
	configure_context(ctx);

	const char *sHost = server_name, *sUser = "root", *sPass = "password";
	int iPort = atoi(server_port);

	sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_port = htons ( iPort );
	//memcpy ( &sin.sin_addr, *(in_addr **)pHost->h_addr_list, sizeof(in_addr) );
        sin.sin_addr.s_addr = inet_addr2(sHost);
        memset(&(sin.sin_zero), sizeof(sin.sin_zero), 0);

	int iSock = socket ( AF_INET, SOCK_STREAM, 0 );
	if ( iSock<0 || connect ( iSock, (sockaddr*)&sin, sizeof(sin) )<0 )
		die ( "connection failed: %s", strerror(errno) );

	// get and parse handshake packet
	//MysqlDriver_t db ( iSock );
	MysqlDriver_t *pdb = NULL;
	pdb = new MysqlDriver_t();
	*xdb = (void *)pdb;
	pdb->set_sock(iSock);
	pdb->ReadPacket();

	string sVer;
	BYTE dScramble[21], uLang;

	pdb->GetByte(); // proto_version
	do { sVer.push_back ( pdb->GetByte() ); } while ( sVer.end()[-1] ); // server_version
	pdb->GetDword(); // thread_id
	for ( int i=0; i<8; i++ )
		dScramble[i] = pdb->GetByte();
	pdb->SkipBytes(3); // byte filler1, word caps_lo
	uLang = pdb->GetByte();
	pdb->SkipBytes(15); // word status, word caps_hi, byte scramble_len, byte filler2[10]
	for ( int i=0; i<13; i++ )
		dScramble[i+8] = pdb->GetByte();

	if ( pdb->GetReadError() )
		die ( "failed to parse mysql handshacke packet" );

	//Send TLS request
	pdb->SendDword ( (1<<24) + 4+4+1+23 );
	pdb->SendDword ( 0x4003ffcfUL ); // +SSL, SSL_VERIFY_SERVER_CERT
	//pdb->SendDword ( 0x19ffae85 ); // +SSL
	pdb->SendDword ( MAX_PACKET-1 ); // max_packet_size, 16 MB
	pdb->SendByte ( uLang );
	for ( int i=0; i<23; i++ )
		pdb->SendByte ( 0 ); // filler
	pdb->Flush();

	//The usual SSL exchange leading to establishing SSL connection
	//Standard TLS handshake
	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, iSock); // iSock is your socket file descriptor
	
	if (SSL_connect(ssl) != 1) {
		printf("SSL connections failed!\n");
		exit(EXIT_FAILURE);
	}

	if (SSL_get_verify_result(ssl) != X509_V_OK) {
		// Handle error: Verification failed
		printf("SSL CA Verification failed!\n");
		exit(EXIT_FAILURE);
	}

	pdb->set_ssl(ssl, ctx);

	// send auth packet
	//pdb->SendDword ( (1<<24) + 34 + strlen(sUser) + ( strlen(sPass) ? 21 : 1 ) ); // byte len[3], byte packet_no
	pdb->SendDword ( (1<<25) + 34 + strlen(sUser) + ( strlen(sPass) ? 21 : 1 ) ); // byte len[3], byte packet_no
	//pdb->SendDword ( 0x4003F7CFUL ); // all CLIENT_xxx flags but SSL, COMPRESS, SSL_VERIFY_SERVER_CERT, NO_SCHEMA
	pdb->SendDword ( 0x4003ffcfUL ); // +SSL, SSL_VERIFY_SERVER_CERT
	//pdb->SendDword ( 2048+512 ); // +SSL, SSL_VERIFY_SERVER_CERT

	//pdb->SendDword( (1<<24)+4+4+1+23+strlen(sUser)+1+1+20 );
	//pdb->SendDword( 0x7fae85 );
	//pdb->SendDword( 0x7fa685 );

	pdb->SendDword ( MAX_PACKET-1 ); // max_packet_size, 16 MB
	pdb->SendByte ( uLang );
	for ( int i=0; i<23; i++ )
		pdb->SendByte ( 0 ); // filler
	pdb->SendBytes ( sUser, strlen(sUser)+1 ); // including trailing zero
	if ( !sPass || !*sPass )
	{
		pdb->SendByte ( 0 ); // 0 password length = no password
	} else
	{
		BYTE dStage1[SHA1_SIZE], dStage2[SHA1_SIZE], dRes[SHA1_SIZE];
		SHA1_t sha;
		sha.Init().Update ( (BYTE*)sPass, strlen(sPass) ).Final ( dStage1 );
		sha.Init().Update ( dStage1, SHA1_SIZE ).Final ( dStage2 );
		sha.Init().Update ( dScramble, 20 ).Update ( dStage2, SHA1_SIZE ).Final ( dRes );
		pdb->SendByte ( SHA1_SIZE );
		for ( int i=0; i<SHA1_SIZE; i++ )
			pdb->SendByte ( dRes[i] ^ dStage1[i] );
	}
	
	pdb->SendByte ( 0 ); // just a trailing zero instead of a full DB name
	pdb->Flush();
	
	if ( pdb->ReadPacket()<0 )
		die ( "auth failed: %s", pdb->m_sError.c_str() );
	
	printf ( "connected to mysql %s\n\n", sVer.c_str() );
	
	return 0;
}

int close_db_connect(void *xdb)
{

	MysqlDriver_t *pdb = (MysqlDriver_t *)xdb;
	SSL_free(pdb->m_ssl);
	close(pdb->m_iSock);
	SSL_CTX_free(pdb->m_ctx);
	
	delete pdb;

	return 0;
}

char *memfgets(char *buffer, int size, const char *memory, int *offset) {
    if (buffer == NULL || memory == NULL || offset == NULL) {
        return NULL;
    }

    int i = 0;
    while (i < size - 1 && memory[*offset] != '\0' && memory[*offset] != '\n') {
        buffer[i++] = memory[*offset];
        (*offset)++;
    }

    if (memory[*offset] == '\n') {
        buffer[i++] = memory[*offset];
        (*offset)++;
    }

    buffer[i] = '\0';

    if (i == 0) {
        return NULL;
    }

    return buffer;
}

int exec_db_sql(char* input, char* output, void *xdb)
{
	MysqlDriver_t *pdb = (MysqlDriver_t *)xdb;
	
	// action!
	char q[4096];
	int n1 = 0;
	int offset_out = 0;
	int n2 = 0;

	/*
	FILE *input = fopen(input_file, "r");
	if (!input) {
		fprintf(stderr, "Error: Failed to open input file %s.\n", input_file);
		return 1;
	}

	FILE *output = fopen(output_file, "w");
	if (!output) {
		fprintf(stderr, "Error: Failed to open output file %s.\n", output_file);
		return 1;
	}
	*/
	
	for ( ;; )
	{
		//printf ( "nanomysql> " );
		//fflush ( stdout );
		//if ( !fgets ( q, sizeof(q), input ) || !strcmp ( q, "quit\n" ) || !strcmp ( q, "exit\n" ) )
		if ( memfgets(q, sizeof(q), input, &n1) == NULL || !strcmp ( q, "quit\n" ) || !strcmp ( q, "exit\n" ) )
		{
			n2 = sprintf ( output+offset_out, "bye\n\n" );
			offset_out += n2;
			break;
		}
		if ( !pdb->Query(q) )
		{
			n2 = sprintf ( output+offset_out, "error: %s\n\n", pdb->m_sError.c_str() );
			offset_out += n2;
			continue;
		}
		int n = 0;
		for ( size_t i=0; i<pdb->m_dFields.size(); i++ )
		{
			n2 = sprintf ( output+offset_out, "%s%s", i ? ", " : "", pdb->m_dFields[i].c_str() );
			offset_out += n2;
		}
		if ( pdb->m_dFields.size() )
		{
			n2 = sprintf ( output+offset_out, "\n\n---\n\n" );
			offset_out += n2;
		}
		while ( pdb->FetchRow() )
		{
			for ( size_t i=0; i<pdb->m_dRow.size(); i++ )
			{
				n2 = sprintf ( output+offset_out, "%s%s", i ? ", " : "", pdb->m_dRow[i].c_str() );
				offset_out += n2;
			}
			n2 = sprintf ( output+offset_out, "\n\n" );
			offset_out += n2;
			n++;
		}
		n2 = sprintf ( output+offset_out, "---\n\nok, %d row(s)\n\n", n );
		offset_out += n2;
	}

	return 0;

}

//Secure file storage

SGX_FILE* ecall_file_open(const char* filename, const char* mode)
{
        return sgx_fopen_auto_key(filename, mode);
}

uint64_t ecall_file_get_file_size(SGX_FILE * fp)
{
        uint64_t file_size = 0;
        sgx_fseek(fp, 0, SEEK_END);
        file_size = sgx_ftell(fp);
        sgx_fseek(fp, 0, SEEK_SET);
        return file_size;
}

size_t ecall_file_write(SGX_FILE* fp, const char* writeData, uint64_t size)
{
        size_t sizeofRead = sgx_fwrite(writeData, sizeof(char), size, fp);
        return sizeofRead;
}

size_t ecall_file_read(SGX_FILE* fp, char* readData, uint64_t size)
{
	size_t sizeofRead = sgx_fread(readData, sizeof(char), size, fp);
	return sizeofRead;

}

int32_t ecall_file_close(SGX_FILE* fp)
{
        return sgx_fclose(fp);
}

