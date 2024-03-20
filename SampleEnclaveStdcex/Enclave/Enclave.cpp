/*
 * Copyright (C) 2011-2022 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <errno.h>
#include <mbusafecrt.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include "sgx_thread.h"

#include <ctype.h>
#include <sys/types.h>
//#include <arpa/inet.h>
//#include <winsock2.h>

//#include "se_memory.h"
//#include "se_trace.h"
//#include "util.h"
#include <sys/mman.h>

#define CHECK_ERR(err, msg) { \
    if (err != Z_OK) { \
        fprintf(stderr, "%s error: %d\n", msg, err); \
        return -1; \
    } \
}

#define TEST_PATH_MAX 1024
static const mode_t MODE = 0644;


void ecall_printf()
{
    printf("Printing by the printf() from the SDK.\n");
    return;
}

int ecall_memset_s()
{
    char str[15] = {0};
    if ( 0 != memset_s(str, sizeof(str), 'b', sizeof(str)-1)) return -1;
    printf("After setting buffer with memset_s(): %s.\n", str);
    return 0;
}

int ecall_fchmod()
{
    int fd;
    char oldname[TEST_PATH_MAX] = "/tmp/testfile.txt";

    const int flags = O_CREAT | O_TRUNC | O_WRONLY;
    if((fd = open(oldname, flags, MODE)) == -1)
        return -2;

    if (fchmod(fd, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH) != 0)
    {
    printf("fchmod fail, errno is %d\n", errno);
        printf("fchmod(): FAIL\n");
        return -3;
    }
    else
        printf("fchmod(): PASS\n");

    close(fd);
    return 0;
}

int ecall_time()
{
    time_t tloc;
    time(&tloc);
    if (-1 == tloc)
    {
        printf("can't get the time\n");
        return -1;
    }
    printf("time(): Since 1st January 1970 UTC, %d seconds or %d days passed\n",(int)tloc,(int)tloc/86400);
    return 0;
}

void ecall_socket_receiver()
{
    int sockfd = 0;
    char recv_buff[1024]={0};
    size_t buff_len = 1024;
    struct sockaddr_in serv_addr = {0};

    printf("CLIENT: create socket\n");
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n CLIENT: Could not create socket \n");
        abort();
    }
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    serv_addr.sin_port = htons(1492);

    printf("CLIENT: socket fd = %d\n", sockfd);
    printf("CLIENT: connecting...\n");
    int retries = 0;
    static const int max_retries = 4;

    while (connect(
               sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)
    {
        if (retries++ > max_retries)
        {
            printf("\n CLIENT: Connect Failed \n");
            close(sockfd);
            abort();
        }
        else
        {
            printf("CLIENT: Connect Failed. Retrying... \n");
        }
    }

    printf("CLIENT: reading...\n");

    size_t nread = 0;

    struct timeval tv;
    fd_set rfds;
    int nfds = 1;
    while(1) {
        int ready = -1, ready_for_recv = 0;
        ssize_t nbytes;

        nfds = sockfd+1;
        tv.tv_sec = 5;
        tv.tv_usec = 0;

        FD_ZERO(&rfds);
        FD_CLR(0,&rfds);
        FD_SET(sockfd, &rfds);

        ready = select(nfds, &rfds, NULL, NULL, &tv);

        if (ready == -1 && errno == EINTR)
            continue;

        if (ready == -1)
        {
            printf("CLIENT: ERROR select\n");
            close(sockfd);
            abort();
        }
        ready_for_recv = FD_ISSET(sockfd, &rfds);

        if (ready_for_recv) {
            nbytes = recv(sockfd, recv_buff + nread, buff_len - nread, 0);

            if (nbytes < 0)
            {
                printf("CLIENT: ERROR recv\n");
                break;
            }
            else if (nbytes == 0)
            {
                printf("CLIENT: finished reading of %ld bytes\n", nread);
                break;
            }
            else
            {
                printf("CLIENT: recv %ld bytes : %s", nbytes, recv_buff);
                nread += (size_t)nbytes;
            }
        }
    }

    /* Make sure shutdown call also works. */
    if (shutdown(sockfd, SHUT_RDWR) != 0) abort();

    printf("CLIENT: closing...\n");
    close(sockfd);
    return ;
}


void ecall_socket_sender()
{
    static const char TESTDATA[] = "This is TEST DATA\n";
    int listenfd = socket(AF_INET, SOCK_STREAM, 0);
    int connfd = 0;
    struct sockaddr_in serv_addr = {0};

    const int optVal = 1;
    const socklen_t optLen = sizeof(optVal);

    int rtn =
            setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (const void*)&optVal, optLen);
    if (rtn > 0)
    {
            printf("SERVER: setsockopt failed return = %d\n", rtn);
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    serv_addr.sin_port = htons(1492);

    bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));

    listen(listenfd, 10);

    while (1)
    {
        printf("SERVER: accepting...\n");
        connfd = accept(listenfd, (struct sockaddr*)NULL, NULL);

        printf("SERVER: accept fd = %d\n", connfd);
        if (connfd >= 0)
        {
            printf("SERVER: send %d bytes\ : %s", strlen(TESTDATA), TESTDATA);
            ssize_t n = send(connfd, TESTDATA, strlen(TESTDATA), 0);
            if ((size_t)n == strlen(TESTDATA))
            {
                printf("SERVER: send complete\n");
            }
            else
            {
                printf("SERVER: send failed\n");
            }
            close(connfd);
            break;
        }
    }

    printf("SERVER: closing\n");
    close(listenfd);

    return;
}
int test_mmap(void* address, size_t size)
{
    int mmap_flag = MAP_PRIVATE |  MAP_ANONYMOUS;
    if(address != NULL)
    mmap_flag |= MAP_FIXED;
    void* pRet = mmap(address, size, PROT_READ | PROT_WRITE, mmap_flag, -1, 0);
    if(MAP_FAILED == pRet)
        return 1;
    return 0;
}

int  ecall_mmap()
{
    int ret;
    ret = test_mmap(NULL,0x100);
    if (ret ==1)
    {
        printf("fail to mmap");
        return 1;
    }
    printf("mmap(): PASS\n");
    return 0;
}

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

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>
using namespace std;

#define MAX_PACKET      16777216 // bytes
#define SHA1_SIZE       20

void die ( const char * msg, ... )
{
        printf ( "*** error: " );
        va_list ap;
        va_start ( ap, msg );
        vprintf ( msg, ap );
        va_end ( ap );
        printf ( "\n" );
        exit ( 1 );
}

struct MysqlDriver_t
{
        int             m_iSock, m_iCols;
        BYTE    *m_pReadBuf, *m_pReadCur, *m_pReadMax, m_dWriteBuf[8192], *m_pWriteBuf;
        vector<string>  m_dFields, m_dRow;
        string                  m_sError;

        MysqlDriver_t ( int iSock )
        {
                m_iSock = iSock;
                m_pReadBuf = m_pReadCur = m_pReadMax = new BYTE [ MAX_PACKET ];
                m_pWriteBuf = m_dWriteBuf;
        }

        void ReadFrom ( int iLen, const char * sWhat )
        {
                if ( iLen>MAX_PACKET )
                        die ( "packet too big while reading %s\n", sWhat );
                m_pReadCur = m_pReadBuf;
                m_pReadMax = m_pReadBuf + iLen;
                if ( recv ( m_iSock, (char*)m_pReadBuf, iLen, 0 )!=iLen )
                        die ( "recv failed while reading %s: %s", sWhat, strerror(errno) ); // strerror fails on Windows, but who cares
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

        virtual                 ~MysqlDriver_t()        { delete [] m_pReadBuf; }
        DWORD                   GetDword()                      { int r = GetByte(); r += GetByte()<<8; r += GetByte()<<16; return r + ( GetByte()<<24 ); }
        bool                    GetReadError()          { return m_pReadCur > m_pReadMax; }
        char *                  GetCur()                        { return (char*)m_pReadCur; }
        int                             PeekByte()                      { return m_pReadCur < m_pReadMax ? *m_pReadCur : -1; }
        void                    SkipBytes ( int n )     { m_pReadCur += n; }

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
                if ( send ( m_iSock, (char*)m_dWriteBuf, iLen, 0 )!=iLen )
                        die ( "send failed: %s", strerror(errno) );
                m_pWriteBuf = m_dWriteBuf;
        }

        int ReadPacket()
        {
                ReadFrom ( 4, "packet header" );
                int iLen = GetDword() & 0xffffff; // byte len[3], byte packet_no
                ReadFrom ( iLen, "packet data" );
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

                        if ( i<20 )                     e += ((b&(c^d))^d) + 0x5A827999;
                        else if ( i<40 )        e += (b^c^d) + 0x6ED9EBA1;
                        else if ( i<60 )        e += (((b|c) & d) | (b & c)) + 0x8F1BBCDC;
                        else                            e += (b^c^d) + 0xCA62C1D6;

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

//int ecall_sqlclient(int argc, const char ** argv)
int ecall_sqlclient()
{
        const char *sHost = "127.0.0.1", *sUser = "root", *sPass = "password";
        int iPort = 3306;
	/*
        for ( int i=1; i+1<argc; i+=2 )
        {
                if ( !strcmp ( argv[i], "-h" ) )                sHost = argv[i+1];
                else if ( !strcmp ( argv[i], "-u" ) )   sUser = argv[i+1];
                else if ( !strcmp ( argv[i], "-p" ) )   sPass = argv[i+1];
                else if ( !strcmp ( argv[i], "-P" ) )   iPort = atoi(argv[i+1]);
                else die ( "unknown switch %s\nusage: nanomysql [-h host] [-P port] [-u user] [-p password]", argv[i] );
        }
	*/

        // resolve host, prepare socket
        //hostent * pHost = gethostbyname ( sHost );
        //if ( !pHost || pHost->h_addrtype!=AF_INET )
        //        die ( "no AF_INET address found for %s", sHost );

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
        MysqlDriver_t db ( iSock );
        db.ReadPacket();

        string sVer;
        BYTE dScramble[21], uLang;

        db.GetByte(); // proto_version
        do { sVer.push_back ( db.GetByte() ); } while ( sVer.end()[-1] ); // server_version
        db.GetDword(); // thread_id
        for ( int i=0; i<8; i++ )
                dScramble[i] = db.GetByte();
        db.SkipBytes(3); // byte filler1, word caps_lo
        uLang = db.GetByte();
        db.SkipBytes(15); // word status, word caps_hi, byte scramble_len, byte filler2[10]
        for ( int i=0; i<13; i++ )
                dScramble[i+8] = db.GetByte();

        if ( db.GetReadError() )
                die ( "failed to parse mysql handshacke packet" );

        // send auth packet
        db.SendDword ( (1<<24) + 34 + strlen(sUser) + ( strlen(sPass) ? 21 : 1 ) ); // byte len[3], byte packet_no
        db.SendDword ( 0x4003F7CFUL ); // all CLIENT_xxx flags but SSL, COMPRESS, SSL_VERIFY_SERVER_CERT, NO_SCHEMA
        db.SendDword ( MAX_PACKET-1 ); // max_packet_size, 16 MB
        db.SendByte ( uLang );
        for ( int i=0; i<23; i++ )
                db.SendByte ( 0 ); // filler
        db.SendBytes ( sUser, strlen(sUser)+1 ); // including trailing zero
        if ( !sPass || !*sPass )
        {
                db.SendByte ( 0 ); // 0 password length = no password
        } else
        {
                BYTE dStage1[SHA1_SIZE], dStage2[SHA1_SIZE], dRes[SHA1_SIZE];
                SHA1_t sha;
                sha.Init().Update ( (BYTE*)sPass, strlen(sPass) ).Final ( dStage1 );
                sha.Init().Update ( dStage1, SHA1_SIZE ).Final ( dStage2 );
                sha.Init().Update ( dScramble, 20 ).Update ( dStage2, SHA1_SIZE ).Final ( dRes );
                db.SendByte ( SHA1_SIZE );
                for ( int i=0; i<SHA1_SIZE; i++ )
                        db.SendByte ( dRes[i] ^ dStage1[i] );
        }
        db.SendByte ( 0 ); // just a trailing zero instead of a full DB name
        db.Flush();

        if ( db.ReadPacket()<0 )
                die ( "auth failed: %s", db.m_sError.c_str() );

        // action!
        printf ( "connected to mysql %s\n\n", sVer.c_str() );
	
	char q[4096];
        for ( ;; )
        {
                printf ( "nanomysql> " );
                fflush ( stdout );
                if ( !fgets ( q, sizeof(q), stdin ) || !strcmp ( q, "quit\n" ) || !strcmp ( q, "exit\n" ) )
                {
                        printf ( "bye\n\n" );
                        break;
                }
                if ( !db.Query(q) )
                {
                        printf ( "error: %s\n\n", db.m_sError.c_str() );
                        continue;
                }
                int n = 0;
                for ( size_t i=0; i<db.m_dFields.size(); i++ )
                        printf ( "%s%s", i ? ", " : "", db.m_dFields[i].c_str() );
                if ( db.m_dFields.size() )
                        printf ( "\n---\n" );
                while ( db.FetchRow() )
                {
                        for ( size_t i=0; i<db.m_dRow.size(); i++ )
                                printf ( "%s%s", i ? ", " : "", db.m_dRow[i].c_str() );
                        printf ( "\n" );
                        n++;
                }
                printf ( "---\nok, %d row(s)\n\n", n );
        }

}

