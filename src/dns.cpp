/*****************************************************************************
*  Copyright 2005 Alt-N Technologies, Ltd. 
*
*  Licensed under the Apache License, Version 2.0 (the "License"); 
*  you may not use this file except in compliance with the License. 
*  You may obtain a copy of the License at 
*
*      http://www.apache.org/licenses/LICENSE-2.0 
*
*  Unless required by applicable law or agreed to in writing, software 
*  distributed under the License is distributed on an "AS IS" BASIS, 
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
*  See the License for the specific language governing permissions and 
*  limitations under the License.
*****************************************************************************/

#ifdef WIN32
#include <windows.h>
#include "windns.h"
#else
#include <sys/types.h>
#include <ctype.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#endif

#include <stdio.h>
#include <string.h>

#include "dkim.h"
#include "dns.h"

#ifdef WIN32
#include "dnsresolv.h"
#endif



bool IsPolicyRecord( char* szTxt )
{
	// TODO: Replace with TXT record verification when available
	return ( szTxt[0] != '\0' );
}


bool IsKeyRecord( char* szTxt )
{
	// TODO: Replace with TXT record verification when available	
	return (szTxt[0] != '\0');
}

#ifdef WIN32


#ifndef DNS_ERROR_RCODE_SERVER_FAILURE
#define DNS_ERROR_RCODE_SERVER_FAILURE   9002L
#endif

typedef DNS_STATUS (WINAPI *DNSQUERYFUNC)( LPCSTR lpstrName, WORD wType, DWORD fOptions,
										     PIP4_ARRAY aipServers, PDNS_RECORD *ppQueryResultsSet,
                                             PVOID *pReserved );

typedef void (WINAPI *DNSRECORDLISTFREE)(PDNS_RECORD, DNS_FREE_TYPE);



static HMODULE s_hDNSAPI = NULL;			// handle to dnsapi.dll 
static bool    s_bDNSAPIAvailable = true;	// set to false if DLL can't be loaded
static DNSQUERYFUNC s_DnsQuery = NULL;		// DnsQuery function address
static DNSRECORDLISTFREE s_DnsRecordListFree = NULL;

////////////////////////////////////////////////////////////////////////////////
// 
// CheckForDNSAPI - Attempt to load dnsapi.dll once
//
////////////////////////////////////////////////////////////////////////////////
bool CheckForDNSAPI(void)
{
	if( s_bDNSAPIAvailable )
	{
		if( s_hDNSAPI == NULL )
		{
			s_hDNSAPI = LoadLibrary( "dnsapi.dll" );

			if( s_hDNSAPI == NULL )
			{
				s_bDNSAPIAvailable = false;
			}
			else
			{
				s_DnsQuery = (DNSQUERYFUNC)GetProcAddress( s_hDNSAPI, "DnsQuery_A" );
				s_DnsRecordListFree = (DNSRECORDLISTFREE)GetProcAddress( s_hDNSAPI, "DnsRecordListFree" );

				if( s_DnsQuery == NULL || s_DnsRecordListFree == NULL )
				{
					FreeLibrary( s_hDNSAPI );
					s_hDNSAPI = NULL;
					s_bDNSAPIAvailable = false;
				}
			}
		}
	}

	return s_bDNSAPIAvailable;
}



////////////////////////////////////////////////////////////////////////////////
// 
// _DNSGetPolicy2k - for Win2k+
//
////////////////////////////////////////////////////////////////////////////////
int _DNSGetPolicy2k( const char* szSubDomain, char* Buffer, int nBufLen )
{
	int nRet = DNSRESP_PERM_FAIL;
	DNS_STATUS res;
	PDNS_RECORD answer, prr;
	bool bFoundPolicy = false;

	// TODO: Query for a DKSP RR first

	res = s_DnsQuery( szSubDomain, DNS_TYPE_TEXT, DNS_QUERY_TREAT_AS_FQDN, NULL, 
		              &answer, NULL );

	if (res) 
	{
		if( res == DNS_ERROR_RCODE_SERVER_FAILURE)
			return DNSRESP_TEMP_FAIL;
		else
			return DNSRESP_PERM_FAIL;
	}

	prr = answer;

	while( prr )
	{
		if( prr->wType == DNS_TYPE_TEXT )
		{
			for( unsigned int i = 0; i < prr->Data.Txt.dwStringCount; i++ )
			{
				if( IsPolicyRecord( prr->Data.Txt.pStringArray[i] ) )
				{
					if( bFoundPolicy )
					{
						// Error! multiple policy records returned
						nRet = DNSRESP_PERM_FAIL;
					}
					else
					{
						strncpy( Buffer, prr->Data.Txt.pStringArray[i], nBufLen );
						Buffer[nBufLen-1] = '\0';
						bFoundPolicy = true;
						nRet = DNSRESP_SUCCESS;
					}

				}
			}
		}

		prr = prr->pNext;
	}

	s_DnsRecordListFree( answer, DnsFreeRecordList );

	return nRet;
}

////////////////////////////////////////////////////////////////////////////////
// 
// _DNSGetKey2k - for win2k+
//
////////////////////////////////////////////////////////////////////////////////
int _DNSGetKey2k( const char*szSubDomain, char* Buffer, int nBufLen )
{
	int nRet = DNSRESP_PERM_FAIL;
	DNS_STATUS res;
	PDNS_RECORD answer, prr;
	bool bFoundKey = false;

	// TODO: Query for a DKK RR first


	res = s_DnsQuery( szSubDomain, DNS_TYPE_TEXT, DNS_QUERY_TREAT_AS_FQDN, NULL, 
		              &answer, NULL );

	if (res) 
	{
		if( res == DNS_ERROR_RCODE_SERVER_FAILURE)
			return DNSRESP_TEMP_FAIL;
		else
			return DNSRESP_PERM_FAIL;
	}

	prr = answer;

	while( prr )
	{
		if( prr->wType == DNS_TYPE_TEXT && prr->Data.Txt.dwStringCount > 0 )
		{
			if( IsKeyRecord( prr->Data.Txt.pStringArray[0] ) )
			{
				if( bFoundKey )
				{
					// Error! multiple key records returned
					nRet = DNSRESP_PERM_FAIL;
				}
				else
				{
					char* BufPtr = Buffer;
					int BufLeft = nBufLen-1;	// -1 to save room for null terminator
					bool Truncated = false;

					for( unsigned int i = 0; i < prr->Data.Txt.dwStringCount && !Truncated; i++ )
					{
						int Len = strlen( prr->Data.Txt.pStringArray[i] );
						if( Len > BufLeft )
						{
							Len = BufLeft;
							Truncated = true;
						}

						memcpy( BufPtr, prr->Data.Txt.pStringArray[i], Len );
						BufPtr += Len;
						BufLeft -= Len;
					}
					*BufPtr = '\0';
					bFoundKey = true;

					// TODO: use a different return code if the result was truncated?
					nRet = DNSRESP_SUCCESS;	
				}
			}
		}

		prr = prr->pNext;
	}

	s_DnsRecordListFree( answer, DnsFreeRecordList );

	return nRet;
}

#define PACKETSZ	1024
#define C_IN		1
#define T_TXT		16
#define HFIXEDSZ	12	/* #/bytes of fixed data in header */
#define MAXDNAME	1025	/* maximum domain name */
#define QFIXEDSZ	4
#define RRFIXEDSZ	10	/* #/bytes of fixed data in r record */
#define NS_CMPRSFLGS	0xc0	/* Flag bits indicating name compression. */
#define NS_MAXCDNAME	255	/* maximum compressed domain name */
#define MAXCDNAME	NS_MAXCDNAME


#endif // defined WIN32

static unsigned short getshort(unsigned char *cp) {
  return (cp[0] << 8) | cp[1];
}

////////////////////////////////////////////////////////////////////////////////
// 
// _DNSGetPolicy for UNIX and win2k-
//
////////////////////////////////////////////////////////////////////////////////
int _DNSGetPolicy( const char* szSubDomain, char* Buffer, int nBufLen )
{
    u_char answer[PACKETSZ+1]; 
	int answerlen;
    int ancount, qdcount;	/* answer count and query count */
    u_char *eom, *cp;
    u_short type, rdlength;		/* fields of records returned */
	int rc;
	char* bufptr;

	// TODO: Query for a DKSP RR first

    answerlen = res_query( szSubDomain, C_IN, T_TXT, answer, sizeof(answer));

	if( answerlen < 0 )
	{
		if( h_errno == TRY_AGAIN )
			return DNSRESP_TEMP_FAIL;
		else
			return DNSRESP_PERM_FAIL;
	}

    qdcount = getshort( answer + 4); /* http://crynwr.com/rfc1035/rfc1035.html#4.1.1. */
    ancount = getshort( answer + 6);


    eom = answer + answerlen;
    cp  = answer + HFIXEDSZ;
	
	while( qdcount-- > 0 && cp < eom ) 
	{
		rc = dn_expand( answer, eom, cp, Buffer, nBufLen );
		if( rc < 0 ) {
			return DNSRESP_PERM_FAIL;
		}
		cp += rc + QFIXEDSZ;
    }
	
    while( ancount-- > 0 && cp < eom ) 
	{
		rc = dn_expand( answer, eom, cp, Buffer, nBufLen );
		if( rc < 0 ) {
			return DNSRESP_PERM_FAIL;
		}
		
		cp += rc;
		
		if (cp + RRFIXEDSZ >= eom) return DNSRESP_PERM_FAIL;
		
		type = getshort(cp + 0); /* http://crynwr.com/rfc1035/rfc1035.html#4.1.3. */
		rdlength = getshort(cp + 8);
		cp += RRFIXEDSZ;
		
		if( type != T_TXT ) {
			cp += rdlength;
			continue;
		}
		
		bufptr = Buffer;
		while (rdlength && cp < eom) 
		{
			int cnt;
			
			cnt = *cp++;		 /* http://crynwr.com/rfc1035/rfc1035.html#3.3.14. */
			if( bufptr-Buffer + cnt + 1 >= nBufLen )
				return DNSRESP_PERM_FAIL;
			if (cp + cnt > eom)
				return DNSRESP_PERM_FAIL;
			memcpy( bufptr, cp, cnt);
			rdlength -= cnt + 1;
			bufptr += cnt;
			cp += cnt;
			*bufptr = '\0';
		}
		
		return DNSRESP_SUCCESS;
    }

	return DNSRESP_PERM_FAIL;
}


////////////////////////////////////////////////////////////////////////////////
// 
// _DNSGetKey for UNIX and win2k-
//
////////////////////////////////////////////////////////////////////////////////
int _DNSGetKey( const char*szSubDomain, char* Buffer, int nBufLen )
{
    u_char answer[2*PACKETSZ+1]; 
	int answerlen;
    int ancount, qdcount;	/* answer count and query count */
    u_char *eom, *cp;
    u_short type, rdlength;		/* fields of records returned */
	int rc;
	char* bufptr;

	// TODO: Query for a DKK RR first


    answerlen = res_query( szSubDomain, C_IN, T_TXT, answer, sizeof(answer));

	if( answerlen < 0 )
	{
		if( h_errno == TRY_AGAIN )
			return DNSRESP_TEMP_FAIL;
		else
			return DNSRESP_PERM_FAIL;
	}

    qdcount = getshort( answer + 4); /* http://crynwr.com/rfc1035/rfc1035.html#4.1.1. */
    ancount = getshort( answer + 6);


    eom = answer + answerlen;
    cp  = answer + HFIXEDSZ;
	
	while( qdcount-- > 0 && cp < eom ) 
	{
		rc = dn_expand( answer, eom, cp, Buffer, nBufLen );
		if( rc < 0 ) {
			return DNSRESP_PERM_FAIL;
		}
		cp += rc + QFIXEDSZ;
    }
	
    while( ancount-- > 0 && cp < eom ) 
	{
		rc = dn_expand( answer, eom, cp, Buffer, nBufLen );
		if( rc < 0 ) {
			return DNSRESP_PERM_FAIL;
		}
		
		cp += rc;
		
		if (cp + RRFIXEDSZ >= eom) return DNSRESP_PERM_FAIL;
		
		type = getshort(cp + 0); /* http://crynwr.com/rfc1035/rfc1035.html#4.1.3. */
		rdlength = getshort(cp + 8);
		cp += RRFIXEDSZ;
		
		if( type != T_TXT ) {
			cp += rdlength;
			continue;
		}
		
		bufptr = Buffer;
		while (rdlength && cp < eom) 
		{
			int cnt;
			
			cnt = *cp++;		 /* http://crynwr.com/rfc1035/rfc1035.html#3.3.14. */
			if( bufptr-Buffer + cnt + 1 >= nBufLen )
				return DNSRESP_PERM_FAIL;
			if (cp + cnt > eom)
				return DNSRESP_PERM_FAIL;
			memcpy( bufptr, cp, cnt);
			rdlength -= cnt + 1;
			bufptr += cnt;
			cp += cnt;
			*bufptr = '\0';
		}
		
		return DNSRESP_SUCCESS;
    }

	return DNSRESP_PERM_FAIL;
}


////////////////////////////////////////////////////////////////////////////////
// 
// DNSGetPolicy
//
// Pass in the user and domain. This function combines them into the FQDN
// to query
//
////////////////////////////////////////////////////////////////////////////////
int DNSGetPolicy( const char* szUser, const char* szDomain, char* Buffer, int nBufLen )
{
	char szSubDomain[MAX_DOMAIN+1];
	int nUserStrLen = 0;

	if( szUser && szUser[0] )
	{
		nUserStrLen = strlen( szUser );
	}


	if( strlen(szDomain) + nUserStrLen > MAX_DOMAIN - 20 )
		return DNSRESP_DOMAIN_NAME_TOO_LONG;

	// construct the subdomain to query

	if( nUserStrLen > 0 )
	{
		strcpy( szSubDomain, szUser );
		strcat( szSubDomain, "._policy._domainkey." );
	}
	else
	{
		strcpy( szSubDomain, "_policy._domainkey." );
	}
	strcat( szSubDomain, szDomain );

	// Initialize out parameter
	Buffer[0] = '\0';

#ifdef WIN32
	if( CheckForDNSAPI() == true )
	{
		return _DNSGetPolicy2k( szSubDomain, Buffer, nBufLen );
	}
#endif

	return _DNSGetPolicy( szSubDomain, Buffer, nBufLen );
}

////////////////////////////////////////////////////////////////////////////////
// 
// DNSGetPolicy
//
// Pass in the FQDN to get the policy
//
////////////////////////////////////////////////////////////////////////////////
int DNSGetPolicy( const char* szFQDN, char* Buffer, int nBufLen )
{
	if (strlen(szFQDN) > MAX_DOMAIN)
		return DNSRESP_DOMAIN_NAME_TOO_LONG;

	// Initialize out parameter
	Buffer[0] = '\0';

#ifdef WIN32
	if( CheckForDNSAPI() == true )
	{
		return _DNSGetPolicy2k( szFQDN, Buffer, nBufLen );
	}
#endif

	return _DNSGetPolicy( szFQDN, Buffer, nBufLen );
}


////////////////////////////////////////////////////////////////////////////////
// 
// DNSGetKey
//
// Pass in the selector name and domain name. This function combines them into 
// the fqdn to query.
//
////////////////////////////////////////////////////////////////////////////////
int DNSGetKey( const char* szSelector, const char* szDomain, char* Buffer, int nBufLen )
{
	char szSubDomain[MAX_DOMAIN+1];
	int nSelectorStrLen = 0;

	if( szSelector && szSelector[0] )
	{
		nSelectorStrLen = strlen( szSelector );
	}

	if( strlen(szDomain) + nSelectorStrLen > MAX_DOMAIN - 11 )
		return DNSRESP_DOMAIN_NAME_TOO_LONG;

	// construct the subdomain to query

	if( nSelectorStrLen > 0 )
	{
		strcpy( szSubDomain, szSelector );
		strcat( szSubDomain, "._domainkey." );
	}
	else
	{
		strcpy( szSubDomain, "_domainkey." );
	}

	strcat( szSubDomain, szDomain );

	// Initialize out parameter
	Buffer[0] = '\0';

#ifdef WIN32
	if( CheckForDNSAPI() == true )
	{
		return _DNSGetKey2k( szSubDomain, Buffer, nBufLen );
	}
#endif

	return _DNSGetKey( szSubDomain, Buffer, nBufLen );
}


////////////////////////////////////////////////////////////////////////////////
// 
// DNSGetKey
//
// Pass in the FQDN to get the selector
//
////////////////////////////////////////////////////////////////////////////////
int DNSGetKey( const char* szFQDN, char* Buffer, int nBufLen )
{
	if (strlen(szFQDN) > MAX_DOMAIN)
		return DNSRESP_DOMAIN_NAME_TOO_LONG;

	// Initialize out parameter
	Buffer[0] = '\0';

#ifdef WIN32
	if( CheckForDNSAPI() == true )
	{
		return _DNSGetKey2k( szFQDN, Buffer, nBufLen );
	}
#endif

	return _DNSGetKey( szFQDN, Buffer, nBufLen );
}
