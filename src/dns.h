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

// This file is an intermediary which chooses the correct resolver
// to use based on the platform
//
// Windows 2k+ -> Dynamically load dnsapi.dll and use DnsQuery()
// Win9x/NT    -> Use dnsresolv.cpp
// UNIX        -> Use res_query from libresolv
//
// These DNS resolution routines are encapsulated by the API below

// return values for DNS functions:


#define MAX_DOMAIN			254

#define DNSRESP_SUCCESS					0	// DNS lookup returned sought after records
#define DNSRESP_TEMP_FAIL				1	// No response from DNS server
#define DNSRESP_PERM_FAIL				2	// DNS server replied but no records found
#define DNSRESP_DOMAIN_NAME_TOO_LONG	3	// Domain name too long

// Pass in the user and domain. This function combines them into the FQDN
// to query
int DNSGetPolicy( const char* szUser, const char* szDomain, char* Buffer, int nBufLen );

// Pass in the FQDN to get the policy
int DNSGetPolicy( const char *szFQDN, char* Buffer, int nBufLen );

// Pass in the selector name and domain name. This function combines them into 
// the fqdn to query.
int DNSGetKey( const char* szSelector, const char* szDomain, char* Buffer, int nBufLen );

// Pass in the FQDN to get the selector
int DNSGetKey( const char* szFQDN, char* Buffer, int nBufLen );
