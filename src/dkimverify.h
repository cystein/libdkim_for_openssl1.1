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

#ifndef DKIMVERIFY_H
#define DKIMVERIFY_H

#include "dkimbase.h"
#include <vector>

#define DKIM_POLICY_SIGNS_SOME					1
#define DKIM_POLICY_SIGNS_ALL					2
#define DKIM_POLICY_SIGNS_ALL_NO_THIRD_PARTY	3
#define DKIM_POLICY_NEVER_SENDS_EMAIL			4
#define DKIM_POLICY_REPEAT_AT_USER_LEVEL		5

#define DKIM_POLICY_DOMAIN_NAME_TOO_LONG	-50		// internal error
#define DKIM_POLICY_DNS_TEMP_FAILURE		-51		// internal error
#define DKIM_POLICY_DNS_PERM_FAILURE		-52		// internal error
#define DKIM_POLICY_INVALID					-53		// internal error

#define DKIM_SIG_VERSION_PRE_02			0
#define DKIM_SIG_VERSION_02_PLUS		1


class SelectorInfo
{
public:
	SelectorInfo(const string &sSelector, const string &sDomain);
	~SelectorInfo();

	string Domain;
	string Selector;
	string Granularity;
	bool AllowSHA1;
	bool AllowSHA256;
	EVP_PKEY *PublicKey;	/* the public key */
	bool Testing;
	bool SameDomain;

	int Status;

	int Parse( char* Buffer );
};

class SignatureInfo
{
public:
	SignatureInfo();
	~SignatureInfo();

	void Hash( const char* szBuffer, unsigned nBufLength, bool IsBody=false );

	string Header;
	unsigned Version;
	string Domain;
	string Selector;
	string SignatureData;
	string BodyHashData;
	string IdentityLocalPart;
	string IdentityDomain;
	vector<string> SignedHeaders;
	unsigned BodyLength;
	unsigned HeaderCanonicalization;
	unsigned BodyCanonicalization;
	unsigned ExpireTime;

	unsigned VerifiedBodyCount;
	unsigned UnverifiedBodyCount;

	EVP_MD_CTX *m_Hdr_ctx;
	EVP_MD_CTX *m_Bdy_ctx;
	SelectorInfo *m_pSelector;

	int Status;
	int m_nHash;						// use one of the DKIM_HASH_xxx constants here
};

class CDKIMVerify : public CDKIMBase
{
public:

	CDKIMVerify();
	~CDKIMVerify();

	int Init( DKIMVerifyOptions* pOptions );

	int GetResults(void);
	int GetDetails( int* nSigCount, DKIMVerifyDetails** pDetails );

	virtual int ProcessHeaders(void);
	virtual int ProcessBody( char* szBuffer, int nBufLength );

	const char* GetPolicy() { return Policy.c_str(); }

protected:

	int ParseDKIMSignature( const string& sHeader, SignatureInfo &sig );

	SelectorInfo& GetSelector( const string &sSelector, const string &sDomain );

	int GetPolicy( const string &sDomain, int &iPolicy, bool &bTesting);

	list<SignatureInfo> Signatures;
	list<SelectorInfo> Selectors;

	DKIMDNSCALLBACK m_pfnSelectorCallback;		// selector record callback
	DKIMDNSCALLBACK m_pfnPolicyCallback;		// policy record callback

	bool m_HonorBodyLengthTag;
	bool m_CheckPolicy;
	bool m_SubjectIsRequired;

	vector<DKIMVerifyDetails> Details;
	string Policy;
};

#endif //DKIMVERIFY_H
