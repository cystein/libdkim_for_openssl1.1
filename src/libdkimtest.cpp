
#ifdef WIN32
#include <windows.h>
#else
#define strnicmp strncasecmp 
#endif

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#include "dkim.h"
#include "dns.h"


int DKIM_CALL SignThisHeader(const char* szHeader)
{
	if( strnicmp( szHeader, "X-", 2 ) == 0 )
	{
		return 0;
	}

	return 1;
}


int DKIM_CALL SelectorCallback(const char* szFQDN, char* szBuffer, int nBufLen )
{
	return 0;
}

int DKIM_CALL PolicyCallback(const char* szFQDN, char* szBuffer, int nBufLen )
{
	return 0;
}

void usage()
{

	printf( "usage: libdkimtest [-b<allman|ietf|both>] [-c<r|s|t|u>] [-d<domain>] [-l] [-h] [-i<you@yourdomain.com>] [-q] [-s] [-t] [-v] [-x<expire time>] [-z<hash>] <msgfile> <privkeyfile> <outfile>\n");
	printf( "-b<standard> allman , ietf or both\n");
	printf( "-c<canonicalization> r for relaxed [DEFAULT], s - simple, t relaxed/simple, u - simple/relaxed\n");
	printf( "-d<domain> the domain tag, if not provided it will be determined from the sender/from header\n");
	printf( "-l include body length tag\n");
	printf( "-h this help\n");
	printf( "-i<identity> the identity, if not provided it will not be included\n");
	printf( "-s sign the message\n");
	printf( "-t include a timestamp tag\n");
	printf( "-v verify the message\n");
	printf( "-x<expire_time> the expire time in seconds since epoch ( DEFAULT = current time + 604800)\n\t if set to - then it will not be included");
	printf( "-z<hash>  1 for sha1, 2 for sha256, 3 for both\n");
	printf( "-y<selector> the selector tag DEFAULT=MDaemon\n");
}
int main(int argc, char* argv[])
{
	int n;
	char* PrivKeyFile = "test.pem";
	char* MsgFile = "test.msg";
	char* OutFile = "signed.msg";
	int nPrivKeyLen;
	char PrivKey[2048];
	char Buffer[1024];
	int BufLen;
	char szSignature[10024];
	time_t t;
	DKIMContext ctxt;
	DKIMSignOptions opts;

	opts.nHash = DKIM_HASH_SHA1_AND_256;

	time(&t);

	opts.nCanon = DKIM_SIGN_RELAXED;
	opts.nIncludeBodyLengthTag = 0;
	opts.nIncludeQueryMethod = 0;
	opts.nIncludeTimeStamp = 0;
	opts.expireTime = t + 604800;		// expires in 1 week
	strcpy( opts.szSelector, "MDaemon" );
	opts.pfnHeaderCallback = SignThisHeader;
	strcpy( opts.szRequiredHeaders, "NonExistant" );
	opts.nIncludeCopiedHeaders = 0;
	opts.nIncludeBodyHash = DKIM_BODYHASH_BOTH;

	int nArgParseState = 0;
	bool bSign = true;

	if(argc<2){
		usage();
		exit(1);
	}

	for( n = 1; n < argc; n++ )
	{
		if( argv[n][0] == '-' && strlen(argv[n]) > 1 )
		{
			switch( argv[n][1] )
			{
			case 'b':		// allman or ietf draft 1 or both
				opts.nIncludeBodyHash = atoi( &argv[n][2] );
				break;

			case 'c':		// canonicalization
				if( argv[n][2] == 'r' )
				{
					opts.nCanon = DKIM_SIGN_RELAXED;
				}
				else if( argv[n][2] == 's' )
				{
					opts.nCanon = DKIM_SIGN_SIMPLE;
				}
				else if( argv[n][2] == 't' )
				{
					opts.nCanon = DKIM_SIGN_RELAXED_SIMPLE;
				}
				else if( argv[n][2] == 'u' )
				{
					opts.nCanon = DKIM_SIGN_SIMPLE_RELAXED;
				}
				break;

			case 'd': 
				strncpy(opts.szDomain,(const char*)(argv[n]+2),sizeof(opts.szDomain)-1);
				break;
			case 'l':		// body length tag
				opts.nIncludeBodyLengthTag = 1;
				break;


			case 'h':
				usage();	
				return 0;

			case 'i':		// identity 
				if( argv[n][2] == '-' )
				{
					opts.szIdentity[0] = '\0';
				}
				else
				{
					strncpy( opts.szIdentity, argv[n] + 2,sizeof(opts.szIdentity)-1 );
				}
				break;

			case 'q':		// query method tag
				opts.nIncludeQueryMethod = 1;
				break;

			case 's':		// sign
				bSign = true;
				break;

			case 't':		// timestamp tag
				opts.nIncludeTimeStamp = 1;
				break;

			case 'v':		// verify
				bSign = false;
				break;

			case 'x':		// expire time 
				if( argv[n][2] == '-' )
				{
					opts.expireTime = 0;
				}
				else
				{
					opts.expireTime = t + atoi( argv[n] + 2  );
				}
				break;

			case 'y':
				strncpy( opts.szSelector, argv[n]+2, sizeof(opts.szSelector)-1);
				break;

			case 'z':		// sign w/ sha1, sha256 or both 
				opts.nHash = atoi( &argv[n][2] );
				break;
			}
		}
		else
		{
			switch( nArgParseState )
			{
			case 0:
				MsgFile = argv[n];
				break;
			case 1:
				PrivKeyFile = argv[n];
				break;
			case 2:
				OutFile = argv[n];
				break;
			}
			nArgParseState++;
		}
	}


	if( bSign )
	{
		FILE* PrivKeyFP = fopen( PrivKeyFile, "r" );

		if ( PrivKeyFP == NULL ) 
		{ 
		  printf( "dkimlibtest: can't open private key file %s\n", PrivKeyFile );
		  exit(1);
		}
		nPrivKeyLen = fread( PrivKey, 1, sizeof(PrivKey), PrivKeyFP );
		if (nPrivKeyLen == sizeof(PrivKey)) { /* TC9 */
		  printf( "dkimlibtest: private key buffer isn't big enough, use a smaller private key or recompile.\n");
		  exit(1);
		}
		PrivKey[nPrivKeyLen] = '\0';
		fclose(PrivKeyFP);


		FILE* MsgFP = fopen( MsgFile, "rb" );

		if ( MsgFP == NULL ) 
		{ 
			printf( "dkimlibtest: can't open msg file %s\n", MsgFile );
			exit(1);
		}

		n = DKIMSignInit( &ctxt, &opts );

		while (1) {
			
			BufLen = fread( Buffer, 1, sizeof(Buffer), MsgFP );

			if( BufLen > 0 )
			{
				DKIMSignProcess( &ctxt, Buffer, BufLen );
			}
			else
			{
				break;
			}
		}

		fclose( MsgFP );
		
		//n = DKIMSignGetSig( &ctxt, PrivKey, szSignature, sizeof(szSignature) );

		char* pSig = NULL;

		n = DKIMSignGetSig2( &ctxt, PrivKey, &pSig );

		strcpy( szSignature, pSig );

		DKIMSignFree( &ctxt );

		FILE* in = fopen( MsgFile, "rb" );
		FILE* out = fopen( OutFile, "wb+" );

		fwrite( szSignature, 1, strlen(szSignature), out );
		fwrite( "\r\n", 1, 2, out );

		while (1) {
			
			BufLen = fread( Buffer, 1, sizeof(Buffer), in );

			if( BufLen > 0 )
			{
				fwrite( Buffer, 1, BufLen, out );
			}
			else
			{
				break;
			}
		}

		fclose( in );
	}
	else
	{
		FILE* in = fopen( MsgFile, "rb" );

		DKIMVerifyOptions vopts;
		vopts.pfnSelectorCallback = NULL; //SelectorCallback;
		vopts.pfnPolicyCallback = NULL; //PolicyCallback;

		n = DKIMVerifyInit( &ctxt, &vopts );

		while (1) {
			
			BufLen = fread( Buffer, 1, sizeof(Buffer), in );

			if( BufLen > 0 )
			{
				DKIMVerifyProcess( &ctxt, Buffer, BufLen );
			}
			else
			{
				break;
			}
		}

		n = DKIMVerifyResults( &ctxt );

		int nSigCount = 0;
		DKIMVerifyDetails* pDetails;
		char szPolicy[512];

		n = DKIMVerifyGetDetails(&ctxt, &nSigCount, &pDetails, szPolicy );

		for ( int i = 0; i < nSigCount; i++)
		{
			printf( "Signature #%d: ", i + 1 );

			if( pDetails[i].nResult >= 0 )
				printf( "Success\n" );
			else
				printf( "Failure\n" );
		}

		DKIMVerifyFree( &ctxt );
	}

	return 0;
}
