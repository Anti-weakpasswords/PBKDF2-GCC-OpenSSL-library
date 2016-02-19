//In progress - SHA-512 updated with bin.  Do the same to the others.


#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <getopt.h>
#include <ctype.h>
// crypto.h used for the version
#include <openssl/crypto.h>
// bio.h and buffer.h are solely for Base64
#include <openssl/bio.h>
#include <openssl/buffer.h>

#define MD5_openssl           100
#define SHA_1_openssl_native  1000
#define SHA_1_openssl         2100
#define SHA_224_openssl       2200
#define SHA_256_openssl       2300
#define SHA_384_openssl       2400
#define SHA_512_openssl       2500
#define OUT_HEX 	      0
#define OUT_HEXU	      1
#define OUT_HEXC	      2
#define OUT_HEXUC	      3
#define OUT_BASE64	      4
#define OUT_BIN	 	      5
#define SFMT_HEX		0
#define SFMT_STR		1
#define SFMT_B64        2

// Binary printing courtesy https://stackoverflow.com/questions/111928/is-there-a-printf-converter-to-print-in-binary-format
#define BYTETOBINARYPATTERN "%d%d%d%d%d%d%d%d"
#define BYTETOBINARY(byte)  \
  (byte & 0x80 ? 1 : 0), \
  (byte & 0x40 ? 1 : 0), \
  (byte & 0x20 ? 1 : 0), \
  (byte & 0x10 ? 1 : 0), \
  (byte & 0x08 ? 1 : 0), \
  (byte & 0x04 ? 1 : 0), \
  (byte & 0x02 ? 1 : 0), \
  (byte & 0x01 ? 1 : 0) 


// Originally from http://stackoverflow.com/questions/10067729/fast-sha-2-authentication-with-apache-is-it-even-possible

void PBKDF2_HMAC_MD5(const char* pass, const unsigned char* salt, int32_t iterations, uint32_t outputBytes, char* hexResult, uint8_t* binResult)
{
    unsigned int i;
    unsigned char digest[outputBytes];
    PKCS5_PBKDF2_HMAC(pass, strlen(pass), salt, strlen(salt), iterations, EVP_md5(), outputBytes, digest);
    for (i = 0; i < sizeof(digest); i++)
    {
        sprintf(hexResult + (i * 2), "%02x", 255 & digest[i]);
        binResult[i] = digest[i];
    };
}


void PBKDF2_HMAC_SHA_1nat(const char* pass, const unsigned char* salt, int32_t iterations, uint32_t outputBytes, char* hexResult, uint8_t* binResult)
{
    unsigned int i;
    unsigned char digest[outputBytes];
    PKCS5_PBKDF2_HMAC_SHA1(pass, strlen(pass), salt, strlen(salt), iterations, outputBytes, digest);
    for (i = 0; i < sizeof(digest); i++)
    {
        sprintf(hexResult + (i * 2), "%02x", 255 & digest[i]);
        binResult[i] = digest[i];
    };
}


void PBKDF2_HMAC_SHA_1(const char* pass, const unsigned char* salt, int32_t iterations, uint32_t outputBytes, char* hexResult, uint8_t* binResult)
{
    unsigned int i;
    unsigned char digest[outputBytes];
    PKCS5_PBKDF2_HMAC(pass, strlen(pass), salt, strlen(salt), iterations, EVP_sha1(), outputBytes, digest);
    for (i = 0; i < sizeof(digest); i++)
    {
        sprintf(hexResult + (i * 2), "%02x", 255 & digest[i]);
        binResult[i] = digest[i];
    };
}


void PBKDF2_HMAC_SHA_224(const char* pass, const unsigned char* salt, int32_t iterations, uint32_t outputBytes, char* hexResult, uint8_t* binResult)
{
    unsigned int i;
    unsigned char digest[outputBytes];
    PKCS5_PBKDF2_HMAC(pass, strlen(pass), salt, strlen(salt), iterations, EVP_sha224(), outputBytes, digest);
    for (i = 0; i < sizeof(digest); i++)
    {
        sprintf(hexResult + (i * 2), "%02x", 255 & digest[i]);
        binResult[i] = digest[i];
    };
}


void PBKDF2_HMAC_SHA_256(const char* pass, const unsigned char* salt, int32_t iterations, uint32_t outputBytes, char* hexResult, uint8_t* binResult)
{
    unsigned int i;
    unsigned char digest[outputBytes];
    PKCS5_PBKDF2_HMAC(pass, strlen(pass), salt, strlen(salt), iterations, EVP_sha256(), outputBytes, digest);
    for (i = 0; i < sizeof(digest); i++)
    {
        sprintf(hexResult + (i * 2), "%02x", 255 & digest[i]);
        binResult[i] = digest[i];
    };
}

void PBKDF2_HMAC_SHA_384(const char* pass, const unsigned char* salt, int32_t iterations, uint32_t outputBytes, char* hexResult, uint8_t* binResult)
{
    unsigned int i;
    unsigned char digest[outputBytes];
    PKCS5_PBKDF2_HMAC(pass, strlen(pass), salt, strlen(salt), iterations, EVP_sha384(), outputBytes, digest);
    for (i = 0; i < sizeof(digest); i++)
    {
	sprintf(hexResult + (i * 2), "%02x", 255 & digest[i]);
        binResult[i] = digest[i];
    };
}


void PBKDF2_HMAC_SHA_512(const char* pass, const unsigned char* salt, int32_t iterations, uint32_t outputBytes, char* hexResult, uint8_t* binResult)
{
    unsigned int i;
    unsigned char digest[outputBytes];
    PKCS5_PBKDF2_HMAC(pass, strlen(pass), salt, strlen(salt), iterations, EVP_sha512(), outputBytes, digest);
    for (i = 0; i < sizeof(digest); i++)
    {
        sprintf(hexResult + (i * 2), "%02x", 255 & digest[i]);
        binResult[i] = digest[i];
    };
        
}



char *Base64PlusSlashEqualsMultiLine2bin(unsigned char *input, int length)
{
// from http://www.ioncannon.net/programming/122/howto-base64-decode-with-cc-and-openssl/
  BIO *b64, *bmem;

  char *buffer = (char *)malloc(length);
  memset(buffer, 0, length);

  b64 = BIO_new(BIO_f_base64());
  bmem = BIO_new_mem_buf(input, length);
  bmem = BIO_push(b64, bmem);

  BIO_read(bmem, buffer, length);

  BIO_free_all(bmem);

  return buffer;
}

char *bin2Base64PlusSlashEqualsMultiLine(const unsigned char *input, int length)
{
// from http://www.ioncannon.net/programming/34/howto-base64-encode-with-cc-and-openssl/
  BIO *bmem, *b64;
  BUF_MEM *bptr;

  b64 = BIO_new(BIO_f_base64());
  bmem = BIO_new(BIO_s_mem());
  b64 = BIO_push(b64, bmem);
  BIO_write(b64, input, length);
  BIO_flush(b64);
  BIO_get_mem_ptr(b64, &bptr);

  char *buff = (char *)malloc(bptr->length);
  memcpy(buff, bptr->data, bptr->length-1);
  buff[bptr->length-1] = 0;

  BIO_free_all(b64);

  return buff;
}

char *toUpper(char *str, int len)
{
    unsigned int i;
    char *out = (char *)malloc(len);
    for(i = 0; i < len; i++)
        *(out+i) = toupper(*(str+i));
    return out;
}

char *hex2val(char *hexstr, int len)
{
    int i;
    char *tStr = (char *)malloc(2);
    int vlen = (len+1)/2;
    char *valstr = (char *)malloc(vlen); // to be sure we have all values, if len is not 2*x
    for (i = 0; i < vlen; i++)
    {
        memcpy(tStr, hexstr+(2*i), 2);
        *(valstr+i) = (char)strtol(tStr, NULL, 16);
    }
    return valstr;
}

char *colonDeliminate(char *input, int len)
{
    int i,j = 0;
    if (2*(len/2) != len) // if len is not even reduce it, or may be it's better to return null?!
        len--;
    int olen = 3*len/2 - 1;
    char *out = (char *)malloc(olen);
    for(i = 0; i < olen-3-1; i+=3)
    {
        memcpy(out+i, input+j, 2);
        *(out+i+2) = ':';
        j +=2;
    }
    memcpy(out+olen-2, input+len-2, 2);

    return out;
}

int main(int argc, char **argv)
{
  char *pass = NULL;
  char *salt = NULL;
  char *expected = NULL;
  uint32_t iterations = 0;
  uint32_t outputBytes = 0;
  uint16_t algo = 0;
  int c;
  uint8_t verbose = 0;
  uint8_t help = 0;
  uint8_t oType = 0;
  uint8_t sType = 0;
  
  opterr = 0;
  
//    printf("%s\n", hex2val("73616C7473616C74", 16));

  while ((c = getopt (argc, argv, "nhva:p:P:s:S:i:o:O:e:")) != -1)
    switch (c)
      {
      case 'a':
        if (strcmp(optarg,"SHA-512")==0)
          {
            algo = SHA_512_openssl;
          }
        else if (strcmp(optarg,"SHA-384")==0)
          {
            algo = SHA_384_openssl;
          }
        else if (strcmp(optarg,"SHA-256")==0)
          {
            algo = SHA_256_openssl;
          }
        else if (strcmp(optarg,"SHA-224")==0)
          {
            algo = SHA_224_openssl;
          }
        else if (strcmp(optarg,"SHA-1")==0)
          {
            algo = SHA_1_openssl;
          }
        else if (strcmp(optarg,"SHA-1nat")==0)
          {
            algo = SHA_1_openssl_native;
          }
        else if (strcmp(optarg,"MD5")==0)
          {
            algo = MD5_openssl;
          }
        else
          {
            printf("ERROR: -a argument %s unknown.\n",optarg);
            return -4;
          }
        break;
      case 'p':
        pass = optarg;
        break;
      case 's':
        salt = optarg;
        break;
      case 'i':
        iterations = atoi(optarg);
        break;
      case 'o':
        outputBytes = atoi(optarg);
        break;
      case 'v':
        verbose = 1;
        break;
      case 'h':
        help = 1;
        break;
      case 'e':
        expected = optarg;
        break;
      case 'O':
	if (strcmp(optarg,"hex")==0)
		oType = OUT_HEX;
	else if(strcmp(optarg,"Hex")==0)
		oType = OUT_HEXU;
	else if(strcmp(optarg,"hexc")==0)
		oType = OUT_HEXC;
	else if(strcmp(optarg,"Hexc")==0)
		oType = OUT_HEXUC;
	else if(strcmp(optarg,"base64")==0)
		oType = OUT_BASE64;
	else if(strcmp(optarg,"bin")==0)
		oType = OUT_BIN;
	else
	{
            printf("ERROR: For -O (Outputfmt) argument %s unknown.\n", optarg);
            return -5;
	}
      break;
      case 'S':
      	if(strcmp(optarg, "hex")==0)
		    sType = SFMT_HEX;
	    else if(strcmp(optarg, "str")==0)
		    sType = SFMT_STR;
        else if (strcmp(optarg, "base64"))
            sType = SFMT_B64;
	    else
	    {
            printf("ERROR: For -S (saltfmt) argument %s unknown.\n", optarg);
            return -6;
	    }

      break;
      case '?':
        puts("Case ?");fflush;
       if (optopt == 'c')
         fprintf (stderr, "Option -%c requires an argument.\n", optopt);
       else if (isprint (optopt))
         fprintf (stderr, "Unknown option `-%c'.\n", optopt);
       else
         fprintf (stderr,
                  "Unknown option character `\\x%x'.\n",
                  optopt);
       return 1;
      default:
        puts("Case default");fflush;
        break;//abort ();
      }

  if (help)
  {
    printf("Compiled with OpenSSL version: %s\n",OPENSSL_VERSION_TEXT);
    printf("Running with OpenSSL version: %s\n",SSLeay_version(SSLEAY_VERSION));
    printf("Example: %s -a SHA-512 -p password -s salt -i 131072 -o 64\n",argv[0]);
    puts("\nOptions: ");
    puts("  -h                 help");
    puts("  -v                 Verbose");
    puts("  -a algo            algorithm, valid values SHA-512|SHA-384|SHA-256|SHA-224|SHA-1|SHA-1nat|MD5   Note that in particular, SHA-384 and SHA-512 use 64-bit operations which as of 2014 penalize GPU's (attackers) much, much more than CPU's (you).  Use one of these two if at all possible.");
    puts("  -p password        Password to hash");
    puts("  -P passwordfmt     NOT YET IMPLEMENTED - always string");
    puts("  -s salt            Salt for the hash.  Should be long and cryptographically random.");
    puts("  -S saltfmt         hex: for Hex (default) / str: for String / base64: for Base64 string format");
    puts("  -i iterations      Number of iterations, as high as you can handle the delay for, at least 16384 recommended.");
    puts("  -o bytes           Number of bytes of output; for password hashing, keep less than or equal to native hash size (MD5 <=16, SHA-1 <=20, SHA-256 <=32, SHA-512 <=64)");
    //puts("  -O outputfmt       Output format NOT YET IMPLEMENTED - always HEX (lowercase)");
    puts("  -O outputfmt       Output format:");
    puts("                            - hex:		Lowercase Hex (default)");
    puts("                            - Hex:		Uppercase Hex");
    puts("                            - hexc:		Lowercase Hex with : deliminated");
    puts("                            - Hexc:		Uppercase Hex with : deliminated");
    puts("                            - base64:		Base64");
    puts("                            - bin:		Binary");
    puts("  -e hash            Expected hash (in the same format as outputfmt) results in output of 0 <actual> <expected> = different, 1 = same NOT YET IMPLEMENTED");
    puts("  -n                 Interactive mode; NOT YET IMPLEMENTED");
  }
     
  if (verbose)
  {
        printf("Interpreted arguments: algo %i password %s salt %s iterations %i outputbytes %i\n\n",algo,pass,salt,iterations,outputBytes);
  }


  if (algo <= 0)
    {
    puts("You must select a known algorithm identifier.");
    return 10;
    }

  if (iterations <= 0)
    {
    puts("You must select at least one iteration (and preferably tens of thousands or (much) more.");
    return 11;
    }

  if (outputBytes <= 0)
    {
    puts("You must select at least one byte of output length.");
    return 12;
    }

  switch (sType)
  {
	  case SFMT_HEX: // this is the default
        salt = hex2val(salt, strlen(salt));
        break;
      case SFMT_B64:
        salt= Base64PlusSlashEqualsMultiLine2bin(salt, strlen(salt));
        break;
	  case SFMT_STR:
	  break; 
  }
    
  // 2*outputBytes+1 is 2 hex bytes per binary byte, and one character at the end for the string-terminating \0
  char hexResult[2*outputBytes+1];
  memset(hexResult,0,sizeof(hexResult));
  uint8_t binResult[outputBytes+1];
  memset(binResult,0,sizeof(binResult));
  char *finResult = NULL;

//    printf("Computing PBKDF2(HMAC-SHA512, '%s', '%s', %d, %d) ...\n", pass, salt, iterations, outputBytes);
  switch (algo)
    {
    case SHA_512_openssl:
      if (verbose && outputBytes > 64)
      {
        puts("WARNING: If you intend to use the result for password hashing, you should not choose a length greater than the native output size of the underlying hash function.");
      }
      PBKDF2_HMAC_SHA_512(pass, salt, iterations, outputBytes, hexResult, binResult);
      break;
    case SHA_384_openssl:
      if (verbose && outputBytes > 48)
      {
        puts("WARNING: If you intend to use the result for password hashing, you should not choose a length greater than the native output size of the underlying hash function.");
      }
      PBKDF2_HMAC_SHA_384(pass, salt, iterations, outputBytes, hexResult, binResult);
      break;
    case SHA_256_openssl:
      if (verbose && outputBytes > 32)
      {
        puts("WARNING: If you intend to use the result for password hashing, you should not choose a length greater than the native output size of the underlying hash function.");
      }
      PBKDF2_HMAC_SHA_256(pass, salt, iterations, outputBytes, hexResult, binResult);
      break;
    case SHA_224_openssl:
      if (verbose && outputBytes > 28)
      {
        puts("WARNING: If you intend to use the result for password hashing, you should not choose a length greater than the native output size of the underlying hash function.");
      }
      PBKDF2_HMAC_SHA_224(pass, salt, iterations, outputBytes, hexResult, binResult);
      break;
    case SHA_1_openssl:
      if (verbose && outputBytes > 20)
      {
        puts("WARNING: If you intend to use the result for password hashing, you should not choose a length greater than the native output size of the underlying hash function.");
      }
      PBKDF2_HMAC_SHA_1(pass, salt, iterations, outputBytes, hexResult, binResult);
      break;
    case SHA_1_openssl_native:
      if (verbose && outputBytes > 20)
      {
        puts("WARNING: If you intend to use the result for password hashing, you should not choose a length greater than the native output size of the underlying hash function.");
      }
      PBKDF2_HMAC_SHA_1nat(pass, salt, iterations, outputBytes, hexResult, binResult);
      break;
    case MD5_openssl:
      if (verbose && outputBytes > 16)
      {
        puts("WARNING: If you intend to use the result for password hashing, you should not choose a length greater than the native output size of the underlying hash function.");
      }
      PBKDF2_HMAC_MD5(pass, salt, iterations, outputBytes, hexResult, binResult);
      break;
    default:
      printf("Invalid algorithm choice.  Internal value %i\n",algo);
      return 2;
    }

    switch(oType)
    {
    //		case OUT_HEX: // this is the default in this case goto default:
    //			printf("%s\n", hexResult);
    //			break;
		case OUT_HEXU:
            finResult = toUpper(hexResult, strlen(hexResult));
			break;
		case OUT_HEXC:
            finResult = colonDeliminate(hexResult, strlen(hexResult));
			break;
		case OUT_HEXUC:
            finResult = colonDeliminate(toUpper(hexResult, strlen(hexResult)), strlen(hexResult));
			break;
		case OUT_BASE64:
            finResult = bin2Base64PlusSlashEqualsMultiLine(binResult, strlen(binResult));
			break;
		case OUT_BIN:
            finResult = binResult;
			break;
		default:
		    finResult = hexResult;	
    }

  if (expected == NULL)
  {
    // Normal output
    //
        printf("%s\n",finResult);
  }
  else 
  {
 	   // Did it match or not?
    	if (strcmp(expected,finResult)==0)
      	{
      		puts("1");
      	}
    	else
      	{
      		printf("0 %s %s\n",finResult,expected);
      	}
  }
    
  
  return 0;
}
