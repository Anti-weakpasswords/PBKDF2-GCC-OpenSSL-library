#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <getopt.h>
// crypto.h used for the version
#include <openssl/crypto.h>


#define MD5_openssl           100
#define SHA_1_openssl_native  1000
#define SHA_1_openssl         2100
#define SHA_224_openssl       2200
#define SHA_256_openssl       2300
#define SHA_384_openssl       2400
#define SHA_512_openssl       2500

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

void PBKDF2_HMAC_MD5(const char* pass, const unsigned char* salt, int32_t iterations, uint32_t outputBytes, char* hexResult)
{
    unsigned int i;
    unsigned char digest[outputBytes];
    PKCS5_PBKDF2_HMAC(pass, strlen(pass), salt, strlen(salt), iterations, EVP_md5(), outputBytes, digest);
    for (i = 0; i < sizeof(digest); i++)
        sprintf(hexResult + (i * 2), "%02x", 255 & digest[i]);
}


void PBKDF2_HMAC_SHA_1nat(const char* pass, const unsigned char* salt, int32_t iterations, uint32_t outputBytes, char* hexResult)
{
    unsigned int i;
    unsigned char digest[outputBytes];
    PKCS5_PBKDF2_HMAC_SHA1(pass, strlen(pass), salt, strlen(salt), iterations, outputBytes, digest);
    for (i = 0; i < sizeof(digest); i++)
        sprintf(hexResult + (i * 2), "%02x", 255 & digest[i]);
}


void PBKDF2_HMAC_SHA_1(const char* pass, const unsigned char* salt, int32_t iterations, uint32_t outputBytes, char* hexResult)
{
    unsigned int i;
    unsigned char digest[outputBytes];
    PKCS5_PBKDF2_HMAC(pass, strlen(pass), salt, strlen(salt), iterations, EVP_sha1(), outputBytes, digest);
    for (i = 0; i < sizeof(digest); i++)
        sprintf(hexResult + (i * 2), "%02x", 255 & digest[i]);
}


void PBKDF2_HMAC_SHA_224(const char* pass, const unsigned char* salt, int32_t iterations, uint32_t outputBytes, char* hexResult)
{
    unsigned int i;
    unsigned char digest[outputBytes];
    PKCS5_PBKDF2_HMAC(pass, strlen(pass), salt, strlen(salt), iterations, EVP_sha224(), outputBytes, digest);
    for (i = 0; i < sizeof(digest); i++)
        sprintf(hexResult + (i * 2), "%02x", 255 & digest[i]);
}


void PBKDF2_HMAC_SHA_256(const char* pass, const unsigned char* salt, int32_t iterations, uint32_t outputBytes, char* hexResult)
{
    unsigned int i;
    unsigned char digest[outputBytes];
    PKCS5_PBKDF2_HMAC(pass, strlen(pass), salt, strlen(salt), iterations, EVP_sha256(), outputBytes, digest);
    for (i = 0; i < sizeof(digest); i++)
        sprintf(hexResult + (i * 2), "%02x", 255 & digest[i]);
}

void PBKDF2_HMAC_SHA_384(const char* pass, const unsigned char* salt, int32_t iterations, uint32_t outputBytes, char* hexResult)
{
    unsigned int i;
    unsigned char digest[outputBytes];
    PKCS5_PBKDF2_HMAC(pass, strlen(pass), salt, strlen(salt), iterations, EVP_sha384(), outputBytes, digest);
    for (i = 0; i < sizeof(digest); i++)
        sprintf(hexResult + (i * 2), "%02x", 255 & digest[i]);
}


void PBKDF2_HMAC_SHA_512(const char* pass, const unsigned char* salt, int32_t iterations, uint32_t outputBytes, char* hexResult)
{
    unsigned int i;
    unsigned char digest[outputBytes];
    PKCS5_PBKDF2_HMAC(pass, strlen(pass), salt, strlen(salt), iterations, EVP_sha512(), outputBytes, digest);
    for (i = 0; i < sizeof(digest); i++)
        sprintf(hexResult + (i * 2), "%02x", 255 & digest[i]);
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
  


  opterr = 0;
  
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
            return 4;
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
    puts("  -S saltfmt         NOT YET IMPLEMENTED - always string");
    puts("  -i iterations      Number of iterations, as high as you can handle the delay for, at least 16384 recommended.");
    puts("  -o bytes           Number of bytes of output; for password hashing, keep less than or equal to native hash size (MD5 <=16, SHA-1 <=20, SHA-256 <=32, SHA-512 <=64)");
    puts("  -O outputfmt       Output format NOT YET IMPLEMENTED - always HEX (lowercase)");
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
    
  // 2*outputBytes+1 is 2 hex bytes per binary byte, and one character at the end for the string-terminating \0
  char hexResult[2*outputBytes+1];
  memset(hexResult,0,sizeof(hexResult));
  char binResult[outputBytes];
  memset(hexResult,0,sizeof(binResult));

//    printf("Computing PBKDF2(HMAC-SHA512, '%s', '%s', %d, %d) ...\n", pass, salt, iterations, outputBytes);
  switch (algo)
    {
    case SHA_512_openssl:
      if (verbose && outputBytes > 64)
      {
        puts("WARNING: If you intend to use the result for password hashing, you should not choose a length greater than the native output size of the underlying hash function.");
      }
      PBKDF2_HMAC_SHA_512(pass, salt, iterations, outputBytes, hexResult);
      break;
    case SHA_384_openssl:
      if (verbose && outputBytes > 48)
      {
        puts("WARNING: If you intend to use the result for password hashing, you should not choose a length greater than the native output size of the underlying hash function.");
      }
      PBKDF2_HMAC_SHA_384(pass, salt, iterations, outputBytes, hexResult);
      break;
    case SHA_256_openssl:
      if (verbose && outputBytes > 32)
      {
        puts("WARNING: If you intend to use the result for password hashing, you should not choose a length greater than the native output size of the underlying hash function.");
      }
      PBKDF2_HMAC_SHA_256(pass, salt, iterations, outputBytes, hexResult);
      break;
    case SHA_224_openssl:
      if (verbose && outputBytes > 28)
      {
        puts("WARNING: If you intend to use the result for password hashing, you should not choose a length greater than the native output size of the underlying hash function.");
      }
      PBKDF2_HMAC_SHA_224(pass, salt, iterations, outputBytes, hexResult);
      break;
    case SHA_1_openssl:
      if (verbose && outputBytes > 20)
      {
        puts("WARNING: If you intend to use the result for password hashing, you should not choose a length greater than the native output size of the underlying hash function.");
      }
      PBKDF2_HMAC_SHA_1(pass, salt, iterations, outputBytes, hexResult);
      break;
    case SHA_1_openssl_native:
      if (verbose && outputBytes > 20)
      {
        puts("WARNING: If you intend to use the result for password hashing, you should not choose a length greater than the native output size of the underlying hash function.");
      }
      PBKDF2_HMAC_SHA_1nat(pass, salt, iterations, outputBytes, hexResult);
      break;
    case MD5_openssl:
      if (verbose && outputBytes > 16)
      {
        puts("WARNING: If you intend to use the result for password hashing, you should not choose a length greater than the native output size of the underlying hash function.");
      }
      PBKDF2_HMAC_MD5(pass, salt, iterations, outputBytes, hexResult);
      break;
    default:
      printf("Invalid algorithm choice.  Internal value %i\n",algo);
      return 2;
    }

  if (expected == NULL)
    {
    // Normal output
    printf("%s\n", hexResult);
    }
  else 
    {
    // Did it match or not?
    if (strcmp(expected,hexResult)==0)
      {
      puts("1");
      }
    else
      {
      printf("0 %s %s\n",hexResult,expected);
      }
    }
    
  
  return 0;
}
