/* salt formats and output formats appear to be working. 
Next up: Validating base64 input
After that: add some deliberate failure tests!
*/

// TODO: All of the https://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c can be removed as soon as the Base64 OpenSSL code can be validated.

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

#define MD5_openssl             100
#define SHA_1_openssl_native  1000
#define SHA_1_openssl         2100
#define SHA_224_openssl       2200
#define SHA_256_openssl       2300
#define SHA_384_openssl       2400
#define SHA_512_openssl       2500
#define OUTFMT_HEX               10000
#define OUTFMT_HEXU              10100
#define OUTFMT_HEXC              10200
#define OUTFMT_HEXUC             10300
#define OUTFMT_BASE64SingleLine  10400
#define OUTFMT_BASE64SingleLineURL  10425
#define OUTFMT_BASE64MultiLine   10450
#define OUTFMT_BASE64MultiLineURL   10475
#define OUTFMT_BIN               10500
#define SFMT_HEX              11000
#define SFMT_STR              11100
#define SFMT_BASE64SingleLine 11200
#define SFMT_BASE64MultiLine  11300
#define PFMT_HEX              12000
#define PFMT_STR              12100
#define PFMT_BASE64SingleLine 12200
#define PFMT_BASE64MultiLine  12300



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

void PBKDF2_HMAC_MD5(const char* pass, int passlen, const unsigned char* salt, int saltlen, int32_t iterations, uint32_t outputBytes, char* hexResult, uint8_t* binResult)
{
    unsigned int i;
    unsigned char digest[outputBytes];
    PKCS5_PBKDF2_HMAC(pass, passlen, salt, saltlen, iterations, EVP_md5(), outputBytes, digest);
    for (i = 0; i < sizeof(digest); i++)
    {
        sprintf(hexResult + (i * 2), "%02x", 255 & digest[i]);
        binResult[i] = digest[i];
    };
}


void PBKDF2_HMAC_SHA_1nat(const char* pass, int passlen, const unsigned char* salt, int saltlen, int32_t iterations, uint32_t outputBytes, char* hexResult, uint8_t* binResult)
{
    unsigned int i;
    unsigned char digest[outputBytes];
    PKCS5_PBKDF2_HMAC_SHA1(pass, passlen, salt, saltlen, iterations, outputBytes, digest);
    for (i = 0; i < sizeof(digest); i++)
    {
        sprintf(hexResult + (i * 2), "%02x", 255 & digest[i]);
        binResult[i] = digest[i];
    };
}


void PBKDF2_HMAC_SHA_1(const char* pass, int passlen, const unsigned char* salt, int saltlen, int32_t iterations, uint32_t outputBytes, char* hexResult, uint8_t* binResult)
{
    unsigned int i;
    unsigned char digest[outputBytes];
    PKCS5_PBKDF2_HMAC(pass, passlen, salt, saltlen, iterations, EVP_sha1(), outputBytes, digest);
    for (i = 0; i < sizeof(digest); i++)
    {
        sprintf(hexResult + (i * 2), "%02x", 255 & digest[i]);
        binResult[i] = digest[i];
    };
}


void PBKDF2_HMAC_SHA_224(const char* pass, int passlen, const unsigned char* salt, int saltlen, int32_t iterations, uint32_t outputBytes, char* hexResult, uint8_t* binResult)
{
    unsigned int i;
    unsigned char digest[outputBytes];
    PKCS5_PBKDF2_HMAC(pass, passlen, salt, saltlen, iterations, EVP_sha224(), outputBytes, digest);
    for (i = 0; i < sizeof(digest); i++)
    {
        sprintf(hexResult + (i * 2), "%02x", 255 & digest[i]);
        binResult[i] = digest[i];
    };
}


void PBKDF2_HMAC_SHA_256(const char* pass, int passlen, const unsigned char* salt, int saltlen, int32_t iterations, uint32_t outputBytes, char* hexResult, uint8_t* binResult)
{
    unsigned int i;
    unsigned char digest[outputBytes];
    PKCS5_PBKDF2_HMAC(pass, passlen, salt, saltlen, iterations, EVP_sha256(), outputBytes, digest);
    for (i = 0; i < sizeof(digest); i++)
    {
        sprintf(hexResult + (i * 2), "%02x", 255 & digest[i]);
        binResult[i] = digest[i];
    };
}

void PBKDF2_HMAC_SHA_384(const char* pass, int passlen, const unsigned char* salt, int saltlen, int32_t iterations, uint32_t outputBytes, char* hexResult, uint8_t* binResult)
{
    unsigned int i;
    unsigned char digest[outputBytes];
    PKCS5_PBKDF2_HMAC(pass, passlen, salt, saltlen, iterations, EVP_sha384(), outputBytes, digest);
    for (i = 0; i < sizeof(digest); i++)
    {
        sprintf(hexResult + (i * 2), "%02x", 255 & digest[i]);
        binResult[i] = digest[i];
    };
}


void PBKDF2_HMAC_SHA_512(const char* pass, int passlen, const unsigned char* salt, int saltlen, int32_t iterations, uint32_t outputBytes, char* hexResult, uint8_t* binResult)
{
    unsigned int i;
    unsigned char digest[outputBytes];
    PKCS5_PBKDF2_HMAC(pass, passlen, salt, saltlen, iterations, EVP_sha512(), outputBytes, digest);
    for (i = 0; i < sizeof(digest); i++)
    {
        sprintf(hexResult + (i * 2), "%02x", 255 & digest[i]);
        binResult[i] = digest[i];
    };
        
}



char *Base64PlusSlashEqualsMultiLine2bin(unsigned char *input, int length)
{
// from http://www.ioncannon.net/programming/122/howto-base64-decode-with-cc-and-openssl/

// BROKEN BROKEN BROKEN - DOES NOT RETURN ACTUAL LENGTH OF DECODED OUTPUT

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

char *Base64PlusSlashEqualsSingleLine2bin(unsigned char *input, int length)
{
// from http://www.ioncannon.net/programming/122/howto-base64-decode-with-cc-and-openssl/

// BROKEN BROKEN BROKEN - DOES NOT RETURN ACTUAL LENGTH OF DECODED OUTPUT

  BIO *b64, *bmem;

  char *buffer = (char *)malloc(length);
  memset(buffer, 0, length);

  b64 = BIO_new(BIO_f_base64());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  bmem = BIO_new_mem_buf(input, length);
  bmem = BIO_push(b64, bmem);

  BIO_read(bmem, buffer, length);

  BIO_free_all(bmem);

  return buffer;
}






static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'}; // from https://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c

static char *decoding_table = NULL; // from https://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c

static int mod_table[] = {0, 2, 1}; // from https://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c


void build_decoding_table() {
// from https://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c
    int i;
    decoding_table = malloc(256);

    for (i = 0; i < 64; i++)
        decoding_table[(unsigned char) encoding_table[i]] = i;
}


void base64_cleanup() {
// from https://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c
    free(decoding_table);
}


char *base64_encode(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length) {
// from https://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c

// Probably has some issues.

    int i;
    int j;
    *output_length = 4 * ((input_length + 2) / 3);


    char *encoded_data = malloc(*output_length+1); // modified to add a place to add \0
	  memset(encoded_data,0,sizeof(encoded_data)); // \0 fill


    if (encoded_data == NULL) return NULL;

    for (i = 0, j = 0; i < input_length;) {

        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[*output_length - 1 - i] = '=';


    return encoded_data;
}


unsigned char *base64_decode(const char *data,
                             size_t input_length,
                             size_t *output_length) {
// from https://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c

// probably has some SERIOUS issues with malformed input.

    int i;
    int j;
    if (decoding_table == NULL) build_decoding_table();

    if (input_length % 4 != 0) return NULL;

    *output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=') (*output_length)--;
    if (data[input_length - 2] == '=') (*output_length)--;

    unsigned char *decoded_data = malloc(*output_length);
    if (decoded_data == NULL) return NULL;

    for (i = 0, j = 0; i < input_length;) {

        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];

        uint32_t triple = (sextet_a << 3 * 6)
        + (sextet_b << 2 * 6)
        + (sextet_c << 1 * 6)
        + (sextet_d << 0 * 6);

        if (j < *output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
    }

    return decoded_data;
}






char *bin2Base64PlusSlashEqualsMultiLine(const unsigned char *input, int length, uint32_t *output_length)
{
// from http://www.ioncannon.net/programming/34/howto-base64-encode-with-cc-and-openssl/
  BIO *bmem, *b64;
  BUF_MEM *bptr;

  b64 = BIO_new(BIO_f_base64());
  //BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // When this is set, for 1 binary byte of input, bptr->length is 4 (no space for trailing \0).  When not set, bptr->length is 5 (i.e. space for trailing \0 is included).
  bmem = BIO_new(BIO_s_mem());
  b64 = BIO_push(b64, bmem);
  BIO_write(b64, input, length);
  BIO_flush(b64);
  BIO_get_mem_ptr(b64, &bptr);

  char *buff = (char *)malloc(bptr->length); // when the BIO_FLAGS_BASE64_NO_NL is NOT set, no need for an extra byte.  If it IS set, then we must add a spot for \0.
  memset(buff,0,bptr->length); // \0 fill for completeness
  memcpy(buff, bptr->data, bptr->length);
  *output_length = (uint32_t)bptr->length;
  BIO_free_all(b64);

  return buff;
}


char *bin2Base64PlusSlashEqualsSingleLine(const unsigned char *input, int length, uint32_t *output_length)
{
// from http://www.ioncannon.net/programming/34/howto-base64-encode-with-cc-and-openssl/
  BIO *bmem, *b64;
  BUF_MEM *bptr;

  b64 = BIO_new(BIO_f_base64());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // When this is set, for 1 binary byte of input, bptr->length is 4 (no space for trailing \0).  When not set, bptr->length is 5 (i.e. space for trailing \0 is included).
  bmem = BIO_new(BIO_s_mem());
  b64 = BIO_push(b64, bmem);
  BIO_write(b64, input, length);
  BIO_flush(b64);
  BIO_get_mem_ptr(b64, &bptr);

  char *buff = (char *)malloc(bptr->length+1); // when the BIO_FLAGS_BASE64_NO_NL is NOT set, no need for this.  If it IS set, then we must add a spot for \0.
  memset(buff,0,bptr->length+1); // \0 fill for completeness
  memcpy(buff, bptr->data, bptr->length);
  *output_length = (uint32_t)bptr->length;
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

uint8_t ValidateHexStringMultiCase(const char *hexstr, int len)
{
  uint32_t i;
  // Hex strings must be an even number of characters, and each character must be in the range 0-9a-fA-F
	if (strlen(hexstr)%2!=0)
		{
		return 0;
		};
  for (i=0;i<len;i++)
    {
    // validate that all characters are actual ASCII hex chars; 0-9a-fA-F
    if (((uint8_t)hexstr[i] < 48) || (((uint8_t)hexstr[i] > 57) && ((uint8_t)hexstr[i] < 65)) || (((uint8_t)hexstr[i] > 70) && ((uint8_t)hexstr[i] < 97)) || ((uint8_t)hexstr[i] > 102))
      {
      return 0;
      };
    };

  return 1;
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

char *Base64RFC1521toURLsafe(char *input, int len)
{
    /* RFC1521 Base64 uses + and / for characters 63 and 64, and = for padding */
    /* URLsafe Base64 uses - and _ for characters 63 and 64, and = for padding */
    char *out = (char *)malloc(len);
    for(int i = 0; i < len; i++)
    {
        if(input[i] == '+')
          {
          out[i] = '-';
          }
        else if(input[i] == '/')
          {
          out[i] = '_';
          }
        else
          out[i] = input[i];
    }
    
    return out;
}




int main(int argc, char **argv)
{
  char *pass = NULL;
  char *salt = NULL;
  uint32_t templen = 0; // templen used to avoid gcc 4.9.2 on Debian Jessie incorrectly using original variable on subsequent calls when -O3 is used (but NOT when -O3 was omitted)
  uint32_t passlen = 0;  
  uint32_t saltlen = 0;
  char *expected = NULL;
  uint32_t iterations = 0;
  uint32_t outputBytes = 0;
  uint32_t outputActualLength = 0;
  uint16_t algo = 0;
  int c;
  uint8_t verbose = 0;
  uint8_t help = 0;
  uint32_t oType = OUTFMT_HEX;
  uint32_t sType = SFMT_STR;
  uint32_t pType = PFMT_STR;
  
  opterr = 0;

	build_decoding_table();// from https://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c
  

  while ((c = getopt (argc, argv, "nhva:p:P:s:S:i:o:O:e:")) != -1)
    switch (c)
      {
      case 'a':
        // algorithm
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
        // password
        pass = optarg;
        passlen = strlen(pass);
        break;
      case 's':
        // salt
        salt = optarg;
        saltlen = strlen(salt);
        break;
      case 'i':
        // iteration count
        iterations = atoi(optarg);
        break;
      case 'o':
        // number of bytes of output
        outputBytes = atoi(optarg);
        break;
      case 'v':
        // verbosity
        verbose = 1;
        break;
      case 'h':
        // help
        help = 1;
        break;
      case 'e':
        // expected result
        expected = optarg;
        break;
      case 'O':
        // output format
        if (strcmp(optarg,"hex")==0)
            oType = OUTFMT_HEX;
        else if(strcmp(optarg,"HEX")==0)
            oType = OUTFMT_HEXU;
        else if(strcmp(optarg,"hexc")==0)
            oType = OUTFMT_HEXC;
        else if(strcmp(optarg,"HEXC")==0)
            oType = OUTFMT_HEXUC;
        else if(strcmp(optarg,"base64")==0)
            oType = OUTFMT_BASE64SingleLine;
        else if(strcmp(optarg,"base64url")==0)
            oType = OUTFMT_BASE64SingleLineURL;
        else if(strcmp(optarg,"base64ML")==0)
            oType = OUTFMT_BASE64MultiLine;
        else if(strcmp(optarg,"base64MLurl")==0)
            oType = OUTFMT_BASE64MultiLineURL;
        else if(strcmp(optarg,"bin")==0)
            oType = OUTFMT_BIN;
        else
        {
            printf("ERROR: For -O (Outputfmt) argument %s unknown.  See %s -h for help.\n", optarg, argv[0]);
            return -5;
        }
      break;
      case 'S':
        // salt format
        if(strcmp(optarg, "hex")==0)
            sType = SFMT_HEX;
        else if(strcmp(optarg, "str")==0)
            sType = SFMT_STR;
        else if (strcmp(optarg, "base64")==0)
            sType = SFMT_BASE64SingleLine;
        else if (strcmp(optarg, "base64ML")==0)
            sType = SFMT_BASE64MultiLine;
        else
        {
            printf("ERROR: For -S (saltfmt) argument %s unknown.  See %s -h for help.\n", optarg,argv[0]);
            return -6;
        }
      break;
      case 'P':
        // password format
        if(strcmp(optarg, "hex")==0)
            pType = PFMT_HEX;
        else if(strcmp(optarg, "str")==0)
            pType = PFMT_STR;
        else if (strcmp(optarg, "base64")==0)
            pType = PFMT_BASE64SingleLine;
        else if (strcmp(optarg, "base64ML")==0)
            pType = PFMT_BASE64MultiLine;
        else
        {
            printf("ERROR: For -P (passfmt) argument %s unknown.  See %s -h for help.\n", optarg,argv[0]);
            return -7;
        }
      break;
      case '?':
         puts("Case ?");fflush;
       if (optopt == 'c')
         fprintf (stderr, "Option -%c requires an argument.  See %s -h for help.\n", optopt,argv[0]);
       else if (isprint (optopt))
         fprintf (stderr, "Unknown option `-%c'.  See %s -h for help.\n", optopt,argv[0]);
       else
         fprintf (stderr,
                  "Unknown option character `\\x%x'.  See %s -h for help.\n",optopt,argv[0]);
       return 1;
      default:
        puts("Case default.  Use -h for help.");fflush;
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
    puts("  -P passwordfmt     Password format, valid values hex|str|base64     default is str");
    puts("  -s salt            Salt for the hash.  Should be long and cryptographically random.");
    puts("  -S saltfmt         Salt format, valid values hex|str|base64     default is str");
    puts("  -i iterations      Number of iterations, as high as you can handle the delay for, at least 16384 recommended.");
    puts("  -o bytes           Number of bytes of output; for password hashing, keep less than or equal to native hash size (MD5 <=16, SHA-1 <=20, SHA-256 <=32, SHA-512 <=64)");
    puts("  -O outputfmt       Output format, valid values hex|Hex|hexc|Hexc|base64|bin    ");
    puts("                            - hex:            Lowercase Hex (default)");
    puts("                            - HEX:            Uppercase Hex");
    puts("                            - hexc:           Lowercase Hex, colon deliminated");
    puts("                            - HEXC:           Uppercase Hex, colon deliminated");
    puts("                            - base64:         Base64 single line RFC1521 MIME, PEM - extra chars + and /, padding =");
    puts("                            - base64url:      Base64 single line URLsafe - extra chars - and _, padding =");
    puts("                            - base64ML:       Base64 multi line RFC1521 MIME, PEM - extra chars + and /, padding =");
    puts("                            - base64MLurl:    Base64 multi line URLsafe - extra chars - and _, padding =");
    puts("                            - bin:            Binary (actual binary output)");
    puts("  -e hash            Expected hash (in the same format as outputfmt) results in output of 0 <actual> <expected> = different, 1 = same NOT tested with outputfmt");
    puts("  -n                 Interactive mode; NOT YET IMPLEMENTED");
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
      case SFMT_HEX:
				if (ValidateHexStringMultiCase(salt,strlen(salt)) == 0)
					{
          puts("Hex strings must have an even number of characters, and hexadecimal string characters MUST only be part of the set [0-9a-fA-F].");
          return 13;
          };
        salt = hex2val(salt, saltlen);
        saltlen = saltlen / 2; // Validation ensured it was even and all characters were there
        break;
      case SFMT_BASE64SingleLine:
//        salt= Base64PlusSlashEqualsSingleLine2bin(salt, strlen(salt));
          salt = base64_decode(salt, strlen(salt),(size_t *)&templen); // templen used to avoid gcc 4.9.2 on Debian Jessie incorrectly using original variable on subsequent calls when -O3 is used (but NOT when -O3 was omitted)
          saltlen = templen; // templen used to avoid gcc 4.9.2 on Debian Jessie incorrectly using original variable on subsequent calls when -O3 is used (but NOT when -O3 was omitted)
        break;
      case SFMT_BASE64MultiLine:
        salt= Base64PlusSlashEqualsMultiLine2bin(salt, strlen(salt));
// SALTLEN needs to be set!!!
        break;
      case SFMT_STR: // this is the default
        break; 
  }



switch (pType)
  {
      case PFMT_HEX:
				if (ValidateHexStringMultiCase(pass,strlen(pass)) == 0)
					{
          puts("Hex strings must have an even number of characters, and hexadecimal string characters MUST only be part of the set [0-9a-fA-F].");
          return 14;
          };
        pass = hex2val(pass, passlen);
        passlen = passlen / 2; // Validation ensured it was even and all characters were there
        break;
      case PFMT_BASE64SingleLine:
//        pass= Base64PlusSlashEqualsSingleLine2bin(pass, strlen(pass));
          pass = base64_decode(pass, strlen(pass),(size_t *)&templen); // templen used to avoid gcc 4.9.2 on Debian Jessie incorrectly using original variable on subsequent calls when -O3 is used (but NOT when -O3 was omitted)
          passlen = templen; // templen used to avoid gcc 4.9.2 on Debian Jessie incorrectly using original variable on subsequent calls when -O3 is used (but NOT when -O3 was omitted)
        break;
      case PFMT_BASE64MultiLine:
        pass= Base64PlusSlashEqualsMultiLine2bin(pass, strlen(pass));
// PASSLEN needs to be set!!!
        break;
      case PFMT_STR: // this is the default
        break; 
  }



  if (verbose)
  {
        printf("Interpreted arguments: algo %i iterations %i outputbytes %i outputfmt %i saltfmt %i passfmt %i decoded length %i password: %s Decoded length %i salt: %s expected %s \n\n",algo,iterations,outputBytes,oType,sType,pType,passlen,pass,saltlen,salt,expected);
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
      PBKDF2_HMAC_SHA_512(pass, passlen, salt, saltlen, iterations, outputBytes, hexResult, binResult);
      break;
    case SHA_384_openssl:
      if (verbose && outputBytes > 48)
      {
        puts("WARNING: If you intend to use the result for password hashing, you should not choose a length greater than the native output size of the underlying hash function.");
      }
      PBKDF2_HMAC_SHA_384(pass, passlen, salt, saltlen, iterations, outputBytes, hexResult, binResult);
      break;
    case SHA_256_openssl:
      if (verbose && outputBytes > 32)
      {
        puts("WARNING: If you intend to use the result for password hashing, you should not choose a length greater than the native output size of the underlying hash function.");
      }
      PBKDF2_HMAC_SHA_256(pass, passlen, salt, saltlen, iterations, outputBytes, hexResult, binResult);
      break;
    case SHA_224_openssl:
      if (verbose && outputBytes > 28)
      {
        puts("WARNING: If you intend to use the result for password hashing, you should not choose a length greater than the native output size of the underlying hash function.");
      }
      PBKDF2_HMAC_SHA_224(pass, passlen, salt, saltlen, iterations, outputBytes, hexResult, binResult);
      break;
    case SHA_1_openssl:
      if (verbose && outputBytes > 20)
      {
        puts("WARNING: If you intend to use the result for password hashing, you should not choose a length greater than the native output size of the underlying hash function.");
      }
      PBKDF2_HMAC_SHA_1(pass, passlen, salt, saltlen, iterations, outputBytes, hexResult, binResult);
      break;
    case SHA_1_openssl_native:
      if (verbose && outputBytes > 20)
      {
        puts("WARNING: If you intend to use the result for password hashing, you should not choose a length greater than the native output size of the underlying hash function.");
      }
      PBKDF2_HMAC_SHA_1nat(pass, passlen, salt, saltlen, iterations, outputBytes, hexResult, binResult);
      break;
    case MD5_openssl:
      if (verbose && outputBytes > 16)
      {
        puts("WARNING: If you intend to use the result for password hashing, you should not choose a length greater than the native output size of the underlying hash function.");
      }
      PBKDF2_HMAC_MD5(pass, passlen, salt, saltlen, iterations, outputBytes, hexResult, binResult);
      break;
    default:
      printf("Invalid algorithm choice.  Internal value %i\n",algo);
      return 2;
    }

    switch(oType)
    {
    //          case OUTFMT_HEX: // this is the default in this case goto default:
    //                  printf("%s\n", hexResult);
    //                  break;
                case OUTFMT_HEXU:
            finResult = toUpper(hexResult, strlen(hexResult));
                        break;
                case OUTFMT_HEXC:
            finResult = colonDeliminate(hexResult, strlen(hexResult));
                        break;
                case OUTFMT_HEXUC:
            finResult = colonDeliminate(toUpper(hexResult, strlen(hexResult)), strlen(hexResult));
                        break;
                case OUTFMT_BASE64MultiLine:
            finResult = bin2Base64PlusSlashEqualsMultiLine(binResult, outputBytes,(uint32_t *)&outputActualLength);
                        break;
                case OUTFMT_BIN:
            finResult = binResult;
                        break;
                case OUTFMT_BASE64SingleLine:
            finResult = bin2Base64PlusSlashEqualsSingleLine(binResult, outputBytes,(uint32_t *)&outputActualLength);
//            // both methods appear to be working with the changes made.
//              finResult = base64_encode(binResult, outputBytes, (size_t *)&outputActualLength); // from https://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c
                        break;
                case OUTFMT_BASE64SingleLineURL:
            finResult = bin2Base64PlusSlashEqualsSingleLine(binResult, outputBytes,(uint32_t *)&outputActualLength);
            finResult = Base64RFC1521toURLsafe(finResult, outputActualLength+1);
                        break;
                case OUTFMT_BASE64MultiLineURL:
            finResult = bin2Base64PlusSlashEqualsMultiLine(binResult, outputBytes,(uint32_t *)&outputActualLength);
            finResult = Base64RFC1521toURLsafe(finResult, outputActualLength+1);
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
    
  base64_cleanup();// from https://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c
  
  return 0;
}
