/* Simple dedicated signing and verification openssl wrapper libs */
#include <stdlib.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

#include "sslsign.h"

static int initialized = 0;
static X509 *signing_cert = NULL;
static EVP_PKEY *signing_key = NULL;
static X509_STORE *store = NULL;

void initialize()
{
    if( !initialized )
    {
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
        initialized = 1;
    }
}

eValid hasSigningCert() { return signing_cert && signing_key ? VALID : INVALID; }

eValid initializeSigningCert( void* certData, size_t certDataLength )
{
    eValid result = INVALID;

    initialize();
    
    // make sure we have cleaned up any previous data
    invalidateSigningCert();

    BIO * pem = BIO_new_mem_buf(certData, certDataLength);
    if( pem )
    {
	BIO_set_mem_eof_return(pem, 0);
        signing_cert = PEM_read_bio_X509_AUX(pem, NULL, NULL, NULL);
        
        BIO_reset(pem);
        
        signing_key = PEM_read_bio_PrivateKey(pem, NULL, NULL, NULL);
        
        BIO_free(pem);
        
        result = hasSigningCert();
        if( !result ) {
            invalidateSigningCert();
        }
    }
    
    return result;
}

void invalidateSigningCert()
{
    if( signing_cert ) {
        X509_free(signing_cert);
        signing_cert = NULL;
    }
    if (signing_key) {
        EVP_PKEY_free(signing_key);
        signing_key = NULL;
    }
}

eValid hasCaCert() { return store ? VALID : INVALID; }

eValid initializeCaCert( const char* certFilename )
{
    eValid result = INVALID;
    X509_LOOKUP *lookup;
    
    initialize();
    
    // make sure we have cleaned up any previous data
    invalidateCaCert();
    
    // set up the store
    if( (store = X509_STORE_new()) )
    {
        X509_STORE_set_purpose(store, X509_PURPOSE_ANY);        
        X509_STORE_set_flags(store,0);
        
        lookup=X509_STORE_add_lookup(store, X509_LOOKUP_file());
        if( lookup )
        {
            if( X509_LOOKUP_load_file(lookup, certFilename, X509_FILETYPE_PEM) )
            {
                lookup=X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir());
                if( lookup )
                {
                    X509_LOOKUP_add_dir(lookup, NULL, X509_FILETYPE_DEFAULT);
                }
                
                result = VALID;
            }
        }
        
        if( !result ) {
            invalidateCaCert();
        }
    }
    
    return result;
}

void invalidateCaCert()
{
    if( store ) {
        X509_STORE_free(store);
        store = NULL;
    }
}

Results signData( void* data, size_t length )
{
    BIO *in = NULL, *out = NULL;
    PKCS7 *p7 = NULL;
    int flags = PKCS7_BINARY;
    int ret = 1;
    Results result;

    initializeResults( &result );
    if( hasSigningCert() )
    {
        ++ret;
        in = BIO_new_mem_buf(data, length);
        if( in )
        {
            ++ret;

            BIO_set_mem_eof_return(in, 0);
            
            /* Sign content */
            p7 = PKCS7_sign(signing_cert, signing_key, NULL, in, flags);
            
            if( p7 )
            {
                ++ret;
   
                out = BIO_new(BIO_s_mem());
                if( out )
                {
                    ++ret;
                    BIO_set_close(out, BIO_CLOSE);
                    
                    /* Write out signed data */
                    if( i2d_PKCS7_bio(out, p7) )
                    {
                        // TODO: send the data back out
			char* resultData;
                        result.size = BIO_get_mem_data(out, &resultData);

                        result.data = malloc(result.size);
                        memcpy( result.data, resultData, result.size );
                        ret = 0;
                    }
                    BIO_free(out);
                }
                PKCS7_free(p7);
            }
            BIO_free(in);
        }
    }

    result.error = ret;
    
    return result;
}

Results verifySignedData( void* data, size_t length )
{
    BIO *in = NULL, *out = NULL;
    PKCS7 *p7 = NULL;
    int ret = 1;
    Results result;

    initializeResults(&result);
    
    if( hasCaCert() )
    {
        ++ret;
        in = BIO_new_mem_buf(data, length);
        if( in )
        { 
            ++ret;
            BIO_set_mem_eof_return(in, 0);

            out = BIO_new(BIO_s_mem());
            if( out )
            {
                ++ret;
                BIO_set_close(out, BIO_CLOSE);

                /* get signed content */
                p7 = d2i_PKCS7_bio(in, NULL);
                
                if( p7 )
                {
                    ++ret;

                    /* verify cert chain, signatures and extract the signed contents */
                    if( PKCS7_verify(p7, NULL, store, NULL, out, 0) )
                    {
                        char* resultData;
                        result.size = BIO_get_mem_data(out, &resultData);

                        result.data = malloc(result.size);
                        memcpy( result.data, resultData, result.size );

                        ret = 0;
                    }
                    
                    PKCS7_free(p7);
                }
                
                BIO_free(out);
            }
            
            BIO_free(in);
        }
    }

    result.error = ret;
        
    return result;
}

Results extractSignedContents( void* data, size_t length )
{
    BIO *in = NULL, *out = NULL;
    PKCS7 *p7 = NULL;
    int ret = 1;
    Results result;

    initializeResults(&result);

    in = BIO_new_mem_buf(data, length);
    if( in )
    {
        ++ret;
        BIO_set_mem_eof_return(in, 0);

        out = BIO_new(BIO_s_mem());
        if( out )
        {
            ++ret;
            BIO_set_close(out, BIO_CLOSE);

            /* get signed content */
            p7 = d2i_PKCS7_bio(in, NULL);

            if( p7 )
            {
                ++ret;

                /* extract the signed contents */
                if( PKCS7_verify(p7, NULL, store, NULL, out, PKCS7_NOVERIFY|PKCS7_NOSIGS) )
                {
                    char* resultData;
                    result.size = BIO_get_mem_data(out, &resultData);

                    result.data = malloc(result.size);
                    memcpy( result.data, resultData, result.size );

                    ret = 0;
                }

                PKCS7_free(p7);
            }

            BIO_free(out);
        }

        BIO_free(in);
    }

    result.error = ret;

    return result;
}


void initializeResults( Results * result )
{
    if( result )
    {
        result->size = 0L;
        result->data = NULL;
        result->error = 0;
    }
}

void getErrorResults( Results * result )
{
    unsigned long errcode = ERR_peek_last_error();
    if( errcode )
    {
         result->error = errcode;
         ERR_error_string_n(errcode, result->reason, sizeof(result->reason));
    }
}

void freeResults( Results * result )
{
    if( result && result->data )
    {
        free(result->data);
    }
}

