//
//  sslsign.h
//  SslSign library of wrapper functions on openssl for signing & verifying signed data
//
//  Created by Michael Hunley on 2/25/13.
//  Copyright (c) 2013 GM. All rights reserved.
//

#ifndef sslsign_h
#define sslsign_h

typedef enum {
    VALID = 1,
    INVALID = 0
} eValid;

typedef enum {
    eNone = 0,
    eMissingSigningCert,
    eMissingCaCert,
    eInputDataFailure,
    eSignFailure,
    eSignedDataRetrievalFailure,
    eVerifyFailure,
    eExtractFailure,
    eOutputBufferFailure,
    eOutputWriteFailure,

    eErrorLast	// never used
} eSslSignError;

typedef struct {
    void* data;
    size_t size;
    int error;
    char reason[1024];
} Results;

extern eValid hasSigningCert();
extern eValid initializeSigningCert( void* certData, size_t certDataLength );
extern void invalidateSigningCert();

extern eValid hasCaCert();
extern eValid initializeCaCert( const char* certFilename );
extern void invalidateCaCert();

extern Results signData( void* data, size_t length );
extern Results verifySignedData( void* data, size_t length );
extern Results extractSignedContents( void* data, size_t length );

extern void initializeResults( Results* result );
extern void getErrorResults( Results * result );
extern void freeResults( Results* result );

#endif
