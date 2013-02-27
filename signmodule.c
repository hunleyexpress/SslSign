// Copyright (c) 2013 General Motors Corporation
// Author: michael hunley

// a python extension module to expose data signing and verification using openssl for production application servers

#include <Python.h>
#include "sslsign.h"

static PyObject * set_signing_cert(PyObject *self, PyObject *args)
{
    Py_buffer cert;
    if (!PyArg_ParseTuple(args, "y*", &cert))
        return NULL;

    int ret = initializeSigningCert(cert.buf, cert.len);
    PyBuffer_Release(&cert);

    if( ret == INVALID )
    {
        // TODO raise an error
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyObject * has_signing_cert(PyObject *self, PyObject *args)
{
    long ret = hasSigningCert() == VALID ? 1L : 0L;
    return PyBool_FromLong(ret);
}

static PyObject * set_ca_cert(PyObject *self, PyObject *args)
{
    char* certFilename;
    if (!PyArg_ParseTuple(args, "s", &certFilename))
        return NULL;

    int ret = initializeCaCert(certFilename);

    if( ret == INVALID )
    {
        // TODO raise an error
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyObject * has_ca_cert(PyObject *self, PyObject *args)
{
    long ret = hasCaCert() == VALID ? 1L : 0L;
    return PyBool_FromLong(ret);
}

static PyObject * sign(PyObject *self, PyObject *args)
{
    Py_buffer data;
    if (!PyArg_ParseTuple(args, "y*", &data))
        return NULL;

    Results ret = signData(data.buf, data.len);
    PyBuffer_Release(&data);

    if( ret.error )
    {
	getErrorResults( &ret );
        // TODO raise an error
        return NULL;
    }

    // return a buffer of the data    
    PyObject* result = PyByteArray_FromStringAndSize(ret.data, ret.size);
    Py_INCREF(result);
    freeResults(&ret);
    return result;
}

static PyObject * verify(PyObject *self, PyObject *args)
{
    Py_buffer data;
    if (!PyArg_ParseTuple(args, "y*", &data))
        return NULL;

    Results ret = verifySignedData(data.buf, data.len);
    PyBuffer_Release(&data);

    if( ret.error )
    {
        getErrorResults( &ret );
        // TODO raise an error
        return NULL;
    }

    // return a buffer of the data
    PyObject* result = PyByteArray_FromStringAndSize(ret.data, ret.size);
    Py_INCREF(result);
    freeResults(&ret);
    return result;
}

static PyObject * extract(PyObject *self, PyObject *args)
{
    Py_buffer data;
    if (!PyArg_ParseTuple(args, "y*", &data))
        return NULL;

    Results ret = extractSignedContents(data.buf, data.len);
    PyBuffer_Release(&data);

    if( ret.error )
    {
        getErrorResults( &ret );
        // TODO raise an error
        return NULL;
    }

    // return a buffer of the data
    PyObject* result = PyByteArray_FromStringAndSize(ret.data, ret.size);
    Py_INCREF(result);
    freeResults(&ret);
    return result;
}


/*********** Python Declarations ************/
static PyMethodDef SslSignMethods[] = {
    {"set_signing_cert",  set_signing_cert, METH_VARARGS, "Set the cached signing certificate to the bytearray argument."},
    {"has_signing_cert",  has_signing_cert, METH_VARARGS, "check if the cached signing certificate is initialized and ready."},
    {"set_ca_cert",  set_ca_cert, METH_VARARGS, "Set the cached CA certificate for verification to the filename argument."},
    {"has_ca_cert",  has_ca_cert, METH_VARARGS, "check if the cached CA certificate is initialized and ready."},
    {"sign",  sign, METH_VARARGS, "sign the data in the parameter with the signing cert previously set and return the signed object"},
    {"verify",  verify, METH_VARARGS, "use the CA cert to verify a signed object returned frim sign"},
    {"extract",  extract, METH_VARARGS, "extract the unsigned data from a signed object without verifying.  useful for maintenance if the cert has expired."},

    {NULL, NULL, 0, NULL}        /* Sentinel */
};

static struct PyModuleDef signmodule = {
   PyModuleDef_HEAD_INIT,
   "sslsign",   /* name of module */
   NULL, /* module documentation, may be NULL */
   -1,       /* size of per-interpreter state of the module,
                or -1 if the module keeps state in global variables. */
   SslSignMethods
};

PyMODINIT_FUNC PyInit_sslsign(void)
{
    return PyModule_Create(&signmodule);
}
