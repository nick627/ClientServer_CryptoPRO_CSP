/*
 * Copyright(C) 2000 ������ ���
 *
 * ���� ���� �������� ����������, ����������
 * �������������� �������� ������ ���.
 *
 * ����� ����� ����� ����� �� ����� ���� �����������,
 * ����������, ���������� �� ������ �����,
 * ������������ ��� �������������� ����� ��������,
 * ���������������, �������� �� ���� � ��� ��
 * ����� ������������ ������� ��� ����������������
 * ���������� ���������� � ��������� ������ ���.
 */

/*!
 * \file $RCSfile$
 * \version $Revision: 126987 $
 * \date $Date:: 2015-09-08 16:51:58 +0300#$
 * \author $Author: pav $
 *
 * \brief ��������� Microsoft Cryptography Service Provider.
 *
 * �������� ��������� �������, ������� ������ ������������� ����� CSP.
 */
#ifndef _WINCSP_H_INCLUDED
#define _WINCSP_H_INCLUDED

#include "cspvtable.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef CSP_EXPORT
#define CSP_EXPORT extern
#endif /* CSP_EXPORT */

#define CPREGSTR_PATH_PROVIDER _TEXT("Software\\Microsoft\\Cryptography\\Defaults\\Provider")

CSP_EXPORT BOOL WINAPI CPAcquireContext (
    /* [out] */ HCRYPTPROV *phProv,
    /* [string][in] */ CHAR *pszContainer,
    /* [in] */ DWORD dwFlags,
    /* [in] */ PVTABLEPROVSTRUC pVTable);

CSP_EXPORT BOOL WINAPI CPReleaseContext (
    /* [in] */ HCRYPTPROV hProv,
    /* [in] */ DWORD dwFlags);

CSP_EXPORT BOOL WINAPI CPGetProvParam ( 
    /* [in] */ HCRYPTPROV hProv,
    /* [in] */ DWORD dwParam,
    /* [size_is][out] */ BYTE *pbData,
    /* [out][in] */ DWORD *pdwDataLen,
    /* [in] */ DWORD dwFlags);

CSP_EXPORT BOOL WINAPI CPSetProvParam (
    /* [in] */ HCRYPTPROV hProv,
    /* [in] */ DWORD dwParam,
    /* [size_is][in] */ BYTE *pbData,
    /* [in] */ DWORD dwFlags);

CSP_EXPORT BOOL WINAPI CPGenKey (
    /* [in] */ HCRYPTPROV hProv,
    /* [in] */ ALG_ID AlgId,
    /* [in] */ DWORD dwFlags,
    /* [out] */ HCRYPTKEY *phKey);

CSP_EXPORT BOOL WINAPI CPDestroyKey (
    /* [in] */ HCRYPTPROV hProv,
    /* [in] */ HCRYPTKEY hKey);

CSP_EXPORT BOOL WINAPI CPCreateHash (
    /* [in] */ HCRYPTPROV hProv,
    /* [in] */ ALG_ID AlgId,
    /* [in] */ HCRYPTKEY hKey,
    /* [in] */ DWORD dwFlags,
    /* [out] */ HCRYPTHASH *phHash);

CSP_EXPORT BOOL WINAPI CPDestroyHash (
    /* [in] */ HCRYPTPROV hProv,
    /* [in] */ HCRYPTHASH hHash);

CSP_EXPORT BOOL WINAPI CPEncrypt (
    /* [in] */ HCRYPTPROV hProv,
    /* [in] */ HCRYPTKEY hKey,
    /* [in] */ HCRYPTHASH hHash,
    /* [in] */ BOOL Final,
    /* [in] */ DWORD dwFlags,
    /* [size_is][out][in] */ BYTE *pbData,
    /* [out][in] */ DWORD *pdwDataLen,
    /* [in] */ DWORD dwBufLen);

CSP_EXPORT BOOL WINAPI CPDecrypt (
    /* [in] */ HCRYPTPROV hProv,
    /* [in] */ HCRYPTKEY hKey,
    /* [in] */ HCRYPTHASH hHash,
    /* [in] */ BOOL Final,
    /* [in] */ DWORD dwFlags,
    /* [full][size_is][out][in] */ BYTE *pbData,
    /* [out][in] */ DWORD *pdwDataLen);

CSP_EXPORT BOOL WINAPI CPDeriveKey (
    /* [in] */ HCRYPTPROV hProv,
    /* [in] */ ALG_ID AlgId,
    /* [in] */ HCRYPTHASH hBaseData,
    /* [in] */ DWORD dwFlags,
    /* [out] */ HCRYPTKEY *phKey);

CSP_EXPORT BOOL WINAPI CPDuplicateKey (
    /* [in] */ HCRYPTPROV hProv,
    /* [in] */ HCRYPTKEY hKey,
    /* [full][in] */ DWORD *pdwReserved,
    /* [in] */ DWORD dwFlags,
    /* [out] */ HCRYPTKEY *phKey);

CSP_EXPORT BOOL WINAPI CPDuplicateHash (
    /* [in] */ HCRYPTPROV hProv,
    /* [in] */ HCRYPTHASH hHash,
    /* [full][in] */ DWORD *pdwReserved,
    /* [in] */ DWORD dwFlags,
    /* [out] */ HCRYPTHASH *phHash);

CSP_EXPORT BOOL WINAPI CPExportKey (
    /* [in] */ HCRYPTPROV hProv,
    /* [in] */ HCRYPTKEY hKey,
    /* [in] */ HCRYPTKEY hExpKey,
    /* [in] */ DWORD dwBlobType,
    /* [in] */ DWORD dwFlags,
    /* [full][size_is][out][in] */ BYTE *pbData,
    /* [out][in] */ DWORD *pdwDataLen);

CSP_EXPORT BOOL WINAPI CPGenRandom (
    /* [in] */ HCRYPTPROV hProv,
    /* [in] */ DWORD dwLen,
    /* [size_is][out][in] */ BYTE *pbBuffer);

CSP_EXPORT BOOL WINAPI CPGetHashParam (
    /* [in] */ HCRYPTPROV hProv,
    /* [in] */ HCRYPTHASH hHash,
    /* [in] */ DWORD dwParam,
    /* [full][size_is][out][in] */ BYTE *pbData,
    /* [out][in] */ DWORD *pdwDataLen,
    /* [in] */ DWORD dwFlags);

CSP_EXPORT BOOL WINAPI CPGetKeyParam (
    /* [in] */ HCRYPTPROV hProv,
    /* [in] */ HCRYPTKEY hKey,
    /* [in] */ DWORD dwParam,
    /* [full][size_is][out][in] */ BYTE *pbData,
    /* [out][in] */ DWORD *pdwDataLen,
    /* [in] */ DWORD dwFlags);

CSP_EXPORT BOOL WINAPI CPGetUserKey (
    /* [in] */ HCRYPTPROV hProv,
    /* [in] */ DWORD dwKeySpec,
    /* [out] */ HCRYPTKEY *phUserKey);

CSP_EXPORT BOOL WINAPI CPHashData (
    /* [in] */ HCRYPTPROV hProv,
    /* [in] */ HCRYPTHASH hHash,
    /* [full][size_is][in] */ CONST BYTE *pbData,
    /* [in] */ DWORD dwDataLen,
    /* [in] */ DWORD dwFlags);

CSP_EXPORT BOOL WINAPI CPHashSessionKey (
    /* [in] */ HCRYPTPROV hProv,
    /* [in] */ HCRYPTHASH hHash,
    /* [in] */ HCRYPTKEY hKey,
    /* [in] */ DWORD dwFlags);

CSP_EXPORT BOOL WINAPI CPImportKey (
    /* [in] */ HCRYPTPROV hProv,
    /* [full][size_is][in] */ CONST BYTE *pbData,
    /* [in] */ DWORD dwDataLen,
    /* [in] */ HCRYPTKEY hImpKey,
    /* [in] */ DWORD dwFlags,
    /* [out] */ HCRYPTKEY *phKey);

CSP_EXPORT BOOL WINAPI CPSetHashParam (
    /* [in] */ HCRYPTPROV hProv,
    /* [in] */ HCRYPTHASH hHash,
    /* [in] */ DWORD dwParam,
    /* [size_is][in] */ BYTE *pbData,
    /* [in] */ DWORD dwFlags);

CSP_EXPORT BOOL WINAPI CPSetKeyParam (
    /* [in] */ HCRYPTPROV hProv,
    /* [in] */ HCRYPTKEY hKey,
    /* [in] */ DWORD dwParam,
    /* [size_is][in] */ BYTE *pbData,
    /* [in] */ DWORD dwFlags);

CSP_EXPORT BOOL WINAPI CPSignHash (
    /* [in] */ HCRYPTPROV hProv,
    /* [in] */ HCRYPTHASH hHash,
    /* [in] */ DWORD dwKeySpec,
    /* [string][full][in] */ LPCWSTR sDescription,
    /* [in] */ DWORD dwFlags,
    /* [size_is][out][in] */ BYTE *pbSignature,
    /* [out][in] */ DWORD *pdwSigLen);

CSP_EXPORT BOOL WINAPI CPVerifySignature (
    /* [in] */ HCRYPTPROV hProv,
    /* [in] */ HCRYPTHASH hHash,
    /* [size_is][in] */ CONST BYTE *pbSignature,
    /* [in] */ DWORD dwSigLen,
    /* [in] */ HCRYPTKEY hPubKey,
    /* [string][full][in] */ LPCWSTR sDescription,
    /* [in] */ DWORD dwFlags);

/* Callbacks: */

typedef struct _CRYPTOAPI_CARRIER_INFO
    {
    DWORD login_type;
    short max_length;
    short min_length;
    /* [string][full] */ TCHAR *reader_name;
    /* [string][full] */ TCHAR *nickname;
    /* [string][full] */ TCHAR *passwd_term;
    unsigned char flags;
    } 	CRYPTOAPI_CARRIER_INFO;

typedef struct _CRYPTOAPI_CARRIER_LIST
    {
    short n;
    /* [size_is] */ CRYPTOAPI_CARRIER_INFO *parts;
    } 	CRYPTOAPI_CARRIER_LIST;

typedef struct _CRYPTOAPI_RDR_PIN_FLAGS
    {
    unsigned char use_double;
    unsigned char same_double;
    unsigned char save_passwd;
    unsigned char disable_save_passwd;
    } 	CRYPTOAPI_RDR_PIN_FLAGS;


/*!
 * \brief ���������� ��� ������� ������� ������ � ��������������.
 *
 * ��������� �������� ���������� � ������� ��������� ������.
 * �� ���� ������� ��������� ����� ������������ ������ "%s" ��� ��������
 * ������� ������.
 */
typedef struct _CRYPTOAPI_PIN_WND_CONFIG
    {
    DWORD size_of;
    CRYPTOAPI_CARRIER_INFO context;
    /* [full][string] */ TCHAR *header;
    /* [full][string] */ TCHAR *text;
    /* [full][string] */ TCHAR *input;
    /* [full][string] */ TCHAR *input2;
    /* [full][string] */ TCHAR *default_passwd;
    /* [full][string] */ TCHAR *not_same;
    /* [full][string] */ TCHAR *save_text;
    /* [full][string] */ TCHAR *container_name;
    CRYPTOAPI_RDR_PIN_FLAGS flags;
    int try_number;
    DWORD idd;
    DWORD container_flags;
    DWORD action;
#ifndef NO_NK
    short n;
    short k;
    short max_n;
    short max_k;
#endif // NO_NK
    } 	CRYPTOAPI_PIN_WND_CONFIG;

typedef struct _CRYPTOAPI_PIN_WND_OUT
    {
    TCHAR passwd [256];
    TCHAR passwd2 [256];
#ifndef NO_NK
    TCHAR container [256];
    short n;
    short k;
    char create_container;
#endif // NO_NK
    char save_passwd;
    } 	CRYPTOAPI_PIN_WND_OUT;

#define PINWND_IDD_PASSWORD                    301
#define PINWND_IDD_PASSWORD2                   302
#define PINWND_IDD_PASSWORD_FKC			    381
#define FNAME_IDD_FRIENDLY_NAME			    383
#ifndef NO_NK
#define PINWND_IDD_PASSWORD_CHOICE_NK2         2109
#endif // NO_NK

/*! \internal
 * \ingroup grp_carrier_wind_real
 * \brief ������� - �������� ����������
 */
typedef struct CPUISelectItem_ {
    TCHAR name[256]; /*!< ������������� ��� */
    TCHAR unique[256]; /*!< ���������� ��� */
    TCHAR reader_name[256]; /*!< ��� ����������� */
    TCHAR nickname[256]; /*!< �������� ����������� */
    TCHAR connect[256];
    TCHAR friendly_name[256];
} CPUISelectItem;


typedef HRESULT WINAPI cpui_enum_containers_open (
    void *arg, void **ctx, DWORD flags );

typedef HRESULT WINAPI cpui_enum_containers_next (
    void *arg, void *ctx, CPUISelectItem* item );

typedef HRESULT WINAPI cpui_enum_containers_close (
    void *arg, void *ctx );

/*! \internal
 * \ingroup grp_carrier_wind_real
 * \brief ��������� ���� ������ ����������
 */
typedef struct CRYPTOAPI_SELECT_WND_CONFIG_ {
    DWORD size_of;
    DWORD flags; /*!< [in] ����� ������������ �����������. */
    void * enum_containers_arg;
    cpui_enum_containers_open * enum_containers_open;
    cpui_enum_containers_next * enum_containers_next;
    cpui_enum_containers_close * enum_containers_close;
} CRYPTOAPI_SELECT_WND_CONFIG;

/*! \internal
 * \ingroup grp_carrier_wind_real
 * \brief ���������� ���� ������ ����������
 */
typedef struct CRYPTOAPI_SELECT_WND_OUT_ {
    TCHAR container_name[512+1]; /*!< [out] �������������� ������, � ������� 
        ����� �������� ��� ���������� ����������. */
} CRYPTOAPI_SELECT_WND_OUT;


#define CRYPTOAPI_MESSAGE_BTN_OK	1
#define CRYPTOAPI_MESSAGE_BTN_CANCEL	2
#define CRYPTOAPI_MESSAGE_DEF_CANCEL	4
#define CRYPTOAPI_MESSAGE_BTN_LIC	8
#define CRYPTOAPI_MESSAGE_BTN_PRESS_BUY	256

/*! \internal
 * \ingroup grp_carrier_wind_real
 * \brief ��������� ���� ���������
 */
typedef struct CRYPTOAPI_MESSAGE_WND_CONFIG_ {
    DWORD size_of;
    DWORD num; /*!< ����� ������ � �������. */
    DWORD buttons; /*!< ����� ������� ������. */
    TCHAR containername [256]; /*!< ��� ���������� "� ���������" */
    TCHAR* message; // message 
    DWORD message_len; //message len
} CRYPTOAPI_MESSAGE_WND_CONFIG;

/*! \internal
 * \ingroup grp_carrier_wind_real
 * \brief ���������� ���� ���������
 */
typedef struct CRYPTOAPI_MESSAGE_WND_OUT_ {
    DWORD ok;
} CRYPTOAPI_MESSAGE_WND_OUT;

typedef HRESULT( WINAPI * cpui_select_container_ptr_t )(
    /* in */ HWND parent,
    /* in */ CRYPTOAPI_SELECT_WND_CONFIG * info,
    /* out */ CRYPTOAPI_SELECT_WND_OUT * out );

typedef HRESULT( WINAPI * cpui_query_pin_ptr_t )(
    /* [in] */ HWND parent,
    /* [in] */ CRYPTOAPI_PIN_WND_CONFIG * info,
    /* [in] */ CRYPTOAPI_SELECT_WND_CONFIG * select_info,
    /* [out] */ CRYPTOAPI_PIN_WND_OUT * out );

typedef HRESULT( WINAPI*cpui_display_message_ptr_t )(
    /* [in] */ HWND parent,
    /* [in] */ CRYPTOAPI_MESSAGE_WND_CONFIG * info,
    /* [out] */ CRYPTOAPI_MESSAGE_WND_OUT * out );

HRESULT WINAPI CPSelectContainer ( 
    /* in */ HWND parent,
    /* in */ CRYPTOAPI_SELECT_WND_CONFIG * info,
    /* out */ CRYPTOAPI_SELECT_WND_OUT * out );

HRESULT WINAPI CPQueryPin (
    /* [in] */ HWND parent, 
    /* [in] */ CRYPTOAPI_PIN_WND_CONFIG *info, 
    /* [in] */ CRYPTOAPI_SELECT_WND_CONFIG * select_info,
    /* [out] */ CRYPTOAPI_PIN_WND_OUT * out);

HRESULT WINAPI CPDisplayMessage (
    /* [in] */ HWND parent, 
    /* [in] */ CRYPTOAPI_MESSAGE_WND_CONFIG *info, 
    /* [out] */ CRYPTOAPI_MESSAGE_WND_OUT * out);


/*======================================================*/
/* ������������� � ��������� ���������������� */

/*------------------------------------------------------*/
/* ����������� ������� CPAcquireContext*/
typedef BOOL (WINAPI *CPAcquireContext_t) (
    HCRYPTPROV *phProv,       /* out*/
    CHAR *pszContainer,       /* in, out*/
    DWORD dwFlags,            /* in*/
    PVTABLEPROVSTRUC pVTable  /* in*/
);

/*------------------------------------------------------*/
/* ����������� ������� CPReleaseContext */
typedef BOOL (WINAPI *CPReleaseContext_t) (
    HCRYPTPROV hProv,  /* in*/
    DWORD dwFlags      /* in*/
);

/*------------------------------------------------------*/
/* ����������� ������� CPGetProvParam */
typedef BOOL (WINAPI *CPGetProvParam_t) (
    HCRYPTPROV hProv,  /* in*/
    DWORD dwParam,     /* in*/
    BYTE *pbData,      /* out*/
    DWORD *pdwDataLen, /* in, out*/
    DWORD dwFlags      /* in*/
);

/*------------------------------------------------------*/
/* ����������� ������� CPSetProvParam */
typedef BOOL (WINAPI *CPSetProvParam_t) (
    HCRYPTPROV hProv,  /* in*/
    DWORD dwParam,     /* in*/
    BYTE *pbData,      /* in*/
    DWORD dwFlags      /* in*/
);

/*======================================================*/
/* ������� ��������� � ������ � ������� */

/*------------------------------------------------------*/
/* ����������� ������� CPGenKey */
typedef BOOL (WINAPI *CPGenKey_t) (
    HCRYPTPROV hProv,     /* in*/
    ALG_ID Algid,         /* in*/
    DWORD dwFlags,        /* in*/
    HCRYPTKEY *phKey     /* out*/
);

/*------------------------------------------------------*/
/* ����������� ������� CPDestroyKey */
typedef BOOL (WINAPI *CPDestroyKey_t) (
    HCRYPTPROV hProv,  /* in*/
    HCRYPTKEY  hKey    /* in*/
);

/*------------------------------------------------------*/
/* ����������� ������� CPDeriveKey */
typedef BOOL (WINAPI *CPDeriveKey_t) ( 
	HCRYPTPROV hProv,		/* in*/
	ALG_ID AlgId,			/* in*/
	HCRYPTHASH hBaseData,	/* in*/
	DWORD dwFlags,			/* in*/
	HCRYPTKEY *phKey		/* out*/
);

/*------------------------------------------------------*/
/* ����������� ������� CPDuplicateKey */
typedef BOOL (WINAPI *CPDuplicateKey_t) ( 
	HCRYPTPROV hProv,		/* in*/
	HCRYPTKEY hKey,			/* in*/
	DWORD *pdwReserved,		/* in*/
	DWORD dwFlags,			/* in*/
	HCRYPTKEY *phKey		/* out*/
);

/*------------------------------------------------------*/
/* ����������� ������� CPExportKey */
typedef BOOL (WINAPI *CPExportKey_t) (
    HCRYPTPROV hProv,      /* in*/
    HCRYPTKEY hKey,        /* in*/
    HCRYPTKEY hPubKey,     /* in*/
    DWORD dwBlobType,      /* in*/
    DWORD dwFlags,         /* in*/
    BYTE *pbData,          /* out*/
    DWORD *pdwDataLen	   /* in, out*/
);

/*------------------------------------------------------*/
/* ����������� ������� CPGenRandom */
typedef BOOL (WINAPI *CPGenRandom_t) ( 
	HCRYPTPROV hProv,		/* in*/
	DWORD dwLen,			/* in*/
	BYTE *pbBuffer			/* in, out*/
);

/*------------------------------------------------------*/
/* ����������� ������� CPGetKeyParam*/
typedef BOOL (WINAPI *CPGetKeyParam_t) (
    HCRYPTPROV hProv,       /* in*/
    HCRYPTKEY hKey,         /* in*/
    DWORD dwParam,          /* in*/
    BYTE *pbData,           /* out*/
    DWORD *pdwDataLen,      /* in, out*/
    DWORD dwFlags           /* in*/
);

/*------------------------------------------------------*/
/* ����������� ������� CPGetUserKey */
typedef BOOL (WINAPI *CPGetUserKey_t) (
    HCRYPTPROV hProv,      
    DWORD dwKeySpec,       
    HCRYPTKEY *phUserKey   
);

/*------------------------------------------------------*/
/* ����������� ������� CPImportKey */
typedef BOOL (WINAPI *CPImportKey_t) (
    HCRYPTPROV hProv,       /* in*/
    CONST BYTE *pbData,     /* in*/
    DWORD  dwDataLen,       /* in*/
    HCRYPTKEY hPubKey,      /* in*/
    DWORD dwFlags,          /* in*/
HCRYPTKEY *phKey        /* out*/
);

/*------------------------------------------------------*/
/* ����������� ������� CPSetKeyParam*/
typedef BOOL (WINAPI *CPSetKeyParam_t) (
    HCRYPTPROV hProv,       /* in*/
    HCRYPTKEY hKey,         /* in*/
    DWORD dwParam,          /* in*/
    BYTE *pbData,           /* in*/
    DWORD dwFlags           /* in*/
);

/*======================================================*/
/* ������� ����������/������������� ������ */

/*------------------------------------------------------*/
/* ����������� ������� CPEncrypt*/
typedef BOOL (WINAPI *CPEncrypt_t) ( 
	HCRYPTPROV hProv,		/* in*/
	HCRYPTKEY hKey,			/* in*/
	HCRYPTHASH hHash,		/* in*/
	BOOL Final,				/* in*/
	DWORD dwFlags,			/* in*/
	BYTE *pbData,			/* in, out*/
	DWORD *pdwDataLen,		/* in, out*/
	DWORD dwBufLen			/* in*/
);

/*------------------------------------------------------*/
/* ����������� ������� CPDecrypt*/
typedef BOOL (WINAPI *CPDecrypt_t) (
	HCRYPTPROV hProv,		/* in*/
	HCRYPTKEY hKey,			/* in*/
	HCRYPTHASH hHash,		/* in*/
	BOOL Final,				/* in*/
	DWORD dwFlags,			/* in*/
	BYTE *pbData,			/* in, out*/
	DWORD *pdwDataLen		/* in, out*/
);

/*======================================================*/
/* ������� ����������� � ��� */

/*------------------------------------------------------*/
/* ����������� ������� CPCreateHash */
typedef BOOL (WINAPI *CPCreateHash_t) (
    HCRYPTPROV hProv,    /* in*/
    ALG_ID Algid,        /* in*/
    HCRYPTKEY hKey,      /* in*/
    DWORD dwFlags,       /* in*/
    HCRYPTHASH *phHash   /* out*/
);

/*------------------------------------------------------*/
/* ����������� ������� CPDestroyHash */
typedef BOOL (WINAPI *CPDestroyHash_t) (
    HCRYPTPROV hProv, /* in*/
    HCRYPTHASH hHash  /* in*/
);

/*------------------------------------------------------*/
/* ����������� ������� CPDuplicateHash */
typedef BOOL (WINAPI *CPDuplicateHash_t) ( 
	HCRYPTPROV hProv, 
	HCRYPTHASH hHash,		/* in*/ 
	DWORD *pdwReserved,		/* in*/
	DWORD dwFlags,			/* in*/
	HCRYPTHASH *phHash		/* out*/
);

/*------------------------------------------------------*/
/* ����������� ������� CPGetHashParam */
typedef BOOL (WINAPI *CPGetHashParam_t) (
    HCRYPTPROV hProv,        /* in*/
    HCRYPTHASH hHash,        /* in*/
    DWORD dwParam,           /* in*/
    BYTE *pbData,            /* out*/
    DWORD *pdwDataLen,       /* in, out*/
    DWORD dwFlags            /* in*/
);

/*------------------------------------------------------*/
/* ����������� ������� CPHashData */
typedef BOOL (WINAPI *CPHashData_t) (
    HCRYPTPROV hProv,       /* in*/
    HCRYPTHASH hHash,       /* in*/
    CONST BYTE *pbData,     /* in*/
    DWORD dwDataLen,        /* in*/
    DWORD dwFlags           /* in*/
);

/*------------------------------------------------------*/
/* ����������� ������� CPHashSessionKey */
typedef BOOL (WINAPI *CPHashSessionKey_t) ( 
	HCRYPTPROV hProv,		/* in*/
	HCRYPTHASH hHash,		/* in*/
	HCRYPTKEY hKey,			/* in*/
	DWORD dwFlags			/* in*/
);

/*------------------------------------------------------*/
/* ����������� ������� CPGetHashParam */
typedef BOOL (WINAPI *CPSetHashParam_t) (
    HCRYPTPROV hProv,        /* in*/
    HCRYPTHASH hHash,        /* in*/
    DWORD dwParam,           /* in*/
    BYTE *pbData,            /* out*/
    DWORD dwFlags            /* in*/
);

/*------------------------------------------------------*/
/* ����������� ������� CPSignHash */
typedef BOOL (WINAPI *CPSignHash_t) (
    HCRYPTPROV hProv,           /* in*/
    HCRYPTHASH hHash,           /* in*/
    DWORD dwKeySpec,            /* in*/
    LPCWSTR sDescription,       /* in*/
    DWORD dwFlags,              /* in*/
    BYTE *pbSignature,          /* out*/
    DWORD *pdwSigLen            /* in, out*/
);

/*------------------------------------------------------*/
/* ����������� ������� CPVerifySignature */
typedef BOOL (WINAPI *CPVerifySignature_t) (
    HCRYPTPROV hProv,         /* in*/
    HCRYPTHASH hHash,         /* in*/
    CONST BYTE *pbSignature,  /* in*/
    DWORD dwSigLen,           /* in*/
    HCRYPTKEY hPubKey,        /* in*/
    LPCWSTR sDescription,     /* in*/
    DWORD dwFlags             /* in*/
);

/* ������������� � ��������� ���������������� */
typedef struct _CSP_FUNCTION_TABLE {
    CPAcquireContext_t	AcquireContext;
    CPReleaseContext_t	ReleaseContext;
    CPGetProvParam_t	GetProvParam;
    CPSetProvParam_t	SetProvParam;
    CPGenKey_t		GenKey;
    CPDestroyKey_t	DestroyKey;
    CPDeriveKey_t	DeriveKey;
    CPDuplicateKey_t	DuplicateKey;
    CPExportKey_t	ExportKey;
    CPGenRandom_t	GenRandom; 
    CPGetKeyParam_t	GetKeyParam;
    CPGetUserKey_t	GetUserKey;
    CPImportKey_t	ImportKey;
    CPSetKeyParam_t	SetKeyParam;
    CPEncrypt_t		Encrypt;
    CPDecrypt_t		Decrypt;
    CPCreateHash_t	CreateHash;
    CPDestroyHash_t	DestroyHash;
    CPDuplicateHash_t	DuplicateHash;
    CPGetHashParam_t	GetHashParam;
    CPHashData_t	HashData;
    CPHashSessionKey_t	HashSessionKey; 
    CPSetHashParam_t	SetHashParam;
    CPSignHash_t	SignHash;
    CPVerifySignature_t	VerifySignature;
} CSP_FUNCTION_TABLE, *PCSP_FUNCTION_TABLE;

CSP_EXPORT PCSP_FUNCTION_TABLE WINAPI CPGetFunctionTable (void);

typedef PCSP_FUNCTION_TABLE (WINAPI *CPGetFunctionTable_t) (void);

#ifdef __cplusplus
}
#endif

#endif /* _WINCSP_H_INCLUDED */
