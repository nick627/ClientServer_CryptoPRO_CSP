/**
  *Configure solution
  *
  *Add in solution folowwing projects
  *
  *File->Create->Project->Visual C++->Classic application Windows->Static Library
  *
  *Project->Options->C / C++->Precomplier headers->No use precompilier headers
  *
  *You can delete files: stdafx.cpp, stdafx.h, targetver.h
  *
  *Add files and code
  *
  *File->Create->Project->Visual C++->Empty project
  *
  *Refernces->Add refernce->Your project->OK
  *
  *Project->Options->C / C++->General->Additional include file directories->$(SolutionDir)Name_your_project_library
  *
  * For debuging
  *Project->Options->Debuging->Working directory->..\Relesase and ..\Debug
  *
  *Add files and code
  *
  *For debug : Project->Options->Debug->Working directory(default - $(ProjectDir))->..\Debug
  *
  *Build
**/

#include <stdio.h>
#include <windows.h>

#include <Wincrypt.h>
#include "_include\\WinCryptEx.h"

#include <string>

#pragma comment(lib, "crypt32.lib")

#define SIZE_COMMAND sizeof("SGN_")

#define COMM_SGN "SGN_"
#define COMM_ENC "ENC_"
#define COMM_HSH "HSH_"


// Формат ASN.1
#define MY_ENCODING_TYPE (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

//--------------------------------------------------------------------
// cert.cpp

extern PCCERT_CONTEXT WINAPI MyCertCreateCertificateContext(
	DWORD dwCertEncodingType,
	const BYTE *pbCertEncoded,
	DWORD cbCertEncoded);

extern PCCERT_CONTEXT read_cert_from_file(const char *fname);

//--------------------------------------------------------------------
// encodedecodeasn1.cpp

extern DWORD EncodeToASN1(
	char ** result,
	BYTE* pbContent,     // Байтовый указатель на сообщение
	DWORD cbContent      // Длина сообщения
);

extern DWORD DecodeFromASN1(
	char ** result,
	BYTE* pbEncodedBlob,     // Байтовый указатель на сообщение
	DWORD cbEncodedBlob      // Длина сообщения
);

//--------------------------------------------------------------------
// encryptdecrypt.cpp

extern DWORD cryptenc_encrypt(
	char ** result,
	BYTE* pbContent,
	DWORD cbContent,
	// char *my_certfile,
	char **recipient_certfile,
	int recipient_cnt,
	char *OID
);

extern DWORD cryptenc_decrypt(
	char ** result,
	BYTE* pbEncodedBlob,
	DWORD cbEncodedBlob
);

//--------------------------------------------------------------------
// hash.cpp

extern int GetHash(std::string & result, BYTE* hData, DWORD dataLen);

//--------------------------------------------------------------------
// signverify.cpp

extern LPCSTR GetHashOidForSign(HCRYPTPROV_LEGACY* hCryptProv, DWORD dwKeySpec);

extern DWORD Sign(
	char ** result,
	BYTE* pbContent,
	DWORD cbContent,
	char *certfile,
	int include, // Флаг добавления сертификата отправителя
	int detached // Поместить только значение ЭЦП, если установлен признак detached
);

extern DWORD Verify(char ** result, BYTE* pbEncodedBlob, DWORD cbEncodedBlob);

extern int get_signing_time(std::string & result, HCRYPTMSG hMsg, int signerIndex);

//--------------------------------------------------------------------
// utils.cpp

extern void HandleError(char const *s);

extern void GetDecodedMessage(std::string & result, BYTE *pbDecoded, DWORD cbDecoded);

extern int get_file_data_pointer(const char *infile, size_t *len, unsigned char **buffer);

extern int release_file_data_pointer(unsigned char *buffer);

extern void PrepareContext(HCRYPTPROV_LEGACY* hCryptProv, HCERTSTORE* hStoreHandle);

extern void ReleaseContext(HCRYPTPROV_LEGACY* hCryptProv, HCERTSTORE* hStoreHandle, PCCERT_CONTEXT* pCertContext);

//--------------------------------------------------------------------

extern void printfile(char const *namefile, char const *msg, long len);
extern int Read_Opened_Text_From_File(char * path, char ** buffer);

//--------------------------------------------------------------------