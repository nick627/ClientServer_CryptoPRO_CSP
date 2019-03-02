#define _CRT_SECURE_NO_WARNINGS

#include <limits.h>
#include "utils.h"

#define NAME_MAX 255

//--------------------------------------------------------------------
// Получение OID хэша 

LPCSTR GetHashOidForSign(HCRYPTPROV_LEGACY* hCryptProv, DWORD dwKeySpec)
{
	LPCSTR		hash_oid = NULL;
	ALG_ID		key_algid;
	DWORD		dwAlgidLen = sizeof(ALG_ID);
	HCRYPTKEY	hKey = 0;

	if (!CryptGetUserKey(*hCryptProv, dwKeySpec, &hKey))
	{
		goto error;
	}

	if (!CryptGetKeyParam(hKey, KP_ALGID, (BYTE*)&key_algid, &dwAlgidLen, 0))
	{
		goto error;
	}

	switch (key_algid)
	{
	
	case CALG_DH_EL_SF:
	
	case CALG_GR3410EL:
		hash_oid = szOID_CP_GOST_R3411;
		break;
	
	case CALG_DH_GR3410_12_256_SF:
	
	case CALG_GR3410_12_256:
		hash_oid = szOID_CP_GOST_R3411_12_256;
		break;
	
	case CALG_DH_GR3410_12_512_SF:
	
	case CALG_GR3410_12_512:
		hash_oid = szOID_CP_GOST_R3411_12_512;
		break;
	
	default:
		break;
	}

error:
	if (!CryptDestroyKey(hKey))
	{
		hash_oid = NULL;
	}

	return hash_oid;
}

//--------------------------------------------------------------------
// Cоздание PKCS#7 Signed

DWORD Sign(
	char ** result,
	BYTE* pbContent,
	DWORD cbContent,
	char *certfile,
	int include, // Флаг добавления сертификата отправителя
	int detached // Поместить только значение ЭЦП, если установлен признак detached
)
{
	HCRYPTPROV	    hCryptProv = 0;	    // Дескриптор провайдера
	PCCERT_CONTEXT  pUserCert = NULL;	// Сертификат, используемый для формирования ЭЦП

	DWORD	    keytype = 0;	    // Тип ключа (возвращается)
	BOOL	    should_release_ctx = FALSE;
	int		    ret = 0;
	BYTE	    *mem_tbs = NULL;	// Исходные данные
	size_t	    mem_len = 0;	    // Длина данных

	HCRYPTMSG	hMsg = 0;			// Дескриптор сообщения

	CRYPT_ALGORITHM_IDENTIFIER	HashAlgorithm;			  // Идентификатор алгоритма хэширования
	DWORD						HashAlgSize;
	CMSG_SIGNER_ENCODE_INFO		SignerEncodeInfo;		  // Структура, описывающая отправителя
	CMSG_SIGNER_ENCODE_INFO		SignerEncodeInfoArray[1]; // Массив структур, описывающих отправителя
	CERT_BLOB					SignerCertBlob;
	CERT_BLOB					SignerCertBlobArray[1];
	DWORD						cbEncodedBlob;
	BYTE						*pbEncodedBlob = NULL;
	CMSG_SIGNED_ENCODE_INFO		SignedMsgEncodeInfo;	  // Структура, описывающая подписанное сообщение
	DWORD						flags = 0;

	HCERTSTORE	hStoreHandle = NULL;
	PrepareContext(&hCryptProv, &hStoreHandle);

	std::string error_message = "";

	//--------------------------------------------------------------------
	//  Используем сертификат из файла для инициализации контекста
	if (!certfile)
	{
		error_message += "No user cert specified\n";
		goto err;
		// HandleError("No user cert specified\n");
	}

	pUserCert = read_cert_from_file(certfile);

	if (!pUserCert) {
		error_message += "CertCreateCertificateContext\r\nCannot find User certificate\n";
		goto err;
		// HandleError("Cannot find User certificate\n");
	}

	//--------------------------------------------------------------------
	// Программа по заданному сертификату определяет наличие секретного ключа
	// и загружает требуемый провайдер.
	// Для определения провайдера используется функция CryptAcquireCertificatePrivateKey, 
	// если она присутствует в crypt32.dll. Иначе производистя поиск ключа по сертификату в справочнике.
	// ret = CryptAcquireProvider("my", pUserCert, &hCryptProv, &keytype, &should_release_ctx);

	// Получение закрытого ключа  	
	ret = CryptAcquireCertificatePrivateKey(
		pUserCert,
		0,
		NULL,
		&hCryptProv,
		&keytype,
		&should_release_ctx);
	if (ret) {
		;// printf("A CSP has been acquired. \n");
	}
	else {
		error_message += "Cryptographic context could not be acquired.";
		goto err;
		// HandleError("Cryptographic context could not be acquired.");
	}

	//--------------------------------------------------------------------
	// Инициализируем структуру алгоритма

	HashAlgSize = sizeof(HashAlgorithm);
	memset(&HashAlgorithm, 0, HashAlgSize);
	HashAlgorithm.pszObjId = (LPSTR)GetHashOidForSign(&hCryptProv, keytype); // Идентификатор алгоритма хэша

	//--------------------------------------------------------------------
	// Инициализируем структуру CMSG_SIGNER_ENCODE_INFO

	memset(&SignerEncodeInfo, 0, sizeof(CMSG_SIGNER_ENCODE_INFO));
	SignerEncodeInfo.cbSize = sizeof(CMSG_SIGNER_ENCODE_INFO);
	SignerEncodeInfo.pCertInfo = pUserCert->pCertInfo;
	SignerEncodeInfo.hCryptProv = hCryptProv;
	SignerEncodeInfo.dwKeySpec = keytype;
	SignerEncodeInfo.HashAlgorithm = HashAlgorithm;
	SignerEncodeInfo.pvHashAuxInfo = NULL;

	//--------------------------------------------------------------------
	// Создадим массив отправителей. Сейчас только из одного.

	SignerEncodeInfoArray[0] = SignerEncodeInfo;

	//--------------------------------------------------------------------
	// Инициализируем структуру CMSG_SIGNED_ENCODE_INFO

	SignerCertBlob.cbData = pUserCert->cbCertEncoded;
	SignerCertBlob.pbData = pUserCert->pbCertEncoded;

	//--------------------------------------------------------------------
	// Инициализируем структуру массив структур CertBlob.

	SignerCertBlobArray[0] = SignerCertBlob;
	memset(&SignedMsgEncodeInfo, 0, sizeof(CMSG_SIGNED_ENCODE_INFO));
	SignedMsgEncodeInfo.cbSize = sizeof(CMSG_SIGNED_ENCODE_INFO);
	SignedMsgEncodeInfo.cSigners = 1;
	SignedMsgEncodeInfo.rgSigners = SignerEncodeInfoArray;
	SignedMsgEncodeInfo.cCertEncoded = include;
	// Если задан флаг добавления сертификата отправителя
	if (include)
		SignedMsgEncodeInfo.rgCertEncoded = SignerCertBlobArray;
	else
		SignedMsgEncodeInfo.rgCertEncoded = NULL;

	SignedMsgEncodeInfo.rgCrlEncoded = NULL;
	if (detached)
		flags = CMSG_DETACHED_FLAG;

	//--------------------------------------------------------------------
	// Определим длину подписанного сообщения

	cbEncodedBlob = CryptMsgCalculateEncodedLength(
		MY_ENCODING_TYPE,		// Message encoding type
		flags,                  // Flags
		CMSG_SIGNED,            // Message type
		&SignedMsgEncodeInfo,   // Pointer to structure
		NULL,                   // Inner content object ID
		cbContent);				// Size of content
	if (cbEncodedBlob)
	{
		;// printf("The length of the data has been calculated. \n");
	}
	else
	{
		error_message += "Getting cbEncodedBlob length failed";
		goto err;
		// HandleError("Getting cbEncodedBlob length failed");
	}

	//--------------------------------------------------------------------
	// Резервируем память, требуемой длины

	pbEncodedBlob = (BYTE *)malloc(cbEncodedBlob);
	if (!pbEncodedBlob)
	{
		error_message += "Memory allocation failed";
		goto err;
		// HandleError("Memory allocation failed");
	}

	//--------------------------------------------------------------------
	// Создадим дескриптор сообщения
	hMsg = CryptMsgOpenToEncode(
		MY_ENCODING_TYPE,		// Encoding type
		flags,                  // Flags (CMSG_DETACHED_FLAG )
		CMSG_SIGNED,            // Message type
		&SignedMsgEncodeInfo,   // Pointer to structure
		NULL,                   // Inner content object ID
		NULL);                  // Stream information (not used)
	if (hMsg) {
		;// printf("The message to be encoded has been opened. \n");
	}
	else
	{
		error_message += "OpenToEncode failed";
		goto err;
		// HandleError("OpenToEncode failed");
	}
	//--------------------------------------------------------------------
	// Поместим в сообщение подписываемые данные

	if (CryptMsgUpdate(
		hMsg,		    // Handle to the message
		pbContent,	    // Pointer to the content
		cbContent,	    // Size of the content
		TRUE))		    // Last call
	{
		;// printf("Content has been added to the encoded message. \n");
	}
	else
	{
		error_message += "MsgUpdate failed";
		goto err;
		// HandleError("MsgUpdate failed");
	}

	//--------------------------------------------------------------------
	// Вернем подписанное сообщение или только значение ЭЦП, если установлен признак detached

	if (CryptMsgGetParam(
		hMsg,                      // Handle to the message
		CMSG_CONTENT_PARAM,        // Parameter type
		0,                         // Index
		pbEncodedBlob,             // Pointer to the blob
		&cbEncodedBlob))           // Size of the blob
	{
		;// printf("Message encoded successfully. \n");
	}
	else
	{
		error_message += "MsgGetParam failed";
		goto err;
		// HandleError("MsgGetParam failed");
	}
	//--------------------------------------------------------------------

	*result = new char[cbEncodedBlob];
	memcpy(*result, pbEncodedBlob, cbEncodedBlob);

	//--------------------------------------------------------------------
	// Очистка памяти
err:

	if (pbEncodedBlob)
		free(pbEncodedBlob);
	if (hMsg)
		CryptMsgClose(hMsg);
	// if (hCryptProv) CryptReleaseContext(hCryptProv, 0);

	ReleaseContext(&hCryptProv, &hStoreHandle, &pUserCert);

	if (error_message != "")
	{
		// Show error
		MessageBox(NULL, error_message.c_str(), ("Error Sign"), MB_OK);

		return 0;
	}

	return cbEncodedBlob;
}

// Для проверки ЭЦП публичный ключ отправителя должен быть находиться в личных (!) сертификатах
// Корень консоли > Сертификаты - текущий пользователь > Личное (> Реестр > Сертификаты)
// Потому что hStoreHandle открывает личное хранилище сертификатов

// Следует доработать код и/или искать сертификаты во всех хранилищах

//--------------------------------------------------------------------
// Проверка PKCS#7 Signed


#define MY_STRING_TYPE (CERT_SIMPLE_NAME_STR)

DWORD Verify(char ** result, BYTE* pbEncodedBlob, DWORD cbEncodedBlob)
{
	HCRYPTPROV	hCryptProv = 0;	    // Дескриптор провайдера
	HCERTSTORE	hStoreHandle = NULL;

	PrepareContext(&hCryptProv, &hStoreHandle);

	int res = 0;

	DWORD flags = 0;

	//---------------------------------------------------------------
	// Buffer to hold the name of the subject of a certificate.

	//char pszNameString[NAME_MAX];

	//---------------------------------------------------------------
	// The following variables are used only in the decoding phase.

	HCRYPTMSG hMsg = NULL;
	//HCERTSTORE hStoreHandle;           // certificate store handle
	DWORD cbData = sizeof(DWORD);
	DWORD cbDecoded;
	BYTE *pbDecoded = NULL;
	DWORD cbSignerCertInfo = NULL;
	PCERT_INFO pSignerCertInfo = NULL;
	PCCERT_CONTEXT pSignerCertContext = NULL;

	std::string error_message = "";

	//---------------------------------------------------------------
	// The following code decodes the message and verifies the
	// message signature.  This code would normally be in a
	// stand-alone program that would read the signed and encoded
	// message and its length from a file from an email message,
	// or from some other source.
	// ---------------------------------------------------------------

	//---------------------------------------------------------------
	// Open a message for decoding.

	if (hMsg = CryptMsgOpenToDecode(
		MY_ENCODING_TYPE,      // encoding type
		flags,                 // flags
		0,                     // use the default message type
							   // the message type is 
							   // listed in the message header
		hCryptProv,           // cryptographic provider 
							   // use NULL for the default provider
		NULL,                  // recipient information
		NULL))                 // stream information
	{
		;// printf("The message to decode is open. \n");
	}
	else
	{
		error_message += "OpenToDecode failed";
		goto err;
		//HandleError("OpenToDecode failed");
	}

	//---------------------------------------------------------------
	// Update the message with an encoded BLOB.

	if (CryptMsgUpdate(
		hMsg,                 // handle to the message
		pbEncodedBlob, // pointer to the encoded BLOB
		cbEncodedBlob, // size of the encoded BLOB
		TRUE))                // last call
	{
		;// printf("The encoded BLOB has been added to the message. \n");
	}
	else
	{
		error_message += "Decode MsgUpdate failed";
		goto err;
		// HandleError("Decode MsgUpdate failed");
	}

	//---------------------------------------------------------------
	// Get the number of bytes needed for a buffer
	//  to hold the decoded message.
	// Определение длины подписанных данных

	if (CryptMsgGetParam(
		hMsg,                  // handle to the message
		CMSG_CONTENT_PARAM,    // parameter type
		NULL,                     // index
		NULL,
		&cbDecoded))           // size of the returned information
	{
		;// printf("The message parameter has been acquired. \n");
	}
	else
	{
		error_message += "Decode CMSG_CONTENT_PARAM failed.";
		goto err;
		// HandleError("Decode CMSG_CONTENT_PARAM failed.");
	}

	//---------------------------------------------------------------
	// Allocate memory.

	if (!(pbDecoded = (BYTE *)malloc(cbDecoded)))
	{
		error_message += "Decode memory allocation failed.";
		goto err;
		// HandleError("Decode memory allocation failed.");
	}

	//---------------------------------------------------------------
	// Copy the content to the buffer.
	// Получение подписанных данных

	if (CryptMsgGetParam(
		hMsg,                 // handle to the message
		CMSG_CONTENT_PARAM,   // parameter type
		NULL,                    // index
		pbDecoded,            // address for returned information
		&cbDecoded))          // size of the returned information
	{
		; // printf("The decoded message is =>\n%s\n\n", (LPSTR)pbDecoded);
		//return;
	}
	else
	{
		error_message += "Decode CMSG_CONTENT_PARAM #2 failed";
		goto err;
		// HandleError("Decode CMSG_CONTENT_PARAM #2 failed");
	}

	error_message += "Decode message is \"";
	GetDecodedMessage(error_message, pbDecoded, cbDecoded);
	//result += (char *)pbDecoded;
	error_message += "\"\r\n";

	//---------------------------------------------------------------
	// Verify the signature.
	// First, get the signer CERT_INFO from the message.

	//---------------------------------------------------------------
	// Get the size of memory required for the certificate.

	if (CryptMsgGetParam(
		hMsg,                         // handle to the message
		CMSG_SIGNER_CERT_INFO_PARAM,  // parameter type
		0,                            // index
		NULL,
		&cbSignerCertInfo))           // size of the returned 
									  // information
	{
		;// printf("%d bytes needed for the buffer.\n", cbSignerCertInfo);
	}
	else
	{
		error_message += "Verify SIGNER_CERT_INFO #1 failed.";
		goto err;
		// HandleError("Verify SIGNER_CERT_INFO #1 failed.");
	}

	//---------------------------------------------------------------
	// Allocate memory.

	if (!(pSignerCertInfo = (PCERT_INFO)malloc(cbSignerCertInfo)))
	{
		error_message += "Verify memory allocation failed.";
		goto err;
		// HandleError("Verify memory allocation failed.");
	}

	//---------------------------------------------------------------
	// Get the message certificate information (CERT_INFO structure).

	if (!(CryptMsgGetParam(
		hMsg,                         // handle to the message
		CMSG_SIGNER_CERT_INFO_PARAM,  // parameter type
		0,                            // index
		pSignerCertInfo,              // address for returned 
									  // information
		&cbSignerCertInfo)))          // size of the returned 
									  // information
	{
		error_message += "Verify SIGNER_CERT_INFO #2 failed";
		goto err;
		// HandleError("Verify SIGNER_CERT_INFO #2 failed");
	}

	LPTSTR pszString;
	DWORD cbSize1 = pSignerCertInfo->Issuer.cbData;

	if (!(pszString = (LPTSTR)malloc(cbSize1 * sizeof(TCHAR))))
	{
		error_message += "Memory allocation failed.";
		goto err;
		// HandleError(TEXT("Memory allocation failed."));
	}

	//-----------------------------------------------------------
	//       Call the function again to get the string. 

	cbSize1 = CertNameToStr(
		//pCertContext->dwCertEncodingType,
		MY_ENCODING_TYPE,
		&(pSignerCertInfo->Issuer),
		MY_STRING_TYPE,
		pszString,
		cbSize1);

	error_message += "The message signer is \"";
	error_message += pszString;
	error_message += "\"\r\n";

	//-----------------------------------------------------------
	//  The function CertNameToStr returns the number
	//  of bytes in the string, including the null terminator.
	//  If it returns 1, the name is an empty string.

	if (1 == cbSize1)
	{
		error_message += "Subject name is an empty string.";
		goto err;
		// HandleError(TEXT("Subject name is an empty string."));
	}


	//---------------------------------------------------------------
	// Find the signer's certificate in the store.

	if (pSignerCertContext = CertGetSubjectCertificateFromStore(
		hStoreHandle,       // handle to the store
		MY_ENCODING_TYPE,   // encoding type
		pSignerCertInfo))   // pointer to retrieved CERT_CONTEXT
	{
		/*
		if (CertGetNameString(
			pSignerCertContext,
			CERT_NAME_SIMPLE_DISPLAY_TYPE,
			0,
			NULL,
			pszNameString,
			NAME_MAX) > 1)
		{
			// printf("The message signer is  %s \n", pszNameString);
			result += "The message signer is \"";
			result += pszNameString;
			result += "\"\n";
		}
		else
		{
			result += "Getting the signer's name failed.\n";
			HandleError("Getting the signer's name failed.\n");
		}
		//*/
		/*
		if (CertGetNameString(
			pSignerCertContext,
			CERT_NAME_RDN_TYPE,
			0,
			NULL,
			pszNameString,
			NAME_MAX) > 1)
		{
			// printf("The message signer is %s \n", pszNameString);
			result += "The message signer is \"";
			result += pszNameString;
			result += "\"\r\n";
		}
		else
		{
			error_message += "Getting the signer's name failed.\n";
			goto err;
			// HandleError("Getting the signer's name failed.\n");
		}
		//*/
	}
	else
	{
		error_message += "Verify GetSubjectCert failed\r\n";
		goto err;
		// HandleError("Verify GetSubjectCert failed");
	}

	//---------------------------------------------------------------
	// Use the CERT_INFO from the signer certificate to verify
	// the signature.

	if (CryptMsgControl(
		hMsg,
		0,
		CMSG_CTRL_VERIFY_SIGNATURE,
		pSignerCertContext->pCertInfo))
	{
		error_message += "Verify signature SUCCEEDED\r\n";
	}
	else
	{
		error_message += "Signature was NOT VERIFIED\r\n";
		goto err;
		// HandleError("The signature was not verified. \r\n");
	}

err:
	get_signing_time(error_message, hMsg, 0);

	//---------------------------------------------------------------
	// Clean up.

	if (pbDecoded)
	{
		free(pbDecoded);
	}
	if (pSignerCertInfo)
	{
		free(pSignerCertInfo);
	}
	/*
	if (pSignerCertContext)
	{
		CertFreeCertificateContext(pSignerCertContext);
	}
	if (hStoreHandle)
	{
		CertCloseStore(hStoreHandle, CERT_CLOSE_STORE_FORCE_FLAG);
	}
	//*/
	if (hMsg)
	{
		CryptMsgClose(hMsg);
	}

	ReleaseContext(&hCryptProv, &hStoreHandle, &pSignerCertContext);

	*result = new char[error_message.length()];
	memcpy(*result, error_message.c_str(), error_message.length());
	return error_message.length();
}

//--------------------------------------------------------------------
// Определение времени формирования ЭЦП из сообщения

int get_signing_time(std::string & result, HCRYPTMSG hMsg, int signerIndex)
{
	CHAR SIGNINGTIME[50] = { 0 };

	DWORD		ret = 0;
	PCRYPT_ATTRIBUTES	authAttr = NULL;
	DWORD		authAttr_len = 0;
	DWORD		i = 0;
	PCRYPT_ATTR_BLOB	timeBlob = NULL;
	DWORD		size = 0;
	FILETIME		fileTime;
	SYSTEMTIME		systemTime;

	if (!hMsg)
		return ret;

	ret = CryptMsgGetParam(
		hMsg,							// Handle to the message
		CMSG_SIGNER_AUTH_ATTR_PARAM,    // Parameter type
		signerIndex,                    // Signer Index
		NULL,							// Address for returned info
		&authAttr_len);					// Size of the returned info
	if (ret) {
		;// printf("The attribute (CMSG_SIGNER_AUTH_ATTR_PARAM) has been acquired. Attribute size: %d\n", authAttr_len);
	}
	else
	{
		if (GetLastError() == CRYPT_E_ATTRIBUTES_MISSING) {
			// printf("The attribute CMSG_SIGNER_AUTH_ATTR_PARAM is not included into message.\n");
			result += "The attribute CMSG_SIGNER_AUTH_ATTR_PARAM is not included into message.\r\n";
			ret = 1;
			return ret;
		}
		else
		{
			result += "Decode CMSG_SIGNER_AUTH_ATTR_PARAM failed";
			HandleError("Decode CMSG_SIGNER_AUTH_ATTR_PARAM failed");
		}
	}
	//--------------------------------------------------------------------
	// Резервируем память

	if (authAttr_len) {
		authAttr = (PCRYPT_ATTRIBUTES)malloc(authAttr_len);
		if (!authAttr)
		{
			result += "Decode memory allocation failed";
			HandleError("Decode memory allocation failed");
		}

		//--------------------------------------------------------------------
		// Вернем атрибут

		ret = CryptMsgGetParam(
			hMsg,							// Handle to the message
			CMSG_SIGNER_AUTH_ATTR_PARAM,    // Parameter type
			signerIndex,					// Signer Index
			authAttr,						// Address for returned info
			&authAttr_len);					// Size of the returned info
		if (ret)
		{
			;// printf("The attribute (CMSG_SIGNER_AUTH_ATTR_PARAM) returned. Length is %lu.\n", authAttr_len);
		}
		else
		{
			result += "Decode CMSG_SIGNER_AUTH_ATTR_PARAM #2 failed";
			HandleError("Decode CMSG_SIGNER_AUTH_ATTR_PARAM #2 failed");
		}
	}

	for (i = 0; i < authAttr->cAttr; i++)
	{

		// 1.2.840.113549.1.9.3 - content type attribute "pkcs9 contentType"
		// 1.2.840.113549.1.9.5 - signing time attribute "pkcs9 signingTime"
		// 1.2.840.113549.1.9.4 - message digest attribute "pkcs9 messageDigest"
		if (strcmp(authAttr->rgAttr[i].pszObjId, szOID_RSA_signingTime) == 0 &&
			authAttr->rgAttr[i].cValue)
		{
			timeBlob = (authAttr->rgAttr[i]).rgValue;

			size = sizeof(FILETIME);
			ret = CryptDecodeObject(MY_ENCODING_TYPE,
				szOID_RSA_signingTime,
				timeBlob->pbData,
				timeBlob->cbData,
				0,            // no Flags
				(DWORD*)&fileTime,
				&size);
			if (!ret)
				return ret;

			if (!FileTimeToSystemTime(&fileTime, &systemTime))
				return 0;


			sprintf(SIGNINGTIME, "%04d-%02d-%02d-%02d:%02d:%02d  - is signing time\r\n",
				systemTime.wYear, systemTime.wMonth, systemTime.wDay,
				systemTime.wHour, systemTime.wMinute, systemTime.wSecond);
			result += SIGNINGTIME;
		}
	}
	return ret;
}

//--------------------------------------------------------------------

/*
int get_signing_time(std::string & result, HCRYPTMSG hMsg, int signerIndex)
{
	PCMSG_SIGNER_INFO pSignerInfo = NULL;
	PCMSG_SIGNER_INFO pCounterSignerInfo = NULL;
	DWORD dwSignerInfo;
	CryptMsgGetParam(hMsg,
		CMSG_SIGNER_INFO_PARAM,
		0,
		NULL,
		&dwSignerInfo);
	pSignerInfo = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwSignerInfo);
	CryptMsgGetParam(hMsg,
		CMSG_SIGNER_INFO_PARAM,
		0,
		(PVOID)pSignerInfo,
		&dwSignerInfo);

	BOOL fResult;
	FILETIME lft, ft;
	DWORD dwData;
	BOOL fReturn = FALSE;  	SYSTEMTIME st;
	for (DWORD n = 0; n < pSignerInfo->AuthAttrs.cAttr; n++)
	{
		if (lstrcmpA(szOID_RSA_signingTime,
			pSignerInfo->AuthAttrs.rgAttr[n].pszObjId) == 0)
		{
			dwData = sizeof(ft);
			fResult = CryptDecodeObject(
				MY_ENCODING_TYPE, szOID_RSA_signingTime,
				pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].pbData,
				pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].cbData,
				0,
				(PVOID)&ft,
				&dwData);
			if (!fResult)
			{
				//_tprintf(_T("CryptDecodeObject failed with %x\n"), GetLastError());
				break;
			}
			FileTimeToLocalFileTime(&ft, &lft);
			FileTimeToSystemTime(&lft, &st);
			fReturn = TRUE;
			break;
		}
	}

	CHAR SIGNINGTIME[50] = { 0 };

	sprintf(SIGNINGTIME, "%04d-%02d-%02d-%02d:%02d:%02d  - is signing time\r\n",
		st.wYear, st.wMonth, st.wDay,
		st.wHour, st.wMinute, st.wSecond);
	result += SIGNINGTIME;

	return fResult;
}
//*/