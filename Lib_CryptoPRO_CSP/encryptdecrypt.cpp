#define _CRT_SECURE_NO_WARNINGS

#include "utils.h"

#define MAX_ADD_SENDERS 64

// ��������� ����� - ����������� � ������� *.p7b 
// (�������� Cryptographic Message Syntax - ����������� PKCS #7 (.p7b))

//----------------------------------------------------------------------
// �������� ������������� ���������

DWORD cryptenc_encrypt(
	char ** result,
	BYTE* pbContent, // ������ ��� ����������
	DWORD cbContent, // �����
	// char *my_certfile, 
	char **recipient_certfile,
	int recipient_cnt,
	char *OID
)
{
	DWORD EncryptAlgSize;

	CRYPT_ALGORITHM_IDENTIFIER EncryptAlgorithm;
	CRYPT_ENCRYPT_MESSAGE_PARA EncryptParams;

	HCRYPTPROV hCryptProv = 0;          // ���������� ����������
	PCCERT_CONTEXT pUserCert = NULL;	// ����������� �����������

	HCERTSTORE	hStoreHandle = NULL;

	//PrepareContext(&hCryptProv, &hStoreHandle);

	DWORD EncryptParamsSize;
	BYTE*    pbEncryptedBlob = NULL;	// ������������� ������
	DWORD    cbEncryptedBlob = 0;		// ����� ������������� ������

	BOOL  should_release_ctx = 0;		// if FALSE DO NOT Release CTX

	PCCERT_CONTEXT pRecipientCerts[MAX_ADD_SENDERS];	// ����������� �����������

	int	    ret = 0;			// ������ ��������
	// DWORD   keytype = 0;
	int	    i;

	std::string error_message = "";

	//--------------------------------------------------------------------
	//  �������������� ��������, ��������� ���� ����������
	/*
	if (my_certfile)
	{
		pUserCert = read_cert_from_file(my_certfile);
		if (!pUserCert) {
			printf("Cannot find User certificate: %s\n", my_certfile);
			goto err;
		}
		// ��������� �� ��������� ����������� ���������� ������� ���������� �����
		// � ��������� ��������� ���������.
		// ��� ����������� ���������� ������������ ������� CryptAcquireCertificatePrivateKey,
		// ���� ��� ������������ � crypt32.dll. ����� ������������ ����� ����� �� ����������� � �����������.
		// ret = CryptAcquireProvider("my", pUserCert, &hCryptProv, &keytype, &should_release_ctx);
		// ��������� ��������� �����
		ret = CryptAcquireCertificatePrivateKey(pUserCert, 0, NULL, &hCryptProv, &keytype, &should_release_ctx);
		if (ret) {
			printf("A CSP has been acquired. \n");
		}
		else {
			HandleError("Cryptographic context could not be acquired.");
		}
	}
	else {
		fprintf(stderr, "No user cert specified. Cryptocontext will be opened automaticaly.\n");
	}
	//*/
	//--------------------------------------------------------------------
	//  ������ ����������� �����������

	for (i = 0; i < recipient_cnt; i++) {
		PCCERT_CONTEXT tmp;
		tmp = read_cert_from_file((char*)recipient_certfile[i]);
		if (!tmp)
		{
			error_message += "Cannot read recipient certfile.";
			goto err;
			// HandleError("Cannot read recipient certfile.");
		}


		pRecipientCerts[i] = tmp;
	}

	//--------------------------------------------------------------------
	// �������������� ��������� �������� ��������� 

	EncryptAlgSize = sizeof(CRYPT_ALGORITHM_IDENTIFIER);
	memset(&EncryptAlgorithm, 0, EncryptAlgSize);

	//--------------------------------------------------------------------
	// ������������� �������� ���������� ������

	EncryptAlgorithm.pszObjId = OID;

	//--------------------------------------------------------------------
	// �������������� ��������� ��������� CRYPT_ENCRYPT_MESSAGE_PARA 

	EncryptParamsSize = sizeof(EncryptParams);
	memset(&EncryptParams, 0, EncryptParamsSize);
	EncryptParams.cbSize = EncryptParamsSize;

	EncryptParams.dwMsgEncodingType = MY_ENCODING_TYPE;

	EncryptParams.hCryptProv = hCryptProv;
	EncryptParams.ContentEncryptionAlgorithm = EncryptAlgorithm;

	//--------------------------------------------------------------------
	// ����� CryptEncryptMessage ��� ����������� ����� ����������� ������

	if (CryptEncryptMessage(
		&EncryptParams,
		recipient_cnt,
		pRecipientCerts,
		pbContent,
		cbContent,
		NULL,
		&cbEncryptedBlob))
	{
		;// printf("The encrypted message is %d bytes. \n", cbEncryptedBlob);
	}
	else
	{
		error_message += "Getting EncrypBlob size failed.";
		goto err;
		// HandleError("Getting EncrypBlob size failed.");
	}
	//--------------------------------------------------------------------
	// ����������� ������ ��� ����������� ������

	pbEncryptedBlob = (BYTE*)malloc(cbEncryptedBlob);
	if (pbEncryptedBlob)
		;// printf("Memory has been allocated for the encrypted blob. \n");
	else
	{
		error_message += "Memory allocation error while encrypting.";
		goto err;
		// HandleError("Memory allocation error while encrypting.");
	}

	//--------------------------------------------------------------------
	// ����� CryptEncryptMessage ��� ���������� ������

	ret = CryptEncryptMessage(
		&EncryptParams,
		recipient_cnt,
		pRecipientCerts,
		pbContent,
		cbContent,
		pbEncryptedBlob,
		&cbEncryptedBlob);

	if (ret) {
		;// printf("File has been encrypted with alg: %s\n", OID);
	}
	else
	{
		error_message += "Encryption failed.";
		goto err;
		// HandleError("Encryption failed.");
	}

	if (ret) {
		// ret = write_file(out_filename, cbEncryptedBlob, pbEncryptedBlob);
		*result = new char[cbEncryptedBlob];
		memcpy(*result, pbEncryptedBlob, cbEncryptedBlob);
	}
	//--------------------------------------------------------------------
	// ������� ������

	for (i = 0; i < recipient_cnt; i++) {
		CertFreeCertificateContext(pRecipientCerts[i]);
	}

err:

	if (hCryptProv)
	{
		// CryptReleaseContext(hCryptProv, 0);
		// printf("The CSP has been released. \n");
		ReleaseContext(&hCryptProv, NULL, &pUserCert);
	}

	if (pbEncryptedBlob)
		free(pbEncryptedBlob);

	if (error_message != "")
	{
		// Show error
		MessageBox(NULL, error_message.c_str(), ("Error Encrypt"), MB_OK);

		return 0;
	}

	return cbEncryptedBlob;
}

// ��� ������������� ��������� ���� ����������� ������ ���� ���������� � ������ (!) ������������
// ������ ������� > ����������� - ������� ������������ > ������ (> ������ > �����������)
// ������ ��� hStoreHandle ��������� ������ ��������� ������������

// ������� ���������� ��� �/��� ������ ����������� �� ���� ����������

//--------------------------------------------------------------------
// ������������� ���������

DWORD cryptenc_decrypt(char ** result,
	BYTE* pbEncryptedBlob,
	DWORD cbEncryptedBlob
)
{
	HCRYPTPROV	hCryptProv = 0;	    // ���������� ����������
	HCERTSTORE	hStoreHandle = NULL;
	PCCERT_CONTEXT pUserCert = NULL;	// ����������� �����������

	PrepareContext(&hCryptProv, &hStoreHandle);

	DWORD cbDecryptedMessage;
	CRYPT_DECRYPT_MESSAGE_PARA	decryptParams;
	BYTE*  pbDecryptedMessage = NULL;

	// ��������� ��������� �� ������������� ���������, pbEncryptedBlob,  	
	// � ��� �����, cbEncryptedBlob. � ���� ������� ��� ��������������� 
	// ��� ��������� ��������� �  CSP � ������������ ��������� ���������. 

	// ������������� ��������� CRYPT_DECRYPT_MESSAGE_PARA.  	
	memset(&decryptParams, 0, sizeof(CRYPT_DECRYPT_MESSAGE_PARA));
	decryptParams.cbSize = sizeof(CRYPT_DECRYPT_MESSAGE_PARA);
	decryptParams.dwMsgAndCertEncodingType = MY_ENCODING_TYPE;
	decryptParams.cCertStore = 1;
	decryptParams.rghCertStore = &hStoreHandle;

	std::string error_message = "";

	//  ����� ������� CryptDecryptMessage ��� ��������� ������������� ������� ������. 
	if (!CryptDecryptMessage(
		&decryptParams,
		pbEncryptedBlob,
		cbEncryptedBlob,
		NULL,
		&cbDecryptedMessage,
		NULL))
	{
		error_message += "Error getting decrypted message size";
		goto err;
		// HandleError("Error getting decrypted message size");
	}

	// ��������� ������ ��� ������������ �������������� ������.  	
	pbDecryptedMessage = (BYTE*)malloc(cbDecryptedMessage);
	if (!pbDecryptedMessage)
	{
		free(pbDecryptedMessage);
		error_message += "Memory allocation error while decrypting";
		goto err;
		// HandleError("Memory allocation error while decrypting");
	}

	// ����� ������� CryptDecryptMessage ��� ������������� ������. 
	if (!CryptDecryptMessage(
		&decryptParams,
		pbEncryptedBlob,
		cbEncryptedBlob,
		pbDecryptedMessage,
		&cbDecryptedMessage,
		NULL))
	{
		free(pbDecryptedMessage);
		error_message += "Error decrypting the message";
		goto err;
		// HandleError("Error decrypting the message");
	}

	*result = new char[cbDecryptedMessage];
	memcpy(*result, pbDecryptedMessage, cbDecryptedMessage);

	//GetDecodedMessage(result, pbDecryptedMessage, cbDecryptedMessage);

	free(pbDecryptedMessage);

err:
	if (error_message != "")
	{
		*result = new char[error_message.length()];
		memcpy(*result, error_message.c_str(), error_message.length());
		return error_message.length();
	}

	return cbDecryptedMessage;
}

//--------------------------------------------------------------------







///////////////////////////////
//delete
int cryptenc_decrypt____(
	std::string & result,
	BYTE* pbEncodedBlob,
	DWORD cbEncodedBlob
	//char *my_certfile
)
{
	char *my_certfile = (char *)"win10.p7b";

	//*
	PCCERT_CONTEXT pUserCert = NULL;	// ���������� ����������
	HCERTSTORE CertStoreArray[1];	// ������ ������������ ������������



	//BYTE *tbdec = NULL;	// ����������� ������
	//size_t tbdec_len = 0;	// �����

	BYTE *pbDecryptedMessage = NULL;	// �������������� ������
	DWORD cbDecryptedMessage = 0;	// �����

	int	    ret = 1;

	HCERTSTORE mem = NULL;		// ���������� ���������� ����������� ������������ � ������

								//--------------------------------------------------------------------
								//  ������ ���� ��� �������������

	//ret = get_file_data_pointer(in_filename, &tbdec_len, &tbdec);
	if (!ret)
		HandleError("Cannot read input file.");

	//--------------------------------------------------------------------
	//  ������ ����������, ������� ����� �������������� ��� �������������.

	pUserCert = read_cert_from_file(my_certfile);
	if (!pUserCert) {
		HandleError("Cannot find User certificate");
	}

	//--------------------------------------------------------------------
	//   ������� �������������� ������ � �������������� �����������
	//   ������� ��������� ���������� � ������ � ������� ���� ���������� ����������

	mem = CertOpenStore(CERT_STORE_PROV_MEMORY, MY_ENCODING_TYPE, 0, CERT_STORE_CREATE_NEW_FLAG, NULL);
	if (!mem)
		HandleError("Cannot create temporary store in memory.");

	ret = CertAddCertificateContextToStore(mem, pUserCert, CERT_STORE_ADD_ALWAYS, NULL);
	if (!ret)
		HandleError("Cannot add certificate to store.");

	CertStoreArray[0] = mem;
	//*/

	/*
	HCRYPTPROV	hCryptProv = 0;	    // ���������� ����������
	HCERTSTORE	hStoreHandle = NULL;
	PCCERT_CONTEXT pUserCert = NULL;	// ����������� �����������

	PrepareContext(&hCryptProv, &hStoreHandle);


	BYTE *pbDecryptedMessage = NULL;	// �������������� ������
	DWORD cbDecryptedMessage = 0;	// �����


	DWORD EncryptAlgSize;

	CRYPT_ALGORITHM_IDENTIFIER EncryptAlgorithm;
	CRYPT_ENCRYPT_MESSAGE_PARA EncryptParams;


	DWORD EncryptParamsSize;
	BYTE*    pbEncryptedBlob = NULL;	// ������������� ������
	DWORD    cbEncryptedBlob = 0;		// ����� ������������� ������

	BOOL  should_release_ctx = 0;		// if FALSE DO NOT Release CTX

	int	    ret = 0;			// ������ ��������
	DWORD   keytype = 0;
	int	    i;
	//*/



	CRYPT_DECRYPT_MESSAGE_PARA  DecryptParams;
	//--------------------------------------------------------------------
	//   ������������� ��������� CRYPT_DECRYPT_MESSAGE_PARA

	memset(&DecryptParams, 0, sizeof(CRYPT_DECRYPT_MESSAGE_PARA));
	DecryptParams.cbSize = sizeof(CRYPT_DECRYPT_MESSAGE_PARA);

	DecryptParams.dwMsgAndCertEncodingType = MY_ENCODING_TYPE;

	DecryptParams.cCertStore = 1;
	DecryptParams.rghCertStore = CertStoreArray;


	//--------------------------------------------------------------------
	//  �������������� ��������, ��������� ���� ����������
	/*
	if (my_certfile)
	{
		pUserCert = read_cert_from_file(my_certfile);
		if (!pUserCert) {
			printf("Cannot find User certificate: %s\n", my_certfile);
			exit(0);
		}
		// ��������� �� ��������� ����������� ���������� ������� ���������� �����
		// � ��������� ��������� ���������.
		// ��� ����������� ���������� ������������ ������� CryptAcquireCertificatePrivateKey,
		// ���� ��� ������������ � crypt32.dll. ����� ������������ ����� ����� �� ����������� � �����������.
		// ret = CryptAcquireProvider("my", pUserCert, &hCryptProv, &keytype, &should_release_ctx);
		// ��������� ��������� �����
		ret = CryptAcquireCertificatePrivateKey(
			pUserCert,
			0,
			NULL,
			&hCryptProv,
			&keytype,
			&should_release_ctx);

		if (ret) {
			printf("A CSP has been acquired. \n");
		}
		else {
			HandleError("Cryptographic context could not be acquired.");
		}
	}
	else {
		fprintf(stderr, "No user cert specified. Cryptocontext will be opened automaticaly.\n");
	}
	//*/

	//--------------------------------------------------------------------
	// ����������� ������ ��� �������������� ������ �������.
	// ��� ��������� ��������� ������������������.
	/*
	cbDecryptedMessage = cbEncodedBlob;
	pbDecryptedMessage = (BYTE*)malloc(cbDecryptedMessage);

	if (NULL == pbDecryptedMessage)
		HandleError("Memory allocation error while decrypting");
	*/
	/*--------------------------------------------------------------------*/
	/*  �������������� ��������� */

	ret = CryptDecryptMessage(
		&DecryptParams,
		pbEncodedBlob,
		cbEncodedBlob,
		NULL,
		&cbDecryptedMessage,
		NULL);

	if (!ret)
	{
		/* ���� �������� ������������ ������ ��� �������������� ������*/
		/* ����������� �� ��� ���*/
		if (GetLastError() != ERROR_MORE_DATA)
			HandleError("Error decrypting message.");
	}

	//free(pbDecryptedMessage);
	pbDecryptedMessage = (BYTE*)malloc(cbDecryptedMessage);

	if (NULL == pbDecryptedMessage)
		HandleError("Memory allocation error while decrypting");
	/*--------------------------------------------------------------------*/
	/* ��������� ����� �������, ���� ��������� ������*/

	ret = CryptDecryptMessage(
		&DecryptParams,
		pbEncodedBlob,
		cbEncodedBlob,
		pbDecryptedMessage,
		&cbDecryptedMessage,
		NULL);

	if (!ret)
		HandleError("Error decrypting message.");

	// printf("Message Decrypted Successfully.\n");
	/*
	if (out_filename)
		ret = write_file(out_filename, cbDecryptedMessage, pbDecryptedMessage);
	//*/
	GetDecodedMessage(result, pbDecryptedMessage, cbDecryptedMessage);

	/*--------------------------------------------------------------------*/
	/* ������� ������*/

	ReleaseContext(NULL, NULL, &pUserCert);

	//release_file_data_pointer(tbdec);
	if (pbDecryptedMessage) free(pbDecryptedMessage);

	/*
	if (mem)
		CertCloseStore(mem, 0);
	//*/
	return ret;

}
/*
  //----------------------------------------------------------------------------
  // ��������� ����� �� CERT_NAME_BLOB
void GetCertDName(PCERT_NAME_BLOB pNameBlob, char **pszName) 
{
	DWORD       cbName;

	cbName = CertNameToStr(
		X509_ASN_ENCODING, pNameBlob,
		CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
		NULL, 0);
	if (cbName <= 1)
		HandleError("CertNameToStr(NULL)");

	*pszName = (char *)malloc(cbName * sizeof(char));
	if (!*pszName)
		HandleError("Out of memory.");

	cbName = CertNameToStr(
		X509_ASN_ENCODING, pNameBlob,
		CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
		*pszName, cbName);
	if (cbName <= 1)
		HandleError("CertNameToStr(pbData)");
}

// ����� ������� 
//*/