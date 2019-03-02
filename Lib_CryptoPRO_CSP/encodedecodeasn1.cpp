#define _CRT_SECURE_NO_WARNINGS

// http://cpdn.cryptopro.ru/content/csp40/html/group___acquire_example_CodingDataExample.html

#include "utils.h"

//--------------------------------------------------------------------
// ��� ��� ������������� � �������������� ���������.
//--------------------------------------------------------------------

//--------------------------------------------------------------------
// ����������� � ������ ASN.1

DWORD EncodeToASN1(
	char ** result,
	BYTE* pbContent,     // �������� ��������� �� ���������
	DWORD cbContent      // ����� ���������
)
{
	//-------------------------------------------------------------
	// ���������� � ������������� ����������. ��� �������� ��������� ��  
	// ���������� ���������. ��� ��������� ������� ���������� ��������� 
	// � �������� ��������� �� ����. � ����������� �������, ����������  
	// ��������� ��� ���-�� ���������� � ��������� �� ��������� ���������������
	// �����������. 

	HCRYPTMSG hMsg;

	DWORD cbEncodedBlob = 0;
	BYTE *pbEncodedBlob = NULL;

	std::string error_message = "";

	//--------------------------------------------------------------------
	//  ������ ����������. ����������� ��������� ���������. 

	// pbContent = (BYTE*) "Security is our only business";
	// cbContent = (DWORD)(strlen((char *)pbContent) + 1);

	// printf("The original message => %s\n", pbContent);

	//--------------------------------------------------------------------
	// �������� ��������� ��� �������������.

	hMsg = CryptMsgOpenToEncode(
		MY_ENCODING_TYPE,        // ��� ��������������� ���������
		0,                       // �����
		CMSG_DATA,               // ��� ���������
		NULL,                    // ��������� �� ���������
		NULL,                    // ���������� �������� ID �������
		NULL);                   // ��������� ���������� (�� ������������)

	if (hMsg)
	{
		// printf("The message to be encoded has been opened. \n");
	}
	else
	{
		error_message += "OpenToEncode failed";
		goto err;
		// HandleError("OpenToEncode failed");
	}
	//--------------------------------------------------------------------
	// ���������� ��������� � �������.

	if (CryptMsgUpdate(
		hMsg,         // ���������� ���������
		pbContent,    // ��������� �� ����������
		cbContent,    // ������ �����������
		TRUE))        // ��������� �����
	{
		// printf("Content has been added to the encoded message. \n");
	}
	else
	{
		error_message += "MsgUpdate failed";
		goto err;
		// HandleError("MsgUpdate failed");
	}
	//--------------------------------------------------------------------
	// ��������� ������� BLOB� ��������������� ���������.

	if (CryptMsgGetParam(
		hMsg,                    // ���������� ���������
		CMSG_CONTENT_PARAM,      // ��� ����������
		0,                       // ������
		NULL,                    // ��������� �� BLOB
		&cbEncodedBlob)) {       // ������ BLOB�
		if (cbEncodedBlob) {
			// printf("The length of the data has been calculated. \n");
		}
		else {
			error_message += "Getting cbEncodedBlob length failed";
			goto err;
			// HandleError("Getting cbEncodedBlob length failed");
		}
	}
	else {
		error_message += "Getting cbEncodedBlob length failed";
		goto err;
		// HandleError("Getting cbEncodedBlob length failed");
	}
	//--------------------------------------------------------------------
	// ������������ ������ ��� �������������� BLOB.

	pbEncodedBlob = (BYTE *)malloc(cbEncodedBlob);

	if (pbEncodedBlob)
	{
		// printf("Memory has been allocated for the signed message. \n");
	}
	else
	{
		error_message += "Memory allocation failed";
		goto err;
		// HandleError("Memory allocation failed");
	}

	//--------------------------------------------------------------------
	// ��������� ��������������� ���������.

	if (CryptMsgGetParam(
		hMsg,                      // ���������� ���������
		CMSG_CONTENT_PARAM,        // ��� ����������
		0,                         // ������
		pbEncodedBlob,             // ��������� �� BLOB
		&cbEncodedBlob))           // ������ BLOB�
	{
		// printf("Message encoded successfully. \n");
	}
	else
	{
		error_message += "MsgGetParam failed";
		goto err;
		// HandleError("MsgGetParam failed");
	}
	//--------------------------------------------------------------------
	// pbEncodedBlob ������ ��������� �� ��������������, ����������� ����������.

	*result = new char[cbEncodedBlob];
	memcpy(*result, pbEncodedBlob, cbEncodedBlob);
	//--------------------------------------------------------------------
	// ������������.
	
err:
	
	if (pbEncodedBlob)
		free(pbEncodedBlob);
	// �������� ���������.
	if (hMsg)
		CryptMsgClose(hMsg);

	if (error_message != "")
	{
		// Show error
		MessageBox(NULL, error_message.c_str(), ("Error Encode To ASN.1"), MB_OK);

		return 0;
	}

	return cbEncodedBlob;
}

//--------------------------------------------------------------------
// ������������� �� ������� ASN.1

DWORD DecodeFromASN1(
	char ** result,
	BYTE* pbEncodedBlob,     // �������� ��������� �� ���������
	DWORD cbEncodedBlob      // ����� ���������
)
{
	CHAR * result_message = NULL;

	//--------------------------------------------------------------------
	//  ��������� ���� ���������� ������������ ������ � ���� ��������������.

	DWORD cbDecoded = 0;
	BYTE *pbDecoded = NULL;

	//--------------------------------------------------------------------
	// ������������� ��� ������������ �������������� ���������. 
	// ���� ��� ����� ���� ������� ����� ��� ����� ���� ����������� � 
	// ���������� ���������, ���� ���������, ���������� ��������������,  
	// � ��� ����� ������. 
	// BLOB ��������������� ��������� � ��� ����� ����� ���� ��������� 
	// � ��������� ����� ��� ����� ���� �������� �� e-mail ��������� ���  
	// �� ������ ������� ������.

	HCRYPTMSG hMsg;

	//DWORD cbEncodedBlob;
	//BYTE *pbEncodedBlob;

	std::string error_message = "";

	//--------------------------------------------------------------------
	// �������� ��������� ��� ��������������.

	hMsg = CryptMsgOpenToDecode(
		MY_ENCODING_TYPE,      // ��� ��������������� ���������.
		0,                     // �����.
		0,                     // ����� ������ ���������.
		0,                     // ����������������� ���������.
		NULL,                  // ���������� ��������.
		NULL);                 // ��������� ����������.

	if (hMsg)
	{
		// printf("The message to decode is open. \n");
	}
	else
	{
		error_message += "OpenToDecode failed";
		goto err;
		// HandleError("OpenToDecode failed");
	}
	//--------------------------------------------------------------------
	// ���������� ��������� � �������������� BLOB��.
	// � pbEncodedBlob, �������������� ������, 
	// � cbEncodedBlob, ����� �������������� ������,
	// ������ ���� ��������. 

	// printf("\nThe length of the encoded message is %d.\n\n", cbEncodedBlob);

	if (CryptMsgUpdate(
		hMsg,                 // ���������� ���������
		pbEncodedBlob,        // ��������� �� �������������� BLOB
		cbEncodedBlob,        // ������ ��������������� BLOB�
		TRUE))                // ��������� �����
	{
		// printf("The encoded BLOB has been added to the message. \n");
	}
	else
	{
		error_message += "Decode MsgUpdate failed";
		goto err;
		// HandleError("Decode MsgUpdate failed");
	}
	//--------------------------------------------------------------------
	// ��������� ������� �����������.

	if (CryptMsgGetParam(
		hMsg,                  // ���������� ���������
		CMSG_CONTENT_PARAM,    // ��� ����������
		0,                     // ������
		NULL,                  // ����� ������������ 
							   // ����������
		&cbDecoded))           // ������ ������������
							   // ����������
	{
		// printf("The decoded message size is %d. \n", cbDecoded);
	}
	else
	{
		error_message += "Decode CMSG_CONTENT_PARAM failed";
		goto err;
		// HandleError("Decode CMSG_CONTENT_PARAM failed");
	}
	//--------------------------------------------------------------------
	// ������������� ������.

	pbDecoded = (BYTE *)malloc(cbDecoded);

	if (pbDecoded)
	{
		// printf("Memory has been allocated for the decoded message.\n");
	}
	else
	{
		error_message += "Decoding memory allocation failed.";
		goto err;
		// HandleError("Decoding memory allocation failed.");
	}
	//--------------------------------------------------------------------
	// ��������� ��������� �� ����������.

	if (CryptMsgGetParam(
		hMsg,                  // ���������� ���������
		CMSG_CONTENT_PARAM,    // ��� ����������
		0,                     // ������
		pbDecoded,             // ����� ������������ 
							   // ����������
		&cbDecoded))           // ������ ������������ 
							   // ����������
	{
		// printf("The message is %s.\n", (LPSTR)pbDecoded);
	}
	else
	{
		error_message += "Decode CMSG_CONTENT_PARAM #2 failed";
		goto err;
		// HandleError("Decode CMSG_CONTENT_PARAM #2 failed");
	}

	//--------------------------------------------------------------------

	*result = new char[cbDecoded];
	memcpy(*result, pbDecoded, cbDecoded);
	
	//--------------------------------------------------------------------
	// ������������.
err:

	if (pbDecoded)
		free(pbDecoded);
	// �������� ���������.
	if (hMsg)
		CryptMsgClose(hMsg);

	// printf("This program ran to completion without error. \n");

	if (error_message != "")
	{
		*result = new char[error_message.length()];
		memcpy(*result, error_message.c_str(), error_message.length());
		return error_message.length();
	}

	return cbDecoded;
}

//--------------------------------------------------------------------

