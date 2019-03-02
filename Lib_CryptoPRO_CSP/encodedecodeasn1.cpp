#define _CRT_SECURE_NO_WARNINGS

// http://cpdn.cryptopro.ru/content/csp40/html/group___acquire_example_CodingDataExample.html

#include "utils.h"

//--------------------------------------------------------------------
// Код для закодирования и раскодирования сообщения.
//--------------------------------------------------------------------

//--------------------------------------------------------------------
// Кодирование в формат ASN.1

DWORD EncodeToASN1(
	char ** result,
	BYTE* pbContent,     // Байтовый указатель на сообщение
	DWORD cbContent      // Длина сообщения
)
{
	//-------------------------------------------------------------
	// Объявление и инициализация переменных. Они получают указатель на  
	// содержимое сообщения. Эта программа создает содержимое сообщения 
	// и получает указатель на него. В большинстве случаев, содержимое  
	// сообщения уже где-то существует и указатель на сообщение устанавливается
	// приложением. 

	HCRYPTMSG hMsg;

	DWORD cbEncodedBlob = 0;
	BYTE *pbEncodedBlob = NULL;

	std::string error_message = "";

	//--------------------------------------------------------------------
	//  Начало выполнения. Отображение исходного сообщения. 

	// pbContent = (BYTE*) "Security is our only business";
	// cbContent = (DWORD)(strlen((char *)pbContent) + 1);

	// printf("The original message => %s\n", pbContent);

	//--------------------------------------------------------------------
	// Открытие сообщения для закодирования.

	hMsg = CryptMsgOpenToEncode(
		MY_ENCODING_TYPE,        // Тип закодированного сообщения
		0,                       // Флаги
		CMSG_DATA,               // Тип сообщения
		NULL,                    // Указатель на структуру
		NULL,                    // Внутренний контекст ID объекта
		NULL);                   // Потоковая информация (не используется)

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
	// Обновление сообщения с данными.

	if (CryptMsgUpdate(
		hMsg,         // Дескриптор сообщения
		pbContent,    // Указатель на содержимое
		cbContent,    // Размер содержимого
		TRUE))        // Последний вызов
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
	// Получение размера BLOBа закодированного сообщения.

	if (CryptMsgGetParam(
		hMsg,                    // Дескриптор сообщения
		CMSG_CONTENT_PARAM,      // Тип параметров
		0,                       // Индекс
		NULL,                    // Указатель на BLOB
		&cbEncodedBlob)) {       // Размер BLOBа
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
	// Распределени памяти под закодированный BLOB.

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
	// Получение результирующего сообщения.

	if (CryptMsgGetParam(
		hMsg,                      // Дескриптор сообщения
		CMSG_CONTENT_PARAM,        // Тип параметров
		0,                         // Индекс
		pbEncodedBlob,             // Указатель на BLOB
		&cbEncodedBlob))           // Размер BLOBа
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
	// pbEncodedBlob сейчас указывает на закодированное, подписанное содержимое.

	*result = new char[cbEncodedBlob];
	memcpy(*result, pbEncodedBlob, cbEncodedBlob);
	//--------------------------------------------------------------------
	// Освобождение.
	
err:
	
	if (pbEncodedBlob)
		free(pbEncodedBlob);
	// Закрытие сообщения.
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
// Декодирование из формата ASN.1

DWORD DecodeFromASN1(
	char ** result,
	BYTE* pbEncodedBlob,     // Байтовый указатель на сообщение
	DWORD cbEncodedBlob      // Длина сообщения
)
{
	CHAR * result_message = NULL;

	//--------------------------------------------------------------------
	//  Следующие ниже переменные используются только в фазе раскодирования.

	DWORD cbDecoded = 0;
	BYTE *pbDecoded = NULL;

	//--------------------------------------------------------------------
	// Нижеследующий код осуществляет раскодирование сообщения. 
	// Этот код может быть включен здесь или может быть использован в 
	// автономной программе, если сообщение, подлежащее раскодированию,  
	// и его длина заданы. 
	// BLOB закодированного сообщения и его длина могут быть прочитаны 
	// с дискового файла или могут быть получены из e-mail сообщения или  
	// из других входных данных.

	HCRYPTMSG hMsg;

	//DWORD cbEncodedBlob;
	//BYTE *pbEncodedBlob;

	std::string error_message = "";

	//--------------------------------------------------------------------
	// Открытие сообщения для раскодирования.

	hMsg = CryptMsgOpenToDecode(
		MY_ENCODING_TYPE,      // тип закодированного сообщения.
		0,                     // Флаги.
		0,                     // Поиск данных сообщения.
		0,                     // Криптографический провайдер.
		NULL,                  // Информация издателя.
		NULL);                 // потоковая информация.

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
	// Обновление сообщения с закодированным BLOBом.
	// И pbEncodedBlob, закодированные данные, 
	// и cbEncodedBlob, длина закодированных данных,
	// должны быть доступны. 

	// printf("\nThe length of the encoded message is %d.\n\n", cbEncodedBlob);

	if (CryptMsgUpdate(
		hMsg,                 // Дескриптор сообщения
		pbEncodedBlob,        // Указатель на закодированный BLOB
		cbEncodedBlob,        // Размер закодированного BLOBа
		TRUE))                // Последний вызов
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
	// Получение размера содержимого.

	if (CryptMsgGetParam(
		hMsg,                  // Дескриптор сообщения
		CMSG_CONTENT_PARAM,    // Тип параметров
		0,                     // Индекс
		NULL,                  // Адрес возвращаемой 
							   // информации
		&cbDecoded))           // Размер возвращаемой
							   // информации
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
	// Распределение памяти.

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
	// Получение указателя на содержимое.

	if (CryptMsgGetParam(
		hMsg,                  // Дескриптор сообщения
		CMSG_CONTENT_PARAM,    // Тип параметров
		0,                     // Индекс
		pbDecoded,             // Адрес возвращаемой 
							   // информации
		&cbDecoded))           // Размер возвращаемой 
							   // информации
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
	// Освобождение.
err:

	if (pbDecoded)
		free(pbDecoded);
	// Закрытие сообщения.
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

