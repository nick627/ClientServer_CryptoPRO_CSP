
// https://cpdn.cryptopro.ru/content/csp36/html/group___hash_example_CreatingHash.html

// Тестовые векторы. ГОСТ Р 34.11-94 с параметрами CryptoPro
// http://gosthash.chat.ru/

#include "utils.h"

//--------------------------------------------------------------------
// Создание хеша из переданных данных.
//--------------------------------------------------------------------

#define GR3411LEN 64

int GetHash(std::string & result, BYTE* hData, DWORD dataLen)
{
	//-------------------------------------------------------------
	// Объявление и инициализация переменных. 
	BOOL bIsReadingFailed = FALSE;
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	BYTE rgbHash[GR3411LEN];
	DWORD cbHash = 0;
	CHAR rgbDigits[] = "0123456789abcdef";
	DWORD i;

	CHAR resultHash[GR3411LEN + 1] = { 0 };

	//--------------------------------------------------------------------
	// Получение дескриптора криптопровайдера.

	if (!CryptAcquireContext(
		&hProv,
		NULL,
		NULL,
		PROV_GOST_2001_DH,
		CRYPT_VERIFYCONTEXT))
	{
		HandleError("CryptAcquireContext failed");
	}

	//--------------------------------------------------------------------
	// Создание пустого объекта функции хеширования.

	if (!CryptCreateHash(hProv, CALG_GR3411, 0, 0, &hHash))
	{
		CryptReleaseContext(hProv, 0);
		HandleError("CryptAcquireContext failed");
	}

	if (!CryptSetHashParam(hHash, HP_OID, (BYTE*)OID_HashVerbaO, 0))
	{
		CryptReleaseContext(hProv, 0);
		HandleError("CryptAcquireContext failed");
	}

	//--------------------------------------------------------------------
	// Хеширование данных.

	if (!CryptHashData(hHash, hData, dataLen, 0))
	{
		CryptReleaseContext(hProv, 0);
		CryptDestroyHash(hHash);
		HandleError("CryptHashData failed");
	}

	//--------------------------------------------------------------------
	// Получение параметра объекта функции хеширования.
	cbHash = GR3411LEN;
	if (!CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
	{
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		HandleError("CryptGetHashParam failed");
	}

	// printf("GR3411 hash is: ");
	for (i = 0; i < cbHash; i++)
	{
		resultHash[2 * i] = rgbDigits[rgbHash[i] >> 4];
		resultHash[2 * i + 1] = rgbDigits[rgbHash[i] & 0xf];
	}

	result = resultHash;

	//--------------------------------------------------------------------
	// Освобождение.
	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);

	return S_OK;
}

//--------------------------------------------------------------------

