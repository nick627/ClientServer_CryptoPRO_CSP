#define _CRT_SECURE_NO_WARNINGS

// Большая часть функций из файлов проекта \Csptest\
// https://www.cryptopro.ru/products/csp/usage#forintegration
// https ://www.cryptopro.ru/sites/default/files/products/csp/20/sample-2-0.zip

#include "utils.h"

#include <iostream>
#include <string>
#include <fstream>



// Хранилище сертификатов.
/// MY = C:\Users\%UserProfile%\Application Data\Microsoft\SystemCertificates\My\Certificates
// https://docs.microsoft.com/en-us/windows/desktop/api/wincrypt/nf-wincrypt-certopensystemstorea
#define CERT_STORE "MY" // "CA"/"MY"/"ROOT"

//----------------------------------------------------------------------

void HandleError(char const *s)
{
	printf("An error occurred in running the program.\n");
	printf("%s\n", s);
	printf("Error number %x\n.", GetLastError());
	printf("Program terminating.\n");
	exit(1);
}

//----------------------------------------------------------------------

void GetDecodedMessage(std::string & result, BYTE *pbDecoded, DWORD cbDecoded)
{
	CHAR * result_message = (CHAR *)malloc(cbDecoded + 1);
	memset(result_message, 0, cbDecoded + 1);
	memcpy(result_message, pbDecoded, cbDecoded);

	result += result_message;

	free(result_message);
}

//----------------------------------------------------------------------
// Чтение файла

int get_file_data_pointer(const char *infile, size_t *len, unsigned char **buffer)
{
	DWORD dwSize;
	HANDLE hFile;
	HANDLE hMap;
	unsigned char *pStart;

	if (!infile || !len || !buffer) {
		fprintf(stderr, "Invalid argument specified\n");
		return 0;
	}
	hFile = CreateFile(infile, GENERIC_READ, 0,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
		NULL);
	if (INVALID_HANDLE_VALUE == hFile) {
		fprintf(stderr, "Unable to open file\n");
		return 0;
	}
	dwSize = GetFileSize(hFile, NULL);
	hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (NULL == hMap) {
		fprintf(stderr, "Unable to create map file\n");
		CloseHandle(hFile);
		return 0;
	}
	pStart = (unsigned char *)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
	if (NULL == pStart) {
		fprintf(stderr, "Unable to map file into memory\n");
		CloseHandle(hMap);
		CloseHandle(hFile);
		return 0;
	}
	CloseHandle(hMap);
	CloseHandle(hFile);
	*len = dwSize;
	*buffer = pStart;
	return 1;
}

//----------------------------------------------------------------------

int release_file_data_pointer(unsigned char *buffer)
{
	if (buffer) UnmapViewOfFile((char *)buffer);
	return 1;
}

//--------------------------------------------------------------------
// Подготовка контекста криптопровайдера и хранилища 

void PrepareContext(HCRYPTPROV_LEGACY* hCryptProv, HCERTSTORE* hStoreHandle)
{
	if (!CryptAcquireContext(
		hCryptProv,  	 	 	// Адрес возврашаемого дескриптора. 
		NULL, 	 				// Используется имя текущего зарегестрированного пользователя. 
		NULL,  	 	 	 	 	// Используется провайдер по умолчанию.   
		PROV_GOST_2001_DH, 	 	// Необходимо для зашифрования и подписи. 
		CRYPT_VERIFYCONTEXT))  	// Никакие флаги не нужны. 
	{
		HandleError("Error: Cryptographic context could not be acquired");
	}

	*hStoreHandle = CertOpenSystemStore(*hCryptProv, CERT_STORE);
	if (!hStoreHandle)
	{
		HandleError("Error: Error getting store handle");
	}
}

//----------------------------------------------------------------------
// Завершение работы с криптопровайдером 

void ReleaseContext(HCRYPTPROV_LEGACY* hCryptProv, HCERTSTORE* hStoreHandle, PCCERT_CONTEXT* pCertContext)
{
	if (*pCertContext)
		if (!CertFreeCertificateContext(*pCertContext))
			;// HandleError("Error: CertFreeCertificateContext");

	if (*hStoreHandle)
		if (!CertCloseStore(*hStoreHandle, CERT_CLOSE_STORE_CHECK_FLAG))
			;// HandleError("Error: CertCloseStore");

	if (*hCryptProv)
		if (!CryptReleaseContext(*hCryptProv, 0))
			;// HandleError("Error: CryptReleaseContext");
}

//----------------------------------------------------------------------

int Read_Opened_Text_From_File(char * path, char ** buffer)
{
	std::ifstream file(path, std::ios_base::binary);
	if (!file.is_open())
	{
		std::cout << "Error: Can not open the file" << std::endl;
		return -1;
	}

	file.seekg(0, std::ios_base::end);
	int fileSize = (int)file.tellg();
	file.seekg(0, std::ios_base::beg);

	if (fileSize > 0)
	{
		*buffer = new char[fileSize];
	}
	else
	{
		std::cout << "Error: The file is empty" << std::endl;
		file.close();
		return -1;
	}

	file.read((char *)*buffer, fileSize);
	file.close();

	std::cout << "Success: The data was read from " << path << std::endl;
	return fileSize;
}

void printfile(char const *namefile, char const *msg, long len)
{
	FILE *file = fopen(namefile, "wb");
	fwrite(msg, len, 1, file);
	printf("%s\n", msg);
	fclose(file);
}
