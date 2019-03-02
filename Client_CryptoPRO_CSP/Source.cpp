#define _CRT_SECURE_NO_WARNINGS

#include "utils.h"


#define CLIENT

int main()
{
#ifdef CLIENT
	// ��������� ��� ����������, �������, ���������� ����
	std::string test = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";


	// ���������� ��� �������
	std::string pathcert = "C:\\Users\\Nick\\Desktop\\certnick.p7b";


	// ��������� ����� ��� ����������
	const char *recipient[] = {
		/*
		"C:\\Users\\Nick\\Desktop\\certnick.p7b",
		"C:\\Users\\Nick\\Desktop\\other.p7b",
		"C:\\Users\\ibks\\Desktop\\wintest.p7b"
		//*/
		"..\\cert_public\\certnick.p7b",
		"..\\cert_public\\win10.p7b"
	};
#endif


	// ���������� � ������ ���������� � ����
	char * encodetext = nullptr;
	DWORD lenencodetext = NULL;
#ifdef CLIENT
	lenencodetext = cryptenc_encrypt(
		&encodetext,
		(BYTE *)test.c_str(),
		test.length(),
		(char **)recipient,
		//1,
		2,
		(char *)szOID_CP_GOST_28147
	);
	printfile("testencryt.txt", encodetext, lenencodetext);


	//#elif SERVER
	// ������������� ��������� �� ����� � ��� ������
	lenencodetext = Read_Opened_Text_From_File((char *)"testencryt.txt", &encodetext);
	std::string decodetext;
	cryptenc_decrypt(decodetext, (BYTE *)(char *)encodetext, lenencodetext);
	printf("decode - \n%s\n\n", decodetext.c_str());
#endif

	// ���������� ��������� � ������ ���������� � ����
	char * encodesigntext = nullptr;
	DWORD lenencodesigntext = NULL;
#ifdef CLIENT
	lenencodesigntext = Sign(
		&encodesigntext,
		(BYTE *)test.c_str(),
		test.length(),
		(char *)pathcert.c_str(),
		0,
		0
	);
	printfile("testsign.txt", encodesigntext, lenencodesigntext);


#elif SERVER
	// �������� ������� �� ����� � ������ ������ ������������ ���������
	lenencodesigntext = Read_Opened_Text_From_File((char *)"testsign.txt", &encodesigntext);
	std::string decodesigntext;
	Verify(decodesigntext, (BYTE *)(char *)encodesigntext, lenencodesigntext);
	printf("decodesign - \n%s\n\n", decodesigntext.c_str());
#endif	


#ifdef CLIENT
	// ���������� ����
	std::string hashres;
	GetHash(hashres, (BYTE *)test.c_str(), test.length());


	test = hashres;
#endif

	// ����������� ������ � ����� ASN.1 � �� ������ � ����
	char * encodeasntext = nullptr;
	DWORD lenencodeasntext = 0;
#ifdef CLIENT	
	lenencodeasntext = EncodeToASN1(&encodeasntext, (BYTE *)test.c_str(), test.length());
	printfile("testasn.txt", encodeasntext, lenencodeasntext);


#elif SERVER
	// ������������� ������ �� ����� � ������ �� � ����
	lenencodeasntext = Read_Opened_Text_From_File((char *)"testasn.txt", &encodeasntext);
	std::string decodeasntext;
	DecodeFromASN1(decodeasntext, (BYTE *)(char *)encodeasntext, lenencodeasntext);
	printfile("testdeasn.txt", decodeasntext.c_str(), decodeasntext.length());
#endif


	delete[] encodetext;
	delete[] encodeasntext;
	delete[] encodesigntext;


	return 0;
}
