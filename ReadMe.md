# ClientServer_CryptoPRO_CSP
Client-Server Application C/C++/WinAPI uses CSP ���������

-----------------------------------------
// ��� CSP (cryptography service provider)
// https://www.cryptopro.ru/products/csp/downloads#latest_csp40r3

> ������� ��������� SCP 4.0.9944 https://www.cryptopro.ru/sites/default/files/private/csp/40/9944/CSPSetup.exe

> CSPSetup.exe (..\Software\CSPSetup.exe)

> �������������� �����

> ������� ����, ��1

> ����������

> ������� ����� ���� ��� "��������� SCP 4.0.9944" https://forum.ruboard.ru/showthread.php/264712-%D0%98%D1%89%D1%83-%D0%BA%D0%BB%D1%8E%D1%87-%D0%BD%D0%B0-%D0%9A%D1%80%D0%B8%D0%BF%D1%82%D0%BE-%D0%9F%D1%80%D0%BE-4-0-%D1%81%D0%B5%D1%80%D0%B2%D0%B5%D1%80%D0%BD%D0%B0%D1%8F/page3

4040A-Q000K-9KAC2-9A6QR-6FCZN

40403-D000Z-8KAC2-8QV3G-53VX4 // valid

4040U-M000Q-UKAC2-U6X29-W8T4G // valid

4040A-Q000K-9KAC2-9A6QR-6FCZN

-----------------------------------------

// ������ ��� ��������, ��� ��������� �����������

// https://www.cryptopro.ru/products/cades/plugin

> ������� ��������� ��� Browser plug-in ������ 2.0 https://www.cryptopro.ru/products/cades/plugin/get_2_0

> cadesplugin.exe (..\Software\cadesplugin.exe)

> ��������� ����������

-----------------------------------------

// ��������� ��������� �����������

// https://www.cryptopro.ru/certsrv/

> �������� ���������� ��������� ��� Browser plug-in � ���������� �������� (Chrome - �������������� �����������->����������)

> ������� https://www.cryptopro.ru/certsrv/certrqma.asp

> ������������ ����������:


> OID = 1.2.643.3.6.0.12 (��������� ��, ���� �������� ����������� 12 �������)

> �������� ���� ��� �������������� (�������������)

> �������� ��� - �������, ��� ����� ������������ ������ 7 ������ ��������

> ������

> ���������� ���� ����������

-----------------------------------------

// �������� �� ��������������� ������������:

// ���������� �������� � "������� ������ �� ����������" �������� ������������

> ����

> �����������

> ������ ������� > ����������� - ������� ������������ > ������� ������ �� ���������� > ������ > �����������

> ��� ������ > �������


// ��� ��������� �����

> ��, �������������� �������� ����

> ���� ������ ������ ����������� - PKCS #12 (.PFX) > �������� �� ����������� ��� ����������� � ���� ������������


// ��� ���������� �����

///���� P7B �������� ������ ����������� � ������ ����������� (������������� CA), �� �� �������� ����

> ���, �� �������������� �������� ����

> �������� Cryptographic Message Syntax - ����������� PKCS #7 (.p7b)

-----------------------------------------

// ������ ������������

// � ����� \cert_privates ��� ����������� � ������� ������


// �������� ���� ��������� ��� ������������ (���������-������) � ��� (���������-������)

// ��������� ���� ��������� ��� ��������� (���������-������) � �������� ��� (���������-������)


// ����������� ������� �������� � "������" �������� ������������

> ����

> �����������

> ������ ������� > ����������� - ������� ������������ > ������ > ������ > �����������


// ������

// (���������� ����������) ��� ���������� �����������

> ������������ ��������� > ������� ������������

> ��������� ��� ����������� � ��������� ��������� > ������

-----------------------------------------

// ������� ����� ���� ������

https://www.cryptopro.ru/sites/default/files/products/csp/20/sample-2-0.zip

-----------------------------------------

// dumpasn1

cmd> dumpasn1.exe file

cmd> dumpasn1.exe -ad file

-----------------------------------------

// Notes

// https://www.cryptopro.ru/products/csp/usage#forintegration

// ��������� CSP ����������� ������������ http://cpdn.cryptopro.ru/default.asp?url=content/csp36/html/Titul.html

// ������ �� �������� ��������� ���������� � ��������� ������ 

http://cpdn.cryptopro.ru/content/csp40/html/group___acquire_example_CreatingKeyContainerExample.html


�� ������� ������� � ���������� �������������, ���������


http://www.justsign.me/verifycpca/VerifyCertificate/

https://docs.microsoft.com/en-us/windows/desktop/seccrypto/example-c-program-signing-encoding-decoding-and-verifying-a-message
