#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <windows.h>
#include <Windowsx.h>
#include <commctrl.h>

#include <atlstr.h>

#include <string>
#include <vector>

#include "client_resource.h"
#include "clientgui_headers.h"

#include "utils.h"

#pragma comment (lib, "ws2_32.lib")
#pragma warning(disable : 4996)
#pragma comment(lib, "mswsock.lib")

#define WM_SOCKET WM_USER + 100

//----------------------------------------------------------------------

void reset_controls(HWND hWnd)
{	
	Button_Enable(GetDlgItem(hWnd, IDC_IP_ADDRESS), TRUE);
	Edit_SetReadOnly(GetDlgItem(hWnd, IDC_PORT), FALSE);

	Button_Enable(GetDlgItem(hWnd, IDC_CONNECT), TRUE);
	Button_Enable(GetDlgItem(hWnd, IDC_DISCONNECT), FALSE);

	Button_Enable(GetDlgItem(hWnd, IDC_CHOOSE_CERT), FALSE);

	Button_Enable(GetDlgItem(hWnd, IDC_CHOOSE_SERV_CERT), FALSE);

	Button_Enable(GetDlgItem(hWnd, IDC_PRE_SERVER), FALSE);
	Button_Enable(GetDlgItem(hWnd, IDC_SIGN), FALSE);
	Button_Enable(GetDlgItem(hWnd, IDC_ENCRYPT), FALSE);
	Button_Enable(GetDlgItem(hWnd, IDC_HASH), FALSE);
}

//----------------------------------------------------------------------

void end_connection()
{
#define SD_SEND 1
	shutdown(sock, SD_SEND);
	//shutdown(sock, 1);
	closesocket(sock);
	WSACleanup();
}

//----------------------------------------------------------------------

void init_dll(HWND hWnd)
{
	WSADATA wsa;

	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
	{
		MessageBox(NULL, TEXT("Failed to initialize ws2_32.dll"), TEXT("Error"), MB_OK | MB_ICONERROR);
		EndDialog(hWnd, TRUE);
	}
}

//----------------------------------------------------------------------

void init_connection(HWND hWnd)
{
	sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (sock == INVALID_SOCKET)
	{
		char Message[256] = "socket() : ";
		char error_code[50];

		itoa(WSAGetLastError(), error_code, 10);
		strcat(Message, error_code);
		MessageBox(NULL, Message, TEXT("Error"), MB_OK | MB_ICONERROR);
		EndDialog(hWnd, TRUE);
	}

	if (WSAAsyncSelect(sock, hWnd, WM_SOCKET, (FD_CLOSE | FD_READ | FD_CONNECT)) != 0)
	{
		MessageBox(hWnd, TEXT("WSAAsyncSelect() Failed"), TEXT("Error"), MB_OK);
	}

	SOCKADDR_IN sin = { 0 };
	// Get ip address from ip control
	SendDlgItemMessage(hWnd, IDC_IP_ADDRESS, IPM_GETADDRESS, 0, reinterpret_cast<LPARAM>(&ip));

	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.s_addr = htonl(ip);

	connect(sock, (SOCKADDR*)&sin, sizeof(sin));
}

//----------------------------------------------------------------------

BOOL myCreateOpenFile(HWND hwnd, std::string & filename)
{
	OPENFILENAMEW ofn = { 0 };
	WCHAR szFile[260];
	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = hwnd;
	ofn.lpstrFile = szFile;
	ofn.lpstrFile[0] = '\0';
	ofn.nMaxFile = sizeof(szFile);
	//USES_CONVERSION;
	//ofn.lpstrFilter = L"All Files (*.*)\0*.*\0";
	ofn.lpstrFilter = L"Certificates PKCS #7 (*.p7b)\0*.p7b\0";
	ofn.nFilterIndex = 1;
	ofn.lpstrFileTitle = NULL;
	ofn.nMaxFileTitle = 0;
	ofn.lpstrInitialDir = NULL;
	ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

	if (!GetOpenFileNameW(&ofn))
		return FALSE;
	//wcscpy(filename, ofn.lpstrFile);
	filename = CW2A(ofn.lpstrFile);
	return TRUE;
}

//----------------------------------------------------------------------

void toClipboard(HWND hwnd, const std::string &s)
{
	OpenClipboard(hwnd);
	EmptyClipboard();

	HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, s.size() + 1);

	if (!hg)
	{
		CloseClipboard();
		return;
	}

	memcpy(GlobalLock(hg), s.c_str(), s.size() + 1);
	GlobalUnlock(hg);
	SetClipboardData(CF_TEXT, hg);

	CloseClipboard();
	GlobalFree(hg);
}

//----------------------------------------------------------------------

int GetDataFromBox(HWND hWnd, char ** buffer, int Window)
{
	int n = GetWindowTextLength(GetDlgItem(hWnd, Window));
	if (n == 0)
	{
		MessageBox(hWnd, TEXT("You must enter a message"), TEXT("Message Sign"), 0);
		return 0;
	}
	*buffer = (char*)GlobalAlloc(GPTR, n + 1);
	GetDlgItemText(hWnd, Window, *buffer, n + 1);

	return 1;
}

//----------------------------------------------------------------------
/*
void sedncommand(HWND hWnd, SOCKET sock, char *command, DWORD sizecommand)
{
	char *buffer = nullptr;
	if (!GetDataFromBox(hWnd, &buffer, IDC_PATH_SERV_CERT))
		return;

	// Шифрование и запись результата в файл
	char * encodetext = nullptr;
	DWORD lenencodetext = NULL;
	const char *recipient[1];

	recipient[0] = buffer;

	lenencodetext = cryptenc_encrypt(
		&encodetext,
		(BYTE *)command,
		sizecommand,
		(char **)recipient,
		1,
		(char *)szOID_CP_GOST_28147
	);
	// printfile("testencryt.txt", encodetext, lenencodetext);
	GlobalFree((HANDLE)buffer);

	send(sock, encodetext, lenencodetext, 0);

	delete[] encodetext;
}
//*/

void SendCommandAndData(SOCKET sock, char * data, DWORD datasize, char * command, DWORD commandsize)
{
	// COMMAND_ + data
	char * sendtext = new char[commandsize + datasize];
	memcpy(sendtext, command, commandsize);
	memcpy(sendtext + commandsize, data, datasize);
	
	// Кодирование данных в фрмат ASN.1 и их запись в файл
	char * encodeasntext = nullptr;
	DWORD lenencodeasntext = 0;
	lenencodeasntext = EncodeToASN1(&encodeasntext, (BYTE *)(char *)sendtext, commandsize + datasize);
	// printfile(command, encodeasntext, lenencodeasntext);

	send(sock, encodeasntext, lenencodeasntext, 0);

	delete[] encodeasntext;
	delete[] sendtext;
}

//----------------------------------------------------------------------

BOOL CALLBACK DlgProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_SOCKET:
	{
		char buffer2[1024] = "\r\nServer : ";
		char buffer1[1024] = "";

		if (WSAGETSELECTERROR(lParam) && WSAGETSELECTEVENT(lParam) != FD_CLOSE)
		{
			bError = TRUE;
			char Message[40] = "<<<<< ERROR : Server Unreachable >>>>>";
			SendDlgItemMessage(hWnd, IDC_LISTBOX, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(Message));
			reset_controls(hWnd);
			end_connection();
			break;
		}

		switch (WSAGETSELECTEVENT(lParam))
		{
		case FD_READ:
		{
			int n = recv(sock, buffer1, sizeof(buffer1) - 1, 0);

			buffer1[n] = 0;
			strcat(buffer2, buffer1);

			//MessageBox(hWnd, TEXT("U haved masg35"), TEXT("Notice"), MB_OK | MB_ICONEXCLAMATION);
			SendDlgItemMessage(hWnd, IDC_LISTBOX, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>("\r\nMessage from server"));
			SendDlgItemMessage(hWnd, IDC_LISTBOX, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(buffer2));
		}
		break;

		case FD_CLOSE:
		{
			SendDlgItemMessage(hWnd, IDC_LISTBOX, LB_RESETCONTENT, 0, 0);
			SendDlgItemMessage(hWnd, IDC_LISTBOX, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>("\r\nServer closed connection"));

			reset_controls(hWnd);
			end_connection();
		}
		break;

		case FD_CONNECT:
		{
			Button_Enable(GetDlgItem(hWnd, IDC_IP_ADDRESS), FALSE);
			Edit_SetReadOnly(GetDlgItem(hWnd, IDC_PORT), TRUE);

			Button_Enable(GetDlgItem(hWnd, IDC_CONNECT), FALSE);
			Button_Enable(GetDlgItem(hWnd, IDC_DISCONNECT), TRUE);

			//SendDlgItemMessage(hWnd, IDC_PATH_CERT, WM_SETTEXT, 0, reinterpret_cast<LPARAM>("C:\\Users\\%userprofile%\\Desktop\\MySert.p7b"));
			Button_Enable(GetDlgItem(hWnd, IDC_CHOOSE_CERT), TRUE);

			//SendDlgItemMessage(hWnd, IDC_PATH_SERV_CERT, WM_SETTEXT, 0, reinterpret_cast<LPARAM>("C:\\Users\\%userprofile%\\Desktop\\ServerSert.p7b"));
			Button_Enable(GetDlgItem(hWnd, IDC_CHOOSE_SERV_CERT), TRUE);

			Button_Enable(GetDlgItem(hWnd, IDC_PRE_SERVER), TRUE);
			Button_Enable(GetDlgItem(hWnd, IDC_HASH), TRUE);

			SendDlgItemMessage(hWnd, IDC_LISTBOX, LB_RESETCONTENT, 0, 0);
			char Message[50] = "<<<<< You are connected to server >>>>>";
			SendDlgItemMessage(hWnd, IDC_LISTBOX, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(Message));
		}
		break;
		}
	}
	break;

	case WM_COMMAND:
	{
		switch (LOWORD(wParam))
		{

		case IDC_CONNECT:
		{
			init_dll(hWnd);
			port = GetDlgItemInt(hWnd, IDC_PORT, NULL, NULL);

			if (port < 1024 || port > 65535)
			{
				MessageBox(hWnd, TEXT("Please Enter a PORT number between 1024 and 65535"), TEXT("Notice"), MB_OK | MB_ICONEXCLAMATION);
				break;
			}
			init_connection(hWnd);
		}
		break;

		case IDC_DISCONNECT:
		{
			SendDlgItemMessage(hWnd, IDC_LISTBOX, LB_RESETCONTENT, 0, 0);
			reset_controls(hWnd);
			end_connection();
		}
		break;

		case IDC_CHOOSE_CERT:
		{
			std::string pathcer;
			BOOL isOpenFile = myCreateOpenFile(hWnd, pathcer);
			if (!isOpenFile)
				break;
			SendDlgItemMessage(hWnd, IDC_PATH_CERT, WM_SETTEXT, 0, reinterpret_cast<LPARAM>(pathcer.c_str()));
			Button_Enable(GetDlgItem(hWnd, IDC_SIGN), TRUE);
		}
		break;

		case IDC_CHOOSE_SERV_CERT:
		{
			std::string pathcer;
			BOOL isOpenFile = myCreateOpenFile(hWnd, pathcer);
			if (!isOpenFile)
				break;
			SendDlgItemMessage(hWnd, IDC_PATH_SERV_CERT, WM_SETTEXT, 0, reinterpret_cast<LPARAM>(pathcer.c_str()));
			Button_Enable(GetDlgItem(hWnd, IDC_ENCRYPT), TRUE);
		}
		break;

		//!!!
		case IDC_SIGN:
		{
			std::string for_sign;

			char *buffer = nullptr;

			if (!GetDataFromBox(hWnd, &buffer, IDC_PRE_SERVER))
				break;
			for_sign = buffer;
			GlobalFree((HANDLE)buffer);

			if (!GetDataFromBox(hWnd, &buffer, IDC_PATH_CERT))
				break;

			// Подписание сообщения и запись результата в файл
			char * encodesigntext = nullptr;
			DWORD lenencodesigntext = NULL;

			lenencodesigntext = Sign(
				&encodesigntext,
				(BYTE *)for_sign.c_str(),
				for_sign.length(),
				(char *)buffer,
				0,
				0
			);

			if (!lenencodesigntext)
			{
				break;
			}

			printfile("testsign.txt", encodesigntext, lenencodesigntext);
			GlobalFree((HANDLE)buffer);

			SendCommandAndData(sock, encodesigntext, lenencodesigntext, COMM_SGN, SIZE_COMMAND);

			//sedncommand(hWnd, sock, "SGN", strlen("SGN") + 1);
			// send(sock, encodesigntext, lenencodesigntext, 0);
			//SendDlgItemMessage(hWnd, IDC_TO_SERVER, WM_SETTEXT, 0, reinterpret_cast<LPARAM>(encodesigntext));
			// send ?

			delete[] encodesigntext;
		}
		break;

		//!!!
		case IDC_ENCRYPT:
		{
			std::string for_enc;

			char *buffer = nullptr;

			if (!GetDataFromBox(hWnd, &buffer, IDC_PRE_SERVER))
				break;
			for_enc = buffer;
			GlobalFree((HANDLE)buffer);

			if (!GetDataFromBox(hWnd, &buffer, IDC_PATH_SERV_CERT))
				break;

			// Шифрование и запись результата в файл
			char * encodetext = nullptr;
			DWORD lenencodetext = NULL;
			const char *recipient[1];

			recipient[0] = buffer;

			lenencodetext = cryptenc_encrypt(
				&encodetext,
				(BYTE *)for_enc.c_str(),
				for_enc.length(),
				(char **)recipient,
				1,
				(char *)szOID_CP_GOST_28147
			);

			if (!lenencodetext)
			{
				break;
			}

			printfile("testencryt.txt", encodetext, lenencodetext);
			GlobalFree((HANDLE)buffer);

			SendCommandAndData(sock, encodetext, lenencodetext, COMM_ENC, SIZE_COMMAND);
			
			//sedncommand(hWnd, sock, "ENC", strlen("ENC") + 1);
			//send(sock, encodetext, lenencodetext, 0);
			//SendDlgItemMessage(hWnd, IDC_TO_SERVER, WM_SETTEXT, 0, reinterpret_cast<LPARAM>(encodetext));
			// send ?

			delete[] encodetext;
		}
		break;

		//!!!
		case IDC_HASH:
		{
			char *buffer = nullptr;

			if (!GetDataFromBox(hWnd, &buffer, IDC_PRE_SERVER))
				break;

			// Вычисление хеша
			std::string hashres;
			GetHash(hashres, (BYTE *)(char *)buffer, strlen(buffer));
			GlobalFree((HANDLE)buffer);

			// Кодирование данных в фрмат ASN.1 и их запись в файл
			char * encodeasntext = nullptr;
			DWORD lenencodeasntext = 0;
			lenencodeasntext = EncodeToASN1(&encodeasntext, (BYTE *)hashres.c_str(), hashres.length());
			// printfile("testasn.txt", encodeasntext, lenencodeasntext);

			if (!lenencodeasntext)
			{
				break;
			}

			SendCommandAndData(sock, encodeasntext, lenencodeasntext, COMM_HSH, SIZE_COMMAND);

			//sedncommand(hWnd, sock, "HSH", strlen("HSH") + 1);
			//send(sock, encodeasntext, lenencodeasntext, 0);
			//SendDlgItemMessage(hWnd, IDC_TO_SERVER, WM_SETTEXT, 0, reinterpret_cast<LPARAM>(encodeasntext));
			// send ?
		
			delete[] encodeasntext;
		}
		break;

		case IDC_COPY_PREVIEW:
		{
			char *buffer = nullptr;
			if (!GetDataFromBox(hWnd, &buffer, IDC_PRE_SERVER))
				break;
			toClipboard(hWnd, buffer);
			GlobalFree((HANDLE)buffer);
		}
		break;

		//!!!
		/*
		case IDC_SEND:
		{
			int n = GetWindowTextLength(GetDlgItem(hWnd, IDC_TO_SERVER));

			if (n == 0)
			{
				MessageBox(hWnd, TEXT("You must enter a message"), TEXT("Preview Message Send"), 0);
				break;
			}

			char *buffer = (char*)GlobalAlloc(GPTR, n + 1);
			GetDlgItemText(hWnd, IDC_TO_SERVER, buffer, n + 1);

			SendDlgItemMessage(hWnd, IDC_LISTBOX, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(buffer));

			send(sock, buffer, strlen(buffer), 0);
			
			GlobalFree((HANDLE)buffer);
			SendDlgItemMessage(hWnd, IDC_TO_SERVER, WM_SETTEXT, 0, reinterpret_cast<LPARAM>(""));
		}
		break;
		//*/

		case IDC_LISTBOX:
		{
			switch (HIWORD(wParam))
			{
			case LBN_SELCHANGE:
			{
				// https://social.msdn.microsoft.com/Forums/en-US/f893f3c6-f3e9-4acd-9051-b23936bbf0fd/get-text-from-listbox-win32?forum=vcgeneral

				HWND hwndList = GetDlgItem(hWnd, IDC_LISTBOX);

				// Get current selection index in listbox
				int itemIndex = (int)SendMessage(hwndList, LB_GETCURSEL, (WPARAM)0, (LPARAM)0);
				if (itemIndex == LB_ERR)
				{
					// No selection
					break;
				}

				// Get length of text in listbox
				int textLen = (int)SendMessage(hwndList, LB_GETTEXTLEN, (WPARAM)itemIndex, 0);

				// Allocate buffer to store text (consider +1 for end of string)
				TCHAR * textBuffer = new TCHAR[textLen + 1];

				// Get actual text in buffer
				SendMessage(hwndList, LB_GETTEXT, (WPARAM)itemIndex, (LPARAM)textBuffer);

				// Show it
				MessageBox(NULL, textBuffer, _T("Selected Text"), MB_OK);

				// Free text
				delete[] textBuffer;

				// Avoid dangling references
				textBuffer = NULL;
			}
			}
		}

		break;
		}
	}
	break;

	case WM_INITDIALOG:
	{
		SendDlgItemMessage(hWnd, IDC_IP_ADDRESS, IPM_SETADDRESS, 0, MAKEIPADDRESS(127, 0, 0, 1));
		SendDlgItemMessage(hWnd, IDC_PORT, WM_SETTEXT, 0, reinterpret_cast<LPARAM>("5050"));

		SendDlgItemMessage(hWnd, IDC_PATH_CERT, WM_SETTEXT, 0, reinterpret_cast<LPARAM>("C:\\Users\\%userprofile%\\Desktop\\MySert.p7b"));
		
		SendDlgItemMessage(hWnd, IDC_PATH_SERV_CERT, WM_SETTEXT, 0, reinterpret_cast<LPARAM>("C:\\Users\\%userprofile%\\Desktop\\ServerSert.p7b"));

		SendDlgItemMessage(hWnd, IDC_LISTBOX, LB_SETHORIZONTALEXTENT, (WPARAM)1024, 0);
	}
	break;

	case WM_DESTROY:
		end_connection();
		PostQuitMessage(0);
		break;

	case WM_CLOSE:
	{
		end_connection();
		EndDialog(hWnd, TRUE);
	}
	break;

	case WM_CTLCOLORLISTBOX:
	{
		if (bError == TRUE)
		{
			SetTextColor((HDC)wParam, RGB(237, 28, 36));
			bError = FALSE;
		}
		else
		{
			SetTextColor((HDC)wParam, RGB(0, 176, 88));
		}
	}
	return (BOOL)GetStockObject(WHITE_BRUSH);

	default:
		return FALSE;
	}
	return TRUE;
}

//----------------------------------------------------------------------

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	return DialogBox(GetModuleHandle(NULL), MAKEINTRESOURCE(IDD_DIALOG1), NULL, &DlgProc);
}

//----------------------------------------------------------------------

