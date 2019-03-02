#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <windowsx.h>
#include <stdio.h>

#include "server_resource.h"
#include "servergui_headers.h"

#pragma comment (lib, "ws2_32.lib")
#pragma warning(disable : 4996)
#pragma comment(lib, "mswsock.lib")

#define WM_SOCKET WM_USER + 101

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

BOOL init_connection(HWND hWnd)
{

	sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (sock == INVALID_SOCKET)
	{
		char Message[256] = "socket() : ";
		char error_code[50];

		_itoa(WSAGetLastError(), error_code, 10);
		strcat(Message, error_code);
		MessageBox(NULL, Message, TEXT("Error"), MB_OK | MB_ICONERROR);
		EndDialog(hWnd, TRUE);
	}

	SOCKADDR_IN sin = { 0 };

	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.s_addr = htonl(INADDR_ANY);

	WSAAsyncSelect(sock, hWnd, WM_SOCKET, FD_CLOSE | FD_READ | FD_ACCEPT);

	if (bind(sock, (SOCKADDR*)&sin, sizeof(sin)) == SOCKET_ERROR)
	{
		bError = TRUE;
		char Message[40] = "<<<< Sorry this port is busy :( >>>>>";
		SendDlgItemMessage(hWnd, IDC_LISTBOX, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(Message));
		return FALSE;
	}

	listen(sock, 0);


	char Message[50] = "Wating for client(s) ...";
	SendDlgItemMessage(hWnd, IDC_LISTBOX, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(Message));


	Button_Enable(GetDlgItem(hWnd, IDC_STOP_SERVER), TRUE);
	Button_Enable(GetDlgItem(hWnd, IDC_PORT), FALSE);
	Button_Enable(GetDlgItem(hWnd, IDC_START_SERVER), FALSE);

	return TRUE;
}

//----------------------------------------------------------------------

void end_connection(HWND hWnd)
{
	int n_client = SendDlgItemMessage(hWnd, IDC_SELECT_CLIENT, CB_GETCOUNT, 0, 0);
	int i;

	for (i = 0; i < n_client; i++)
	{
		s_client = SendDlgItemMessage(hWnd, IDC_SELECT_CLIENT, CB_GETITEMDATA, (WPARAM)i, 0);
		closesocket(s_client);
	}
	closesocket(sock);
	WSACleanup();
}

//----------------------------------------------------------------------

BOOL CALLBACK DlgProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_SOCKET:
	{
		char buffer2[1024];
		char buffer1[65536];
		char buffer_client_id[65536];

		switch (WSAGETSELECTEVENT(lParam))
		{
		case FD_ACCEPT:
		{
			SOCKADDR_IN client;
			int csize = sizeof(client);

			s_client = accept(sock, (SOCKADDR*)&client, &csize);

			if (s_client == INVALID_SOCKET)
			{
				char Message[256] = "Failed to accept connection : ";
				char error_code[50];

				_itoa(WSAGetLastError(), error_code, 10);
				strcat(Message, error_code);
				bError = TRUE;
				SendDlgItemMessage(hWnd, IDC_LISTBOX, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(Message));
			}
			else
			{

				char buffer[100], buffer2[256];
				sprintf(buffer, "%s", inet_ntoa(client.sin_addr));
				strcat(buffer, "@Port:");
				sprintf(buffer2, "%d", client.sin_port);
				strcat(buffer, buffer2);


				int index = SendDlgItemMessage(hWnd, IDC_SELECT_CLIENT, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(buffer)); // Add client to combobox
				SendDlgItemMessage(hWnd, IDC_SELECT_CLIENT, CB_SETITEMDATA, (WPARAM)index, (LPARAM)s_client);  // Bind socket descriptor to address in combobox
				Button_Enable(GetDlgItem(hWnd, IDC_SELECT_CLIENT), TRUE);  // eNABLE cLIENT LIST
				strcat(buffer, "  is connected");
				SendDlgItemMessage(hWnd, IDC_LISTBOX, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(buffer));

			}
		}
		break;

		case FD_READ:
		{
			SOCKADDR_IN clt = { 0 };
			int clt_size = sizeof(clt);
			int i;
			long lenrecvedtext;

			ZeroMemory(buffer1, sizeof(buffer1));

			int n_client = SendDlgItemMessage(hWnd, IDC_SELECT_CLIENT, CB_GETCOUNT, 0, 0);

			for (i = 0; i < n_client; i++)
			{
				s_client = SendDlgItemMessage(hWnd, IDC_SELECT_CLIENT, CB_GETITEMDATA, (WPARAM)i, 0);

				lenrecvedtext = recv(s_client, buffer1, sizeof(buffer1) - 1, 0);

				if (lenrecvedtext != -1)
				{
					getpeername(s_client, (SOCKADDR*)&clt, &clt_size);        // Get client address
					sprintf(buffer_client_id, "%s", inet_ntoa(clt.sin_addr));  // copy client address into buffer_client

					strcat(buffer_client_id, "@Port:");
					sprintf(buffer2, "%d", clt.sin_port);
					strcat(buffer_client_id, buffer2);

					strcat(buffer_client_id, " : ");
					//strcat(buffer_client_id, buffer1);

					std::string res;

					// Декодирование данных из файла и запись их в файл
					// Кодирование данных в фрмат ASN.1 и их запись в файл
					char * recvedtext = new char[lenrecvedtext];
					memcpy(recvedtext, buffer1, lenrecvedtext);

					//char buf[100] = { 0 };
					//itoa(lenrecvedtext, buf, 10);
					//MessageBox(hWnd, TEXT(buf), TEXT("Len Sign"), 0);

					char * decoderecvtext = nullptr;
					DWORD lendecoderecvtext = DecodeFromASN1(&decoderecvtext, (BYTE *)(char *)recvedtext, lenrecvedtext);


					char command[SIZE_COMMAND ] = { 0 };
					memcpy(command, decoderecvtext, SIZE_COMMAND);
					if (!strcmp(command, COMM_SGN))
					{
						res = "\r\nSIGN\r\n";

						DWORD lenencodesigntext = lendecoderecvtext - SIZE_COMMAND;
						char * encodesigntext = new char[lenencodesigntext];
						memcpy(encodesigntext, decoderecvtext + SIZE_COMMAND, lenencodesigntext);

						char * decodesigntext;
						DWORD lendecodesigntext = Verify(&decodesigntext, (BYTE *)(char *)encodesigntext, lenencodesigntext);

						// Чтобы выводить строки
						std::string decodesign;
						GetDecodedMessage(decodesign, (BYTE *)(char *)decodesigntext, lendecodesigntext);

						res += decodesign;

						delete[] decodesigntext;
						delete[] encodesigntext;
					}
					else if (!strcmp(command, COMM_ENC))
					{
						res = "\r\nDECRYPT MESSAGE\r\n";

						DWORD lenencodetext = lendecoderecvtext - SIZE_COMMAND;
						char * encodetext = new char[lenencodetext];
						memcpy(encodetext, decoderecvtext + SIZE_COMMAND, lenencodetext);

						char * decodetext = nullptr;
						DWORD lendecodetext = cryptenc_decrypt(&decodetext, (BYTE *)(char *)encodetext, lenencodetext);

						// Чтобы выводить строки
						std::string decode;
						GetDecodedMessage(decode, (BYTE *)(char *)decodetext, lendecodetext);

						res += decode;

						delete[] decodetext;
						delete[] encodetext;
					}

					else if (!strcmp(command, COMM_HSH))
					{
						res = "\r\nHASH MESSAGE\r\n";

						// Кодирование данных в фрмат ASN.1 и их запись в файл
						DWORD lenencodeasntext = lendecoderecvtext - SIZE_COMMAND;
						char * encodeasntext = new char[lenencodeasntext];
						memcpy(encodeasntext, decoderecvtext + SIZE_COMMAND, lenencodeasntext);

						char * decodeasntext = nullptr;
						DWORD lendecodeasntext = DecodeFromASN1(&decodeasntext, (BYTE *)(char *)encodeasntext, lenencodeasntext);

						// Чтобы выводить строки
						std::string decodeasn;
						GetDecodedMessage(decodeasn, (BYTE *)(char *)decodeasntext, lendecodeasntext);

						res += decodeasn;

						delete[] decodeasntext;
						delete[] encodeasntext;
					}

					else
					{
						res = "Invalid command";
					}

					//memcpy(sign_com_text + SIZE_COMMAND, encodesigntext, lenencodesigntext);

					//printfile("testdeasn.txt", decodeasntext.c_str(), decodeasntext.length());

					strcat(buffer_client_id, res.c_str());

					SendDlgItemMessage(hWnd, IDC_LISTBOX, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(buffer_client_id));

					delete[] decoderecvtext;
					delete[] recvedtext;
				}
			}

		}
		break;
		}
	}
	break;

	case WM_INITDIALOG:
	{

		//Button_Enable(GetDlgItem(hWnd, IDC_SEND), FALSE);
		//Button_Enable(GetDlgItem(hWnd, IDC_SELECT_CLIENT), FALSE);
		//Button_Enable(GetDlgItem(hWnd, IDC_TO_CLIENT), FALSE);
		Button_Enable(GetDlgItem(hWnd, IDC_STOP_SERVER), FALSE);
		SendDlgItemMessage(hWnd, IDC_PORT, WM_SETTEXT, 0, reinterpret_cast<LPARAM>("5050"));
		//SendDlgItemMessage(hWnd, IDC_SELECT_CLIENT, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>("All Clients"));
		SendDlgItemMessage(hWnd, IDC_LISTBOX, LB_SETHORIZONTALEXTENT, (WPARAM)1024, 0);
	}
	break;

	case WM_COMMAND:
	{
		switch (LOWORD(wParam))
		{
		case IDC_START_SERVER:
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

		case IDC_STOP_SERVER:
		{
			//Button_Enable(GetDlgItem(hWnd, IDC_SEND), FALSE);
			//Button_Enable(GetDlgItem(hWnd, IDC_SELECT_CLIENT), FALSE);
			//Button_Enable(GetDlgItem(hWnd, IDC_TO_CLIENT), FALSE);
			Button_Enable(GetDlgItem(hWnd, IDC_STOP_SERVER), FALSE);
			Button_Enable(GetDlgItem(hWnd, IDC_START_SERVER), TRUE);
			Button_Enable(GetDlgItem(hWnd, IDC_PORT), TRUE);
			SendDlgItemMessage(hWnd, IDC_LISTBOX, LB_RESETCONTENT, 0, 0);
			end_connection(hWnd);
		}
		break;

		case IDC_SEND:
		{
			int n = SendDlgItemMessage(hWnd, IDC_TO_CLIENT, WM_GETTEXTLENGTH, 0, 0);

			if (n == 0)
			{
				MessageBox(hWnd, TEXT("You must enter a message"), TEXT("Hey"), 0);
				break;
			}

			char *buffer = (char*)GlobalAlloc(GMEM_FIXED, (n + 1) * sizeof(char));
			GetDlgItemText(hWnd, IDC_TO_CLIENT, buffer, n + 1); // We retrieve message to be sent
			int item_index = SendDlgItemMessage(hWnd, IDC_SELECT_CLIENT, CB_GETCURSEL, 0, 0); // We get index of current address in combobox

			if (item_index == CB_ERR)
			{
				bError = TRUE;
				SendDlgItemMessage(hWnd, IDC_LISTBOX, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>("Please select a client"));
				break;
			}

			SOCKET dest = (int)SendDlgItemMessage(hWnd, IDC_SELECT_CLIENT, CB_GETITEMDATA, (WPARAM)item_index, 0); // We get the associated data which is nothing but the socket of client

			if (dest == 0)
			{
				int count = SendDlgItemMessage(hWnd, IDC_SELECT_CLIENT, CB_GETCOUNT, 0, 0);
				int i;

				for (i = 0; i < count; i++)
				{
					dest = (int)SendDlgItemMessage(hWnd, IDC_SELECT_CLIENT, CB_GETITEMDATA, (WPARAM)i, 0);
					send(dest, buffer, strlen(buffer), 0);
					SendDlgItemMessage(hWnd, IDC_TO_CLIENT, WM_SETTEXT, 0, reinterpret_cast<LPARAM>(""));
				}
			}
			else
			{
				if (send(dest, buffer, strlen(buffer), 0) == SOCKET_ERROR)
				{
					if (send(dest, buffer, strlen(buffer), 0) == SOCKET_ERROR)
					{
						char disconected_client[256];
						char buff[256];
						SendDlgItemMessage(hWnd, IDC_SELECT_CLIENT, CB_GETLBTEXT, (WPARAM)item_index, reinterpret_cast<LPARAM>(disconected_client));// Get client name from combo box
						sprintf(buff, "%s has disconnected", disconected_client);
						SendDlgItemMessage(hWnd, IDC_SELECT_CLIENT, CB_DELETESTRING, (WPARAM)item_index, 0);
						bError = TRUE;
						SendDlgItemMessage(hWnd, IDC_LISTBOX, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(buff)); // write 'client' has disconnected in listbox
						closesocket(dest);
					}
				}

				SendDlgItemMessage(hWnd, IDC_TO_CLIENT, WM_SETTEXT, 0, reinterpret_cast<LPARAM>(""));
			}

		}
		break;


		case IDC_SELECT_CLIENT:
		{
			if (HIWORD(wParam) == CBN_SELENDOK)
			{
				Button_Enable(GetDlgItem(hWnd, IDC_SEND), TRUE);
				Button_Enable(GetDlgItem(hWnd, IDC_TO_CLIENT), TRUE);
				SendDlgItemMessage(hWnd, IDC_SELECT_CLIENT, CB_GETCURSEL, 0, 0);
			}
		}


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
				//MessageBox(NULL, textBuffer, TEXT("Selected Text"), MB_OK);
				SendDlgItemMessage(hWnd, IDC_INFO, WM_SETTEXT, 0, reinterpret_cast<LPARAM>(textBuffer));

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

	case WM_DESTROY:
	{
		end_connection(hWnd);
		PostQuitMessage(0);
	}
	break;

	case WM_CLOSE:
		EndDialog(hWnd, TRUE);
		break;

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

