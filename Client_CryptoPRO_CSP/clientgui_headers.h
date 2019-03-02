#pragma once

void init_dll(HWND);
void init_connection(HWND);
void end_connection();
void reset_controls(HWND);
BOOL bError = FALSE;
SOCKET sock;
DWORD ip;
unsigned int port = 5050;
