#pragma once

#include "utils.h"

BOOL bError = FALSE;

void init_dll(HWND);
BOOL init_connection(HWND);
void end_connection(HWND);


SOCKET sock;
SOCKET  s_client;
unsigned int port = 5050;
