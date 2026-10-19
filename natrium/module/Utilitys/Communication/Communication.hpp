#pragma once

#include <string>
#include <vector>
#include <thread>
#include <WinSock2.h>
#include <WS2tcpip.h>

namespace Communication
{
	void Initialize();
}

namespace ConsoleChannel
{
	// Frame: 4-byte big-endian payload length, then 1-byte level ('p','w','e') + UTF-8 text.
	void Enqueue(char Level, const char* Data, size_t Size);
}