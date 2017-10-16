#pragma once

#include "RemCom.h"

namespace RemCom
{
	class RemComMessage
	{
	public:
		TCHAR szCommand[0x1000];
		TCHAR szWorkingDir[_MAX_PATH];
		DWORD dwPriority;
		DWORD dwProcessId;
		TCHAR szMachine[_MAX_PATH];
		BOOL  bNoWait;

		RemComMessage();
		~RemComMessage();
	};
}
