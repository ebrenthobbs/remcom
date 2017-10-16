#pragma once
#include "RemCom.h"

namespace RemCom
{
	class RemComResponse
	{
	public:
		DWORD dwErrorCode;
		DWORD dwReturnCode;

		RemComResponse();
	};
}
