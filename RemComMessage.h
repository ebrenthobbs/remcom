#pragma once

#include "RemCom.h"

namespace RemCom
{
	struct RemComMessagePayload
	{
		DWORD	dwCommandLength;
		TCHAR	szWorkingDir[_MAX_PATH];
		DWORD	dwPriority;
		DWORD	dwProcessId;
		TCHAR	szMachine[_MAX_PATH];
		BOOL	bNoWait;
	};

	class RemComMessage
	{
	public:
		RemComMessage();
		~RemComMessage();

		RemComMessage& operator<<(const char* szString);
		const std::string& getCommand(std::string& command);

		void setMachine(LPCTSTR machine);

		void setNoWait(bool noWait);
		bool shouldWait();

		DWORD getPriority();
		void setPriority(DWORD priority);

		void setProcessId(DWORD processId);

		LPCTSTR getWorkingDirectory();
		void setWorkingDirectory(LPCTSTR workingDirectory);

		bool receive(const HANDLE &handle);
		bool send(const HANDLE &handle);

		void createPipeName(const char* baseName, std::string& pipeName);

	private:
		RemComMessagePayload m_payload;
		std::stringstream m_command;

		bool readAck(const HANDLE &pipe);
		bool receiveCommandText(const HANDLE &pipe);
		bool receiveHeader(const HANDLE &pipe);
		bool sendCommandText(const HANDLE &pipe, const std::string &command);
		bool sendHeader(const HANDLE &pipe);
		bool writeAck(const HANDLE &pipe);

	};
}
