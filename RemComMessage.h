#pragma once

#include "RemCom.h"
#include "Logger.h"

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
		DWORD	dwLogonFlags;
		TCHAR	szUser[_MAX_PATH];
		TCHAR	szPassword[_MAX_PATH];
	};

	class RemComMessage
	{
	public:
		RemComMessage(DWORD dwReadBufferSize, Logger* pLogger);
		~RemComMessage();

		RemComMessage& operator<<(const char* szString);
		const std::string& getCommand(std::string& command);

		void setMachine(LPCTSTR machine);

		void setNoWait(bool noWait);
		bool shouldWait();

		DWORD getLogonFlags();
		void setLogonFlags(DWORD logonFlags);

		LPCTSTR getPassword();
		void setPassword(LPCTSTR password);

		DWORD getPriority();
		void setPriority(DWORD priority);

		void setProcessId(DWORD processId);

		LPCTSTR getUser();
		void setUser(LPCTSTR user);

		LPCTSTR getWorkingDirectory();
		void setWorkingDirectory(LPCTSTR workingDirectory);

		bool receive(const HANDLE &handle);
		bool send(const HANDLE &handle);

		void createPipeName(const char* baseName, std::string& pipeName);

	private:
		Logger* m_pLogger;
		RemComMessagePayload m_payload;
		std::stringstream m_command;
		DWORD m_dwReadBufferSize;
		LPBYTE m_readBuffer;

		bool readAck(const HANDLE &pipe);
		bool receiveCommandText(const HANDLE &pipe);
		bool receiveHeader(const HANDLE &pipe);
		bool sendCommandText(const HANDLE &pipe, const std::string &command);
		bool sendHeader(const HANDLE &pipe);
		bool writeAck(const HANDLE &pipe);
		bool readBytes(const HANDLE &pipe, LPVOID bytes, DWORD numBytes, const char* suffix);
		bool writeBytes(const HANDLE &pipe, LPVOID bytes, DWORD numBytes, const char* suffix);
	};
}
