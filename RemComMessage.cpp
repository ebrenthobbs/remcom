#include "RemComMessage.h"
#include <stdio.h>

namespace RemCom
{
	using namespace std;

	RemComMessage::RemComMessage(DWORD dwReadBufferSize, Logger* pLogger) : m_dwReadBufferSize(dwReadBufferSize), m_pLogger(pLogger)
	{
		::ZeroMemory(&m_payload, sizeof(m_payload));
		m_readBuffer = new byte[m_dwReadBufferSize];
		::ZeroMemory(m_readBuffer, m_dwReadBufferSize);
	}

	RemComMessage::~RemComMessage()
	{
		delete m_readBuffer;
	}

	void RemComMessage::createPipeName(const char* baseName, string& pipeName)
	{
		stringstream stream;
		stream << "\\\\.\\pipe\\" << baseName << m_payload.szMachine << m_payload.dwProcessId;
		pipeName = stream.str();
	}

	RemComMessage& RemComMessage::operator<<(const char* szString)
	{
		m_command << szString;
		return *this;
	}

	const string& RemComMessage::getCommand(string& command)
	{
		command = m_command.str();
		return command;
	}

	DWORD RemComMessage::getLogonFlags()
	{
		return m_payload.dwLogonFlags;
	}

	void RemComMessage::setLogonFlags(DWORD logonFlags)
	{
		m_payload.dwLogonFlags = logonFlags;
	}

	LPCTSTR RemComMessage::getMachine()
	{
		return m_payload.szMachine;
	}

	void RemComMessage::setMachine(LPCTSTR machine)
	{
		strncpy_s(m_payload.szMachine, sizeof(m_payload.szMachine) / sizeof(TCHAR) - 1, machine, strlen(machine));
	}

	void RemComMessage::setNoWait(bool noWait)
	{
		m_payload.bNoWait = noWait ? TRUE : FALSE;
	}

	bool RemComMessage::shouldWait()
	{
		return !m_payload.bNoWait;
	}

	LPCTSTR RemComMessage::getPassword()
	{
		return m_payload.szPassword;
	}

	void RemComMessage::setPassword(LPCTSTR password)
	{
		if (password == NULL)
		{
			::ZeroMemory(m_payload.szPassword, sizeof(m_payload.szPassword));
			return;
		}
		strncpy_s(m_payload.szPassword, sizeof(m_payload.szPassword) / sizeof(TCHAR) - 1, password, strlen(password));
	}

	DWORD RemComMessage::getPriority()
	{
		return m_payload.dwPriority;
	}

	void RemComMessage::setPriority(DWORD priority)
	{
		m_payload.dwPriority = priority;
	}

	DWORD RemComMessage::getProcessId()
	{
		return m_payload.dwProcessId;
	}

	void RemComMessage::setProcessId(DWORD processId)
	{
		m_payload.dwProcessId = processId;
	}

	LPCTSTR RemComMessage::getUser()
	{
		return m_payload.szUser;
	}

	void RemComMessage::setUser(LPCTSTR user)
	{
		if (user == NULL)
		{
			::ZeroMemory(m_payload.szUser, sizeof(m_payload.szUser));
			return;
		}
		strncpy_s(m_payload.szUser, sizeof(m_payload.szUser) / sizeof(TCHAR) - 1, user, strlen(user));
	}

	LPCTSTR RemComMessage::getWorkingDirectory()
	{
		return m_payload.szWorkingDir;
	}

	void RemComMessage::setWorkingDirectory(LPCTSTR workingDirectory)
	{
		strncpy_s(m_payload.szWorkingDir, sizeof(m_payload.szWorkingDir) / sizeof(TCHAR) - 1, workingDirectory, strlen(workingDirectory));
	}

	bool RemComMessage::receive(const HANDLE &pipe)
	{
		if (m_pLogger != NULL) m_pLogger->logDebug("Receiving message");
		if (!receiveHeader(pipe))
			return false;

		if (!writeAck(pipe))
			return false;

		if (!receiveCommandText(pipe))
			return false;

		if (!writeAck(pipe))
			return false;

		return true;
	}

	bool RemComMessage::send(const HANDLE &pipe)
	{
		if (m_pLogger != NULL) m_pLogger->logDebug("Sending message");
		const string& command = m_command.str();
		m_payload.dwCommandLength = command.length();

		if (!sendHeader(pipe))
			return false;

		if (!readAck(pipe))
			return false;

		if (!sendCommandText(pipe, command))
			return false;

		return readAck(pipe);
	}

	//
	// Private
	//

	bool RemComMessage::receiveCommandText(const HANDLE &pipe)
	{
		char* buf = new char[m_payload.dwCommandLength+1];
		if (!readBytes(pipe, buf, m_payload.dwCommandLength, "command bytes"))
		{
			delete buf;
			return false;
		}
		buf[m_payload.dwCommandLength] = 0;
		m_command << buf;
		delete buf;
		return true;
	}

	bool RemComMessage::sendCommandText(const HANDLE &pipe, const string &command)
	{
		return writeBytes(pipe, (LPVOID)command.c_str(), m_payload.dwCommandLength, "command bytes");
	}

	bool RemComMessage::receiveHeader(const HANDLE &pipe)
	{
		return readBytes(pipe, &m_payload, sizeof(m_payload), "header bytes");
	}

	bool RemComMessage::sendHeader(const HANDLE &pipe)
	{
		return writeBytes(pipe, &m_payload, sizeof(m_payload), "header bytes");
	}

	bool RemComMessage::readAck(const HANDLE &pipe)
	{
		RemComResponse response;
		BOOL bSuccess = readBytes(pipe, &response, sizeof(response), "ack bytes");
		if (!bSuccess)
			return false;
		if (response.dwErrorCode != 0)
			return false;
		return true;
	}

	bool RemComMessage::writeAck(const HANDLE &pipe)
	{
		RemComResponse response;
		response.dwErrorCode = 0;
		response.dwReturnCode = 0;
		return writeBytes(pipe, &response, sizeof(response), "ack bytes");
	}

	bool RemComMessage::readBytes(const HANDLE &pipe, LPVOID bytes, DWORD bytesToRead, const char* suffix)
	{
		if (m_pLogger != NULL) m_pLogger->logDebug("Reading %d %s", bytesToRead, suffix);
		DWORD totalBytesRead = 0;
		::ZeroMemory(bytes, bytesToRead);
		LPBYTE curPtr = (LPBYTE)bytes;
		while (totalBytesRead < bytesToRead)
		{
			if (m_pLogger != NULL) m_pLogger->logDebug("Reading %d byte buffer", m_dwReadBufferSize);
			DWORD bytesRead = 0;
			BOOL bSuccess = ReadFile(pipe, m_readBuffer, m_dwReadBufferSize, &bytesRead, NULL);
			if (!bSuccess && GetLastError() != ERROR_MORE_DATA)
				return false;
			if (bytesRead > 0)
			{
				if (m_pLogger != NULL) m_pLogger->logDebug("Read %d byte(s)", bytesRead);
				memcpy(curPtr, m_readBuffer, bytesRead);
				curPtr += bytesRead;
				totalBytesRead += bytesRead;
			}
			else
			{
				if (m_pLogger != NULL) m_pLogger->logDebug("Read completed without any bytes read");
			}
		}
		return true;
	}

	bool RemComMessage::writeBytes(const HANDLE &pipe, LPVOID bytes, DWORD bytesToWrite, const char* suffix)
	{
		if (m_pLogger != NULL) m_pLogger->logDebug("Writing %d %s", bytesToWrite, suffix);
		DWORD totalBytesWritten = 0;
		LPBYTE curPtr = (LPBYTE)bytes;
		while (totalBytesWritten < bytesToWrite)
		{
			DWORD bytesToWriteThisTime = bytesToWrite - totalBytesWritten;
			if (bytesToWriteThisTime > m_dwReadBufferSize)
				bytesToWriteThisTime = m_dwReadBufferSize;
			if (m_pLogger != NULL) m_pLogger->logDebug("Writing %d byte buffer", bytesToWriteThisTime);
			DWORD bytesWritten = 0;
			if (!WriteFile(pipe, curPtr, bytesToWriteThisTime, &bytesWritten, NULL))
				return false;
			totalBytesWritten += bytesWritten;
			curPtr += bytesWritten;
			if (m_pLogger != NULL) m_pLogger->logDebug("Flushing buffers");
			if (!FlushFileBuffers(pipe))
			{
				DWORD err = GetLastError();
				if (m_pLogger != NULL) m_pLogger->logDebug("FlushFileBuffers failed, error code %d", err);
				SetLastError(err);
				return false;
			}
			else
			{
				if (m_pLogger != NULL) m_pLogger->logDebug("Buffers flushed");
			}
		}
		return true;
	}
}
