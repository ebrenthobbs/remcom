#include "RemComMessage.h"
#include <stdio.h>

#define LOG_BUFFER_SIZE 2048

namespace RemCom
{
	using namespace std;

	RemComMessage::RemComMessage(DWORD dwReadBufferSize, std::ostream* debugLogStream) : m_dwReadBufferSize(dwReadBufferSize), m_debugLogStream(debugLogStream)
	{
		ZeroMemory(&m_payload, sizeof(m_payload));
		m_szLogBuffer = new char[LOG_BUFFER_SIZE];
		m_readBuffer = new byte[m_dwReadBufferSize];
	}

	RemComMessage::~RemComMessage()
	{
		delete m_szLogBuffer;
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

	DWORD RemComMessage::getPriority()
	{
		return m_payload.dwPriority;
	}

	void RemComMessage::setPriority(DWORD priority)
	{
		m_payload.dwPriority = priority;
	}

	void RemComMessage::setProcessId(DWORD processId)
	{
		m_payload.dwProcessId = processId;
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
		logDebug("Receiving message\n");
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
		logDebug("Sending message\n");
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
		logDebug("Reading %d %s\n", bytesToRead, suffix);
		DWORD totalBytesRead = 0;
		::ZeroMemory(bytes, bytesToRead);
		LPBYTE curPtr = (LPBYTE)bytes;
		while (totalBytesRead < bytesToRead)
		{
			logDebug("Reading %d byte buffer\n", m_dwReadBufferSize);
			DWORD bytesRead = 0;
			BOOL bSuccess = ReadFile(pipe, m_readBuffer, m_dwReadBufferSize, &bytesRead, NULL);
			if (!bSuccess && GetLastError() != ERROR_MORE_DATA)
				return false;
			if (bytesRead > 0)
			{
				logDebug("Read %d byte(s)\n", bytesRead);
				memcpy(curPtr, m_readBuffer, bytesRead);
				curPtr += bytesRead;
				totalBytesRead += bytesRead;
			}
		}
		return true;
	}

	bool RemComMessage::writeBytes(const HANDLE &pipe, LPVOID bytes, DWORD bytesToWrite, const char* suffix)
	{
		logDebug("Writing %d %s\n", bytesToWrite, suffix);
		DWORD bytesWritten = 0;
		if (!WriteFile(pipe, bytes, bytesToWrite, &bytesWritten, NULL))
			return false;
		//logDebug("Flushing buffers\n");
		//FlushFileBuffers(pipe);
		if (bytesWritten != bytesToWrite)
			return false;
		return true;
	}

	void RemComMessage::logDebug(const char* fmt, ...)
	{
		if (m_debugLogStream == NULL)
			return;

		va_list args;
		va_start(args, fmt);
		vsprintf_s(m_szLogBuffer, LOG_BUFFER_SIZE, fmt, args);
		(*m_debugLogStream) << m_szLogBuffer;
	}
}
