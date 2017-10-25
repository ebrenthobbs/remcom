#include "RemComMessage.h"

namespace RemCom
{
	using namespace std;

	RemComMessage::RemComMessage()
	{

	}

	RemComMessage::~RemComMessage()
	{

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
		if (!receiveHeader(pipe))
			return false;

		if (!receiveCommandText(pipe))
			return false;

		if (!writeAck(pipe))
			return false;

		return true;
	}

	bool RemComMessage::send(const HANDLE &pipe)
	{
		const string& command = m_command.str();
		m_payload.dwCommandLength = command.length();

		if (!sendHeader(pipe))
			return false;

		if (!readAck(pipe))
			return false;

		return sendCommandText(pipe, command);
	}

	//
	// Private
	//

	bool RemComMessage::receiveCommandText(const HANDLE &pipe)
	{
		DWORD bytesRead;
		char* buf = new char[m_payload.dwCommandLength+1];
		if (!ReadFile(pipe, buf, m_payload.dwCommandLength, &bytesRead, NULL) || bytesRead != m_payload.dwCommandLength)
		{
			delete buf;
			return false;
		}

		m_command << buf;
		delete buf;
		return true;
	}

	bool RemComMessage::sendCommandText(const HANDLE &pipe, const string &command)
	{
		DWORD bytesWritten;
		BOOL bSuccess = WriteFile(pipe, command.c_str(), m_payload.dwCommandLength, &bytesWritten, NULL);
		if (!bSuccess)
			return false;
		return m_payload.dwCommandLength == bytesWritten;
	}

	bool RemComMessage::receiveHeader(const HANDLE &pipe)
	{
		::ZeroMemory(&m_payload, sizeof(m_payload));
		DWORD bytesRead;
		if (!ReadFile(pipe, &m_payload, sizeof(m_payload), &bytesRead, NULL) || bytesRead == 0)
			return false;
		return true;
	}

	bool RemComMessage::sendHeader(const HANDLE &pipe)
	{
		DWORD bytesWritten;
		BOOL bSuccess = WriteFile(pipe, &m_payload, sizeof(m_payload), &bytesWritten, NULL);
		if (!bSuccess)
			return false;
		if (sizeof(m_payload) != bytesWritten)
			return false;
		return true;
	}

	bool RemComMessage::readAck(const HANDLE &pipe)
	{
		RemComResponse response;
		DWORD bytesRead;
		BOOL bSuccess = ReadFile(pipe, &response, sizeof(response), &bytesRead, NULL);
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
		DWORD bytesWritten;
		if (!WriteFile(pipe, &response, sizeof(response), &bytesWritten, NULL) || bytesWritten != sizeof(response))
			return false;
		return true;
	}
}
