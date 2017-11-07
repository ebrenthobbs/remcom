/*
	Copyright (c) 2006 Talha Tariq [ talha.tariq@gmail.com ]
	All rights are reserved.

	Permission to use, copy, modify, and distribute this software
	for any purpose and without any fee is hereby granted,
	provided this notice is included in its entirety in the
	documentation and in the source files.

	This software and any related documentation is provided "as is"
	without any warranty of any kind, either express or implied,
	including, without limitation, the implied warranties of
	merchantability or fitness for a particular purpose. The entire
	risk arising out of use or performance of the software remains
	with you.

	$Author:	Talha Tariq [ talha.tariq@gmail.com ]
				uses some code from xCmd by Zoltan Csizmadia
	$Revision:	Talha Tariq [ talha.tariq@gmail.com ]
	$Date: 2006/10/03 09:00:00 $
	$Version History: $			-
	$TODO:						- Implement Delete Service
	$Description: $				- RemCom Service is contained in the parent binary as a local resource which is extracted at runtime from itself
								  pushed to admin$, installed to the remote service control manager which interacts remotely for local process invocation

	$Workfile: $				- RemComSvc.cpp
 */

#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <winsvc.h>
#include <process.h>
#include <fstream>
#include "RemComSvc.h"
#include "../RemCom.h"
#include "../RemComMessage.h"

#define BUFSIZE 512
#define LOG_BUFFER_SIZE 2048

namespace RemCom
{
	using namespace std;

	mutex LogFileMutex;

	class Component
	{
	public:
		Component()
		{
			m_debugLogStream = NULL;
			m_szLogBuffer = new char[LOG_BUFFER_SIZE];
		}

		~Component()
		{
			delete m_szLogBuffer;
		}

		void setDebugLogStream(ostream* debugLogStream)
		{
			m_debugLogStream = debugLogStream;
		}

		DWORD logLastError()
		{
			LPVOID lpvMessageBuffer;
			DWORD rc = GetLastError();

			FormatMessage(
				FORMAT_MESSAGE_ALLOCATE_BUFFER |
				FORMAT_MESSAGE_FROM_SYSTEM |
				FORMAT_MESSAGE_IGNORE_INSERTS,
				NULL,
				rc,
				MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
				(LPTSTR)&lpvMessageBuffer,
				0,
				NULL
			);

			writeEventLog((LPTSTR)lpvMessageBuffer);

			LocalFree(lpvMessageBuffer);
			//ExitProcess(GetLastError());
			return rc;
		}

		void writeEventString(const std::string &strMessage, bool appendNewline)
		{
			LogFileMutex.lock();
			string logFilePath = "C:/temp";
			logFilePath += "/RemComSvc.log";
			ofstream logStream;
			logStream.open(logFilePath, ios_base::app);
			logStream << strMessage.c_str();
			if (appendNewline)
				logStream << endl;
			logStream.close();
			LogFileMutex.unlock();
		}

	protected:
		ostream* m_debugLogStream;

		LPCTSTR getCodeDisplayString(DWORD dwCode)
		{
			_stprintf_s(m_szCodeDisplayBuffer, "%d(%08X)", dwCode, dwCode);
			return m_szCodeDisplayBuffer;
		}

		void logDebug(const char* fmt, ...)
		{
			if (m_debugLogStream == NULL)
				return;

			va_list args;
			va_start(args, fmt);
			vsprintf_s(m_szLogBuffer, LOG_BUFFER_SIZE, fmt, args);
			(*m_debugLogStream) << m_szLogBuffer;
		}

		void writeEventLog(const std::string &strMessage)
		{
			writeEventString(strMessage, true);
		}

		void writeLastError(const string strPrefix)
		{
			string strMessage = strPrefix;
			strMessage += getCodeDisplayString(GetLastError());
			writeEventLog(strMessage);
		}

		void writeLastError(const stringstream strPrefix)
		{
			const string strTemp = strPrefix.str();
			writeLastError(strTemp);
		}

		void writeLastError(LPCTSTR szPrefix)
		{
			string strPrefix = szPrefix;
			writeLastError(strPrefix);
		}

	private:
		char *m_szLogBuffer;
		char m_szCodeDisplayBuffer[40];
	};

	class ClientInstance : public Component
	{
	public:
		ClientInstance(HANDLE hCommPipe) : m_hCommPipe(hCommPipe)
		{
			logDebug("ClientInstance: constructor\n");
		}

		void start(function<void()> shutdownCallback)
		{
			logDebug("ClientInstance: Starting client thread\n");
			m_shutdownCallback = shutdownCallback;
			_beginthread(CommunicationPipeThreadProc, 0, (void*)this);
		}

	private:
		static DWORD s_dwSvcPipeInstanceCount;

		HANDLE	m_hCommPipe = NULL;
		function<void()> m_shutdownCallback;

		// Client thread proc
		static void CommunicationPipeThreadProc(void* pThis)
		{
			ClientInstance* pInstance = (ClientInstance*)pThis;
			pInstance->runCommunicationPipeThread();
		}

		void runCommunicationPipeThread()
		{
			RemComMessage msg(BUFSIZ, m_debugLogStream);
			RemComResponse response;

			DWORD dwWritten;

			// Increment instance counter 
			InterlockedIncrement(&s_dwSvcPipeInstanceCount);

			::ZeroMemory(&response, sizeof(response));

			// Waiting for communication message from client
			logDebug("Waiting for client message\n");
			if (!msg.receive(m_hCommPipe))
			{
				writeLastError(_T("Could not read message from client. Error was "));
				goto cleanup;
			}
			else
			{
				string command;
				writeEventLog(msg.getCommand(command));
			}

			// Execute the requested command
			response.dwErrorCode = execute(&msg, &response.dwReturnCode);
			logDebug("Returned from execute, writing %d response bytes\n", sizeof(response));

			// Send back the response message (client is waiting for this response)
			if (!WriteFile(m_hCommPipe, &response, sizeof(response), &dwWritten, NULL) || dwWritten == 0)
			{
				writeLastError(_T("Could not write response to client. Error was "));
				goto cleanup;
			}
			else
			{
				logDebug("Wrote response to client. dwErrorCode=%d, dwReturnCode=%d\n", response.dwErrorCode, response.dwReturnCode);
			}

		cleanup:
			writeEventLog("Client finished");
			DisconnectNamedPipe(m_hCommPipe);
			CloseHandle(m_hCommPipe);

			// Decrement instance counter 
			InterlockedDecrement(&s_dwSvcPipeInstanceCount);

			// Tell the service instance we're finished
			m_shutdownCallback();
		}

		// Creates named pipes for stdout, stderr, stdin
		bool createProcessIoPipes(RemComMessage* pMsg, STARTUPINFO* psi)
		{
			SECURITY_ATTRIBUTES SecAttrib = { 0 };
			SECURITY_DESCRIPTOR SecDesc;

			InitializeSecurityDescriptor(&SecDesc, SECURITY_DESCRIPTOR_REVISION);
			SetSecurityDescriptorDacl(&SecDesc, TRUE, NULL, FALSE);

			SecAttrib.nLength = sizeof(SECURITY_ATTRIBUTES);
			SecAttrib.lpSecurityDescriptor = &SecDesc;;
			SecAttrib.bInheritHandle = TRUE;

			psi->dwFlags |= STARTF_USESTDHANDLES;
			psi->hStdOutput = INVALID_HANDLE_VALUE;
			psi->hStdInput = INVALID_HANDLE_VALUE;
			psi->hStdError = INVALID_HANDLE_VALUE;

			string strStdOut, strStdIn, strStdErr;
			pMsg->createPipeName(RemComSTDOUT, strStdOut);
			pMsg->createPipeName(RemComSTDIN, strStdIn);
			pMsg->createPipeName(RemComSTDERR, strStdErr);
			const char* szStdOut = strStdOut.c_str();
			const char* szStdIn = strStdIn.c_str();
			const char* szStdErr = strStdErr.c_str();

			logDebug("Creating named pipes for remote caller: "
				" stdin=%s"
				" stdout=%s"
				" stderr=%s\n", szStdIn, szStdOut, szStdErr);

			// Create StdOut pipe
			psi->hStdOutput = CreateNamedPipe(
				szStdOut,
				PIPE_ACCESS_OUTBOUND,
				PIPE_TYPE_MESSAGE | PIPE_WAIT,
				PIPE_UNLIMITED_INSTANCES,
				0,
				0,
				(DWORD)-1,
				&SecAttrib);
			checkPipeCreationError(psi->hStdOutput, szStdOut);

			// Create StdError pipe
			psi->hStdError = CreateNamedPipe(
				szStdErr,
				PIPE_ACCESS_OUTBOUND,
				PIPE_TYPE_MESSAGE | PIPE_WAIT,
				PIPE_UNLIMITED_INSTANCES,
				0,
				0,
				(DWORD)-1,
				&SecAttrib);
			checkPipeCreationError(psi->hStdError, szStdErr);

			// Create StdIn pipe
			psi->hStdInput = CreateNamedPipe(
				szStdIn,
				PIPE_ACCESS_INBOUND,
				PIPE_TYPE_MESSAGE | PIPE_WAIT,
				PIPE_UNLIMITED_INSTANCES,
				0,
				0,
				(DWORD)-1,
				&SecAttrib);
			checkPipeCreationError(psi->hStdInput, szStdIn);

			if (psi->hStdOutput == INVALID_HANDLE_VALUE ||
				psi->hStdError == INVALID_HANDLE_VALUE ||
				psi->hStdInput == INVALID_HANDLE_VALUE)
			{
				CloseHandle(psi->hStdOutput);
				CloseHandle(psi->hStdError);
				CloseHandle(psi->hStdInput);

				return false;
			}

			// Waiting for client to connect to this pipe
			ConnectNamedPipe(psi->hStdOutput, NULL);
			ConnectNamedPipe(psi->hStdInput, NULL);
			ConnectNamedPipe(psi->hStdError, NULL);

			return true;
		}

		void checkPipeCreationError(HANDLE hPipe, const char* szPipeName)
		{
			if (hPipe != INVALID_HANDLE_VALUE)
				return;
			stringstream strMessage;
			strMessage << "Error creating pipe " << szPipeName << ": ";
			writeLastError(strMessage.str());
		}

		// Execute the requested client command
		DWORD execute(RemComMessage* pMsg, DWORD* pReturnCode)
		{
			DWORD rc;
			PROCESS_INFORMATION pi;
			STARTUPINFO si;

			::ZeroMemory(&si, sizeof(si));
			si.cb = sizeof(si);

			// Create named pipes for stdout, stdin, stderr
			// Client will sit on these pipes
			if (!createProcessIoPipes(pMsg, &si))
				return 2;

			*pReturnCode = 0;
			rc = 0;

			// Initialize command
			// cmd.exe /c /q allows us to execute internal dos commands too.
			stringstream strCommand;
			string command;
			strCommand << "cmd.exe /q /c \"" << pMsg->getCommand(command) << "\"";
			const string tmpCommand = strCommand.str();
			LPTSTR szCommand = const_cast<LPTSTR>(tmpCommand.c_str());

			// Start the requested process
			if (CreateProcess(
				NULL,
				szCommand,
				NULL,
				NULL,
				TRUE,
				pMsg->getPriority() | CREATE_NO_WINDOW,
				NULL,
				pMsg->getWorkingDirectory(),
				&si,
				&pi))
			{
				HANDLE hProcess = pi.hProcess;

				*pReturnCode = 0;

				// Wait for process to terminate
				if (pMsg->shouldWait())
				{
					logDebug("Waiting for process to terminate\n");
					WaitForSingleObject(hProcess, INFINITE);
					logDebug("Process terminated\n");
					GetExitCodeProcess(hProcess, pReturnCode);
					stringstream stdMessage;
					logDebug("Exit code = %d\n", *pReturnCode);
				}
				else
				{
					logDebug("NOT waiting for process to terminate\n");
				}
			}
			else
			{
				writeEventLog("Error creating process");
				logLastError();
				rc = 1;
			}

			return rc;
		}
	};

	DWORD ClientInstance::s_dwSvcPipeInstanceCount = 0;

	class Service : public Component
	{
	public:
		void start()
		{
			// Start CommunicationPoolThread, which handles the incoming instances
			_beginthread(RemCom::Service::CommunicationPoolThread, 0, this);
		}

		void stop()
		{
			logDebug("Shutting down\n");
			//TODO Gracefully shut down the processing thread
		}

	private:
		vector<ClientInstance*> m_clientInstances;
		mutex m_clientMutex;

		static void CommunicationPoolThread(PVOID pThis)
		{
			Service* pInstance = (Service*)pThis;
			pInstance->runCommunicationPoolThread();
		}

		// Communication Thread Pool, handles the incoming RemCom.exe requests
		void runCommunicationPoolThread()
		{	
			logDebug("Starting communication pool thread\n");
			LPTSTR szCommPipeName = "\\\\.\\pipe\\" RemComCOMM;
			for (;;)
			{
				DWORD pipeMode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT;
				size_t numInstances = m_clientInstances.size();
				logDebug("Awaiting next client connection on pipe " "\\\\.\\pipe\\" RemComCOMM " in %s mode. # current instances: %d\n",
					(pipeMode & PIPE_TYPE_MESSAGE ? "MESSAGE" : "BYTE"), numInstances);
				SECURITY_ATTRIBUTES SecAttrib = { 0 };
				SECURITY_DESCRIPTOR SecDesc;

				InitializeSecurityDescriptor(&SecDesc, SECURITY_DESCRIPTOR_REVISION);
				SetSecurityDescriptorDacl(&SecDesc, TRUE, NULL, TRUE);

				SecAttrib.nLength = sizeof(SECURITY_ATTRIBUTES);
				SecAttrib.lpSecurityDescriptor = &SecDesc;;
				SecAttrib.bInheritHandle = TRUE;

				// Create communication pipe
				HANDLE hCommPipe = CreateNamedPipe(
					szCommPipeName,
					PIPE_ACCESS_DUPLEX,
					pipeMode,
					PIPE_UNLIMITED_INSTANCES,
					BUFSIZE,
					BUFSIZE,
					0,
					&SecAttrib);

				if (hCommPipe != INVALID_HANDLE_VALUE)
				{
					// Waiting for client to connect to this pipe
					if (ConnectNamedPipe(hCommPipe, NULL))
					{
						logDebug("Client connected, creating client instance\n");
						ClientInstance* client = new ClientInstance(hCommPipe);
						logDebug("Setting client's debug log stream\n");
						client->setDebugLogStream(m_debugLogStream);
						logDebug("Adding client to instance collection\n");
						m_clientInstances.push_back(client);
						logDebug("Starting client\n");
						try
						{
							function<void()> shutdownCallback = [&]() { removeClientInstance(client); };
							client->start(shutdownCallback);
							logDebug("Called client->start\n");
						}
						catch (...)
						{
							logDebug("Unknown exception calling client.start\n");
							throw;
						}
					}
					else
					{
						writeLastError("ConnectNamedPipe failed waiting for client to connect");
					}
				}
				else
				{
					writeLastError("CreateNamedPipe failed creating communication pipe");
				}
			}
		}

		void removeClientInstance(const ClientInstance* client)
		{
			logDebug("Removing completed client\n");
			m_clientMutex.lock();
			auto it = std::find(m_clientInstances.begin(), m_clientInstances.end(), client);
			if (it != m_clientInstances.end())
			{
				m_clientInstances.erase(it);
				delete client;
			}
			m_clientMutex.unlock();
		}
	};

	struct debug_streambuf : public std::streambuf
	{
	public:
		debug_streambuf(Service& svc) : m_svc(svc)
		{
		}

	protected:
		std::streamsize xsputn(const char_type* s, std::streamsize n) override
		{
			std::string str;
			str.append(s, (const unsigned int)n);
			m_svc.writeEventString(str, false);
			return n;
		}

		int_type overflow(int_type ch) override
		{
			std::string str;
			str.append(1, (const char)ch);
			return 1;
		}

	private:
		Service& m_svc;
	};
}

// Service "main" function
void _ServiceMain(void*)
{
	// Create/configure service
	RemCom::Service service;
	RemCom::debug_streambuf debugbuf(service);
	service.setDebugLogStream(new std::ostream(&debugbuf));

	// Tell service to start processing incoming requests
	service.start();

	// Wait service stop event
	while (WaitForSingleObject(hStopServiceEvent, 10) != WAIT_OBJECT_0)
	{
	}

	// Stop the service
	CloseHandle(hStopServiceEvent);
	service.stop();
}
