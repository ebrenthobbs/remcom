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
#include "../Logger.h"

#define BUFSIZE 512
#define LOG_BUFFER_SIZE 2048

namespace RemCom
{
	using namespace std;

	class Component
	{
	public:
		Component()
		{
		}

	protected:
		Logger* m_pLogger;

		DWORD writeLastError(const string strPrefix)
		{
			string strMessage = strPrefix;
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

			m_pLogger->logError("%s: %s", strPrefix.c_str(), (LPTSTR)lpvMessageBuffer);

			LocalFree(lpvMessageBuffer);
			//ExitProcess(GetLastError());
			return rc;
		}

		DWORD writeLastError(const stringstream strPrefix)
		{
			const string strTemp = strPrefix.str();
			return writeLastError(strTemp);
		}

		DWORD writeLastError(LPCTSTR szPrefix)
		{
			string strPrefix = szPrefix;
			return writeLastError(strPrefix);
		}

	private:
		char m_szCodeDisplayBuffer[40];
	};

	class ClientInstance : public Component
	{
	public:
		ClientInstance(HANDLE hCommPipe, Logger* pLogger) : m_hCommPipe(hCommPipe)
		{
			m_pLogger = pLogger;
			m_pLogger->logDebug("ClientInstance: constructor");
		}

		void start(function<void()> shutdownCallback)
		{
			m_pLogger->logDebug("ClientInstance: Starting client thread");
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
			RemComMessage msg(BUFSIZ, m_pLogger);
			RemComResponse response;

			DWORD dwWritten;

			// Increment instance counter 
			InterlockedIncrement(&s_dwSvcPipeInstanceCount);

			WaitForMessageThenProcess();

			DisconnectNamedPipe(m_hCommPipe);
			CloseHandle(m_hCommPipe);

			// Decrement instance counter 
			InterlockedDecrement(&dwSvcPipeInstanceCount);
		}

		void WaitForMessageThenProcess()
		{
			RemComMessage msg;
			WaitForMessageFromClient(msg);

			RemComResponse response;
			ProcessMessage(msg, response);

			WriteEventLog("Command execution finished");
		}

		void WaitForMessageFromClient(RemCom::RemComMessage &msg)
		{
			// Waiting for communication message from client
			m_pLogger->logDebug("Waiting for client message");
			if (!msg.receive(m_hCommPipe))
			{
				writeLastError("Could not read message from client.");
				goto cleanup;
			}
			else
			{
				string command;
				m_pLogger->logDebug(msg.getCommand(command).c_str());
			}

			WriteEventLog(string(msg.szCommand));
		}

		void ProcessMessage(RemComMessage& msg, RemComResponse& response)
		{
			// Execute the requested command
			response.dwErrorCode = execute(&msg, &response.dwReturnCode);
			m_pLogger->logDebug("Returned from execute, writing %d response bytes", sizeof(response));

			// Send back the response message (client is waiting for this response)
			DWORD dwWritten;
			if (!WriteFile(m_hCommPipe, &response, sizeof(response), &dwWritten, NULL) || dwWritten == 0)
			{
				writeLastError("Could not write response to client");
				goto cleanup;
			}
			else
			{
				m_pLogger->logDebug("Wrote response to client. dwErrorCode=%d, dwReturnCode=%d", response.dwErrorCode, response.dwReturnCode);
			}

		cleanup:
			m_pLogger->logDebug("Client finished");
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

			m_pLogger->logDebug("Creating named pipes for remote caller: "
				" stdin=%s"
				" stdout=%s"
				" stderr=%s", szStdIn, szStdOut, szStdErr);

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
			strMessage << "Error creating pipe " << szPipeName;
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
			string command;
			pMsg->getCommand(command);
			size_t bufferSize = command.length() + 40;
			LPTSTR szCommand = new TCHAR[bufferSize];
			sprintf_s(szCommand, bufferSize, "cmd.exe /q /c \"%s\"", command.c_str());
			LPCTSTR szWorkingDir = pMsg->getWorkingDirectory();
			
			// Start the requested process
			if (CreateProcess(
				NULL,
				szCommand,
				NULL,
				NULL,
				TRUE,
				pMsg->getPriority() | CREATE_NO_WINDOW,
				NULL,
				szWorkingDir[0] != _T('\0') ? szWorkingDir : NULL,
				&si,
				&pi))
			{	
				HANDLE hProcess = pi.hProcess;

				*pReturnCode = 0;

				// Wait for process to terminate
				if (pMsg->shouldWait())
				{
					m_pLogger->logDebug("Waiting for process to terminate");
					WaitForSingleObject(hProcess, INFINITE);
					m_pLogger->logDebug("Process terminated");
					GetExitCodeProcess(hProcess, pReturnCode);
					stringstream stdMessage;
					m_pLogger->logDebug("Exit code = %d", *pReturnCode);
				}
				else
				{
					m_pLogger->logDebug("NOT waiting for process to terminate");
				}
			}
			else
			{
				writeLastError("Error creating process");
				rc = 1;
			}

			delete szCommand;
			return rc;
		}
	};

	DWORD ClientInstance::s_dwSvcPipeInstanceCount = 0;

	class Service : public Component
	{
	public:
		Service()
		{

		}

		void start()
		{
			m_logStream.open("c:\\temp\\remcomsvc.log", ios_base::out | ios_base::in | ios_base::app);
			m_pLogger = new Logger(m_logStream, LogLevel::Debug, LOG_BUFFER_SIZE);

			// Start CommunicationPoolThread, which handles the incoming instances
			_beginthread(RemCom::Service::CommunicationPoolThread, 0, this);
		}

		void stop()
		{
			m_pLogger->logDebug("Shutting down");
			//TODO Gracefully shut down the processing thread
		}

	private:
		ofstream m_logStream;
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
			m_pLogger->logDebug("Starting communication pool thread");
			LPTSTR szCommPipeName = "\\\\.\\pipe\\" RemComCOMM;
			for (;;)
			{
				DWORD pipeMode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT;
				size_t numInstances = m_clientInstances.size();
				m_pLogger->logDebug("Awaiting next client connection on pipe " "\\\\.\\pipe\\" RemComCOMM " in %s mode. # current instances: %d",
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
						m_pLogger->logDebug("Client connected, creating client instance");
						ClientInstance* client = new ClientInstance(hCommPipe, m_pLogger);
						m_pLogger->logDebug("Adding client to instance collection");
						m_clientInstances.push_back(client);
						m_pLogger->logDebug("Starting client");
						try
						{
							function<void()> shutdownCallback = [&]() { removeClientInstance(client); };
							client->start(shutdownCallback);
							m_pLogger->logDebug("Called client->start");
						}
						catch (...)
						{
							m_pLogger->logDebug("Unknown exception calling client.start");
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
			m_pLogger->logDebug("Removing completed client");
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
}

// Service "main" function
void _ServiceMain(void*)
{
	// Create/configure service
	RemCom::Service service;

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
