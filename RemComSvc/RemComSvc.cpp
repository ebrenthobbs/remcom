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

namespace RemCom
{
	using namespace std;

	class RemComSvc
	{
	public:
		void StartCommunicationPoolThread()
		{
			// Start CommunicationPoolThread, which handles the incoming instances
			_beginthread(RemCom::RemComSvc::CommunicationPoolThread, 0, this);
		}

	private:
		HANDLE	m_hCommPipe = NULL;
		LONG	dwSvcPipeInstanceCount = 0;
		TCHAR	szCodeDisplayBuffer[40];

		static void CommunicationPoolThread(PVOID pThis)
		{
			RemComSvc* pInstance = (RemComSvc*)pThis;
			pInstance->CommunicationPoolThread();
		}

		// Communication Thread Pool, handles the incoming RemCom.exe requests
		void CommunicationPoolThread()
		{
			for (;;)
			{
				SECURITY_ATTRIBUTES SecAttrib = { 0 };
				SECURITY_DESCRIPTOR SecDesc;

				InitializeSecurityDescriptor(&SecDesc, SECURITY_DESCRIPTOR_REVISION);
				SetSecurityDescriptorDacl(&SecDesc, TRUE, NULL, TRUE);

				SecAttrib.nLength = sizeof(SECURITY_ATTRIBUTES);
				SecAttrib.lpSecurityDescriptor = &SecDesc;;
				SecAttrib.bInheritHandle = TRUE;

				// Create communication pipe
				m_hCommPipe = CreateNamedPipe(
					"\\\\.\\pipe\\" RemComCOMM,
					PIPE_ACCESS_DUPLEX,
					PIPE_TYPE_MESSAGE | PIPE_WAIT,
					PIPE_UNLIMITED_INSTANCES,
					0,
					0,
					(DWORD)-1,
					&SecAttrib);

				if (m_hCommPipe != NULL)
				{
					// Waiting for client to connect to this pipe
					ConnectNamedPipe(m_hCommPipe, NULL);
					_beginthread(CommunicationPipeThreadProc, 0, (void*)this);
				}
			}
		}

		LPCTSTR GetCodeDisplayString(DWORD dwCode)
		{
			_stprintf_s(szCodeDisplayBuffer, "%d(%08X)", dwCode, dwCode);
			return szCodeDisplayBuffer;
		}

		void WriteEventLog(string strMessage)
		{
			//TCHAR szTempPathBuf[MAX_PATH];
			//GetTempPath(MAX_PATH, szTempPathBuf);
			//string logFilePath = szTempPathBuf;
			string logFilePath = "C:/temp";
			logFilePath += "/RemComSvc.log";
			ofstream logStream;
			logStream.open(logFilePath, ios_base::app);
			logStream << strMessage.c_str() << endl;
			logStream.close();
		}

		void WriteLastError(const string strPrefix)
		{
			string strMessage = strPrefix;
			strMessage += GetCodeDisplayString(GetLastError());
			WriteEventLog(strMessage);
		}

		void WriteLastError(const stringstream strPrefix)
		{
			const string strTemp = strPrefix.str();
			WriteLastError(strTemp);
		}

		void WriteLastError(LPCTSTR szPrefix)
		{
			string strPrefix = szPrefix;
			WriteLastError(strPrefix);
		}

		// Handles a client
		static void CommunicationPipeThreadProc(void* pThis)
		{
			RemComSvc* pInstance = (RemComSvc*)pThis;
			pInstance->CommunicationPipeThreadProc();
		}

		void CommunicationPipeThreadProc()
		{
			RemComMessage msg;
			RemComResponse response;

			DWORD dwWritten;
			DWORD dwRead;

			// Increment instance counter 
			InterlockedIncrement(&dwSvcPipeInstanceCount);

			::ZeroMemory(&response, sizeof(response));

			// Waiting for communication message from client
			if (!ReadFile(m_hCommPipe, &msg, sizeof(msg), &dwRead, NULL) || dwRead == 0)
			{
				WriteLastError(_T("Could not read message from client. Error was "));
				goto cleanup;
			}
			else
			{
				WriteEventLog(string(msg.szCommand));
			}

			// Execute the requested command
			response.dwErrorCode = Execute(&msg, &response.dwReturnCode);

			// Send back the response message (client is waiting for this response)
			if (!WriteFile(m_hCommPipe, &response, sizeof(response), &dwWritten, NULL) || dwWritten == 0)
			{
				WriteLastError(_T("Could not write response to client. Error was "));
				goto cleanup;
			}

		cleanup:

			DisconnectNamedPipe(m_hCommPipe);
			CloseHandle(m_hCommPipe);

			// Decrement instance counter 
			InterlockedDecrement(&dwSvcPipeInstanceCount);

			// If this was the last client, let's stop ourself
			if (dwSvcPipeInstanceCount == 0)
				SetEvent(hStopServiceEvent);

		}

		const string CreatePipeName(LPCTSTR szBaseName, RemComMessage* pMsg)
		{
			stringstream strPipeName;
			strPipeName << "\\\\.\\pipe\\" << szBaseName << pMsg->szMachine << pMsg->dwProcessId;
			return strPipeName.str();
		}

		// Creates named pipes for stdout, stderr, stdin
		BOOL CreateNamedPipes(RemComMessage* pMsg, STARTUPINFO* psi)
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

			const string strStdOut = CreatePipeName(RemComSTDOUT, pMsg);
			const char* szStdOut = strStdOut.c_str();
			const string strStdIn = CreatePipeName(RemComSTDIN, pMsg);
			const char* szStdIn = strStdIn.c_str();
			const string strStdErr = CreatePipeName(RemComSTDERR, pMsg);
			const char* szStdErr = strStdErr.c_str();

			stringstream strMessage;
			strMessage << "Creating named pipes for remote caller:"
				<< " stdin=" << strStdIn
				<< " stdout=" << strStdOut
				<< " stderr=" << strStdErr;
			WriteEventLog(strMessage.str());

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
			CheckPipeCreationError(psi->hStdOutput, szStdOut);

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
			CheckPipeCreationError(psi->hStdError, szStdErr);

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
			CheckPipeCreationError(psi->hStdInput, szStdIn);

			if (psi->hStdOutput == INVALID_HANDLE_VALUE ||
				psi->hStdError == INVALID_HANDLE_VALUE ||
				psi->hStdInput == INVALID_HANDLE_VALUE)
			{
				CloseHandle(psi->hStdOutput);
				CloseHandle(psi->hStdError);
				CloseHandle(psi->hStdInput);

				return FALSE;
			}

			// Waiting for client to connect to this pipe
			ConnectNamedPipe(psi->hStdOutput, NULL);
			ConnectNamedPipe(psi->hStdInput, NULL);
			ConnectNamedPipe(psi->hStdError, NULL);

			return TRUE;
		}

		void CheckPipeCreationError(HANDLE hPipe, const char* szPipeName)
		{
			if (hPipe != INVALID_HANDLE_VALUE)
				return;
			stringstream strMessage;
			strMessage << "Error creating pipe " << szPipeName << ": ";
			WriteLastError(strMessage.str());
		}
		
		// Execute the requested client command
		DWORD Execute(RemComMessage* pMsg, DWORD* pReturnCode)
		{
			DWORD rc;
			PROCESS_INFORMATION pi;
			STARTUPINFO si;

			::ZeroMemory(&si, sizeof(si));
			si.cb = sizeof(si);

			// Creates named pipes for stdout, stdin, stderr
			// Client will sit on these pipes
			if (!CreateNamedPipes(pMsg, &si))
				return 2;

			*pReturnCode = 0;
			rc = 0;

			// Initializes command
			// cmd.exe /c /q allows us to execute internal dos commands too.
			stringstream strCommand;
			strCommand << "cmd.exe /q /c \"" << pMsg->szCommand << "\"";
			const string tmpCommand = strCommand.str();
			LPTSTR szCommand = const_cast<LPTSTR>(tmpCommand.c_str());

			// Start the requested process
			if (CreateProcess(
				NULL,
				szCommand,
				NULL,
				NULL,
				TRUE,
				pMsg->dwPriority | CREATE_NO_WINDOW,
				NULL,
				pMsg->szWorkingDir[0] != _T('\0') ? pMsg->szWorkingDir : NULL,
				&si,
				&pi))
			{
				HANDLE hProcess = pi.hProcess;

				*pReturnCode = 0;

				// Waiting for process to terminate
				if (!pMsg->bNoWait)
				{
					WaitForSingleObject(hProcess, INFINITE);
					GetExitCodeProcess(hProcess, pReturnCode);
				}
			}
			else
				rc = 1;

			return rc;
		}
	};
}

// Service "main" function
void _ServiceMain(void*)
{
	RemCom::RemComSvc service;

	service.StartCommunicationPoolThread();

	// Waiting for stop the service
	while (WaitForSingleObject(hStopServiceEvent, 10) != WAIT_OBJECT_0)
	{
	}

	CloseHandle(hStopServiceEvent);
}
