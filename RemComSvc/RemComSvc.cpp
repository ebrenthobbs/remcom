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
#include <atlbase.h>
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
#define MAXUSERNAME 104
#define MAXDOMAINNAME 253
#define DOMAIN_USER_DELIMITER "\\"

namespace RemCom
{
	using namespace std;

	struct DomainUserInfo
	{
		TCHAR userName[MAXUSERNAME + 1];
		TCHAR domainName[MAXDOMAINNAME + 1];
	};

	enum ProcessCreationMode
	{
		Anonymous = 1,
		WithLogon = 2,
		WithToken = 3
	};

	class Component
	{
	public:
		Component()
		{
		}

	protected:
		Logger* m_pLogger;

		bool openRegistry(PHKEY phRegKey)
		{
			LPCTSTR szRegistryKey = "Software\\Arxscan\\RemComSvc";
			LONG rc = RegOpenKeyEx(HKEY_LOCAL_MACHINE, szRegistryKey, 0, KEY_READ, phRegKey);
			return rc == ERROR_SUCCESS;
		}

		DWORD getDwordRegKey(HKEY hKey, const std::wstring &strValueName, LPDWORD pValue)
		{
			DWORD dwBufferSize = sizeof(DWORD);
			*pValue = 0;
			ULONG nError = RegQueryValueExW(hKey, strValueName.c_str(), 0, NULL, (LPBYTE)pValue, &dwBufferSize);
			return nError;
		}

		LONG getStringRegKey(HKEY hKey, const std::wstring &strValueName, std::wstring &strValue, const std::wstring &strDefaultValue)
		{
			strValue = strDefaultValue;
			WCHAR szBuffer[512];
			DWORD dwBufferSize = sizeof(szBuffer);
			ULONG nError = RegQueryValueExW(hKey, strValueName.c_str(), 0, NULL, (LPBYTE)szBuffer, &dwBufferSize);
			if (ERROR_SUCCESS == nError)
			{
				strValue = szBuffer;
			}
			return nError;
		}

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

		bool launchDebugger()
		{
			// Get System directory, typically c:\windows\system32
			std::wstring systemDir(MAX_PATH + 1, '\0');
			UINT nChars = GetSystemDirectoryW(&systemDir[0], systemDir.length());
			if (nChars == 0) return false; // failed to get system directory
			systemDir.resize(nChars);

			// Get process ID and create the command line
			DWORD pid = GetCurrentProcessId();
			std::wostringstream s;
			s << systemDir << L"\\vsjitdebugger.exe -p " << pid;
			std::wstring cmdLine = s.str();

			// Start debugger process
			STARTUPINFOW si;
			ZeroMemory(&si, sizeof(si));
			si.cb = sizeof(si);

			PROCESS_INFORMATION pi;
			ZeroMemory(&pi, sizeof(pi));

			if (!CreateProcessW(NULL, &cmdLine[0], NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) return false;

			// Close debugger process handles to eliminate resource leak
			CloseHandle(pi.hThread);
			CloseHandle(pi.hProcess);

			// Wait for the debugger to attach
			while (!IsDebuggerPresent()) Sleep(100);

			// Stop execution so the debugger can take over
			DebugBreak();
			return true;
		}

	private:
		char m_szCodeDisplayBuffer[40];
	};

	class ClientInstance : public Component
	{
	public:
		ClientInstance(HANDLE hCommPipe, Logger* pLogger) :
			m_hCommPipe(hCommPipe)
		{
			m_pLogger = pLogger;
			if (m_pLogger->isEnabled(LogLevel::Debug))
				m_pLogger->logDebug("ClientInstance: constructor");
			initFromRegistry();
		}

		void start(function<void()> shutdownCallback)
		{
			if (m_pLogger->isEnabled(LogLevel::Debug))
				m_pLogger->logDebug("ClientInstance: Starting client thread");
			m_shutdownCallback = shutdownCallback;
			_beginthread(CommunicationPipeThreadProc, 0, (void*)this);
		}

	private:
		static DWORD s_dwSvcPipeInstanceCount;

		ProcessCreationMode m_processCreationMode;
		HANDLE	m_hCommPipe = NULL;
		function<void()> m_shutdownCallback;
		PROCESS_INFORMATION m_processInfo;
		STARTUPINFO m_startupInfo;
		HANDLE m_hToken;

		void initFromRegistry()
		{
			HKEY hRegKey;
			if (openRegistry(&hRegKey))
			{
				DWORD dwProcessCreationMode;
				getDwordRegKey(hRegKey, L"ProcessCreationMode", &dwProcessCreationMode);
				switch (m_processCreationMode)
				{
				case 1:
					m_processCreationMode = ProcessCreationMode::Anonymous;
					break;
				case 2:
					m_processCreationMode = ProcessCreationMode::WithLogon;
					break;
				case 3:
					m_processCreationMode = ProcessCreationMode::WithToken;
					break;
				default:
					m_processCreationMode = ProcessCreationMode::WithToken;
					break;
				}
			}
			else
				m_processCreationMode = ProcessCreationMode::WithToken;
		}

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

			::ZeroMemory(&response, sizeof(response));

			// Waiting for communication message from client
			if (m_pLogger->isEnabled(LogLevel::Debug))
				m_pLogger->logDebug("Waiting for client message");
			if (!msg.receive(m_hCommPipe))
			{
				writeLastError("Could not read message from client.");
				goto cleanup;
			}
			else
			{
				string command;
				if (m_pLogger->isEnabled(LogLevel::Debug))
				{
					const char* szCommandString = msg.getCommand(command).c_str();
					m_pLogger->logDebug("Command string length: %d", strlen(szCommandString));
					m_pLogger->logDebug("Command: %s", szCommandString);
				}
			}

			// Execute the requested command
			execute(&msg, &response);
			if (m_pLogger->isEnabled(LogLevel::Debug))
				m_pLogger->logDebug("Returned from execute, writing %d response bytes", sizeof(response));

			// Send back the response message (client is waiting for this response)
			if (!WriteFile(m_hCommPipe, &response, sizeof(response), &dwWritten, NULL) || dwWritten == 0)
			{
				writeLastError("Could not write response to client");
				goto cleanup;
			}
			else
			{
				if (m_pLogger->isEnabled(LogLevel::Debug))
					m_pLogger->logDebug("Wrote response to client. dwStatusCode=%d, dwReturnCode=%d", response.dwStatusCode, response.dwExitCode);
			}

		cleanup:
			if (m_pLogger->isEnabled(LogLevel::Debug))
				m_pLogger->logDebug("Client finished");
			DisconnectNamedPipe(m_hCommPipe);
			CloseHandle(m_hCommPipe);

			// Decrement instance counter 
			InterlockedDecrement(&s_dwSvcPipeInstanceCount);

			// Tell the service instance we're finished
			m_shutdownCallback();
		}

		bool connectIoPipe(HANDLE hPipe, LPCTSTR pipeName)
		{
			if (!ConnectNamedPipe(hPipe, NULL))
			{
				DWORD err = GetLastError();
				if (err != ERROR_PIPE_CONNECTED)
				{
					stringstream strMessage;
					strMessage << "Error connecting client to " << pipeName << " pipe";
					writeLastError(strMessage.str());
					return false;
				}
			}
			if (m_pLogger->isEnabled(LogLevel::Debug))
				m_pLogger->logDebug("Client connected to %s pipe", pipeName);
			return true;
		}

		// Creates named pipes for stdout, stderr, stdin
		bool createProcessIoPipes(RemComMessage* pMsg)
		{
			SECURITY_ATTRIBUTES SecAttrib = { 0 };
			SECURITY_DESCRIPTOR SecDesc;

			InitializeSecurityDescriptor(&SecDesc, SECURITY_DESCRIPTOR_REVISION);
			SetSecurityDescriptorDacl(&SecDesc, TRUE, NULL, FALSE);

			SecAttrib.nLength = sizeof(SECURITY_ATTRIBUTES);
			SecAttrib.lpSecurityDescriptor = &SecDesc;;
			SecAttrib.bInheritHandle = TRUE;

			m_startupInfo.dwFlags |= STARTF_USESTDHANDLES;
			m_startupInfo.hStdOutput = INVALID_HANDLE_VALUE;
			m_startupInfo.hStdInput = INVALID_HANDLE_VALUE;
			m_startupInfo.hStdError = INVALID_HANDLE_VALUE;

			string strStdOut, strStdIn, strStdErr;
			pMsg->createPipeName(RemComSTDOUT, strStdOut);
			pMsg->createPipeName(RemComSTDIN, strStdIn);
			pMsg->createPipeName(RemComSTDERR, strStdErr);
			const char* szStdOut = strStdOut.c_str();
			const char* szStdIn = strStdIn.c_str();
			const char* szStdErr = strStdErr.c_str();

			if (m_pLogger->isEnabled(LogLevel::Debug))
				m_pLogger->logDebug("Creating named pipes for remote caller");

			// Create StdOut pipe
			m_startupInfo.hStdOutput = CreateNamedPipe(
				szStdOut,
				PIPE_ACCESS_DUPLEX,
				PIPE_WAIT,
				1,
				BUFSIZE,
				BUFSIZE,
				NMPWAIT_USE_DEFAULT_WAIT,
				&SecAttrib);
			if (m_pLogger->isEnabled(LogLevel::Debug))
				m_pLogger->logDebug("%s: 0x%08x", szStdOut, m_startupInfo.hStdOutput);
			checkPipeCreationError(m_startupInfo.hStdOutput, szStdOut);

			// Create StdError pipe
			m_startupInfo.hStdError = CreateNamedPipe(
				szStdErr,
				PIPE_ACCESS_DUPLEX,
				PIPE_WAIT,
				1,
				BUFSIZE,
				BUFSIZE,
				NMPWAIT_USE_DEFAULT_WAIT,
				&SecAttrib);
			if (m_pLogger->isEnabled(LogLevel::Debug))
				m_pLogger->logDebug("%s: 0x%08x", szStdErr, m_startupInfo.hStdError);
			checkPipeCreationError(m_startupInfo.hStdError, szStdErr);

			// Create StdIn pipe
			m_startupInfo.hStdInput = CreateNamedPipe(
				szStdIn,
				PIPE_ACCESS_DUPLEX,
				PIPE_WAIT,
				1,
				BUFSIZE,
				BUFSIZE,
				NMPWAIT_USE_DEFAULT_WAIT,
				&SecAttrib);
			if (m_pLogger->isEnabled(LogLevel::Debug))
				m_pLogger->logDebug("%s: 0x%08x", szStdIn, m_startupInfo.hStdInput);
			checkPipeCreationError(m_startupInfo.hStdInput, szStdIn);

			if (m_startupInfo.hStdOutput == INVALID_HANDLE_VALUE ||
				m_startupInfo.hStdError == INVALID_HANDLE_VALUE ||
				m_startupInfo.hStdInput == INVALID_HANDLE_VALUE)
			{
				CloseHandle(m_startupInfo.hStdOutput);
				CloseHandle(m_startupInfo.hStdError);
				CloseHandle(m_startupInfo.hStdInput);

				return false;
			}

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
		void execute(RemComMessage* pMsg, RemComResponse* pResponse)
		{
			try
			{
				HANDLE hProcess;
				switch (m_processCreationMode)
				{
				case ProcessCreationMode::Anonymous:
					if (m_pLogger->isEnabled(LogLevel::Debug))
						m_pLogger->logDebug("Creating process anonymously");
					hProcess = createProcessAnonymously(pMsg, &pResponse->dwExitCode);
					break;
				default:
					if (m_pLogger->isEnabled(LogLevel::Debug))
						m_pLogger->logDebug("Creating process with logon token");
					hProcess = createProcessWithToken(pMsg, pResponse);
					break;
				}

				if (hProcess == INVALID_HANDLE_VALUE)
					return;

				if (pMsg->shouldWait())
				{
					if (m_pLogger->isEnabled(LogLevel::Debug))
						m_pLogger->logDebug("Waiting for process to complete");
					WaitForSingleObject(hProcess, INFINITE);
					pResponse->dwStatusCode = RemComResponseStatus::PROCESS_COMPLETED;
					if (m_pLogger->isEnabled(LogLevel::Debug))
						m_pLogger->logDebug("Process completed");
					GetExitCodeProcess(hProcess, &pResponse->dwExitCode);
					stringstream stdMessage;
					if (m_pLogger->isEnabled(LogLevel::Debug))
						m_pLogger->logDebug("Exit code = %d", pResponse->dwExitCode);
				}
				else
				{
					if (m_pLogger->isEnabled(LogLevel::Debug))
						m_pLogger->logDebug("NOT waiting for process to complete");
				}
				FlushFileBuffers(m_startupInfo.hStdError);
				FlushFileBuffers(m_startupInfo.hStdOutput);
				CloseHandle(m_processInfo.hProcess);
				CloseHandle(m_processInfo.hThread);
				DisconnectNamedPipe(m_startupInfo.hStdError);
				DisconnectNamedPipe(m_startupInfo.hStdInput);
				DisconnectNamedPipe(m_startupInfo.hStdOutput);
				CloseHandle(m_startupInfo.hStdError);
				CloseHandle(m_startupInfo.hStdInput);
				CloseHandle(m_startupInfo.hStdOutput);
				CloseHandle(m_hToken);
			}
			catch (const std::runtime_error& re)
			{
				m_pLogger->logError("Runtime error occurred trying to execute command: %s", re.what());
				pResponse->dwStatusCode = RemComResponseStatus::PROCESS_EXECUTION_FAILED;
			}
			catch (const std::exception& ex)
			{
				m_pLogger->logError("Exception error occurred trying to execute command: %s", ex.what());
				pResponse->dwStatusCode = RemComResponseStatus::PROCESS_EXECUTION_FAILED;
			}
			catch (...)
			{
				m_pLogger->logError("Unknown exception occurred trying to execute command");
				pResponse->dwStatusCode = RemComResponseStatus::PROCESS_EXECUTION_FAILED;
			}
		}

		LPTSTR createCommandLine(RemComMessage* pMsg)
		{
			string command;
			pMsg->getCommand(command);
			size_t bufferSize = command.length() + 40;
			LPTSTR szCommand = new TCHAR[bufferSize];
			//sprintf_s(szCommand, bufferSize, "cmd.exe /q /c \"%s\"", command.c_str());
			sprintf_s(szCommand, bufferSize, "%s", command.c_str());
			return szCommand;
		}

		void extractDomainUserInfo(RemComMessage* pMsg, DomainUserInfo& domainUserInfo)
		{
			if (m_pLogger->isEnabled(LogLevel::Debug))
				m_pLogger->logDebug("Extracting domain user info from message");
			TCHAR szUserNameBuffer[MAXUSERNAME + MAXDOMAINNAME + 2];
			LPCTSTR szUser = pMsg->getUser();
			if (m_pLogger->isEnabled(LogLevel::Debug))
				m_pLogger->logDebug("Specified Username: %s", szUser);
			strncpy_s(szUserNameBuffer, sizeof(szUserNameBuffer) / sizeof(TCHAR) - 1, szUser, strlen(szUser));
			LPCTSTR szTok0, szTok1;
			TCHAR* nextToken = NULL;
			szTok0 = _tcstok_s(szUserNameBuffer, DOMAIN_USER_DELIMITER, &nextToken);
			szTok1 = _tcstok_s(NULL, DOMAIN_USER_DELIMITER, &nextToken);
			if (szTok0 != NULL)
			{
				if (szTok1 != NULL) // domain\user
				{
					_tcsncpy_s(domainUserInfo.domainName, szTok0, _tcslen(szTok0));
					_tcsncpy_s(domainUserInfo.userName, szTok1, _tcslen(szTok1));
				}
				else // user
				{
					*domainUserInfo.domainName = 0;
					_tcsncpy_s(domainUserInfo.userName, szTok0, _tcslen(szTok0));
				}
			}
			else
			{
				if (szTok1 != NULL) // \user
				{
					*domainUserInfo.domainName = 0;
					_tcsncpy_s(domainUserInfo.userName, szTok1, _tcslen(szTok1));
				}
				else // weird, hopefully unreachable case indicating _tcstok_s just didn't work at all
				{
					*domainUserInfo.domainName = 0;
					_tcsncpy_s(domainUserInfo.userName, szUser, _tcslen(szUser));
				}
			}
			if (m_pLogger->isEnabled(LogLevel::Debug))
				m_pLogger->logDebug("Extracted DomainName: \"%s\", UserName: \"%s\"", domainUserInfo.domainName, domainUserInfo.userName);
		}

		HANDLE createProcessWithToken(RemComMessage* pMsg, RemComResponse* pResponse)
		{
			DomainUserInfo userInfo;
			extractDomainUserInfo(pMsg, userInfo);

			bool runas = false; // winexe has a runas option. not sure if we want to support it, but including it for now just for information
			if (runas)
			{
				if (m_pLogger->isEnabled(LogLevel::Debug))
					m_pLogger->logDebug("Calling LogonUser");
				if (!LogonUser(userInfo.userName, userInfo.domainName, pMsg->getPassword(), LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &m_hToken))
				{
					writeLastError("Error getting logon token with supplied credentials");
					return INVALID_HANDLE_VALUE;
				}
				return m_hToken;
			}
			else
			{
				if (!ImpersonateNamedPipeClient(m_hCommPipe))
				{
					writeLastError("ImpersonateNamedPipeClient failed");
					return INVALID_HANDLE_VALUE;
				}
				if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &m_hToken))
				{
					writeLastError("OpenThreadToken failed");
					if (!RevertToSelf())
					{
						writeLastError("RevertToSelf failed");
					}
					return INVALID_HANDLE_VALUE;
				}
			}

			HANDLE hExtendedToken;
			if (!DuplicateTokenEx(m_hToken, MAXIMUM_ALLOWED, NULL, SECURITY_IMPERSONATION_LEVEL::SecurityImpersonation, TOKEN_TYPE::TokenPrimary, &hExtendedToken))
			{
				writeLastError("Could not get extended token information, proceeding with original logon token");
			}
			else
			{
				CloseHandle(m_hToken);
				m_hToken = hExtendedToken;
				if (m_pLogger->isEnabled(LogLevel::Debug))
					m_pLogger->logDebug("Successfully extended token");
			}

			LPTSTR szCommandLine = createCommandLine(pMsg);

			// Create the pipes that will be used for the spawned process's IO
			::ZeroMemory(&m_startupInfo, sizeof(m_startupInfo));
			m_startupInfo.cb = sizeof(m_startupInfo);
			if (!createProcessIoPipes(pMsg))
			{
				pResponse->dwStatusCode = RemComResponseStatus::IO_PIPES_CREATION_FAILED;
				return INVALID_HANDLE_VALUE;
			}
			m_startupInfo.dwFlags |= STARTF_USESTDHANDLES;

			// Tell the client it can now attach to the pipes
			pResponse->dwStatusCode = RemComResponseStatus::IO_PIPES_READY;
			DWORD dwWritten;
			if (!WriteFile(m_hCommPipe, pResponse, sizeof(RemComResponse), &dwWritten, NULL) || dwWritten == 0)
			{
				writeLastError("Could not send IO_PIPES_READY message to client");
				return INVALID_HANDLE_VALUE;
			}
			if (m_pLogger->isEnabled(LogLevel::Debug))
				m_pLogger->logDebug("Sent IO_PIPES_READY message to client");

			// Wait for client to connect to the io pipes
			if (m_pLogger->isEnabled(LogLevel::Debug))
				m_pLogger->logDebug("Connecting stdout pipe");
			if (!ConnectNamedPipe(m_startupInfo.hStdOutput, NULL))
			{
				m_pLogger->logError("Could not connnect stdout pipe");
			}
			if (m_pLogger->isEnabled(LogLevel::Debug))
				m_pLogger->logDebug("Connecting stdin pipe");
			if (!ConnectNamedPipe(m_startupInfo.hStdInput, NULL))
			{
				m_pLogger->logError("Could not connnect stdin pipe");
			}
			if (m_pLogger->isEnabled(LogLevel::Debug))
				m_pLogger->logDebug("Connecting stderr pipe");
			if (!ConnectNamedPipe(m_startupInfo.hStdError, NULL))
			{
				m_pLogger->logError("Could not connnect stderr pipe");
			}

			// Wait for client to tell us it has attached to the pipes
			if (m_pLogger->isEnabled(LogLevel::Debug))
				m_pLogger->logDebug("Waiting for IO_PIPES_ATTACHED message from client");
			DWORD dwRead;
			if (!ReadFile(m_hCommPipe, pResponse, sizeof(RemComResponse), &dwRead, NULL) || dwRead == 0)
			{
				writeLastError("Could not read IO_PIPES_ATTACHED message from client");
				return INVALID_HANDLE_VALUE;
			}
			if (pResponse->dwStatusCode != RemComResponseStatus::IO_PIPES_ATTACHED)
			{
				pResponse->dwStatusCode = RemComResponseStatus::CLIENT_PROTOCOL_ERROR;
				m_pLogger->logError("Expecting client to have sent status code %d, received %d", RemComResponseStatus::IO_PIPES_ATTACHED, pResponse->dwStatusCode);
				return INVALID_HANDLE_VALUE;
			}
			if (m_pLogger->isEnabled(LogLevel::Debug))
				m_pLogger->logDebug("Client sent IO_PIPES_ATTACHED message, proceeding with process creation");

			// Spawn the process
			DWORD dwCreationFlags = CREATE_DEFAULT_ERROR_MODE | CREATE_NO_WINDOW;
			if (CreateProcessAsUser(m_hToken, NULL, szCommandLine, NULL, NULL, TRUE,
				dwCreationFlags, NULL, NULL, &m_startupInfo, &m_processInfo))
			{
				if (m_pLogger->isEnabled(LogLevel::Debug))
					m_pLogger->logDebug("Created process id %d", m_processInfo.dwProcessId);
				delete szCommandLine;
				pResponse->dwStatusCode = RemComResponseStatus::PROCESS_STARTED;
				return m_processInfo.hProcess;
			}
			else
			{
				writeLastError("Error creating process");
				m_pLogger->logError("Process creation parameters:\n"
					"  lpUsername=%s\n"
					"  lpDomain=%s\n"
					"  lpCommandLine=%s\n"
					"  dwCreationFlags=%s\n"
					"  lpStartupInfo=%s\n"
					, display(userInfo.userName).c_str()
					, display(userInfo.domainName).c_str()
					, display(szCommandLine, 256).c_str()
					, displayCreationFlags(dwCreationFlags).c_str()
					, display(m_startupInfo).c_str()
				);
				delete szCommandLine;
				pResponse->dwStatusCode = RemComResponseStatus::PROCESS_CREATION_FAILED;
				return INVALID_HANDLE_VALUE;
			}
		}

		static void appendFlag(string& str, DWORD flags, DWORD bit, LPCTSTR flagName)
		{
			if (flags & bit)
			{
				if (str.length() > 0)
					str += "|";
				str += flagName;
			}
		}

		static const string displayCreationFlags(DWORD flags)
		{
			TCHAR fmtBuf[16];
			string str;
			str += displayHexInt(flags, fmtBuf);
			str += "(";
			string flagStr;
			appendFlag(flagStr, flags, CREATE_DEFAULT_ERROR_MODE, "CREATE_DEFAULT_ERROR_MODE");
			appendFlag(flagStr, flags, CREATE_NEW_CONSOLE, "CREATE_NEW_CONSOLE");
			appendFlag(flagStr, flags, CREATE_NEW_PROCESS_GROUP, "CREATE_NEW_PROCESS_GROUP");
			appendFlag(flagStr, flags, CREATE_NO_WINDOW, "CREATE_NO_WINDOW");
			appendFlag(flagStr, flags, CREATE_SEPARATE_WOW_VDM, "CREATE_SEPARATE_WOW_VDM");
			appendFlag(flagStr, flags, CREATE_SUSPENDED, "CREATE_SUSPENDED");
			appendFlag(flagStr, flags, CREATE_UNICODE_ENVIRONMENT, "CREATE_UNICODE_ENVIRONMENT");
			str += flagStr;
			str += ")";
			return str;
		}

		static const string displayLogonFlags(DWORD flags)
		{
			TCHAR fmtBuf[16];
			string str;
			str += displayHexInt(flags, fmtBuf);
			str += "(";
			string flagStr;
			appendFlag(flagStr, flags, LOGON_WITH_PROFILE, "LOGON_WITH_PROFILE");
			appendFlag(flagStr, flags, LOGON_NETCREDENTIALS_ONLY, "LOGON_NETCREDENTIALS_ONLY");
			str += flagStr;
			str += ")";
			return str;
		}

#define MAX_DISPLAY_STRING 32768
		static const string display(LPCWSTR value)
		{
			return display(value, MAX_DISPLAY_STRING);
		}

		static const string display(LPCWSTR value, size_t maxLength)
		{
			USES_CONVERSION;
			return display(W2T(value), maxLength);
		}

		static const string display(LPSTR value)
		{
			return display(value, MAX_DISPLAY_STRING);
		}

		static const string display(LPSTR value, size_t maxLength)
		{
			string str;
			if (value == NULL)
			{
				str += "NULL";
			}
			else
			{
				str += "\"";
				str += value;
				if (str.length() > maxLength + 1)
					str = str.substr(0, maxLength + 1);
				str += "\"";
			}
			return str;
		}

		static const string display(const STARTUPINFO& startupInfo)
		{
			USES_CONVERSION;
			TCHAR fmtBuf[256];
			stringstream s;
			s << "{";
			s << "\n    cb: " << startupInfo.cb << ",";
			s << "\n    cbReserved2: " << startupInfo.cbReserved2 << ",";
			s << "\n    dwFillAttribute: " << displayHexInt(startupInfo.dwFillAttribute, fmtBuf) << ",";
			s << "\n    dwFlags: " << displayHexInt(startupInfo.dwFlags, fmtBuf) << ",";
			s << "\n    dwX: " << startupInfo.dwX << ",";
			s << "\n    dwXCountChars: " << startupInfo.dwXCountChars << ",";
			s << "\n    dwXSize: " << startupInfo.dwXSize << ",";
			s << "\n    dwY: " << startupInfo.dwY << ",";
			s << "\n    dwYCountChars: " << startupInfo.dwYCountChars << ",";
			s << "\n    dwYSize: " << startupInfo.dwYSize << ",";
			s << "\n    hStdError: " << displayHexInt((LONG)startupInfo.hStdError, fmtBuf) << ",";
			s << "\n    hStdInput: " << displayHexInt((LONG)startupInfo.hStdInput, fmtBuf) << ",";
			s << "\n    hStdOutput: " << displayHexInt((LONG)startupInfo.hStdOutput, fmtBuf) << ",";
			s << "\n    lpTitle: " << display(startupInfo.lpTitle) << ",";
			s << "\n    wShowWindow: " << startupInfo.wShowWindow << ",";
			s << "\n  }";
			return s.str();
		}

		static const string display(const STARTUPINFOW& startupInfo)
		{
			USES_CONVERSION;
			TCHAR fmtBuf[256];
			stringstream s;
			s << "{";
			s << "\n    cb: " << startupInfo.cb << ",";
			s << "\n    cbReserved2: " << startupInfo.cbReserved2 << ",";
			s << "\n    dwFillAttribute: " << displayHexInt(startupInfo.dwFillAttribute, fmtBuf) << ",";
			s << "\n    dwFlags: " << displayHexInt(startupInfo.dwFlags, fmtBuf) << ",";
			s << "\n    dwX: " << startupInfo.dwX << ",";
			s << "\n    dwXCountChars: " << startupInfo.dwXCountChars << ",";
			s << "\n    dwXSize: " << startupInfo.dwXSize << ",";
			s << "\n    dwY: " << startupInfo.dwY << ",";
			s << "\n    dwYCountChars: " << startupInfo.dwYCountChars << ",";
			s << "\n    dwYSize: " << startupInfo.dwYSize << ",";
			s << "\n    hStdError: " << displayHexInt((LONG)startupInfo.hStdError, fmtBuf) << ",";
			s << "\n    hStdInput: " << displayHexInt((LONG)startupInfo.hStdInput, fmtBuf) << ",";
			s << "\n    hStdOutput: " << displayHexInt((LONG)startupInfo.hStdOutput, fmtBuf) << ",";
			s << "\n    lpTitle: " << display(startupInfo.lpTitle) << ",";
			s << "\n    wShowWindow: " << startupInfo.wShowWindow << ",";
			s << "\n  }";
			return s.str();
		}

		static LPCTSTR displayHexInt(LONG value, LPTSTR buf)
		{
			_stprintf_s(buf, 16, "0x%08X", value);
			return buf;
		}

		HANDLE createProcessAnonymously(RemComMessage* pMsg, DWORD* pReturnCode)
		{
			DWORD rc;
			PROCESS_INFORMATION pi;

			::ZeroMemory(&m_startupInfo, sizeof(m_startupInfo));

			// Create named pipes for stdout, stdin, stderr
			// Client will sit on these pipes
			if (!createProcessIoPipes(pMsg))
			{
				*pReturnCode = 2;
				return INVALID_HANDLE_VALUE;
			}

			*pReturnCode = 0;
			rc = 0;
			LPTSTR szCommand = createCommandLine(pMsg);
			LPCTSTR szWorkingDir = pMsg->getWorkingDirectory();
			szWorkingDir = szWorkingDir[0] != _T('\0') ? szWorkingDir : NULL;
			DWORD dwPriority = pMsg->getPriority() | CREATE_NO_WINDOW;
			if (CreateProcess(
				NULL,			// lpApplicationName
				szCommand,		// lpCommandLine
				NULL,			// lpProcessAttributes
				NULL,			// lpThreadAttributes
				TRUE,			// bInheritHandles	
				dwPriority,		// dwCreationFlags
				NULL,			// lpEnvironment
				szWorkingDir,	// lpCurrentDirectory
				&m_startupInfo, // lpStartupInfo
				&pi))			// lpProcessInformation
			{
				delete szCommand;
				*pReturnCode = 0;
				return pi.hProcess;
			}
			delete szCommand;
			*pReturnCode = 1;
			return INVALID_HANDLE_VALUE;
		}
	};

	DWORD ClientInstance::s_dwSvcPipeInstanceCount = 0;

	class Service : public Component
	{
	public:
		Service(bool interactive)
		{
			m_interactive = interactive;
		}

		void start()
		{
			initFromRegistry();

			if (m_pLogger->isEnabled(LogLevel::Info))
				m_pLogger->logInfo("Starting version 20180829.1");

			// Start CommunicationPoolThread, which handles the incoming instances
			_beginthread(RemCom::Service::CommunicationPoolThread, 0, this);
		}

		void stop()
		{
			if (m_pLogger->isEnabled(LogLevel::Info))
				m_pLogger->logInfo("Shutting down");
			//TODO Gracefully shut down the processing thread
		}

	private:
		bool m_interactive;
		ofstream m_logStream;
		vector<ClientInstance*> m_clientInstances;
		mutex m_clientMutex;

		void initFromRegistry()
		{
			m_pLogger = NULL;
			HKEY hRegKey;
			if (openRegistry(&hRegKey))
			{
				initLogger(hRegKey);
			}
			if (m_pLogger == NULL) 
			{
				if (m_interactive)
				{
					// Log to cout when running interactively
					m_pLogger = new Logger(cout, LogLevel::Trace);
				}
				else
				{
					// Otherwise create a null logger
					m_pLogger = new Logger(NULL, 0, LogLevel::Fatal);
				}
			}
		}

		void initLogger(HKEY hRegKey)
		{
			USES_CONVERSION;

			wstring strLogFilePath;
			LogLevel minLogLevel = LogLevel::Trace;
			if (getStringRegKey(hRegKey, L"LogFilePath", strLogFilePath, L"") == ERROR_SUCCESS)
			{
				minLogLevel = lookupMinLogLevel(hRegKey);
				char* szLogFilePath = W2A(strLogFilePath.c_str());
				m_logStream.open(szLogFilePath, ios_base::out | ios_base::in | ios_base::app);
				if (m_interactive)
				{
					pOstream *streams = new pOstream[2] { &cout, &m_logStream };
					m_pLogger = new Logger(streams, 2, minLogLevel);
				}
				else
				{
					pOstream *streams = new pOstream[1] { &m_logStream };
					m_pLogger = new Logger(streams, 1, minLogLevel);
				}
			}
		}

		LogLevel lookupMinLogLevel(HKEY hKey)
		{
			LogLevel minLogLevel = LogLevel::Error;
			wstring strMinLogLevel;
			if (getStringRegKey(hKey, L"MinLogLevel", strMinLogLevel, L"") == ERROR_SUCCESS)
			{
				const wchar_t* wszMinLogLevel = strMinLogLevel.c_str();
				if (_wcsicmp(wszMinLogLevel, L"trc") == 0 || _wcsicmp(wszMinLogLevel, L"trace") == 0)
					minLogLevel = LogLevel::Trace;
				else if (_wcsicmp(wszMinLogLevel, L"dbg") == 0 || _wcsicmp(wszMinLogLevel, L"debug") == 0)
					minLogLevel = LogLevel::Debug;
				else if (_wcsicmp(wszMinLogLevel, L"inf") == 0 || _wcsicmp(wszMinLogLevel, L"info") == 0)
					minLogLevel = LogLevel::Info;
				else if (_wcsicmp(wszMinLogLevel, L"wrn") == 0 || _wcsicmp(wszMinLogLevel, L"warn") == 0)
					minLogLevel = LogLevel::Warn;
				else if (_wcsicmp(wszMinLogLevel, L"err") == 0 || _wcsicmp(wszMinLogLevel, L"error") == 0)
					minLogLevel = LogLevel::Error;
				else if (_wcsicmp(wszMinLogLevel, L"crt") == 0 || _wcsicmp(wszMinLogLevel, L"critical") == 0)
					minLogLevel = LogLevel::Critical;
				else if (_wcsicmp(wszMinLogLevel, L"fat") == 0 || _wcsicmp(wszMinLogLevel, L"fatal") == 0)
					minLogLevel = LogLevel::Fatal;
			}
			return minLogLevel;
		}

		static void CommunicationPoolThread(PVOID pThis)
		{
			Service* pInstance = (Service*)pThis;
			pInstance->runCommunicationPoolThread();
		}

		// Communication Thread Pool, handles the incoming RemCom.exe requests
		void runCommunicationPoolThread()
		{	
			if (m_pLogger->isEnabled(LogLevel::Debug))
				m_pLogger->logDebug("Starting communication pool thread");
			LPTSTR szCommPipeName = "\\\\.\\pipe\\" RemComCOMM;
			for (;;)
			{
				DWORD pipeMode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT;
				size_t numInstances = m_clientInstances.size();
				if (m_pLogger->isEnabled(LogLevel::Debug))
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
						if (m_pLogger->isEnabled(LogLevel::Debug))
							m_pLogger->logDebug("Client connected, creating client instance");
						ClientInstance* client = new ClientInstance(hCommPipe, m_pLogger);
						if (m_pLogger->isEnabled(LogLevel::Debug))
							m_pLogger->logDebug("Adding client to instance collection");
						m_clientInstances.push_back(client);
						if (m_pLogger->isEnabled(LogLevel::Debug))
							m_pLogger->logDebug("Starting client");
						try
						{
							function<void()> shutdownCallback = [&]() { removeClientInstance(client); };
							client->start(shutdownCallback);
							if (m_pLogger->isEnabled(LogLevel::Debug))
								m_pLogger->logDebug("Called client->start");
						}
						catch (...)
						{
							if (m_pLogger->isEnabled(LogLevel::Debug))
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
			if (m_pLogger->isEnabled(LogLevel::Debug))
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
	RemCom::Service service(false);

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


void RunInteractively()
{
	try
	{
		RemCom::Service service(true);

		service.start();

		boolean stop = false;
		while (!stop)
		{
			for (std::string line; std::getline(std::cin, line);)
			{
				std::cout << line << std::endl;
			}
		}
	}
	catch (...)
	{
		std::cerr << "Uncaught error occurred, press Enter to continue";
		std::string strInput;
		std::cin >> strInput;
	}
}