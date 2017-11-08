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

	$Date: 2006/10/04 09:00:00 $

	$Version History: $			- Refactored and Restructured Code - Deleted Unnecessary variables and Functions for Memory Consumption and Optimisation.
								- Added Function StartLocalProcessAsUser for local user impersonation
								- Added Start Local Process for launching external commands
								- Added GetAdminSid, GetLocalSid, GetLogonSID, FreeLogonSid for getting tokens to pass on for logon impersonation
								- Added IsLaunchedFromAdmin to get the local admin sid
								- Added ExtractLocalBinaryResource to extract the local binary resource for local process impersonation
								- Added ProcComs to implement local  process functionality
								- Added RemCom   to implement remote process functionality

	$TODO:						- Add Getopt to parse command line parametres more effectively.
								- Implemement cleanup and disconnect remote share command

	$Description: $				- RemCom is RAT [Remote Administration Tool] that lets you execute processes on remote windows systems, copy files,
								  process there output and stream it back. It allows execution of remote shell commands directly with full interactive console

	$Workfile: $				- RemCom.cpp
 */


#define _WIN32_WINNT 0x0500 //Will work only on W2K and above 

#include "RemCom.h"
#include "RemComMessage.h"
#include "Logger.h"

#define		DESKTOP_ALL (DESKTOP_READOBJECTS | DESKTOP_CREATEWINDOW | \
			DESKTOP_CREATEMENU | DESKTOP_HOOKCONTROL | DESKTOP_JOURNALRECORD | \
			DESKTOP_JOURNALPLAYBACK | DESKTOP_ENUMERATE | DESKTOP_WRITEOBJECTS | \
			DESKTOP_SWITCHDESKTOP | STANDARD_RIGHTS_REQUIRED)

#define		WINSTA_ALL (WINSTA_ENUMDESKTOPS | WINSTA_READATTRIBUTES | \
			WINSTA_ACCESSCLIPBOARD | WINSTA_CREATEDESKTOP | WINSTA_WRITEATTRIBUTES | \
			WINSTA_ACCESSGLOBALATOMS | WINSTA_EXITWINDOWS | WINSTA_ENUMERATE | \
			WINSTA_READSCREEN | STANDARD_RIGHTS_REQUIRED)

#define		GENERIC_ACCESS (GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL)

 // Constant Definitions
#define		SIZEOF_BUFFER   0x100
#define		LOG_BUFFER_SIZE	4096

namespace RemCom
{
	using namespace std;

	class RemCom
	{
	public:
		RemCom() : m_logger(cerr, LogLevel::Error, LOG_BUFFER_SIZE)
		{
		}

		int run()
		{
			int   rc = 0;
			DWORD dwTemp = SIZEOF_BUFFER;
			DWORD dwIndex = 0;

			LPCTSTR minLogLevel = getParamValue("v:");
			if (minLogLevel != NULL)
				m_logger.setMinLogLevel(minLogLevel);

			m_lpszMachine = getRemoteMachineName();

			m_lpszCommandExe = getNthParameter(2, dwIndex);

			getRemoteCommandArguments(m_strArguments);

			// Show help, if parameters are incorrect, or /?,/h,/help
			if (isCmdLineParameter("h") ||
				isCmdLineParameter("?") ||
				isCmdLineParameter("help") ||
				m_lpszCommandExe == NULL ||
				m_lpszMachine == NULL)
			{
				showUsage();
				return -1;
			}

			// Initialize console's title
			m_strConsoleTitle = m_lpszMachine;
			m_strConsoleTitle += " : Starting Connection to: ";
			SetConsoleTitle(m_strConsoleTitle.c_str());

			// Sets our Ctrl handler
			SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

			// Gets our computer's name
			TCHAR lpszThisMachine[MAX_COMPUTERNAME_LENGTH + 1];
			if (!GetComputerName(lpszThisMachine, &dwTemp))
			{
				cout << "GetComputerName() failed. Use a valid name! :)\n" << flush;
				return -3;
			}
			m_strThisMachine = lpszThisMachine;

			// Check the user/pwd from command line, and prompts for the password if needed
			if (!setConnectionCredentials(FALSE))
			{
				rc = -2;
				cleanup();
				return rc;
			}

			rc = runOnRemoteMachine();

			cleanup();

			return rc;
		}

	private:
		Logger		m_logger;

		// Local Machine Settings
		string		m_strThisMachine;
		string		m_strPassword;
		string		m_strArguments;
		string		m_strConsoleTitle;
		string		m_strLocalBinPath;

		// Remote Parameters
		LPCTSTR		m_lpszMachine = NULL;
		LPCTSTR		m_lpszPassword = NULL;
		LPCTSTR		m_lpszUser = NULL;
		LPCTSTR		m_lpszDomain = NULL;
		LPCTSTR		m_lpszCommandExe = NULL;

		// Named Pipes for Input and Output
		HANDLE		m_hCommandPipe = INVALID_HANDLE_VALUE;
		HANDLE		m_hRemoteOutPipe = INVALID_HANDLE_VALUE;
		HANDLE		m_hRemoteStdInputPipe = INVALID_HANDLE_VALUE;
		HANDLE		m_hRemoteErrorPipe = INVALID_HANDLE_VALUE;

		// Show the last error's description
		DWORD showLastError()
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

			cerr << (LPCTSTR)lpvMessageBuffer << "\n";

			LocalFree(lpvMessageBuffer);
			//ExitProcess(GetLastError());
			return rc;
		}

		//Gets the SID for Admin
		void* getAdminSid()
		{
			SID_IDENTIFIER_AUTHORITY ntauth = SECURITY_NT_AUTHORITY;

			void* psid = 0;

			if (!AllocateAndInitializeSid(&ntauth, 2,
				SECURITY_BUILTIN_DOMAIN_RID,
				DOMAIN_ALIAS_RID_ADMINS,
				0, 0, 0, 0, 0, 0, &psid))

				showLastError();

			return psid;
		}

		// Gets the SID for System Account
		void* getLocalSystemSid()
		{
			SID_IDENTIFIER_AUTHORITY ntauth = SECURITY_NT_AUTHORITY;

			void* psid = 0;

			if (!AllocateAndInitializeSid(&ntauth, 1,
				SECURITY_LOCAL_SYSTEM_RID,
				0, 0, 0, 0, 0, 0, 0, &psid))

				showLastError();

			return psid;
		}

		// Checks if the launching process parent is local administrator
		bool isLaunchedFromAdmin()
		{
			bool bIsAdmin = false;

			HANDLE hToken = 0;

			if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
				showLastError();
			}

			DWORD cb = 0;

			GetTokenInformation(hToken, TokenGroups, 0, 0, &cb);

			TOKEN_GROUPS* pTokenGroups = (TOKEN_GROUPS*)malloc(cb);

			if (!pTokenGroups)
				showLastError();

			if (!GetTokenInformation(hToken, TokenGroups, pTokenGroups, cb, &cb))
				showLastError();

			void* pAdminSid = getAdminSid();

			SID_AND_ATTRIBUTES* const end = pTokenGroups->Groups + pTokenGroups->GroupCount;

			SID_AND_ATTRIBUTES* it;
			for (it = pTokenGroups->Groups; end != it; ++it)
				if (EqualSid(it->Sid, pAdminSid))
					break;

			bIsAdmin = end != it;

			FreeSid(pAdminSid);
			free(pTokenGroups);
			CloseHandle(hToken);

			return bIsAdmin;
		}

		VOID freeLogonSID(PSID *ppsid)
		{
			HeapFree(GetProcessHeap(), 0, (LPVOID)*ppsid);
		}

		bool getLogonSID(HANDLE hToken, PSID *ppsid)
		{
			BOOL bSuccess = false;
			DWORD dwIndex;
			DWORD dwLength = 0;
			PTOKEN_GROUPS ptg = NULL;

			// Verify the parameter passed in is not NULL.
			if (NULL == ppsid)
				goto Cleanup;

			// Get required buffer size and allocate the TOKEN_GROUPS buffer.

			if (!GetTokenInformation(
				hToken,         // handle to the access token
				TokenGroups,    // get information about the token's groups 
				(LPVOID)ptg,   // pointer to TOKEN_GROUPS buffer
				0,              // size of buffer
				&dwLength       // receives required buffer size
			))
			{
				if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
					goto Cleanup;

				ptg = (PTOKEN_GROUPS)HeapAlloc(GetProcessHeap(),
					HEAP_ZERO_MEMORY, dwLength);

				if (ptg == NULL)
					goto Cleanup;
			}

			// Get the token group information from the access token.

			if (!GetTokenInformation(
				hToken,         // handle to the access token
				TokenGroups,    // get information about the token's groups 
				(LPVOID)ptg,   // pointer to TOKEN_GROUPS buffer
				dwLength,       // size of buffer
				&dwLength       // receives required buffer size
			))
			{
				goto Cleanup;
			}

			// Loop through the groups to find the logon SID.

			for (dwIndex = 0; dwIndex < ptg->GroupCount; dwIndex++)
				if ((ptg->Groups[dwIndex].Attributes & SE_GROUP_LOGON_ID)
					== SE_GROUP_LOGON_ID)
				{
					// Found the logon SID; make a copy of it.

					dwLength = GetLengthSid(ptg->Groups[dwIndex].Sid);
					*ppsid = (PSID)HeapAlloc(GetProcessHeap(),
						HEAP_ZERO_MEMORY, dwLength);
					if (*ppsid == NULL)
						goto Cleanup;
					if (!CopySid(dwLength, *ppsid, ptg->Groups[dwIndex].Sid))
					{
						HeapFree(GetProcessHeap(), 0, (LPVOID)*ppsid);
						goto Cleanup;
					}
					break;
				}

			bSuccess = true;

		Cleanup:

			// Free the buffer for the token groups.

			if (ptg != NULL)
				HeapFree(GetProcessHeap(), 0, (LPVOID)ptg);

			return bSuccess;
		}


		// Check the command line arguments
		bool isCmdLineParameter(LPCTSTR lpszParam)
		{
			for (int i = 1; i < __argc; i++)
				if (__targv[i][0] == _T('\\'))
					continue;
				else
					if (__targv[i][0] == _T('/') || __targv[i][0] == _T('-'))
					{
						if (_tcsicmp(__targv[i] + 1, lpszParam) == 0)
							return true;
					}
					else
						return false;

			return false;
		}

		LPCTSTR getParamValue(LPCTSTR lpszParam)
		{
			DWORD dwParamLength = _tcslen(lpszParam);

			for (int i = 1; i < __argc; i++)
				if (__targv[i][0] == _T('\\') || __targv[i][0] == _T('.'))
					continue;
				else
					if (__targv[i][0] == _T('/') || __targv[i][0] == _T('-'))
					{
						if (_tcsnicmp(__targv[i] + 1, lpszParam, dwParamLength) == 0)
							return __targv[i] + dwParamLength + 1;
					}
					else
						return NULL;

			return NULL;
		}

		LPCTSTR getNthParameter(DWORD n, DWORD& argvIndex)
		{
			DWORD index = 0;

			for (int i = 1; i < __argc; i++)
			{
				if (__targv[i][0] != _T('/') && __targv[i][0] != _T('-'))
					index++;

				if (index == n)
				{
					argvIndex = i;
					return __targv[i];
				}
			}

			return NULL;
		}

		// Gets the arguments parameter
		void getRemoteCommandArguments(string strCommandArguments)
		{
			DWORD dwIndex = 0;
			strCommandArguments = "";

			if (getNthParameter(3, dwIndex) != NULL)
				for (int i = dwIndex; i < __argc; i++)
				{
					strCommandArguments += __targv[i];
					if (i + 1 < __argc)
						strCommandArguments += " ";
				}
		}

		// Gets the remote machine parameter
		LPCTSTR getRemoteMachineName()
		{
			DWORD dwIndex = 0;
			LPCTSTR lpszMachine = getNthParameter(1, dwIndex);

			if (lpszMachine == NULL)
				return LOOPBACKIP;

			if (_tcsnicmp(lpszMachine, " ", 2) == 0)
				return LOOPBACKIP;

			if (_tcsnicmp(lpszMachine, "\\\\", 2) == 0)
				return lpszMachine;

			// If a dot is entered we take it as localhost
			if (_tcsnicmp(lpszMachine, ".", 2) == 0)
				return LOOPBACKIP;

			return NULL;
		}

		// Turns off the echo on a console input handle - Used for hiding password typing
		bool enableEcho(HANDLE handle, BOOL bEcho)
		{
			DWORD mode;

			if (!GetConsoleMode(handle, &mode))
				return false;

			if (bEcho)
				mode |= ENABLE_ECHO_INPUT;
			else
				mode &= ~ENABLE_ECHO_INPUT;

			return SetConsoleMode(handle, mode);
		}

		// Gets the password
		bool promptForPassword()
		{
			HANDLE hInput = GetStdHandle(STD_INPUT_HANDLE);
			DWORD dwRead = 0;

			cout << "Enter Password: " << flush;

			// Turn off echo
			if (enableEcho(hInput, false))
			{
				TCHAR lpszPwd[SIZEOF_BUFFER];
				// Read password from console
				::ReadConsole(hInput, lpszPwd, SIZEOF_BUFFER, &dwRead, NULL);

				// Ignore ENTER (0x0D0A) 
				lpszPwd[max(dwRead - 2, 0)] = _T('\0');

				m_strPassword = lpszPwd;

				// Turn echo on
				enableEcho(hInput, true);

				cout << "\n\n" << flush;
			}
			else
			{
				//Console input doesn't support echo on/off
				cout << "\n" << flush;
				cerr << "Couldn't turn off echo to hide password chars.\n";
			}

			return true;
		}

		bool setConnectionCredentials(bool bPromptForPassword)
		{
			// Check the command line
			m_lpszPassword = getParamValue("pwd:");
			m_lpszUser = getParamValue("user:");

			if (m_lpszUser != NULL && m_lpszPassword != NULL && !bPromptForPassword)
				if (_tcscmp(m_lpszPassword, "*") == 0)
					// We found user name, and * as password, which means prompt for password
					bPromptForPassword = true;

			if (bPromptForPassword)
			{
				// We found user name, and * as password, which means prompt for password
				m_lpszPassword = m_strPassword.c_str();
				if (!promptForPassword())
					return false;
			}

			return true;
		}

		// Establish Connection to Remote Machine
		bool establishConnection(LPCTSTR lpszRemote, LPCTSTR lpszResource, bool bEstablish)
		{
			// Remote resource, \\remote\ipc$, remote\admin$, ...
			stringstream strRemoteResource;
			strRemoteResource << lpszRemote << "\\" << lpszResource;
			auto str = strRemoteResource.str();
			auto c_str = str.c_str();
			LPTSTR szRemoteResource = const_cast<LPTSTR>(c_str);

			//
			// disconnect or connect to the resource, based on bEstablish
			//
			DWORD rc;

			if (bEstablish)
			{
				NETRESOURCE nr;
				nr.dwType = RESOURCETYPE_ANY;
				nr.lpLocalName = NULL;
				nr.lpRemoteName = szRemoteResource;
				nr.lpProvider = NULL;

				//Establish connection (using username/pwd)
				m_logger.logInfo("Establishing connection to %s", szRemoteResource);
				rc = WNetAddConnection2(&nr, m_lpszPassword, m_lpszUser, FALSE);

				switch (rc)
				{
				case ERROR_ACCESS_DENIED:
				case ERROR_INVALID_PASSWORD:
				case ERROR_LOGON_FAILURE:
				case ERROR_SESSION_CREDENTIAL_CONFLICT:
					// Prompt for password if the default(NULL) was not good
					if (m_lpszUser != NULL && m_lpszPassword == NULL)
					{
						cout << "Invalid password\n\n" << flush;
						setConnectionCredentials(TRUE);
						cout << "Connecting to remote service ... " << flush;
						//Establish connection (using username/pwd) again
						rc = WNetAddConnection2(&nr, m_lpszPassword, m_lpszUser, FALSE);
					}
					break;
				}
			}
			else
			{
				// Disconnect
				m_logger.logDebug("Disconnecting from %s", szRemoteResource);
				rc = WNetCancelConnection2(szRemoteResource, 0, NULL);
			}

			if (rc == NO_ERROR)
				return true; // indicate success

			SetLastError(rc);

			return false;
		}

		// Copies the command's exe file to remote machine (\\remote\ADMIN$\System32)
		// This function called, if the /c option is used
		bool copyBinaryToRemoteSystem()
		{
			if (!isCmdLineParameter("c"))
				return true;

			TCHAR drive[_MAX_DRIVE];
			TCHAR dir[_MAX_DIR];
			TCHAR fname[_MAX_FNAME];
			TCHAR ext[_MAX_EXT];

			// Gets the file name and extension
			_splitpath_s(m_lpszCommandExe, drive, dir, fname, ext);
			stringstream strRemoteResource;
			strRemoteResource << m_lpszMachine << "\\ADMIN$\\System32\\" << fname << ext;
			const char* szRemoteResource = strRemoteResource.str().c_str();

			// Copy the Command's exe file to \\remote\ADMIN$\System32
			m_logger.logDebug("Copying file to %s", szRemoteResource);
			return CopyFile(m_lpszCommandExe, szRemoteResource, FALSE);
		}

		// Copies the Local Process Launcher Executable from Self Resource -> Copies to Current Path 
		bool ExtractLocalBinaryResource()
		{
			DWORD dwWritten = 0;

			HMODULE hInstance = ::GetModuleHandle(NULL);

			// Find the binary file in resources
			HRSRC hLocalBinRes = ::FindResource(
				hInstance,
				MAKEINTRESOURCE(IDR_ProcComs),
				"ProcComs");

			HGLOBAL hLocalBinary = ::LoadResource(
				hInstance,
				hLocalBinRes);

			LPVOID pLocalBinary = ::LockResource(hLocalBinary);

			if (pLocalBinary == NULL)
				return false;

			DWORD dwLocalBinarySize = ::SizeofResource(
				hInstance,
				hLocalBinRes);
			TCHAR lpTestBuffer[1];
			DWORD dwPathLen = GetCurrentDirectory(1, lpTestBuffer);
			if (dwPathLen > 0)
			{
				TCHAR* lpDirBuffer = new TCHAR[dwPathLen];
				GetCurrentDirectory(dwPathLen, lpDirBuffer);
				lpDirBuffer[dwPathLen] = 0;
				m_strLocalBinPath = lpDirBuffer;
				m_strLocalBinPath += "\\";
				delete lpDirBuffer;
			}
			else
				m_strLocalBinPath = "";

			m_strLocalBinPath += ProcComs;

			HANDLE hFileLocalBinary = CreateFile(
				m_strLocalBinPath.c_str(),
				GENERIC_WRITE,
				0,
				NULL,
				CREATE_ALWAYS,
				FILE_ATTRIBUTE_NORMAL,
				NULL);
			if (hFileLocalBinary == INVALID_HANDLE_VALUE)
				return false;

			WriteFile(hFileLocalBinary, pLocalBinary, dwLocalBinarySize, &dwWritten, NULL);
			CloseHandle(hFileLocalBinary);

			return dwWritten == dwLocalBinarySize;
		}

		// Extracts the Service Executable from Self Resource -> Pushes to the remote machine
		bool copyServiceToRemoteMachine()
		{
			DWORD dwWritten = 0;

			HMODULE hInstance = ::GetModuleHandle(NULL);

			// Find the binary file in resources
			HRSRC hSvcExecutableRes = ::FindResource(
				hInstance,
				MAKEINTRESOURCE(IDR_RemComSVC),
				"RemComSVC");

			HGLOBAL hSvcExecutable = ::LoadResource(
				hInstance,
				hSvcExecutableRes);

			LPVOID pSvcExecutable = ::LockResource(hSvcExecutable);

			if (pSvcExecutable == NULL)
				return FALSE;

			DWORD dwSvcExecutableSize = ::SizeofResource(
				hInstance,
				hSvcExecutableRes);

			string strSvcExePath = m_lpszMachine;
			strSvcExePath += "\\ADMIN$\\System32\\RemComSvc";
			//time_t now = std::time(NULL);
			//char timeBuf[100];
			//struct tm current;
			//gmtime_s(&current, &now);
			//strftime(timeBuf, sizeof(timeBuf), "%Y%m%d%H%M%S", &current);
			//strSvcExePath += ".";
			//strSvcExePath += timeBuf;
			strSvcExePath += ".exe";

			// Copy binary file from resources to \\remote\ADMIN$\System32
			m_logger.logInfo("Creating service file %s", strSvcExePath.c_str());
			HANDLE hFileSvcExecutable = CreateFile(
				strSvcExePath.c_str(),
				GENERIC_WRITE,
				0,
				NULL,
				CREATE_ALWAYS,
				FILE_ATTRIBUTE_NORMAL,
				NULL);

			if (hFileSvcExecutable == INVALID_HANDLE_VALUE)
				return false;

			m_logger.logDebug("Writing %d bytes to service file", dwSvcExecutableSize);
			WriteFile(hFileSvcExecutable, pSvcExecutable, dwSvcExecutableSize, &dwWritten, NULL);

			CloseHandle(hFileSvcExecutable);

			return dwWritten == dwSvcExecutableSize;
		}

		// Installs and starts the remote service on remote machine
		bool installAndStartRemoteService()
		{
			// Open remote Service Manager
			m_logger.logInfo("Opening service manager on %s", m_lpszMachine);
			SC_HANDLE hSCM = ::OpenSCManager(m_lpszMachine, NULL, SC_MANAGER_ALL_ACCESS);

			if (hSCM == NULL)
				return false;

			// Maybe it's already there and installed, let's try to run
			SC_HANDLE hService = ::OpenService(hSCM, SERVICENAME, SERVICE_ALL_ACCESS);

			// Creates service on remote machine, if it's not installed yet
			if (hService == NULL)
			{
				m_logger.logInfo("Creating service %s\n", SERVICENAME);
				hService = ::CreateService(
					hSCM, SERVICENAME, LONGSERVICENAME,
					SERVICE_ALL_ACCESS,
					SERVICE_WIN32_OWN_PROCESS,
					SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
					SYSTEM32 "\\" RemComSVCEXE,
					NULL, NULL, NULL, NULL, NULL);
			}

			if (hService == NULL)
			{
				::CloseServiceHandle(hSCM);
				m_logger.logError("Could not create service");
				return false;
			}

			// Start service
			m_logger.logInfo("Starting service");
			if (!StartService(hService, 0, NULL))
			{
				m_logger.logError("Could not start service");
				return false;
			}

			::CloseServiceHandle(hService);
			::CloseServiceHandle(hSCM);

			return true;
		}

		// Connects to the remote service
		bool connectToRemoteService(DWORD dwRetry, DWORD dwRetryTimeOut)
		{
			// Remote service communication pipe name
			stringstream strPipeName;
			strPipeName << m_lpszMachine << "\\pipe\\" << RemComCOMM;
			const string& tmpPipeName = strPipeName.str();
			const char* szPipeName = tmpPipeName.c_str();

			SECURITY_ATTRIBUTES SecAttrib = { 0 };
			SECURITY_DESCRIPTOR SecDesc;
			InitializeSecurityDescriptor(&SecDesc, SECURITY_DESCRIPTOR_REVISION);
			SetSecurityDescriptorDacl(&SecDesc, TRUE, NULL, TRUE);

			SecAttrib.nLength = sizeof(SECURITY_ATTRIBUTES);
			SecAttrib.lpSecurityDescriptor = &SecDesc;;
			SecAttrib.bInheritHandle = TRUE;

			// Connects to the remote service's communication pipe
			while (dwRetry--)
			{
				m_logger.logDebug("Connecting to remote service communication pipe %s", szPipeName);
				if (WaitNamedPipe(szPipeName, 5000))
				{
					m_hCommandPipe = CreateFile(
						szPipeName,
						GENERIC_WRITE | GENERIC_READ,
						0,
						&SecAttrib,
						OPEN_EXISTING,
						FILE_ATTRIBUTE_NORMAL,
						NULL);

					break;
				}
				else
				{
					m_logger.logWarn("Could not connect, waiting %d ms", dwRetryTimeOut);
					// Try Again
					Sleep(dwRetryTimeOut);
				}
			}

			if (m_hCommandPipe != INVALID_HANDLE_VALUE)
			{
				//cout << "Connected, changing to message read mode" << endl;
				//DWORD dwMode = PIPE_READMODE_MESSAGE;
				//if (!SetNamedPipeHandleState(
				//	m_hCommandPipe,
				//	&dwMode,
				//	NULL,	// don't set maximum bytes
				//	NULL))	// don't set maximum time
				//{
				//	return false;
				//}
				return true;
			}

			return false;
		}

		// Fill the communication message structure
		// This structure will be transferred to remote machine
		bool buildMessageStructure(RemComMessage* pMsg)
		{
			const char* szArguments = m_strArguments.c_str();

			// Info
			pMsg->setProcessId(GetCurrentProcessId());
			pMsg->setMachine(m_strThisMachine.c_str());

			// Cmd
			if (!isCmdLineParameter("c"))
				*pMsg << m_lpszCommandExe << " " << szArguments;
			else
			{
				TCHAR drive[_MAX_DRIVE];
				TCHAR dir[_MAX_DIR];
				TCHAR fname[_MAX_FNAME];
				TCHAR ext[_MAX_EXT];

				_splitpath_s(m_lpszCommandExe, drive, dir, fname, ext);

				*pMsg << fname << ext << " " << szArguments;
			}

			// Priority
			if (isCmdLineParameter("realtime"))
				pMsg->setPriority(REALTIME_PRIORITY_CLASS);
			else
				if (isCmdLineParameter("high"))
					pMsg->setPriority(HIGH_PRIORITY_CLASS);
				else
					if (isCmdLineParameter("idle"))
						pMsg->setPriority(IDLE_PRIORITY_CLASS);
					else
						pMsg->setPriority(NORMAL_PRIORITY_CLASS); // default

			// No wait
			pMsg->setNoWait(isCmdLineParameter("nowait"));

			LPCTSTR lpszWorkingDir = getParamValue("d:");
			if (lpszWorkingDir != NULL)
				pMsg->setWorkingDirectory(lpszWorkingDir);

			// Console Title
			m_strConsoleTitle = m_lpszMachine;
			m_strConsoleTitle += " : ";
			string command;
			pMsg->getCommand(command);
			m_strConsoleTitle += command;
			SetConsoleTitle(m_strConsoleTitle.c_str());

			return true;
		}

		// Listens the remote stdout pipe
		// Remote process will send its stdout to this pipe
		static void ListenRemoteOutPipeThread(void* pThis)
		{
			RemCom* pInstance = (RemCom*)pThis;
			pInstance->listenToRemoteOutPipe();
		}

		void listenToRemoteOutPipe()
		{
			HANDLE hOutput = GetStdHandle(STD_OUTPUT_HANDLE);
			TCHAR szBuffer[SIZEOF_BUFFER+1];
			DWORD dwRead;

			for (;;)
			{
				if (!ReadFile(m_hRemoteOutPipe, szBuffer, SIZEOF_BUFFER, &dwRead, NULL) ||
					dwRead == 0)
				{
					DWORD dwErr = GetLastError();
					if (dwErr == ERROR_NO_DATA)
						break;
				}

				// Handle CLS command, just for fun :)
				switch (szBuffer[0])
				{
				case 12: //cls
				{
					DWORD dwWritten;
					COORD origin = { 0,0 };
					CONSOLE_SCREEN_BUFFER_INFO sbi;

					if (GetConsoleScreenBufferInfo(hOutput, &sbi))
					{
						FillConsoleOutputCharacter(
							hOutput,
							_T(' '),
							sbi.dwSize.X * sbi.dwSize.Y,
							origin,
							&dwWritten);

						SetConsoleCursorPosition(
							hOutput,
							origin);
					}
				}
				continue;
				break;
				}

				szBuffer[dwRead / sizeof(TCHAR)] = _T('\0');

				// Send it to our stdout
				cout << szBuffer << flush;
			}

			CloseHandle(m_hRemoteOutPipe);

			m_hRemoteOutPipe = INVALID_HANDLE_VALUE;

			::ExitThread(0);
		}

		// Listens the remote stderr pipe
		// Remote process will send its stderr to this pipe
		static void ListenRemoteErrorPipeThread(void* pThis)
		{
			RemCom* pInstance = (RemCom*)pThis;
			pInstance->listenToRemoteErrorPipe();
		}

		void listenToRemoteErrorPipe()
		{
			TCHAR szBuffer[SIZEOF_BUFFER+1];
			DWORD dwRead;

			for (;;)
			{
				if (!ReadFile(m_hRemoteErrorPipe, szBuffer, SIZEOF_BUFFER, &dwRead, NULL) ||
					dwRead == 0)
				{
					DWORD dwErr = GetLastError();
					if (dwErr == ERROR_NO_DATA)
						break;
				}

				szBuffer[dwRead / sizeof(TCHAR)] = _T('\0');

				// Write it to our stderr
				cerr << szBuffer;
			}

			CloseHandle(m_hRemoteErrorPipe);

			m_hRemoteErrorPipe = INVALID_HANDLE_VALUE;

			::ExitThread(0);
		}

		// Listens our console, and if the user types in something,
		// we will pass it to the remote machine.
		// ReadConsole return after pressing the ENTER
		static void ListenRemoteStdInputPipeThread(void* pThis)
		{
			RemCom* pInstance = (RemCom*)pThis;
			pInstance->listenToRemoteStdInputPipe();
		}

		void listenToRemoteStdInputPipe()
		{
			HANDLE hInput = GetStdHandle(STD_INPUT_HANDLE);
			TCHAR szInputBuffer[SIZEOF_BUFFER+1] = "";
			DWORD nBytesRead;
			DWORD nBytesWrote;

			for (;;)
			{
				// Read our console input
				if (!ReadConsole(hInput, szInputBuffer, SIZEOF_BUFFER, &nBytesRead, NULL))
				{
					DWORD dwErr = GetLastError();
					if (dwErr == ERROR_NO_DATA)
						break;
				}

				// Send it to remote process' stdin
				if (!WriteFile(m_hRemoteStdInputPipe, szInputBuffer, nBytesRead, &nBytesWrote, NULL))
					break;
			}

			CloseHandle(m_hRemoteStdInputPipe);

			m_hRemoteStdInputPipe = INVALID_HANDLE_VALUE;

			::ExitThread(0);
		}

		// Start listening stdout, stderr and stdin
		void listenToRemoteNamedPipes()
		{
			// StdOut
			_beginthread(ListenRemoteOutPipeThread, 0, this);

			// StdErr
			_beginthread(ListenRemoteErrorPipeThread, 0, this);

			// StdIn
			_beginthread(ListenRemoteStdInputPipeThread, 0, this);
		}

		const string createRemotePipeName(LPCSTR szPipeBaseName)
		{
			stringstream strPipeName;
			strPipeName << m_lpszMachine << "\\pipe\\" << szPipeBaseName << m_strThisMachine << GetCurrentProcessId();
			return strPipeName.str();
		}

		// Connects to the remote processes stdout, stderr and stdin named pipes
		bool connectToRemotePipes(DWORD dwRetryCount, DWORD dwRetryTimeOut)
		{
			SECURITY_ATTRIBUTES SecAttrib = { 0 };
			SECURITY_DESCRIPTOR SecDesc;

			InitializeSecurityDescriptor(&SecDesc, SECURITY_DESCRIPTOR_REVISION);
			SetSecurityDescriptorDacl(&SecDesc, TRUE, NULL, FALSE);

			SecAttrib.nLength = sizeof(SECURITY_ATTRIBUTES);
			SecAttrib.lpSecurityDescriptor = &SecDesc;;
			SecAttrib.bInheritHandle = TRUE;

			m_hRemoteOutPipe = INVALID_HANDLE_VALUE;
			m_hRemoteStdInputPipe = INVALID_HANDLE_VALUE;
			m_hRemoteErrorPipe = INVALID_HANDLE_VALUE;

			const string strStdOut = createRemotePipeName(RemComSTDOUT);
			const char* szStdOut = strStdOut.c_str();
			const string strStdIn = createRemotePipeName(RemComSTDIN);
			const char* szStdIn = strStdIn.c_str();
			const string strStdErr = createRemotePipeName(RemComSTDERR);
			const char* szStdErr = strStdErr.c_str();

			while (dwRetryCount--)
			{
				// Connects to StdOut pipe
				if (m_hRemoteOutPipe == INVALID_HANDLE_VALUE)
					if (WaitNamedPipe(szStdOut, NULL))
						m_hRemoteOutPipe = CreateFile(
							szStdOut,
							GENERIC_READ,
							0,
							&SecAttrib,
							OPEN_EXISTING,
							FILE_ATTRIBUTE_NORMAL,
							NULL);

				// Connects to Error pipe
				if (m_hRemoteErrorPipe == INVALID_HANDLE_VALUE)
					if (WaitNamedPipe(szStdErr, NULL))
						m_hRemoteErrorPipe = CreateFile(
							szStdErr,
							GENERIC_READ,
							0,
							&SecAttrib,
							OPEN_EXISTING,
							FILE_ATTRIBUTE_NORMAL,
							NULL);

				// Connects to StdIn pipe
				if (m_hRemoteStdInputPipe == INVALID_HANDLE_VALUE)
					if (WaitNamedPipe(szStdIn, NULL))
						m_hRemoteStdInputPipe = CreateFile(
							szStdIn,
							GENERIC_WRITE,
							0,
							&SecAttrib,
							OPEN_EXISTING,
							FILE_ATTRIBUTE_NORMAL,
							NULL);

				if (m_hRemoteOutPipe != INVALID_HANDLE_VALUE &&
					m_hRemoteErrorPipe != INVALID_HANDLE_VALUE &&
					m_hRemoteStdInputPipe != INVALID_HANDLE_VALUE)
					break;

				// One of the pipes failed, try it again
				Sleep(dwRetryTimeOut);
			}

			if (m_hRemoteOutPipe == INVALID_HANDLE_VALUE ||
				m_hRemoteErrorPipe == INVALID_HANDLE_VALUE ||
				m_hRemoteStdInputPipe == INVALID_HANDLE_VALUE)
			{
				CloseHandle(m_hRemoteOutPipe);
				CloseHandle(m_hRemoteErrorPipe);
				CloseHandle(m_hRemoteStdInputPipe);

				return false;
			}

			// Start listening these pipes
			listenToRemoteNamedPipes();

			return true;
		}

		// 1. Send the message to remote service
		// 2. Connects to remote pipes
		// 3. Waiting for finishing remote process
		bool executeRemoteCommand()
		{
			DWORD dwTemp = 0;
			RemComMessage msg(BUFSIZ, &m_logger);
			RemComResponse response;

			::ZeroMemory(&response, sizeof(response));

			buildMessageStructure(&msg);

			// Send message to service
			m_logger.logTrace("Writing message to command pipe");
			if (!msg.send(m_hCommandPipe))
			{
				DWORD dwLastError = GetLastError();
				m_logger.logError("\nCould not send command to remote service. Returned error code is %s", DisplayableCode(dwLastError));
				return false;
			}

			// Connects to remote pipes (stdout, stdin, stderr)
			m_logger.logTrace("Connecting to remote process pipes");
			if (connectToRemotePipes(5, 1000))
			{
				// Waiting for response from service
				m_logger.logTrace("Waiting for %d response bytes", sizeof(response));
				ReadFile(m_hCommandPipe, &response, sizeof(response), &dwTemp, NULL);
			}
			else
				m_logger.logCritical("Failed to connect to remote process pipes");

			if (response.dwErrorCode == 0)
				m_logger.logDebug("Remote command returned %s", DisplayableCode(response.dwReturnCode));
			else
				m_logger.logError("Remote command failed to start. Returned error code is %s", DisplayableCode(response.dwErrorCode));

			return true;
		}

		static LPCTSTR DisplayableCode(DWORD dwError)
		{
			static TCHAR szBuf[40];
			_stprintf_s(szBuf, "%d(0x%X)", dwError, dwError);
			return szBuf;
		}

		static BOOL WINAPI ConsoleCtrlHandler(DWORD dwCtrlType)
		{
			switch (dwCtrlType)
			{
			case CTRL_C_EVENT:
			case CTRL_BREAK_EVENT:
				break;
			}

			return FALSE;
		}

		void showUsage()
		{
			cout << "------------------------------------------------------------------\n"
			     << "| Usage: RemCom.exe [\\\\computer] [options] [cmd/exe arguments] |\n"
			     << "------------------------------------------------------------------\n"
			     << "\n"
			     << "Options:\n"
			     << "\n"
			     << " /user:UserName\t\tUserName for Remote Connection\n"
			     << " /pwd:[password|*]\tPassword. * will delay the input (if required)\n"
			     << "\n"
			     << " /d:directory\t\tSet working directory\n"
			     << "\t\t\t(Default: \\\\RemoteSystem\"%SystemRoot%\\System32\")\n\n"
			     << " [/idle | /normal | /high | /realtime]\tPriority class (use only one)\n"
			     << "  /nowait\t\tDon't wait for remote process to terminate\n"
			     << "\n"
			     << " /c\t\t\tCopy the specified program to the remote machine's\n"
			     << "   \t\t\t\"%SystemRoot%\\System32\" directory\n"
			     << "   \t\t\tCommand's exe file must be absolute to local machine\n"
				 << "\n"
				 << " /v:[TRC|DBG|INF|ERR|CRT|FAT]\tVerbosity of log messages. Default is ERR\n"
			     << "\n"
			     << "   .........................................................................\n"
			     << "\n"
			     << "Examples:\n"
			     << "\n"
			     << " RemCom.exe \\\\remote cmd\t[Starts a \"telnet\" client]\n"
			     << " RemCom.exe \\\\remote /user:Username /pwd:Password cmd.exe\t[Starts a \"telnet\" client]\n"
			     << " RemCom.exe \\\\localhost /user:Username /pwd:Password  \"C:\\InstallMe.bat\"\t[A replacement for RunAs Command]\"\n"
			     << "\n"
			     << "   .........................................................................\n"
			     << "\n"
			     << "Notes:\n"
			     << "\n"
			     << "-  A \".\" for Machine Name will be treated as localhost\n"
			     << "-  Input is passed to remote machine when you press the ENTER.\n"
			     << "-  Ctrl-C terminates the remote process\n"
			     << "-  Command and file path arguments have to be absolute to remote machine\n"
			     << "-  If you are using /c option, command exe file path must be absolute to\n"
			     << "   local machine, but the arguments must be absolute to remote machine\n"
			     << "-  A dot . for machine name is taken as localhost\n"
			     << "-  Not providing any credentials, the Process will (impersonate and) run\n"
			     << "   in the context of your account on the remote system, but will not have\n"
			     << "   access to network resources \n"
			     << "-  Specify a valid user name in the Domain\\User syntax if the remote process\n"
			     << "   requires access to network resources or to run in a different account. \n"
			     << "-  The password is transmitted in clear text to the remote system.\n"
			     << "-  You can enclose applications that have spaces in their name with \n"
			     << "   quotation marks  e.g. RemCom \\\\computername \"c:\\long name app.exe\".\\n"
			     << "-  Input is only passed to the remote system when you press the enter key \n"
			     << "-  Typing Ctrl-C terminates the remote process.            \n"
			     << "-  Error codes returned by RemCom are specific to the applications you execute, not RemCom.\n"
			     << " \n"
			     << "   .........................................................................\n"
				 << flush;
		}

		bool startInteractiveClientProcess(
			LPTSTR lpszUsername,    // client to log on
			LPTSTR lpszDomain,      // domain of client's account
			LPTSTR lpszPassword,    // client's password
			LPTSTR lpCommandLine    // command line to execute
		)
		{
			HANDLE      hToken;
			HDESK       hdesk = NULL;
			HWINSTA     hwinsta = NULL, hwinstaSave = NULL;
			PROCESS_INFORMATION pi;
			PSID pSid = NULL;
			STARTUPINFO si;
			BOOL bResult = FALSE;

			// Log the client on to the local computer.

			if (!LogonUser(
				lpszUsername,
				lpszDomain,
				lpszPassword,
				LOGON32_LOGON_INTERACTIVE,
				LOGON32_PROVIDER_DEFAULT,
				&hToken))
			{
				goto Cleanup;
			}

			// Save a handle to the caller's current window station.

			if ((hwinstaSave = GetProcessWindowStation()) == NULL)
				goto Cleanup;

			// Get a handle to the interactive window station.

			hwinsta = OpenWindowStation(
				"winsta0",                   // the interactive window station 
				FALSE,                       // handle is not inheritable
				READ_CONTROL | WRITE_DAC);   // rights to read/write the DACL

			if (hwinsta == NULL)
				goto Cleanup;

			// To get the correct default desktop, set the caller's 
			// window station to the interactive window station.

			if (!SetProcessWindowStation(hwinsta))
				goto Cleanup;

			// Get a handle to the interactive desktop.

			hdesk = OpenDesktop(
				"default",     // the interactive window station 
				0,             // no interaction with other desktop processes
				FALSE,         // handle is not inheritable
				READ_CONTROL | // request the rights to read and write the DACL
				WRITE_DAC |
				DESKTOP_WRITEOBJECTS |
				DESKTOP_READOBJECTS);

			// Restore the caller's window station.

			if (!SetProcessWindowStation(hwinstaSave))
				goto Cleanup;

			if (hdesk == NULL)
				goto Cleanup;

			// Get the SID for the client's logon session.

			if (!getLogonSID(hToken, &pSid))
				goto Cleanup;

			// Allow logon SID full access to interactive window station.

			//TODO
			//   if (! AddAceToWindowStation(hwinsta, pSid) ) 
			//    goto Cleanup;

			// Allow logon SID full access to interactive desktop.

			if (!addAceToDesktop(hdesk, pSid))
				goto Cleanup;

			// Impersonate client to ensure access to executable file.

			if (!ImpersonateLoggedOnUser(hToken))
				goto Cleanup;

			// Initialize the STARTUPINFO structure.
			// Specify that the process runs in the interactive desktop.

			ZeroMemory(&si, sizeof(STARTUPINFO));
			si.cb = sizeof(STARTUPINFO);

			//   si.lpDesktop = TEXT("winsta0\\default");
			//   si.wShowWindow
			si.hStdOutput = m_hRemoteOutPipe;
			si.hStdError = m_hRemoteOutPipe;

			// Launch the process in the client's logon session.

			bResult = CreateProcessAsUser(
				hToken,            // client's access token
				NULL,              // file to execute
				lpCommandLine,     // command line
				NULL,              // pointer to process SECURITY_ATTRIBUTES
				NULL,              // pointer to thread SECURITY_ATTRIBUTES
				FALSE,             // handles are not inheritable
				NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE,   // creation flags
				NULL,              // pointer to new environment block 
				NULL,              // name of current directory 
				&si,               // pointer to STARTUPINFO structure
				&pi                // receives information about new process
			);

			// End impersonation of client.
			showLastError();
			RevertToSelf();

			if (bResult && pi.hProcess != INVALID_HANDLE_VALUE)
			{
				WaitForSingleObject(pi.hProcess, INFINITE);
				CloseHandle(pi.hProcess);
				//ShowLastError();
			}

			if (pi.hThread != INVALID_HANDLE_VALUE)
				CloseHandle(pi.hThread);

		Cleanup:

			if (hwinstaSave != NULL)
				SetProcessWindowStation(hwinstaSave);

			// Free the buffer for the logon SID.

			if (pSid)
				freeLogonSID(&pSid);

			// Close the handles to the interactive window station and desktop.

			if (hwinsta)
				CloseWindowStation(hwinsta);

			if (hdesk)
				CloseDesktop(hdesk);

			// Close the handle to the client's access token.

			if (hToken != INVALID_HANDLE_VALUE)
				CloseHandle(hToken);

			return bResult;
		}

		bool startProcessWithUserLogon()
		{
			HANDLE    hToken;
			//  LPVOID    lpvEnv;
			PROCESS_INFORMATION pi = { 0 };
			STARTUPINFOW         si = { 0 };
			//	TCHAR szUserProfile[SIZEOF_BUFFER] = "";

				// Initialize the STARTUPINFO structure.
				// Specify that the process runs in the interactive desktop.

			ZeroMemory(&si, sizeof(STARTUPINFOW));
			si.cb = sizeof(STARTUPINFOW);

			si.hStdOutput = m_hRemoteOutPipe;
			si.hStdError = m_hRemoteOutPipe;
			//	CreateEnvironmentBlock(&lpvEnv, hToken, TRUE);

			if (!LogonUser(m_lpszUser, NULL, m_lpszPassword, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &hToken))
			{
				showLastError();
				return false;
			}

			//(LPCWSTR)
			int bResult;

			/*	bResult =  CreateProcessWithLogonW(		(LPCWSTR)lpszUser, 		(LPCWSTR)lpszDomain,		(LPCWSTR)lpszPassword,  		LOGON_WITH_PROFILE,
			NULL,		(LPWSTR) lpszCommandExe, 		CREATE_UNICODE_ENVIRONMENT, NULL, 		NULL,
			&si,
			&pi
			);
			*/

			bResult = CreateProcessWithLogonW(
				(LPCWSTR)m_lpszUser,
				NULL,
				(LPCWSTR)m_lpszPassword,
				LOGON_WITH_PROFILE,
				NULL,
				(LPWSTR)m_lpszCommandExe,
				CREATE_UNICODE_ENVIRONMENT,
				/*lpvEnv*/ NULL,
				(LPCWSTR) SYSTEM32,
				&si,
				&pi
			);

			showLastError();

			//    if (!DestroyEnvironmentBlock(lpvEnv))        DisplayError(L"DestroyEnvironmentBlock");

			CloseHandle(hToken);
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);

			return bResult;
		}

		bool addAceToWindowStation(HWINSTA hwinsta, PSID psid)
		{
			ACCESS_ALLOWED_ACE   *pace;
			ACL_SIZE_INFORMATION aclSizeInfo;
			BOOL                 bDaclExist;
			BOOL                 bDaclPresent;
			BOOL                 bSuccess = FALSE;
			DWORD                dwNewAclSize;
			DWORD                dwSidSize = 0;
			DWORD                dwSdSizeNeeded;
			PACL                 pacl = 0;
			PACL                 pNewAcl = 0;
			PSECURITY_DESCRIPTOR psd = NULL;
			PSECURITY_DESCRIPTOR psdNew = NULL;
			PVOID                pTempAce;
			SECURITY_INFORMATION si = DACL_SECURITY_INFORMATION;
			unsigned int         i;

			__try
			{
				// Obtain the DACL for the window station.

				if (!GetUserObjectSecurity(
					hwinsta,
					&si,
					psd,
					dwSidSize,
					&dwSdSizeNeeded)
					)
					if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
					{
						psd = (PSECURITY_DESCRIPTOR)HeapAlloc(
							GetProcessHeap(),
							HEAP_ZERO_MEMORY,
							dwSdSizeNeeded);

						if (psd == NULL)
							__leave;

						psdNew = (PSECURITY_DESCRIPTOR)HeapAlloc(
							GetProcessHeap(),
							HEAP_ZERO_MEMORY,
							dwSdSizeNeeded);

						if (psdNew == NULL)
							__leave;

						dwSidSize = dwSdSizeNeeded;

						if (!GetUserObjectSecurity(
							hwinsta,
							&si,
							psd,
							dwSidSize,
							&dwSdSizeNeeded)
							)
							__leave;
					}
					else
						__leave;

				// Create a new DACL.

				if (!InitializeSecurityDescriptor(
					psdNew,
					SECURITY_DESCRIPTOR_REVISION)
					)
					__leave;

				// Get the DACL from the security descriptor.

				if (!GetSecurityDescriptorDacl(
					psd,
					&bDaclPresent,
					&pacl,
					&bDaclExist)
					)
					__leave;

				// Initialize the ACL.

				ZeroMemory(&aclSizeInfo, sizeof(ACL_SIZE_INFORMATION));
				aclSizeInfo.AclBytesInUse = sizeof(ACL);

				// Call only if the DACL is not NULL.

				if (pacl != NULL)
				{
					// get the file ACL size info
					if (!GetAclInformation(
						pacl,
						(LPVOID)&aclSizeInfo,
						sizeof(ACL_SIZE_INFORMATION),
						AclSizeInformation)
						)
						__leave;
				}

				// Compute the size of the new ACL.

				dwNewAclSize = aclSizeInfo.AclBytesInUse + (2 * sizeof(ACCESS_ALLOWED_ACE)) +
					(2 * GetLengthSid(psid)) - (2 * sizeof(DWORD));

				// Allocate memory for the new ACL.

				pNewAcl = (PACL)HeapAlloc(
					GetProcessHeap(),
					HEAP_ZERO_MEMORY,
					dwNewAclSize);

				if (pNewAcl == NULL)
					__leave;

				// Initialize the new DACL.

				if (!InitializeAcl(pNewAcl, dwNewAclSize, ACL_REVISION))
					__leave;

				// If DACL is present, copy it to a new DACL.

				if (bDaclPresent)
				{
					// Copy the ACEs to the new ACL.
					if (aclSizeInfo.AceCount)
					{
						for (i = 0; i < aclSizeInfo.AceCount; i++)
						{
							// Get an ACE.
							if (!GetAce(pacl, i, &pTempAce))
								__leave;

							// Add the ACE to the new ACL.
							if (!AddAce(
								pNewAcl,
								ACL_REVISION,
								MAXDWORD,
								pTempAce,
								((PACE_HEADER)pTempAce)->AceSize)
								)
								__leave;
						}
					}
				}

				// Add the first ACE to the window station.

				pace = (ACCESS_ALLOWED_ACE *)HeapAlloc(
					GetProcessHeap(),
					HEAP_ZERO_MEMORY,
					sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(psid) -
					sizeof(DWORD));

				if (pace == NULL)
					__leave;

				pace->Header.AceType = ACCESS_ALLOWED_ACE_TYPE;
				pace->Header.AceFlags = CONTAINER_INHERIT_ACE |
					INHERIT_ONLY_ACE | OBJECT_INHERIT_ACE;
				pace->Header.AceSize = (WORD)(sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(psid) - sizeof(DWORD));
				pace->Mask = GENERIC_ACCESS;

				if (!CopySid(GetLengthSid(psid), &pace->SidStart, psid))
					__leave;

				if (!AddAce(
					pNewAcl,
					ACL_REVISION,
					MAXDWORD,
					(LPVOID)pace,
					pace->Header.AceSize)
					)
					__leave;

				// Add the second ACE to the window station.

				pace->Header.AceFlags = NO_PROPAGATE_INHERIT_ACE;
				pace->Mask = WINSTA_ALL;

				if (!AddAce(
					pNewAcl,
					ACL_REVISION,
					MAXDWORD,
					(LPVOID)pace,
					pace->Header.AceSize)
					)
					__leave;

				// Set a new DACL for the security descriptor.

				if (!SetSecurityDescriptorDacl(
					psdNew,
					TRUE,
					pNewAcl,
					FALSE)
					)
					__leave;

				// Set the new security descriptor for the window station.

				if (!SetUserObjectSecurity(hwinsta, &si, psdNew))
					__leave;

				// Indicate success.

				bSuccess = TRUE;
			}
			__finally
			{
				// Free the allocated buffers.

				if (pace != NULL)
					HeapFree(GetProcessHeap(), 0, (LPVOID)pace);

				if (pNewAcl != NULL)
					HeapFree(GetProcessHeap(), 0, (LPVOID)pNewAcl);

				if (psd != NULL)
					HeapFree(GetProcessHeap(), 0, (LPVOID)psd);

				if (psdNew != NULL)
					HeapFree(GetProcessHeap(), 0, (LPVOID)psdNew);
			}

			return bSuccess;

		}

		bool addAceToDesktop(HDESK hdesk, PSID psid)
		{
			ACL_SIZE_INFORMATION aclSizeInfo;
			BOOL                 bDaclExist;
			BOOL                 bDaclPresent;
			BOOL                 bSuccess = FALSE;
			DWORD                dwNewAclSize;
			DWORD                dwSidSize = 0;
			DWORD                dwSdSizeNeeded;
			PACL                 pacl;
			PACL                 pNewAcl;
			PSECURITY_DESCRIPTOR psd = NULL;
			PSECURITY_DESCRIPTOR psdNew = NULL;
			PVOID                pTempAce;
			SECURITY_INFORMATION si = DACL_SECURITY_INFORMATION;
			unsigned int         i;

			__try
			{
				// Obtain the security descriptor for the desktop object.

				if (!GetUserObjectSecurity(
					hdesk,
					&si,
					psd,
					dwSidSize,
					&dwSdSizeNeeded))
				{
					if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
					{
						psd = (PSECURITY_DESCRIPTOR)HeapAlloc(
							GetProcessHeap(),
							HEAP_ZERO_MEMORY,
							dwSdSizeNeeded);

						if (psd == NULL)
							__leave;

						psdNew = (PSECURITY_DESCRIPTOR)HeapAlloc(
							GetProcessHeap(),
							HEAP_ZERO_MEMORY,
							dwSdSizeNeeded);

						if (psdNew == NULL)
							__leave;

						dwSidSize = dwSdSizeNeeded;

						if (!GetUserObjectSecurity(
							hdesk,
							&si,
							psd,
							dwSidSize,
							&dwSdSizeNeeded)
							)
							__leave;
					}
					else
						__leave;
				}

				// Create a new security descriptor.

				if (!InitializeSecurityDescriptor(
					psdNew,
					SECURITY_DESCRIPTOR_REVISION)
					)
					__leave;

				// Obtain the DACL from the security descriptor.

				if (!GetSecurityDescriptorDacl(
					psd,
					&bDaclPresent,
					&pacl,
					&bDaclExist)
					)
					__leave;

				// Initialize.

				ZeroMemory(&aclSizeInfo, sizeof(ACL_SIZE_INFORMATION));
				aclSizeInfo.AclBytesInUse = sizeof(ACL);

				// Call only if NULL DACL.

				if (pacl != NULL)
				{
					// Determine the size of the ACL information.

					if (!GetAclInformation(
						pacl,
						(LPVOID)&aclSizeInfo,
						sizeof(ACL_SIZE_INFORMATION),
						AclSizeInformation)
						)
						__leave;
				}

				// Compute the size of the new ACL.

				dwNewAclSize = aclSizeInfo.AclBytesInUse +
					sizeof(ACCESS_ALLOWED_ACE) +
					GetLengthSid(psid) - sizeof(DWORD);

				// Allocate buffer for the new ACL.

				pNewAcl = (PACL)HeapAlloc(
					GetProcessHeap(),
					HEAP_ZERO_MEMORY,
					dwNewAclSize);

				if (pNewAcl == NULL)
					__leave;

				// Initialize the new ACL.

				if (!InitializeAcl(pNewAcl, dwNewAclSize, ACL_REVISION))
					__leave;

				// If DACL is present, copy it to a new DACL.

				if (bDaclPresent)
				{
					// Copy the ACEs to the new ACL.
					if (aclSizeInfo.AceCount)
					{
						for (i = 0; i < aclSizeInfo.AceCount; i++)
						{
							// Get an ACE.
							if (!GetAce(pacl, i, &pTempAce))
								__leave;

							// Add the ACE to the new ACL.
							if (!AddAce(
								pNewAcl,
								ACL_REVISION,
								MAXDWORD,
								pTempAce,
								((PACE_HEADER)pTempAce)->AceSize)
								)
								__leave;
						}
					}
				}

				// Add ACE to the DACL.

				if (!AddAccessAllowedAce(
					pNewAcl,
					ACL_REVISION,
					DESKTOP_ALL,
					psid)
					)
					__leave;

				// Set new DACL to the new security descriptor.

				if (!SetSecurityDescriptorDacl(
					psdNew,
					TRUE,
					pNewAcl,
					FALSE)
					)
					__leave;

				// Set the new security descriptor for the desktop object.

				if (!SetUserObjectSecurity(hdesk, &si, psdNew))
					__leave;

				// Indicate success.

				bSuccess = TRUE;
			}
			__finally
			{
				// Free buffers.

				if (pNewAcl != NULL)
					HeapFree(GetProcessHeap(), 0, (LPVOID)pNewAcl);

				if (psd != NULL)
					HeapFree(GetProcessHeap(), 0, (LPVOID)psd);

				if (psdNew != NULL)
					HeapFree(GetProcessHeap(), 0, (LPVOID)psdNew);
			}

			return bSuccess;
		}

		// executes a local process under the local user account who launched the process
		bool startLocalProcess(LPTSTR szCommandName)
		{
			SECURITY_ATTRIBUTES secAttrib;
			ZeroMemory(&secAttrib, sizeof(secAttrib));
			secAttrib.nLength = sizeof(secAttrib);
			secAttrib.bInheritHandle = TRUE;

			STARTUPINFO si;
			PROCESS_INFORMATION pi;

			ZeroMemory(&si, sizeof(si));
			si.cb = sizeof(si);
			ZeroMemory(&pi, sizeof(pi));

			si.hStdInput = m_hRemoteStdInputPipe;
			si.hStdOutput = m_hRemoteOutPipe;
			si.hStdError = m_hRemoteOutPipe;

			// Start the child process. 
			if (!CreateProcess(NULL,   // No module name (use command line)
				szCommandName,      // Command line
				NULL,           // Process handle not inheritable
				NULL,           // Thread handle not inheritable
				FALSE,          // Set handle inheritance to FALSE
				0,              // No creation flags
				NULL,           // Use parent's environment block
				NULL,           // Use parent's starting directory 
				&si,            // Pointer to STARTUPINFO structure
				&pi)           // Pointer to PROCESS_INFORMATION structure
				)
			{
				showLastError();
				return false;
			}
			else
			{
				//	printf("CreateProcess Success (%d).\n", GetLastError());
			}
			// Wait until child process exits.
			WaitForSingleObject(pi.hProcess, INFINITE);

			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);

			return true;
		}

		bool startLocalProcessAsUser()
		{
			HANDLE	hToken;
			PSID pSid = NULL;

			SECURITY_ATTRIBUTES secAttrib;
			ZeroMemory(&secAttrib, sizeof(secAttrib));
			secAttrib.nLength = sizeof(secAttrib);
			secAttrib.bInheritHandle = TRUE;

			STARTUPINFO si;
			PROCESS_INFORMATION pi;
			LPTSTR szCmdline = (LPTSTR)m_lpszCommandExe;

			ZeroMemory(&si, sizeof(si));
			si.cb = sizeof(si);
			ZeroMemory(&pi, sizeof(pi));

			si.hStdOutput = m_hRemoteOutPipe;
			si.hStdError = m_hRemoteOutPipe;

			// Log the client on to the local computer.

			if (!LogonUser((LPTSTR)m_lpszUser, (LPTSTR)m_lpszDomain, (LPTSTR)m_lpszPassword, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &hToken))
			{
				m_logger.logFatal("User Logon failed (%d)", GetLastError());
				//goto Cleanup;
				showLastError();
				return false;
			}

			if (!getLogonSID(hToken, &pSid))
			{
				showLastError();
				return false;
			}

			// Impersonate client to ensure access to executable file.

			if (!ImpersonateLoggedOnUser(hToken))
			{
				showLastError();
				return false;
			}

			// Start the child process. 
			if (!CreateProcessAsUser(
				hToken, //Security Token
				NULL,   // No module name (use command line)
				szCmdline,      // Command line
				NULL,           // Process handle not inheritable
				NULL,           // Thread handle not inheritable
				FALSE,          // Set handle inheritance to FALSE
				0,              // No creation flags
				NULL,           // Use parent's environment block
				NULL,           // Use parent's starting directory 
				&si,            // Pointer to STARTUPINFO structure
				&pi)           // Pointer to PROCESS_INFORMATION structure
				)
			{
				m_logger.logFatal("CreateProcess failed (%d).", GetLastError());
				showLastError();
				return false;
			}
			else
			{
				m_logger.logDebug("User Impersonation Success");
			}

			// Wait until child process exits.
			WaitForSingleObject(pi.hProcess, INFINITE);
			// Close process and thread handles. 

			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);

			return true;
		}

		void cleanup()
		{
			// Disconnect from remote machine
			establishConnection(m_lpszMachine, "IPC$", false);
			establishConnection(m_lpszMachine, "ADMIN$", false);
		}

		int runOnRemoteMachine()
		{
			m_logger.logDebug("Initiating Connection to Remote Service...");
			int rc = 0;
			// Connect to remote machine's ADMIN$
			if (!establishConnection(m_lpszMachine, "ADMIN$", true))
			{
				rc = -2;
				m_logger.logError("Couldn't connect to %s\\ADMIN$\n", m_lpszMachine);
				showLastError();
				return rc;
			}

			// Connect to remote machine IPC$
			if (!establishConnection(m_lpszMachine, "IPC$", true))
			{
				rc = -2;
				m_logger.logError("Couldn't connect to %s\\IPC$\n", m_lpszMachine);
				showLastError();
				return rc;
			}

			// Copy the command's exe file to remote machine (if using /c)
			if (!copyBinaryToRemoteSystem())
			{
				rc = -2;
				m_logger.logError("Couldn't copy %s to \\ADMIN$\\System32", m_lpszCommandExe);
				showLastError();
				return rc;
			}

			// Connects to remote service, maybe it's already running :)
			if (!connectToRemoteService(1, 0))
			{
				//We couldn't connect, so let's install it and start it

				// Copy the service executable to \\remote\ADMIN$\System32
				if (!copyServiceToRemoteMachine())
				{
					rc = -2;
					m_logger.logError("Couldn't copy service to %s\\ADMIN$\\System32", m_lpszMachine);
					showLastError();
					return rc;
				}

				// Install and start service on remote machine
				if (!installAndStartRemoteService())
				{
					rc = -2;
					m_logger.logError("Couldn't start remote service");
					showLastError();
					return rc;
				}

				// Try to connect again
				if (!connectToRemoteService(5, 1000))
				{
					rc = -2;
					m_logger.logError("Couldn't connect to remote service");
					showLastError();
					return rc;
				}
			}

			// Send the message to remote service to start the remote process
			executeRemoteCommand();

			return rc;
		}
	};
}

// Main function
int _tmain(DWORD, TCHAR**, TCHAR**)
{
	try
	{
		RemCom::RemCom remcom;
		return remcom.run();
	}
	catch(...)
	{
		std::cerr << "Uncaught error occurred, press Enter to continue";
		std::string strInput;
		std::cin >> strInput;
	}
}
