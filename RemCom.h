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
	$Version History: $			- Added ProcComs binary as a local resource for local process impersonation and communication util
	$TODO:						- See destructor
	$Description: $				- RemCom is RAT [Remote Administration Tool] that lets you execute processes on remote windows systems, copy files, 
								  process there output and stream it back. It allows execution of remote shell commands directly with full interactive console
								- Declaration of RemCom Message and Response Classes	
	$Workfile: $				- RemCom.h
 */

#ifndef RemCom_H_INCLUDED
#define RemCom_H_INCLUDED
#include <windows.h>
//#include <winbase.h>
#include <winsvc.h>
#include <tchar.h>
#include <lmcons.h>
#include <stdio.h>
#include <stdlib.h>
#include <process.h>
#include <thread>
#include <iostream>
#include <sstream>
#include <cstdarg>
#include <ctime>
#include <mutex>
#include <vector>
#include <userenv.h>
#include "ProcFunctions.h"
//#include <strsafe.h>
#include "resource.h"

#define SERVICENAME        _T("RemComSvc")
#define LONGSERVICENAME    _T("RemCom Service")

#define RemComSVCEXE     "RemComSvc.exe"
#define ProcComs         _T("ProcComs.bin")

#define RemComCOMM           _T("RemCom_comm")
#define RemComSTDOUT         _T("RemCom_stdout")
#define RemComSTDIN          _T("RemCom_stdin")
#define RemComSTDERR         _T("RemCom_stderr")

#define SYSTEMROOT "%SystemRoot%"
#define SYSTEM32 SYSTEMROOT "\\system32"
#define LOCALHOST "\\\\localhost"
#define LOOPBACKIP "\\\\127.0.0.1"

class RemComResponseStatus
{
public:
	static const DWORD ACK = 0;
	static const DWORD IO_PIPES_READY = 10;
	static const DWORD IO_PIPES_ATTACHED = 20;
	static const DWORD PROCESS_STARTED = 30;
	static const DWORD PROCESS_COMPLETED = 40;
	static const DWORD CLIENT_PROTOCOL_ERROR = 0xFFFFFFFC;
	static const DWORD IO_PIPES_CREATION_FAILED = 0xFFFFFFFD;
	static const DWORD PROCESS_CREATION_FAILED = 0xFFFFFFFE;
	static const DWORD PROCESS_EXECUTION_FAILED = 0xFFFFFFFF;
};

class RemComResponse
{
public:
   DWORD dwStatusCode;
   DWORD dwExitCode;
};


#endif