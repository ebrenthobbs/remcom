#pragma once

#include <stdarg.h>
#include <fstream>

namespace RemCom
{
	using namespace std;

	enum class LogLevel
	{
		Trace,
		Debug,
		Info,
		Warn,
		Error,
		Critical,
		Fatal
	};

	class Logger
	{
	public:
		Logger(ostream& logStream, LogLevel minLogLevel, size_t bufferSize) : m_logStream(logStream), m_minLogLevel(minLogLevel), m_logBufferSize(bufferSize)
		{
			m_logBuffer = new char[m_logBufferSize];
		}

		~Logger()
		{
			delete m_logBuffer;
		}

		LogLevel getMinLogLevel()
		{
			return m_minLogLevel;
		}

		void setMinLogLevel(LogLevel minLogLevel)
		{
			m_minLogLevel = minLogLevel;
		}

		void setMinLogLevel(const char *logLevelCode)
		{
			static char code[8];
			strncpy_s(code, logLevelCode, sizeof(code) - 1);
			_strlwr_s(code);
			if (!strncmp(code, "trc", sizeof(code) - 1))
				setMinLogLevel(LogLevel::Trace);
			else if (!strncmp(code, "dbg", sizeof(code) - 1))
				setMinLogLevel(LogLevel::Debug);
			else if (!strncmp(code, "inf", sizeof(code) - 1))
				setMinLogLevel(LogLevel::Info);
			else if (!strncmp(code, "wrn", sizeof(code) - 1))
				setMinLogLevel(LogLevel::Warn);
			else if (!strncmp(code, "err", sizeof(code) - 1))
				setMinLogLevel(LogLevel::Error);
			else if (!strncmp(code, "crt", sizeof(code) - 1))
				setMinLogLevel(LogLevel::Critical);
			else if (!strncmp(code, "fat", sizeof(code) - 1))
				setMinLogLevel(LogLevel::Fatal);

		}

		bool isEnabled(LogLevel logLevel)
		{
			if (m_minLogLevel > logLevel)
				return false;
			return true;
		}

		void logTrace(const char* fmt, ...)
		{
			if (m_minLogLevel > LogLevel::Trace)
				return;
			va_list args;
			va_start(args, fmt);
			logImpl(LogLevel::Trace, fmt, args);
		}

		void logDebug(const char* fmt, ...)
		{
			if (m_minLogLevel > LogLevel::Debug)
				return;
			va_list args;
			va_start(args, fmt);
			logImpl(LogLevel::Debug, fmt, args);
		}

		void logInfo(const char* fmt, ...)
		{
			if (m_minLogLevel > LogLevel::Info)
				return;
			va_list args;
			va_start(args, fmt);
			logImpl(LogLevel::Info, fmt, args);
		}

		void logWarn(const char* fmt, ...)
		{
			if (m_minLogLevel > LogLevel::Warn)
				return;
			va_list args;
			va_start(args, fmt);
			logImpl(LogLevel::Warn, fmt, args);
		}

		void logError(const char* fmt, ...)
		{
			if (m_minLogLevel > LogLevel::Error)
				return;
			va_list args;
			va_start(args, fmt);
			logImpl(LogLevel::Error, fmt, args);
		}

		void logCritical(const char* fmt, ...)
		{
			if (m_minLogLevel > LogLevel::Critical)
				return;
			va_list args;
			va_start(args, fmt);
			logImpl(LogLevel::Critical, fmt, args);
		}

		void logFatal(const char* fmt, ...)
		{
			va_list args;
			va_start(args, fmt);
			logImpl(LogLevel::Fatal, fmt, args);
		}

		void log(LogLevel logLevel, const char* fmt, ...)
		{
			if (m_minLogLevel > logLevel)
				return;
			va_list args;
			va_start(args, fmt);
			logImpl(logLevel, fmt, args);
		}

	private:
		size_t m_logBufferSize;
		char* m_logBuffer;
		ostream& m_logStream;
		LogLevel m_minLogLevel;

		mutex logMutex;

		void logImpl(LogLevel logLevel, const char* fmt, va_list args)
		{
			logMutex.lock();
			::ZeroMemory(m_logBuffer, m_logBufferSize);
			int len = vsprintf_s(m_logBuffer, m_logBufferSize, fmt, args);
			m_logStream << code(logLevel) << ": ";
			m_logStream << m_logBuffer;
			if (m_logBuffer[len - 1] != '\n')
				m_logStream << '\n';
			m_logStream << flush;
			logMutex.unlock();
		}

		const char* code(LogLevel logLevel)
		{
			switch (logLevel)
			{
			case LogLevel::Trace: return "TRC";
			case LogLevel::Debug: return "DBG";
			case LogLevel::Info: return "INF";
			case LogLevel::Warn: return "WRN";
			case LogLevel::Error: return "ERR";
			case LogLevel::Critical: return "CRT";
			case LogLevel::Fatal: return "FAT";
			default:
				return "ERR";
			}
		}

	};
}
