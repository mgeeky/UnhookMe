
#include "resolver.h"


namespace UnhookingImportResolver
{
	//
	// Resolver global options:
	//
	//   globalQuietOption          - set to true if you don't want to have any sort of output
	//   globalVerboseOption        - set to true if you want to have detailed verbose output
	//   globalAntiSplicingOption   - unhook resolved functions if they're hooked.
	//   globalLogFilePath          - where to redirect output log lines. If empty, pick stdout.
	//

	bool globalQuietOption = true;
	bool globalVerboseOption = false;
	bool globalAntiSplicingOption = true;

	wchar_t globalLogFilePath[MAX_PATH] = L"";


	ImportResolverCache<std::string> UnhookingImportResolver::globalResolverCache;


	void die()
	{
		::ExitProcess(0);
	}

	void _output(bool verbose, const std::string& out)
	{
		if (UnhookingImportResolver::globalQuietOption) return;

		DWORD written = 0;

		static auto _WriteFile = reinterpret_cast<fn_WriteFile*>(::GetProcAddress(
			GetModuleHandleW(L"kernel32.dll"),
			ADV_OBF("WriteFile")
		));

		if (UnhookingImportResolver::globalLogFilePath[0] != L'\0' 
			&& UnhookingImportResolver::globalLogFilePath[0] != L'-')
		{
			static auto _CreateFileW = reinterpret_cast<fn_CreateFileW*>(::GetProcAddress(
				GetModuleHandleW(L"kernel32.dll"),
				ADV_OBF("CreateFileW")
			));

			HANDLE hFile = _CreateFileW(
				UnhookingImportResolver::globalLogFilePath,
				FILE_APPEND_DATA,
				FILE_SHARE_READ | FILE_SHARE_WRITE,
				NULL,
				OPEN_ALWAYS,
				FILE_ATTRIBUTE_NORMAL,
				NULL
			);

			if (hFile != INVALID_HANDLE_VALUE && hFile != NULL)
			{
				static auto _SetFilePointer = reinterpret_cast<fn_SetFilePointer*>(::GetProcAddress(
					GetModuleHandleW(L"kernel32.dll"),
					ADV_OBF("SetFilePointer")
				));

				_SetFilePointer(
					hFile,
					0,
					nullptr,
					FILE_END
				);

				_WriteFile(
					hFile,
					out.c_str(),
					static_cast<DWORD>(out.size()),
					&written,
					nullptr
				);

				CloseHandle(hFile);
			}
		}
		else
		{
			_WriteFile(
				GetStdHandle(static_cast<DWORD>(-11) /* STD_OUTPUT_HANDLE */),
				out.c_str(),
				static_cast<DWORD>(out.size()),
				&written,
				nullptr
			);
		}
	}

	std::wstring adjustPath(const std::wstring& szPath)
	{
		auto out = _adjustPath(szPath);
		if (!out.empty()) return out;

		out = _adjustPath(szPath + OBFI(L".exe"));
		if (!out.empty()) return out;

		out = _adjustPath(szPath + OBFI(L".dll"));
		if (!out.empty()) return out;

		out = _adjustPath(OBFI(L"..\\") + szPath);
		if (!out.empty()) return out;

		out = _adjustPath(OBFI(L"..\\") + szPath + OBFI(L".exe"));
		if (!out.empty()) return out;

		out = _adjustPath(OBFI(L"..\\") + szPath + OBFI(L".dll"));
		if (!out.empty()) return out;

		info(OBF(L"[!] Specified file ("), szPath, OBF(L") does not exist in CWD, Windows or Windows\\System32!"));
		die();
		return L"";
	}

	std::wstring _adjustPath(const std::wstring& szPath)
	{
		//
		// Can't RESOLVE GetFileAttributesW and ExpandEnvironmentStringsW as we're unable to
		// #include Resolver here. This would lead to cyclic dependency and wouldn't build.
		//

		DWORD dwAttrib = GetFileAttributesW(szPath.c_str());

		bool exists = (dwAttrib != INVALID_FILE_ATTRIBUTES &&
			!(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));

		if (exists)
		{
			return std::wstring(szPath);
		}
		else
		{
			wchar_t path[1024] = { 0 };
			ExpandEnvironmentStringsW(OBF_WSTR(L"%SystemRoot%").c_str(), path, _countof(path));

			auto newPath = std::wstring(path) + OBF_WSTR(L"\\System32\\") + szPath;

			dwAttrib = GetFileAttributesW(newPath.c_str());
			exists = (dwAttrib != INVALID_FILE_ATTRIBUTES &&
				!(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));

			if (!exists)
			{
				return {};
			}

			return newPath;
		}
	}

	std::string adjustPathA(const std::string& szPath)
	{
		static std::map<std::string, std::string> cachedAdjustedPaths;
		if (cachedAdjustedPaths.count(szPath) != 0)
		{
			return cachedAdjustedPaths[szPath];
		}

		std::wstring b(szPath.begin(), szPath.end());
		auto a = adjustPath(b);

		cachedAdjustedPaths[szPath] = std::string(a.begin(), a.end());
		return cachedAdjustedPaths[szPath];
	}
}