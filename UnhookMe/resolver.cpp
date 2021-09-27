
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

	ImportResolverCache<std::string> UnhookingImportResolver::globalResolverCache;

	void die()
	{
		::ExitProcess(0);
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