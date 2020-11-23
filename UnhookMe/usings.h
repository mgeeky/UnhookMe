#pragma once

#include <windows.h>
#include <winternl.h>
#include <wininet.h>
#include <tlhelp32.h>
#include <objidl.h>
#include <WTypes.h>
#include <unknwn.h>
#include <Lm.h>
#include <lmjoin.h>
#include <DsRole.h>
#include <SetupAPI.h>

namespace {

    namespace MyDefs {

        typedef enum _SYSTEM_INFORMATION_CLASS
        {
            SystemBasicInformation = 0,
            SystemProcessorInformation = 1,             // obsolete...delete
            SystemPerformanceInformation = 2,
            SystemTimeOfDayInformation = 3,
            SystemPathInformation = 4,
            SystemProcessInformation = 5,
            SystemCallCountInformation = 6,
            SystemDeviceInformation = 7,
            SystemProcessorPerformanceInformation = 8,
            SystemFlagsInformation = 9,
            SystemCallTimeInformation = 10,
            SystemModuleInformation = 11,
            SystemLocksInformation = 12,
            SystemStackTraceInformation = 13,
            SystemPagedPoolInformation = 14,
            SystemNonPagedPoolInformation = 15,
            SystemHandleInformation = 16,
            SystemObjectInformation = 17,
            SystemPageFileInformation = 18,
            SystemVdmInstemulInformation = 19,
            SystemVdmBopInformation = 20,
            SystemFileCacheInformation = 21,
            SystemPoolTagInformation = 22,
            SystemInterruptInformation = 23,
            SystemDpcBehaviorInformation = 24,
            SystemFullMemoryInformation = 25,
            SystemLoadGdiDriverInformation = 26,
            SystemUnloadGdiDriverInformation = 27,
            SystemTimeAdjustmentInformation = 28,
            SystemSummaryMemoryInformation = 29,
            SystemMirrorMemoryInformation = 30,
            SystemPerformanceTraceInformation = 31,
            SystemObsolete0 = 32,
            SystemExceptionInformation = 33,
            SystemCrashDumpStateInformation = 34,
            SystemKernelDebuggerInformation = 35,
            SystemContextSwitchInformation = 36,
            SystemRegistryQuotaInformation = 37,
            SystemExtendServiceTableInformation = 38,
            SystemPrioritySeperation = 39,
            SystemVerifierAddDriverInformation = 40,
            SystemVerifierRemoveDriverInformation = 41,
            SystemProcessorIdleInformation = 42,
            SystemLegacyDriverInformation = 43,
            SystemCurrentTimeZoneInformation = 44,
            SystemLookasideInformation = 45,
            SystemTimeSlipNotification = 46,
            SystemSessionCreate = 47,
            SystemSessionDetach = 48,
            SystemSessionInformation = 49,
            SystemRangeStartInformation = 50,
            SystemVerifierInformation = 51,
            SystemVerifierThunkExtend = 52,
            SystemSessionProcessInformation = 53,
            SystemLoadGdiDriverInSystemSpace = 54,
            SystemNumaProcessorMap = 55,
            SystemPrefetcherInformation = 56,
            SystemExtendedProcessInformation = 57,
            SystemRecommendedSharedDataAlignment = 58,
            SystemComPlusPackage = 59,
            SystemNumaAvailableMemory = 60,
            SystemProcessorPowerInformation = 61,
            SystemEmulationBasicInformation = 62,
            SystemEmulationProcessorInformation = 63,
            SystemExtendedHandleInformation = 64,
            SystemLostDelayedWriteInformation = 65,
            SystemBigPoolInformation = 66,
            SystemSessionPoolTagInformation = 67,
            SystemSessionMappedViewInformation = 68,
            SystemHotpatchInformation = 69,
            SystemObjectSecurityMode = 70,
            SystemWatchdogTimerHandler = 71,
            SystemWatchdogTimerInformation = 72,
            SystemLogicalProcessorInformation = 73,
            SystemWow64SharedInformation = 74,
            SystemRegisterFirmwareTableInformationHandler = 75,
            SystemFirmwareTableInformation = 76,
            SystemModuleInformationEx = 77,
            SystemVerifierTriageInformation = 78,
            SystemSuperfetchInformation = 79,
            SystemMemoryListInformation = 80,
            SystemFileCacheInformationEx = 81,
            MaxSystemInfoClass = 82  // MaxSystemInfoClass should always be the last enum
        } SYSTEM_INFORMATION_CLASS;


        enum KWAIT_REASON
        {
            Executive,
            FreePage,
            PageIn,
            PoolAllocation,
            DelayExecution,
            Suspended,
            UserRequest,
            WrExecutive,
            WrFreePage,
            WrPageIn,
            WrPoolAllocation,
            WrDelayExecution,
            WrSuspended,
            WrUserRequest,
            WrEventPair,
            WrQueue,
            WrLpcReceive,
            WrLpcReply,
            WrVirtualMemory,
            WrPageOut,
            WrRendezvous,
            Spare2,
            Spare3,
            Spare4,
            Spare5,
            Spare6,
            WrKernel,
            MaximumWaitReason
        };

        enum THREAD_STATE
        {
            Running = 2,
            Waiting = 5,
        };

#pragma pack(push,8)

        struct CLIENT_ID
        {
            HANDLE UniqueProcess; // Process ID
            HANDLE UniqueThread;  // Thread ID
        };

        // http://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/thread.htm
        // Size = 0x40 for Win32
        // Size = 0x50 for Win64
        struct SYSTEM_THREAD
        {
            LARGE_INTEGER KernelTime;
            LARGE_INTEGER UserTime;
            LARGE_INTEGER CreateTime;
            ULONG         WaitTime;
            PVOID         StartAddress;
            CLIENT_ID     ClientID;           // process/thread ids
            LONG          Priority;
            LONG          BasePriority;
            ULONG         ContextSwitches;
            THREAD_STATE  ThreadState;
            KWAIT_REASON  WaitReason;
        };

        struct VM_COUNTERS // virtual memory of process
        {
            ULONG_PTR PeakVirtualSize;
            ULONG_PTR VirtualSize;
            ULONG     PageFaultCount;
            ULONG_PTR PeakWorkingSetSize;
            ULONG_PTR WorkingSetSize;
            ULONG_PTR QuotaPeakPagedPoolUsage;
            ULONG_PTR QuotaPagedPoolUsage;
            ULONG_PTR QuotaPeakNonPagedPoolUsage;
            ULONG_PTR QuotaNonPagedPoolUsage;
            ULONG_PTR PagefileUsage;
            ULONG_PTR PeakPagefileUsage;
        };

        // http://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/process.htm
        // See also SYSTEM_PROCESS_INROMATION in Winternl.h
        // Size = 0x00B8 for Win32
        // Size = 0x0100 for Win64
        struct SYSTEM_PROCESS
        {
            ULONG          NextEntryOffset; // relative offset
            ULONG          ThreadCount;
            LARGE_INTEGER  WorkingSetPrivateSize;
            ULONG          HardFaultCount;
            ULONG          NumberOfThreadsHighWatermark;
            ULONGLONG      CycleTime;
            LARGE_INTEGER  CreateTime;
            LARGE_INTEGER  UserTime;
            LARGE_INTEGER  KernelTime;
            UNICODE_STRING ImageName;
            LONG           BasePriority;
            PVOID          UniqueProcessId;
            PVOID          InheritedFromUniqueProcessId;
            ULONG          HandleCount;
            ULONG          SessionId;
            ULONG_PTR      UniqueProcessKey;
            VM_COUNTERS    VmCounters;
            ULONG_PTR      PrivatePageCount;
            IO_COUNTERS    IoCounters;   // defined in winnt.h
        };

#pragma pack(pop)

    }

    typedef struct _STARTUPINFOEX {
        STARTUPINFO StartupInfo;
        PPROC_THREAD_ATTRIBUTE_LIST lpAttributeList;
    } STARTUPINFOEX, *LPSTARTUPINFOEX;

    using fn_NtOpenProcess = NTSTATUS NTAPI(
        PHANDLE            ProcessHandle,
        ACCESS_MASK        DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        CLIENT_ID*         ClientId
    );

    using fn_InitializeProcThreadAttributeList = BOOL NTAPI(
        LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
        DWORD dwAttributeCount,
        DWORD dwFlags,
        PSIZE_T lpSize
    );

    using fn_UpdateProcThreadAttribute = BOOL NTAPI(
        LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
        DWORD dwFlags,
        DWORD_PTR Attribute,
        PVOID lpValue,
        SIZE_T cbSize,
        PVOID lpPreviousValue,
        PSIZE_T lpReturnSize
    );

    using fn_NtUnmapViewOfSection = NTSTATUS NTAPI(
        HANDLE ProcessHandle,
        PVOID BaseAddress
    );

    using fn_NtQueryInformationProcess = NTSTATUS NTAPI(
        HANDLE ProcessHandle,
        DWORD ProcessInformationClass,
        PVOID ProcessInformation,
        DWORD ProcessInformationLength,
        PDWORD ReturnLength
    );

    using fn_NtQuerySystemInformation = NTSTATUS NTAPI(
        IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
        OUT PVOID SystemInformation,
        IN ULONG SystemInformationLength,
        OUT PULONG ReturnLength OPTIONAL
    );

    using fn_RtlCreateUserThread = NTSTATUS NTAPI(
        HANDLE ProcessHandle,
        PSECURITY_DESCRIPTOR SecurityDescriptor,
        BOOLEAN CreateSuspended,
        ULONG StackZeroBits,
        SIZE_T StackReserve,
        SIZE_T StackCommit,
        PTHREAD_START_ROUTINE StartAddress,
        PVOID Parameter,
        PHANDLE ThreadHandle,
        CLIENT_ID* ClientId
    );

    using fn_NtQueueApcThreadEx = NTSTATUS NTAPI(
        HANDLE ThreadHandle,
        HANDLE UserApcReserveHandle,
        PVOID ApcRoutine,
        PVOID ApcRoutineContext,
        PVOID ApcStatusBlock,
        PVOID ApcReserved
    );

    using fn_WriteFile = BOOL WINAPI(
        HANDLE       hFile,
        LPCVOID      lpBuffer,
        DWORD        nNumberOfBytesToWrite,
        LPDWORD      lpNumberOfBytesWritten,
        LPOVERLAPPED lpOverlapped
    );

    using fn_SetFilePointer = DWORD WINAPI(
        HANDLE hFile,
        LONG   lDistanceToMove,
        PLONG  lpDistanceToMoveHigh,
        DWORD  dwMoveMethod
    );

    using fn_ZwSetInformationThread = NTSTATUS NTAPI(
        HANDLE ThreadHandle,
        LONG ThreadInformationClass,
        PVOID ThreadInformation,
        ULONG ThreadInformationLength
    );

    using fn_OpenProcess = HANDLE WINAPI(
        DWORD dwDesiredAccess,
        BOOL  bInheritHandle,
        DWORD dwProcessId
    );

    using fn_VirtualProtectEx = BOOL WINAPI(
        HANDLE hProcess,
        LPVOID lpAddress,
        SIZE_T dwSize,
        DWORD  flNewProtect,
        PDWORD lpflOldProtect
    );

    using fn_QueueUserAPC = DWORD WINAPI(
        PVOID     pfnAPC,
        HANDLE    hThread,
        ULONG_PTR dwData
    );

    using fn_ReadProcessMemory = BOOL WINAPI(
        HANDLE  hProcess,
        LPCVOID lpBaseAddress,
        LPVOID  lpBuffer,
        SIZE_T  nSize,
        SIZE_T  *lpNumberOfBytesRead
    );

    using fn_NtReadVirtualMemory = NTSTATUS NTAPI(
        IN HANDLE  ProcessHandle,
        IN PVOID   BaseAddress,
        OUT PVOID  Buffer,
        IN ULONG   NumberOfBytesToRead,
        OUT PULONG NumberOfBytesReaded OPTIONAL
    );

    using fn_NtWriteVirtualMemory = NTSTATUS NTAPI(
        IN HANDLE  ProcessHandle,
        IN PVOID   BaseAddress,
        IN PVOID   Buffer,
        IN ULONG   NumberOfBytesToWrite,
        OUT PULONG NumberOfBytesWritten OPTIONAL
    );

    using fn_WriteProcessMemory = BOOL WINAPI(
        HANDLE  hProcess,
        LPVOID  lpBaseAddress,
        LPCVOID lpBuffer,
        SIZE_T  nSize,
        SIZE_T  *lpNumberOfBytesWritten
    );

    using fn_NtGetContextThread = BOOL NTAPI(
        HANDLE    hThread,
        LPCONTEXT lpContext
    );

    using fn_NtSetContextThread = BOOL NTAPI(
        HANDLE    hThread,
        LPCONTEXT lpContext
    );

    using fn_GetThreadContext = BOOL WINAPI(
        HANDLE    hThread,
        LPCONTEXT lpContext
    );

    using fn_GetUserNameW = BOOL WINAPI(
        LPWSTR  lpBuffer,
        LPDWORD pcbBuffer
    );

    using fn_GetComputerNameW = BOOL WINAPI(
        LPWSTR  lpBuffer,
        LPDWORD nSize
    );

    using fn_SetThreadContext = BOOL WINAPI(
        HANDLE    hThread,
        LPCONTEXT lpContext
    );

    using fn_CreateToolhelp32Snapshot = HANDLE WINAPI(
        DWORD dwFlags,
        DWORD th32ProcessID
    );

    using fn_Process32FirstW = BOOL WINAPI(
        HANDLE            hSnapshot,
        LPPROCESSENTRY32W lppe
    );

    using fn_Process32NextW = BOOL WINAPI(
        HANDLE            hSnapshot,
        LPPROCESSENTRY32W lppe
    );

    using fn_OpenThreadToken = BOOL WINAPI(
        HANDLE  ThreadHandle,
        DWORD   DesiredAccess,
        BOOL    OpenAsSelf,
        PHANDLE TokenHandle
    );

    using fn_CreateRemoteThread = HANDLE WINAPI(
        HANDLE                 hProcess,
        LPSECURITY_ATTRIBUTES  lpThreadAttributes,
        SIZE_T                 dwStackSize,
        LPTHREAD_START_ROUTINE lpStartAddress,
        LPVOID                 lpParameter,
        DWORD                  dwCreationFlags,
        LPDWORD                lpThreadId
    );

    using fn_CreateThread = HANDLE WINAPI(
        LPSECURITY_ATTRIBUTES   lpThreadAttributes,
        SIZE_T                  dwStackSize,
        LPTHREAD_START_ROUTINE  lpStartAddress,
        LPVOID                  lpParameter,
        DWORD                   dwCreationFlags,
        LPDWORD                 lpThreadId
    );

    using fn_VirtualAllocEx = LPVOID WINAPI(
        HANDLE hProcess,
        LPVOID lpAddress,
        SIZE_T dwSize,
        DWORD  flAllocationType,
        DWORD  flProtect
    );

    using fn_CreateFileMappingA = HANDLE WINAPI(
        HANDLE                hFile,
        LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
        DWORD                 flProtect,
        DWORD                 dwMaximumSizeHigh,
        DWORD                 dwMaximumSizeLow,
        LPCSTR                lpName
    );

    using fn_CreateFileMappingW = HANDLE WINAPI(
        HANDLE                hFile,
        LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
        DWORD                 flProtect,
        DWORD                 dwMaximumSizeHigh,
        DWORD                 dwMaximumSizeLow,
        LPCWSTR               lpName
    );

    using fn_MapViewOfFile = LPVOID WINAPI(
        HANDLE hFileMappingObject,
        DWORD  dwDesiredAccess,
        DWORD  dwFileOffsetHigh,
        DWORD  dwFileOffsetLow,
        SIZE_T dwNumberOfBytesToMap
    );

    using fn_VirtualAlloc = LPVOID WINAPI(
        LPVOID lpAddress,
        SIZE_T dwSize,
        DWORD  flAllocationType,
        DWORD  flProtect
    );

    using fn_LookupPrivilegeValueW = BOOL WINAPI(
        LPCWSTR lpSystemName,
        LPCWSTR lpName,
        PLUID   lpLuid
    );

    using fn_AdjustTokenPrivileges = BOOL WINAPI(
        HANDLE            TokenHandle,
        BOOL              DisableAllPrivileges,
        PTOKEN_PRIVILEGES NewState,
        DWORD             BufferLength,
        PTOKEN_PRIVILEGES PreviousState,
        PDWORD            ReturnLength
    );

    using fn_CreateProcessW = BOOL WINAPI(
        LPCWSTR               lpApplicationName,
        LPWSTR                lpCommandLine,
        LPSECURITY_ATTRIBUTES lpProcessAttributes,
        LPSECURITY_ATTRIBUTES lpThreadAttributes,
        BOOL                  bInheritHandles,
        DWORD                 dwCreationFlags,
        LPVOID                lpEnvironment,
        LPCWSTR               lpCurrentDirectory,
        LPSTARTUPINFOW        lpStartupInfo,
        LPPROCESS_INFORMATION lpProcessInformation
    );

    using fn_OpenProcessToken = BOOL WINAPI(
        HANDLE  ProcessHandle,
        DWORD   DesiredAccess,
        PHANDLE TokenHandle
    );

    using fn_GetTokenInformation = BOOL WINAPI(
        HANDLE  TokenHandle,
        DWORD   TokenInformationClass,
        LPVOID  TokenInformation,
        DWORD   TokenInformationLength,
        PDWORD  ReturnLength
    );

    using fn_NtAllocateVirtualMemory = NTSTATUS NTAPI(
        HANDLE    ProcessHandle,
        PVOID     *BaseAddress,
        ULONG_PTR ZeroBits,
        PSIZE_T   RegionSize,
        ULONG     AllocationType,
        ULONG     Protect
    );

    using fn_VirtualAllocExNuma = LPVOID WINAPI(
        HANDLE hProcess,
        LPVOID lpAddress,
        SIZE_T dwSize,
        DWORD  flAllocationType,
        DWORD  flProtect,
        DWORD  nndPreferred
    );

    using fn_VirtualFreeEx = BOOL WINAPI(
        HANDLE hProcess,
        LPVOID lpAddress,
        SIZE_T dwSize,
        DWORD  dwFreeType
    );

    using fn_ZwCreateSection = NTSTATUS NTAPI(
        PHANDLE            SectionHandle,
        ACCESS_MASK        DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        PLARGE_INTEGER     MaximumSize,
        ULONG              SectionPageProtection,
        ULONG              AllocationAttributes,
        HANDLE             FileHandle
    );

    using fn_NtMapViewOfSection = NTSTATUS NTAPI(
        HANDLE          SectionHandle,
        HANDLE          ProcessHandle,
        PVOID           *BaseAddress,
        ULONG_PTR       ZeroBits,
        SIZE_T          CommitSize,
        PLARGE_INTEGER  SectionOffset,
        PSIZE_T         ViewSize,
        DWORD           InheritDisposition,
        ULONG           AllocationType,
        ULONG           Win32Protect
    );

    //SOURCE: http://processhacker.sourceforge.net/doc/ntpsapi_8h_source.html
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001
#define THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH 0x00000002 // ?
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x00000004
#define THREAD_CREATE_FLAGS_HAS_SECURITY_DESCRIPTOR 0x00000010 // ?
#define THREAD_CREATE_FLAGS_ACCESS_CHECK_IN_TARGET 0x00000020 // ?
#define THREAD_CREATE_FLAGS_INITIAL_THREAD 0x00000080

    using fn_ZwCreateThreadEx = NTSTATUS NTAPI(
        PHANDLE             ThreadHandle,
        ACCESS_MASK         DesiredAccess,
        POBJECT_ATTRIBUTES  ObjectAttributes,
        HANDLE              ProcessHandle,
        PVOID               StartRoutine,
        PVOID               Argument,
        ULONG               CreateFlags,
        ULONG_PTR           ZeroBits,
        SIZE_T              StackSize,
        SIZE_T              MaximumStackSize,
        PVOID               AttributeList
    );

    using fn_ZwUnmapViewOfSection = NTSTATUS NTAPI(
        HANDLE ProcessHandle,
        PVOID  BaseAddress
    );

    using fn_ZwClose = NTSTATUS NTAPI(
        HANDLE Handle
    );

    using fn_NtProtectVirtualMemory = NTSTATUS NTAPI(
        HANDLE ProcessHandle,
        PVOID  *BaseAddress,
        PULONG NumberOfBytesToProtect,
        ULONG  NewAccessProtection,
        PULONG OldAccessProtection
    );

    using fn_NtOpenThread = NTSTATUS WINAPI(
        _Out_ PHANDLE            ThreadHandle,
        _In_  ACCESS_MASK        DesiredAccess,
        _In_  POBJECT_ATTRIBUTES ObjectAttributes,
        _In_  CLIENT_ID         *ClientId
    );

    using fn_OpenThread = HANDLE WINAPI(
        DWORD dwDesiredAccess,
        BOOL  bInheritHandle,
        DWORD dwThreadId
    );

    using fn_Thread32First = BOOL WINAPI(
        HANDLE          hSnapshot,
        LPTHREADENTRY32 lpte
    );

    using fn_Thread32Next = BOOL WINAPI(
        HANDLE          hSnapshot,
        LPTHREADENTRY32 lpte
    );

    using fn_EnumChildWindows = BOOL WINAPI(
        HWND        hWndParent,
        WNDENUMPROC lpEnumFunc,
        LPARAM      lParam
    );

    using fn_EnumPropsExW = int WINAPI(
        HWND            hWnd,
        PROPENUMPROCEXW lpEnumFunc,
        LPARAM          lParam
    );

    using fn_EnumWindows = BOOL WINAPI(
        WNDENUMPROC lpEnumFunc,
        LPARAM      lParam
    );

    using fn_GetPropW = HANDLE WINAPI(
        HWND    hWnd,
        LPCWSTR lpString
    );

     using fn_SetPropW = BOOL WINAPI(
        HWND    hWnd,
        LPCWSTR lpString,
        HANDLE  hData
    );

    using fn_UnmapViewOfFile = BOOL WINAPI(
        LPCVOID lpBaseAddress
    );

    using fn_NtQueryInformationProcess = NTSTATUS NTAPI(
        HANDLE ProcessHandle,
        DWORD ProcessInformationClass,
        PVOID ProcessInformation,
        DWORD ProcessInformationLength,
        PDWORD ReturnLength
    );

    using fn_CreateFileA = HANDLE WINAPI(
        LPCSTR                lpFileName,
        DWORD                 dwDesiredAccess,
        DWORD                 dwShareMode,
        LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        DWORD                 dwCreationDisposition,
        DWORD                 dwFlagsAndAttributes,
        HANDLE                hTemplateFile
    );

    using fn_CreateToolhelp32Snapshot = HANDLE WINAPI(
        DWORD dwFlags,
        DWORD th32ProcessID
    );

    using fn_Module32FirstW = BOOL WINAPI(
        HANDLE            hSnapshot,
        LPMODULEENTRY32W  lppe
    );

    using fn_Module32NextW = BOOL WINAPI(
        HANDLE            hSnapshot,
        LPMODULEENTRY32W  lppe
    );

    using fn_OpenProcess = HANDLE WINAPI(
        DWORD dwDesiredAccess,
        BOOL  bInheritHandle,
        DWORD dwProcessId
    );

    using fn_MapViewOfFile = LPVOID WINAPI(
        HANDLE hFileMappingObject,
        DWORD  dwDesiredAccess,
        DWORD  dwFileOffsetHigh,
        DWORD  dwFileOffsetLow,
        SIZE_T dwNumberOfBytesToMap
    );

    using fn_VirtualProtectEx = BOOL WINAPI(
        HANDLE hProcess,
        LPVOID lpAddress,
        SIZE_T dwSize,
        DWORD  flNewProtect,
        PDWORD lpflOldProtect
    );

    using fn_ReadProcessMemory = BOOL WINAPI(
        HANDLE  hProcess,
        LPCVOID lpBaseAddress,
        LPVOID  lpBuffer,
        SIZE_T  nSize,
        SIZE_T  *lpNumberOfBytesRead
    );

    using fn_WriteProcessMemory = BOOL WINAPI(
        HANDLE  hProcess,
        LPVOID  lpBaseAddress,
        LPCVOID lpBuffer,
        SIZE_T  nSize,
        SIZE_T  *lpNumberOfBytesWritten
    );

    using fn_VirtualQueryEx = SIZE_T WINAPI(
        HANDLE                    hProcess,
        LPCVOID                   lpAddress,
        PMEMORY_BASIC_INFORMATION lpBuffer,
        SIZE_T                    dwLength
    );

    using fn_NtUnmapViewOfSection = NTSTATUS NTAPI(
        HANDLE ProcessHandle,
        PVOID  BaseAddress
    );

    using fn_CreateEventW = HANDLE WINAPI(
        LPSECURITY_ATTRIBUTES lpEventAttributes,
        BOOL                  bManualReset,
        BOOL                  bInitialState,
        LPCWSTR               lpName
    );

    using fn_SetEvent = BOOL WINAPI(
        HANDLE hEvent
    );

    typedef enum _SE_OBJECT_TYPE {
        SE_UNKNOWN_OBJECT_TYPE,
        SE_FILE_OBJECT,
        SE_SERVICE,
        SE_PRINTER,
        SE_REGISTRY_KEY,
        SE_LMSHARE,
        SE_KERNEL_OBJECT,
        SE_WINDOW_OBJECT,
        SE_DS_OBJECT,
        SE_DS_OBJECT_ALL,
        SE_PROVIDER_DEFINED_OBJECT,
        SE_WMIGUID_OBJECT,
        SE_REGISTRY_WOW64_32KEY,
        SE_REGISTRY_WOW64_64KEY
    } SE_OBJECT_TYPE;

    using fn_SetSecurityInfo = DWORD WINAPI(
        HANDLE               handle,
        SE_OBJECT_TYPE       ObjectType,
        SECURITY_INFORMATION SecurityInfo,
        PSID                 psidOwner,
        PSID                 psidGroup,
        PACL                 pDacl,
        PACL                 pSacl
    );

    using fn_GlobalAddAtomA = ATOM WINAPI(
        LPCSTR lpString
    );

    using fn_GlobalGetAtomNameA = UINT WINAPI(
        ATOM  nAtom,
        LPSTR lpBuffer,
        int   nSize
    );

    using fn_NtResumeThread = NTSTATUS NTAPI(
        HANDLE ThreadHandle,
        PULONG SuspendCount
    );

    using fn_NtSuspendThread = NTSTATUS NTAPI(
        HANDLE ThreadHandle,
        PULONG SuspendCount
    );

    using fn_NtDelayExecution = NTSTATUS NTAPI(
        BOOLEAN Alertable,
        PLARGE_INTEGER DelayInterval
    );

    using fn_ObtainUserAgentString = HRESULT WINAPI(
        DWORD dwOption, 
        LPCSTR pcszUAOut, 
        DWORD* cbSize
    );

    using fn_VirtualQuery = SIZE_T WINAPI(
        LPCVOID                   lpAddress,
        PMEMORY_BASIC_INFORMATION lpBuffer,
        SIZE_T                    dwLength
    );

    using fn_InternetOpenW = HANDLE WINAPI(
        LPCWSTR  lpszAgent,
        DWORD    dwAccessType,
        LPCWSTR  lpszProxy,
        LPCWSTR  lpszProxyBypass,
        DWORD    dwFlags
    );

    using fn_InternetConnectW = HANDLE WINAPI(
        HANDLE        hInternet,
        LPCWSTR       lpszServerName,
        WORD          nServerPort,
        LPCWSTR       lpszUserName,
        LPCWSTR       lpszPassword,
        DWORD         dwService,
        DWORD         dwFlags,
        DWORD_PTR     dwContext
    );

    using fn_HttpOpenRequestW = HANDLE WINAPI(
        HANDLE    hConnect,
        LPCWSTR   lpszVerb,
        LPCWSTR   lpszObjectName,
        LPCWSTR   lpszVersion,
        LPCWSTR   lpszReferrer,
        LPCWSTR   *lplpszAcceptTypes,
        DWORD     dwFlags,
        DWORD_PTR dwContext
    );

    using fn_InternetCrackUrlW = BOOL WINAPI(
        LPCWSTR           lpszUrl,
        DWORD             dwUrlLength,
        DWORD             dwFlags,
        LPURL_COMPONENTSW lpUrlComponents
    );

    using fn_HttpSendRequestW = BOOL WINAPI(
        HANDLE    hRequest,
        LPCWSTR   lpszHeaders,
        DWORD     dwHeadersLength,
        LPVOID    lpOptional,
        DWORD     dwOptionalLength
    );

    using fn_InternetReadFile = BOOL WINAPI(
        HANDLE    hFile,
        LPVOID    lpBuffer,
        DWORD     dwNumberOfBytesToRead,
        LPDWORD   lpdwNumberOfBytesRead
    );

    using fn_InternetGetLastResponseInfoW = BOOL WINAPI(
        LPDWORD lpdwError,
        LPWSTR  lpszBuffer,
        LPDWORD lpdwBufferLength
    );

    using fn_InternetCloseHandle = BOOL WINAPI(
        HANDLE  hInternet
    );

    using fn_HttpQueryInfoW = BOOL WINAPI(
        HANDLE    hRequest,
        DWORD     dwInfoLevel,
        LPVOID    lpBuffer,
        LPDWORD   lpdwBufferLength,
        LPDWORD   lpdwIndex
    );

    using fn_CoInitializeEx = HRESULT WINAPI(
        LPVOID pvReserved,
        DWORD  dwCoInit
    );

    using fn_CoInitializeSecurity = HRESULT WINAPI(
        PSECURITY_DESCRIPTOR        pSecDesc,
        LONG                        cAuthSvc,
        SOLE_AUTHENTICATION_SERVICE *asAuthSvc,
        void                        *pReserved1,
        DWORD                       dwAuthnLevel,
        DWORD                       dwImpLevel,
        void                        *pAuthList,
        DWORD                       dwCapabilities,
        void                        *pReserved3
    );

    using fn_CoCreateInstance = HRESULT WINAPI(
        REFCLSID  rclsid,
        LPUNKNOWN pUnkOuter,
        DWORD     dwClsContext,
        REFIID    riid,
        LPVOID    *ppv
    );

    using fn_SysAllocString = BSTR WINAPI(
        const OLECHAR *psz
    );

    using fn_SysFreeString = BSTR WINAPI(
        const OLECHAR *psz
    );

    using fn_CoUninitialize = void WINAPI();

    using fn_CoSetProxyBlanket = HRESULT WINAPI(
        IUnknown                 *pProxy,
        DWORD                    dwAuthnSvc,
        DWORD                    dwAuthzSvc,
        OLECHAR                  *pServerPrincName,
        DWORD                    dwAuthnLevel,
        DWORD                    dwImpLevel,
        RPC_AUTH_IDENTITY_HANDLE pAuthInfo,
        DWORD                    dwCapabilities
    );

    using fn_CLSIDFromString = HRESULT WINAPI(
        LPCOLESTR lpsz,
        LPCLSID   pclsid
    );

    using fn_NetGetJoinInformation = NET_API_STATUS WINAPI(
        LPCWSTR               lpServer,
        LPWSTR                *lpNameBuffer,
        PNETSETUP_JOIN_STATUS BufferType
    );

    using fn_DsRoleGetPrimaryDomainInformation = DWORD WINAPI(
        IN LPCWSTR                          lpServer,
        IN DSROLE_PRIMARY_DOMAIN_INFO_LEVEL InfoLevel,
        OUT PBYTE                           *Buffer
    );

    using fn_DsRoleFreeMemory = void WINAPI(
        IN PVOID Buffer
    );

    using fn_CommandLineToArgvW = LPWSTR * WINAPI(
        LPCWSTR lpCmdLine,
        int     *pNumArgs
    );

    using fn_GetParent = HWND WINAPI(
        HWND hWnd
    );

    using fn_GetWindowThreadProcessId = DWORD WINAPI(
        HWND    hWnd,
        LPDWORD lpdwProcessId
    );

    using fn_GetClassNameW = int WINAPI(
        HWND   hWnd,
        LPWSTR lpClassName,
        int    nMaxCount
    );

    using fn_PostMessageW = BOOL WINAPI(
        HWND   hWnd,
        UINT   Msg,
        WPARAM wParam,
        LPARAM lParam
    );

    using fn_GetCursorPos = BOOL WINAPI(
        LPPOINT lpPoint
    );

    using fn_ImpersonateSelf = BOOL WINAPI(
        SECURITY_IMPERSONATION_LEVEL ImpersonationLevel
    );

    using fn_GetSidSubAuthority = PDWORD WINAPI(
        PSID  pSid,
        DWORD nSubAuthority
    );

    using fn_GetSidSubAuthorityCount = PUCHAR WINAPI(
        PSID pSid
    );

    using fn_LookupAccountSidW = BOOL WINAPI(
        LPCWSTR       lpSystemName,
        PSID          Sid,
        LPWSTR        Name,
        LPDWORD       cchName,
        LPWSTR        ReferencedDomainName,
        LPDWORD       cchReferencedDomainName,
        PSID_NAME_USE peUse
    );

    using fn_GetSystemInfo = void WINAPI(
        LPSYSTEM_INFO lpSystemInfo
    );

    using fn_GlobalMemoryStatusEx = BOOL WINAPI(
        LPMEMORYSTATUSEX lpBuffer
    );

    using fn_GetPhysicallyInstalledSystemMemory = BOOL WINAPI(
        PULONGLONG TotalMemoryInKilobytes
    );

    using fn_QueryPerformanceCounter = BOOL WINAPI(
        LARGE_INTEGER *lpPerformanceCount
    );

    using fn_QueryPerformanceFrequency = BOOL WINAPI(
        LARGE_INTEGER *lpPerformanceCount
    );

    using fn_SetProcessMitigationPolicy = BOOL WINAPI(
        PROCESS_MITIGATION_POLICY MitigationPolicy,
        PVOID                     lpBuffer,
        SIZE_T                    dwLength
    );

    using fn_GetThreadTimes = BOOL WINAPI(
        HANDLE     hThread,
        LPFILETIME lpCreationTime,
        LPFILETIME lpExitTime,
        LPFILETIME lpKernelTime,
        LPFILETIME lpUserTime
    );

    using fn_PeekNamedPipe = BOOL WINAPI(
        HANDLE  hNamedPipe,
        LPVOID  lpBuffer,
        DWORD   nBufferSize,
        LPDWORD lpBytesRead,
        LPDWORD lpTotalBytesAvail,
        LPDWORD lpBytesLeftThisMessage
    );

    using fn_CreatePipe = BOOL WINAPI(
        PHANDLE               hReadPipe,
        PHANDLE               hWritePipe,
        LPSECURITY_ATTRIBUTES lpPipeAttributes,
        DWORD                 nSize
    );

    using fn_GetComputerNameW = BOOL WINAPI(
        LPWSTR  lpBuffer,
        LPDWORD nSize
    );

    using fn_GetComputerNameExW = BOOL WINAPI(
        COMPUTER_NAME_FORMAT NameType,
        LPWSTR               lpBuffer,
        LPDWORD              nSize
    );

    using fn_QueryFullProcessImageNameA = BOOL WINAPI(
        HANDLE hProcess,
        DWORD  dwFlags,
        LPSTR  lpExeName,
        PDWORD lpdwSize
    );

    using fn_RegOpenKeyExW = LSTATUS WINAPI(
        HKEY    hKey,
        LPCWSTR lpSubKey,
        DWORD   ulOptions,
        REGSAM  samDesired,
        PHKEY   phkResult
    );

    using fn_RegEnumKeyExW = LSTATUS WINAPI(
        HKEY      hKey,
        DWORD     dwIndex,
        LPWSTR    lpName,
        LPDWORD   lpcchName,
        LPDWORD   lpReserved,
        LPWSTR    lpClass,
        LPDWORD   lpcchClass,
        PFILETIME lpftLastWriteTime
    );

    using fn_RegCloseKey = LSTATUS WINAPI(
        HKEY hKey
    );

    using fn_RegEnumValueW = LSTATUS WINAPI(
        HKEY    hKey,
        DWORD   dwIndex,
        LPWSTR  lpValueName,
        LPDWORD lpcchValueName,
        LPDWORD lpReserved,
        LPDWORD lpType,
        LPBYTE  lpData,
        LPDWORD lpcbData
    );

    using fn_FindFirstFileW = HANDLE WINAPI(
        LPCWSTR            lpFileName,
        LPWIN32_FIND_DATAW lpFindFileData
    );

    using fn_FindNextFileW = BOOL WINAPI(
        HANDLE             hFindFile,
        LPWIN32_FIND_DATAW lpFindFileData
    );

    using fn_IsNativeVhdBoot = BOOL WINAPI(
        PBOOL NativeVhdBoot
    );

    using fn_SetupDiGetClassDevsW = HDEVINFO WINAPI(
        const GUID* ClassGuid,
        PCWSTR Enumerator,
        HWND hwndParent,
        DWORD Flags
    );

    using fn_SetupDiEnumDeviceInfo = BOOL WINAPI(
        HDEVINFO DeviceInfoSet,
        DWORD MemberIndex,
        PSP_DEVINFO_DATA DeviceInfoData
    );

    using fn_SetupDiGetDeviceRegistryPropertyW = BOOL WINAPI(
        HDEVINFO         DeviceInfoSet,
        PSP_DEVINFO_DATA DeviceInfoData,
        DWORD            Property,
        PDWORD           PropertyRegDataType,
        PBYTE            PropertyBuffer,
        DWORD            PropertyBufferSize,
        PDWORD           RequiredSize
    );

    using fn_CreateFileW = HANDLE WINAPI(
        LPCWSTR               lpFileName,
        DWORD                 dwDesiredAccess,
        DWORD                 dwShareMode,
        LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        DWORD                 dwCreationDisposition,
        DWORD                 dwFlagsAndAttributes,
        HANDLE                hTemplateFile
    );

    using fn_NtCreateFile = NTSTATUS WINAPI(
        OUT PHANDLE           FileHandle,
        IN ACCESS_MASK        DesiredAccess,
        IN POBJECT_ATTRIBUTES ObjectAttributes,
        OUT PIO_STATUS_BLOCK  IoStatusBlock,
        IN PLARGE_INTEGER     AllocationSize,
        IN ULONG              FileAttributes,
        IN ULONG              ShareAccess,
        IN ULONG              CreateDisposition,
        IN ULONG              CreateOptions,
        IN PVOID              EaBuffer,
        IN ULONG              EaLength
    );

    using fn_RtlInitUnicodeString = void WINAPI(
        PUNICODE_STRING DestinationString,
        PCWSTR          SourceString
    );

    using fn_RtlSecureZeroMemory = PVOID WINAPI(
        PVOID  ptr,
        SIZE_T cnt
    );

    using fn_GetNativeSystemInfo = void WINAPI(
        LPSYSTEM_INFO lpSystemInfo
    );

    using fn_IsWow64Process = BOOL WINAPI(
        HANDLE hProcess,
        PBOOL  Wow64Process
    );

    using fn_SetThreadPriorityBoost = BOOL WINAPI(
        HANDLE hThread,
        BOOL   bDisablePriorityBoost
    );

    using fn_SetThreadPriority = BOOL WINAPI(
        HANDLE hThread,
        int    nPriority
    );

    using fn_GetThreadPriority = int WINAPI(
        HANDLE hThread
    );
    
    using fn_NtTestAlert = NTSTATUS WINAPI(
    );

    using fn_GetFileSizeEx = BOOL WINAPI(
        HANDLE         hFile,
        PLARGE_INTEGER lpFileSize
    );

    using fn_ReadFile = BOOL WINAPI(
        HANDLE       hFile,
        LPVOID       lpBuffer,
        DWORD        nNumberOfBytesToRead,
        LPDWORD      lpNumberOfBytesRead,
        LPOVERLAPPED lpOverlapped
    );

    using fn_VirtualProtect = BOOL WINAPI(
        LPVOID lpAddress,
        SIZE_T dwSize,
        DWORD  flNewProtect,
        PDWORD lpflOldProtect
    );

    using fn_TerminateProcess = BOOL WINAPI(
        HANDLE hProcess,
        UINT uExitCode
    );

    using fn_QueryFullProcessImageNameW = BOOL WINAPI(
        HANDLE hProcess,
        DWORD  dwFlags,
        LPWSTR lpExeName,
        PDWORD lpdwSize
    );

    using fn_SleepEx = DWORD WINAPI(
        DWORD dwMilliseconds,
        BOOL  bAlertable
    );

    using fn_GetFileAttributesW = DWORD WINAPI(
        LPCWSTR lpFileName
    );

    using fn_DeviceIoControl = BOOL WINAPI(
        HANDLE       hDevice,
        DWORD        dwIoControlCode,
        LPVOID       lpInBuffer,
        DWORD        nInBufferSize,
        LPVOID       lpOutBuffer,
        DWORD        nOutBufferSize,
        LPDWORD      lpBytesReturned,
        LPOVERLAPPED lpOverlapped
    );

    using fn_CreateThread = HANDLE WINAPI(
        LPSECURITY_ATTRIBUTES   lpThreadAttributes,
        SIZE_T                  dwStackSize,
        LPTHREAD_START_ROUTINE  lpStartAddress,
        __drv_aliasesMem LPVOID lpParameter,
        DWORD                   dwCreationFlags,
        LPDWORD                 lpThreadId
    );

    using fn_MessageBoxW = int WINAPI(
        HWND    hWnd,
        LPCWSTR lpText,
        LPCWSTR lpCaption,
        UINT    uType
    );
}

typedef LRESULT(CALLBACK *SUBCLASSPROC)(
    HWND      hWnd,
    UINT      uMsg,
    WPARAM    wParam,
    LPARAM    lParam,
    UINT_PTR  uIdSubclass,
    DWORD_PTR dwRefData
);

typedef struct _SUBCLASS_CALL {
    SUBCLASSPROC pfnSubclass;    // subclass procedure
    WPARAM       uIdSubclass;    // unique subclass identifier
    DWORD_PTR    dwRefData;      // optional ref data
} SUBCLASS_CALL, PSUBCLASS_CALL;

typedef struct _SUBCLASS_FRAME {
    UINT                    uCallIndex;   // index of next callback to call
    UINT                    uDeepestCall; // deepest uCallIndex on stack
    struct _SUBCLASS_FRAME  *pFramePrev;  // previous subclass frame pointer
    struct _SUBCLASS_HEADER *pHeader;     // header associated with this frame
} SUBCLASS_FRAME, PSUBCLASS_FRAME;

typedef struct _SUBCLASS_HEADER {
    UINT           uRefs;        // subclass count
    UINT           uAlloc;       // allocated subclass call nodes
    UINT           uCleanup;     // index of call node to clean up
    DWORD          dwThreadId;   // thread id of window we are hooking
    SUBCLASS_FRAME *pFrameCur;   // current subclass frame pointer
    SUBCLASS_CALL  CallArray[1]; // base of packed call node array
} SUBCLASS_HEADER, *PSUBCLASS_HEADER;