#include <windows.h>
#include <tchar.h>
#include <iostream>
#include <lmcons.h>
#include <strsafe.h>
#include <userenv.h>
#include <wtsapi32.h>
#include <TlHelp32.h>
#include <unordered_map>

//#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "wtsapi32.lib")


SERVICE_STATUS ServiceStatus;
SERVICE_STATUS_HANDLE hStatus;

void ServiceMain(int argc, char** argv);
void ControlHandler(DWORD request);
std::wstring GetCurrentUserName();
VOID SvcReportEvent(LPCTSTR szFunction);
void RunNotepadAsCurrentUser();
bool IsProcessRunning(const wchar_t* processName);
void ReadIniSection(const char* sectionName, const char* iniFilePath, std::unordered_map<std::string, std::string>& keyValueMap);
void MakerIniSectionMap(const char* ptr, std::unordered_map<std::string, std::string>& keyValueMap);
bool IsWorkingAutoUpDate(std::unordered_map<std::string, std::string>& keyValueMap);

#define SVCNAME TEXT("VPOS WatchDog")
#define EXENAME TEXT("VPos_Connector.exe")


int _tmain(int argc, TCHAR* argv[]) {

    TCHAR logBuf[2048];
    TCHAR SVCNAME_T[1024];
    swprintf_s(SVCNAME_T,_countof(SVCNAME_T), L"%s", SVCNAME);

    SERVICE_TABLE_ENTRY ServiceTable[] = {
        { SVCNAME_T, (LPSERVICE_MAIN_FUNCTION)ServiceMain },
        { NULL, NULL }
    };

    if (!StartServiceCtrlDispatcher(ServiceTable)) {
        //std::cerr << "StartServiceCtrlDispatcher error: " << GetLastError() << std::endl;
        memset(logBuf, 0x00, _countof(logBuf));
        swprintf_s(logBuf, _countof(logBuf), L"StartServiceCtrlDispatcher error: %d" , GetLastError());
        SvcReportEvent(logBuf);
        return 1;
    }
    else {
        memset(logBuf, 0x00, _countof(logBuf));
        swprintf_s(logBuf, _countof(logBuf), L"StartServiceCtrlDispatcher Success");
        SvcReportEvent(logBuf);
    }

    return 0;
}


void ServiceMain(int argc, char** argv) {
    TCHAR logBuf[2048];
    ServiceStatus.dwServiceType = SERVICE_WIN32;
    ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    ServiceStatus.dwWin32ExitCode = 0;
    ServiceStatus.dwServiceSpecificExitCode = 0;
    ServiceStatus.dwCheckPoint = 0;
    ServiceStatus.dwWaitHint = 0;

    TCHAR  sExeName[1024];
    swprintf_s(sExeName, _countof(sExeName), TEXT("%s"), EXENAME);

    const char* section = "UPDATE";
    const char* path = "C:\\KOVAN\\update_result.ini";

    std::unordered_map<std::string, std::string> myUnorderedMap;

    hStatus = RegisterServiceCtrlHandler(SVCNAME, (LPHANDLER_FUNCTION)ControlHandler);
    if (hStatus == (SERVICE_STATUS_HANDLE)0) {
        memset(logBuf, 0x00, _countof(logBuf));
        swprintf_s(logBuf, _countof(logBuf), L"RegisterServiceCtrlHandler error: %d", GetLastError());
        SvcReportEvent(logBuf);
        return;
    }

    ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(hStatus, &ServiceStatus);

    while (ServiceStatus.dwCurrentState == SERVICE_RUNNING) {

        if (!IsProcessRunning(sExeName)) {
            memset(logBuf, 0x00, _countof(logBuf));
            swprintf_s(logBuf, _countof(logBuf), L"IsProcessRunning is Faill Restart VPOS");
            SvcReportEvent(logBuf);
            ReadIniSection(section, path, myUnorderedMap);

            if (!IsWorkingAutoUpDate(myUnorderedMap)) {
                RunNotepadAsCurrentUser();
            }
        }
        Sleep(11000); // 11초 동안 대기
    }

    return;
}
bool IsWorkingAutoUpDate(std::unordered_map<std::string, std::string>& keyValueMap) {
    bool rtnFlag = true;

    if (keyValueMap["RESULT"].compare("OK") == 0) {
        rtnFlag = false;

    }

    return rtnFlag;

}


void ControlHandler(DWORD request) {
    switch (request) {
    case SERVICE_CONTROL_STOP:
        ServiceStatus.dwWin32ExitCode = 0;
        ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(hStatus, &ServiceStatus);
        return;

    case SERVICE_CONTROL_SHUTDOWN:
        ServiceStatus.dwWin32ExitCode = 0;
        ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(hStatus, &ServiceStatus);
        return;

    default:
        break;
    }

    SetServiceStatus(hStatus, &ServiceStatus);

    return;
}

std::wstring GetCurrentUserName() {
    DWORD size = UNLEN + 1;
    wchar_t username[UNLEN + 1];

    if (GetUserNameW(username, &size)) {
        return std::wstring(username);
    }
    else {
        //std::cerr << "GetUserNameW failed: " << GetLastError() << std::endl;
        //memset(logBuf, 0x00, _countof(logBuf));
        //swprintf_s(logBuf, _countof(logBuf), L"CreateProcessWithLogonW failed : % d", GetLastError());
        //LogPrint(logBuf);
        return L"";
    }
}
VOID SvcReportEvent(LPCTSTR szFunction)
{
    HANDLE hEventSource;
    LPCTSTR lpszStrings[2];
    TCHAR Buffer[80];
    DWORD dwData = EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | EVENTLOG_INFORMATION_TYPE;

    hEventSource = RegisterEventSource(NULL, SVCNAME);

    if (NULL != hEventSource)
    {
        StringCchPrintf(Buffer, 80, TEXT("%s"), szFunction);

        lpszStrings[0] = SVCNAME;
        lpszStrings[1] = Buffer;


        ReportEvent(hEventSource,        // event log handle
            EVENTLOG_ERROR_TYPE, // event type
            0,                   // event category
            dwData,           // event identifier
            NULL,                // no security identifier
            2,                   // size of lpszStrings array
            0,                   // no binary data
            lpszStrings,         // array of strings
            NULL);               // no binary data

        DeregisterEventSource(hEventSource);
    }
}

void RunNotepadAsCurrentUser() {
    DWORD sessionId = WTSGetActiveConsoleSessionId();
    HANDLE hToken = NULL;
    HANDLE hTokenDup = NULL;
    wchar_t szCmdline[] = TEXT("\"C:\\KOVAN\\VPos_Connector.exe");
    TCHAR logBuf[2048];

    if (WTSQueryUserToken(sessionId, &hToken)) {
        if (DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityIdentification, TokenPrimary, &hTokenDup)) {
            STARTUPINFO si;
            PROCESS_INFORMATION pi;
            ZeroMemory(&si, sizeof(si));
            si.cb = sizeof(si);
            ZeroMemory(&pi, sizeof(pi));

            if (CreateProcessAsUser(hTokenDup,
                NULL,
                szCmdline,
                NULL,
                NULL,
                FALSE,
                0,
                NULL,
                NULL,
                &si,
                &pi)) {
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
            }
            else {
                //std::cerr << "CreateProcessAsUser failed: " << GetLastError() << std::endl;
                memset(logBuf, 0x00, _countof(logBuf));
                swprintf_s(logBuf, _countof(logBuf), L"CreateProcessAsUser failed: %d" , GetLastError());
                SvcReportEvent(logBuf);
            }

            CloseHandle(hTokenDup);
        }
        else {
            //std::cerr << "DuplicateTokenEx failed: " << GetLastError() << std::endl;
            memset(logBuf, 0x00, _countof(logBuf));
            swprintf_s(logBuf, _countof(logBuf), L"DuplicateTokenEx failed: %d", GetLastError());
            SvcReportEvent(logBuf);
        }
        CloseHandle(hToken);
    }
    else {
        //std::cerr << "WTSQueryUserToken failed: " << GetLastError() << std::endl;
        memset(logBuf, 0x00, _countof(logBuf));
        swprintf_s(logBuf, _countof(logBuf), L"WTSQueryUserToken failed: %d", GetLastError());
        SvcReportEvent(logBuf);
    }
}
bool IsProcessRunning(const wchar_t* processName) {
    bool exists = false;
    TCHAR getName[1024];
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnap, &pe32)) {
            do {
                swprintf_s(getName, _countof(getName), TEXT("%s"), pe32.szExeFile);
                if (wcsncmp(getName, processName, wcslen(getName)) == 0) {
                    exists = true;
                    break;
                }
            } while (Process32Next(hSnap, &pe32));
        }
        CloseHandle(hSnap);
    }
    return exists;
}
void ReadIniSection(const char* sectionName, const char* iniFilePath , std::unordered_map<std::string, std::string>& keyValueMap) {
    const int bufferSize = 1024; // 적절한 버퍼 크기 선택
    TCHAR logBuf[1024];

    char buffer[bufferSize]; // 값을 읽어올 버퍼
    DWORD bytesRead = GetPrivateProfileSectionA(sectionName, buffer, bufferSize, iniFilePath);

    if (bytesRead > 0) {
        std::cout << "Values in section [" << sectionName << "]:" << std::endl;

        // 버퍼에서 각 키-값 쌍을 분리하여 출력
        const char* ptr = buffer;
        MakerIniSectionMap(ptr , keyValueMap);
    }
    else {
        //std::cerr << "Failed to read section [" << sectionName << "] from INI file." << std::endl;
        memset(logBuf, 0x00, _countof(logBuf));
        swprintf_s(logBuf, _countof(logBuf), L"Failed to read section[%Ts] from INI file." , sectionName);
        SvcReportEvent(logBuf);

        std::string key("NO");
        keyValueMap["RESULT"] = key;
    }
}
void MakerIniSectionMap(const char* ptr , std::unordered_map<std::string, std::string>& keyValueMap) {
    //std::unordered_map<std::string, std::string> myUnorderedMap;

    while (*ptr != '\0') {
        // "=" 문자로 key와 value를 구분하여 map에 저장
        const char* equalSign = strchr(ptr, '=');
        if (equalSign != nullptr) {
            std::string key(ptr, equalSign - ptr);
            std::string value(equalSign + 1);

            // std::unordered_map에 저장
            keyValueMap[key] = value;
        }
        ptr += strlen(ptr) + 1; // 다음 키-값 쌍으로 이동
    }
    /*for (const auto& pair : keyValueMap) {
        std::cout << "Key: " << pair.first << ", Value: " << pair.second << std::endl;
    }*/
}

