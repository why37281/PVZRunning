// CrashDebugger.cpp
#define UNICODE
#define _UNICODE

#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <psapi.h>

class ProcessDebugger {
private:
    DWORD processId;
    HANDLE processHandle;
    bool debugging;

public:
    ProcessDebugger() : processId(0), processHandle(NULL), debugging(false) {}

    ~ProcessDebugger() {
        detach();
    }

    DWORD FindProcessByName(const std::wstring& processName) {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) {
            std::cout << "创建进程快照失败" << std::endl;
            return 0;
        }

        PROCESSENTRY32W processEntry;
        processEntry.dwSize = sizeof(PROCESSENTRY32W);

        DWORD foundPid = 0;
        if (Process32FirstW(snapshot, &processEntry)) {
            do {
                if (_wcsicmp(processEntry.szExeFile, processName.c_str()) == 0) {
                    foundPid = processEntry.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snapshot, &processEntry));
        }
        else {
            std::cout << "Process32FirstW失败" << std::endl;
        }

        CloseHandle(snapshot);
        return foundPid;
    }

    bool EnableDebugPrivilege() {
        HANDLE token;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
            std::cout << "OpenProcessToken失败" << std::endl;
            return false;
        }

        LUID luid;
        if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
            std::cout << "LookupPrivilegeValue失败" << std::endl;
            CloseHandle(token);
            return false;
        }

        TOKEN_PRIVILEGES privileges;
        privileges.PrivilegeCount = 1;
        privileges.Privileges[0].Luid = luid;
        privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if (!AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), NULL, NULL)) {
            std::cout << "AdjustTokenPrivileges失败" << std::endl;
            CloseHandle(token);
            return false;
        }

        CloseHandle(token);
        return true;
    }

    bool attach(const std::wstring& processName) {
        processId = FindProcessByName(processName);
        if (processId == 0) {
            std::wcout << L"未找到进程: " << processName << std::endl;
            return false;
        }

        std::wcout << L"找到进程: " << processName << L" (PID: " << processId << L")" << std::endl;

        if (!EnableDebugPrivilege()) {
            std::wcout << L"无法启用调试权限" << std::endl;
            return false;
        }

        processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
        if (!processHandle) {
            std::wcout << L"无法打开进程句柄" << std::endl;
            return false;
        }

        if (!DebugActiveProcess(processId)) {
            std::wcout << L"无法附加到进程" << std::endl;
            CloseHandle(processHandle);
            return false;
        }

        std::wcout << L"成功附加到进程" << std::endl;
        debugging = true;
        return true;
    }

    DWORD handleException(const DEBUG_EVENT& debugEvent) {
        DWORD exceptionCode = debugEvent.u.Exception.ExceptionRecord.ExceptionCode;
        DWORD threadId = debugEvent.dwThreadId;

        std::cout << "异常代码: 0x" << std::hex << exceptionCode << std::dec << std::endl;

        switch (exceptionCode) {
        case EXCEPTION_ACCESS_VIOLATION:
            std::cout << "处理访问违规异常..." << std::endl;
            return skipFaultingInstruction(threadId);

        case EXCEPTION_BREAKPOINT:
            std::cout << "处理断点异常..." << std::endl;
            return DBG_CONTINUE;

        case EXCEPTION_INT_DIVIDE_BY_ZERO:
            std::cout << "处理除零异常..." << std::endl;
            return skipFaultingInstruction(threadId);

        case EXCEPTION_SINGLE_STEP:
            std::cout << "处理单步执行异常..." << std::endl;
            return DBG_CONTINUE;

        default:
            std::cout << "处理未知异常，尝试继续执行..." << std::endl;
            return DBG_EXCEPTION_NOT_HANDLED;
        }
    }

    DWORD skipFaultingInstruction(DWORD threadId) {
        HANDLE threadHandle = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
            FALSE, threadId);
        if (!threadHandle) {
            std::cout << "无法打开线程句柄" << std::endl;
            return DBG_EXCEPTION_NOT_HANDLED;
        }

        CONTEXT context;
        context.ContextFlags = CONTEXT_CONTROL;

        if (GetThreadContext(threadHandle, &context)) {
#ifdef _WIN64
            std::cout << "跳过异常指令: RIP = 0x" << std::hex << context.Rip << std::endl;
            context.Rip += 1;
#else
            std::cout << "跳过异常指令: EIP = 0x" << std::hex << context.Eip << std::endl;
            context.Eip += 1;
#endif
            if (SetThreadContext(threadHandle, &context)) {
                std::cout << "成功跳过异常指令" << std::endl;
                CloseHandle(threadHandle);
                return DBG_CONTINUE;
            }
            else {
                std::cout << "设置线程上下文失败" << std::endl;
            }
        }
        else {
            std::cout << "获取线程上下文失败" << std::endl;
        }

        CloseHandle(threadHandle);
        return DBG_EXCEPTION_NOT_HANDLED;
    }

    void debugLoop() {
        DEBUG_EVENT debugEvent;
        DWORD continueStatus = DBG_CONTINUE;

        std::cout << "开始调试循环..." << std::endl;

        while (debugging) {
            if (WaitForDebugEvent(&debugEvent, INFINITE)) {
                std::cout << "调试事件类型: " << debugEvent.dwDebugEventCode << std::endl;

                switch (debugEvent.dwDebugEventCode) {
                case EXCEPTION_DEBUG_EVENT:
                    continueStatus = handleException(debugEvent);
                    break;

                case CREATE_PROCESS_DEBUG_EVENT:
                    std::cout << "进程创建事件" << std::endl;
                    continueStatus = DBG_CONTINUE;
                    break;

                case EXIT_PROCESS_DEBUG_EVENT:
                    std::cout << "进程退出事件" << std::endl;
                    debugging = false;
                    continueStatus = DBG_CONTINUE;
                    break;

                case LOAD_DLL_DEBUG_EVENT:
                    std::cout << "DLL加载事件" << std::endl;
                    continueStatus = DBG_CONTINUE;
                    break;

                case UNLOAD_DLL_DEBUG_EVENT:
                    std::cout << "DLL卸载事件" << std::endl;
                    continueStatus = DBG_CONTINUE;
                    break;

                case OUTPUT_DEBUG_STRING_EVENT:
                    std::cout << "调试字符串输出事件" << std::endl;
                    continueStatus = DBG_CONTINUE;
                    break;

                default:
                    std::cout << "未知调试事件" << std::endl;
                    continueStatus = DBG_CONTINUE;
                    break;
                }

                if (!ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, continueStatus)) {
                    std::cout << "ContinueDebugEvent失败" << std::endl;
                    debugging = false;
                }

                // 检查进程是否还在运行
                DWORD exitCode;
                if (GetExitCodeProcess(processHandle, &exitCode) && exitCode != STILL_ACTIVE) {
                    std::cout << "目标进程已退出" << std::endl;
                    debugging = false;
                }
            }
            else {
                DWORD error = GetLastError();
                if (error == ERROR_SEM_TIMEOUT) {
                    // 超时，继续等待
                    continue;
                }
                else {
                    std::cout << "WaitForDebugEvent失败，错误代码: " << error << std::endl;
                    debugging = false;
                }
            }
        }
    }

    void detach() {
        if (debugging && processId) {
            DebugActiveProcessStop(processId);
            std::cout << "已从进程分离" << std::endl;
        }

        if (processHandle) {
            CloseHandle(processHandle);
        }

        debugging = false;
    }

    void run() {
        if (attach(L"PlantsVsZombies.exe")) {
            debugLoop();
        }
        else {
            std::cout << "附加到进程失败" << std::endl;
        }
    }
};

int main() {
    std::cout << "Plants Vs Zombies 崩溃恢复调试器" << std::endl;
    std::cout << "==================================================" << std::endl;

    ProcessDebugger debugger;
    debugger.run();

    std::cout << "调试器已退出" << std::endl;
    return 0;
}