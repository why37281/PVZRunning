/*
a useful program to fight with pvz crash(only one file!)

Copyright (c) 2024 github/why37281
SPDX-License-Identifier: AGPL-3.0-only WITH Additional Permission prohibiting commercial use
*/

// code
#define UNICODE
#define _UNICODE

#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <psapi.h>
#include <chrono>
#include <thread>

class ProcessDebugger {
private:
    DWORD processId;
    HANDLE processHandle;
    bool debugging;
    std::wstring processName;
    bool monitorMode;
    bool verboseOutput;

public:
    ProcessDebugger(const std::wstring& name = L"PlantsVsZombies.exe")
        : processId(0), processHandle(NULL), debugging(false),
        processName(name), monitorMode(false), verboseOutput(false) {
    }

    ~ProcessDebugger() {
        detach();
    }

    DWORD FindProcessByName(const std::wstring& targetName) {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) {
            if (verboseOutput) std::cout << "[INFO] 创建进程快照失败" << std::endl;
            return 0;
        }

        PROCESSENTRY32W processEntry;
        processEntry.dwSize = sizeof(PROCESSENTRY32W);

        DWORD foundPid = 0;
        if (Process32FirstW(snapshot, &processEntry)) {
            do {
                if (_wcsicmp(processEntry.szExeFile, targetName.c_str()) == 0) {
                    foundPid = processEntry.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snapshot, &processEntry));
        }

        CloseHandle(snapshot);
        return foundPid;
    }

    bool EnableDebugPrivilege() {
        HANDLE token;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
            std::cout << "[ERROR] OpenProcessToken失败" << std::endl;
            return false;
        }

        LUID luid;
        if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
            std::cout << "[ERROR] LookupPrivilegeValue失败" << std::endl;
            CloseHandle(token);
            return false;
        }

        TOKEN_PRIVILEGES privileges;
        privileges.PrivilegeCount = 1;
        privileges.Privileges[0].Luid = luid;
        privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if (!AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), NULL, NULL)) {
            std::cout << "[ERROR] AdjustTokenPrivileges失败" << std::endl;
            CloseHandle(token);
            return false;
        }

        CloseHandle(token);
        return true;
    }

    bool attachToProcess() {
        processId = FindProcessByName(processName);
        if (processId == 0) {
            if (monitorMode) {
                std::wcout << L"[MONITOR] 等待进程启动: " << processName << std::endl;
            }
            else {
                std::wcout << L"[ERROR] 未找到进程: " << processName << std::endl;
            }
            return false;
        }

        std::wcout << L"[INFO] 找到进程: " << processName << L" (PID: " << processId << L")" << std::endl;

        if (!EnableDebugPrivilege()) {
            std::wcout << L"[WARNING] 无法启用调试权限，可能影响调试功能" << std::endl;
            // 继续尝试，不一定需要调试权限
        }

        processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
        if (!processHandle) {
            std::wcout << L"[ERROR] 无法打开进程句柄" << std::endl;
            return false;
        }

        if (!DebugActiveProcess(processId)) {
            std::wcout << L"[ERROR] 无法附加到进程" << std::endl;
            CloseHandle(processHandle);
            processHandle = NULL;
            return false;
        }

        std::wcout << L"[SUCCESS] 成功附加到进程" << std::endl;
        debugging = true;
        return true;
    }

    void waitForProcess() {
        std::wcout << L"[MONITOR] 正在等待进程 " << processName << L" 启动..." << std::endl;

        while (true) {
            processId = FindProcessByName(processName);
            if (processId != 0) {
                std::wcout << L"[MONITOR] 检测到进程已启动，PID: " << processId << std::endl;
                break;
            }

            // 显示等待动画
            static int counter = 0;
            const char* spinner = "|/-\\";
            std::cout << "\r[MONITOR] 等待中... " << spinner[counter % 4] << " " << std::flush;
            counter++;

            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
        std::cout << std::endl;
    }

    DWORD handleException(const DEBUG_EVENT& debugEvent) {
        DWORD exceptionCode = debugEvent.u.Exception.ExceptionRecord.ExceptionCode;
        DWORD threadId = debugEvent.dwThreadId;

        // 检查是否是第一次断点异常（正常情况）
        static bool firstBreakpoint = true;
        if (exceptionCode == EXCEPTION_BREAKPOINT && firstBreakpoint) {
            std::cout << "[INFO] 接收到初始断点（正常启动过程）" << std::endl;
            firstBreakpoint = false;
            return DBG_CONTINUE;
        }

        std::cout << "[EXCEPTION] 代码: 0x" << std::hex << exceptionCode << std::dec;

        switch (exceptionCode) {
        case EXCEPTION_ACCESS_VIOLATION:
            std::cout << " (访问违规)";
            if (debugEvent.u.Exception.ExceptionRecord.NumberParameters >= 2) {
                std::cout << " 地址: 0x" << std::hex
                    << debugEvent.u.Exception.ExceptionRecord.ExceptionInformation[1]
                    << std::dec;
            }
            std::cout << std::endl;
            return skipFaultingInstruction(threadId);

        case EXCEPTION_INT_DIVIDE_BY_ZERO:
            std::cout << " (整数除零)" << std::endl;
            return skipFaultingInstruction(threadId);

        case EXCEPTION_FLT_DIVIDE_BY_ZERO:
            std::cout << " (浮点数除零)" << std::endl;
            return skipFaultingInstruction(threadId);

        case EXCEPTION_BREAKPOINT:
            std::cout << " (断点)" << std::endl;
            return DBG_CONTINUE;

        case EXCEPTION_SINGLE_STEP:
            if (verboseOutput) std::cout << " (单步执行)" << std::endl;
            return DBG_CONTINUE;

        case EXCEPTION_GUARD_PAGE:
            std::cout << " (保护页)" << std::endl;
            return DBG_CONTINUE;

        case EXCEPTION_ILLEGAL_INSTRUCTION:
            std::cout << " (非法指令)" << std::endl;
            return skipFaultingInstruction(threadId);

        case EXCEPTION_STACK_OVERFLOW:
            std::cout << " (栈溢出)" << std::endl;
            return DBG_EXCEPTION_NOT_HANDLED; // 栈溢出很难恢复

        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
            std::cout << " (数组越界)" << std::endl;
            return skipFaultingInstruction(threadId);

        default:
            std::cout << " (未知异常)" << std::endl;
            if (verboseOutput) {
                std::cout << "[DEBUG] 异常信息: "
                    << "标志: " << debugEvent.u.Exception.ExceptionRecord.ExceptionFlags
                    << ", 地址: 0x" << std::hex
                    << debugEvent.u.Exception.ExceptionRecord.ExceptionAddress
                    << std::dec << std::endl;
            }
            return DBG_EXCEPTION_NOT_HANDLED;
        }
    }

    DWORD skipFaultingInstruction(DWORD threadId) {
        HANDLE threadHandle = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
            FALSE, threadId);
        if (!threadHandle) {
            std::cout << "[ERROR] 无法打开线程句柄" << std::endl;
            return DBG_EXCEPTION_NOT_HANDLED;
        }

        CONTEXT context;
        context.ContextFlags = CONTEXT_CONTROL;

        if (GetThreadContext(threadHandle, &context)) {
#ifdef _WIN64
            std::cout << "[DEBUG] 跳过异常指令: RIP = 0x" << std::hex << context.Rip << std::dec << std::endl;
            context.Rip += 1;
#else
            std::cout << "[DEBUG] 跳过异常指令: EIP = 0x" << std::hex << context.Eip << std::dec << std::endl;
            context.Eip += 1;
#endif
            if (SetThreadContext(threadHandle, &context)) {
                std::cout << "[SUCCESS] 成功跳过异常指令" << std::endl;
                CloseHandle(threadHandle);
                return DBG_CONTINUE;
            }
            else {
                std::cout << "[ERROR] 设置线程上下文失败" << std::endl;
            }
        }
        else {
            std::cout << "[ERROR] 获取线程上下文失败" << std::endl;
        }

        CloseHandle(threadHandle);
        return DBG_EXCEPTION_NOT_HANDLED;
    }

    void debugLoop() {
        DEBUG_EVENT debugEvent;
        DWORD continueStatus = DBG_CONTINUE;
        bool firstEvent = true;

        std::cout << "[DEBUG] 开始调试循环..." << std::endl;

        while (debugging) {
            if (WaitForDebugEvent(&debugEvent, 100)) { // 使用较短超时以便检查进程状态
                // 忽略第一次的断点异常（这是正常的）
                if (firstEvent && debugEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
                    debugEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) {
                    firstEvent = false;
                    continueStatus = DBG_CONTINUE;
                }
                else {
                    switch (debugEvent.dwDebugEventCode) {
                    case EXCEPTION_DEBUG_EVENT:
                        continueStatus = handleException(debugEvent);
                        break;

                    case CREATE_PROCESS_DEBUG_EVENT:
                        if (verboseOutput) std::cout << "[EVENT] 进程创建" << std::endl;
                        continueStatus = DBG_CONTINUE;
                        break;

                    case EXIT_PROCESS_DEBUG_EVENT:
                        std::cout << "[EVENT] 进程退出，退出代码: "
                            << debugEvent.u.ExitProcess.dwExitCode << std::endl;
                        debugging = false;
                        continueStatus = DBG_CONTINUE;
                        break;

                    case LOAD_DLL_DEBUG_EVENT:
                        if (verboseOutput) std::cout << "[EVENT] DLL加载" << std::endl;
                        continueStatus = DBG_CONTINUE;
                        break;

                    case UNLOAD_DLL_DEBUG_EVENT:
                        if (verboseOutput) std::cout << "[EVENT] DLL卸载" << std::endl;
                        continueStatus = DBG_CONTINUE;
                        break;

                    case OUTPUT_DEBUG_STRING_EVENT:
                        if (verboseOutput) {
                            std::cout << "[EVENT] 调试字符串输出: ";
                            // 这里可以输出调试字符串内容
                        }
                        continueStatus = DBG_CONTINUE;
                        break;

                    case CREATE_THREAD_DEBUG_EVENT:
                        if (verboseOutput) std::cout << "[EVENT] 线程创建" << std::endl;
                        continueStatus = DBG_CONTINUE;
                        break;

                    case EXIT_THREAD_DEBUG_EVENT:
                        if (verboseOutput) std::cout << "[EVENT] 线程退出" << std::endl;
                        continueStatus = DBG_CONTINUE;
                        break;

                    default:
                        if (verboseOutput) std::cout << "[EVENT] 未知调试事件: " << debugEvent.dwDebugEventCode << std::endl;
                        continueStatus = DBG_CONTINUE;
                        break;
                    }
                }

                if (!ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, continueStatus)) {
                    std::cout << "[ERROR] ContinueDebugEvent失败" << std::endl;
                    debugging = false;
                }
            }
            else {
                DWORD error = GetLastError();
                if (error == ERROR_SEM_TIMEOUT) {
                    // 超时，检查进程是否还在运行
                    DWORD exitCode;
                    if (processHandle && GetExitCodeProcess(processHandle, &exitCode)) {
                        if (exitCode != STILL_ACTIVE) {
                            std::cout << "[INFO] 检测到目标进程已退出" << std::endl;
                            debugging = false;
                        }
                    }
                }
                else {
                    std::cout << "[ERROR] WaitForDebugEvent失败，错误代码: " << error << std::endl;
                    debugging = false;
                }
            }
        }
    }

    void detach() {
        if (debugging && processId) {
            DebugActiveProcessStop(processId);
            std::cout << "[INFO] 已从进程分离" << std::endl;
        }

        if (processHandle) {
            CloseHandle(processHandle);
            processHandle = NULL;
        }

        processId = 0;
        debugging = false;
    }

    void setMonitorMode(bool enable) {
        monitorMode = enable;
    }

    void setVerboseOutput(bool enable) {
        verboseOutput = enable;
    }

    void run() {
        std::cout << "[START] Plants Vs Zombies 崩溃恢复调试器启动" << std::endl;
        std::cout << "==================================================" << std::endl;

        // 启用监控模式
        setMonitorMode(true);
        // 禁用详细输出以减少干扰
        std::cout << "[MONITOR] 是否启用详细输出 ( y / n ) :";
        if (std::cin.get() == 'y') {
            std::cout << std::endl;
            setVerboseOutput(true);
        }
        else {
            std::cout << std::endl;
            setVerboseOutput(false);
        }

        while (true) {
            // 等待进程启动
            if (processId == 0) {
                waitForProcess();
            }

            // 尝试附加到进程
            if (attachToProcess()) {
                std::cout << "[DEBUG] 进入调试循环..." << std::endl;
                debugLoop();
                std::cout << "[INFO] 调试循环结束" << std::endl;
            }

            // 清理资源
            detach();

            // 如果进程退出，等待重新启动
            if (monitorMode) {
                std::cout << "[MONITOR] 进程已退出，等待重新启动..." << std::endl;
                std::this_thread::sleep_for(std::chrono::seconds(2));
            }
            else {
                break;
            }
        }

        std::cout << "[END] 调试器退出" << std::endl;
    }
};

void printBanner() {
    /*
    std::cout << R"(
 ______ _   _  ______ ______                    _             
| ___ \| | | ||___  / | ___ \                  (_)            
| |_/ /| | | |   / /  | |_/ / _   _ __ _  __ _  _ __     __ _ 
|  __/ | | | |  / /   |    / | | | | '_ \| '_ \| | '_ \ / _` |
| |    \ \_/ /./ /___ | |\ \ | |_| | | | | | | | | | | | (_| |
\_|     \___/ \_____/ \_| \_\ \__,_|_| |_|_| |_|_|_| |_|\__, |
                                                         _/ |
                                                        |___/ 
    )" << std::endl;*/
    return;
}

int main() {
    printBanner();

    ProcessDebugger debugger(L"PlantsVsZombies.exe");

    try {
        debugger.run();
    }
    catch (const std::exception& e) {
        std::cout << "[FATAL] 发生异常: " << e.what() << std::endl;
    }
    catch (...) {
        std::cout << "[FATAL] 发生未知异常" << std::endl;
    }

    std::cout << "按任意键退出..." << std::endl;
    std::cin.get();

    return 0;
}