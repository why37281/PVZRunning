/*
a useful program to fight with pvz crash(only one file!)

Copyright (c) 2024 github/why37281
SPDX-License-Identifier: AGPL-3.0-only WITH Additional Permission prohibiting commercial use
*/

// code
// test2
#define UNICODE
#define _UNICODE

#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <psapi.h>
#include <chrono>
#include <thread>
#include <fstream>
#include <iomanip>
#include <sstream>

class ProcessDebugger {
private:
    DWORD processId;
    HANDLE processHandle;
    bool debugging;
    std::wstring processName;
    bool monitorMode;
    bool verboseOutput;
    std::ofstream logFile;
    long long logFileSize;
    const long long MAX_LOG_SIZE = 100 * 1024; // 100kB

public:
    ProcessDebugger(const std::wstring& name = L"PlantsVsZombies.exe")
        : processId(0), processHandle(NULL), debugging(false),
        processName(name), monitorMode(false), verboseOutput(false), logFileSize(0) {
    }

    ~ProcessDebugger() {
        detach();
        if (logFile.is_open()) {
            logFile.close();
        }
    }

    bool initializeLog() {
        logFile.open("debug_log.txt", std::ios::out | std::ios::app);
        if (!logFile.is_open()) {
            std::cout << "[WARNING] 无法创建日志文件" << std::endl;
            return false;
        }

        // 检查现有文件大小
        logFile.seekp(0, std::ios::end);
        logFileSize = logFile.tellp();

        // 如果文件太大，清空内容
        if (logFileSize >= MAX_LOG_SIZE) {
            logFile.close();
            logFile.open("debug_log.txt", std::ios::out | std::ios::trunc);
            logFileSize = 0;
            std::cout << "[INFO] 日志文件过大，已清空" << std::endl;
        }

        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);

        logFile << "=== 调试日志开始 ===" << std::endl;
        logFile << "时间: " << std::ctime(&time_t);
        logFile << "目标进程: " << std::string(processName.begin(), processName.end()) << std::endl;
        logFile << "最大日志大小: " << MAX_LOG_SIZE / 1024 << "kB" << std::endl;
        logFile << "==========================================" << std::endl;

        logFileSize = logFile.tellp();

        return true;
    }

    void writeLog(const std::string& message) {
        if (!logFile.is_open()) return;

        // 检查是否超过最大大小
        if (logFileSize >= MAX_LOG_SIZE) {
            return;
        }

        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);

        std::string logEntry = "[" +
            std::string(std::put_time(std::localtime(&time_t), "%H:%M:%S")) +
            "] " + message;

        // 检查写入后是否会超过限制
        if (logFileSize + logEntry.length() + 1 > MAX_LOG_SIZE) {
            logFile << "[INFO] 日志文件大小达到限制，停止记录" << std::endl;
            logFileSize = MAX_LOG_SIZE;
            return;
        }

        logFile << logEntry << std::endl;
        logFileSize += logEntry.length() + 1; // +1 for newline

        // 立即刷新以确保日志及时写入
        logFile.flush();
    }

    void writeExceptionDetails(const DEBUG_EVENT& debugEvent, const std::string& exceptionName) {
        if (!logFile.is_open() || logFileSize >= MAX_LOG_SIZE) return;

        const EXCEPTION_RECORD& exception = debugEvent.u.Exception.ExceptionRecord;

        std::stringstream details;
        details << "异常详情:" << std::endl;
        details << "  类型: " << exceptionName << " (0x" << std::hex << exception.ExceptionCode << ")" << std::dec << std::endl;
        details << "  地址: 0x" << std::hex << exception.ExceptionAddress << std::dec << std::endl;
        details << "  标志: " << exception.ExceptionFlags << std::endl;
        details << "  参数数量: " << exception.NumberParameters << std::endl;

        for (DWORD i = 0; i < exception.NumberParameters && i < EXCEPTION_MAXIMUM_PARAMETERS; i++) {
            details << "  参数[" << i << "]: 0x" << std::hex << exception.ExceptionInformation[i] << std::dec << std::endl;
        }

        // 检查写入后是否会超过限制
        std::string detailsStr = details.str();
        if (logFileSize + detailsStr.length() > MAX_LOG_SIZE) {
            return;
        }

        logFile << detailsStr;

        // 尝试读取异常地址附近的机器码
        readAndLogMachineCode(debugEvent);

        logFile << "------------------------------------------" << std::endl;
        logFileSize = logFile.tellp();
    }

    void readAndLogMachineCode(const DEBUG_EVENT& debugEvent) {
        if (logFileSize >= MAX_LOG_SIZE) return;

        const EXCEPTION_RECORD& exception = debugEvent.u.Exception.ExceptionRecord;
        BYTE buffer[64]; // 读取64字节
        SIZE_T bytesRead = 0;

        // 计算读取的起始地址（向前32字节）
        PVOID readAddress = (PVOID)((ULONG_PTR)exception.ExceptionAddress - 32);

        if (ReadProcessMemory(processHandle, readAddress, buffer, sizeof(buffer), &bytesRead)) {
            std::stringstream machineCode;
            machineCode << "异常地址附近的机器码 (地址: 0x" << std::hex << readAddress << "):" << std::endl;

            // 以十六进制格式输出机器码
            for (SIZE_T i = 0; i < bytesRead; i += 16) {
                machineCode << "  " << std::hex << std::setw(8) << std::setfill('0')
                    << (ULONG_PTR)readAddress + i << ": ";

                for (SIZE_T j = 0; j < 16 && i + j < bytesRead; j++) {
                    machineCode << std::hex << std::setw(2) << std::setfill('0')
                        << (int)buffer[i + j] << " ";
                }
                machineCode << std::endl;
            }

            std::string machineCodeStr = machineCode.str();
            if (logFileSize + machineCodeStr.length() <= MAX_LOG_SIZE) {
                logFile << machineCodeStr;
            }
        }
        else {
            if (logFileSize + 50 <= MAX_LOG_SIZE) {
                logFile << "无法读取异常地址附近的机器码" << std::endl;
            }
        }
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
            writeLog("ERROR: OpenProcessToken失败");
            return false;
        }

        LUID luid;
        if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
            std::cout << "[ERROR] LookupPrivilegeValue失败" << std::endl;
            writeLog("ERROR: LookupPrivilegeValue失败");
            CloseHandle(token);
            return false;
        }

        TOKEN_PRIVILEGES privileges;
        privileges.PrivilegeCount = 1;
        privileges.Privileges[0].Luid = luid;
        privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if (!AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), NULL, NULL)) {
            std::cout << "[ERROR] AdjustTokenPrivileges失败" << std::endl;
            writeLog("ERROR: AdjustTokenPrivileges失败");
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
        writeLog("找到进程: " + std::string(processName.begin(), processName.end()) + " (PID: " + std::to_string(processId) + ")");

        if (!EnableDebugPrivilege()) {
            std::wcout << L"[WARNING] 无法启用调试权限，可能影响调试功能" << std::endl;
            writeLog("WARNING: 无法启用调试权限");
            // 继续尝试，不一定需要调试权限
        }

        processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
        if (!processHandle) {
            std::wcout << L"[ERROR] 无法打开进程句柄" << std::endl;
            writeLog("ERROR: 无法打开进程句柄");
            return false;
        }

        if (!DebugActiveProcess(processId)) {
            std::wcout << L"[ERROR] 无法附加到进程" << std::endl;
            writeLog("ERROR: 无法附加到进程");
            CloseHandle(processHandle);
            processHandle = NULL;
            return false;
        }

        std::wcout << L"[SUCCESS] 成功附加到进程" << std::endl;
        writeLog("SUCCESS: 成功附加到进程");
        debugging = true;
        return true;
    }

    void waitForProcess() {
        std::wcout << L"[MONITOR] 正在等待进程 " << processName << L" 启动..." << std::endl;
        writeLog("MONITOR: 等待进程启动");

        while (true) {
            processId = FindProcessByName(processName);
            if (processId != 0) {
                std::wcout << L"[MONITOR] 检测到进程已启动，PID: " << processId << std::endl;
                writeLog("MONITOR: 检测到进程已启动，PID: " + std::to_string(processId));
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
            writeLog("INFO: 接收到初始断点（正常启动过程）");
            firstBreakpoint = false;
            return DBG_CONTINUE;
        }

        std::string exceptionName = getExceptionName(exceptionCode);
        std::cout << "[EXCEPTION] " << exceptionName << " (0x" << std::hex << exceptionCode << ")" << std::dec << std::endl;
        writeLog("EXCEPTION: " + exceptionName + " (0x" + toHexString(exceptionCode) + ")");

        // 记录异常详情到日志
        writeExceptionDetails(debugEvent, exceptionName);

        // 根据异常类型决定处理方式
        switch (exceptionCode) {
            // 内存访问异常
        case EXCEPTION_ACCESS_VIOLATION:
        case EXCEPTION_IN_PAGE_ERROR:
        case EXCEPTION_GUARD_PAGE:
        case EXCEPTION_DATATYPE_MISALIGNMENT:
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
        case EXCEPTION_STACK_OVERFLOW:
        case EXCEPTION_INVALID_DISPOSITION:
            return handleMemoryException(debugEvent, threadId);

            // 算术异常
        case EXCEPTION_INT_DIVIDE_BY_ZERO:
        case EXCEPTION_FLT_DIVIDE_BY_ZERO:
        case EXCEPTION_INT_OVERFLOW:
        case EXCEPTION_FLT_OVERFLOW:
        case EXCEPTION_FLT_UNDERFLOW:
        case EXCEPTION_FLT_INEXACT_RESULT:
        case EXCEPTION_FLT_INVALID_OPERATION:
        case EXCEPTION_FLT_DENORMAL_OPERAND:
        case EXCEPTION_FLT_STACK_CHECK:
            return handleArithmeticException(debugEvent, threadId);

            // 指令异常
        case EXCEPTION_ILLEGAL_INSTRUCTION:
        case EXCEPTION_PRIVILEGED_INSTRUCTION:  // 0xC0000096
        case EXCEPTION_NONCONTINUABLE_EXCEPTION:
            return handleInstructionException(debugEvent, threadId);

            // 调试异常
        case EXCEPTION_BREAKPOINT:
        case EXCEPTION_SINGLE_STEP:
            return DBG_CONTINUE;

            // .NET异常
        case 0xE0434F4D: // CLR异常
        case 0xE0434352: // CLR异常
            std::cout << "[INFO] 处理CLR异常，尝试继续执行" << std::endl;
            writeLog("INFO: 处理CLR异常，尝试继续执行");
            return DBG_CONTINUE;

            // C++异常
        case 0xE06D7363: // Microsoft C++异常
            std::cout << "[INFO] 处理C++异常，尝试继续执行" << std::endl;
            writeLog("INFO: 处理C++异常，尝试继续执行");
            return DBG_CONTINUE;

        default:
            // 检查是否是NTSTATUS代码
            if ((exceptionCode & 0xFFFF0000) == 0xC0000000) {
                std::cout << "[INFO] 处理NTSTATUS异常: 0x" << std::hex << exceptionCode << std::dec << std::endl;
                writeLog("INFO: 处理NTSTATUS异常: 0x" + toHexString(exceptionCode));
                return handleGenericException(debugEvent, threadId);
            }

            std::cout << "[WARNING] 未知异常类型" << std::endl;
            writeLog("WARNING: 未知异常类型");
            return DBG_EXCEPTION_NOT_HANDLED;
        }
    }

    std::string getExceptionName(DWORD exceptionCode) {
        switch (exceptionCode) {
        case EXCEPTION_ACCESS_VIOLATION: return "访问违规";
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED: return "数组越界";
        case EXCEPTION_BREAKPOINT: return "断点";
        case EXCEPTION_DATATYPE_MISALIGNMENT: return "数据未对齐";
        case EXCEPTION_FLT_DENORMAL_OPERAND: return "浮点数非规范操作数";
        case EXCEPTION_FLT_DIVIDE_BY_ZERO: return "浮点数除零";
        case EXCEPTION_FLT_INEXACT_RESULT: return "浮点数不精确结果";
        case EXCEPTION_FLT_INVALID_OPERATION: return "浮点数无效操作";
        case EXCEPTION_FLT_OVERFLOW: return "浮点数上溢";
        case EXCEPTION_FLT_STACK_CHECK: return "浮点数栈检查";
        case EXCEPTION_FLT_UNDERFLOW: return "浮点数下溢";
        case EXCEPTION_ILLEGAL_INSTRUCTION: return "非法指令";
        case EXCEPTION_IN_PAGE_ERROR: return "页面错误";
        case EXCEPTION_INT_DIVIDE_BY_ZERO: return "整数除零";
        case EXCEPTION_INT_OVERFLOW: return "整数溢出";
        case EXCEPTION_INVALID_DISPOSITION: return "无效处置";
        case EXCEPTION_NONCONTINUABLE_EXCEPTION: return "不可继续异常";
        case EXCEPTION_PRIVILEGED_INSTRUCTION: return "特权指令";  // 0xC0000096
        case EXCEPTION_STACK_OVERFLOW: return "栈溢出";
        case EXCEPTION_GUARD_PAGE: return "保护页";
        case EXCEPTION_SINGLE_STEP: return "单步执行";
        case 0xE0434F4D: return "CLR异常";
        case 0xE0434352: return "CLR异常";
        case 0xE06D7363: return "C++异常";
        default:
            if ((exceptionCode & 0xFFFF0000) == 0xC0000000) {
                return "NTSTATUS异常";
            }
            return "未知异常";
        }
    }

    std::string toHexString(DWORD value) {
        std::stringstream ss;
        ss << std::hex << value;
        return ss.str();
    }

    DWORD handleMemoryException(const DEBUG_EVENT& debugEvent, DWORD threadId) {
        DWORD exceptionCode = debugEvent.u.Exception.ExceptionRecord.ExceptionCode;

        switch (exceptionCode) {
        case EXCEPTION_STACK_OVERFLOW:
            std::cout << "[WARNING] 栈溢出异常，难以恢复" << std::endl;
            writeLog("WARNING: 栈溢出异常，难以恢复");
            return DBG_EXCEPTION_NOT_HANDLED;

        case EXCEPTION_ACCESS_VIOLATION:
            if (debugEvent.u.Exception.ExceptionRecord.NumberParameters >= 2) {
                std::cout << "[INFO] 访问违规地址: 0x" << std::hex
                    << debugEvent.u.Exception.ExceptionRecord.ExceptionInformation[1]
                    << std::dec << std::endl;
                writeLog("INFO: 访问违规地址: 0x" +
                    toHexString((DWORD)debugEvent.u.Exception.ExceptionRecord.ExceptionInformation[1]));
            }
            return skipFaultingInstruction(threadId);

        default:
            return skipFaultingInstruction(threadId);
        }
    }

    DWORD handleArithmeticException(const DEBUG_EVENT& debugEvent, DWORD threadId) {
        return skipFaultingInstruction(threadId);
    }

    DWORD handleInstructionException(const DEBUG_EVENT& debugEvent, DWORD threadId) {
        DWORD exceptionCode = debugEvent.u.Exception.ExceptionRecord.ExceptionCode;

        if (exceptionCode == EXCEPTION_PRIVILEGED_INSTRUCTION) {  // 0xC0000096
            std::cout << "[INFO] 处理特权指令异常 (0xC0000096)" << std::endl;
            writeLog("INFO: 处理特权指令异常 (0xC0000096)");
        }

        return skipFaultingInstruction(threadId);
    }

    DWORD handleGenericException(const DEBUG_EVENT& debugEvent, DWORD threadId) {
        return skipFaultingInstruction(threadId);
    }

    DWORD skipFaultingInstruction(DWORD threadId) {
        HANDLE threadHandle = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
            FALSE, threadId);
        if (!threadHandle) {
            std::cout << "[ERROR] 无法打开线程句柄" << std::endl;
            writeLog("ERROR: 无法打开线程句柄");
            return DBG_EXCEPTION_NOT_HANDLED;
        }

        CONTEXT context;
        context.ContextFlags = CONTEXT_CONTROL;

        if (GetThreadContext(threadHandle, &context)) {
#ifdef _WIN64
            std::cout << "[DEBUG] 跳过异常指令: RIP = 0x" << std::hex << context.Rip << std::dec << std::endl;
            writeLog("DEBUG: 跳过异常指令: RIP = 0x" + toHexString((DWORD)context.Rip));
            context.Rip += 1;
#else
            std::cout << "[DEBUG] 跳过异常指令: EIP = 0x" << std::hex << context.Eip << std::dec << std::endl;
            writeLog("DEBUG: 跳过异常指令: EIP = 0x" + toHexString(context.Eip));
            context.Eip += 1;
#endif
            if (SetThreadContext(threadHandle, &context)) {
                std::cout << "[SUCCESS] 成功跳过异常指令" << std::endl;
                writeLog("SUCCESS: 成功跳过异常指令");
                CloseHandle(threadHandle);
                return DBG_CONTINUE;
            }
            else {
                std::cout << "[ERROR] 设置线程上下文失败" << std::endl;
                writeLog("ERROR: 设置线程上下文失败");
            }
        }
        else {
            std::cout << "[ERROR] 获取线程上下文失败" << std::endl;
            writeLog("ERROR: 获取线程上下文失败");
        }

        CloseHandle(threadHandle);
        return DBG_EXCEPTION_NOT_HANDLED;
    }

    void debugLoop() {
        DEBUG_EVENT debugEvent;
        DWORD continueStatus = DBG_CONTINUE;
        bool firstEvent = true;

        std::cout << "[DEBUG] 开始调试循环..." << std::endl;
        writeLog("DEBUG: 开始调试循环");

        while (debugging) {
            if (WaitForDebugEvent(&debugEvent, 100)) {
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
                        if (verboseOutput) {
                            std::cout << "[EVENT] 进程创建" << std::endl;
                            writeLog("EVENT: 进程创建");
                        }
                        continueStatus = DBG_CONTINUE;
                        break;

                    case EXIT_PROCESS_DEBUG_EVENT:
                        std::cout << "[EVENT] 进程退出，退出代码: "
                            << debugEvent.u.ExitProcess.dwExitCode << std::endl;
                        writeLog("EVENT: 进程退出，退出代码: " + std::to_string(debugEvent.u.ExitProcess.dwExitCode));
                        debugging = false;
                        continueStatus = DBG_CONTINUE;
                        break;

                    case LOAD_DLL_DEBUG_EVENT:
                        if (verboseOutput) {
                            std::cout << "[EVENT] DLL加载" << std::endl;
                            writeLog("EVENT: DLL加载");
                        }
                        continueStatus = DBG_CONTINUE;
                        break;

                    case UNLOAD_DLL_DEBUG_EVENT:
                        if (verboseOutput) {
                            std::cout << "[EVENT] DLL卸载" << std::endl;
                            writeLog("EVENT: DLL卸载");
                        }
                        continueStatus = DBG_CONTINUE;
                        break;

                    case OUTPUT_DEBUG_STRING_EVENT:
                        if (verboseOutput) {
                            std::cout << "[EVENT] 调试字符串输出" << std::endl;
                            writeLog("EVENT: 调试字符串输出");
                        }
                        continueStatus = DBG_CONTINUE;
                        break;

                    case CREATE_THREAD_DEBUG_EVENT:
                        if (verboseOutput) {
                            std::cout << "[EVENT] 线程创建" << std::endl;
                            writeLog("EVENT: 线程创建");
                        }
                        continueStatus = DBG_CONTINUE;
                        break;

                    case EXIT_THREAD_DEBUG_EVENT:
                        if (verboseOutput) {
                            std::cout << "[EVENT] 线程退出" << std::endl;
                            writeLog("EVENT: 线程退出");
                        }
                        continueStatus = DBG_CONTINUE;
                        break;

                    default:
                        if (verboseOutput) {
                            std::cout << "[EVENT] 未知调试事件: " << debugEvent.dwDebugEventCode << std::endl;
                            writeLog("EVENT: 未知调试事件: " + std::to_string(debugEvent.dwDebugEventCode));
                        }
                        continueStatus = DBG_CONTINUE;
                        break;
                    }
                }

                if (!ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, continueStatus)) {
                    std::cout << "[ERROR] ContinueDebugEvent失败" << std::endl;
                    writeLog("ERROR: ContinueDebugEvent失败");
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
                            writeLog("INFO: 检测到目标进程已退出");
                            debugging = false;
                        }
                    }
                }
                else {
                    std::cout << "[ERROR] WaitForDebugEvent失败，错误代码: " << error << std::endl;
                    writeLog("ERROR: WaitForDebugEvent失败，错误代码: " + std::to_string(error));
                    debugging = false;
                }
            }
        }
    }

    void detach() {
        if (debugging && processId) {
            DebugActiveProcessStop(processId);
            std::cout << "[INFO] 已从进程分离" << std::endl;
            writeLog("INFO: 已从进程分离");
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
        std::cout << "[START] Plants Vs Zombies 崩溃恢复调试器(v0.3-alpha)启动" << std::endl;

        // 初始化日志
        if (initializeLog()) {
            std::cout << "[INFO] 日志文件已创建: debug_log.txt (最大100kB)" << std::endl;
        }

        writeLog("START: Plants Vs Zombies 崩溃恢复调试器启动");

        // 启用监控模式
        setMonitorMode(true);

        while (true) {
            // 等待进程启动
            if (processId == 0) {
                waitForProcess();
            }

            // 尝试附加到进程
            if (attachToProcess()) {
                std::cout << "[DEBUG] 进入调试循环..." << std::endl;
                writeLog("DEBUG: 进入调试循环");
                debugLoop();
                std::cout << "[INFO] 调试循环结束" << std::endl;
                writeLog("INFO: 调试循环结束");
            }

            // 清理资源
            detach();

            // 如果进程退出，等待重新启动
            if (monitorMode) {
                std::cout << "[MONITOR] 进程已退出，等待重新启动..." << std::endl;
                writeLog("MONITOR: 进程已退出，等待重新启动");
                std::this_thread::sleep_for(std::chrono::seconds(2));
            }
            else {
                break;
            }
        }

        std::cout << "[END] 调试器退出" << std::endl;
        writeLog("END: 调试器退出");
        writeLog("=== 调试日志结束 ===");
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
    )" << std::endl;
    */
    return;
}

int main() {
    printBanner();

    std::cout << "[MONITOR] 是否启用详细输出 ( y / n ) :";
    if (std::cin.get() == 'y') {
        std::cout << std::endl;
        std::cout << "[INFO] 详细输出已启用" << std::endl;
    }
    else {
        std::cout << std::endl;
        std::cout << "[INFO] 详细输出已禁用" << std::endl;
    }

    // 清除输入缓冲区中的换行符
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    ProcessDebugger debugger(L"PlantsVsZombies.exe");

    // 设置详细输出模式
    debugger.setVerboseOutput(std::cin.peek() == 'y');

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