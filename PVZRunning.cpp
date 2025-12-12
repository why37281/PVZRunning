// CrashDebugger.cpp
#define UNICODE
#define _UNICODE
#define _CRT_SECURE_NO_WARNINGS
#define NOMINMAX  // 避免Windows的min/max宏定义冲突

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
#include <limits>
#include <ctime>

// 定义缺失的异常代码
#ifndef EXCEPTION_PRIVILEGED_INSTRUCTION
#define EXCEPTION_PRIVILEGED_INSTRUCTION 0xC0000096
#endif

// 线程命名异常 (MSVC调试器用于设置线程名)
#ifndef EXCEPTION_MS_VC_THREAD_NAME
#define EXCEPTION_MS_VC_THREAD_NAME 0x406D1388
#endif

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
    ProcessDebugger(const std::wstring& name)
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
        logFile.open("log.txt", std::ios::out | std::ios::app);
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
            logFile.open("log.txt", std::ios::out | std::ios::trunc);
            logFileSize = 0;
            std::cout << "[INFO] 日志文件过大，已清空" << std::endl;
        }

        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);

        logFile << "=== 调试日志开始 ===" << std::endl;
        logFile << "时间: " << std::ctime(&time_t);

        // 将宽字符串转换为窄字符串用于日志
        int size_needed = WideCharToMultiByte(CP_UTF8, 0, processName.c_str(), (int)processName.size(), NULL, 0, NULL, NULL);
        std::string processNameA(size_needed, 0);
        WideCharToMultiByte(CP_UTF8, 0, processName.c_str(), (int)processName.size(), &processNameA[0], size_needed, NULL, NULL);

        logFile << "目标进程: " << processNameA << std::endl;
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

        struct tm timeInfo;
        localtime_s(&timeInfo, &time_t);

        char timeBuffer[20];
        std::strftime(timeBuffer, sizeof(timeBuffer), "%H:%M:%S", &timeInfo);

        std::string logEntry = "[" + std::string(timeBuffer) + "] " + message;

        // 检查写入后是否会超过限制
        if (logFileSize + logEntry.length() + 1 > MAX_LOG_SIZE) {
            logFile << "[INFO] 日志文件大小达到限制，停止记录" << std::endl;
            logFileSize = MAX_LOG_SIZE;
            return;
        }

        logFile << logEntry << std::endl;
        logFileSize += logEntry.length() + 1;

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
        BYTE buffer[64];
        SIZE_T bytesRead = 0;

        // 计算读取的起始地址（向前32字节）
        PVOID readAddress = (PVOID)((ULONG_PTR)exception.ExceptionAddress - 32);

        if (ReadProcessMemory(processHandle, readAddress, buffer, sizeof(buffer), &bytesRead)) {
            std::stringstream machineCode;
            machineCode << "异常地址附近的机器码 (地址: 0x" << std::hex << readAddress << "):" << std::endl;

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
            if (verboseOutput) {
                std::cout << "[INFO] 创建进程快照失败" << std::endl;
            }
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

        // 转换宽字符串为窄字符串用于日志
        int size_needed = WideCharToMultiByte(CP_UTF8, 0, processName.c_str(), (int)processName.size(), NULL, 0, NULL, NULL);
        std::string processNameA(size_needed, 0);
        WideCharToMultiByte(CP_UTF8, 0, processName.c_str(), (int)processName.size(), &processNameA[0], size_needed, NULL, NULL);
        writeLog("找到进程: " + processNameA + " (PID: " + std::to_string(processId) + ")");

        if (!EnableDebugPrivilege()) {
            std::wcout << L"[WARNING] 无法启用调试权限，可能影响调试功能" << std::endl;
            writeLog("WARNING: 无法启用调试权限");
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

        // 转换宽字符串为窄字符串用于日志
        int size_needed = WideCharToMultiByte(CP_UTF8, 0, processName.c_str(), (int)processName.size(), NULL, 0, NULL, NULL);
        std::string processNameA(size_needed, 0);
        WideCharToMultiByte(CP_UTF8, 0, processName.c_str(), (int)processName.size(), &processNameA[0], size_needed, NULL, NULL);
        writeLog("MONITOR: 等待进程 " + processNameA + " 启动");

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
        case EXCEPTION_PRIVILEGED_INSTRUCTION: return "特权指令";
        case EXCEPTION_STACK_OVERFLOW: return "栈溢出";
        case EXCEPTION_GUARD_PAGE: return "保护页";
        case EXCEPTION_SINGLE_STEP: return "单步执行";
        case EXCEPTION_STACK_INVALID: return "栈无效";
        case EXCEPTION_INVALID_HANDLE: return "无效句柄";
        case 0xC0000194: return "可能死锁";  // EXCEPTION_POSSIBLE_DEADLOCK
        case 0xC0000195: return "无效锁定序列";  // EXCEPTION_INVALID_LOCK_SEQUENCE
        case 0xC000005C: return "无效读取";  // EXCEPTION_INVALID_READ
        case 0xC000005D: return "无效写入";  // EXCEPTION_INVALID_WRITE
        case 0xC000005E: return "无效用户缓冲区";  // EXCEPTION_INVALID_USER_BUFFER
        case 0xC0000353: return "端口未设置";  // EXCEPTION_PORT_NOT_SET
        case 0xC0000037: return "端口断开连接";  // EXCEPTION_PORT_DISCONNECTED
        case 0xC0000208: return "地址已关联";  // EXCEPTION_ADDRESS_ALREADY_ASSOCIATED
        case 0xC0000207: return "地址未关联";  // EXCEPTION_ADDRESS_NOT_ASSOCIATED
        case 0xC0000206: return "断开连接";  // EXCEPTION_DISCONNECTED
        case 0xC0000240: return "连接中止";  // EXCEPTION_CONNECTION_ABORTED
        case 0xC0000242: return "连接无效";  // EXCEPTION_CONNECTION_INVALID
        case 0xC0000041: return "连接被拒绝";  // EXCEPTION_CONNECTION_REFUSED

            // 微软调试异常
        case 0x406D1388: return "MSVC线程命名异常";

            // .NET/CLR异常
        case 0xE0434F4D: return "CLR异常";
        case 0xE0434352: return "CLR异常";

            // C++异常
        case 0xE06D7363: return "Microsoft C++异常";

            // Windows异常代码
        case 0xC000000D: return "无效参数";
        case 0xC0000017: return "无足够内存";
        case 0xC0000035: return "模块名称无效";
        case 0xC0000142: return "DLL初始化失败";
        case 0xC000026B: return "DLL未找到";
        case 0xC0000278: return "RPC服务器不可用";
        case 0xC0000279: return "RPC服务器太忙";
        case 0xC0000280: return "RPC调用在错误的线程上";
        case 0xC0000281: return "RPC协议错误";
        case 0xC00002B4: return "DLL初始化例程失败";
        case 0xC00002B5: return "DLL未找到";
        case 0xC00002C9: return "无效指令";
        case 0xC00002CA: return "页保护冲突";
        case 0xC0000409: return "缓冲区溢出";
        case 0xC000041D: return "FATAL_USER_CALLBACK_EXCEPTION";

        default:
            if ((exceptionCode & 0xFFFF0000) == 0xC0000000) {
                return "NTSTATUS异常";
            }
            else if ((exceptionCode & 0xFFFF0000) == 0x80000000) {
                return "HRESULT异常";
            }
            else if (exceptionCode == 0xE06D7363) {
                return "C++异常";
            }
            else if (exceptionCode == 0xE0434F4D || exceptionCode == 0xE0434352) {
                return "CLR异常";
            }
            return "未知异常";
        }
    }

    std::string toHexString(DWORD value) {
        std::stringstream ss;
        ss << std::hex << value;
        return ss.str();
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

        // 处理MSVC调试器用于设置线程名的异常
        if (exceptionCode == 0x406D1388) {  // EXCEPTION_MS_VC_THREAD_NAME
            if (verboseOutput) {
                std::cout << "[INFO] 接收到线程命名异常，正常处理" << std::endl;
                writeLog("INFO: 接收到线程命名异常 (0x406D1388)，正常处理");
            }
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
        case EXCEPTION_STACK_INVALID:
        case EXCEPTION_INVALID_HANDLE:
        case EXCEPTION_INVALID_READ:
        case EXCEPTION_INVALID_WRITE:
        case EXCEPTION_INVALID_USER_BUFFER:
        case EXCEPTION_GUARD_VIOLATION:
        case EXCEPTION_BUFFER_OVERFLOW:
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
        case EXCEPTION_FLT_DENORMAL_OPERATION:
        case EXCEPTION_FLT_INVALID_PARAMETER:
        case EXCEPTION_FLT_OVERFLOW_IN_UNDERFLOW:
        case EXCEPTION_FLT_UNDERFLOW_IN_OVERFLOW:
            return handleArithmeticException(debugEvent, threadId);

            // 指令异常
        case EXCEPTION_ILLEGAL_INSTRUCTION:
        case EXCEPTION_PRIVILEGED_INSTRUCTION:  // 0xC0000096
        case EXCEPTION_NONCONTINUABLE_EXCEPTION:
        case EXCEPTION_INVALID_LOCK_SEQUENCE:
        case EXCEPTION_INVALID_PARAMETER:
        case EXCEPTION_SYSCALL_ERROR:
            return handleInstructionException(debugEvent, threadId);

            // 调试异常
        case EXCEPTION_BREAKPOINT:
        case EXCEPTION_SINGLE_STEP:
        case EXCEPTION_BREAKPOINT_DEBUG:
        case EXCEPTION_SINGLE_STEP_DEBUG:
            return DBG_CONTINUE;

            // 系统异常
        case EXCEPTION_POSSIBLE_DEADLOCK:
        case EXCEPTION_PORT_NOT_SET:
        case EXCEPTION_PORT_DISCONNECTED:
        case EXCEPTION_ADDRESS_ALREADY_ASSOCIATED:
        case EXCEPTION_ADDRESS_NOT_ASSOCIATED:
        case EXCEPTION_DISCONNECTED:
        case EXCEPTION_CONNECTION_ABORTED:
        case EXCEPTION_CONNECTION_INVALID:
        case EXCEPTION_CONNECTION_REFUSED:
            std::cout << "[INFO] 处理系统异常，尝试继续执行" << std::endl;
            writeLog("INFO: 处理系统异常，尝试继续执行");
            return DBG_CONTINUE;

            // 调试器异常
        case 0x406D1388:  // EXCEPTION_MS_VC_THREAD_NAME
            return DBG_CONTINUE;

            // .NET/CLR异常
        case 0xE0434F4D: // CLR异常
        case 0xE0434352: // CLR异常
        case 0xE0434F4E: // CLR异常
        case 0xE0434F4F: // CLR异常
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
            if ((exceptionCode & 0xFFFF0000) == 0xC0000000 ||
                (exceptionCode & 0xFFFF0000) == 0x80000000 ||
                exceptionCode == 0xE06D7363 ||
                exceptionCode == 0xE0434F4D ||
                exceptionCode == 0xE0434352) {
                std::cout << "[INFO] 处理系统异常: 0x" << std::hex << exceptionCode << std::dec << std::endl;
                writeLog("INFO: 处理系统异常: 0x" + toHexString(exceptionCode));
                return handleGenericException(debugEvent, threadId);
            }

            std::cout << "[WARNING] 未知异常类型" << std::endl;
            writeLog("WARNING: 未知异常类型");
            return DBG_EXCEPTION_NOT_HANDLED;
        }
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
        DWORD exceptionCode = debugEvent.u.Exception.ExceptionRecord.ExceptionCode;

        // 对于未知异常，尝试跳过指令
        std::cout << "[INFO] 尝试处理通用异常: 0x" << std::hex << exceptionCode << std::dec << std::endl;
        writeLog("INFO: 尝试处理通用异常: 0x" + toHexString(exceptionCode));

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
        std::cout << "[START] 崩溃恢复调试器(v0.4-beta)启动" << std::endl;

        // 初始化日志
        if (initializeLog()) {
            std::cout << "[INFO] 日志文件已创建: log.txt (最大100kB)" << std::endl;
        }

        writeLog("START: 崩溃恢复调试器(v0.4-beta)启动");

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
    std::cout << R"(
╔══════════════════════════════════════════════════════════════════╗
║          崩溃恢复调试器 v0.4-beta (通用版)                      ║
║            支持任意Windows进程的异常捕获和恢复                 ║
║                Copyright (c) 2024 github/why37281               ║
║               SPDX-License-Identifier: AGPL-3.0-only            ║
║          WITH Additional Permission prohibiting commercial use   ║
╚══════════════════════════════════════════════════════════════════╝
    )" << std::endl;
}

// 从控制台读取一行输入，支持中文
std::wstring getWideStringInput() {
    std::string input;
    std::getline(std::cin, input);

    if (input.empty()) {
        return L"PlantsVsZombies.exe"; // 返回默认值
    }

    // 将UTF-8或ANSI字符串转换为宽字符串
    int wlen = MultiByteToWideChar(CP_ACP, 0, input.c_str(), (int)input.length(), NULL, 0);
    if (wlen == 0) {
        return L"PlantsVsZombies.exe"; // 转换失败，返回默认值
    }

    std::wstring wstr(wlen, 0);
    MultiByteToWideChar(CP_ACP, 0, input.c_str(), (int)input.length(), &wstr[0], wlen);

    return wstr;
}

int main() {
    printBanner();

    char choice;
    std::cout << "[CONFIG] 是否启用详细输出 (y/n) [默认: n]: ";
    choice = std::cin.get();
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    bool verbose = (choice == 'y' || choice == 'Y');
    std::cout << std::endl << "[INFO] 详细输出已" << (verbose ? "启用" : "禁用") << std::endl;

    // 输入进程名
    std::wstring processName = L"PlantsVsZombies.exe"; // 默认值
    std::wstring inputName;

    std::cout << "[CONFIG] 请输入要附加的进程名 (默认为 PlantsVsZombies.exe): ";
    inputName = getWideStringInput();

    if (!inputName.empty() && inputName != L"PlantsVsZombies.exe") {
        processName = inputName;
    }

    // 确保进程名有.exe扩展名
    if (processName.size() < 4 || processName.substr(processName.size() - 4) != L".exe") {
        processName += L".exe";
    }

    std::wcout << L"[INFO] 目标进程: " << processName << std::endl;

    // 显示提示信息
    std::cout << std::endl << "==========================================" << std::endl;
    std::cout << "[提示]" << std::endl;
    std::cout << "1. 确保目标进程已启动" << std::endl;
    std::cout << "2. 调试器会尝试自动附加" << std::endl;
    std::cout << "3. 当目标进程崩溃时，会自动跳过崩溃指令" << std::endl;
    std::cout << "4. 详细输出模式会显示更多调试信息" << std::endl;
    std::cout << "5. 按Ctrl+C可退出调试器" << std::endl;
    std::cout << "==========================================" << std::endl << std::endl;

    ProcessDebugger debugger(processName);
    debugger.setVerboseOutput(verbose);

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