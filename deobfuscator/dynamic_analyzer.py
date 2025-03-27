#!/usr/bin/env python3
"""
动态分析引擎 - 用于恶意软件和壳保护程序的动态分析
具有内存转储、API跟踪和反调试绕过功能
"""
import os
import sys
import time
import json
import signal
import hashlib
import tempfile
import argparse
import subprocess
import threading
import logging
import traceback
from typing import Dict, List, Optional, Any, Tuple, Callable, Union
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from flask import Flask, request, jsonify, send_file, abort

# 设置日志
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("dynamic_analyzer.log")
    ]
)
logger = logging.getLogger(__name__)

# 检查Frida是否已安装
try:
    import frida
except ImportError:
    logger.error("未安装frida库，请先运行: pip install frida-tools")
    sys.exit(1)

# Frida JS脚本 - 核心功能
FRIDA_SCRIPT = """
(function(){
    // 全局变量以跟踪API调用和保护状态
    var apiCalls = []; 
    var memoryAllocs = [];
    var networkData = [];
    var fileData = [];
    var registryData = [];
    var antiDebugAttempts = 0;
    var protectionDetections = {
        'vmprotect': [],
        'themida': [],
        'custom': []
    };
    var threadCreations = [];
    var suspiciousCodeRegions = [];
    
    // 调试和错误处理实用函数
    function safeCall(fn, args, errorDefault) {
        try {
            return fn.apply(null, args);
        } catch (e) {
            console.log('[!] Error in ' + fn.name + ': ' + e.message);
            return errorDefault;
        }
    }
    
    // 高级日志系统
    const LogLevel = {
        DEBUG: 0,
        INFO: 1,
        WARN: 2,
        ERROR: 3
    };
    
    const currentLogLevel = LogLevel.INFO;
    
    function logMessage(level, message) {
        if (level >= currentLogLevel) {
            const prefix = ['[DEBUG]', '[INFO]', '[WARN]', '[ERROR]'][level];
            console.log(prefix + ' ' + message);
        }
    }
    
    const log = {
        debug: function(message) { logMessage(LogLevel.DEBUG, message); },
        info: function(message) { logMessage(LogLevel.INFO, message); },
        warn: function(message) { logMessage(LogLevel.WARN, message); },
        error: function(message) { logMessage(LogLevel.ERROR, message); },
    };
    
    // 内存工具辅助函数
    function dumpMemory(address, size, info) {
        try {
            if (size <= 0 || size > 10485760) { // 限制大小为10MB
                log.warn("请求的内存转储大小超出范围: " + size);
                return false;
            }
            
            const data = Memory.readByteArray(ptr(address), size);
            send({
                type: 'memory_dump', 
                address: address.toString(), 
                size: size,
                info: info || 'Manual dump'
            }, data);
            
            return true;
        } catch (e) {
            log.error("内存转储失败: " + e.message);
            return false;
        }
    }
    
    // 将地址解析为模块+偏移格式
    function formatAddress(address) {
        try {
            const addressPtr = ptr(address);
            const module = Process.findModuleByAddress(addressPtr);
            if (module) {
                const offset = addressPtr.sub(module.base);
                return module.name + "+0x" + offset.toString(16);
            } else {
                return "0x" + addressPtr.toString(16);
            }
        } catch (e) {
            return address.toString();
        }
    }
    
    // 动态扫描和检测功能
    function scanMemoryRegionsForSignatures() {
        log.info("扫描内存区域寻找保护特征...");
        
        // VMP/Themida/自定义保护特征的模式定义
        const patterns = {
            'vmprotect': [
                { pattern: 'EB ?? ?? ?? ?? ?? ?? ?? ?? 00', name: 'VMProtect v1.x-v3.x' },
                { pattern: '68 ?? ?? ?? ?? E9 ?? ?? ?? ?? 00 00', name: 'VMProtect Handler' },
                { pattern: '9C 60 68 53 A3 B5 F7', name: 'VMProtect 2.x' },
            ],
            'themida': [
                { pattern: '55 8B EC 83 C4 F4 FC 53 57 56', name: 'Themida 2.x-3.x' },
                { pattern: 'B8 ?? ?? ?? ?? 60 0B C0 74 58 E8 00 00 00 00', name: 'Themida/WinLicense' },
                { pattern: '83 EC 50 60 68 ?? ?? ?? ?? E8', name: 'Themida 3.0+' },
            ],
            'custom': [
                { pattern: 'E8 00 00 00 00 58 05 ?? ?? ?? ?? 80', name: 'Custom VM Entry' },
                { pattern: '60 9C 8B 44 24 24 E8', name: 'Custom Protection Handler' },
            ]
        };
        
        // 获取所有可读可执行的内存区域
        const memoryRanges = Process.enumerateRanges('r-x');
        
        // 扫描每个内存区域
        for (const range of memoryRanges) {
            // 跳过特别大的内存区域，只扫描头部和尾部
            const scanSize = Math.min(range.size, 16384); // 16KB限制
            
            // 对每种保护类型的每个模式进行扫描
            for (const [protectionType, signaturesList] of Object.entries(patterns)) {
                for (const signatureInfo of signaturesList) {
                    try {
                        Memory.scan(range.base, scanSize, signatureInfo.pattern, {
                            onMatch: function(address, size) {
                                const foundInfo = {
                                    address: address.toString(),
                                    pattern: signatureInfo.pattern,
                                    name: signatureInfo.name,
                                    module: '未知'
                                };
                                
                                // 获取模块信息
                                try {
                                    const moduleInfo = Process.findModuleByAddress(address);
                                    if (moduleInfo) {
                                        foundInfo.module = moduleInfo.name;
                                    }
                                } catch (e) {
                                    // 忽略模块解析错误
                                }
                                
                                log.info(`[+] 发现${protectionType}保护: ${signatureInfo.name} @ ${address}`);
                                protectionDetections[protectionType].push(foundInfo);
                                
                                // 通知宿主应用程序
                                send({
                                    type: 'protection_detected',
                                    protection_type: protectionType, 
                                    info: foundInfo
                                });
                                
                                return 'continue'; // 继续搜索更多匹配
                            },
                            onError: function(reason) {
                                log.debug(`扫描错误: ${reason}`);
                            },
                            onComplete: function() {}
                        });
                    } catch (e) {
                        log.debug(`扫描异常: ${e.message}`);
                    }
                }
            }
        }
        
        log.info("内存保护扫描完成");
    }
    
    // 信息收集和模块扫描
    function collectSystemInfo() {
        const info = {
            arch: Process.arch,
            platform: Process.platform,
            pageSize: Process.pageSize,
            pointerSize: Process.pointerSize,
            mainModule: null,
            modules: []
        };
        
        try {
            const mainModule = Process.mainModule;
            info.mainModule = {
                name: mainModule.name,
                base: mainModule.base.toString(),
                size: mainModule.size,
                path: mainModule.path
            };
        } catch (e) {
            log.warn("无法获取主模块信息: " + e.message);
        }
        
        // 收集所有已加载模块
        try {
            const modules = Process.enumerateModules();
            for (const mod of modules) {
                info.modules.push({
                    name: mod.name,
                    base: mod.base.toString(),
                    size: mod.size,
                    path: mod.path
                });
            }
        } catch (e) {
            log.warn("枚举模块错误: " + e.message);
        }
        
        // 发送系统信息
        send({
            type: 'system_info',
            info: info
        });
        
        return info;
    }
    
    // 扫描非系统模块
    function scanUserModules() {
        const userModules = Process.enumerateModules().filter((m) => {
            return !m.path.toLowerCase().includes('\\windows\\') &&
                   !m.path.toLowerCase().includes('\\syswow64\\') &&
                   !m.name.toLowerCase().includes('api-ms-win');
        });
        
        log.info(`[*] 用户模块: ${userModules.length}`);
        for (const m of userModules) {
            log.debug(`模块: ${m.name} (${m.base})`);
        }
        
        return userModules;
    }
    
    // 通用API拦截配置
    const apiModules = {
        // 反调试API
        "antiDebug": [
            {"module": "kernel32.dll", "function": "IsDebuggerPresent"},
            {"module": "kernel32.dll", "function": "CheckRemoteDebuggerPresent"},
            {"module": "ntdll.dll", "function": "NtQueryInformationProcess"},
            {"module": "kernel32.dll", "function": "OutputDebugString"},
            {"module": "kernel32.dll", "function": "GetTickCount"},
            {"module": "kernel32.dll", "function": "QueryPerformanceCounter"},
            {"module": "ntdll.dll", "function": "NtSetInformationThread"},
            {"module": "ntdll.dll", "function": "NtClose"},
            {"module": "ntdll.dll", "function": "NtGetContextThread"},
            {"module": "ntdll.dll", "function": "NtSetContextThread"},
            {"module": "kernel32.dll", "function": "GetThreadContext"},
            {"module": "kernel32.dll", "function": "SetThreadContext"}
        ],
        // 网络验证API
        "network": [
            {"module": "wininet.dll", "function": "InternetOpen"},
            {"module": "wininet.dll", "function": "InternetOpenUrl"},
            {"module": "wininet.dll", "function": "InternetConnect"},
            {"module": "wininet.dll", "function": "HttpOpenRequest"},
            {"module": "wininet.dll", "function": "HttpSendRequest"},
            {"module": "wininet.dll", "function": "InternetReadFile"},
            {"module": "ws2_32.dll", "function": "connect"},
            {"module": "ws2_32.dll", "function": "send"},
            {"module": "ws2_32.dll", "function": "recv"},
            {"module": "ws2_32.dll", "function": "WSAConnect"},
            {"module": "winhttp.dll", "function": "WinHttpConnect"},
            {"module": "winhttp.dll", "function": "WinHttpOpen"},
            {"module": "winhttp.dll", "function": "WinHttpSendRequest"}
        ],
        // 加密API
        "crypto": [
            {"module": "advapi32.dll", "function": "CryptGenKey"},
            {"module": "advapi32.dll", "function": "CryptDecrypt"},
            {"module": "advapi32.dll", "function": "CryptEncrypt"},
            {"module": "advapi32.dll", "function": "CryptHashData"},
            {"module": "bcrypt.dll", "function": "BCryptEncrypt"},
            {"module": "bcrypt.dll", "function": "BCryptDecrypt"},
            {"module": "bcrypt.dll", "function": "BCryptGenerateSymmetricKey"},
            {"module": "ncrypt.dll", "function": "NCryptEncrypt"},
            {"module": "ncrypt.dll", "function": "NCryptDecrypt"}
        ],
        // 文件操作API
        "file": [
            {"module": "kernel32.dll", "function": "CreateFile"},
            {"module": "kernel32.dll", "function": "ReadFile"},
            {"module": "kernel32.dll", "function": "WriteFile"},
            {"module": "kernel32.dll", "function": "CopyFile"},
            {"module": "kernel32.dll", "function": "DeleteFile"},
            {"module": "kernel32.dll", "function": "GetTempPath"},
            {"module": "kernel32.dll", "function": "GetTempFileName"}
        ],
        // 注册表操作API
        "registry": [
            {"module": "advapi32.dll", "function": "RegOpenKey"},
            {"module": "advapi32.dll", "function": "RegOpenKeyEx"},
            {"module": "advapi32.dll", "function": "RegQueryValue"},
            {"module": "advapi32.dll", "function": "RegQueryValueEx"},
            {"module": "advapi32.dll", "function": "RegSetValue"},
            {"module": "advapi32.dll", "function": "RegSetValueEx"},
            {"module": "advapi32.dll", "function": "RegCreateKey"},
            {"module": "advapi32.dll", "function": "RegCreateKeyEx"}
        ],
        // 进程和线程操作API
        "process": [
            {"module": "kernel32.dll", "function": "CreateProcess"},
            {"module": "kernel32.dll", "function": "CreateThread"},
            {"module": "kernel32.dll", "function": "OpenProcess"},
            {"module": "kernel32.dll", "function": "TerminateProcess"},
            {"module": "kernel32.dll", "function": "VirtualProtect"},
            {"module": "kernel32.dll", "function": "VirtualAlloc"},
            {"module": "ntdll.dll", "function": "NtOpenProcess"},
            {"module": "ntdll.dll", "function": "NtCreateThreadEx"}
        ],
        // 内存操作API
        "memory": [
            {"module": "kernel32.dll", "function": "VirtualAlloc"},
            {"module": "kernel32.dll", "function": "VirtualProtect"},
            {"module": "kernel32.dll", "function": "HeapCreate"},
            {"module": "kernel32.dll", "function": "HeapAlloc"},
            {"module": "kernel32.dll", "function": "WriteProcessMemory"},
            {"module": "kernel32.dll", "function": "ReadProcessMemory"},
            {"module": "ntdll.dll", "function": "NtAllocateVirtualMemory"},
            {"module": "ntdll.dll", "function": "NtProtectVirtualMemory"}
        ]
    };
    
    // 附加钩子到所有配置的API
    function hookSpecifiedAPIs() {
        let hookedCount = 0;
        
        for (const category in apiModules) {
            apiModules[category].forEach(api => {
                try {
                    const name = api.function;
                    const moduleName = api.module;
                    
                    // 解析函数地址
                    const functionAddress = Module.findExportByName(moduleName, name);
                    if (functionAddress !== null) {
                        attachHook(moduleName, name, functionAddress, category);
                        hookedCount++;
                    } else {
                        log.debug(`[!] 无法找到函数 ${moduleName}!${name}`);
                    }
                } catch (e) {
                    log.warn(`[!] 拦截API错误: ${e.message}`);
                }
            });
        }
        
        log.info(`成功挂钩了 ${hookedCount} 个API函数`);
    }
    
    // 为每个API附加钩子的核心函数
    function attachHook(moduleName, funcName, address, category) {
        try {
            Interceptor.attach(address, {
                onEnter: function (args) {
                    // 保存基本调用信息
                    this.category = category;
                    this.funcName = funcName;
                    this.moduleName = moduleName;
                    this.startTime = new Date().getTime();
                    
                    // 为每个API类别保存适当的参数
                    this.args = [];
                    for (let i = 0; i < 8; i++) {  // 保存前8个参数
                        this.args.push(args[i]);
                    }
                    
                    // 记录调用
                    const callInfo = {
                        timestamp: this.startTime,
                        function: funcName,
                        module: moduleName,
                        category: category,
                        caller: formatAddress(this.returnAddress)
                    };
                    
                    apiCalls.push(callInfo);
                    log.debug(`[*] 调用: ${moduleName}!${funcName}`);
                    
                    // 根据API类别处理特定逻辑
                    switch(category) {
                        case 'antiDebug':
                            handleAntiDebugCall(this, args, funcName);
                            break;
                        case 'network':
                            handleNetworkCall(this, args, funcName);
                            break;
                        case 'crypto':
                            handleCryptoCall(this, args, funcName);
                            break;
                        case 'file':
                            handleFileCall(this, args, funcName);
                            break;
                        case 'registry':
                            handleRegistryCall(this, args, funcName);
                            break;
                        case 'process':
                            handleProcessCall(this, args, funcName);
                            break;
                        case 'memory':
                            handleMemoryCall(this, args, funcName);
                            break;
                    }
                },
                onLeave: function (retval) {
                    // 基本结果处理
                    const duration = new Date().getTime() - this.startTime;
                    
                    // 根据API类别处理特定的结果逻辑
                    switch(this.category) {
                        case 'antiDebug':
                            handleAntiDebugResult(this, retval);
                            break;
                        case 'network':
                            handleNetworkResult(this, retval);
                            break;
                        case 'crypto':
                            handleCryptoResult(this, retval);
                            break;
                        case 'file':
                            handleFileResult(this, retval);
                            break;
                        case 'registry':
                            handleRegistryResult(this, retval);
                            break;
                        case 'process':
                            handleProcessResult(this, retval);
                            break;
                        case 'memory':
                            handleMemoryResult(this, retval);
                            break;
                    }
                    
                    // 如果调用时间过长，记录它（可能表示VMProtect或类似的虚拟化）
                    if (duration > 50) { // 50ms阈值
                        log.debug(`长时间API调用: ${this.moduleName}!${this.funcName} (${duration}ms)`);
                    }
                }
            });
        } catch (e) {
            log.warn(`钩子附加错误 ${moduleName}!${funcName}: ${e.message}`);
        }
    }
    
    // === 特定API类别处理程序 ===
    
    // 处理反调试API调用
    function handleAntiDebugCall(context, args, funcName) {
        antiDebugAttempts++;
        send({
            type: 'anti_debug_attempt',
            function: funcName,
            timestamp: new Date().getTime()
        });
        
        // 特定API处理
        if (funcName === 'IsDebuggerPresent') {
            context.override = true;
        } else if (funcName === 'CheckRemoteDebuggerPresent') {
            context.checkRemotePresent = true;
            context.outBuf = args[1];
        } else if (funcName === 'NtQueryInformationProcess') {
            const ProcessDebugPort = 7;
            const ProcessDebugObjectHandle = 30;
            const ProcessDebugFlags = 31;
            
            // 获取查询类型
            const infoClass = parseInt(args[1].toString());
            if (infoClass === ProcessDebugPort || infoClass === ProcessDebugObjectHandle || infoClass === ProcessDebugFlags) {
                context.ntQueryInfo = true;
                context.infoClass = infoClass;
                context.outBuf = args[2];
                context.outSize = parseInt(args[3].toString());
            }
        } else if (funcName === 'NtSetInformationThread') {
            const ThreadHideFromDebugger = 0x11;
            
            // 检查是否是反调试用的线程隐藏
            const infoClass = parseInt(args[1].toString());
            if (infoClass === ThreadHideFromDebugger) {
                log.info('[!] 尝试隐藏线程不被调试器检测');
            }
        } else if (funcName === 'OutputDebugString') {
            context.debugString = args[0];
            try {
                // 记录debug string内容
                if (args[0] !== 0) {
                    const str = Memory.readUtf16String(args[0]);
                    if (str) {
                        log.debug(`OutputDebugString: "${str}"`);
                    }
                }
            } catch (e) {
                // 忽略错误
            }
        }
    }
    
    // 处理反调试API结果
    function handleAntiDebugResult(context, retval) {
        if (context.override) {
            log.info('[*] 欺骗 IsDebuggerPresent, 返回 0');
            retval.replace(0); // 将结果替换为0
        } else if (context.checkRemotePresent) {
            log.info('[*] 欺骗 CheckRemoteDebuggerPresent');
            try {
                Memory.writeU32(context.outBuf, 0);
            } catch (e) {
                log.warn(`内存写入错误: ${e.message}`);
            }
        } else if (context.ntQueryInfo) {
            log.info(`[*] 欺骗 NtQueryInformationProcess(类 ${context.infoClass})`);
            try {
                if (context.infoClass === 7 /* ProcessDebugPort */) {
                    Memory.writeU64(context.outBuf, 0);
                } else if (context.infoClass === 30 /* ProcessDebugObjectHandle */) {
                    Memory.writeU64(context.outBuf, 0);
                } else if (context.infoClass === 31 /* ProcessDebugFlags */) {
                    Memory.writeU32(context.outBuf, 1);
                }
            } catch (e) {
                log.warn(`内存写入错误: ${e.message}`);
            }
        }
    }
    
    // 处理网络API调用
    function handleNetworkCall(context, args, funcName) {
        if (funcName === 'connect') {
            const sockaddr = args[1];
            // 解析sockaddr结构
            const sa_family = Memory.readU16(sockaddr);
            
            if (sa_family === 2) { // AF_INET
                const port = Memory.readU16(sockaddr.add(2));
                const portBE = ((port & 0xFF) << 8) | ((port & 0xFF00) >> 8);
                
                let addr = '';
                for (let i = 0; i < 4; i++) {
                    addr += Memory.readU8(sockaddr.add(4 + i));
                    if (i < 3) addr += '.';
                }
                
                log.info(`[+] 网络连接: ${addr}:${portBE}`);
                
                context.connectAddr = addr;
                context.connectPort = portBE;
                
                send({
                    type: 'network_connect',
                    address: addr,
                    port: portBE,
                    timestamp: new Date().getTime()
                });
            }
        } else if (funcName === 'send') {
            const socket = args[0];
            const buffer = args[1];
            const length = parseInt(args[2].toString());
            
            if (length > 0 && length < 1048576) { // 限制1MB
                context.sendLength = length;
                context.sendBuffer = buffer;
                
                send({
                    type: 'network_send',
                    socket: socket.toString(),
                    length: length,
                    timestamp: new Date().getTime()
                });
            }
        } else if (funcName === 'recv') {
            context.recvSocket = args[0];
            context.recvBuffer = args[1];
            context.recvLength = parseInt(args[2].toString());
        } else if (funcName === 'InternetOpenUrl' || funcName === 'HttpOpenRequest') {
            try {
                if (args[1] !== 0) {
                    const url = Memory.readUtf16String(args[1]);
                    if (url) {
                        log.info(`[+] HTTP请求: ${url}`);
                        
                        send({
                            type: 'http_request',
                            url: url,
                            timestamp: new Date().getTime()
                        });
                    }
                }
            } catch (e) {
                log.debug(`HTTP URL解析错误: ${e.message}`);
            }
        } else if (funcName === 'WinHttpSendRequest') {
            try {
                const headers = args[3];
                const headersLength = parseInt(args[4].toString());
                
                if (headers !== 0 && headersLength > 0) {
                    const headerText = Memory.readUtf16String(headers, headersLength);
                    log.debug(`HTTP Headers: ${headerText}`);
                }
            } catch (e) {
                // 忽略错误
            }
        }
    }
    
    // 处理网络API结果
    function handleNetworkResult(context, retval) {
        if (context.funcName === 'recv' && retval.toInt32() > 0) {
            const receivedLength = retval.toInt32();
            if (receivedLength > 0 && receivedLength < 1048576) { // 限制1MB
                try {
                    const data = Memory.readByteArray(context.recvBuffer, receivedLength);
                    
                    send({
                        type: 'network_recv',
                        socket: context.recvSocket.toString(),
                        length: receivedLength,
                        timestamp: new Date().getTime()
                    }, data);
                } catch (e) {
                    log.warn(`读取接收数据错误: ${e.message}`);
                }
            }
        } else if (context.funcName === 'send' && retval.toInt32() > 0) {
            if (context.sendLength > 0 && context.sendBuffer) {
                try {
                    const sendData = Memory.readByteArray(context.sendBuffer, context.sendLength);
                    
                    send({
                        type: 'network_send_data',
                        socket: "unknown",
                        length: context.sendLength,
                        timestamp: new Date().getTime()
                    }, sendData);
                } catch (e) {
                    log.warn(`读取发送数据错误: ${e.message}`);
                }
            }
        }
    }
    
    // 处理加密API调用
    function handleCryptoCall(context, args, funcName) {
        if (funcName === 'CryptDecrypt') {
            context.cryptKey = args[0];
            context.cryptHash = args[1];
            context.cryptFinal = args[2].toInt32();
            context.cryptData = args[3];
            context.cryptDataLenPtr = args[4];
            
            try {
                if (args[4] !== 0) {
                    context.cryptDataLen = Memory.readUInt(args[4]);
                    log.debug(`[+] 解密数据长度: ${context.cryptDataLen}`);
                }
            } catch (e) {
                log.debug(`CryptDecrypt参数解析错误: ${e.message}`);
            }
        } else if (funcName === 'CryptEncrypt') {
            context.cryptKey = args[0];
            context.cryptHash = args[1];
            context.cryptFinal = args[2].toInt32();
            context.cryptData = args[3];
            context.cryptDataLenPtr = args[4];
            
            try {
                if (args[4] !== 0) {
                    context.cryptDataLen = Memory.readUInt(args[4]);
                    log.debug(`[+] 加密数据长度: ${context.cryptDataLen}`);
                }
            } catch (e) {
                log.debug(`CryptEncrypt参数解析错误: ${e.message}`);
            }
        } else if (funcName === 'BCryptEncrypt' || funcName === 'BCryptDecrypt') {
            context.bcryptKey = args[0];
            context.bcryptInput = args[1];
            context.bcryptInputLen = parseInt(args[2].toString());
            context.bcryptOutput = args[4];
            context.bcryptOutputLenPtr = args[5];
            
            // 记录加密/解密操作
            log.debug(`[*] ${funcName}: 长度=${context.bcryptInputLen}`);
        }
    }
    
    // 处理加密API结果
    function handleCryptoResult(context, retval) {
        if (context.funcName === 'CryptDecrypt' && retval.toInt32() !== 0) {
            // 成功解密
            if (context.cryptDataLen > 0 && context.cryptDataLen < 1048576) { // 限制1MB
                try {
                    const decryptedData = Memory.readByteArray(context.cryptData, context.cryptDataLen);
                    
                    send({
                        type: 'crypto_decrypt',
                        key_handle: context.cryptKey.toString(),
                        data_length: context.cryptDataLen,
                        final: context.cryptFinal,
                        timestamp: new Date().getTime()
                    }, decryptedData);
                } catch (e) {
                    log.warn(`读取解密数据错误: ${e.message}`);
                }
            }
        } else if (context.funcName === 'CryptEncrypt' && retval.toInt32() !== 0) {
            // 成功加密 - 获取加密后的长度
            let encryptedLen = 0;
            try {
                if (context.cryptDataLenPtr !== 0) {
                    encryptedLen = Memory.readUInt(context.cryptDataLenPtr);
                    
                    if (encryptedLen > 0 && encryptedLen < 1048576) { // 限制1MB
                        const encryptedData = Memory.readByteArray(context.cryptData, encryptedLen);
                        
                        send({
                            type: 'crypto_encrypt',
                            key_handle: context.cryptKey.toString(),
                            data_length: encryptedLen,
                            final: context.cryptFinal,
                            timestamp: new Date().getTime()
                        }, encryptedData);
                    }
                }
            } catch (e) {
                log.warn(`读取加密数据错误: ${e.message}`);
            }
        } else if ((context.funcName === 'BCryptEncrypt' || context.funcName === 'BCryptDecrypt') && 
                   retval.toInt32() === 0) { // 0是成功
            if (context.bcryptOutputLenPtr !== 0) {
                try {
                    const outLen = Memory.readUInt(context.bcryptOutputLenPtr);
                    if (outLen > 0 && outLen < 1048576 && context.bcryptOutput !== 0) { // 限制1MB
                        const cryptData = Memory.readByteArray(context.bcryptOutput, outLen);
                        
                        send({
                            type: context.funcName === 'BCryptEncrypt' ? 'crypto_encrypt' : 'crypto_decrypt',
                            key_handle: context.bcryptKey.toString(),
                            data_length: outLen,
                            algorithm: 'BCrypt',
                            timestamp: new Date().getTime()
                        }, cryptData);
                    }
                } catch (e) {
                    log.warn(`读取BCrypt数据错误: ${e.message}`);
                }
            }
        }
    }
    
    // 处理文件API调用
    function handleFileCall(context, args, funcName) {
        if (funcName === 'CreateFile' || funcName === 'CreateFileW') {
            try {
                const path = Memory.readUtf16String(args[0]);
                if (path) {
                    log.info(`[+] 打开文件: ${path}`);
                    context.filePath = path;
                    
                    // 记录访问模式
                    context.fileDesiredAccess = args[1].toInt32();
                    
                    fileData.push({
                        timestamp: new Date().getTime(),
                        operation: 'open',
                        path: path,
                        access: context.fileDesiredAccess
                    });
                    
                    send({
                        type: 'file_access',
                        operation: 'open',
                        path: path,
                        access: context.fileDesiredAccess,
                        timestamp: new Date().getTime()
                    });
                }
            } catch (e) {
                log.debug(`文件路径解析错误: ${e.message}`);
            }
        } else if (funcName === 'ReadFile') {
            context.readFileHandle = args[0];
            context.readBuffer = args[1];
            context.bytesToRead = 0;
            try {
                if (args[2] !== 0) {
                    context.bytesToRead = Memory.readUInt(args[2]);
                }
                
                if (args[3] !== 0) {
                    context.bytesReadPtr = args[3];
                }
            } catch (e) {
                log.debug(`ReadFile参数解析错误: ${e.message}`);
            }
        } else if (funcName === 'WriteFile') {
            context.writeFileHandle = args[0];
            context.writeBuffer = args[1];
            context.bytesToWrite = 0;
            try {
                if (args[2] !== 0) {
                    context.bytesToWrite = Memory.readUInt(args[2]);
                }
            } catch (e) {
                log.debug(`WriteFile参数解析错误: ${e.message}`);
            }
        } else if (funcName === 'DeleteFile' || funcName === 'DeleteFileW') {
            try {
                const path = Memory.readUtf16String(args[0]);
                if (path) {
                    log.info(`[+] 删除文件: ${path}`);
                    
                    fileData.push({
                        timestamp: new Date().getTime(),
                        operation: 'delete',
                        path: path
                    });
                    
                    send({
                        type: 'file_access',
                        operation: 'delete',
                        path: path,
                        timestamp: new Date().getTime()
                    });
                }
            } catch (e) {
                log.debug(`文件路径解析错误: ${e.message}`);
            }
        }
    }
    
    // 处理文件API结果
    function handleFileResult(context, retval) {
        if (context.funcName === 'ReadFile' && retval.toInt32() !== 0) {
            // 成功读取
            let bytesRead = 0;
            try {
                if (context.bytesReadPtr !== undefined && context.bytesReadPtr !== 0) {
                    bytesRead = Memory.readUInt(context.bytesReadPtr);
                    
                    if (bytesRead > 0 && bytesRead < 1048576) { // 限制1MB
                        const fileData = Memory.readByteArray(context.readBuffer, bytesRead);
                        
                        send({
                            type: 'file_read',
                            handle: context.readFileHandle.toString(),
                            length: bytesRead,
                            timestamp: new Date().getTime()
                        }, fileData);
                    }
                }
            } catch (e) {
                log.warn(`读取文件数据错误: ${e.message}`);
            }
        } else if (context.funcName === 'WriteFile' && retval.toInt32() !== 0) {
            // 成功写入
            if (context.bytesToWrite > 0 && context.bytesToWrite < 1048576) { // 限制1MB
                try {
                    const fileData = Memory.readByteArray(context.writeBuffer, context.bytesToWrite);
                    
                    send({
                        type: 'file_write',
                        handle: context.writeFileHandle.toString(),
                        length: context.bytesToWrite,
                        timestamp: new Date().getTime()
                    }, fileData);
                } catch (e) {
                    log.warn(`读取写入数据错误: ${e.message}`);
                }
            }
        } else if (context.funcName === 'CreateFile' || context.funcName === 'CreateFileW') {
            const INVALID_HANDLE_VALUE = ptr("-1");
            if (!retval.equals(INVALID_HANDLE_VALUE)) {
                // 成功打开文件 - 添加额外信息
                send({
                    type: 'file_opened',
                    path: context.filePath || "unknown",
                    handle: retval.toString(),
                    timestamp: new Date().getTime()
                });
            } else {
                log.debug(`打开文件失败: ${context.filePath || "unknown"}`);
            }
        }
    }
    
    // 处理注册表API调用
    function handleRegistryCall(context, args, funcName) {
        if (funcName === 'RegOpenKey' || funcName === 'RegOpenKeyEx') {
            try {
                // args[1]是键名
                if (args[1] !== 0) {
                    const keyName = Memory.readUtf16String(args[1]);
                    if (keyName) {
                        log.info(`[+] 打开注册表键: ${keyName}`);
                        context.regKeyName = keyName;
                        
                        registryData.push({
                            timestamp: new Date().getTime(),
                            operation: 'open',
                            key: keyName
                        });
                        
                        send({
                            type: 'registry_access',
                            operation: 'open',
                            key: keyName,
                            timestamp: new Date().getTime()
                        });
                    }
                }
            } catch (e) {
                log.debug(`注册表键解析错误: ${e.message}`);
            }
        } else if (funcName === 'RegQueryValue' || funcName === 'RegQueryValueEx') {
            try {
                // args[1]是值名
                if (args[0] !== 0 && args[1] !== 0) {
                    const valueName = Memory.readUtf16String(args[1]);
                    if (valueName) {
                        context.regValueName = valueName;
                        log.debug(`[+] 查询注册表值: ${valueName}`);
                        
                        registryData.push({
                            timestamp: new Date().getTime(),
                            operation: 'query',
                            value: valueName
                        });
                        
                        // 捕获输出缓冲区
                        context.regDataPtr = args[4]; // 数据缓冲区
                        context.regDataSizePtr = args[5]; // 缓冲区大小指针
                    }
                }
            } catch (e) {
                log.debug(`注册表值解析错误: ${e.message}`);
            }
        } else if (funcName === 'RegSetValue' || funcName === 'RegSetValueEx') {
            try {
                // args[1]是值名, args[4]是数据, args[5]是大小
                if (args[0] !== 0 && args[1] !== 0) {
                    const valueName = Memory.readUtf16String(args[1]);
                    if (valueName) {
                        context.regValueName = valueName;
                        context.regDataType = args[2].toInt32(); // 值类型
                        context.regData = args[3]; // 数据指针
                        context.regDataSize = args[4].toInt32(); // 数据大小
                        
                        log.info(`[+] 设置注册表值: ${valueName}`);
                        
                        registryData.push({
                            timestamp: new Date().getTime(),
                            operation: 'set',
                            value: valueName,
                            type: context.regDataType
                        });
                        
                        send({
                            type: 'registry_access',
                            operation: 'set',
                            value: valueName,
                            data_type: context.regDataType,
                            timestamp: new Date().getTime()
                        });
                    }
                }
            } catch (e) {
                log.debug(`注册表值解析错误: ${e.message}`);
            }
        }
    }
    
    // 处理注册表API结果
    function handleRegistryResult(context, retval) {
        const ERROR_SUCCESS = 0;
        
        if ((context.funcName === 'RegQueryValue' || context.funcName === 'RegQueryValueEx') && 
            retval.toInt32() === ERROR_SUCCESS) {
            // 成功查询 - 尝试读取值
            try {
                if (context.regDataPtr && context.regDataSizePtr) {
                    const dataSize = Memory.readUInt(context.regDataSizePtr);
                    if (dataSize > 0 && dataSize < 16384) { // 限制16KB
                        // 从内存中读取数据
                        const data = Memory.readByteArray(context.regDataPtr, dataSize);
                        
                        send({
                            type: 'registry_data',
                            value: context.regValueName,
                            size: dataSize,
                            timestamp: new Date().getTime()
                        }, data);
                    }
                }
            } catch (e) {
                log.debug(`读取注册表数据错误: ${e.message}`);
            }
        }
    }
    
    // 处理进程/线程API调用
    function handleProcessCall(context, args, funcName) {
        if (funcName === 'CreateThread') {
            context.threadStart = args[2];
            context.threadParam = args[3];
            
            log.info(`[+] 正在创建线程: 起始地址=${context.threadStart}`);
            
            threadCreations.push({
                timestamp: new Date().getTime(),
                start_address: context.threadStart.toString(),
                parameter: context.threadParam ? context.threadParam.toString() : "null"
            });
        } else if (funcName === 'CreateProcess' || funcName === 'CreateProcessW') {
            try {
                if (args[0] !== 0) {
                    const appName = Memory.readUtf16String(args[0]);
                    if (appName) {
                        log.info(`[+] 正在创建进程: ${appName}`);
                        context.processName = appName;
                    }
                }
                
                if (args[1] !== 0) {
                    const cmdLine = Memory.readUtf16String(args[1]);
                    if (cmdLine) {
                        log.info(`[+] 命令行: ${cmdLine}`);
                        context.commandLine = cmdLine;
                    }
                }
                
                send({
                    type: 'process_creation',
                    app_name: context.processName || "unknown",
                    command_line: context.commandLine || "unknown",
                    timestamp: new Date().getTime()
                });
            } catch (e) {
                log.debug(`CreateProcess参数解析错误: ${e.message}`);
            }
        } else if (funcName === 'VirtualProtect') {
            context.vpAddress = args[0];
            context.vpSize = args[1].toInt32();
            context.vpNewProtect = args[2].toInt32();
            context.vpOldProtectPtr = args[3];
            
            // 检查是否是关键保护变更（例如，将内存从RW改为RWX）
            if (context.vpNewProtect & 0x40) { // PAGE_EXECUTE_READWRITE
                log.info(`[!] 内存变为可执行: ${context.vpAddress}, 大小: ${context.vpSize}`);
                
                send({
                    type: 'memory_protection_change',
                    address: context.vpAddress.toString(),
                    size: context.vpSize,
                    new_protection: context.vpNewProtect,
                    timestamp: new Date().getTime()
                });
            }
        }
    }
    
    // 处理进程/线程API结果
    function handleProcessResult(context, retval) {
        if (context.funcName === 'CreateThread' && !retval.isNull()) {
            // 成功创建线程
            const threadId = retval.toInt32();
            log.info(`[+] 线程创建成功: ID=${threadId}, 起始地址=${context.threadStart}`);
            
            send({
                type: 'thread_created',
                thread_id: threadId,
                start_address: context.threadStart.toString(),
                parameter: context.threadParam ? context.threadParam.toString() : "null",
                timestamp: new Date().getTime()
            });
            
            // 尝试跟踪新创建的线程
            try {
                Stalker.follow(threadId, {
                    events: {
                        call: true,
                        ret: false,
                        exec: false
                    },
                    onReceive: function(events) {
                        // 为了性能，仅记录显著的跟踪
                        const calls = Stalker.parse(events);
                        if (calls.length > 0) {
                            log.debug(`Thread ${threadId}: ${calls.length} 个调用`);
                            
                            // 仅发送最显著的调用
                            const significantCalls = []; 
                            for (let i = 0; i < Math.min(calls.length, 10); i++) {
                                significantCalls.push({
                                    from: calls[i][0].toString(),
                                    to: calls[i][1].toString()
                                });
                            }
                            
                            if (significantCalls.length > 0) {
                                send({
                                    type: 'thread_execution',
                                    thread_id: threadId,
                                    calls: significantCalls,
                                    total_calls: calls.length,
                                    timestamp: new Date().getTime()
                                });
                            }
                        }
                    }
                });
            } catch (e) {
                log.warn(`线程跟踪错误: ${e.message}`);
            }
        } else if ((context.funcName === 'CreateProcess' || context.funcName === 'CreateProcessW') && 
                  retval.toInt32() !== 0) {
            // 成功创建进程
            try {
                // 输出参数通常在args[8]
                const lpProcessInformation = context.args[8];
                if (lpProcessInformation) {
                    const hProcess = Memory.readPointer(lpProcessInformation);
                    const hThread = Memory.readPointer(lpProcessInformation.add(Process.pointerSize));
                    const dwProcessId = Memory.readUInt(lpProcessInformation.add(Process.pointerSize * 2));
                    const dwThreadId = Memory.readUInt(lpProcessInformation.add(Process.pointerSize * 2 + 4));
                    
                    log.info(`[+] 进程创建成功: PID=${dwProcessId}, TID=${dwThreadId}`);
                    
                    send({
                        type: 'process_created',
                        app_name: context.processName || "unknown",
                        command_line: context.commandLine || "unknown",
                        process_id: dwProcessId,
                        thread_id: dwThreadId,
                        timestamp: new Date().getTime()
                    });
                }
            } catch (e) {
                log.debug(`读取进程信息错误: ${e.message}`);
            }
        } else if (context.funcName === 'VirtualProtect' && retval.toInt32() !== 0) {
            // 成功更改保护
            try {
                if (context.vpOldProtectPtr) {
                    const oldProtect = Memory.readUInt(context.vpOldProtectPtr);
                    
                    // 如果内存从非可执行变为可执行，则进行内存转储
                    if ((oldProtect & 0x40) === 0 && (context.vpNewProtect & 0x40) !== 0) {
                        log.info(`[+] 内存从非可执行变为可执行: ${context.vpAddress}`);
                        
                        // 转储新可执行内存
                        dumpMemory(context.vpAddress, context.vpSize, "Memory became executable");
                    }
                }
            } catch (e) {
                log.debug(`读取内存保护错误: ${e.message}`);
            }
        }
    }
    
    // 处理内存API调用
    function handleMemoryCall(context, args, funcName) {
        if (funcName === 'VirtualAlloc') {
            context.vaAddress = args[0];
            context.vaSize = args[1].toInt32();
            context.vaType = args[2].toInt32();
            context.vaProtect = args[3].toInt32();
            
            log.debug(`[*] VirtualAlloc: 大小=${context.vaSize}, 类型=${context.vaType.toString(16)}, 保护=${context.vaProtect.toString(16)}`);
        } else if (funcName === 'NtAllocateVirtualMemory') {
            context.nvaProcessHandle = args[0];
            context.nvaBaseAddressPtr = args[1];
            context.nvaSize = args[3];
            context.nvaType = args[4].toInt32();
            context.nvaProtect = args[5].toInt32();
            
            if (context.nvaBaseAddressPtr) {
                try {
                    context.nvaBaseAddress = Memory.readPointer(context.nvaBaseAddressPtr);
                    log.debug(`[*] NtAllocateVirtualMemory: 地址=${context.nvaBaseAddress}, 保护=${context.nvaProtect.toString(16)}`);
                } catch (e) {
                    // 忽略错误
                }
            }
        } else if (funcName === 'HeapCreate') {
            context.heapOptions = args[0].toInt32();
            context.heapInitialSize = args[1].toInt32();
            context.heapMaximumSize = args[2].toInt32();
            
            // 检查可执行堆（一种可疑行为）
            if (context.heapOptions & 0x00040000) { // HEAP_CREATE_ENABLE_EXECUTE
                log.info(`[!] 创建可执行堆: 初始大小=${context.heapInitialSize}`);
                
                send({
                    type: 'executable_heap',
                    initial_size: context.heapInitialSize,
                    maximum_size: context.heapMaximumSize,
                    timestamp: new Date().getTime()
                });
            }
        } else if (funcName === 'WriteProcessMemory') {
            context.wpmProcessHandle = args[0];
            context.wpmBaseAddress = args[1];
            context.wpmBuffer = args[2];
            context.wpmSize = args[3].toInt32();
            context.wpmBytesWrittenPtr = args[4];
            
            log.debug(`[*] WriteProcessMemory: 地址=${context.wpmBaseAddress}, 大小=${context.wpmSize}`);
        }
    }
    
    // 处理内存API结果
    function handleMemoryResult(context, retval) {
        if (context.funcName === 'VirtualAlloc' && !retval.isNull()) {
            // 获取分配的地址
            const allocatedAddress = retval;
            
            // 记录分配
            memoryAllocs.push({
                timestamp: new Date().getTime(),
                address: allocatedAddress.toString(),
                size: context.vaSize,
                type: context.vaType,
                protection: context.vaProtect
            });
            
            // 如果分配为可执行内存，这可能表示代码注入/自解压
            if (context.vaType & 0x1000 && context.vaProtect & 0x40) { // MEM_COMMIT && PAGE_EXECUTE_READWRITE
                log.info(`[!] 检测到可执行内存分配: ${allocatedAddress}, 大小: ${context.vaSize}`);
                
                send({
                    type: 'executable_allocation',
                    address: allocatedAddress.toString(),
                    size: context.vaSize,
                    protection: context.vaProtect.toString(16),
                    timestamp: new Date().getTime()
                });
                
                // 为可执行内存设置内存访问监视点
                try {
                    MemoryAccessMonitor.enable({
                        base: allocatedAddress, 
                        size: context.vaSize
                    }, {
                        onAccess: function(details) {
                            if (details.operation === 'write') {
                                log.info(`[+] 写入可执行内存: ${details.from} -> ${details.address}`);
                                
                                // 内存转储
                                dumpMemory(allocatedAddress, context.vaSize, "Write to executable memory");
                                
                                send({
                                    type: 'memory_write_exec',
                                    source: details.from.toString(),
                                    target: details.address.toString(),
                                    size: context.vaSize,
                                    timestamp: new Date().getTime()
                                });
                            }
                        }
                    });
                } catch (e) {
                    log.warn(`无法监视内存: ${e.message}`);
                }
            }
        } else if (context.funcName === 'NtAllocateVirtualMemory' && retval.toInt32() === 0) { // 0是成功
            // 获取分配的地址
            if (context.nvaBaseAddressPtr) {
                try {
                    const allocatedAddress = Memory.readPointer(context.nvaBaseAddressPtr);
                    if (!allocatedAddress.isNull()) {
                        // 读取实际写入的大小
                        const allocatedSize = Memory.readUInt(context.nvaSize);
                        
                        // 记录分配
                        memoryAllocs.push({
                            timestamp: new Date().getTime(),
                            address: allocatedAddress.toString(),
                            size: allocatedSize,
                            type: context.nvaType,
                            protection: context.nvaProtect
                        });
                        
                        // 检查可执行内存
                        if (context.nvaProtect & 0x40) { // PAGE_EXECUTE_READWRITE
                            log.info(`[!] 通过NT API分配可执行内存: ${allocatedAddress}, 大小: ${allocatedSize}`);
                            
                            send({
                                type: 'executable_allocation',
                                address: allocatedAddress.toString(),
                                size: allocatedSize,
                                protection: context.nvaProtect.toString(16),
                                api: 'NtAllocateVirtualMemory',
                                timestamp: new Date().getTime()
                            });
                        }
                    }
                } catch (e) {
                    log.debug(`读取分配地址错误: ${e.message}`);
                }
            }
        } else if (context.funcName === 'HeapCreate' && !retval.isNull()) {
            const heapHandle = retval;
            log.debug(`[*] 堆创建成功: ${heapHandle}`);
            
            if (context.heapOptions & 0x00040000) { // HEAP_CREATE_ENABLE_EXECUTE
                send({
                    type: 'executable_heap_created',
                    handle: heapHandle.toString(),
                    initial_size: context.heapInitialSize,
                    maximum_size: context.heapMaximumSize,
                    timestamp: new Date().getTime()
                });
            }
        } else if (context.funcName === 'WriteProcessMemory' && retval.toInt32() !== 0) {
            // 成功写入
            let bytesWritten = context.wpmSize; // 默认为请求的大小
            
            // 尝试获取实际写入的字节数
            if (context.wpmBytesWrittenPtr) {
                try {
                    bytesWritten = Memory.readUInt(context.wpmBytesWrittenPtr);
                } catch (e) {
                    // 忽略错误
                }
            }
            
            if (bytesWritten > 0) {
                log.info(`[+] 写入进程内存: ${context.wpmBaseAddress}, 大小: ${bytesWritten}`);
                
                // 如果是写入当前进程，获取数据
                if (context.wpmProcessHandle.toInt32() === -1) { // -1 = 当前进程
                    try {
                        if (bytesWritten <= 1048576) { // 限制1MB
                            const transferredData = Memory.readByteArray(context.wpmBuffer, bytesWritten);
                            
                            send({
                                type: 'memory_write',
                                address: context.wpmBaseAddress.toString(),
                                size: bytesWritten,
                                timestamp: new Date().getTime()
                            }, transferredData);
                        } else {
                            // 如果数据太大，只发送元数据
                            send({
                                type: 'memory_write',
                                address: context.wpmBaseAddress.toString(),
                                size: bytesWritten,
                                data_too_large: true,
                                timestamp: new Date().getTime()
                            });
                        }
                    } catch (e) {
                        log.warn(`读取写入数据错误: ${e.message}`);
                    }
                }
            }
        }
    }
    
    // 拦截GetProcAddress - 查找动态解析
    try {
        Interceptor.attach(Module.findExportByName('kernel32.dll', 'GetProcAddress'), {
            onEnter: function (args) {
                this.module = args[0];
                this.functionName = args[1];
                if (this.functionName.toInt32() < 0x10000) {
                    this.functionNameValue = "Ordinal#" + this.functionName.toInt32();
                } else {
                    this.functionNameValue = Memory.readUtf8String(this.functionName);
                }
                
                // 尝试获取模块名称
                try {
                    const moduleBase = this.module;
                    const moduleInfo = Process.findModuleByAddress(moduleBase);
                    if (moduleInfo) {
                        this.moduleName = moduleInfo.name;
                    } else {
                        this.moduleName = "UnknownModule";
                    }
                } catch (e) {
                    this.moduleName = "ErrorModule";
                }
            },
            onLeave: function (retval) {
                if (retval.toInt32() !== 0) {
                    log.debug(`[+] GetProcAddress: ${this.moduleName}!${this.functionNameValue} = ${retval}`);
                    
                    // 如果是敏感API，记录解析
                    const sensitiveFunctions = [
                        'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'CreateFile', 
                        'connect', 'send', 'recv', 'VirtualProtect', 'CryptEncrypt', 'CryptDecrypt',
                        'CreateProcess', 'CreateThread', 'LoadLibrary', 'GetModuleHandle'
                    ];
                    
                    if (sensitiveFunctions.includes(this.functionNameValue) || 
                        this.functionNameValue.includes('Nt') || 
                        this.functionNameValue.includes('Crypt')) {
                        
                        log.info(`[!] 动态解析敏感API: ${this.moduleName}!${this.functionNameValue}`);
                        
                        send({
                            type: 'dynamic_api_resolution',
                            module: this.moduleName,
                            function: this.functionNameValue,
                            address: retval.toString(),
                            timestamp: new Date().getTime()
                        });
                    }
                }
            }
        });
    } catch (e) {
        log.warn(`GetProcAddress挂钩错误: ${e.message}`);
    }
    
    // 执行初始配置和扫描
    function initialize() {
        try {
            log.info("动态分析引擎已启动");
            
            // 收集系统和模块信息
            collectSystemInfo();
            
            // 扫描用户模块
            scanUserModules();
            
            // 挂钩关键API
            hookSpecifiedAPIs();
            
            // 延迟一秒后扫描内存保护特征
            setTimeout(scanMemoryRegionsForSignatures, 1000);
            
            // 设置周期性状态报告
            setInterval(function() {
                send({
                    type: 'status_update',
                    anti_debug_attempts: antiDebugAttempts,
                    network_activity: networkData.length,
                    file_activity: fileData.length,
                    registry_activity: registryData.length,
                    thread_creations: threadCreations.length,
                    memory_allocations: memoryAllocs.length,
                    total_api_calls: apiCalls.length,
                    protections: {
                        vmprotect_detections: protectionDetections.vmprotect.length,
                        themida_detections: protectionDetections.themida.length,
                        custom_detections: protectionDetections.custom.length
                    },
                    timestamp: new Date().getTime()
                });
            }, 5000);
            
            log.info("初始化完成，开始监视");
        } catch (e) {
            log.error(`初始化错误: ${e.message}\n${e.stack}`);
        }
    }
    
    // 执行初始化
    initialize();
})();
"""

class DynamicAnalyzer:
    """
    动态分析引擎，用于恶意软件和壳保护程序的动态分析
    具有内存转储、API跟踪和反调试绕过功能
    """
    
    def __init__(self, target_path: str = None, output_dir: str = None, api_port: int = 5000):
        """
        初始化动态分析引擎
        
        Args:
            target_path: 要分析的目标可执行文件路径
            output_dir: 输出结果的目录
            api_port: API服务器端口号
        """
        self.target_path = os.path.abspath(target_path) if target_path else None
        
        # 验证目标文件
        if self.target_path and not os.path.exists(self.target_path):
            raise FileNotFoundError(f"目标文件不存在: {self.target_path}")
        
        # 设置输出目录
        self.output_dir = output_dir or os.path.join(
            os.getcwd(), 
            "analysis_results",
            f"analysis_{int(time.time())}"
        )
        
        # 创建输出目录结构
        self._create_output_directories()
        
        # Frida 会话变量
        self.process = None
        self.session = None
        self.script = None
        self.pid = None
        self.attached = False
        
        # 分析数据存储
        self.memory_dumps = []
        self.network_data = []
        self.file_data = []
        self.registry_data = []
        self.api_calls = []
        self.protection_data = {
            "anti_debug_attempts": 0,
            "network_connections": 0,
            "file_accesses": 0,
            "registry_accesses": 0,
            "thread_creations": 0,
            "memory_allocations": 0,
            "protection_detections": {
                "vmprotect": 0,
                "themida": 0,
                "custom": 0
            }
        }
        
        # API服务器配置
        self.api_server = None
        self.api_thread = None
        self.api_port = api_port
        
        # 实时状态跟踪
        self.running = False
        self.analysis_start_time = None
        self.last_status_update = None
        
        # 设置结果文件路径
        self.log_file = os.path.join(self.output_dir, "dynamic_analysis.log")
        self.report_file = os.path.join(self.output_dir, "analysis_report.html")
        self.json_report_file = os.path.join(self.output_dir, "analysis_report.json")
        
        # 配置文件日志处理程序
        file_handler = logging.FileHandler(self.log_file)
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logger.addHandler(file_handler)
        
        # 自动停止定时器
        self.timeout_timer = None
    
    def _create_output_directories(self) -> None:
        """创建输出目录结构"""
        # 主目录
        os.makedirs(self.output_dir, exist_ok=True)
        
        # 分析类型子目录
        subdirs = [
            "memory_dumps",    # 内存转储
            "network_data",    # 网络通信数据
            "crypto",          # 加密/解密数据
            "file_data",       # 文件访问数据
            "registry_data",   # 注册表访问数据
            "screenshots"      # 分析过程截图
        ]
        
        for subdir in subdirs:
            os.makedirs(os.path.join(self.output_dir, subdir), exist_ok=True)
    
    def _create_api_server(self) -> None:
        """创建REST API服务器以支持远程控制"""
        app = Flask(__name__)
        
        # 禁用Flask的生产警告
        app.logger.disabled = True
        log = logging.getLogger('werkzeug')
        log.disabled = True
        
        # 为API启用CORS
        @app.after_request
        def add_cors_headers(response):
            response.headers['Access-Control-Allow-Origin'] = '*'
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
            return response
        
        # 状态端点
        @app.route('/api/status', methods=['GET'])
        def status():
            if self.running:
                status_data = {
                    "status": "running" if self.running else "not_running",
                    "pid": self.pid,
                    "uptime": time.time() - self.analysis_start_time if self.analysis_start_time else 0,
                    "memory_dumps": len(self.memory_dumps),
                    "network_captures": len(self.network_data),
                    "file_operations": len(self.file_data),
                    "registry_operations": len(self.registry_data),
                    "protection_stats": self.protection_data,
                    "last_update": self.last_status_update
                }
                return jsonify(status_data)
            return jsonify({"status": "not_running"})
        
        # 内存补丁端点
        @app.route('/api/patch', methods=['POST'])
        def apply_patch():
            if not self.running or not self.session:
                return jsonify({"error": "无活动会话"}), 400
                
            data = request.json
            if not data or not data.get('address') or not data.get('bytes'):
                return jsonify({"error": "缺少地址或字节数据"}), 400
                
            try:
                address = int(data['address'], 16) if isinstance(data['address'], str) else data['address']
                bytes_data = bytes.fromhex(data['bytes']) if isinstance(data['bytes'], str) else bytes(data['bytes'])
                
                # 使用Frida写入内存
                result = self._apply_memory_patch(address, bytes_data)
                return jsonify({"result": result})
            except Exception as e:
                logger.error(f"补丁错误: {str(e)}")
                return jsonify({"error": str(e)}), 500
        
        # 内存转储端点
        @app.route('/api/dump', methods=['POST'])
        def dump_memory():
            if not self.running or not self.session:
                return jsonify({"error": "无活动会话"}), 400
                
            data = request.json
            if not data or not data.get('address') or not data.get('size'):
                return jsonify({"error": "缺少地址或大小"}), 400
                
            try:
                address = int(data['address'], 16) if isinstance(data['address'], str) else data['address']
                size = int(data['size'])
                
                # 使用Frida读取内存
                dump_path = self._dump_memory_region(address, size)
                if dump_path:
                    return jsonify({"result": "success", "path": dump_path})
                return jsonify({"error": "内存转储失败"}), 500
            except Exception as e:
                logger.error(f"内存转储错误: {str(e)}")
                return jsonify({"error": str(e)}), 500
        
        # 代码注入端点
        @app.route('/api/inject', methods=['POST'])
        def inject_code():
            if not self.running or not self.session:
                return jsonify({"error": "无活动会话"}), 400
                
            data = request.json
            if not data or not data.get('code'):
                return jsonify({"error": "缺少JavaScript代码"}), 400
                
            try:
                # 注入自定义Frida脚本
                result = self._inject_custom_script(data['code'])
                return jsonify({"result": result})
            except Exception as e:
                logger.error(f"代码注入错误: {str(e)}")
                return jsonify({"error": str(e)}), 500
        
        # 获取内存转储列表
        @app.route('/api/dumps', methods=['GET'])
        def get_dumps():
            return jsonify({"dumps": self.memory_dumps})
        
        # 下载内存转储
        @app.route('/api/dumps/<path:dump_path>', methods=['GET'])
        def download_dump(dump_path):
            # 安全检查，防止路径遍历漏洞
            safe_path = os.path.normpath(os.path.join(self.output_dir, "memory_dumps", os.path.basename(dump_path)))
            if os.path.exists(safe_path) and os.path.isfile(safe_path):
                return send_file(safe_path, as_attachment=True)
            return jsonify({"error": "文件不存在"}), 404
        
        # 停止分析
        @app.route('/api/stop', methods=['POST'])
        def stop_analysis():
            if self.running:
                self.stop_analysis()
                return jsonify({"status": "stopped"})
            return jsonify({"status": "not_running"})
        
        # 获取分析报告
        @app.route('/api/report', methods=['GET'])
        def get_report():
            report_format = request.args.get('format', 'json')
            
            if report_format == 'html' and os.path.exists(self.report_file):
                return send_file(self.report_file)
            elif report_format == 'json' and os.path.exists(self.json_report_file):
                return send_file(self.json_report_file)
            elif self.running:
                # 如果分析正在运行，生成临时报告
                self._generate_interim_report()
                if report_format == 'html' and os.path.exists(self.report_file):
                    return send_file(self.report_file)
                else:
                    return jsonify(self._generate_report_data())
            else:
                return jsonify({"error": "报告不可用"}), 404
        
        self.api_server = app
    
    def _start_api_server(self) -> None:
        """在单独的线程中启动API服务器"""
        if self.api_thread and self.api_thread.is_alive():
            logger.info("API服务器已在运行")
            return
            
        def run_api():
            try:
                self.api_server.run(host='0.0.0.0', port=self.api_port, debug=False, use_reloader=False)
            except Exception as e:
                logger.error(f"API服务器错误: {str(e)}")
            
        self.api_thread = threading.Thread(target=run_api)
        self.api_thread.daemon = True
        self.api_thread.start()
        logger.info(f"API服务器已启动在端口 {self.api_port}")
    
    def _on_message(self, message: Dict[str, Any], data: Optional[bytes]) -> None:
        """
        处理来自Frida脚本的消息
        
        Args:
            message: 消息字典
            data: 可选的二进制数据
        """
        try:
            if message['type'] == 'send':
                payload = message['payload']
                msg_type = payload.get('type', 'unknown')
                
                # 更新最后状态更新时间
                self.last_status_update = time.time()
                
                # 根据消息类型处理不同的分析数据
                if msg_type == 'memory_dump':
                    self._handle_memory_dump(payload, data)
                elif msg_type in ['network_connect', 'network_send', 'network_recv', 'network_send_data', 'http_request']:
                    self._handle_network_data(msg_type, payload, data)
                elif msg_type in ['protection_detected', 'anti_debug_attempt']:
                    self._handle_protection_detection(msg_type, payload)
                elif msg_type in ['file_access', 'file_read', 'file_write', 'file_opened']:
                    self._handle_file_data(msg_type, payload, data)
                elif msg_type in ['registry_access', 'registry_data']:
                    self._handle_registry_data(msg_type, payload, data)
                elif msg_type in ['crypto_encrypt', 'crypto_decrypt']:
                    self._handle_crypto_data(msg_type, payload, data)
                elif msg_type in ['thread_created', 'thread_execution']:
                    self._handle_thread_data(msg_type, payload)
                elif msg_type in ['executable_allocation', 'memory_protection_change', 'memory_write', 'memory_write_exec']:
                    self._handle_memory_operation(msg_type, payload, data)
                elif msg_type == 'status_update':
                    self._handle_status_update(payload)
                elif msg_type == 'system_info':
                    self._handle_system_info(payload)
                else:
                    logger.debug(f"未处理的消息类型: {msg_type}")
                
            elif message['type'] == 'error':
                logger.error(f"Frida错误: {message.get('description', 'Unknown')}")
                if 'stack' in message:
                    logger.error(f"错误堆栈: {message['stack']}")
        except Exception as e:
            logger.error(f"处理消息错误: {str(e)}")
            logger.error(traceback.format_exc())
    
    def _handle_memory_dump(self, payload: Dict[str, Any], data: Optional[bytes]) -> None:
        """
        处理内存转储数据
        
        Args:
            payload: 消息载荷
            data: 二进制数据
        """
        if not data:
            logger.warning("内存转储没有数据")
            return
            
        # 生成转储文件名
        address = payload.get('address', 'unknown')
        size = payload.get('size', len(data))
        info = payload.get('info', '')
        
        safe_info = ''.join(c for c in info if c.isalnum() or c in '._- ')[:50]
        dump_filename = f"dump_{address}_{size}_{int(time.time())}_{safe_info}.bin"
        dump_path = os.path.join(self.output_dir, "memory_dumps", dump_filename)
        
        # 保存转储数据
        with open(dump_path, 'wb') as f:
            f.write(data)
        
        # 记录转储信息
        dump_info = {
            'path': dump_path,
            'address': address,
            'size': size,
            'timestamp': time.time(),
            'info': info,
            'md5': hashlib.md5(data).hexdigest()
        }
        
        self.memory_dumps.append(dump_info)
        logger.info(f"内存转储已保存: {dump_path} (大小: {len(data)})")
    
    def _handle_network_data(self, msg_type: str, payload: Dict[str, Any], data: Optional[bytes]) -> None:
        """
        处理网络数据
        
        Args:
            msg_type: 消息类型
            payload: 消息载荷
            data: 可选的二进制数据
        """
        network_entry = {
            'type': msg_type,
            'timestamp': payload.get('timestamp', time.time()),
            'data_size': 0
        }
        
        # 根据消息类型处理不同的网络事件
        if msg_type == 'network_connect':
            network_entry['address'] = payload.get('address', 'unknown')
            network_entry['port'] = payload.get('port', 0)
            logger.info(f"网络连接: {network_entry['address']}:{network_entry['port']}")
            
        elif msg_type == 'http_request':
            network_entry['url'] = payload.get('url', 'unknown')
            logger.info(f"HTTP请求: {network_entry['url']}")
            
        elif msg_type in ['network_send', 'network_recv', 'network_send_data']:
            network_entry['socket'] = payload.get('socket', 'unknown')
            network_entry['length'] = payload.get('length', 0)
            
            if data:
                network_entry['data_size'] = len(data)
                
                # 保存数据到文件
                direction = 'sent' if 'send' in msg_type else 'received'
                data_filename = f"network_{direction}_{int(time.time())}_{network_entry['socket']}.bin"
                data_path = os.path.join(self.output_dir, "network_data", data_filename)
                
                with open(data_path, 'wb') as f:
                    f.write(data)
                    
                network_entry['data_path'] = data_path
                network_entry['data_md5'] = hashlib.md5(data).hexdigest()
                
                # 尝试检测数据类型
                content_type = self._detect_content_type(data)
                if content_type:
                    network_entry['content_type'] = content_type
                
                logger.info(f"网络数据 {direction}: {network_entry['length']} 字节")
        
        self.network_data.append(network_entry)
        self.protection_data['network_connections'] = len(self.network_data)
    
    def _handle_protection_detection(self, msg_type: str, payload: Dict[str, Any]) -> None:
        """
        处理保护检测事件
        
        Args:
            msg_type: 消息类型
            payload: 消息载荷
        """
        if msg_type == 'protection_detected':
            protection_type = payload.get('protection_type', 'unknown')
            info = payload.get('info', {})
            
            logger.info(f"检测到保护: {protection_type} - {info.get('name', 'unknown')} @ {info.get('address', 'unknown')}")
            
            # 更新保护检测计数
            if protection_type in self.protection_data['protection_detections']:
                self.protection_data['protection_detections'][protection_type] += 1
            
        elif msg_type == 'anti_debug_attempt':
            function_name = payload.get('function', 'unknown')
            
            logger.info(f"检测到反调试尝试: {function_name}")
            self.protection_data['anti_debug_attempts'] += 1
    
    def _handle_file_data(self, msg_type: str, payload: Dict[str, Any], data: Optional[bytes]) -> None:
        """
        处理文件操作数据
        
        Args:
            msg_type: 消息类型
            payload: 消息载荷
            data: 可选的二进制数据
        """
        file_entry = {
            'type': msg_type,
            'timestamp': payload.get('timestamp', time.time())
        }
        
        if msg_type == 'file_access':
            file_entry['operation'] = payload.get('operation', 'unknown')
            file_entry['path'] = payload.get('path', 'unknown')
            
            if 'access' in payload:
                file_entry['access'] = payload['access']
                
            logger.info(f"文件{file_entry['operation']}: {file_entry['path']}")
            
        elif msg_type in ['file_read', 'file_write']:
            file_entry['handle'] = payload.get('handle', 'unknown')
            file_entry['length'] = payload.get('length', 0)
            
            if data:
                # 保存数据到文件
                operation = 'read' if msg_type == 'file_read' else 'write'
                data_filename = f"file_{operation}_{int(time.time())}_{file_entry['handle']}.bin"
                data_path = os.path.join(self.output_dir, "file_data", data_filename)
                
                with open(data_path, 'wb') as f:
                    f.write(data)
                    
                file_entry['data_path'] = data_path
                file_entry['data_size'] = len(data)
                file_entry['data_md5'] = hashlib.md5(data).hexdigest()
                
                # 尝试检测数据类型
                content_type = self._detect_content_type(data)
                if content_type:
                    file_entry['content_type'] = content_type
                
                logger.info(f"文件{operation}: {file_entry['length']} 字节")
                
        elif msg_type == 'file_opened':
            file_entry['path'] = payload.get('path', 'unknown')
            file_entry['handle'] = payload.get('handle', 'unknown')
            
            logger.info(f"文件已打开: {file_entry['path']} -> {file_entry['handle']}")
        
        self.file_data.append(file_entry)
        self.protection_data['file_accesses'] = len(self.file_data)
    
    def _handle_registry_data(self, msg_type: str, payload: Dict[str, Any], data: Optional[bytes]) -> None:
        """
        处理注册表操作数据
        
        Args:
            msg_type: 消息类型
            payload: 消息载荷
            data: 可选的二进制数据
        """
        registry_entry = {
            'type': msg_type,
            'timestamp': payload.get('timestamp', time.time())
        }
        
        if msg_type == 'registry_access':
            registry_entry['operation'] = payload.get('operation', 'unknown')
            
            if 'key' in payload:
                registry_entry['key'] = payload['key']
                logger.info(f"注册表{registry_entry['operation']}: {registry_entry['key']}")
                
            elif 'value' in payload:
                registry_entry['value'] = payload['value']
                if 'data_type' in payload:
                    registry_entry['data_type'] = payload['data_type']
                logger.info(f"注册表{registry_entry['operation']}: {registry_entry['value']}")
                
        elif msg_type == 'registry_data':
            registry_entry['value'] = payload.get('value', 'unknown')
            registry_entry['size'] = payload.get('size', 0)
            
            if data:
                # 保存数据到文件
                data_filename = f"registry_{int(time.time())}_{registry_entry['value']}.bin"
                data_path = os.path.join(self.output_dir, "registry_data", data_filename)
                
                with open(data_path, 'wb') as f:
                    f.write(data)
                    
                registry_entry['data_path'] = data_path
                registry_entry['data_size'] = len(data)
                
                logger.info(f"注册表数据: {registry_entry['value']} ({registry_entry['size']} 字节)")
        
        self.registry_data.append(registry_entry)
        self.protection_data['registry_accesses'] = len(self.registry_data)
    
    def _handle_crypto_data(self, msg_type: str, payload: Dict[str, Any], data: Optional[bytes]) -> None:
        """
        处理加密/解密数据
        
        Args:
            msg_type: 消息类型
            payload: 消息载荷
            data: 二进制数据
        """
        if not data:
            return
            
        # 确定操作类型
        operation = "加密" if msg_type == 'crypto_encrypt' else "解密"
        
        # 保存加密/解密数据
        data_filename = f"{operation}_{int(time.time())}_{payload.get('data_length', len(data))}.bin"
        data_path = os.path.join(self.output_dir, "crypto", data_filename)
        
        with open(data_path, 'wb') as f:
            f.write(data)
            
        logger.info(f"{operation}数据: {payload.get('data_length', len(data))} 字节, 已保存到 {data_path}")
    
    def _handle_thread_data(self, msg_type: str, payload: Dict[str, Any]) -> None:
        """
        处理线程操作数据
        
        Args:
            msg_type: 消息类型
            payload: 消息载荷
        """
        if msg_type == 'thread_created':
            thread_info = {
                'timestamp': payload.get('timestamp', time.time()),
                'thread_id': payload.get('thread_id', 0),
                'start_address': payload.get('start_address', 'unknown'),
                'parameter': payload.get('parameter', 'null')
            }
            
            logger.info(f"创建线程: ID={thread_info['thread_id']}, 地址={thread_info['start_address']}")
            self.protection_data['thread_creations'] += 1
            
        elif msg_type == 'thread_execution':
            # 线程执行跟踪通常量很大，这里只记录日志
            thread_id = payload.get('thread_id', 0)
            total_calls = payload.get('total_calls', 0)
            logger.debug(f"线程执行: ID={thread_id}, 调用数={total_calls}")
    
    def _handle_memory_operation(self, msg_type: str, payload: Dict[str, Any], data: Optional[bytes]) -> None:
        """
        处理内存操作数据
        
        Args:
            msg_type: 消息类型
            payload: 消息载荷
            data: 可选的二进制数据
        """
        if msg_type == 'executable_allocation':
            address = payload.get('address', 'unknown')
            size = payload.get('size', 0)
            protection = payload.get('protection', 'unknown')
            
            logger.info(f"分配可执行内存: {address}, 大小: {size}, 保护: {protection}")
            self.protection_data['memory_allocations'] += 1
            
        elif msg_type == 'memory_protection_change':
            address = payload.get('address', 'unknown')
            size = payload.get('size', 0)
            new_protection = payload.get('new_protection', 0)
            
            logger.info(f"内存保护变更: {address}, 大小: {size}, 新保护: {new_protection}")
            
        elif msg_type == 'memory_write_exec':
            source = payload.get('source', 'unknown')
            target = payload.get('target', 'unknown')
            size = payload.get('size', 0)
            
            logger.info(f"写入可执行内存: {source} -> {target}, 大小: {size}")
            
        elif msg_type == 'memory_write':
            address = payload.get('address', 'unknown')
            size = payload.get('size', 0)
            
            logger.info(f"写入内存: {address}, 大小: {size}")
            
            # 如果有数据且未标记为过大，保存它
            if data and not payload.get('data_too_large', False):
                data_filename = f"memory_write_{int(time.time())}_{address}.bin"
                data_path = os.path.join(self.output_dir, "memory_dumps", data_filename)
                
                with open(data_path, 'wb') as f:
                    f.write(data)
                
                logger.debug(f"内存写入数据已保存: {data_path}")
    
    def _handle_status_update(self, payload: Dict[str, Any]) -> None:
        """
        处理状态更新
        
        Args:
            payload: 状态数据
        """
        # 更新保护数据统计
        self.protection_data.update({
            'anti_debug_attempts': payload.get('anti_debug_attempts', 0),
            'network_connections': payload.get('network_activity', 0),
            'file_accesses': payload.get('file_activity', 0),
            'registry_accesses': payload.get('registry_activity', 0),
            'thread_creations': payload.get('thread_creations', 0),
            'memory_allocations': payload.get('memory_allocations', 0)
        })
        
        # 更新保护检测
        if 'protections' in payload:
            protections = payload['protections']
            self.protection_data['protection_detections'].update({
                'vmprotect': protections.get('vmprotect_detections', 0),
                'themida': protections.get('themida_detections', 0),
                'custom': protections.get('custom_detections', 0)
            })
    
    def _handle_system_info(self, payload: Dict[str, Any]) -> None:
        """
        处理系统信息
        
        Args:
            payload: 系统信息数据
        """
        info = payload.get('info', {})
        
        # 保存系统信息以用于报告
        self.system_info = info
        
        # 记录主要信息
        if 'mainModule' in info:
            main_module = info['mainModule']
            logger.info(f"主模块: {main_module.get('name', 'unknown')} @ {main_module.get('base', 'unknown')}")
            
        logger.info(f"架构: {info.get('arch', 'unknown')}, 平台: {info.get('platform', 'unknown')}")
        logger.info(f"已加载 {len(info.get('modules', []))} 个模块")
    
    def _detect_content_type(self, data: bytes) -> Optional[str]:
        """
        尝试检测二进制数据的内容类型
        
        Args:
            data: 二进制数据
            
        Returns:
            检测到的内容类型或None
        """
        # 检查常见文件头
        if data.startswith(b'MZ'):
            return 'PE Executable'
        elif data.startswith(b'%PDF'):
            return 'PDF Document'
        elif data.startswith(b'PK\x03\x04'):
            return 'ZIP Archive'
        elif data.startswith(b'\xff\xd8\xff'):
            return 'JPEG Image'
        elif data.startswith(b'\x89PNG\r\n\x1a\n'):
            return 'PNG Image'
        elif data.startswith(b'GIF8'):
            return 'GIF Image'
            
        # 检查是否是文本数据
        try:
            text_sample = data[:100].decode('utf-8')
            if all(c.isprintable() or c.isspace() for c in text_sample):
                # 进一步检查是否是JSON
                if (data.strip().startswith(b'{') and data.strip().endswith(b'}')) or \
                   (data.strip().startswith(b'[') and data.strip().endswith(b']')):
                    try:
                        json.loads(data)
                        return 'JSON Data'
                    except:
                        pass
                # 检查是否是HTML
                if b'<html' in data.lower() or b'<!doctype html' in data.lower():
                    return 'HTML Document'
                # 检查是否是XML
                if data.strip().startswith(b'<?xml'):
                    return 'XML Document'
                    
                return 'Text Data'
        except:
            pass
            
        # 默认为二进制数据
        return 'Binary Data'
    
    def _apply_memory_patch(self, address: int, bytes_data: bytes) -> str:
        """
        应用内存补丁
        
        Args:
            address: 内存地址
            bytes_data: 要写入的字节
            
        Returns:
            操作结果描述
        """
        if not self.session:
            return "无活动会话"
            
        try:
            patch_script = f"""
            (function() {{
                try {{
                    const address = ptr("{address:#x}");
                    Memory.writeByteArray(address, {list(bytes_data)});
                    console.log("[+] 已写入 {len(bytes_data)} 字节到 {address:#x}");
                    return true;
                }} catch (e) {{
                    console.log("[!] 补丁错误: " + e);
                    return false;
                }}
            }})();
            """
            
            temp_script = self.session.create_script(patch_script)
            temp_script.load()
            
            # 记录补丁操作
            logger.info(f"已应用内存补丁: {address:#x} ({len(bytes_data)} 字节)")
            
            return f"成功写入 {len(bytes_data)} 字节到 {address:#x}"
        except Exception as e:
            logger.error(f"内存补丁错误: {str(e)}")
            return f"错误: {str(e)}"
    
    def _dump_memory_region(self, address: int, size: int) -> Optional[str]:
        """
        转储内存区域
        
        Args:
            address: 内存地址
            size: 要转储的大小
            
        Returns:
            转储文件路径或None
        """
        if not self.session:
            return None
            
        try:
            dump_script = f"""
            (function() {{
                try {{
                    const address = ptr("{address:#x}");
                    const size = {size};
                    const data = Memory.readByteArray(address, size);
                    send(data, data);
                    return true;
                }} catch (e) {{
                    console.log("[!] 转储错误: " + e);
                    return false;
                }}
            }})();
            """
            
            # 使用临时脚本获取内存内容
            received_data = None
            def on_dump_message(message, data):
                nonlocal received_data
                if message['type'] == 'send' and data:
                    received_data = data
            
            temp_script = self.session.create_script(dump_script)
            temp_script.on('message', on_dump_message)
            temp_script.load()
            
            if received_data:
                # 生成文件名并保存转储
                dump_filename = f"manual_dump_{address:#x}_{size}_{int(time.time())}.bin"
                dump_path = os.path.join(self.output_dir, "memory_dumps", dump_filename)
                
                with open(dump_path, 'wb') as f:
                    f.write(received_data)
                
                # 记录转储信息
                dump_info = {
                    'path': dump_path,
                    'address': f"{address:#x}",
                    'size': size,
                    'timestamp': time.time(),
                    'method': 'manual',
                    'md5': hashlib.md5(received_data).hexdigest()
                }
                
                self.memory_dumps.append(dump_info)
                logger.info(f"手动内存转储已保存: {dump_path} (大小: {len(received_data)})")
                
                return dump_path
            
            logger.warning("内存转储没有返回数据")
            return None
        except Exception as e:
            logger.error(f"内存转储错误: {str(e)}")
            return None
    
    def _inject_custom_script(self, code: str) -> str:
        """
        注入自定义Frida脚本
        
        Args:
            code: 要注入的JavaScript代码
            
        Returns:
            操作结果描述
        """
        if not self.session:
            return "无活动会话"
            
        try:
            # 添加适当的包装，以确保代码被立即调用
            wrapped_code = f"""
            (function() {{
                try {{
                    {code}
                }} catch (e) {{
                    console.log("[!] 自定义脚本错误: " + e);
                    console.log(e.stack);
                }}
            }})();
            """
            
            temp_script = self.session.create_script(wrapped_code)
            temp_script.on('message', self._on_message)
            temp_script.load()
            
            logger.info("已注入自定义脚本")
            return "脚本注入成功"
        except Exception as e:
            logger.error(f"脚本注入错误: {str(e)}")
            return f"错误: {str(e)}"
    
    def start_analysis(self, timeout: Optional[int] = None) -> bool:
        """
        启动动态分析
        
        Args:
            timeout: 分析超时时间（秒）
            
        Returns:
            是否成功启动
        """
        try:
            if not self.target_path:
                logger.error("未指定目标文件")
                return False
                
            logger.info(f"启动分析目标: {self.target_path}")
            
            # 创建并启动API服务器
            self._create_api_server()
            self._start_api_server()
            
            # 启动目标程序
            self.process = frida.spawn(self.target_path)
            self.pid = self.process
            logger.info(f"目标已启动, PID: {self.pid}")
            
            # 附加到进程
            self.session = frida.attach(self.pid)
            self.attached = True
            
            # 创建脚本
            self.script = self.session.create_script(FRIDA_SCRIPT)
            self.script.on('message', self._on_message)
            self.script.load()
            
            # 设置分析状态
            self.running = True
            self.analysis_start_time = time.time()
            
            # 恢复进程执行
            frida.resume(self.pid)
            logger.info("目标已恢复执行, 分析进行中...")
            
            # 设置超时定时器
            if timeout:
                logger.info(f"设置分析超时: {timeout} 秒")
                self.timeout_timer = threading.Timer(timeout, self.stop_analysis)
                self.timeout_timer.daemon = True
                self.timeout_timer.start()
            
            return True
        except Exception as e:
            logger.error(f"启动分析错误: {str(e)}")
            logger.error(traceback.format_exc())
            self.cleanup()
            return False
    
    def attach_to_process(self, pid: int, timeout: Optional[int] = None) -> bool:
        """
        附加到现有进程
        
        Args:
            pid: 进程ID
            timeout: 分析超时时间（秒）
            
        Returns:
            是否成功附加
        """
        try:
            logger.info(f"附加到进程: {pid}")
            self.pid = pid
            
            # 创建并启动API服务器
            self._create_api_server()
            self._start_api_server()
            
            # 附加到进程
            self.session = frida.attach(self.pid)
            self.attached = True
            
            # 创建脚本
            self.script = self.session.create_script(FRIDA_SCRIPT)
            self.script.on('message', self._on_message)
            self.script.load()
            
            # 设置分析状态
            self.running = True
            self.analysis_start_time = time.time()
            
            logger.info(f"成功附加到进程 {pid}, 分析进行中...")
            
            # 设置超时定时器
            if timeout:
                logger.info(f"设置分析超时: {timeout} 秒")
                self.timeout_timer = threading.Timer(timeout, self.stop_analysis)
                self.timeout_timer.daemon = True
                self.timeout_timer.start()
            
            return True
        except Exception as e:
            logger.error(f"附加到进程错误: {str(e)}")
            logger.error(traceback.format_exc())
            self.cleanup()
            return False
    
    def wait_for_completion(self, timeout: Optional[int] = None) -> None:
        """
        等待分析完成或直到超时
        
        Args:
            timeout: 等待超时时间（秒）
        """
        try:
            if timeout:
                logger.info(f"等待最长 {timeout} 秒...")
                end_time = time.time() + timeout
                while self.running and time.time() < end_time:
                    time.sleep(1)
                
                if self.running:
                    logger.info("等待超时，停止分析...")
                    self.stop_analysis()
            else:
                logger.info("按Ctrl+C停止分析...")
                while self.running:
                    time.sleep(1)
        except KeyboardInterrupt:
            logger.info("用户中断分析.")
        finally:
            self.stop_analysis()
    
    def stop_analysis(self) -> None:
        """停止分析并清理资源"""
        if not self.running:
            return
            
        logger.info("停止分析...")
        
        # 取消超时定时器
        if self.timeout_timer:
            self.timeout_timer.cancel()
            self.timeout_timer = None
        
        # 清理Frida资源
        self.cleanup()
        
        # 生成分析报告
        self.generate_report()
        
        # 设置状态
        self.running = False
        logger.info("分析已停止")
    
    def cleanup(self) -> None:
        """清理资源"""
        try:
            if self.script:
                self.script.unload()
                self.script = None
                
            if self.session:
                self.session.detach()
                self.session = None
                
            if self.pid and not self.attached:
                # 仅当我们生成了进程时才尝试终止它
                try:
                    os.kill(self.pid, signal.SIGTERM)
                except:
                    pass
                self.pid = None
            
            self.attached = False
            logger.info("资源已清理")
        except Exception as e:
            logger.error(f"清理错误: {str(e)}")
    
    def _generate_interim_report(self) -> None:
        """生成临时分析报告，在分析仍在进行时使用"""
        # 生成报告数据
        report_data = self._generate_report_data()
        
        # 保存JSON报告
        with open(self.json_report_file, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        # 生成HTML报告
        self._generate_html_report(report_data)
        
        logger.info(f"临时报告已生成: {self.report_file}")
    
    def generate_report(self) -> None:
        """生成最终分析报告"""
        logger.info("生成分析报告...")
        
        # 收集重要数据
        report_data = self._generate_report_data()
        
        # 保存JSON报告
        with open(self.json_report_file, 'w') as f:
            json.dump(report_data, f, indent=2)
            
        logger.info(f"JSON报告已保存到 {self.json_report_file}")
        
        # 生成HTML报告
        self._generate_html_report(report_data)
        
        logger.info(f"HTML报告已保存到 {self.report_file}")
    
    def _generate_report_data(self) -> Dict[str, Any]:
        """
        收集并生成报告数据
        
        Returns:
            报告数据字典
        """
        # 获取分析持续时间
        duration = time.time() - self.analysis_start_time if self.analysis_start_time else 0
        
        # 基本报告数据
        report_data = {
            "meta": {
                "target": self.target_path,
                "pid": self.pid,
                "start_time": datetime.fromtimestamp(self.analysis_start_time).strftime('%Y-%m-%d %H:%M:%S') if self.analysis_start_time else "N/A",
                "duration": f"{int(duration // 60)}分 {int(duration % 60)}秒",
                "analysis_id": os.path.basename(self.output_dir)
            },
            "statistics": {
                "memory_dumps": len(self.memory_dumps),
                "network_activity": len(self.network_data),
                "file_operations": len(self.file_data),
                "registry_operations": len(self.registry_data),
                "protection_data": self.protection_data
            },
            "system_info": getattr(self, 'system_info', {}),
            "memory_dumps": self.memory_dumps,
            "network_data": self.network_data,
            "file_data": self.file_data,
            "registry_data": self.registry_data,
            "running": self.running
        }
        
        # 生成保护检测摘要
        report_data["protection_summary"] = self._generate_protection_summary()
        
        # 提出解决方案和建议
        report_data["recommendations"] = self._generate_recommendations()
        
        return report_data
    
    def _generate_protection_summary(self) -> Dict[str, Any]:
        """
        生成保护检测摘要
        
        Returns:
            保护检测摘要字典
        """
        summary = {
            "detected_protections": [],
            "protection_level": "未知",
            "anti_debugging": False,
            "anti_vm": False,
            "self_modifying_code": False,
            "network_protection": False,
        }
        
        # 确定检测到的保护
        if self.protection_data['protection_detections']['vmprotect'] > 0:
            summary["detected_protections"].append("VMProtect")
        
        if self.protection_data['protection_detections']['themida'] > 0:
            summary["detected_protections"].append("Themida/WinLicense")
        
        if self.protection_data['protection_detections']['custom'] > 0:
            summary["detected_protections"].append("自定义保护")
        
        # 检查反调试
        if self.protection_data['anti_debug_attempts'] > 0:
            summary["anti_debugging"] = True
            summary["detected_protections"].append("反调试技术")
        
        # 检查网络保护
        if self.protection_data['network_connections'] > 2:
            summary["network_protection"] = True
            summary["detected_protections"].append("网络验证")
        
        # 检查自修改代码
        if len([dump for dump in self.memory_dumps if "executable" in dump.get('info', '').lower()]) > 0:
            summary["self_modifying_code"] = True
            summary["detected_protections"].append("自修改/自解密代码")
        
        # 确定保护级别
        num_protections = len(summary["detected_protections"])
        if num_protections >= 3:
            summary["protection_level"] = "高"
        elif num_protections >= 1:
            summary["protection_level"] = "中"
        elif num_protections == 0 and self.protection_data['memory_allocations'] > 0:
            summary["protection_level"] = "低"
        else:
            summary["protection_level"] = "无"
        
        return summary
    
    def _generate_recommendations(self) -> List[Dict[str, str]]:
        """
        基于分析结果生成建议
        
        Returns:
            建议列表
        """
        recommendations = []
        
        # 添加通用建议
        recommendations.append({
            "title": "进行静态分析",
            "description": "将动态分析结果与静态分析相结合，使用转储的内存模块进行反汇编。"
        })
        
        # 根据检测到的保护添加具体建议
        protection_summary = self._generate_protection_summary()
        
        if "VMProtect" in protection_summary["detected_protections"]:
            recommendations.append({
                "title": "VMProtect绕过策略",
                "description": "使用Scylla或类似工具在最终解密完成后转储内存。寻找VM入口点和VM退出点。"
            })
        
        if "Themida/WinLicense" in protection_summary["detected_protections"]:
            recommendations.append({
                "title": "Themida绕过策略",
                "description": "使用专门的Themida脱壳工具。设置硬件断点监控关键内存区域，注意TLS回调。"
            })
        
        if protection_summary["anti_debugging"]:
            recommendations.append({
                "title": "反调试绕过",
                "description": "对IsDebuggerPresent和CheckRemoteDebuggerPresent等API函数使用钩子。使用虚拟机并隐藏调试器特征。"
            })
        
        if protection_summary["network_protection"]:
            recommendations.append({
                "title": "网络验证绕过",
                "description": "分析网络流量并考虑使用网络代理服务器模拟验证服务器。修改网络通信函数返回成功结果。"
            })
        
        if protection_summary["self_modifying_code"]:
            recommendations.append({
                "title": "自修改代码分析",
                "description": "分析内存转储中的解密代码。使用本分析工具导出的内存转储文件，它们可能包含解密后的代码。"
            })
        
        # 添加一般性建议
        if len(self.memory_dumps) > 0:
            recommendations.append({
                "title": "内存转储分析",
                "description": f"分析 {len(self.memory_dumps)} 个内存转储，尤其关注可执行内存区域和自修改代码。"
            })
        
        return recommendations
    
    def _generate_html_report(self, report_data: Dict[str, Any]) -> None:
        """
        生成HTML格式的分析报告
        
        Args:
            report_data: 报告数据
        """
        # HTML报告模板
        html_template = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>动态分析报告</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; color: #333; }
        h1, h2, h3 { color: #2c3e50; }
        .container { max-width: 1200px; margin: 0 auto; }
        .section { margin-bottom: 30px; background: #fff; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .summary-box { background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .data-block { background-color: #f5f5f5; padding: 10px; border-radius: 5px; margin-top: 10px; overflow-x: auto; }
        .protection-high { color: #e74c3c; font-weight: bold; }
        .protection-medium { color: #f39c12; font-weight: bold; }
        .protection-low { color: #3498db; font-weight: bold; }
        .protection-none { color: #2ecc71; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th, td { text-align: left; padding: 8px; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
        tr:hover { background-color: #f5f5f5; }
        .badge { display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 12px; font-weight: bold; margin-right: 5px; margin-bottom: 5px; }
        .badge-primary { background-color: #3498db; color: white; }
        .badge-warning { background-color: #f39c12; color: white; }
        .badge-danger { background-color: #e74c3c; color: white; }
        .badge-success { background-color: #2ecc71; color: white; }
        .badge-info { background-color: #9b59b6; color: white; }
        .recommendations { list-style-type: none; padding: 0; }
        .recommendations li { margin-bottom: 15px; padding-left: 20px; position: relative; }
        .recommendations li:before { content: "→"; position: absolute; left: 0; color: #3498db; }
        .header { background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .footer { text-align: center; margin-top: 30px; font-size: 12px; color: #7f8c8d; }
        .tabs { display: flex; margin-bottom: 20px; }
        .tab { padding: 10px 15px; background-color: #f2f2f2; margin-right: 5px; cursor: pointer; border-radius: 5px 5px 0 0; }
        .tab.active { background-color: #3498db; color: white; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>动态分析报告</h1>
            <p>生成时间: {timestamp}</p>
        </div>
        
        <div class="section">
            <h2>分析概述</h2>
            <div class="summary-box">
                <p><strong>目标文件:</strong> {target}</p>
                <p><strong>进程ID:</strong> {pid}</p>
                <p><strong>开始时间:</strong> {start_time}</p>
                <p><strong>分析持续时间:</strong> {duration}</p>
                <p><strong>保护级别:</strong> <span class="protection-{protection_level_class}">{protection_level}</span></p>
                <p><strong>检测到的保护:</strong> {detected_protections}</p>
            </div>
            
            <h3>保护统计</h3>
            <table>
                <tr><th>指标</th><th>数值</th></tr>
                <tr><td>反调试尝试</td><td>{anti_debug_attempts}</td></tr>
                <tr><td>网络连接</td><td>{network_connections}</td></tr>
                <tr><td>文件访问</td><td>{file_accesses}</td></tr>
                <tr><td>注册表访问</td><td>{registry_accesses}</td></tr>
                <tr><td>线程创建</td><td>{thread_creations}</td></tr>
                <tr><td>内存分配</td><td>{memory_allocations}</td></tr>
            </table>
        </div>
        
        <div class="section">
            <h2>专家建议</h2>
            <ul class="recommendations">
                {recommendations}
            </ul>
        </div>
        
        <div class="section">
            <h2>内存转储</h2>
            <div class="tabs">
                <div class="tab active" onclick="openTab(event, 'tab-memory-table')">表格视图</div>
                <div class="tab" onclick="openTab(event, 'tab-memory-details')">详细信息</div>
            </div>
            
            <div id="tab-memory-table" class="tab-content active">
                {memory_dumps_table}
            </div>
            
            <div id="tab-memory-details" class="tab-content">
                {memory_dumps_details}
            </div>
        </div>
        
        <div class="section">
            <h2>网络活动</h2>
            {network_activity}
        </div>
        
        <div class="section">
            <h2>文件操作</h2>
            {file_operations}
        </div>
        
        <div class="section">
            <h2>注册表操作</h2>
            {registry_operations}
        </div>
        
        <div class="footer">
            <p>由高级逆向工程平台自动生成</p>
            <p>分析ID: {analysis_id}</p>
        </div>
    </div>
    
    <script>
        function openTab(evt, tabId) {
            var i, tabContent, tabLinks;
            
            // 隐藏所有标签内容
            tabContent = document.getElementsByClassName("tab-content");
            for (i = 0; i < tabContent.length; i++) {
                tabContent[i].style.display = "none";
            }
            
            // 移除所有标签的活动状态
            tabLinks = document.getElementsByClassName("tab");
            for (i = 0; i < tabLinks.length; i++) {
                tabLinks[i].className = tabLinks[i].className.replace(" active", "");
            }
            
            // 显示当前标签并添加活动状态
            document.getElementById(tabId).style.display = "block";
            evt.currentTarget.className += " active";
        }
    </script>
</body>
</html>
"""
        
        # 格式化建议
        recommendations_html = ""
        for rec in report_data.get('recommendations', []):
            recommendations_html += f'<li><strong>{rec["title"]}</strong>: {rec["description"]}</li>\n'
        
        # 格式化内存转储表格
        memory_dumps_table = ""
        if report_data.get('memory_dumps', []):
            memory_dumps_table = """
            <table>
                <tr>
                    <th>序号</th>
                    <th>地址</th>
                    <th>大小</th>
                    <th>MD5</th>
                    <th>信息</th>
                </tr>
            """
            
            for i, dump in enumerate(report_data['memory_dumps']):
                memory_dumps_table += f"""
                <tr>
                    <td>{i+1}</td>
                    <td>{dump.get('address', 'unknown')}</td>
                    <td>{dump.get('size', 0)} 字节</td>
                    <td>{dump.get('md5', 'N/A')}</td>
                    <td>{dump.get('info', '')}</td>
                </tr>
                """
            
            memory_dumps_table += "</table>"
        else:
            memory_dumps_table = "<p>未检测到内存转储</p>"
        
        # 格式化内存转储详情
        memory_dumps_details = ""
        if report_data.get('memory_dumps', []):
            for i, dump in enumerate(report_data['memory_dumps']):
                memory_dumps_details += f"""
                <div class="data-block">
                    <h4>转储 #{i+1}: {os.path.basename(dump.get('path', ''))}</h4>
                    <p><strong>地址:</strong> {dump.get('address', 'unknown')}</p>
                    <p><strong>大小:</strong> {dump.get('size', 0)} 字节</p>
                    <p><strong>MD5:</strong> {dump.get('md5', 'N/A')}</p>
                    <p><strong>时间:</strong> {datetime.fromtimestamp(dump.get('timestamp', 0)).strftime('%Y-%m-%d %H:%M:%S')}</p>
                    <p><strong>信息:</strong> {dump.get('info', '')}</p>
                    <p><strong>文件路径:</strong> {dump.get('path', '')}</p>
                </div>
                """
        else:
            memory_dumps_details = "<p>未检测到内存转储</p>"
        
        # 格式化网络活动
        network_activity = ""
        if report_data.get('network_data', []):
            network_activity = """
            <table>
                <tr>
                    <th>类型</th>
                    <th>详细信息</th>
                    <th>数据大小</th>
                    <th>时间</th>
                </tr>
            """
            
            for entry in report_data['network_data']:
                entry_type = entry.get('type', 'unknown')
                details = ""
                
                if entry_type == 'network_connect':
                    details = f"{entry.get('address', 'unknown')}:{entry.get('port', 0)}"
                elif entry_type == 'http_request':
                    details = entry.get('url', 'unknown')
                elif entry_type in ['network_send', 'network_recv', 'network_send_data']:
                    details = f"Socket: {entry.get('socket', 'unknown')}, 长度: {entry.get('length', 0)} 字节"
                    if 'content_type' in entry:
                        details += f", 类型: {entry['content_type']}"
                
                network_activity += f"""
                <tr>
                    <td>{entry_type}</td>
                    <td>{details}</td>
                    <td>{entry.get('data_size', 0)} 字节</td>
                    <td>{datetime.fromtimestamp(entry.get('timestamp', 0)).strftime('%Y-%m-%d %H:%M:%S')}</td>
                </tr>
                """
            
            network_activity += "</table>"
        else:
            network_activity = "<p>未检测到网络活动</p>"
        
        # 格式化文件操作
        file_operations = ""
        if report_data.get('file_data', []):
            file_operations = """
            <table>
                <tr>
                    <th>操作</th>
                    <th>路径/句柄</th>
                    <th>数据大小</th>
                    <th>时间</th>
                </tr>
            """
            
            for entry in report_data['file_data']:
                entry_type = entry.get('type', 'unknown')
                details = ""
                
                if 'path' in entry:
                    details = entry['path']
                elif 'handle' in entry:
                    details = f"句柄: {entry['handle']}"
                
                if 'length' in entry:
                    details += f", 长度: {entry['length']} 字节"
                
                file_operations += f"""
                <tr>
                    <td>{entry_type}</td>
                    <td>{details}</td>
                    <td>{entry.get('data_size', 0)} 字节</td>
                    <td>{datetime.fromtimestamp(entry.get('timestamp', 0)).strftime('%Y-%m-%d %H:%M:%S')}</td>
                </tr>
                """
            
            file_operations += "</table>"
        else:
            file_operations = "<p>未检测到文件操作</p>"
        
        # 格式化注册表操作
        registry_operations = ""
        if report_data.get('registry_data', []):
            registry_operations = """
            <table>
                <tr>
                    <th>操作</th>
                    <th>键/值</th>
                    <th>数据大小</th>
                    <th>时间</th>
                </tr>
            """
            
            for entry in report_data['registry_data']:
                entry_type = entry.get('type', 'unknown')
                details = ""
                
                if 'key' in entry:
                    details = f"键: {entry['key']}"
                elif 'value' in entry:
                    details = f"值: {entry['value']}"
                
                if 'data_type' in entry:
                    details += f", 类型: {entry['data_type']}"
                
                registry_operations += f"""
                <tr>
                    <td>{entry_type}</td>
                    <td>{details}</td>
                    <td>{entry.get('data_size', 0)} 字节</td>
                    <td>{datetime.fromtimestamp(entry.get('timestamp', 0)).strftime('%Y-%m-%d %H:%M:%S')}</td>
                </tr>
                """
            
            registry_operations += "</table>"
        else:
            registry_operations = "<p>未检测到注册表操作</p>"
        
        # 格式化保护级别CSS类
        protection_level_class = report_data['protection_summary']['protection_level'].lower()
        if protection_level_class == "高":
            protection_level_class = "high"
        elif protection_level_class == "中":
            protection_level_class = "medium"
        elif protection_level_class == "低":
            protection_level_class = "low"
        else:
            protection_level_class = "none"
        
        # 格式化检测到的保护
        detected_protections = ""
        protections = report_data['protection_summary']['detected_protections']
        if protections:
            for protection in protections:
                badge_class = "badge-primary"
                if "VMProtect" in protection or "Themida" in protection:
                    badge_class = "badge-danger"
                elif "反调试" in protection:
                    badge_class = "badge-warning"
                
                detected_protections += f'<span class="badge {badge_class}">{protection}</span> '
        else:
            detected_protections = '<span class="badge badge-success">无</span>'
        
        # 填充HTML模板
        html_report = html_template.format(
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            target=report_data['meta']['target'] or "未知",
            pid=report_data['meta']['pid'] or "未知",
            start_time=report_data['meta']['start_time'],
            duration=report_data['meta']['duration'],
            protection_level=report_data['protection_summary']['protection_level'],
            protection_level_class=protection_level_class,
            detected_protections=detected_protections,
            anti_debug_attempts=report_data['protection_data']['anti_debug_attempts'],
            network_connections=report_data['protection_data']['network_connections'],
            file_accesses=report_data['protection_data']['file_accesses'],
            registry_accesses=report_data['protection_data']['registry_accesses'],
            thread_creations=report_data['protection_data']['thread_creations'],
            memory_allocations=report_data['protection_data']['memory_allocations'],
            recommendations=recommendations_html,
            memory_dumps_table=memory_dumps_table,
            memory_dumps_details=memory_dumps_details,
            network_activity=network_activity,
            file_operations=file_operations,
            registry_operations=registry_operations,
            analysis_id=report_data['meta']['analysis_id']
        )
        
        # 写入HTML报告
        with open(self.report_file, 'w', encoding='utf-8') as f:
            f.write(html_report)

def main():
    """主程序入口"""
    # 创建参数解析器
    parser = argparse.ArgumentParser(description='动态分析引擎')
    
    # 添加命令行参数
    parser.add_argument('target', nargs='?', help='目标可执行文件路径或进程ID')
    parser.add_argument('-o', '--output', help='输出目录')
    parser.add_argument('-t', '--timeout', type=int, help='分析超时(秒)')
    parser.add_argument('-p', '--pid', action='store_true', help='目标是PID而非文件路径')
    parser.add_argument('-a', '--api-port', type=int, default=5000, help='API服务器端口(默认: 5000)')
    parser.add_argument('-w', '--wait', action='store_true', help='等待分析完成')
    parser.add_argument('-v', '--verbose', action='store_true', help='启用详细日志输出')
    
    # 解析参数
    args = parser.parse_args()
    
    # 设置日志级别
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        if args.pid:
            # 附加到现有进程
            if not args.target:
                print("错误: 必须指定目标进程ID")
                return 1
                
            pid = int(args.target)
            analyzer = DynamicAnalyzer(None, args.output, args.api_port)
            
            if analyzer.attach_to_process(pid, args.timeout):
                logger.info(f"成功附加到进程 {pid}")
                
                if args.wait:
                    analyzer.wait_for_completion()
                else:
                    print(f"API服务器运行在http://localhost:{args.api_port}")
                    print("进程在后台分析中. 使用Ctrl+C停止.")
                    try:
                        while True:
                            time.sleep(1)
                    except KeyboardInterrupt:
                        analyzer.stop_analysis()
            else:
                logger.error(f"附加到进程 {pid} 失败")
                return 1
        elif args.target:
            # 启动新进程分析
            analyzer = DynamicAnalyzer(args.target, args.output, args.api_port)
            
            if analyzer.start_analysis(args.timeout):
                logger.info(f"成功启动分析: {args.target}")
                
                if args.wait:
                    analyzer.wait_for_completion()
                else:
                    print(f"API服务器运行在http://localhost:{args.api_port}")
                    print("进程在后台分析中. 使用Ctrl+C停止.")
                    try:
                        while True:
                            time.sleep(1)
                    except KeyboardInterrupt:
                        analyzer.stop_analysis()
            else:
                logger.error(f"启动分析失败: {args.target}")
                return 1
        else:
            # 仅启动API服务器
            print("未指定目标. 仅启动API服务器.")
            analyzer = DynamicAnalyzer(None, args.output, args.api_port)
            analyzer._create_api_server()
            analyzer._start_api_server()
            
            print(f"API服务器运行在http://localhost:{args.api_port}")
            print("使用Ctrl+C停止.")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("API服务器已停止.")
        
        return 0
    except Exception as e:
        logger.error(f"错误: {str(e)}")
        logger.error(traceback.format_exc())
        return 1

if __name__ == "__main__":
    sys.exit(main())