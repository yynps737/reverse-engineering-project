#!/usr/bin/env python3
"""
增强版动态分析引擎 - 用于恶意软件和壳保护程序的动态分析
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
    logger.error("尝试自动安装...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "frida-tools"])
        import frida
        logger.info("Frida安装成功")
    except:
        logger.error("自动安装失败，请手动安装Frida")
        sys.exit(1)

# Frida JS脚本 - 核心功能 (保持原有功能但优化结构)
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
    var memoryDumps = [];
    var oepCandidates = [];
    
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
            
            // 记录已创建的内存转储
            memoryDumps.push({
                address: address.toString(),
                size: size,
                info: info || 'Manual dump',
                timestamp: new Date().getTime()
            });
            
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
    
    // OEP监测 - 新增函数，识别可能的原始入口点
    function recordOEPCandidate(address, confidence, reason) {
        // 检查是否已存在此地址
        const existing = oepCandidates.find(oep => oep.address === address.toString());
        if (existing) {
            // 更新置信度
            existing.confidence = Math.max(existing.confidence, confidence);
            existing.reasons.push(reason);
        } else {
            // 添加新候选
            oepCandidates.push({
                address: address.toString(),
                confidence: confidence,
                reasons: [reason],
                timestamp: new Date().getTime()
            });
            
            // 通知宿主
            send({
                type: 'oep_candidate',
                address: address.toString(),
                confidence: confidence,
                reason: reason,
                timestamp: new Date().getTime()
            });
            
            // 如果置信度很高，立即转储内存
            if (confidence >= 80) {
                // 尝试转储可能包含OEP的区域
                try {
                    const addressPtr = ptr(address);
                    dumpMemory(addressPtr.sub(0x1000), 0x2000, "High confidence OEP area");
                    
                    // 尝试转储整个模块
                    const module = Process.findModuleByAddress(addressPtr);
                    if (module) {
                        log.info(`[+] 发现高置信度OEP在模块 ${module.name} 中，尝试转储整个模块`);
                        dumpMemory(module.base, module.size, "Module containing OEP");
                    }
                } catch (e) {
                    log.error("OEP区域转储失败: " + e.message);
                }
            }
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
            ],
            'oep_signatures': [
                { pattern: '55 8B EC 83 EC', name: 'Visual C++ Entry', confidence: 70 },
                { pattern: '55 8B EC 6A FF 68', name: 'Visual C++ Entry with SEH', confidence: 75 },
                { pattern: '55 8B EC 81 EC', name: 'Visual C++ Entry (Stack Frame)', confidence: 70 },
                { pattern: '53 56 57 55 8B EC', name: 'Custom Entry Point', confidence: 65 },
                { pattern: 'E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? CC CC', name: 'Jump Chain End', confidence: 60 },
                // 添加更多OEP特征指纹
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
                                
                                if (protectionType === 'oep_signatures') {
                                    // 记录OEP候选
                                    log.info(`[+] 可能的OEP: ${signatureInfo.name} @ ${address}`);
                                    recordOEPCandidate(address, signatureInfo.confidence, signatureInfo.name);
                                } else {
                                    // 记录保护检测
                                    log.info(`[+] 发现${protectionType}保护: ${signatureInfo.name} @ ${address}`);
                                    protectionDetections[protectionType].push(foundInfo);
                                    
                                    // 通知宿主应用程序
                                    send({
                                        type: 'protection_detected',
                                        protection_type: protectionType, 
                                        info: foundInfo
                                    });
                                }
                                
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
    
    // 收集更详细的PE文件信息 - 新增函数
    function collectDetailedFileInfo() {
        try {
            const mainModule = Process.mainModule;
            if (!mainModule) {
                log.warn("无法获取主模块");
                return;
            }
            
            const peHeader = Memory.readByteArray(mainModule.base, 0x1000); // 读取PE头
            
            // 发送PE头数据
            send({
                type: 'pe_header',
                module_name: mainModule.name,
                module_base: mainModule.base.toString(),
                timestamp: new Date().getTime()
            }, peHeader);
            
            // 尝试解析导入表和导出表
            // 此处简化，实际需要更复杂的PE解析
            log.info("已收集PE头信息");
        } catch (e) {
            log.error("收集PE信息错误: " + e.message);
        }
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
                        
                        // 对于特别长的调用，可能是VM退出点，记录OEP候选
                        if (duration > 200) {
                            log.info(`[!] 可能的VM退出点: ${this.moduleName}!${this.funcName} (${duration}ms)`);
                            recordOEPCandidate(this.returnAddress, 60, "Long API call");
                        }
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
            
            // 如果线程起始地址使用了非系统模块中的代码，可能是壳解密后执行原始代码的点
            try {
                const startAddr = context.threadStart;
                const moduleInfo = Process.findModuleByAddress(startAddr);
                if (moduleInfo && !moduleInfo.path.toLowerCase().includes('\\windows\\')) {
                    log.info(`[!] 创建线程指向用户模块代码 ${moduleInfo.name}, 可能是OEP`);
                    recordOEPCandidate(startAddr, 75, "CreateThread to user module");
                }
            } catch (e) {
                // 忽略错误
            }
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
                
                // 这可能是壳解密后使内存可执行的地方，记录OEP候选
                recordOEPCandidate(context.vpAddress, 65, "Memory made executable");
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
                            } else if (details.operation === 'execute') {
                                log.info(`[!] 执行内存区域: ${details.address}`);
                                
                                // 这可能是OEP - 记录并转储
                                recordOEPCandidate(details.address, 85, "Execution of allocated memory");
                            }
                        }
                    });
                } catch (e) {
                    log.warn(`无法监视内存: ${e.message}`);
                }
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
            
            // 收集更详细的PE文件信息
            collectDetailedFileInfo();
            
            // 扫描用户模块
            scanUserModules();
            
            // 挂钩关键API
            hookSpecifiedAPIs();
            
            // 延迟一秒后扫描内存保护特征
            setTimeout(scanMemoryRegionsForSignatures, 1000);
            
            // 设置周期性状态报告
            setInterval(function() {
                // 发送OEP候选信息
                if (oepCandidates.length > 0) {
                    send({
                        type: 'oep_candidates',
                        candidates: oepCandidates,
                        timestamp: new Date().getTime()
                    });
                }
                
                // 发送常规状态更新
                send({
                    type: 'status_update',
                    anti_debug_attempts: antiDebugAttempts,
                    network_activity: networkData.length,
                    file_activity: fileData.length,
                    registry_activity: registryData.length,
                    thread_creations: threadCreations.length,
                    memory_allocations: memoryAllocs.length,
                    memory_dumps: memoryDumps.length,
                    total_api_calls: apiCalls.length,
                    protections: {
                        vmprotect_detections: protectionDetections.vmprotect.length,
                        themida_detections: protectionDetections.themida.length,
                        custom_detections: protectionDetections.custom.length
                    },
                    timestamp: new Date().getTime()
                });
            }, 5000);
            
            // 在程序结束前尝试保存最终状态（使用setTimeout确保在程序崩溃前完成）
            setInterval(function() {
                // 如果检测到任何用户模块中的执行区域，可能是脱壳后的OEP
                const userModules = Process.enumerateModules().filter((m) => {
                    return !m.path.toLowerCase().includes('\\windows\\') &&
                           !m.path.toLowerCase().includes('\\syswow64\\') &&
                           !m.name.toLowerCase().includes('api-ms-win');
                });
                
                // 对每个用户模块转储可执行区域
                userModules.forEach(function(mod) {
                    try {
                        // 检查是否已转储过此模块
                        const alreadyDumped = memoryDumps.some(dump => 
                            dump.address === mod.base.toString() && dump.size === mod.size);
                        
                        if (!alreadyDumped) {
                            log.info(`[*] 转储用户模块 ${mod.name} 以供脱壳分析`);
                            dumpMemory(mod.base, mod.size, `Module ${mod.name} for unpacking`);
                        }
                    } catch (e) {
                        log.error(`转储模块错误: ${e.message}`);
                    }
                });
            }, 15000);  // 每15秒检查一次
            
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
    增强型动态分析引擎，用于软件保护分析和脱壳
    添加了OEP检测和反汇编功能
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
        self.oep_candidates = []
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
        
        # 反汇编引擎
        self.disassembler = None
        try:
            import capstone
            self.disassembler = capstone
            logger.info("Capstone反汇编引擎已加载")
        except ImportError:
            logger.warning("Capstone反汇编引擎未安装，尝试自动安装...")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", "capstone"])
                import capstone
                self.disassembler = capstone
                logger.info("Capstone反汇编引擎已安装并加载")
            except:
                logger.warning("无法自动安装Capstone，反汇编功能将受限")
    
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
            "disassembly",     # 反汇编结果
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
                    "oep_candidates": len(self.oep_candidates),
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
                    # 生成反汇编（如果可能）
                    disasm_path = None
                    if self.disassembler:
                        disasm_path = self.disassemble_dump(dump_path, address)
                    
                    response = {"result": "success", "path": dump_path}
                    if disasm_path:
                        response["disassembly"] = disasm_path
                    
                    return jsonify(response)
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
        
        # 获取OEP候选列表
        @app.route('/api/oep_candidates', methods=['GET'])
        def get_oep_candidates():
            return jsonify({"candidates": self.oep_candidates})
        
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

        # 获取反汇编结果
        @app.route('/api/disassembly/<path:dump_path>', methods=['GET'])
        def get_disassembly(dump_path):
            # 安全检查，防止路径遍历漏洞
            dump_file = os.path.normpath(os.path.join(self.output_dir, "memory_dumps", os.path.basename(dump_path)))
            if not os.path.exists(dump_file) or not os.path.isfile(dump_file):
                return jsonify({"error": "转储文件不存在"}), 404
            
            # 尝试查找现有反汇编
            disasm_dir = os.path.join(self.output_dir, "disassembly")
            disasm_file = os.path.join(disasm_dir, os.path.basename(dump_path) + "_disasm.txt")
            
            # 如果不存在，尝试生成
            if not os.path.exists(disasm_file):
                if self.disassembler:
                    # 假设地址从0开始
                    disasm_file = self.disassemble_dump(dump_file, 0)
                else:
                    return jsonify({"error": "反汇编引擎不可用"}), 500
            
            if os.path.exists(disasm_file) and os.path.isfile(disasm_file):
                return send_file(disasm_file, as_attachment=True)
            
            return jsonify({"error": "无法生成反汇编"}), 500
        
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
                self.api_server.run(host='0.0.0.0', port=self.api_port, debug=False, use_reloader=False, threaded=True)
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
                elif msg_type == 'oep_candidate':
                    self._handle_oep_candidate(payload)
                elif msg_type == 'oep_candidates':
                    self._handle_oep_candidates(payload)
                elif msg_type == 'pe_header':
                    self._handle_pe_header(payload, data)
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
        
        # 尝试反汇编内存转储
        if self.disassembler:
            try:
                # 将地址从字符串转换为整数
                addr = int(address, 16) if isinstance(address, str) and address.startswith('0x') else int(address)
                disasm_file = self.disassemble_dump(dump_path, addr)
                
                if disasm_file:
                    logger.info(f"内存转储已反汇编: {disasm_file}")
                    dump_info['disassembly'] = disasm_file
            except Exception as e:
                logger.error(f"反汇编内存转储错误: {str(e)}")
    
    def disassemble_dump(self, dump_file: str, base_address: int) -> Optional[str]:
        """
        反汇编内存转储文件
        
        Args:
            dump_file: 转储文件路径
            base_address: 基址
            
        Returns:
            反汇编文件路径或None
        """
        if not self.disassembler:
            logger.warning("Capstone反汇编引擎不可用")
            return None
        
        try:
            # 加载转储数据
            with open(dump_file, 'rb') as f:
                dump_data = f.read()
            
            # 创建反汇编文件
            disasm_dir = os.path.join(self.output_dir, "disassembly")
            disasm_file = os.path.join(disasm_dir, os.path.basename(dump_file) + "_disasm.txt")
            
            # 尝试确定架构和位模式
            # 默认为X86和32位模式，但可以改进以自动检测
            arch = self.disassembler.CS_ARCH_X86
            mode = self.disassembler.CS_MODE_32
            
            # 尝试从内存转储头部检测架构
            if len(dump_data) >= 4:
                # 检查特征以判断是32位还是64位
                # 这是一个简化的启发式方法，实际项目中可能需要更复杂的逻辑
                if dump_data.startswith(b'\x48\x89') or dump_data.startswith(b'\x48\x8B'):
                    mode = self.disassembler.CS_MODE_64
            
            # 初始化反汇编引擎
            md = self.disassembler.Cs(arch, mode)
            md.detail = True
            
            # 反汇编并写入文件
            with open(disasm_file, 'w') as f:
                f.write(f"反汇编 {os.path.basename(dump_file)}\n")
                f.write(f"基址: 0x{base_address:x}\n")
                f.write(f"架构: {'x64' if mode == self.disassembler.CS_MODE_64 else 'x86'}\n")
                f.write(f"大小: {len(dump_data)} 字节\n")
                f.write("=" * 50 + "\n\n")
                
                # 反汇编数据
                for i, (address, size, mnemonic, op_str) in enumerate(md.disasm_lite(dump_data, base_address)):
                    f.write(f"0x{address:08x}:  {mnemonic:8s} {op_str}\n")
                    
                    # 限制输出行数以防止过大的文件
                    if i >= 50000:  # 最多显示5万条指令
                        f.write("\n... 反汇编输出被截断 (超过50000行) ...\n")
                        break
            
            return disasm_file
        except Exception as e:
            logger.error(f"反汇编错误: {str(e)}")
            return None
    
    def _handle_oep_candidate(self, payload: Dict[str, Any]) -> None:
        """
        处理OEP候选信息
        
        Args:
            payload: 消息载荷
        """
        address = payload.get('address', 'unknown')
        confidence = payload.get('confidence', 0)
        reason = payload.get('reason', 'unknown')
        
        logger.info(f"发现OEP候选: {address} (置信度: {confidence}%, 原因: {reason})")
        
        # 检查是否已存在此地址
        for candidate in self.oep_candidates:
            if candidate['address'] == address:
                # 更新置信度
                candidate['confidence'] = max(candidate['confidence'], confidence)
                if reason not in candidate['reasons']:
                    candidate['reasons'].append(reason)
                break
        else:
            # 添加新候选
            self.oep_candidates.append({
                'address': address,
                'confidence': confidence,
                'reasons': [reason],
                'timestamp': payload.get('timestamp', time.time())
            })
            
            # 如果置信度高，自动转储该区域的内存
            if confidence >= 75:
                try:
                    # 将地址从字符串转换为整数
                    addr = int(address, 16) if isinstance(address, str) and address.startswith('0x') else int(address)
                    
                    # 转储前后各2KB的内存
                    self._dump_memory_region(addr - 0x800, 0x1000, f"High confidence OEP (confidence: {confidence}%)")
                except Exception as e:
                    logger.error(f"转储高置信度OEP错误: {str(e)}")
    
    def _handle_oep_candidates(self, payload: Dict[str, Any]) -> None:
        """
        处理OEP候选列表
        
        Args:
            payload: 消息载荷
        """
        candidates = payload.get('candidates', [])
        
        if not candidates:
            return
        
        # 更新或添加每个候选
        for candidate in candidates:
            address = candidate.get('address', 'unknown')
            confidence = candidate.get('confidence', 0)
            reasons = candidate.get('reasons', [])
            
            # 检查是否已存在此地址
            for existing in self.oep_candidates:
                if existing['address'] == address:
                    # 更新置信度和原因
                    existing['confidence'] = max(existing['confidence'], confidence)
                    for reason in reasons:
                        if reason not in existing['reasons']:
                            existing['reasons'].append(reason)
                    break
            else:
                # 添加新候选
                self.oep_candidates.append({
                    'address': address,
                    'confidence': confidence,
                    'reasons': reasons.copy(),
                    'timestamp': candidate.get('timestamp', time.time())
                })
        
        # 对候选按置信度排序
        self.oep_candidates.sort(key=lambda x: x['confidence'], reverse=True)
        logger.info(f"已更新OEP候选列表，共 {len(self.oep_candidates)} 个")
    
    def _handle_pe_header(self, payload: Dict[str, Any], data: Optional[bytes]) -> None:
        """
        处理PE头数据
        
        Args:
            payload: 消息载荷
            data: PE头二进制数据
        """
        if not data:
            logger.warning("PE头数据为空")
            return
        
        module_name = payload.get('module_name', 'unknown')
        module_base = payload.get('module_base', '0')
        
        # 保存PE头
        pe_header_file = os.path.join(self.output_dir, "memory_dumps", f"pe_header_{module_name}_{int(time.time())}.bin")
        with open(pe_header_file, 'wb') as f:
            f.write(data)
        
        logger.info(f"保存PE头: {pe_header_file}")
        
        # 尝试分析PE头以提取有用信息
        try:
            import pefile
            pe = pefile.PE