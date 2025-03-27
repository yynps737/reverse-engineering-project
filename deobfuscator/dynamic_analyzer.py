#!/usr/bin/env python3
import os
import sys
import time
import frida
import signal
import argparse
import tempfile
import subprocess
import threading
import logging
from flask import Flask, request, jsonify

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Frida JS脚本 - 核心功能
FRIDA_SCRIPT = """
(function(){
    // 通用拦截API
    const apiModules = {
        // 反调试API
        "antiDebug": [
            {"module": "kernel32.dll", "function": "IsDebuggerPresent"},
            {"module": "kernel32.dll", "function": "CheckRemoteDebuggerPresent"},
            {"module": "ntdll.dll", "function": "NtQueryInformationProcess"},
            {"module": "kernel32.dll", "function": "OutputDebugString"},
            {"module": "kernel32.dll", "function": "GetTickCount"},
            {"module": "kernel32.dll", "function": "QueryPerformanceCounter"}
        ],
        // 网络验证API
        "network": [
            {"module": "wininet.dll", "function": "InternetOpen"},
            {"module": "wininet.dll", "function": "InternetConnect"},
            {"module": "wininet.dll", "function": "HttpOpenRequest"},
            {"module": "wininet.dll", "function": "HttpSendRequest"},
            {"module": "wininet.dll", "function": "InternetReadFile"},
            {"module": "ws2_32.dll", "function": "connect"},
            {"module": "ws2_32.dll", "function": "send"},
            {"module": "ws2_32.dll", "function": "recv"}
        ],
        // 加密API
        "crypto": [
            {"module": "advapi32.dll", "function": "CryptGenKey"},
            {"module": "advapi32.dll", "function": "CryptDecrypt"},
            {"module": "advapi32.dll", "function": "CryptEncrypt"},
            {"module": "advapi32.dll", "function": "CryptHashData"},
            {"module": "bcrypt.dll", "function": "BCryptEncrypt"},
            {"module": "bcrypt.dll", "function": "BCryptDecrypt"}
        ],
        // 文件操作API
        "file": [
            {"module": "kernel32.dll", "function": "CreateFile"},
            {"module": "kernel32.dll", "function": "ReadFile"},
            {"module": "kernel32.dll", "function": "WriteFile"}
        ],
        // 注册表操作API
        "registry": [
            {"module": "advapi32.dll", "function": "RegOpenKey"},
            {"module": "advapi32.dll", "function": "RegQueryValue"},
            {"module": "advapi32.dll", "function": "RegSetValue"}
        ]
    };

    // 初始化跟踪
    var traces = [];
    var networkData = [];
    var fileData = [];
    var registryData = [];
    var antiDebugAttempts = 0;
    
    // VMP/Themida入口点检测 - 查找特定指令模式
    function scanForVMPPatterns() {
        const moduleMap = Process.enumerateModules();
        
        for (let i = 0; i < moduleMap.length; i++) {
            const m = moduleMap[i];
            try {
                // 扫描前8KB代码以检测模式
                const codeRange = m.base;
                const scanSize = 8192; // 8KB
                
                Memory.scan(codeRange, scanSize, 'EB ?? ?? ?? ?? ?? ?? ?? ?? 00', {
                    onMatch: function(address, size) {
                        console.log('[+] 可能的VMP入口点在: ' + address + ' 模块: ' + m.name);
                        send({
                            type: 'vmp_pattern',
                            address: address.toString(),
                            module: m.name
                        });
                        return 'stop';
                    },
                    onError: function(reason) {
                        console.log('[!] VMProtect扫描错误: ' + reason);
                    },
                    onComplete: function() {}
                });
                
                // 尝试查找Themida模式
                Memory.scan(codeRange, scanSize, '55 8B EC 83 C4 F4 FC 53 57 56', {
                    onMatch: function(address, size) {
                        console.log('[+] 可能的Themida入口点在: ' + address + ' 模块: ' + m.name);
                        send({
                            type: 'themida_pattern',
                            address: address.toString(),
                            module: m.name
                        });
                        return 'stop';
                    },
                    onError: function(reason) {
                        console.log('[!] Themida扫描错误: ' + reason);
                    },
                    onComplete: function() {}
                });
            } catch (e) {
                console.log('[!] 模块扫描错误: ' + e + ' 在模块: ' + m.name);
            }
        }
    }
    
    // 查找所有非系统模块
    const userModules = Process.enumerateModules().filter((m) => {
        return !m.path.toLowerCase().includes('\\windows\\') &&
               !m.path.toLowerCase().includes('\\syswow64\\') &&
               !m.name.toLowerCase().includes('api-ms-win');
    });
    
    console.log('[*] 用户模块: ');
    userModules.forEach((m) => {
        console.log('  - ' + m.name + ' (' + m.base + ')');
    });
    
    // 拦截所有模块的导出函数
    for (const category in apiModules) {
        apiModules[category].forEach(api => {
            try {
                const name = api.function;
                const moduleName = api.module;
                
                try {
                    const moduleAddress = Module.findBaseAddress(moduleName);
                    if (moduleAddress !== null) {
                        console.log('[*] 找到模块 ' + moduleName + ' 在 ' + moduleAddress);
                    } else {
                        console.log('[!] 无法找到模块 ' + moduleName);
                    }
                } catch (e) {
                    console.log('[!] 检查模块错误: ' + e);
                }
                
                // 尝试解析函数
                try {
                    const functionAddress = Module.findExportByName(moduleName, name);
                    if (functionAddress !== null) {
                        attachHook(moduleName, name, functionAddress, category);
                    } else {
                        console.log('[!] 无法找到函数 ' + moduleName + '!' + name);
                    }
                } catch (e) {
                    console.log('[!] 解析函数错误: ' + e);
                }
            } catch (e) {
                console.log('[!] 拦截API错误: ' + e);
            }
        });
    }
    
    // 拦截内存分配 - 对于自解密代码很有用
    try {
        Interceptor.attach(Module.findExportByName('kernel32.dll', 'VirtualAlloc'), {
            onEnter: function (args) {
                this.lpAddress = args[0];
                this.dwSize = args[1];
                this.flAllocationType = args[2];
                this.flProtect = args[3];
            },
            onLeave: function (retval) {
                if (this.flAllocationType.toInt32() & 0x1000 && this.flProtect.toInt32() & 0x40) {
                    const execAddress = retval;
                    const execSize = this.dwSize.toInt32();

                    console.log('[+] 检测到内存执行分配: ' + execAddress + ' 大小: ' + execSize);
                    
                    send({
                        type: 'memory_exec',
                        address: execAddress.toString(),
                        size: execSize
                    });
                    
                    // 添加监视点观察内存变化
                    try {
                        MemoryAccessMonitor.enable({base: execAddress, size: execSize}, {
                            onAccess: function(details) {
                                if (details.operation === 'write') {
                                    console.log('[+] 编写到可执行内存: ' + details.from + ' -> ' + details.address);
                                    
                                    // 内存转储
                                    const buffer = Memory.readByteArray(execAddress, execSize);
                                    send({
                                        type: 'memory_written',
                                        source: details.from.toString(),
                                        target: details.address.toString(),
                                        data: buffer
                                    }, buffer);
                                }
                            }
                        });
                    } catch (e) {
                        console.log('[!] 无法监视内存: ' + e);
                    }
                }
            }
        });
    } catch (e) {
        console.log('[!] VirtualAlloc挂钩错误: ' + e);
    }
    
    // 挂钩CreateThread - 查找新执行路径
    try {
        Interceptor.attach(Module.findExportByName('kernel32.dll', 'CreateThread'), {
            onEnter: function (args) {
                this.threadStart = args[2];
                this.threadParam = args[3];
            },
            onLeave: function (retval) {
                console.log('[+] 新线程创建: 起始地址 = ' + this.threadStart + ', 参数 = ' + this.threadParam);
                
                send({
                    type: 'thread_created',
                    start_address: this.threadStart.toString(),
                    parameter: this.threadParam.toString()
                });
                
                // 尝试跟踪线程启动代码
                try {
                    Stalker.follow(retval.toInt32(), {
                        events: {
                            call: true
                        },
                        onReceive: function(events) {
                            const calls = Stalker.parse(events);
                            for (let i = 0; i < calls.length; i++) {
                                console.log('Thread执行: ' + calls[i][0] + ' -> ' + calls[i][1]);
                            }
                        }
                    });
                } catch (e) {
                    console.log('[!] 线程跟踪错误: ' + e);
                }
            }
        });
    } catch (e) {
        console.log('[!] CreateThread挂钩错误: ' + e);
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
                    console.log('[+] GetProcAddress: ' + this.moduleName + '!' + this.functionNameValue + ' = ' + retval);
                    
                    // 如果是敏感API，进行跟踪
                    const sensitiveFunctions = [
                        'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'CreateFile', 
                        'connect', 'send', 'recv', 'VirtualProtect', 'CryptEncrypt', 'CryptDecrypt'
                    ];
                    
                    if (sensitiveFunctions.includes(this.functionNameValue)) {
                        try {
                            Interceptor.attach(retval, {
                                onEnter: function (args) {
                                    console.log('[+] 调用动态解析的函数: ' + this.functionNameValue);
                                },
                                onLeave: function (retval) {
                                    console.log('[+] 动态解析的函数返回: ' + retval);
                                }
                            });
                        } catch (e) {
                            console.log('[!] 无法跟踪动态解析的函数: ' + e);
                        }
                    }
                }
            }
        });
    } catch (e) {
        console.log('[!] GetProcAddress挂钩错误: ' + e);
    }

    // 附加钩子函数  
    function attachHook(moduleName, funcName, address, category) {
        try {
            Interceptor.attach(address, {
                onEnter: function (args) {
                    this.args = [];
                    for (let i = 0; i < 8; i++) {  // 保存前8个参数
                        this.args.push(args[i]);
                    }
                    
                    // 记录调用
                    const traceLine = moduleName + '!' + funcName + ' 调用';
                    traces.push({timestamp: new Date().getTime(), function: funcName, module: moduleName, category: category});
                    console.log('[*] ' + traceLine);
                    
                    // 特定API处理
                    if (category === 'antiDebug') {
                        antiDebugAttempts++;
                        // 欺骗反调试检查
                        if (funcName === 'IsDebuggerPresent') {
                            this.override = true;
                        } else if (funcName === 'CheckRemoteDebuggerPresent') {
                            this.checkRemotePresent = true;
                            this.outBuf = args[1];
                        } else if (funcName === 'NtQueryInformationProcess') {
                            const ProcessDebugPort = 7;
                            if (args[1].toInt32() === ProcessDebugPort) {
                                this.ntQueryInfo = true;
                                this.outBuf = args[2];
                            }
                        }
                    } else if (category === 'network') {
                        // 保存网络连接信息
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
                                
                                console.log('[+] 网络连接到: ' + addr + ':' + portBE);
                                
                                networkData.push({
                                    timestamp: new Date().getTime(),
                                    type: 'connect',
                                    address: addr,
                                    port: portBE
                                });
                                
                                send({
                                    type: 'network_connect',
                                    address: addr,
                                    port: portBE
                                });
                            }
                        } else if (funcName === 'send') {
                            const socket = args[0];
                            const buffer = args[1];
                            const length = args[2].toInt32();
                            
                            if (length > 0 && length < 10000) { // 合理大小
                                const data = Memory.readByteArray(buffer, length);
                                
                                networkData.push({
                                    timestamp: new Date().getTime(),
                                    type: 'send',
                                    socket: socket.toString(),
                                    data: data,
                                    length: length
                                });
                                
                                send({
                                    type: 'network_send',
                                    socket: socket.toString(),
                                    length: length
                                }, data);
                            }
                        } else if (funcName === 'recv') {
                            this.recvSocket = args[0];
                            this.recvBuffer = args[1];
                            this.recvLength = args[2].toInt32();
                        } else if (funcName === 'InternetOpenUrl' || funcName === 'HttpOpenRequest') {
                            try {
                                if (args[1] !== 0) {
                                    const url = Memory.readUtf16String(args[1]);
                                    console.log('[+] HTTP请求: ' + url);
                                    
                                    networkData.push({
                                        timestamp: new Date().getTime(),
                                        type: 'http_request',
                                        url: url
                                    });
                                    
                                    send({
                                        type: 'http_request',
                                        url: url
                                    });
                                }
                            } catch (e) {
                                console.log('[!] HTTP URL解析错误: ' + e);
                            }
                        }
                    } else if (category === 'file') {
                        if (funcName === 'CreateFile') {
                            try {
                                const path = Memory.readUtf16String(args[0]);
                                console.log('[+] 打开文件: ' + path);
                                
                                fileData.push({
                                    timestamp: new Date().getTime(),
                                    operation: 'open',
                                    path: path
                                });
                                
                                send({
                                    type: 'file_access',
                                    operation: 'open',
                                    path: path
                                });
                            } catch (e) {
                                console.log('[!] 文件路径解析错误: ' + e);
                            }
                        } else if (funcName === 'ReadFile') {
                            this.readFileHandle = args[0];
                            this.readBuffer = args[1];
                            this.bytesToRead = 0;
                            try {
                                if (args[2] !== 0) {
                                    this.bytesToRead = Memory.readUInt(args[2]);
                                }
                                
                                if (args[3] !== 0) {
                                    this.bytesReadPtr = args[3];
                                }
                            } catch (e) {
                                console.log('[!] ReadFile参数解析错误: ' + e);
                            }
                        }
                    } else if (category === 'registry') {
                        if (funcName === 'RegOpenKey' || funcName === 'RegOpenKeyEx') {
                            try {
                                // args[1]是键名
                                if (args[1] !== 0) {
                                    const keyName = Memory.readUtf16String(args[1]);
                                    console.log('[+] 打开注册表键: ' + keyName);
                                    
                                    registryData.push({
                                        timestamp: new Date().getTime(),
                                        operation: 'open',
                                        key: keyName
                                    });
                                    
                                    send({
                                        type: 'registry_access',
                                        operation: 'open',
                                        key: keyName
                                    });
                                }
                            } catch (e) {
                                console.log('[!] 注册表键解析错误: ' + e);
                            }
                        } else if (funcName === 'RegQueryValue' || funcName === 'RegQueryValueEx') {
                            try {
                                // args[1]是值名
                                if (args[1] !== 0) {
                                    const valueName = Memory.readUtf16String(args[1]);
                                    this.regValueName = valueName;
                                    console.log('[+] 查询注册表值: ' + valueName);
                                    
                                    registryData.push({
                                        timestamp: new Date().getTime(),
                                        operation: 'query',
                                        value: valueName
                                    });
                                }
                            } catch (e) {
                                console.log('[!] 注册表值解析错误: ' + e);
                            }
                        }
                    } else if (category === 'crypto') {
                        // 密码学操作处理
                        if (funcName === 'CryptDecrypt') {
                            this.cryptKey = args[0];
                            this.cryptHash = args[1];
                            this.cryptFinal = args[2].toInt32();
                            this.cryptData = args[3];
                            this.cryptDataLen = 0;
                            
                            try {
                                if (args[4] !== 0) {
                                    this.cryptDataLen = Memory.readUInt(args[4]);
                                    console.log('[+] 解密数据长度: ' + this.cryptDataLen);
                                }
                            } catch (e) {
                                console.log('[!] CryptDecrypt参数解析错误: ' + e);
                            }
                        } else if (funcName === 'CryptEncrypt') {
                            this.cryptKey = args[0];
                            this.cryptHash = args[1];
                            this.cryptFinal = args[2].toInt32();
                            this.cryptData = args[3];
                            this.cryptDataLen = 0;
                            
                            try {
                                if (args[4] !== 0) {
                                    this.cryptDataLen = Memory.readUInt(args[4]);
                                    console.log('[+] 加密数据长度: ' + this.cryptDataLen);
                                }
                            } catch (e) {
                                console.log('[!] CryptEncrypt参数解析错误: ' + e);
                            }
                        }
                    }
                },
                onLeave: function (retval) {
                    const funcCat = category;
                    const funcMod = moduleName;
                    const funcNm = funcName;
                    
                    // 处理API特定的返回逻辑
                    if (funcCat === 'antiDebug') {
                        if (this.override) {
                            console.log('[*] 欺骗 IsDebuggerPresent, 返回 0');
                            retval.replace(0); // 将结果替换为0
                        } else if (this.checkRemotePresent) {
                            console.log('[*] 欺骗 CheckRemoteDebuggerPresent');
                            try {
                                Memory.writeU32(this.outBuf, 0);
                            } catch (e) {
                                console.log('[!] 内存写入错误: ' + e);
                            }
                        } else if (this.ntQueryInfo) {
                            console.log('[*] 欺骗 NtQueryInformationProcess(ProcessDebugPort)');
                            try {
                                Memory.writeU32(this.outBuf, 0);
                            } catch (e) {
                                console.log('[!] 内存写入错误: ' + e);
                            }
                        }
                    } else if (funcCat === 'network') {
                        if (funcNm === 'recv' && retval.toInt32() > 0) {
                            const receivedLength = retval.toInt32();
                            if (receivedLength > 0 && receivedLength < 10000) {
                                const data = Memory.readByteArray(this.recvBuffer, receivedLength);
                                
                                networkData.push({
                                    timestamp: new Date().getTime(),
                                    type: 'recv',
                                    socket: this.recvSocket.toString(),
                                    data: data,
                                    length: receivedLength
                                });
                                
                                send({
                                    type: 'network_recv',
                                    socket: this.recvSocket.toString(),
                                    length: receivedLength
                                }, data);
                            }
                        }
                    } else if (funcCat === 'file') {
                        if (funcNm === 'ReadFile' && retval.toInt32() !== 0) {
                            // 成功读取
                            let bytesRead = 0;
                            try {
                                if (this.bytesReadPtr !== undefined && this.bytesReadPtr !== 0) {
                                    bytesRead = Memory.readUInt(this.bytesReadPtr);
                                    
                                    if (bytesRead > 0 && bytesRead < 10000) {
                                        const fileData = Memory.readByteArray(this.readBuffer, bytesRead);
                                        
                                        send({
                                            type: 'file_read',
                                            handle: this.readFileHandle.toString(),
                                            length: bytesRead
                                        }, fileData);
                                    }
                                }
                            } catch (e) {
                                console.log('[!] 读取文件数据错误: ' + e);
                            }
                        }
                    } else if (funcCat === 'crypto') {
                        if (funcNm === 'CryptDecrypt' && retval.toInt32() !== 0) {
                            // 成功解密
                            if (this.cryptDataLen > 0 && this.cryptDataLen < 10000) {
                                try {
                                    const decryptedData = Memory.readByteArray(this.cryptData, this.cryptDataLen);
                                    
                                    send({
                                        type: 'crypto_decrypt',
                                        key_handle: this.cryptKey.toString(),
                                        data_length: this.cryptDataLen,
                                        final: this.cryptFinal
                                    }, decryptedData);
                                } catch (e) {
                                    console.log('[!] 读取解密数据错误: ' + e);
                                }
                            }
                        } else if (funcNm === 'CryptEncrypt' && retval.toInt32() !== 0) {
                            // 成功加密
                            let encryptedLen = 0;
                            try {
                                encryptedLen = Memory.readUInt(args[4]);
                                
                                if (encryptedLen > 0 && encryptedLen < 10000) {
                                    const encryptedData = Memory.readByteArray(this.cryptData, encryptedLen);
                                    
                                    send({
                                        type: 'crypto_encrypt',
                                        key_handle: this.cryptKey.toString(),
                                        data_length: encryptedLen,
                                        final: this.cryptFinal
                                    }, encryptedData);
                                }
                            } catch (e) {
                                console.log('[!] 读取加密数据错误: ' + e);
                            }
                        }
                    }
                }
            });
        } catch (e) {
            console.log('[!] 附加钩子错误 ' + moduleName + '!' + funcName + ': ' + e);
        }
    }
    
    // 扫描VMP模式
    setTimeout(scanForVMPPatterns, 1000);
    
    // 获取保护状态
    setInterval(function() {
        send({
            type: 'protection_status',
            antiDebugAttempts: antiDebugAttempts,
            networkCallsCount: networkData.length,
            fileAccessCount: fileData.length,
            registryAccessCount: registryData.length,
            traceCount: traces.length
        });
    }, 5000);
    
    console.log("[*] 动态分析引擎已启动, 监视保护和解密...");
})();
"""

class DynamicAnalyzer:
    def __init__(self, target_path, output_dir=None):
        self.target_path = os.path.abspath(target_path)
        if not os.path.exists(self.target_path):
            raise FileNotFoundError(f"Target file not found: {self.target_path}")
        
        self.output_dir = output_dir or os.path.join(os.path.dirname(self.target_path), "analysis_results")
        os.makedirs(self.output_dir, exist_ok=True)
        
        self.process = None
        self.session = None
        self.script = None
        self.pid = None
        
        self.memory_dumps = []
        self.network_data = []
        self.protection_data = {
            "anti_debug_attempts": 0,
            "network_connections": 0,
            "file_accesses": 0,
            "registry_accesses": 0
        }
        
        # 初始化API服务器
        self.api_server = None
        self.api_thread = None
        self.api_port = 5000
        
        # 设置结果文件路径
        self.log_file = os.path.join(self.output_dir, "dynamic_analysis.log")
        self.network_dump_file = os.path.join(self.output_dir, "network_data.bin")
        self.report_file = os.path.join(self.output_dir, "analysis_report.html")
        
        # 配置日志
        file_handler = logging.FileHandler(self.log_file)
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logger.addHandler(file_handler)
    
    def _create_api_server(self):
        """创建REST API服务器以支持远程控制"""
        app = Flask(__name__)
        
        @app.route('/status', methods=['GET'])
        def status():
            if self.process and self.session:
                return jsonify({
                    "status": "running" if self.process else "not_running",
                    "pid": self.pid,
                    "memory_dumps": len(self.memory_dumps),
                    "network_captures": len(self.network_data),
                    "protection_stats": self.protection_data
                })
            return jsonify({"status": "not_running"})
            
        @app.route('/patch', methods=['POST'])
        def apply_patch():
            if not self.session:
                return jsonify({"error": "No active session"}), 400
                
            data = request.json
            if not data or not data.get('address') or not data.get('bytes'):
                return jsonify({"error": "Missing address or bytes"}), 400
                
            try:
                address = int(data['address'], 16)
                bytes_data = bytes.fromhex(data['bytes'])
                
                # 使用Frida写入内存
                result = self._apply_memory_patch(address, bytes_data)
                return jsonify({"result": result})
            except Exception as e:
                logger.error(f"Patch error: {str(e)}")
                return jsonify({"error": str(e)}), 500
                
        @app.route('/dump', methods=['POST'])
        def dump_memory():
            if not self.session:
                return jsonify({"error": "No active session"}), 400
                
            data = request.json
            if not data or not data.get('address') or not data.get('size'):
                return jsonify({"error": "Missing address or size"}), 400
                
            try:
                address = int(data['address'], 16)
                size = int(data['size'])
                
                # 使用Frida读取内存
                dump_path = self._dump_memory_region(address, size)
                return jsonify({"result": "success", "path": dump_path})
            except Exception as e:
                logger.error(f"Memory dump error: {str(e)}")
                return jsonify({"error": str(e)}), 500
                
        @app.route('/inject', methods=['POST'])
        def inject_code():
            if not self.session:
                return jsonify({"error": "No active session"}), 400
                
            data = request.json
            if not data or not data.get('code'):
                return jsonify({"error": "Missing JavaScript code"}), 400
                
            try:
                # 注入自定义Frida脚本
                result = self._inject_custom_script(data['code'])
                return jsonify({"result": result})
            except Exception as e:
                logger.error(f"Code injection error: {str(e)}")
                return jsonify({"error": str(e)}), 500
        
        self.api_server = app
        
    def _start_api_server(self):
        """在单独的线程中启动API服务器"""
        def run_api():
            self.api_server.run(host='0.0.0.0', port=self.api_port, debug=False)
            
        self.api_thread = threading.Thread(target=run_api)
        self.api_thread.daemon = True
        self.api_thread.start()
        logger.info(f"API服务器已启动在端口 {self.api_port}")
        
    def _on_message(self, message, data):
        """处理来自Frida脚本的消息"""
        if message['type'] == 'send':
            payload = message['payload']
            msg_type = payload.get('type', 'unknown')
            
            if msg_type == 'memory_exec':
                logger.info(f"检测到可执行内存分配: {payload['address']} (大小: {payload['size']})")
                
            elif msg_type == 'memory_written':
                if data:
                    dump_path = os.path.join(self.output_dir, f"memory_dump_{len(self.memory_dumps)}.bin")
                    with open(dump_path, 'wb') as f:
                        f.write(data)
                    self.memory_dumps.append({
                        'path': dump_path,
                        'source': payload['source'],
                        'target': payload['target'],
                        'size': len(data)
                    })
                    logger.info(f"已保存内存转储到 {dump_path} (大小: {len(data)})")
                    
            elif msg_type == 'network_send' or msg_type == 'network_recv':
                if data:
                    self.network_data.append({
                        'type': msg_type,
                        'socket': payload['socket'],
                        'length': payload['length'],
                        'data': data
                    })
                    logger.info(f"{msg_type}: {payload['length']} 字节")
                    
            elif msg_type == 'network_connect':
                logger.info(f"网络连接到: {payload['address']}:{payload['port']}")
                
            elif msg_type == 'http_request':
                logger.info(f"HTTP请求: {payload['url']}")
                
            elif msg_type == 'vmp_pattern' or msg_type == 'themida_pattern':
                logger.info(f"检测到保护模式: {msg_type} 在 {payload['address']} ({payload['module']})")
                
            elif msg_type == 'protection_status':
                self.protection_data = {
                    "anti_debug_attempts": payload['antiDebugAttempts'],
                    "network_connections": payload['networkCallsCount'],
                    "file_accesses": payload['fileAccessCount'],
                    "registry_accesses": payload['registryAccessCount']
                }
                
            elif msg_type == 'thread_created':
                logger.info(f"新线程: 开始地址 = {payload['start_address']}")
                
            elif msg_type == 'crypto_decrypt' or msg_type == 'crypto_encrypt':
                if data:
                    crypto_dir = os.path.join(self.output_dir, "crypto")
                    os.makedirs(crypto_dir, exist_ok=True)
                    
                    crypto_path = os.path.join(crypto_dir, f"{msg_type}_{len(os.listdir(crypto_dir))}.bin")
                    with open(crypto_path, 'wb') as f:
                        f.write(data)
                    logger.info(f"{msg_type}: {payload['data_length']} 字节, 已保存到 {crypto_path}")
                    
            elif msg_type == 'file_read':
                if data and len(data) > 0:
                    file_dir = os.path.join(self.output_dir, "files")
                    os.makedirs(file_dir, exist_ok=True)
                    
                    file_path = os.path.join(file_dir, f"file_read_{len(os.listdir(file_dir))}.bin")
                    with open(file_path, 'wb') as f:
                        f.write(data)
                    logger.info(f"文件读取: {payload['length']} 字节, 已保存到 {file_path}")
            
        elif message['type'] == 'error':
            logger.error(f"Frida错误: {message['stack']}")
    
    def _apply_memory_patch(self, address, bytes_data):
        """应用内存补丁"""
        if not self.session:
            return "No active session"
            
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
            return "Patch applied successfully"
        except Exception as e:
            logger.error(f"Memory patch error: {str(e)}")
            return f"Error: {str(e)}"
    
    def _dump_memory_region(self, address, size):
        """转储内存区域"""
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
                dump_path = os.path.join(self.output_dir, f"manual_dump_{address:#x}_{size}.bin")
                with open(dump_path, 'wb') as f:
                    f.write(received_data)
                return dump_path
            return None
        except Exception as e:
            logger.error(f"Memory dump error: {str(e)}")
            return None
    
    def _inject_custom_script(self, code):
        """注入自定义Frida脚本"""
        if not self.session:
            return "No active session"
            
        try:
            temp_script = self.session.create_script(code)
            temp_script.on('message', self._on_message)
            temp_script.load()
            return "Script injected successfully"
        except Exception as e:
            logger.error(f"Script injection error: {str(e)}")
            return f"Error: {str(e)}"
    
    def start_analysis(self):
        """启动动态分析"""
        try:
            logger.info(f"启动分析目标: {self.target_path}")
            
            # 创建API服务器
            self._create_api_server()
            self._start_api_server()
            
            # 启动目标程序
            self.process = frida.spawn(self.target_path)
            self.pid = self.process
            logger.info(f"目标已启动, PID: {self.pid}")
            
            # 附加到进程
            self.session = frida.attach(self.pid)
            
            # 创建脚本
            self.script = self.session.create_script(FRIDA_SCRIPT)
            self.script.on('message', self._on_message)
            self.script.load()
            
            # 恢复进程执行
            frida.resume(self.pid)
            logger.info("目标已恢复执行, 分析进行中...")
            
            return True
        except Exception as e:
            logger.error(f"启动分析错误: {str(e)}")
            self.cleanup()
            return False
    
    def attach_to_process(self, pid):
        """附加到现有进程"""
        try:
            logger.info(f"附加到进程: {pid}")
            self.pid = pid
            
            # 创建API服务器
            self._create_api_server()
            self._start_api_server()
            
            # 附加到进程
            self.session = frida.attach(self.pid)
            
            # 创建脚本
            self.script = self.session.create_script(FRIDA_SCRIPT)
            self.script.on('message', self._on_message)
            self.script.load()
            
            logger.info(f"成功附加到进程 {pid}, 分析进行中...")
            
            return True
        except Exception as e:
            logger.error(f"附加到进程错误: {str(e)}")
            self.cleanup()
            return False
    
    def wait_for_completion(self, timeout=None):
        """等待分析完成或直到超时"""
        try:
            if timeout:
                logger.info(f"等待最长 {timeout} 秒...")
                time.sleep(timeout)
            else:
                logger.info("按Ctrl+C停止分析...")
                while True:
                    time.sleep(1)
        except KeyboardInterrupt:
            logger.info("用户中断分析.")
        finally:
            self.cleanup()
            self.generate_report()
    
    def cleanup(self):
        """清理资源"""
        try:
            if self.script:
                self.script.unload()
                self.script = None
                
            if self.session:
                self.session.detach()
                self.session = None
                
            if self.pid:
                try:
                    os.kill(self.pid, signal.SIGTERM)
                except:
                    pass
                self.pid = None
                
            logger.info("资源已清理")
        except Exception as e:
            logger.error(f"清理错误: {str(e)}")
    
    def generate_report(self):
        """生成分析报告"""
        logger.info("生成分析报告...")
        
        # 保存网络数据
        if self.network_data:
            with open(self.network_dump_file, 'wb') as f:
                for entry in self.network_data:
                    if entry.get('data'):
                        f.write(entry['data'])
            logger.info(f"网络数据已保存到 {self.network_dump_file}")
        
        # 生成HTML报告
        try:
            with open(self.report_file, 'w') as f:
                f.write("""<!DOCTYPE html>
<html>
<head>
    <title>动态分析报告</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }
        h1, h2, h3 { color: #333; }
        .section { margin-bottom: 20px; }
        .data-block { background-color: #f5f5f5; padding: 10px; border-radius: 5px; margin-top: 10px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { text-align: left; padding: 8px; border-bottom: 1px solid #ddd; }
        tr:hover { background-color: #f5f5f5; }
    </style>
</head>
<body>
    <h1>动态分析报告</h1>
    <div class="section">
        <h2>分析概述</h2>
        <p>目标文件: """ + self.target_path + """</p>
        <p>分析时间: """ + time.strftime("%Y-%m-%d %H:%M:%S") + """</p>
        
        <h3>保护统计</h3>
        <table>
            <tr><th>指标</th><th>数值</th></tr>
            <tr><td>反调试尝试</td><td>""" + str(self.protection_data['anti_debug_attempts']) + """</td></tr>
            <tr><td>网络连接</td><td>""" + str(self.protection_data['network_connections']) + """</td></tr>
            <tr><td>文件访问</td><td>""" + str(self.protection_data['file_accesses']) + """</td></tr>
            <tr><td>注册表访问</td><td>""" + str(self.protection_data['registry_accesses']) + """</td></tr>
        </table>
    </div>
    
    <div class="section">
        <h2>内存转储</h2>""")
                
                if self.memory_dumps:
                    f.write("""
        <table>
            <tr><th>序号</th><th>源地址</th><th>目标地址</th><th>大小</th><th>文件</th></tr>""")
                    
                    for i, dump in enumerate(self.memory_dumps):
                        f.write(f"""
            <tr>
                <td>{i+1}</td>
                <td>{dump['source']}</td>
                <td>{dump['target']}</td>
                <td>{dump['size']} 字节</td>
                <td>{os.path.basename(dump['path'])}</td>
            </tr>""")
                    
                    f.write("""
        </table>""")
                else:
                    f.write("""
        <p>未检测到内存转储</p>""")
                
                f.write("""
    </div>
    
    <div class="section">
        <h2>网络活动</h2>""")
                
                if self.network_data:
                    f.write("""
        <table>
            <tr><th>类型</th><th>长度</th><th>详细信息</th></tr>""")
                    
                    for entry in self.network_data:
                        size = entry.get('length', 0)
                        socket = entry.get('socket', 'Unknown')
                        f.write(f"""
            <tr>
                <td>{entry['type']}</td>
                <td>{size} 字节</td>
                <td>Socket: {socket}</td>
            </tr>""")
                    
                    f.write("""
        </table>""")
                else:
                    f.write("""
        <p>未检测到网络活动</p>""")
                
                f.write("""
    </div>
    
    <div class="section">
        <h2>建议</h2>""")
                
                # 根据检测到的保护添加建议
                if self.protection_data['anti_debug_attempts'] > 0:
                    f.write("""
        <p>检测到<strong>反调试保护</strong>. 建议使用以下技术绕过:</p>
        <ul>
            <li>使用内存补丁绕过IsDebuggerPresent检查</li>
            <li>挂钩CheckRemoteDebuggerPresent并修改结果</li>
            <li>使用虚拟化环境隐藏调试器痕迹</li>
        </ul>""")
                
                if self.protection_data['network_connections'] > 0:
                    f.write("""
        <p>检测到<strong>网络验证</strong>. 建议使用以下技术绕过:</p>
        <ul>
            <li>使用网络代理服务器模拟验证服务器</li>
            <li>修补网络通信函数以返回成功结果</li>
            <li>分析并克隆验证协议</li>
        </ul>""")
                
                if len(self.memory_dumps) > 0:
                    f.write("""
        <p>检测到<strong>动态代码</strong>. 建议:</p>
        <ul>
            <li>分析内存转储中的解密代码</li>
            <li>使用IDA Pro或Ghidra分析转储的内存区域</li>
            <li>寻找解密后的关键功能</li>
        </ul>""")
                
                f.write("""
    </div>
</body>
</html>""")
                
            logger.info(f"HTML报告已保存到 {self.report_file}")
        except Exception as e:
            logger.error(f"生成报告错误: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description='动态分析引擎')
    parser.add_argument('target', help='目标可执行文件路径或进程ID')
    parser.add_argument('-o', '--output', help='输出目录')
    parser.add_argument('-t', '--timeout', type=int, help='分析超时(秒)')
    parser.add_argument('-p', '--pid', action='store_true', help='目标是PID而非文件路径')
    
    args = parser.parse_args()
    
    try:
        if args.pid:
            # 附加到现有进程
            analyzer = DynamicAnalyzer("/tmp/dummy", args.output)
            if analyzer.attach_to_process(int(args.target)):
                analyzer.wait_for_completion(args.timeout)
        else:
            # 启动新进程分析
            analyzer = DynamicAnalyzer(args.target, args.output)
            if analyzer.start_analysis():
                analyzer.wait_for_completion(args.timeout)
    except Exception as e:
        logger.error(f"错误: {str(e)}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
