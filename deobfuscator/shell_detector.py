#!/usr/bin/env python3
"""
高级壳检测和分析工具
支持多种保护方案检测和详细分析报告
"""
import os
import sys
import pefile
import hashlib
import struct
import argparse
import tempfile
import subprocess
import logging
import math
import json
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Union, Any, Tuple

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("shell_detector.log")
    ]
)
logger = logging.getLogger(__name__)

try:
    import yara
except ImportError:
    logger.error("未安装yara-python。请运行: pip install yara-python")
    sys.exit(1)

# 综合壳识别规则库
RULES = """
rule UPX_Packer {
    strings:
        $upx1 = "UPX!" ascii
        $upx2 = "UPX0" ascii
        $upx3 = "UPX1" ascii
        $upx4 = "UPX2" ascii
        $upx_sig = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF }
    condition:
        2 of them
}

rule VMProtect {
    strings:
        $vmp1 = "VMProtect" ascii wide
        $vmp2 = ".vmp0" ascii
        $vmp3 = ".vmp1" ascii
        $vmp4 = "vmp_" ascii
        $vmp_sig1 = { EB 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 }
        $vmp_sig2 = { 68 ?? ?? ?? ?? E9 ?? ?? ?? ?? 00 00 }
        $vmp_sig3 = { B8 ?? ?? ?? ?? BA ?? ?? ?? ?? 03 C2 FF E0 }
    condition:
        any of them
}

rule Themida_Winlicense {
    strings:
        $th1 = "Themida" ascii wide
        $th2 = "WinLicense" ascii wide
        $th3 = ".themida" ascii
        $th_sig1 = { 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 }
        $th_sig2 = { 8B C5 8B D4 89 45 FC 89 55 F8 8D 45 F0 50 8D 45 FC 50 FF 75 10 }
        $th_sig3 = { B8 ?? ?? ?? ?? 60 0B C0 74 58 E8 00 00 00 00 }
    condition:
        any of them
}

rule Enigma_Protector {
    strings:
        $enigma1 = "Enigma Protector" ascii wide
        $enigma2 = ".enigma" ascii
        $enigma3 = { 60 E8 00 00 00 00 5D 83 ED 06 81 ED ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 }
        $enigma4 = { 60 E8 00 00 00 00 5D 83 C5 ?? 81 ED ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
        $enigma_sig = { 00 00 00 00 ?? 00 00 00 00 00 00 00 ?? 00 00 00 00 00 00 00 ?? 01 00 00 00 00 00 00 33 00 }
    condition:
        any of them
}

rule ASProtect {
    strings:
        $asp1 = "ASProtect" ascii wide
        $asp2 = ".aspack" ascii
        $asp3 = ".adata" ascii
        $asp4 = { 60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? BB ?? ?? ?? ?? 03 DD }
        $asp5 = { 68 ?? ?? ?? ?? E9 ?? ?? ?? FF }
        $asp_sig = { 90 60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? BB ?? ?? ?? ?? 03 DD 2B 9D }
    condition:
        any of them
}

rule CodeVirtualizer {
    strings:
        $cv1 = "CodeVirtualizer" ascii wide
        $cv2 = "VirtualizerSDK" ascii wide
        $cv3 = { 60 9C 54 24 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 }
        $cv_sig = { E9 ?? ?? ?? ?? 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 }
    condition:
        any of them
}

rule Obsidium {
    strings:
        $obsidium1 = "Obsidium" ascii wide
        $obsidium2 = { EB 02 ?? ?? E8 25 00 00 00 EB 04 ?? ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 22 EB 01 ?? 33 C0 EB 02 ?? ?? C3 EB 02 ?? ?? EB 04 ?? ?? ?? ?? }
    condition:
        any of them
}

rule Custom_NET_Obfuscator {
    strings:
        $net1 = "_Closure$__" ascii wide
        $net2 = "DotfuscatorAttribute" ascii
        $net3 = "ObfuscatedByGoliath" ascii
        $net4 = "SmartAssembly.Attributes" ascii
        $net5 = "Babel.ObfuscatorAttribute" ascii
        $net6 = "SecureTeam.Attributes" ascii
        $net7 = "ConfusedByAttribute" ascii
        $net8 = "DotNetPatcher" ascii wide
        $net9 = "SmartAssembly" ascii wide
        $net10 = "ConfuserEx" ascii wide
        $net11 = "dnGuard" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        any of them
}

rule Network_Protection {
    strings:
        $net1 = "CheckLicense" ascii wide
        $net2 = "VerifySignature" ascii wide
        $net3 = "WinHttpRequest" ascii wide
        $net4 = "WSAStartup" ascii
        $net5 = "connect" ascii
        $net6 = "recv" ascii
        $net7 = "send" ascii
        $net8 = "gethostbyname" ascii
        $net9 = "InternetOpenUrl" ascii
        $net10 = "HttpSendRequest" ascii
        $net11 = "InternetReadFile" ascii
        $net12 = "WinHttpConnect" ascii
    condition:
        uint16(0) == 0x5A4D and
        4 of them
}

rule AntiDebug_Protection {
    strings:
        $ad1 = "IsDebuggerPresent" ascii
        $ad2 = "CheckRemoteDebuggerPresent" ascii
        $ad3 = "OutputDebugString" ascii
        $ad4 = "FindWindow" ascii
        $ad5 = "GetTickCount" ascii
        $ad6 = "QueryPerformanceCounter" ascii
        $ad7 = "ZwQueryInformationProcess" ascii
        $ad8 = "IsProcessorFeaturePresent" ascii
        $ad9 = "NtGlobalFlag" ascii
        $ad10 = "CloseHandle" ascii 
        $ad11 = "NtQueryInformationProcess" ascii
        $ad12 = "DebugActiveProcess" ascii
    condition:
        uint16(0) == 0x5A4D and
        4 of them
}

rule PEtite_Packer {
    strings:
        $petite1 = "PEtite" ascii wide
        $petite2 = "petite" ascii wide
        $petite_sig = { B8 ?? ?? ?? ?? 66 9C 60 50 }
    condition:
        any of them
}

rule Armadillo {
    strings:
        $armadillo1 = "Armadillo" ascii wide
        $armadillo2 = ".NET DLL by Silicon Realms Toolworks" ascii wide
        $armadillo_sig1 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }
        $armadillo_sig2 = { 60 E8 ?? ?? ?? ?? 5D 50 51 52 53 56 57 55 E8 ?? ?? ?? ?? }
    condition:
        any of them
}

rule MPRESS {
    strings:
        $mpress1 = ".MPRESS1" ascii wide
        $mpress2 = ".MPRESS2" ascii wide
        $mpress_sig = { 60 E8 00 00 00 00 58 05 ?? ?? ?? ?? 8B 30 03 F0 2B C0 }
    condition:
        any of them
}

rule AntiVM_Techniques {
    strings:
        $vm1 = "VMware" ascii wide nocase
        $vm2 = "VBox" ascii wide nocase
        $vm3 = "VIRTUAL" ascii wide nocase
        $vm4 = "VPCEXT" ascii
        $vm5 = "sbiedll.dll" ascii wide nocase
        $vm6 = "Xen" ascii wide nocase
        $vm7 = "QEMU" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        3 of them
}

rule Golang_Binary {
    strings:
        $go1 = "Go build ID:" ascii wide
        $go2 = "go.buildid" ascii wide
        $go3 = "golang" ascii wide nocase
        $go4 = "runtime.newobject" ascii
        $go5 = "runtime.morestack" ascii
    condition:
        uint16(0) == 0x5A4D and
        2 of them
}
"""

class PackerDetector:
    """壳识别和分析类，使用YARA规则和PE分析技术"""
    
    def __init__(self, custom_rules: Optional[str] = None):
        """
        初始化壳检测器
        
        Args:
            custom_rules: 可选的自定义YARA规则
        """
        try:
            # 合并默认规则和自定义规则
            rules_to_compile = RULES
            if custom_rules:
                rules_to_compile += "\n" + custom_rules
                
            self.compiled_rules = yara.compile(source=rules_to_compile)
            self.custom_rules_added = bool(custom_rules)
            
            # 缓存支持
            self.entropy_cache = {}
            
            logger.info("PackerDetector 初始化成功" + 
                       (" (包含自定义规则)" if self.custom_rules_added else ""))
        except Exception as e:
            logger.error(f"初始化壳检测器失败: {e}")
            raise
    
    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """
        分析文件并检测壳或保护
        
        Args:
            file_path: 要分析的文件路径
            
        Returns:
            包含分析结果的字典
        """
        try:
            # 确保文件存在
            if not os.path.exists(file_path):
                return {"error": f"文件不存在: {file_path}"}
                
            # 基本文件信息
            start_time = time.time()
            file_size = os.path.getsize(file_path)
            
            with open(file_path, 'rb') as f:
                file_data = f.read()
                
            md5_hash = hashlib.md5(file_data).hexdigest()
            sha1_hash = hashlib.sha1(file_data).hexdigest()
            sha256_hash = hashlib.sha256(file_data).hexdigest()
            
            # 检查文件是否为有效的PE
            is_pe = file_data.startswith(b'MZ')
            
            # 文件全局熵值
            global_entropy = self._calculate_entropy(file_data)
            
            # YARA 匹配
            matches = self.compiled_rules.match(data=file_data)
            detected_packers = [match.rule for match in matches]
            
            # 分析结果结构
            result = {
                "file_path": file_path,
                "file_name": os.path.basename(file_path),
                "file_size": file_size,
                "file_size_human": self._human_readable_size(file_size),
                "md5": md5_hash,
                "sha1": sha1_hash,
                "sha256": sha256_hash,
                "global_entropy": global_entropy,
                "is_pe": is_pe,
                "detected_packers": detected_packers,
                "analysis_time": time.time() - start_time
            }
            
            # 分析PE结构 (如果是PE文件)
            if is_pe:
                pe_info = self._analyze_pe(file_path, file_data)
                result.update({"pe_info": pe_info})
            
            # 添加额外检测
            additional_packers = self._additional_detection(file_path, file_data)
            if additional_packers:
                result["detected_packers"].extend(additional_packers)
                result["detected_packers"] = list(set(result["detected_packers"]))
            
            if not result["detected_packers"]:
                protection_score = self._calculate_protection_score(result)
                if protection_score > 70:
                    result["detected_packers"] = ["Possible Custom/Unknown Packer"]
                else:
                    result["detected_packers"] = ["No Protection Detected"]
                
                result["protection_score"] = protection_score
            
            # 建议脱壳策略
            result["unpacking_strategy"] = self._suggest_unpacking_strategy(result)
            
            logger.info(f"成功分析文件: {file_path}")
            return result
        except Exception as e:
            logger.error(f"分析文件 {file_path} 出错: {e}")
            return {
                "file_path": file_path,
                "error": str(e)
            }
    
    def analyze_directory(self, directory: str, recursive: bool = False, 
                         max_workers: int = 4) -> List[Dict[str, Any]]:
        """
        分析目录中的所有文件
        
        Args:
            directory: 要分析的目录
            recursive: 是否递归分析子目录
            max_workers: 最大并行工作线程数
            
        Returns:
            包含所有文件分析结果的列表
        """
        if not os.path.isdir(directory):
            logger.error(f"找不到目录: {directory}")
            return [{"error": f"找不到目录: {directory}"}]
        
        file_paths = []
        
        if recursive:
            for root, _, files in os.walk(directory):
                for file in files:
                    file_paths.append(os.path.join(root, file))
        else:
            file_paths = [os.path.join(directory, f) for f in os.listdir(directory) 
                         if os.path.isfile(os.path.join(directory, f))]
        
        logger.info(f"开始分析 {len(file_paths)} 个文件...")
        
        # 并行分析文件
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = list(executor.map(self.analyze_file, file_paths))
        
        return results
        
    def _calculate_entropy(self, data: bytes) -> float:
        """
        计算数据的Shannon熵
        
        Args:
            data: 要计算熵的二进制数据
            
        Returns:
            Shannon熵值 (0-8)
        """
        if not data:
            return 0
            
        # 使用数据的哈希作为缓存键以避免重复计算
        data_hash = hashlib.md5(data[:4096] + data[-4096:]).hexdigest()
        if data_hash in self.entropy_cache:
            return self.entropy_cache[data_hash]
        
        # 字节频率统计
        byte_count = {}
        for byte in data:
            byte_count[byte] = byte_count.get(byte, 0) + 1
                
        # 计算熵
        entropy = 0
        for count in byte_count.values():
            probability = count / len(data)
            entropy -= probability * (math.log(probability, 2))
        
        # 缓存结果
        self.entropy_cache[data_hash] = entropy
        return entropy
    
    def _analyze_pe(self, file_path: str, file_data: bytes) -> Dict[str, Any]:
        """
        分析PE文件结构
        
        Args:
            file_path: PE文件路径
            file_data: 文件数据
            
        Returns:
            包含PE分析结果的字典
        """
        try:
            pe = pefile.PE(data=file_data)
            high_entropy_sections = []
            suspicious_sections = []
            all_sections = []
            
            # 分析区段
            for section in pe.sections:
                section_name = section.Name.decode('utf-8', 'ignore').strip('\x00')
                section_data = section.get_data()
                section_entropy = self._calculate_entropy(section_data)
                
                section_info = {
                    "name": section_name,
                    "virtual_address": hex(section.VirtualAddress),
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_size": section.SizeOfRawData,
                    "entropy": section_entropy,
                    "characteristics": hex(section.Characteristics),
                    "executable": bool(section.Characteristics & 0x20000000),
                    "readable": bool(section.Characteristics & 0x40000000),
                    "writable": bool(section.Characteristics & 0x80000000)
                }
                
                all_sections.append(section_info)
                
                if section_entropy > 7.0:
                    high_entropy_sections.append(section_info)
                
                if section.SizeOfRawData == 0 and section.Misc_VirtualSize > 0:
                    suspicious_sections.append(section_info)
            
            # 分析导入表
            suspicious_imports = []
            normal_imports = []
            import_count = 0
            
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', 'ignore').lower()
                    functions = []
                    
                    for imp in entry.imports:
                        func_name = "ORDINAL" if not imp.name else imp.name.decode('utf-8', 'ignore')
                        functions.append(func_name)
                    
                    import_info = {
                        "dll": dll_name,
                        "functions": functions
                    }
                    
                    import_count += len(functions)
                    
                    if any(x in dll_name for x in ['crypt', 'ssl', 'winhttp', 'socket', 'wsock', 'inet']):
                        suspicious_imports.append(import_info)
                    else:
                        normal_imports.append(import_info)
            
            # 分析TLS回调
            has_tls_callbacks = False
            tls_callbacks = []
            
            if hasattr(pe, 'DIRECTORY_ENTRY_TLS') and pe.DIRECTORY_ENTRY_TLS:
                has_tls_callbacks = True
                tls_directory = pe.DIRECTORY_ENTRY_TLS.struct
                
                if hasattr(tls_directory, 'AddressOfCallBacks'):
                    callback_array_rva = tls_directory.AddressOfCallBacks - pe.OPTIONAL_HEADER.ImageBase
                    callback_array_offset = pe.get_offset_from_rva(callback_array_rva)
                    
                    # 读取回调函数地址
                    callback_ptr = callback_array_offset
                    while True:
                        try:
                            addr_bytes = file_data[callback_ptr:callback_ptr+pe.OPTIONAL_HEADER.ImageBase.size]
                            if len(addr_bytes) < pe.OPTIONAL_HEADER.ImageBase.size or all(b == 0 for b in addr_bytes):
                                break
                                
                            address = int.from_bytes(addr_bytes, 
                                                    byteorder='little', 
                                                    signed=False)
                            if address == 0:
                                break
                                
                            tls_callbacks.append(hex(address))
                            callback_ptr += pe.OPTIONAL_HEADER.ImageBase.size
                        except:
                            break
            
            # 获取入口点信息
            ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            ep_offset = pe.get_offset_from_rva(ep_rva)
            ep_bytes = file_data[ep_offset:ep_offset+16]
            ep_signature = ' '.join([f'{b:02X}' for b in ep_bytes])
            
            # 检查是否有资源
            has_resources = hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE')
            resource_count = 0
            
            if has_resources:
                def count_resources(rsrc):
                    count = 0
                    if hasattr(rsrc, 'entries'):
                        for entry in rsrc.entries:
                            if hasattr(entry, 'data'):
                                count += 1
                            else:
                                count += count_resources(entry)
                    return count
                
                resource_count = count_resources(pe.DIRECTORY_ENTRY_RESOURCE)
            
            # 检查是否为.NET程序
            is_dotnet = hasattr(pe, 'DIRECTORY_ENTRY_COM_DESCRIPTOR') and pe.DIRECTORY_ENTRY_COM_DESCRIPTOR
            
            # 获取编译时间
            timestamp = pe.FILE_HEADER.TimeDateStamp
            compilation_date = "N/A"
            
            if timestamp != 0:
                try:
                    compilation_date = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
                except:
                    compilation_date = f"Invalid ({timestamp})"
            
            # 检查调试信息
            has_debug_info = hasattr(pe, 'DIRECTORY_ENTRY_DEBUG') and pe.DIRECTORY_ENTRY_DEBUG
            
            # 检查异常表
            has_exception_table = hasattr(pe, 'DIRECTORY_ENTRY_EXCEPTION') and pe.DIRECTORY_ENTRY_EXCEPTION
            
            pe_info = {
                "machine_type": pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine, "Unknown"),
                "subsystem": pefile.SUBSYSTEM_TYPE.get(pe.OPTIONAL_HEADER.Subsystem, "Unknown"),
                "dll": pe.is_dll(),
                "exe": pe.is_exe(),
                "driver": pe.is_driver(),
                "compiled_time": compilation_date,
                "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                "ep_signature": ep_signature,
                "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
                "sections": all_sections,
                "high_entropy_sections": high_entropy_sections,
                "suspicious_sections": suspicious_sections,
                "normal_imports": normal_imports,
                "suspicious_imports": suspicious_imports,
                "import_count": import_count,
                "has_tls_callbacks": has_tls_callbacks,
                "tls_callbacks": tls_callbacks,
                "has_resources": has_resources,
                "resource_count": resource_count,
                "is_dotnet": is_dotnet,
                "has_debug_info": has_debug_info,
                "has_exception_table": has_exception_table,
                "architecture": "32-bit" if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['I386'] else "64-bit"
            }
            
            pe.close()
            return pe_info
        except Exception as e:
            logger.error(f"PE分析错误: {e}")
            return {"error": str(e)}
    
    def _additional_detection(self, file_path: str, file_data: bytes) -> List[str]:
        """
        执行额外的检测逻辑
        
        Args:
            file_path: 文件路径
            file_data: 文件数据
            
        Returns:
            检测到的额外保护列表
        """
        additional = []
        
        # 检查文件头部特征
        if file_data.startswith(b'MZ'):
            # 检查.NET程序特征
            if b'_CorExeMain' in file_data:
                additional.append('.NET Assembly')
            
            # 检查Python打包程序
            if b'PYZ' in file_data and (b'python' in file_data.lower() or b'py2exe' in file_data.lower() or b'pyinstaller' in file_data.lower()):
                additional.append('Python Packed')
            
            # 检查Java程序
            if b'META-INF' in file_data and b'PK\x03\x04' in file_data:
                additional.append('Java JAR/Class')
            
            # 检查AutoIt脚本
            if b'AU3!' in file_data:
                additional.append('AutoIt Script')
                
            # 检查NSIS安装程序
            if b'Nullsoft' in file_data:
                additional.append('NSIS Installer')
                
            # 检查加密文件
            if self._calculate_entropy(file_data) > 7.8:
                additional.append('Highly Encrypted/Compressed')
        
        # 运行strings并查找特征 (仅对大文件进行)
        if len(file_data) > 1024*1024:  # 大于1MB时使用外部strings
            try:
                strings_output = subprocess.check_output(['strings', file_path], stderr=subprocess.PIPE, timeout=10)
                strings_output = strings_output.decode('utf-8', 'ignore').lower()
                
                # 检查.NET特征
                if 'mscorlib' in strings_output or 'system.runtime' in strings_output:
                    additional.append('.NET Assembly')
                    
                # 检查Python特征
                if ('python' in strings_output and 
                    ('import' in strings_output or 'module' in strings_output)):
                    additional.append('Python Packed')
                    
                # 检查Java特征    
                if 'java/lang' in strings_output and 'class' in strings_output:
                    additional.append('Java JAR/Class')
                    
                # 检查Go语言特征
                if 'go1.' in strings_output or 'golang' in strings_output:
                    additional.append('Go Binary')
                    
                # 检查Rust特征
                if 'rust_panic' in strings_output or 'rustc' in strings_output:
                    additional.append('Rust Binary')
                    
                # 检查其他壳
                if 'safengine' in strings_output:
                    additional.append('SafeEngine Shielden')
                    
                if 'delphi' in strings_output:
                    additional.append('Delphi Binary')
            except:
                pass
        else:
            # 对于小文件，在内存中执行strings操作
            strings_data = self._extract_strings(file_data)
            
            if any(s in strings_data for s in ['mscorlib', 'system.runtime']):
                additional.append('.NET Assembly')
                
            if 'python' in strings_data and any(s in strings_data for s in ['import', 'module']):
                additional.append('Python Packed')
        
        # 去重
        return list(set(additional))
    
    def _extract_strings(self, data: bytes, min_length: int = 4) -> str:
        """
        从二进制数据中提取ASCII和UTF-16字符串
        
        Args:
            data: 二进制数据
            min_length: 最小字符串长度
            
        Returns:
            提取的字符串列表连接成的字符串
        """
        result = []
        current = bytearray()
        
        # 提取ASCII字符串
        for byte in data:
            if 32 <= byte <= 126:  # 可打印ASCII字符
                current.append(byte)
            else:
                if len(current) >= min_length:
                    result.append(current.decode('ascii', errors='ignore'))
                current = bytearray()
        
        if len(current) >= min_length:
            result.append(current.decode('ascii', errors='ignore'))
        
        # 提取UTF-16字符串 (简化版)
        i = 0
        while i < len(data) - 1:
            if data[i] >= 32 and data[i] <= 126 and data[i+1] == 0:
                # 可能的UTF-16LE字符串
                current = bytearray()
                j = i
                while j < len(data) - 1 and data[j] >= 32 and data[j] <= 126 and data[j+1] == 0:
                    current.append(data[j])
                    j += 2
                
                if len(current) >= min_length:
                    result.append(current.decode('ascii', errors='ignore'))
                i = j
            else:
                i += 1
        
        return ' '.join(result).lower()
    
    def _calculate_protection_score(self, result: Dict[str, Any]) -> int:
        """
        计算文件被保护的可能性得分
        
        Args:
            result: 分析结果字典
            
        Returns:
            保护得分 (0-100)
        """
        score = 0
        
        # 1. 检查全局熵值
        global_entropy = result.get("global_entropy", 0)
        if global_entropy > 7.5:
            score += 30
        elif global_entropy > 7.0:
            score += 20
        elif global_entropy > 6.5:
            score += 10
        
        # 2. 检查PE信息
        pe_info = result.get("pe_info", {})
        
        # 2.1 高熵区段
        high_entropy_sections = pe_info.get("high_entropy_sections", [])
        if len(high_entropy_sections) > 3:
            score += 25
        elif len(high_entropy_sections) > 0:
            score += 15
        
        # 2.2 可疑区段
        suspicious_sections = pe_info.get("suspicious_sections", [])
        if suspicious_sections:
            score += 10
        
        # 2.3 TLS回调
        if pe_info.get("has_tls_callbacks", False):
            score += 15
        
        # 2.4 可疑导入
        suspicious_imports = pe_info.get("suspicious_imports", [])
        if len(suspicious_imports) > 2:
            score += 10
        
        # 3. 限制得分范围
        return min(100, max(0, score))
    
    def _suggest_unpacking_strategy(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """
        基于分析结果建议脱壳策略
        
        Args:
            result: 分析结果字典
            
        Returns:
            包含脱壳建议的字典
        """
        packers = result.get("detected_packers", [])
        pe_info = result.get("pe_info", {})
        
        # 默认策略
        strategy = {
            "recommended_method": "generic",
            "difficulty": "medium",
            "tools": ["generic_dumper", "memory_scanner"],
            "steps": ["使用通用脱壳工具", "监视内存分配", "找到OEP后转储"]
        }
        
        # 按照优先级处理不同的保护
        if any("UPX" in p for p in packers):
            strategy = {
                "recommended_method": "static",
                "difficulty": "easy",
                "tools": ["upx", "upx_custom_variant"],
                "steps": [
                    "尝试标准UPX脱壳: upx -d input.exe -o output.exe",
                    "如果失败，尝试修复UPX头部",
                    "对于变种，使用通用内存转储工具"
                ]
            }
        elif any("VMProtect" in p for p in packers):
            strategy = {
                "recommended_method": "dynamic",
                "difficulty": "hard",
                "tools": ["scylla", "x64dbg", "vmp_specific_tools"],
                "steps": [
                    "使用调试器附加并绕过反调试",
                    "找到VM入口处的转换例程",
                    "等待解密完成后在OEP处停止",
                    "使用Scylla转储并修复IAT"
                ]
            }
        elif any("Themida" in p for p in packers) or any("WinLicense" in p for p in packers):
            strategy = {
                "recommended_method": "dynamic",
                "difficulty": "very_hard",
                "tools": ["themida_unpacker", "x64dbg", "hw_breakpoints"],
                "steps": [
                    "使用专用的Themida脱壳工具",
                    "设置硬件断点监视关键内存区域",
                    "使用反VM规避技术",
                    "使用自定义跟踪记录所有执行跳转",
                    "使用高级内存转储工具"
                ]
            }
        elif any(".NET" in p for p in packers) or pe_info.get("is_dotnet", False):
            strategy = {
                "recommended_method": "static",
                "difficulty": "medium",
                "tools": ["de4dot", "dnspy", "ilspy"],
                "steps": [
                    "使用de4dot进行初步反混淆",
                    "使用dnSpy或ILSpy分析反编译代码",
                    "修复字符串加密",
                    "重建类结构"
                ]
            }
        elif any("ASPack" in p for p in packers) or any("ASProtect" in p for p in packers):
            strategy = {
                "recommended_method": "dynamic",
                "difficulty": "medium",
                "tools": ["aspr_unpacker", "scylla", "x64dbg"],
                "steps": [
                    "使用专用ASProtect脱壳工具",
                    "如果失败，使用通用脱壳方法",
                    "在最终跳转前捕获OEP",
                    "使用Scylla修复导入表"
                ]
            }
        elif any("Python" in p for p in packers):
            strategy = {
                "recommended_method": "static",
                "difficulty": "medium",
                "tools": ["pyinstxtractor", "uncompyle6", "pycdc"],
                "steps": [
                    "使用PyInstaller Extractor提取pyc文件",
                    "使用uncompyle6或pycdc反编译pyc文件",
                    "重构Python代码逻辑"
                ]
            }
        
        # 添加一般性建议
        general_tips = []
        
        if pe_info.get("has_tls_callbacks", False):
            general_tips.append("注意TLS回调函数可能用于反调试")
        
        if len(pe_info.get("high_entropy_sections", [])) > 0:
            general_tips.append("文件包含高熵区段，表明存在加密或压缩")
        
        if len(pe_info.get("suspicious_imports", [])) > 0:
            general_tips.append("检测到可疑网络或加密API调用，可能存在网络验证")
        
        strategy["general_tips"] = general_tips
        return strategy
    
    def _human_readable_size(self, size: int) -> str:
        """
        将字节大小转换为人类可读格式
        
        Args:
            size: 字节大小
            
        Returns:
            人类可读的大小字符串
        """
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024 or unit == 'TB':
                return f"{size:.2f} {unit}" if unit != 'B' else f"{size} {unit}"
            size /= 1024

def generate_report(result: Dict[str, Any], output_format: str = "text") -> str:
    """
    生成分析报告
    
    Args:
        result: 分析结果字典
        output_format: 报告格式 (text, json, html)
        
    Returns:
        格式化的报告字符串
    """
    if output_format == "json":
        return json.dumps(result, indent=2)
        
    elif output_format == "html":
        # 简单HTML报告
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>壳检测报告</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                h1, h2, h3 { color: #333; }
                .section { margin-bottom: 20px; }
                .success { color: green; }
                .warning { color: orange; }
                .danger { color: red; }
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                tr:nth-child(even) { background-color: #f2f2f2; }
            </style>
        </head>
        <body>
            <h1>壳检测报告</h1>
            <div class="section">
                <h2>文件信息</h2>
                <table>
                    <tr><td>文件路径</td><td>{}</td></tr>
                    <tr><td>文件大小</td><td>{}</td></tr>
                    <tr><td>MD5哈希</td><td>{}</td></tr>
                    <tr><td>全局熵值</td><td>{:.2f}</td></tr>
                </table>
            </div>
        """.format(
            result.get("file_path", "N/A"),
            result.get("file_size_human", "N/A"),
            result.get("md5", "N/A"),
            result.get("global_entropy", 0)
        )
        
        # 添加检测到的保护
        html += """
            <div class="section">
                <h2>检测到的保护</h2>
                <ul>
        """
        
        for packer in result.get("detected_packers", []):
            html += f"<li>{packer}</li>"
            
        html += """
                </ul>
            </div>
        """
        
        # 添加PE信息
        if "pe_info" in result:
            pe_info = result["pe_info"]
            html += """
                <div class="section">
                    <h2>PE文件信息</h2>
                    <table>
                        <tr><td>机器类型</td><td>{}</td></tr>
                        <tr><td>子系统</td><td>{}</td></tr>
                        <tr><td>类型</td><td>{}</td></tr>
                        <tr><td>编译时间</td><td>{}</td></tr>
                        <tr><td>入口点</td><td>{}</td></tr>
                        <tr><td>导入函数数量</td><td>{}</td></tr>
                        <tr><td>TLS回调</td><td>{}</td></tr>
                    </table>
                </div>
            """.format(
                pe_info.get("machine_type", "N/A"),
                pe_info.get("subsystem", "N/A"),
                "DLL" if pe_info.get("dll", False) else "EXE",
                pe_info.get("compiled_time", "N/A"),
                pe_info.get("entry_point", "N/A"),
                pe_info.get("import_count", 0),
                "是" if pe_info.get("has_tls_callbacks", False) else "否"
            )
            
            # 添加区段信息
            html += """
                <div class="section">
                    <h3>区段信息</h3>
                    <table>
                        <tr>
                            <th>名称</th>
                            <th>虚拟大小</th>
                            <th>原始大小</th>
                            <th>熵值</th>
                            <th>属性</th>
                        </tr>
            """
            
            for section in pe_info.get("sections", []):
                entropy_class = ""
                if section.get("entropy", 0) > 7.0:
                    entropy_class = "danger"
                elif section.get("entropy", 0) > 6.5:
                    entropy_class = "warning"
                    
                html += """
                    <tr>
                        <td>{}</td>
                        <td>{}</td>
                        <td>{}</td>
                        <td class="{}">{:.2f}</td>
                        <td>{}</td>
                    </tr>
                """.format(
                    section.get("name", "N/A"),
                    section.get("virtual_size", 0),
                    section.get("raw_size", 0),
                    entropy_class, section.get("entropy", 0),
                    "可执行" if section.get("executable", False) else "" +
                    " 可写" if section.get("writable", False) else ""
                )
            
            html += """
                    </table>
                </div>
            """
        
        # 添加脱壳建议
        if "unpacking_strategy" in result:
            strategy = result["unpacking_strategy"]
            
            html += """
                <div class="section">
                    <h2>脱壳建议</h2>
                    <p><strong>推荐方法:</strong> {}</p>
                    <p><strong>难度:</strong> {}</p>
                    <p><strong>建议工具:</strong></p>
                    <ul>
            """.format(
                strategy.get("recommended_method", "通用方法"),
                {
                    "easy": "简单", 
                    "medium": "中等", 
                    "hard": "困难", 
                    "very_hard": "非常困难"
                }.get(strategy.get("difficulty", "medium"), "中等")
            )
            
            for tool in strategy.get("tools", []):
                html += f"<li>{tool}</li>"
                
            html += """
                    </ul>
                    <p><strong>建议步骤:</strong></p>
                    <ol>
            """
            
            for step in strategy.get("steps", []):
                html += f"<li>{step}</li>"
                
            html += """
                    </ol>
                </div>
            """
            
            # 一般提示
            if "general_tips" in strategy and strategy["general_tips"]:
                html += """
                    <div class="section">
                        <h3>一般提示</h3>
                        <ul>
                """
                
                for tip in strategy["general_tips"]:
                    html += f"<li>{tip}</li>"
                    
                html += """
                        </ul>
                    </div>
                """
        
        html += """
        </body>
        </html>
        """
        
        return html
    
    else:  # text格式 (默认)
        report = []
        
        # 标题
        report.append("=" * 50)
        report.append("壳检测报告")
        report.append("=" * 50)
        
        # 基本信息
        report.append(f"文件: {result.get('file_path', 'N/A')}")
        report.append(f"大小: {result.get('file_size_human', 'N/A')} ({result.get('file_size', 0)} 字节)")
        report.append(f"MD5: {result.get('md5', 'N/A')}")
        report.append(f"SHA1: {result.get('sha1', 'N/A')}")
        report.append(f"全局熵值: {result.get('global_entropy', 0):.2f}")
        
        # 检测到的保护
        report.append("\n检测到的保护:")
        for packer in result.get("detected_packers", []):
            report.append(f"  - {packer}")
        
        # PE信息
        if "pe_info" in result:
            pe_info = result["pe_info"]
            report.append("\nPE文件信息:")
            report.append(f"  架构: {pe_info.get('architecture', 'Unknown')}")
            report.append(f"  机器类型: {pe_info.get('machine_type', 'Unknown')}")
            report.append(f"  子系统: {pe_info.get('subsystem', 'Unknown')}")
            report.append(f"  类型: {'DLL' if pe_info.get('dll', False) else 'EXE'}")
            report.append(f"  编译时间: {pe_info.get('compiled_time', 'N/A')}")
            report.append(f"  入口点: {pe_info.get('entry_point', 'N/A')}")
            
            # 添加入口点特征码
            report.append(f"  入口点特征码: {pe_info.get('ep_signature', 'N/A')}")
            
            # 高熵区段
            if "high_entropy_sections" in pe_info and pe_info["high_entropy_sections"]:
                report.append("\n高熵区段 (可能已加密/压缩):")
                for section in pe_info["high_entropy_sections"]:
                    report.append(f"  - {section.get('name', 'N/A')} (熵值: {section.get('entropy', 0):.2f})")
            
            # 可疑区段
            if "suspicious_sections" in pe_info and pe_info["suspicious_sections"]:
                report.append("\n可疑区段:")
                for section in pe_info["suspicious_sections"]:
                    report.append(f"  - {section.get('name', 'N/A')} (虚拟大小: {section.get('virtual_size', 0)})")
            
            # 可疑导入
            if "suspicious_imports" in pe_info and pe_info["suspicious_imports"]:
                report.append("\n可疑导入 (网络/加密):")
                for imp in pe_info["suspicious_imports"]:
                    report.append(f"  - {imp.get('dll', 'N/A')} ({len(imp.get('functions', []))} 函数)")
            
            # TLS回调
            if pe_info.get("has_tls_callbacks", False):
                report.append("\n警告: 检测到TLS回调 (反调试技术)")
                if "tls_callbacks" in pe_info and pe_info["tls_callbacks"]:
                    for addr in pe_info["tls_callbacks"]:
                        report.append(f"  - 回调地址: {addr}")
            
            # 其他信息
            report.append(f"\n总导入函数数量: {pe_info.get('import_count', 0)}")
            if pe_info.get("is_dotnet", False):
                report.append("检测到.NET程序")
        
        # 脱壳建议
        if "unpacking_strategy" in result:
            strategy = result["unpacking_strategy"]
            
            report.append("\n脱壳策略建议:")
            report.append(f"  - 推荐方法: {strategy.get('recommended_method', '通用方法')}")
            difficulty_map = {
                "easy": "简单", 
                "medium": "中等", 
                "hard": "困难", 
                "very_hard": "非常困难"
            }
            report.append(f"  - 难度: {difficulty_map.get(strategy.get('difficulty', 'medium'), '中等')}")
            
            report.append("\n  - 建议工具:")
            for tool in strategy.get("tools", []):
                report.append(f"    * {tool}")
            
            report.append("\n  - 建议步骤:")
            for i, step in enumerate(strategy.get("steps", []), 1):
                report.append(f"    {i}. {step}")
            
            # 一般提示
            if "general_tips" in strategy and strategy["general_tips"]:
                report.append("\n  - 一般提示:")
                for tip in strategy["general_tips"]:
                    report.append(f"    * {tip}")
        
        report.append("=" * 50)
        return "\n".join(report)

def main():
    """主程序入口"""
    parser = argparse.ArgumentParser(description='高级壳检测工具')
    parser.add_argument('target', help='要分析的文件或目录路径')
    parser.add_argument('-r', '--recursive', action='store_true', help='递归分析目录')
    parser.add_argument('-o', '--output', help='输出文件路径 (默认为标准输出)')
    parser.add_argument('-f', '--format', choices=['text', 'json', 'html'], default='text', help='输出格式')
    parser.add_argument('-c', '--custom-rules', help='自定义YARA规则文件路径')
    parser.add_argument('-j', '--jobs', type=int, default=4, help='并行分析的最大作业数')
    
    args = parser.parse_args()
    
    try:
        # 加载自定义规则
        custom_rules = None
        if args.custom_rules:
            try:
                with open(args.custom_rules, 'r') as f:
                    custom_rules = f.read()
            except Exception as e:
                logger.error(f"加载自定义规则失败: {e}")
        
        # 初始化检测器
        detector = PackerDetector(custom_rules)
        
        # 分析目标
        if os.path.isdir(args.target):
            # 分析目录
            logger.info(f"分析目录: {args.target} {'(递归)' if args.recursive else ''}")
            results = detector.analyze_directory(args.target, args.recursive, args.jobs)
            
            # 生成多文件报告
            if args.format == 'json':
                final_result = results
            else:
                reports = []
                for result in results:
                    if "error" in result:
                        reports.append(f"错误分析文件 {result.get('file_path', 'unknown')}: {result['error']}")
                    else:
                        reports.append(generate_report(result, args.format))
                
                final_result = "\n\n".join(reports)
        else:
            # 分析单个文件
            logger.info(f"分析文件: {args.target}")
            result = detector.analyze_file(args.target)
            
            if "error" in result:
                logger.error(f"分析错误: {result['error']}")
                sys.exit(1)
                
            # 生成报告
            final_result = generate_report(result, args.format)
        
        # 输出报告
        if args.output:
            with open(args.output, 'w') as f:
                if args.format == 'json':
                    json.dump(final_result, f, indent=2)
                else:
                    f.write(final_result)
            logger.info(f"报告已保存到: {args.output}")
        else:
            # 打印到标准输出
            if args.format == 'json':
                print(json.dumps(final_result, indent=2))
            else:
                print(final_result)
        
        return 0
    except KeyboardInterrupt:
        logger.info("用户中断")
        return 1
    except Exception as e:
        logger.error(f"错误: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())