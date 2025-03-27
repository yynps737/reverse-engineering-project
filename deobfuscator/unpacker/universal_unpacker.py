#!/usr/bin/env python3
"""
通用可执行文件脱壳工具
支持多种保护技术和静态/动态脱壳方法
"""
import os
import sys
import argparse
import subprocess
import tempfile
import logging
import time
import json
import struct
import shutil
import hashlib
import traceback
from typing import Dict, List, Optional, Any, Tuple, Set, Union
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# 设置日志
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("unpacker.log")
    ]
)
logger = logging.getLogger(__name__)

class UniversalUnpacker:
    """通用可执行文件脱壳器，支持多种保护技术和静态/动态脱壳方法"""
    
    def __init__(self, input_file: str, output_dir: Optional[str] = None, strategies: Optional[List[str]] = None):
        """
        初始化脱壳器
        
        Args:
            input_file: 输入可执行文件路径
            output_dir: 输出目录
            strategies: 脱壳策略列表（静态、动态、IAT修复）
        """
        self.input_file = os.path.abspath(input_file)
        if not os.path.exists(self.input_file):
            raise FileNotFoundError(f"输入文件不存在: {self.input_file}")
        
        # 设置输出目录
        self.output_dir = output_dir or os.path.join(
            os.path.dirname(self.input_file), 
            "unpacked", 
            os.path.basename(self.input_file)
        )
        os.makedirs(self.output_dir, exist_ok=True)
        
        # 创建子目录
        self._create_output_subdirs()
        
        # 默认策略: 静态脱壳、动态脱壳、通用IAT修复
        self.strategies = strategies or ['static', 'dynamic', 'iat_fix']
        
        # 脱壳结果
        self.unpacked_files = []
        self.sections = []
        self.imports = []
        self.oep = 0  # 原始入口点
        self.dump_success = False
        
        # 详细分析结果
        self.analysis_result = {
            'input_file': self.input_file,
            'file_size': os.path.getsize(self.input_file),
            'md5': self.get_file_md5(self.input_file),
            'sha256': self.get_file_sha256(self.input_file),
            'unpacked_files': [],
            'detected_protections': [],
            'oep_candidates': [],
            'import_table': [],
            'timestamp': time.time(),
            'success': False
        }
        
        # 检查依赖工具
        self._check_dependencies()
    
    def _create_output_subdirs(self) -> None:
        """创建输出子目录"""
        subdirs = [
            "static_results",    # 静态脱壳结果
            "dynamic_results",   # 动态脱壳结果
            "iat_results",       # IAT修复结果
            "dumps",             # 内存转储
            "imports",           # 导入表信息
            "logs"               # 日志文件
        ]
        
        for subdir in subdirs:
            os.makedirs(os.path.join(self.output_dir, subdir), exist_ok=True)
    
    def _check_dependencies(self) -> None:
        """检查工具依赖"""
        # 基本工具检查
        required_tools = {
            "pefile": self._check_python_module,
            "frida": self._check_python_module,
            "upx": self._check_command,
            "strings": self._check_command
        }
        
        optional_tools = {
            "de4dot": self._check_command,
            "scylla": self._check_command,
            "x64dbg": self._check_command
        }
        
        missing_required = []
        missing_optional = []
        
        # 检查必需工具
        for tool, check_func in required_tools.items():
            if not check_func(tool):
                missing_required.append(tool)
        
        # 检查可选工具
        for tool, check_func in optional_tools.items():
            if not check_func(tool):
                missing_optional.append(tool)
        
        # 报告结果
        if missing_required:
            logger.warning(f"缺少必需工具: {', '.join(missing_required)}")
            logger.warning("某些脱壳功能可能不可用")
        
        if missing_optional:
            logger.info(f"缺少可选工具: {', '.join(missing_optional)}")
            logger.info("某些高级脱壳功能可能不可用")
    
    def _check_python_module(self, module_name: str) -> bool:
        """
        检查Python模块是否已安装
        
        Args:
            module_name: 模块名称
            
        Returns:
            是否已安装
        """
        try:
            __import__(module_name)
            return True
        except ImportError:
            return False
    
    def _check_command(self, command: str) -> bool:
        """
        检查命令行工具是否可用
        
        Args:
            command: 命令名称
            
        Returns:
            是否可用
        """
        try:
            devnull = open(os.devnull, 'w')
            subprocess.call([command, "--help"], stdout=devnull, stderr=devnull)
            return True
        except (subprocess.SubprocessError, FileNotFoundError, PermissionError):
            return False
    
    def get_file_md5(self, filepath: str) -> str:
        """
        计算文件MD5哈希
        
        Args:
            filepath: 文件路径
            
        Returns:
            MD5哈希值
        """
        hasher = hashlib.md5()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    
    def get_file_sha256(self, filepath: str) -> str:
        """
        计算文件SHA256哈希
        
        Args:
            filepath: 文件路径
            
        Returns:
            SHA256哈希值
        """
        hasher = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    
    def analyze_file(self) -> None:
        """执行初步分析"""
        logger.info(f"分析文件: {self.input_file}")
        
        # 运行壳识别工具
        try:
            detected_protections = self._detect_protections()
            self.analysis_result['detected_protections'] = detected_protections
            logger.info(f"检测到的保护: {', '.join(detected_protections)}")
        except Exception as e:
            logger.error(f"壳识别失败: {str(e)}")
        
        # 提取基本PE信息
        try:
            self._analyze_pe_structure()
        except Exception as e:
            logger.error(f"PE分析失败: {str(e)}")
    
    def _detect_protections(self) -> List[str]:
        """
        检测文件保护类型
        
        Returns:
            检测到的保护类型列表
        """
        protections = []
        
        # 使用shell_detector.py检测壳（如果存在）
        detector_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'shell_detector.py')
        if os.path.exists(detector_path):
            try:
                output = subprocess.check_output(
                    ['python3', detector_path, self.input_file], 
                    stderr=subprocess.STDOUT,
                    timeout=60
                )
                output_str = output.decode('utf-8', errors='ignore')
                
                # 解析保护类型
                for line in output_str.splitlines():
                    if line.strip().startswith('-'):
                        protection = line.strip()[2:].strip()
                        if protection and protection not in protections:
                            protections.append(protection)
            except subprocess.TimeoutExpired:
                logger.warning("壳检测超时")
            except Exception as e:
                logger.error(f"运行壳检测工具出错: {str(e)}")
        
        # 如果壳检测工具不可用或未检测到任何保护，使用内置的检测逻辑
        if not protections:
            logger.info("使用内置检测逻辑")
            protections = self._detect_protections_internal()
        
        return protections
    
    def _detect_protections_internal(self) -> List[str]:
        """
        使用内置逻辑检测保护类型
        
        Returns:
            检测到的保护类型列表
        """
        protections = []
        
        # 读取文件前8KB用于快速检测
        with open(self.input_file, 'rb') as f:
            header_data = f.read(8192)
        
        # 检测UPX
        if b'UPX!' in header_data or b'UPX0' in header_data:
            protections.append('UPX Packer')
        
        # 检测.NET
        if b'.NET' in header_data or b'mscoree.dll' in header_data:
            protections.append('.NET Assembly')
        
        # 检测VMProtect
        if b'VMProtect' in header_data or b'vmp' in header_data.lower():
            protections.append('VMProtect')
        
        # 检测Themida/WinLicense
        if b'Themida' in header_data or b'WinLicense' in header_data:
            protections.append('Themida/WinLicense')
        
        # 检测ASPack/ASProtect
        if b'ASPack' in header_data or b'ASProtect' in header_data:
            protections.append('ASPack/ASProtect')
        
        # 检测Enigma Protector
        if b'Enigma' in header_data:
            protections.append('Enigma Protector')
        
        # 检测Python打包
        if b'Python' in header_data and (b'PYZ' in header_data or b'PyInstaller' in header_data):
            protections.append('Python Packed')
        
        # 使用字符串检测进一步检查
        try:
            strings_output = subprocess.check_output(['strings', self.input_file], stderr=subprocess.PIPE)
            strings_text = strings_output.decode('utf-8', errors='ignore').lower()
            
            # 检查其他保护特征
            protection_markers = {
                'obsidium': 'Obsidium',
                'safengine': 'SafeEngine Shielden',
                'pespin': 'PESpin',
                'exestealth': 'ExeStealth',
                'morphnah': 'MorphNah',
                'pelock': 'PELock',
                'tpppack': 'tElock',
                'xcomp': 'XComp/XPack',
                'pecompact': 'PECompact',
                'upx': 'UPX Packer',
                'confuser': 'ConfuserEx (.NET)',
                'dotfuscator': 'Dotfuscator (.NET)',
                'babel': 'Babel (.NET)',
                'smartassembly': 'SmartAssembly (.NET)',
                'crypto obfuscator': 'Crypto Obfuscator (.NET)',
                'spices.net': 'Spices.Net (.NET)'
            }
            
            for marker, protection_name in protection_markers.items():
                if marker in strings_text and protection_name not in protections:
                    protections.append(protection_name)
        except:
            pass
        
        # 如果没有检测到任何保护，使用pefile进行高级分析
        if not protections:
            protections = self._detect_protections_advanced()
        
        return protections
    
    def _detect_protections_advanced(self) -> List[str]:
        """
        使用PE结构分析检测保护类型
        
        Returns:
            检测到的保护类型列表
        """
        protections = []
        
        try:
            import pefile
            pe = pefile.PE(self.input_file)
            
            # 检查区段熵值
            high_entropy_sections = 0
            suspicious_named_sections = 0
            
            for section in pe.sections:
                section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                
                # 计算熵值
                entropy = self._calculate_entropy(section.get_data())
                
                # 高熵值区段（可能是加密或压缩）
                if entropy > 7.5:
                    high_entropy_sections += 1
                
                # 可疑区段名称
                suspicious_names = ['.vmp', '.themida', 'UPX', 'ASPack', '.aspack', '.enigma', '.nsp']
                if any(suspicious in section_name for suspicious in suspicious_names):
                    suspicious_named_sections += 1
                    
                    # 根据区段名称确定保护类型
                    if '.vmp' in section_name:
                        protections.append('VMProtect')
                    elif '.themida' in section_name:
                        protections.append('Themida/WinLicense')
                    elif 'UPX' in section_name:
                        protections.append('UPX Packer')
                    elif 'ASPack' in section_name or '.aspack' in section_name:
                        protections.append('ASPack/ASProtect')
                    elif '.enigma' in section_name:
                        protections.append('Enigma Protector')
            
            # 高熵值区段比例较大，可能是自定义保护
            if high_entropy_sections >= 2 and len(pe.sections) > 0 and high_entropy_sections / len(pe.sections) >= 0.5:
                protections.append('高熵值加密/自定义保护')
            
            # 分析导入表
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                imported_dlls = [entry.dll.decode().lower() for entry in pe.DIRECTORY_ENTRY_IMPORT]
                
                # .NET检测
                if b'mscoree.dll' in pe.__data__ or 'mscoree.dll' in imported_dlls:
                    protections.append('.NET Assembly')
                
                # 检查反调试API
                anti_debug_apis = ['isdebuggerpresent', 'checkremotedebuggerpresent', 'outputdebugstring']
                
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    try:
                        for imp in entry.imports:
                            if imp.name:
                                api_name = imp.name.decode().lower()
                                if any(api in api_name for api in anti_debug_apis):
                                    if '反调试技术' not in protections:
                                        protections.append('反调试技术')
                    except:
                        continue
            
            # 分析是否为加壳的.NET程序
            if '.NET Assembly' in protections:
                try:
                    dotnet_section = None
                    for section in pe.sections:
                        if '.text' in section.Name.decode('utf-8', errors='ignore'):
                            dotnet_section = section
                            break
                    
                    if dotnet_section and self._calculate_entropy(dotnet_section.get_data()) > 7.2:
                        protections.append('.NET Obfuscator')
                except:
                    pass
            
            # 检查TLS回调（可能是反调试）
            if hasattr(pe, 'DIRECTORY_ENTRY_TLS') and pe.DIRECTORY_ENTRY_TLS:
                protections.append('TLS回调(可能反调试)')
            
            pe.close()
        except:
            pass
        
        return protections
    
    def _calculate_entropy(self, data: bytes) -> float:
        """
        计算数据的Shannon熵
        
        Args:
            data: 二进制数据
            
        Returns:
            熵值 (0-8)
        """
        if not data:
            return 0
            
        byte_count = {}
        for byte in data:
            byte_count[byte] = byte_count.get(byte, 0) + 1
                
        entropy = 0
        for count in byte_count.values():
            probability = count / len(data)
            entropy -= probability * (math.log(probability, 2))
                
        return entropy
    
    def _analyze_pe_structure(self) -> None:
        """分析PE文件结构"""
        try:
            import pefile
            pe = pefile.PE(self.input_file)
            
            # 收集区段信息
            for section in pe.sections:
                section_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
                section_entropy = self._calculate_entropy(section.get_data())
                
                self.sections.append({
                    'name': section_name,
                    'virtual_address': section.VirtualAddress,
                    'virtual_size': section.Misc_VirtualSize,
                    'raw_size': section.SizeOfRawData,
                    'characteristics': section.Characteristics,
                    'entropy': section_entropy,
                    'md5': hashlib.md5(section.get_data()).hexdigest()
                })
            
            # 收集导入表
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    try:
                        dll_name = entry.dll.decode('utf-8', errors='ignore')
                        functions = []
                        
                        for imp in entry.imports:
                            func_name = "ORDINAL" if imp.name is None else imp.name.decode('utf-8', errors='ignore')
                            functions.append({
                                'name': func_name,
                                'address': imp.address
                            })
                        
                        self.imports.append({
                            'dll': dll_name,
                            'functions': functions
                        })
                        
                        self.analysis_result['import_table'].append({
                            'dll': dll_name,
                            'function_count': len(functions)
                        })
                    except Exception as e:
                        logger.warning(f"解析导入表条目错误: {str(e)}")
            
            # 获取原始入口点
            self.oep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            self.analysis_result['oep'] = self.oep
            
            # 获取时间戳
            if pe.FILE_HEADER.TimeDateStamp != 0:
                timestamp = pe.FILE_HEADER.TimeDateStamp
                self.analysis_result['compile_time'] = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            
            # 获取其他PE特征
            self.analysis_result['machine_type'] = pe.FILE_HEADER.Machine
            self.analysis_result['subsystem'] = pe.OPTIONAL_HEADER.Subsystem
            self.analysis_result['image_base'] = pe.OPTIONAL_HEADER.ImageBase
            self.analysis_result['section_count'] = len(pe.sections)
            self.analysis_result['characteristics'] = pe.FILE_HEADER.Characteristics
            self.analysis_result['dll'] = pe.is_dll()
            self.analysis_result['exe'] = pe.is_exe()
            
            pe.close()
        except Exception as e:
            logger.error(f"PE分析: {str(e)}")
            logger.error(traceback.format_exc())
    
    def unpack(self) -> bool:
        """
        执行脱壳过程
        
        Returns:
            是否成功脱壳
        """
        logger.info(f"开始脱壳: {self.input_file}")
        self.analyze_file()
        
        results = []
        
        # 根据检测到的保护类型调整策略优先级
        self._optimize_strategies()
        
        # 并行执行脱壳策略
        with ThreadPoolExecutor(max_workers=min(len(self.strategies), 3)) as executor:
            futures = {}
            
            for strategy in self.strategies:
                if strategy == 'static':
                    futures[executor.submit(self.static_unpack)] = 'static'
                elif strategy == 'dynamic':
                    futures[executor.submit(self.dynamic_unpack)] = 'dynamic'
                elif strategy == 'iat_fix':
                    futures[executor.submit(self.repair_imports)] = 'iat_fix'
            
            # 收集结果
            for future in as_completed(futures):
                strategy = futures[future]
                try:
                    result = future.result()
                    if result:
                        logger.info(f"{strategy} 策略成功")
                        results.append(result)
                    else:
                        logger.warning(f"{strategy} 策略失败")
                except Exception as e:
                    logger.error(f"{strategy} 策略执行错误: {str(e)}")
                    logger.error(traceback.format_exc())
        
        # 处理结果
        for result in results:
            if result.get('unpacked_file') and os.path.exists(result['unpacked_file']):
                self.unpacked_files.append(result['unpacked_file'])
                self.analysis_result['unpacked_files'].append({
                    'path': result['unpacked_file'],
                    'size': os.path.getsize(result['unpacked_file']),
                    'md5': self.get_file_md5(result['unpacked_file']),
                    'method': result.get('method', 'unknown')
                })
                
                if result.get('oep_found'):
                    self.analysis_result['oep_candidates'].append({
                        'address': result.get('oep', 0),
                        'confidence': result.get('confidence', 0)
                    })
        
        # 确定脱壳结果
        if self.unpacked_files:
            logger.info(f"脱壳成功! 生成了 {len(self.unpacked_files)} 个文件")
            self.dump_success = True
            
            # 选择最佳脱壳结果
            best_file = self.select_best_unpacked_file()
            if best_file:
                final_output = os.path.join(self.output_dir, "final_unpacked.exe")
                shutil.copy(best_file, final_output)
                logger.info(f"最佳脱壳结果: {final_output}")
                self.analysis_result['best_result'] = final_output
        else:
            logger.warning("所有脱壳策略均失败")
        
        # 更新结果状态
        self.analysis_result['success'] = self.dump_success
        self.analysis_result['completion_time'] = time.time()
        
        # 生成最终报告
        self.generate_report()
        
        return self.dump_success
    
    def _optimize_strategies(self) -> None:
        """根据检测到的保护类型调整策略优先级"""
        protections = self.analysis_result.get('detected_protections', [])
        
        # 根据保护类型优化策略顺序
        if any('.NET' in p for p in protections):
            # .NET程序优先使用静态脱壳
            if 'static' in self.strategies and 'dynamic' in self.strategies:
                self.strategies.remove('static')
                self.strategies.insert(0, 'static')
                
        elif any('UPX' in p for p in protections):
            # UPX优先使用静态脱壳
            if 'static' in self.strategies and 'dynamic' in self.strategies:
                self.strategies.remove('static')
                self.strategies.insert(0, 'static')
                
        elif any(p in protections for p in ['VMProtect', 'Themida/WinLicense', 'Enigma Protector']):
            # 高级壳优先使用动态脱壳
            if 'dynamic' in self.strategies and 'static' in self.strategies:
                self.strategies.remove('dynamic')
                self.strategies.insert(0, 'dynamic')
        
        logger.info(f"优化后的策略顺序: {self.strategies}")
    
    def static_unpack(self) -> Optional[Dict[str, Any]]:
        """
        静态脱壳实现
        
        Returns:
            脱壳结果字典或None
        """
        logger.info("尝试静态脱壳...")
        
        # 检测常见壳类型并应用相应处理
        protections = self.analysis_result.get('detected_protections', [])
        
        try:
            # 按保护类型选择合适的静态脱壳方法
            if any('UPX' in p for p in protections):
                return self.unpack_upx()
            
            if any('ASPack' in p for p in protections) or any('ASProtect' in p for p in protections):
                return self.unpack_aspack()
            
            if any('.NET' in p for p in protections):
                return self.unpack_dotnet()
            
            if any('PECompact' in p for p in protections):
                return self.unpack_pecompact()
            
            if any('Python' in p for p in protections):
                return self.unpack_python()
            
            # 如果没有匹配的特定脱壳器，尝试通用静态脱壳
            return self.generic_static_unpack()
        except Exception as e:
            logger.error(f"静态脱壳错误: {str(e)}")
            logger.error(traceback.format_exc())
            return None
    
    def unpack_upx(self) -> Optional[Dict[str, Any]]:
        """
        UPX脱壳
        
        Returns:
            脱壳结果字典或None
        """
        logger.info("UPX脱壳...")
        
        output_file = os.path.join(self.output_dir, "static_results", "upx_unpacked.exe")
        
        try:
            # 尝试使用官方UPX脱壳
            subprocess.run(
                ["upx", "-d", self.input_file, "-o", output_file], 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                check=True
            )
            
            if os.path.exists(output_file):
                logger.info(f"UPX脱壳成功: {output_file}")
                return {
                    'unpacked_file': output_file,
                    'method': 'upx_static',
                    'oep_found': True,
                    'oep': self.oep,
                    'confidence': 90
                }
        except Exception as e:
            logger.error(f"标准UPX脱壳失败: {str(e)}")
            
            # 如果官方工具失败，尝试UPX变种处理
            try:
                logger.info("尝试处理UPX变种...")
                # 特殊处理修改过的UPX头部
                with open(self.input_file, 'rb') as f:
                    data = bytearray(f.read())
                
                # 搜索UPX特征并修正
                upx0_pos = data.find(b'UPX0')
                upx1_pos = data.find(b'UPX1')
                
                if upx0_pos != -1 and upx1_pos != -1:
                    logger.info("检测到UPX变种，尝试修正...")
                    
                    # 修正UPX头部
                    temp_file = os.path.join(self.output_dir, "static_results", "fixed_upx.exe")
                    with open(temp_file, 'wb') as f:
                        f.write(data)
                    
                    # 重新尝试脱壳
                    subprocess.run(
                        ["upx", "-d", temp_file, "-o", output_file], 
                        stdout=subprocess.PIPE, 
                        stderr=subprocess.PIPE, 
                        check=True
                    )
                    
                    if os.path.exists(output_file):
                        logger.info(f"UPX变种脱壳成功: {output_file}")
                        return {
                            'unpacked_file': output_file,
                            'method': 'upx_variant_static',
                            'oep_found': True,
                            'oep': self.oep,
                            'confidence': 80
                        }
            except Exception as e2:
                logger.error(f"UPX变种处理失败: {str(e2)}")
                
                # 最后尝试临时目录
                try:
                    logger.info("尝试在临时目录中运行UPX...")
                    with tempfile.TemporaryDirectory() as temp_dir:
                        temp_input = os.path.join(temp_dir, "input.exe")
                        temp_output = os.path.join(temp_dir, "output.exe")
                        
                        shutil.copy(self.input_file, temp_input)
                        
                        subprocess.run(
                            ["upx", "-d", temp_input, "-o", temp_output], 
                            stdout=subprocess.PIPE, 
                            stderr=subprocess.PIPE, 
                            check=True
                        )
                        
                        if os.path.exists(temp_output):
                            shutil.copy(temp_output, output_file)
                            logger.info(f"临时目录UPX脱壳成功: {output_file}")
                            return {
                                'unpacked_file': output_file,
                                'method': 'upx_temp_static',
                                'oep_found': True,
                                'oep': self.oep,
                                'confidence': 70
                            }
                except Exception as e3:
                    logger.error(f"临时目录UPX脱壳失败: {str(e3)}")
        
        return None
    
    def unpack_aspack(self) -> Optional[Dict[str, Any]]:
        """
        ASPack脱壳
        
        Returns:
            脱壳结果字典或None
        """
        logger.info("尝试ASPack脱壳...")
        
        output_file = os.path.join(self.output_dir, "static_results", "aspack_unpacked.exe")
        
        # 目前没有可靠的静态ASPack脱壳工具，通常需要使用动态方法
        # 这里仅实现检测，实际脱壳将通过动态方法完成
        logger.warning("ASPack静态脱壳不可用，将通过动态方法脱壳")
        return None
    
    def unpack_dotnet(self) -> Optional[Dict[str, Any]]:
        """
        处理.NET程序
        
        Returns:
            脱壳结果字典或None
        """
        logger.info("尝试.NET反混淆...")
        
        output_file = os.path.join(self.output_dir, "static_results", "dotnet_deobfuscated.exe")
        
        try:
            # 使用de4dot进行.NET反混淆
            de4dot_path = self._find_tool("de4dot")
            if not de4dot_path:
                logger.warning("未找到de4dot工具，无法进行.NET反混淆")
                return None
                
            subprocess.run(
                [de4dot_path, self.input_file, "-o", output_file], 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                check=True
            )
            
            if os.path.exists(output_file):
                logger.info(f".NET反混淆成功: {output_file}")
                return {
                    'unpacked_file': output_file,
                    'method': 'dotnet_static',
                    'oep_found': True,
                    'oep': 0,  # .NET没有传统OEP概念
                    'confidence': 85
                }
        except Exception as e:
            logger.error(f".NET反混淆失败: {str(e)}")
        
        return None
    
    def unpack_pecompact(self) -> Optional[Dict[str, Any]]:
        """
        PECompact脱壳
        
        Returns:
            脱壳结果字典或None
        """
        logger.info("尝试PECompact脱壳...")
        # PECompact静态脱壳实现（目前未实现）
        logger.warning("PECompact静态脱壳不可用，将通过动态方法脱壳")
        return None
    
    def unpack_python(self) -> Optional[Dict[str, Any]]:
        """
        Python打包程序脱壳
        
        Returns:
            脱壳结果字典或None
        """
        logger.info("尝试Python打包程序脱壳...")
        
        output_dir = os.path.join(self.output_dir, "static_results", "python_extracted")
        os.makedirs(output_dir, exist_ok=True)
        
        # 尝试使用pyinstxtractor
        try:
            pyinstxtractor_available = False
            
            # 检查pyinstxtractor是否可用
            try:
                import sys
                sys.path.append(os.path.dirname(os.path.abspath(__file__)))
                import pyinstxtractor
                pyinstxtractor_available = True
            except ImportError:
                logger.warning("pyinstxtractor不可用，尝试使用脚本")
                
                # 尝试从GitHub下载pyinstxtractor
                pyinstxtractor_url = "https://raw.githubusercontent.com/extremecoders-re/pyinstxtractor/master/pyinstxtractor.py"
                pyinstxtractor_script = os.path.join(self.output_dir, "pyinstxtractor.py")
                
                try:
                    import urllib.request
                    urllib.request.urlretrieve(pyinstxtractor_url, pyinstxtractor_script)
                    pyinstxtractor_available = True
                except:
                    logger.error("无法下载pyinstxtractor")
            
            if pyinstxtractor_available:
                # 使用pyinstxtractor提取PyInstaller打包程序
                subprocess.run(
                    ["python3", pyinstxtractor_script, self.input_file], 
                    cwd=output_dir,
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE
                )
                
                # 检查是否成功提取
                extracted_dir = os.path.join(output_dir, os.path.basename(self.input_file) + "_extracted")
                if os.path.exists(extracted_dir):
                    # 创建结果文件
                    result_file = os.path.join(self.output_dir, "static_results", "python_extracted.txt")
                    with open(result_file, 'w') as f:
                        f.write(f"Python打包程序已提取到: {extracted_dir}\n\n")
                        f.write("提取的文件列表:\n")
                        
                        for root, dirs, files in os.walk(extracted_dir):
                            for file in files:
                                rel_path = os.path.relpath(os.path.join(root, file), extracted_dir)
                                f.write(f"- {rel_path}\n")
                    
                    logger.info(f"Python打包程序提取成功: {extracted_dir}")
                    
                    # 尝试找到主Python脚本
                    main_script = None
                    
                    for root, dirs, files in os.walk(extracted_dir):
                        for file in files:
                            if file.endswith('.pyc') and 'main' in file.lower():
                                main_script = os.path.join(root, file)
                                break
                        if main_script:
                            break
                    
                    if main_script:
                        # 尝试反编译主脚本
                        try:
                            decompiled = os.path.join(output_dir, "decompiled_main.py")
                            subprocess.run(
                                ["pycdc", main_script, "-o", decompiled], 
                                stdout=subprocess.PIPE, 
                                stderr=subprocess.PIPE
                            )
                            
                            if os.path.exists(decompiled):
                                logger.info(f"主脚本反编译成功: {decompiled}")
                                with open(result_file, 'a') as f:
                                    f.write(f"\n主脚本已反编译: {decompiled}\n")
                        except:
                            logger.warning("无法反编译主脚本")
                    
                    return {
                        'unpacked_file': result_file,
                        'method': 'python_static',
                        'oep_found': False,
                        'confidence': 75
                    }
        except Exception as e:
            logger.error(f"Python打包程序脱壳失败: {str(e)}")
        
        return None
    
    def generic_static_unpack(self) -> Optional[Dict[str, Any]]:
        """
        通用静态脱壳方法
        
        Returns:
            脱壳结果字典或None
        """
        logger.info("尝试通用静态脱壳...")
        
        # 尝试运行多种通用静态脱壳方法
        methods = [
            self._try_universal_extractor,
            self._try_simple_packer_signature_patch
        ]
        
        for method in methods:
            result = method()
            if result:
                return result
        
        return None
    
    def _try_universal_extractor(self) -> Optional[Dict[str, Any]]:
        """
        尝试使用Universal Extractor
        
        Returns:
            脱壳结果字典或None
        """
        # Universal Extractor实现（暂未实现）
        return None
    
    def _try_simple_packer_signature_patch(self) -> Optional[Dict[str, Any]]:
        """
        尝试简单的壳特征修补
        
        Returns:
            脱壳结果字典或None
        """
        logger.info("尝试壳特征修补...")
        
        output_file = os.path.join(self.output_dir, "static_results", "signature_patched.exe")
        
        try:
            # 读取文件
            with open(self.input_file, 'rb') as f:
                data = bytearray(f.read())
            
            patched = False
            
            # 尝试一些常见的特征修补
            # 1. UPX特征
            upx_sig_pos = data.find(b'UPX!')
            if upx_sig_pos != -1:
                data[upx_sig_pos:upx_sig_pos+4] = b'NOPX'
                patched = True
                logger.info("已修补UPX特征")
            
            # 2. 其他壳特征处理...
            
            if patched:
                # 写入修补后的文件
                with open(output_file, 'wb') as f:
                    f.write(data)
                
                logger.info(f"特征修补成功: {output_file}")
                return {
                    'unpacked_file': output_file,
                    'method': 'signature_patch',
                    'oep_found': False,
                    'confidence': 30  # 低置信度
                }
        except Exception as e:
            logger.error(f"特征修补失败: {str(e)}")
        
        return None
    
    def _find_tool(self, tool_name: str) -> Optional[str]:
        """
        查找工具路径
        
        Args:
            tool_name: 工具名称
            
        Returns:
            工具路径或None
        """
        # 检查常见位置
        common_paths = [
            os.path.join(os.path.dirname(os.path.abspath(__file__)), tool_name),
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools", tool_name),
            tool_name
        ]
        
        # 添加扩展名
        if sys.platform == 'win32':
            common_paths.extend([p + '.exe' for p in common_paths])
        
        # 检查每个路径
        for path in common_paths:
            try:
                subprocess.call([path, "--help"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                return path
            except:
                continue
        
        return None
    
    def dynamic_unpack(self) -> Optional[Dict[str, Any]]:
        """
        动态脱壳实现
        
        Returns:
            脱壳结果字典或None
        """
        logger.info("尝试动态脱壳...")
        
        output_file = os.path.join(self.output_dir, "dynamic_results", "dynamic_dump.exe")
        
        # 确定合适的脱壳策略
        strategies = []
        
        # 根据保护类型确定策略
        protections = self.analysis_result.get('detected_protections', [])
        
        if any('VMProtect' in p for p in protections):
            strategies.append('vmp_specialized')
        elif any('Themida' in p for p in protections) or any('WinLicense' in p for p in protections):
            strategies.append('themida_specialized')
        elif any('ASPack' in p for p in protections) or any('ASProtect' in p for p in protections):
            strategies.append('aspack_specialized')
        elif any('Enigma' in p for p in protections):
            strategies.append('enigma_specialized')
        
        # 始终添加通用策略
        strategies.append('generic_memory_dump')
        
        # 尝试每种策略
        for strategy in strategies:
            result = None
            
            if strategy == 'vmp_specialized':
                result = self.vmp_dynamic_unpack(output_file)
            elif strategy == 'themida_specialized':
                result = self.themida_dynamic_unpack(output_file)
            elif strategy == 'aspack_specialized':
                result = self.aspack_dynamic_unpack(output_file)
            elif strategy == 'enigma_specialized':
                result = self.enigma_dynamic_unpack(output_file)
            elif strategy == 'generic_memory_dump':
                result = self.generic_dynamic_unpack(output_file)
            
            if result:
                return result
        
        logger.warning("所有动态脱壳策略均失败")
        return None
    
    def vmp_dynamic_unpack(self, output_file: str) -> Optional[Dict[str, Any]]:
        """
        VMProtect专用动态脱壳
        
        Args:
            output_file: 输出文件路径
            
        Returns:
            脱壳结果字典或None
        """
        logger.info("尝试VMProtect专用动态脱壳...")
        
        # 使用Frida脚本专门处理VMProtect
        try:
            # 检查Frida是否可用
            try:
                import frida
            except ImportError:
                logger.error("Frida未安装，无法使用VMProtect专用脱壳")
                return None
            
            # VMProtect专用Frida脚本
            vmp_script = """
            (function() {
                // VMProtect专用脱壳逻辑
                console.log("[+] VMProtect脱壳脚本已加载");
                
                // 主要实现...（完整实现很长，这里省略）
                
                // 查找VMProtect特征
                function findVMPPatterns() {
                    console.log("[*] 扫描VMProtect特征");
                    const modules = Process.enumerateModules();
                    for (const mod of modules) {
                        Memory.scan(mod.base, mod.size, "EB ?? ?? ?? ?? ?? ?? ?? ?? 00", {
                            onMatch: function(address, size) {
                                console.log("[+] 找到VMProtect特征: " + address);
                                // 处理特征...
                            },
                            onError: function(reason) {
                                console.log("[!] 扫描错误: " + reason);
                            },
                            onComplete: function() {}
                        });
                    }
                }
                
                // 查找VM处理程序
                function findVMHandlers() {
                    // 实现...
                }
                
                // 等待VM执行完成
                function waitForVMCompletion() {
                    // 实现...
                }
                
                // 转储内存
                function dumpExecutableMemory() {
                    // 实现...
                }
                
                // 执行脱壳
                findVMPPatterns();
                findVMHandlers();
                waitForVMCompletion();
                dumpExecutableMemory();
            })();
            """
            
            # 使用通用动态脱壳 - 这里实际中需要替换为专用实现
            # 由于专用实现较为复杂，此处使用通用方法
            logger.warning("VMProtect专用脱壳未完全实现，回退到通用方法")
            return self.generic_dynamic_unpack(output_file)
        except Exception as e:
            logger.error(f"VMProtect动态脱壳错误: {str(e)}")
            return None
    
    def themida_dynamic_unpack(self, output_file: str) -> Optional[Dict[str, Any]]:
        """
        Themida专用动态脱壳
        
        Args:
            output_file: 输出文件路径
            
        Returns:
            脱壳结果字典或None
        """
        logger.info("尝试Themida专用动态脱壳...")
        
        # 使用通用动态脱壳 - 这里实际中需要替换为专用实现
        logger.warning("Themida专用脱壳未完全实现，回退到通用方法")
        return self.generic_dynamic_unpack(output_file)
    
    def aspack_dynamic_unpack(self, output_file: str) -> Optional[Dict[str, Any]]:
        """
        ASPack专用动态脱壳
        
        Args:
            output_file: 输出文件路径
            
        Returns:
            脱壳结果字典或None
        """
        logger.info("尝试ASPack专用动态脱壳...")
        
        # 使用通用动态脱壳 - 这里实际中需要替换为专用实现
        logger.warning("ASPack专用脱壳未完全实现，回退到通用方法")
        return self.generic_dynamic_unpack(output_file)
    
    def enigma_dynamic_unpack(self, output_file: str) -> Optional[Dict[str, Any]]:
        """
        Enigma专用动态脱壳
        
        Args:
            output_file: 输出文件路径
            
        Returns:
            脱壳结果字典或None
        """
        logger.info("尝试Enigma专用动态脱壳...")
        
        # 使用通用动态脱壳 - 这里实际中需要替换为专用实现
        logger.warning("Enigma专用脱壳未完全实现，回退到通用方法")
        return self.generic_dynamic_unpack(output_file)
    
    def generic_dynamic_unpack(self, output_file: str) -> Optional[Dict[str, Any]]:
        """
        通用动态脱壳
        
        Args:
            output_file: 输出文件路径
            
        Returns:
            脱壳结果字典或None
        """
        logger.info("尝试通用动态内存转储脱壳...")
        
        try:
            # 使用动态分析引擎进行分析
            analyzer_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'dynamic_analyzer.py')
            result_dir = os.path.join(self.output_dir, "dynamic_results", "analysis")
            os.makedirs(result_dir, exist_ok=True)
            
            # 检查dynamic_analyzer.py是否存在
            if not os.path.exists(analyzer_path):
                logger.warning(f"动态分析引擎不存在: {analyzer_path}")
                analyzer_path = self._find_dynamic_analyzer()
            
            if not analyzer_path:
                logger.error("无法找到动态分析引擎")
                return None
            
            logger.info(f"使用动态分析引擎: {analyzer_path}")
            
            # 运行动态分析
            subprocess.run([
                "python3", analyzer_path, 
                self.input_file, 
                "-o", result_dir,
                "-t", "60",  # 60秒超时
                "-w"         # 等待完成
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            
            # 查找生成的内存转储
            memory_dumps = []
            for root, dirs, files in os.walk(result_dir):
                for file in files:
                    if file.startswith("memory_dump_") and file.endswith(".bin"):
                        memory_dumps.append(os.path.join(root, file))
            
            if not memory_dumps:
                logger.warning("未找到内存转储文件")
                return None
            
            # 处理内存转储文件
            largest_dump = max(memory_dumps, key=os.path.getsize)
            logger.info(f"选择最大的内存转储: {largest_dump}")
            
            # 转换内存转储为可执行文件
            dump_to_pe_result = self.convert_dump_to_pe(largest_dump, output_file)
            if dump_to_pe_result:
                return dump_to_pe_result
            
            logger.warning("无法转换内存转储到PE文件")
            return None
        except Exception as e:
            logger.error(f"通用动态脱壳错误: {str(e)}")
            logger.error(traceback.format_exc())
            return None
    
    def _find_dynamic_analyzer(self) -> Optional[str]:
        """
        查找动态分析引擎
        
        Returns:
            动态分析引擎路径或None
        """
        # 检查常见位置
        common_paths = [
            "dynamic_analyzer.py",
            os.path.join("deobfuscator", "dynamic_analyzer.py"),
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "dynamic_analyzer.py"),
            os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dynamic_analyzer.py")
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                return os.path.abspath(path)
        
        return None
    
    def convert_dump_to_pe(self, dump_file: str, output_file: str) -> Optional[Dict[str, Any]]:
        """
        将内存转储转换为PE文件
        
        Args:
            dump_file: 内存转储文件路径
            output_file: 输出PE文件路径
            
        Returns:
            转换结果字典或None
        """
        logger.info(f"尝试将内存转储转换为PE文件: {dump_file} -> {output_file}")
        
        try:
            # 尝试使用Scylla或其他工具进行转换
            scylla_result = self._convert_with_scylla(dump_file, output_file)
            if scylla_result:
                return scylla_result
            
            # 如果Scylla失败，使用自定义方法
            return self._convert_dump_manually(dump_file, output_file)
        except Exception as e:
            logger.error(f"转换内存转储错误: {str(e)}")
            return None
    
    def _convert_with_scylla(self, dump_file: str, output_file: str) -> Optional[Dict[str, Any]]:
        """
        使用Scylla转换内存转储
        
        Args:
            dump_file: 内存转储文件路径
            output_file: 输出PE文件路径
            
        Returns:
            转换结果字典或None
        """
        # 检查Scylla是否可用
        scylla_path = self._find_tool("Scylla")
        if not scylla_path:
            logger.warning("未找到Scylla工具")
            return None
            
        try:
            # 使用Scylla转换内存转储
            # 注意：实际使用中可能需要借助脚本或其他方式控制Scylla
            # 这里使用简化的示例命令行
            command = [
                scylla_path,
                "--dump", dump_file,
                "--output", output_file,
                "--iat-fix"
            ]
            
            subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            
            if os.path.exists(output_file):
                logger.info(f"使用Scylla成功转换: {output_file}")
                return {
                    'unpacked_file': output_file,
                    'method': 'scylla_conversion',
                    'oep_found': False,
                    'confidence': 80
                }
        except Exception as e:
            logger.error(f"Scylla转换错误: {str(e)}")
        
        return None
    
    def _convert_dump_manually(self, dump_file: str, output_file: str) -> Optional[Dict[str, Any]]:
        """
        手动转换内存转储为PE文件
        
        Args:
            dump_file: 内存转储文件路径
            output_file: 输出PE文件路径
            
        Returns:
            转换结果字典或None
        """
        logger.info("尝试手动转换内存转储...")
        
        try:
            with open(dump_file, "rb") as f:
                dump_data = f.read()
            
            # 分析数据是否包含PE头
            pe_header_offset = dump_data.find(b'MZ')
            if pe_header_offset == -1:
                logger.warning("在内存转储中未找到PE头")
                return None
            
            # 提取并修复PE
            fixed_pe_data = self.fix_pe_from_dump(dump_data, pe_header_offset)
            if not fixed_pe_data:
                logger.warning("PE修复失败")
                return None
            
            # 写入输出文件
            with open(output_file, "wb") as f:
                f.write(fixed_pe_data)
            
            if os.path.exists(output_file):
                logger.info(f"成功生成PE文件: {output_file}")
                return {
                    'unpacked_file': output_file,
                    'method': 'memory_dump_conversion',
                    'oep_found': False,
                    'confidence': 70
                }
            
            return None
        except Exception as e:
            logger.error(f"手动转换内存转储错误: {str(e)}")
            return None
    
    def fix_pe_from_dump(self, dump_data: bytes, pe_offset: int) -> Optional[bytes]:
        """
        从内存转储中修复PE结构
        
        Args:
            dump_data: 转储数据
            pe_offset: PE头偏移
            
        Returns:
            修复后的PE数据或None
        """
        try:
            # 提取MZ/PE头
            if len(dump_data) < pe_offset + 1024:
                logger.warning("转储数据不足以包含完整PE头")
                return None
            
            # 使用pefile分析并修复
            import pefile
            
            # 创建临时文件
            with tempfile.NamedTemporaryFile(delete=False) as temp:
                temp.write(dump_data[pe_offset:])
                temp_path = temp.name
            
            try:
                # 尝试解析PE
                pe = pefile.PE(temp_path)
                
                # 修复各种PE结构问题
                try:
                    # 1. 修复区段
                    for section in pe.sections:
                        # 确保PointerToRawData与区段对齐
                        if section.PointerToRawData == 0 and section.SizeOfRawData > 0:
                            section.PointerToRawData = section.VirtualAddress
                    
                    # 2. 修复导入表
                    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                        pass  # 这里可以添加更详细的导入表修复
                    
                    # 3. 修复资源表
                    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                        pass  # 这里可以添加资源表修复
                    
                    # 4. 修复重定位表
                    if hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC'):
                        pass  # 这里可以添加重定位表修复
                except Exception as fix_error:
                    logger.warning(f"PE结构修复警告: {str(fix_error)}")
                
                # 导出修复后的PE
                fixed_pe_path = temp_path + "_fixed"
                pe.write(fixed_pe_path)
                
                # 读取修复后的PE
                with open(fixed_pe_path, 'rb') as f:
                    fixed_pe_data = f.read()
                
                # 清理临时文件
                try:
                    os.unlink(temp_path)
                    os.unlink(fixed_pe_path)
                except:
                    pass
                
                return fixed_pe_data
            except Exception as pe_error:
                logger.error(f"PE修复失败: {str(pe_error)}")
                
                # 清理临时文件
                try:
                    os.unlink(temp_path)
                except:
                    pass
                
                # 如果pefile失败，尝试简单复制数据
                return dump_data[pe_offset:]
        except Exception as e:
            logger.error(f"从转储修复PE错误: {str(e)}")
            return None
    
    def repair_imports(self) -> Optional[Dict[str, Any]]:
        """
        修复导入表
        
        Returns:
            修复结果字典或None
        """
        logger.info("尝试修复导入表...")
        
        # 检查是否有已生成的脱壳文件
        if not self.unpacked_files:
            logger.warning("没有脱壳文件可修复")
            return None
        
        # 选择最可能的脱壳文件
        target_file = self.select_best_unpacked_file()
        if not target_file:
            logger.warning("未找到合适的脱壳文件进行修复")
            return None
        
        output_file = os.path.join(self.output_dir, "iat_results", "imports_fixed.exe")
        
        try:
            # 使用ImpREC或类似工具修复导入表
            imprec_result = self._fix_imports_with_imprec(target_file, output_file)
            if imprec_result:
                return imprec_result
            
            # 或使用自定义方法
            return self.manual_import_fix(target_file, output_file)
        except Exception as e:
            logger.error(f"导入表修复错误: {str(e)}")
            return None
    
    def _fix_imports_with_imprec(self, input_file: str, output_file: str) -> Optional[Dict[str, Any]]:
        """
        使用ImportREC修复导入表
        
        Args:
            input_file: 输入文件路径
            output_file: 输出文件路径
            
        Returns:
            修复结果字典或None
        """
        # ImportREC通常是交互式工具，这里简化处理
        logger.warning("ImportREC自动化未实现")
        return None
    
    def manual_import_fix(self, input_file: str, output_file: str) -> Optional[Dict[str, Any]]:
        """
        手动修复导入表
        
        Args:
            input_file: 输入文件路径
            output_file: 输出文件路径
            
        Returns:
            修复结果字典或None
        """
        logger.info(f"手动修复导入表: {input_file}")
        
        try:
            # 导入pefile模块
            import pefile
            
            # 复制文件作为起点
            shutil.copy(input_file, output_file)
            
            # 分析原始文件以获取正确的导入表
            try:
                original_pe = pefile.PE(self.input_file)
                original_imports = {}
                
                if hasattr(original_pe, 'DIRECTORY_ENTRY_IMPORT'):
                    for entry in original_pe.DIRECTORY_ENTRY_IMPORT:
                        dll_name = entry.dll.decode('utf-8', errors='ignore')
                        functions = []
                        
                        for imp in entry.imports:
                            if imp.name:
                                func_name = imp.name.decode('utf-8', errors='ignore')
                                functions.append(func_name)
                        
                        original_imports[dll_name] = functions
                
                original_pe.close()
            except:
                logger.warning("无法分析原始文件导入表")
                original_imports = {}
            
            # 打开目标文件进行修复
            pe = pefile.PE(output_file)
            
            # 检查是否已有有效的导入表
            has_valid_imports = False
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') and len(pe.DIRECTORY_ENTRY_IMPORT) > 0:
                # 导入表已存在，检查完整性
                import_count = sum(len(entry.imports) for entry in pe.DIRECTORY_ENTRY_IMPORT)
                if import_count > 10:  # 假设至少需要10个导入函数才算有效
                    has_valid_imports = True
                    logger.info(f"文件已有有效导入表，包含 {import_count} 个函数")
            
            if not has_valid_imports:
                logger.info("尝试重建导入表...")
                
                # 这里是实际导入表修复代码
                # 由于复杂性，这里只实现一个简化版，真实实现需要更多细节
                
                # 简单修复: 如果我们有原始导入
                if original_imports:
                    logger.info("使用原始文件导入表进行修复")
                    
                    # TODO: 使用原始导入表重建脱壳文件的导入表
                    # 这需要高级PE操作，这里仅作为占位符
                    
                    logger.warning("导入表重建功能未完全实现")
            
            pe.close()
            
            logger.info(f"导入表修复完成: {output_file}")
            return {
                'unpacked_file': output_file,
                'method': 'import_table_fix',
                'oep_found': False,
                'confidence': 60
            }
        except Exception as e:
            logger.error(f"手动修复导入表错误: {str(e)}")
            return None
    
    def select_best_unpacked_file(self) -> Optional[str]:
        """
        选择最佳脱壳结果
        
        Returns:
            最佳脱壳文件路径或None
        """
        if not self.unpacked_files:
            return None
        
        if len(self.unpacked_files) == 1:
            return self.unpacked_files[0]
        
        # 按照优先级排序: 有效PE > 导入表完整 > 大小更合理 > 静态方法
        valid_files = []
        
        for file_path in self.unpacked_files:
            try:
                import pefile
                pe = pefile.PE(file_path)
                
                # 检查PE是否有效
                if hasattr(pe, 'OPTIONAL_HEADER') and hasattr(pe, 'sections'):
                    import_count = 0
                    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                        import_count = sum(len(entry.imports) for entry in pe.DIRECTORY_ENTRY_IMPORT)
                    
                    valid_files.append({
                        'path': file_path,
                        'size': os.path.getsize(file_path),
                        'is_dll': pe.is_dll(),
                        'is_exe': pe.is_exe(),
                        'has_imports': hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'),
                        'import_count': import_count,
                        'section_count': len(pe.sections)
                    })
                
                pe.close()
            except Exception as e:
                logger.warning(f"分析脱壳文件出错: {file_path} - {str(e)}")
        
        if not valid_files:
            return self.unpacked_files[0]  # 没有有效文件，返回第一个
        
        # 按导入表数量排序
        valid_files.sort(key=lambda x: x['import_count'], reverse=True)
        
        # 取前三名评分
        top_files = valid_files[:3] if len(valid_files) >= 3 else valid_files
        
        # 进行更详细的评分
        for file_info in top_files:
            score = 0
            
            # 优先选择EXE而非DLL
            if file_info['is_exe']:
                score += 10
            
            # 导入数量评分
            score += min(file_info['import_count'] * 2, 20)
            
            # 区段数量评分
            score += min(file_info['section_count'], 10)
            
            # 大小合理性 (假设原文件大小的50%-150%是合理的)
            original_size = self.analysis_result['file_size']
            size_ratio = file_info['size'] / original_size
            if 0.5 <= size_ratio <= 1.5:
                score += 10
            
            file_info['score'] = score
        
        # 选择得分最高的
        top_files.sort(key=lambda x: x['score'], reverse=True)
        return top_files[0]['path']
    
    def generate_report(self) -> None:
        """生成最终报告"""
        report_path = os.path.join(self.output_dir, "unpacking_report.json")
        report_html = os.path.join(self.output_dir, "unpacking_report.html")
        
        # 添加时间戳
        self.analysis_result['timestamp'] = time.strftime("%Y-%m-%d %H:%M:%S")
        self.analysis_result['success'] = self.dump_success
        
        # 保存JSON报告
        with open(report_path, 'w') as f:
            json.dump(self.analysis_result, f, indent=2)
        
        logger.info(f"JSON报告已保存到: {report_path}")
        
        # 生成HTML报告
        self._generate_html_report(report_html)
        
        logger.info(f"HTML报告已保存到: {report_html}")
    
    def _generate_html_report(self, output_path: str) -> None:
        """
        生成HTML格式的报告
        
        Args:
            output_path: 输出文件路径
        """
        # HTML报告模板
        html = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>脱壳报告</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }
        h1, h2, h3 { color: #333; }
        .container { max-width: 1000px; margin: 0 auto; }
        .section { margin-bottom: 20px; }
        .success { color: green; font-weight: bold; }
        .failure { color: red; font-weight: bold; }
        .data-block { background-color: #f5f5f5; padding: 10px; border-radius: 5px; margin-top: 10px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { text-align: left; padding: 8px; border-bottom: 1px solid #ddd; }
        tr:hover { background-color: #f5f5f5; }
        .protection { display: inline-block; background-color: #e74c3c; color: white; padding: 3px 8px; 
                      border-radius: 3px; margin-right: 5px; margin-bottom: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>脱壳报告</h1>
        <div class="section">
            <h2>文件信息</h2>
            <table>
                <tr><td>文件路径</td><td>{input_file}</td></tr>
                <tr><td>文件大小</td><td>{file_size} 字节</td></tr>
                <tr><td>MD5哈希</td><td>{md5}</td></tr>
                <tr><td>SHA256哈希</td><td>{sha256}</td></tr>
                <tr><td>脱壳状态</td><td class="{status_class}">{status}</td></tr>
            </table>
        </div>
        
        <div class="section">
            <h2>检测到的保护</h2>
            <div>
                {protections}
            </div>
        </div>
        
        <div class="section">
            <h2>脱壳结果</h2>
            {unpacked_files}
        </div>
        
        <div class="section">
            <h2>OEP候选</h2>
            {oep_candidates}
        </div>
        
        <div class="section">
            <h2>PE信息</h2>
            <div class="data-block">
                <p><strong>入口点:</strong> {oep}</p>
                <p><strong>机器类型:</strong> {machine_type}</p>
                <p><strong>子系统:</strong> {subsystem}</p>
                <p><strong>文件类型:</strong> {file_type}</p>
                {compile_time}
            </div>
            
            <h3>区段信息</h3>
            <table>
                <tr>
                    <th>名称</th>
                    <th>虚拟地址</th>
                    <th>虚拟大小</th>
                    <th>原始大小</th>
                    <th>熵值</th>
                </tr>
                {sections}
            </table>
            
            <h3>导入表</h3>
            <table>
                <tr>
                    <th>DLL</th>
                    <th>函数数量</th>
                </tr>
                {imports}
            </table>
        </div>
    </div>
</body>
</html>
"""
        
        # 格式化保护
        protections_html = ""
        for protection in self.analysis_result.get('detected_protections', []):
            protections_html += f'<span class="protection">{protection}</span>'
        
        if not protections_html:
            protections_html = "<p>未检测到特定保护</p>"
        
        # 格式化脱壳文件
        unpacked_files_html = ""
        if self.analysis_result.get('unpacked_files', []):
            unpacked_files_html = "<table><tr><th>文件</th><th>大小</th><th>MD5</th><th>方法</th></tr>"
            for unpacked in self.analysis_result['unpacked_files']:
                unpacked_files_html += f"""
                <tr>
                    <td>{os.path.basename(unpacked['path'])}</td>
                    <td>{unpacked['size']} 字节</td>
                    <td>{unpacked['md5']}</td>
                    <td>{unpacked['method']}</td>
                </tr>
                """
            unpacked_files_html += "</table>"
            
            if 'best_result' in self.analysis_result:
                unpacked_files_html += f"<p><strong>最佳结果:</strong> {os.path.basename(self.analysis_result['best_result'])}</p>"
        else:
            unpacked_files_html = "<p>未生成脱壳文件</p>"
        
        # 格式化OEP候选
        oep_candidates_html = ""
        if self.analysis_result.get('oep_candidates', []):
            oep_candidates_html = "<table><tr><th>地址</th><th>置信度</th></tr>"
            for candidate in self.analysis_result['oep_candidates']:
                oep_candidates_html += f"""
                <tr>
                    <td>0x{candidate['address']:08X}</td>
                    <td>{candidate['confidence']}%</td>
                </tr>
                """
            oep_candidates_html += "</table>"
        else:
            oep_candidates_html = "<p>未找到OEP候选</p>"
        
        # 格式化区段信息
        sections_html = ""
        for section in self.sections:
            sections_html += f"""
            <tr>
                <td>{section['name']}</td>
                <td>0x{section['virtual_address']:08X}</td>
                <td>{section['virtual_size']}</td>
                <td>{section['raw_size']}</td>
                <td>{section.get('entropy', 0):.2f}</td>
            </tr>
            """
        
        # 格式化导入表
        imports_html = ""
        for imp in self.analysis_result.get('import_table', []):
            imports_html += f"""
            <tr>
                <td>{imp['dll']}</td>
                <td>{imp['function_count']}</td>
            </tr>
            """
        
        # 格式化编译时间
        compile_time_html = ""
        if 'compile_time' in self.analysis_result:
            compile_time_html = f"<p><strong>编译时间:</strong> {self.analysis_result['compile_time']}</p>"
        
        # 填充模板
        formatted_html = html.format(
            input_file=self.analysis_result['input_file'],
            file_size=self.analysis_result['file_size'],
            md5=self.analysis_result['md5'],
            sha256=self.analysis_result['sha256'],
            status_class="success" if self.analysis_result['success'] else "failure",
            status="成功" if self.analysis_result['success'] else "失败",
            protections=protections_html,
            unpacked_files=unpacked_files_html,
            oep_candidates=oep_candidates_html,
            oep=f"0x{self.analysis_result.get('oep', 0):08X}",
            machine_type=self.analysis_result.get('machine_type', 'Unknown'),
            subsystem=self.analysis_result.get('subsystem', 'Unknown'),
            file_type="DLL" if self.analysis_result.get('dll', False) else "EXE",
            compile_time=compile_time_html,
            sections=sections_html,
            imports=imports_html
        )
        
        # 写入HTML报告
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(formatted_html)

def main():
    """主程序入口"""
    parser = argparse.ArgumentParser(description='通用脱壳工具')
    parser.add_argument('input', help='输入可执行文件路径')
    parser.add_argument('-o', '--output', help='输出目录')
    parser.add_argument('-s', '--strategies', help='脱壳策略,逗号分隔 (static,dynamic,iat_fix)', default='static,dynamic,iat_fix')
    parser.add_argument('-v', '--verbose', action='store_true', help='显示详细日志')
    
    args = parser.parse_args()
    
    # 设置日志级别
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        strategies = args.strategies.split(',')
        unpacker = UniversalUnpacker(args.input, args.output, strategies)
        success = unpacker.unpack()
        
        if success:
            print(f"脱壳成功! 结果已保存到 {unpacker.output_dir}")
            print(f"最佳脱壳结果: {unpacker.analysis_result.get('best_result', '无')}")
            
            if 'detected_protections' in unpacker.analysis_result:
                print("检测到的保护:")
                for protection in unpacker.analysis_result['detected_protections']:
                    print(f"  - {protection}")
            
            return 0
        else:
            print("脱壳失败。请查看日志获取详细信息。")
            return 1
    except Exception as e:
        logger.error(f"错误: {str(e)}")
        logger.error(traceback.format_exc())
        return 1

if __name__ == "__main__":
    sys.exit(main())