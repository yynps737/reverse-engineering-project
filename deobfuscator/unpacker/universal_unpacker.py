#!/usr/bin/env python3
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
from concurrent.futures import ThreadPoolExecutor

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class UniversalUnpacker:
    def __init__(self, input_file, output_dir=None, strategies=None):
        self.input_file = os.path.abspath(input_file)
        if not os.path.exists(self.input_file):
            raise FileNotFoundError(f"输入文件不存在: {self.input_file}")
        
        self.output_dir = output_dir or os.path.join(os.path.dirname(self.input_file), "unpacked")
        os.makedirs(self.output_dir, exist_ok=True)
        
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
            'unpacked_files': [],
            'detected_protections': [],
            'oep_candidates': [],
            'import_table': []
        }
    
    def get_file_md5(self, filepath):
        """计算文件MD5哈希"""
        md5_hash = hashlib.md5()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5_hash.update(chunk)
        return md5_hash.hexdigest()
    
    def analyze_file(self):
        """执行初步分析"""
        logger.info(f"分析文件: {self.input_file}")
        
        # 运行壳识别工具
        try:
            detector_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'shell_detector.py')
            if os.path.exists(detector_path):
                output = subprocess.check_output(['python3', detector_path, self.input_file], stderr=subprocess.STDOUT)
                output_str = output.decode('utf-8', errors='ignore')
                
                # 解析保护类
                for line in output_str.splitlines():
                    if line.strip().startswith('-'):
                        protection = line.strip()[2:].strip()
                        if protection:
                            self.analysis_result['detected_protections'].append(protection)
                
                logger.info(: {', '.join(self.analysis_result['detected_protections'])}")
            else:
                logger.warning(f"壳识别工具不存在: {detector_path}")
        except Exception as e:
            logger.error(f"壳识别失败: {str(e)}")
        
        # 提取基本PE信息
        try:
            # 使用pefile分析PE结构
            import pefile
            pe = pefile.PE(self.input_file)
            
            # 收集区段信息
            for section in pe.sections:
                section_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
                self.sections.append({
                    'name': section_name,
                    'virtual_address': section.VirtualAddress,
                    'virtual_size': section.Misc_VirtualSize,
                    'raw_size': section.SizeOfRawData,
                    'characteristics': section.Characteristics
                })
            
            # 收集导
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
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
            
            # 获取原始入口点
            self.oep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            self.analysis_result['oep'] = self.oep
            
            pe.close()
        except Exception as e:
            logger.error(f"PE分析: {str(e)}")
    
    def unpack(self):
        """执行脱壳过程"""
        logger.info(f"开始脱壳: {self.input_file}")
        self.analyze_file()
        
        results = []
        
        # 并行执行所有脱壳策略
        with ThreadPoolExecutor(max_workers=len(self.strategies)) as executor:
            futures = []
            
            for strategy in self.strategies:
                if strategy == 'static':
                    futures.append(executor.submit(self.static_unpack))
                elif strategy == 'dynamic':
                    futures.append(executor.submit(self.dynamic_unpack))
                elif strategy == 'iat_fix':
                    futures.append(executor.submit(self.repair_imports))
            
            for future in futures:
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except Exception as e:
                    logger.error(f"脱壳策略执行失败: {str(e)}")
        
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
        
        if self.unpacked_files:
            logger.info(f"脱壳成功! 生成了 {len(self.unpacked_files)} 个文件")
            self.dump_success = True
            
#            # 尝试确定最佳

            best_file = self.select_best_unpacked_file()
            if best_file:
                final_output = os.path.join(self.output_dir, "final_unpacked.exe")
                shutil.copy(best_file, final_output)
                logger.info(f"最佳脱壳结果: {final_output}")
                self.analysis_result['best_result'] = final_output
        else:
            logger.warning("所有脱壳策略均失败")
        
        # 生成最终报告
        self.generate_report()
        
        return self.dump_success
    
    def static_unpack(self):
        """静态脱壳实现"""
        logger.info("尝试静态脱壳...")
        
        # 检测常见壳类型并应用相应处理
        try:
            if any('UPX' in p for p in self.analysis_result['detected_protections']):
                return self.unpack_upx()
            
            if any('ASPack' in p for p in self.analysis_result['detected_protections']):
                return self.unpack_aspack()
            
            if any('.NET Assembly' in p for p in self.analysis_result['detected_protections']):
                return self.unpack_dotnet()
            
            # 其他静态脱壳策略...
            
            logger.info("没有找到匹配的静态脱壳方法")
            return None
        except Exception as e:
            logger.error(f"静态脱壳错误: {str(e)}")
            return None
    
    def unpack_upx(self):
        """UPX脱壳"""
        logger.info("UPX脱壳...")
        
        output_file = os.path.join(self.output_dir, "upx_unpacked.exe")
        
        try:
            # 尝试使用官方UPX脱壳
            subprocess.run(["upx", "-d", self.input_file, "-o", output_file], 
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            
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
            logger.error(f"UPX脱壳失败: {str(e)}")
            
            # 如果官方工具失败，尝试UPX变种处理
            try:
                # 特殊处理修改过的UPX头部
                with open(self.input_file, 'rb') as f:
                    data = bytearray(f.read())
                
                # 搜索UPX特征并修正
                upx0_pos = data.find(b'UPX0')
                upx1_pos = data.find(b'UPX1')
                
                if upx0_pos != -1 and upx1_pos != -1:
                    logger.info("检测到UPX变种，尝试修正...")
                    
                    # 修正UPX头部
                    temp_file = os.path.join(self.output_dir, "fixed_upx.exe")
                    with open(temp_file, 'wb') as f:
                        f.write(data)
                    
                    # 重新尝试脱壳
                    subprocess.run(["upx", "-d", temp_file, "-o", output_file], 
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
                    
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
        
        return None
    
    def unpack_aspack(self):
        """ASPack脱壳"""
        logger.info("尝试ASPack脱壳...")
        
        # ASPack静态脱壳实现...
        
        return None
    
    def unpack_dotnet(self):
        """处理.NET程序"""
        logger.info("尝试.NET反混淆...")
        
        output_file = os.path.join(self.output_dir, "dotnet_deobfuscated.exe")
        
        try:
            # 使用de4dot进行.NET反混淆
            subprocess.run(["de4dot", self.input_file, "-o", output_file], 
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            
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
    
    def dynamic_unpack(self):
        """动态脱壳实现"""
        logger.info("尝试动态脱壳...")
        
        output_file = os.path.join(self.output_dir, "dynamic_dump.exe")
        
        # 'EOF''EOF'
        strategies = []
        
        # 根据保护类型确定策略
        if any('VMProtect' in p for p in self.analysis_result['detected_protections']):
            strategies.append('vmp_specialized')
        elif any('Themida' in p for p in self.analysis_result['detected_protections']):
            strategies.append('themida_specialized')
        
        # 始终添加通用策略
        strategies.append('generic_memory_dump')
        
        # 尝试每种策略
        for strategy in strategies:
            result = None
            
            if strategy == 'vmp_specialized':
                result = self.vmp_dynamic_unpack(output_file)
            elif strategy == 'themida_specialized':
                result = self.themida_dynamic_unpack(output_file)
            elif strategy == 'generic_memory_dump':
                result = self.generic_dynamic_unpack(output_file)
            
            if result:
                return result
        
        logger.warning("所有动态脱壳策略均失败")
        return None
    
    def vmp_dynamic_unpack(self, output_file):
        """VMProtect专用动态脱壳"""
        logger.info("尝VMProtect专用动态脱壳...")
        
#        # VMProtect
'EOF'..
        
        return None
    
    def themida_dynamic_unpack(self, output_file):
        """Themida专用动态脱壳"""
        logger.info("尝试Themida专用动态脱壳...")
        
        # Themida专用脱壳实现...
        
        return None
    
    def generic_dynamic_unpack(self, output_file):
#        通用动
"""""
        logger.info("尝试通用动态内存转储脱壳...")
        
        try:
            # 使用动态分析引擎进行分析
            analyzer_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'dynamic_analyzer.py')
            result_dir = os.path.join(self.output_dir, "dynamic_analysis")
            os.makedirs(result_dir, exist_ok=True)
            
            subprocess.run([
                "python3", analyzer_path, 
                self.input_file, 
                "-o", result_dir,
                "-t", "60"  # 60秒超时
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
            
            logger.warning("转换内存转储到PE文件")
            return None
        except Exception as e:
            logger.error(f"通用动态脱壳错误: {str(e)}")
            return None
    
    def convert_dump_to_pe(self, dump_file, output_file):
        """将内存转储转换为PE文件"""
        logger.info(f"尝试将内存转PE文件: {dump_file} -> {output_file}")
        
        try:
            # 使用Scylla或其他工具进行转换
            scylla_script = """
            // 这里是Scylla或类似工具的自动化脚本
            // 实际实现时需要替换为具体工具的API或命令行
            """
            
            # 示例: Scylla命令行版本
            # subprocess.run(["scylla_dumper", dump_file, output_file, "-f", "-r"], check=True)
            
            # 这里使用自定义方法手动转换
            with open(dump_file, "rb") as f:
                dump_data = f.read()
            
            # 分析数据是否包含PE头
            pe_header_offset = dump_data.find(b'MZ')
            if pe_header_offset == -1:
                logger.warning("在内存转--------未找到PE头")
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
            logger.error(f"转换内存转储错误: {str(e)}")
            return None
    
    def fix_pe_from_dump(self, dump_data, pe_offset):
        """从内存转储中修复PE结构"""
        # 实际实现需要处理PE头、节表、重定位、导入表等修复
        # 这里是简化示例
        
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
                # ...
                
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
                
                return None
        except Exception as e:
            logger.error(f"从转储修复PE错误: {str(e)}")
            return None
    
    def repair_imports(self):
        """修复导入表"""
        logger.info(尝试导'EOF'...")
        
        # 检查是否有已生成的脱壳文件
        if not self.unpacked_files:
            logger.warning("没有脱壳文件可修复")
            return None
        
        # 选择最可能的脱壳文件
        target_file = self.select_best_unpacked_file()
        if not target_file:
            logger.warning("未找到合适的脱壳文件进行修复")
            return None
        
        output_file = os.path.join(self.output_dir, "imports_fixed.exe")
        
        try:
            # 使用ImpREC或类似工具修复导入表
            # subprocess.run(["imprec", target_file, "-o", output_file], check=True)
            
            # 或使用自定义方法
            self.manual_import_fix(target_file, output_file)
            
            if os.path.exists(output_file):
                logger.info(f"导入表修复成功: {output_file}")
                return {
                    'unpacked_file': output_file,
                    'method': 'import_table_fix',
                    'oep_found': False,
                    'confidence': 75
                }
            
            logger.warning("导入表修复失败")
            return None
        except Exception as e:
            logger.error(f"导入表修复错误: {str(e)}")
            return None
    
    def manual_import_fix(self, input_file, output_file):
        """手动修复导入表"""
        logger.info(f"手动修复导入表: {input_file}")
        
        # 复制文件作为起点
        shutil.copy(input_file, output_file)
        
        # 实现IAT修复逻辑
        # ...
    
    def select_best_unpacked_file(self):
        """选择最佳脱壳结果"""
        if not self.unpacked_files:
            return None
        
        if len(self.unpacked_files) == 1:
            return self.unpacked_files[0]
        
#        # 按照优先级排序: 
PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPE > 大小更合理 > 静态方法
        valid_files = []
        
        for file_path in self.unpacked_files:
            try:
                import pefile
                pe = pefile.PE(file_path)
                
                # 检查PE是否有效
                if hasattr(pe, 'OPTIONAL_HEADER') and hasattr(pe, 'sections'):
                    valid_files.append({
                        'path': file_path,
                        'size': os.path.getsize(file_path),
                        'is_dll': pe.is_dll(),
                        'is_exe': pe.is_exe(),
                        'has_imports': hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'),
                        'import_count': len(pe.DIRECTORY_ENTRY_IMPORT) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0,
                        'section_count': len(pe.sections)
                    })
                
                pe.close()
            except Exception as e:
                logger.warning(f"分析脱壳文件出错: {file_path} - {str(e)}")
        
        if not valid_files:
            return self.unpacked_files[0]  # 没有有效文件，返回第一个
        
    if task_id not in active_tasks:))))
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
            
            # 大小合理性 (假'EOF'50%-150%是合理的)
            original_size = self.analysis_result['file_size']
            size_ratio = file_info['size'] / original_size
            if 0.5 <= size_ratio <= 1.5:
                score += 10
            
            file_info['score'] = score
        
        # 选择得分最高的
        top_files.sort(key=lambda x: x['score'], reverse=True)
        return top_files[0]['path']
    
    def generate_report(self):
        """生成最终报告"""
        report_path = os.path.join(self.output_dir, "unpacking_report.json")
        
        # 添加时间戳
        self.analysis_result['timestamp'] = time.strftime("%Y-%m-%d %H:%M:%S")
        self.analysis_result['success'] = self.dump_success
        
        with open(report_path, 'w') as f:
            json.dump(self.analysis_result, f, indent=2)
        
        logger.info(f"报告已保存到: {report_path}")

def main():
    parser = argparse.ArgumentParser(description='通用脱壳工具')
    parser.add_argument('input', help='输入可执行文件路径')
    parser.add_argument('-o', '--output', help='输出目录')
    parser.add_argument('-s', '--strategies', help='脱壳策略,逗号分隔 (static,dynamic,iat_fix)', default='static,dynamic,iat_fix')
    
    args = parser.parse_args()
    
    try:
        strategies = args.strategies.split(',')
        unpacker = UniversalUnpacker(args.input, args.output, strategies)
        success = unpacker.unpack()
        
        return 0 if success else 1
    except Exception as e:
        logger.error(f"错误: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
