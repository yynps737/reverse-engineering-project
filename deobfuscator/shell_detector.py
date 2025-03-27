#!/usr/bin/env python3
import os
import sys
import pefile
import hashlib
import struct
import yara
import subprocess
import logging
from concurrent.futures import ThreadPoolExecutor

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 综合壳识别规则库
RULES = """
rule UPX_Packer {
    strings:
        $upx1 = "UPX!" ascii
        $upx2 = "UPX0" ascii
        $upx3 = "UPX1" ascii
        $upx4 = "UPX2" ascii
    condition:
        2 of them
}

rule VMProtect {
    strings:
        $vmp1 = "VMProtect" ascii wide
        $vmp2 = ".vmp0" ascii
        $vmp3 = ".vmp1" ascii
        $vmp4 = "vmp_" ascii
        $vmp5 = {EB 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00}
    condition:
        any of them
}

rule Themida_Winlicense {
    strings:
        $th1 = "Themida" ascii wide
        $th2 = "WinLicense" ascii wide
        $th3 = ".themida" ascii
        $th4 = {55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00}
    condition:
        any of them
}

rule Enigma_Protector {
    strings:
        $enigma1 = "Enigma Protector" ascii wide
        $enigma2 = ".enigma" ascii
        $enigma3 = {60 E8 00 00 00 00 5D 83 ED 06 81 ED ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00}
    condition:
        any of them
}

rule ASProtect {
    strings:
        $asp1 = "ASProtect" ascii wide
        $asp2 = ".aspack" ascii
        $asp3 = ".adata" ascii
        $asp4 = {60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? BB ?? ?? ?? ?? 03 DD}
    condition:
        any of them
}

rule CodeVirtualizer {
    strings:
        $cv1 = "CodeVirtualizer" ascii wide
        $cv2 = "VirtualizerSDK" ascii wide
        $cv3 = {60 9C 54 24 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00}
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
    condition:
        uint16(0) == 0x5A4D and
        4 of them
}
"""

class PackerDetector:
    def __init__(self):
        self.compiled_rules = yara.compile(source=RULES)
        
    def analyze_file(self, file_path):
        try:
            # 基本文件信息
            file_size = os.path.getsize(file_path)
            md5_hash = hashlib.md5(open(file_path, 'rb').read()).hexdigest()
            
            # YARA 匹配
            matches = self.compiled_rules.match(file_path)
            detected_packers = [match.rule for match in matches]
            
            # PE结构分析
            try:
                pe = pefile.PE(file_path)
                high_entropy_sections = []
                suspicious_sections = []
                
                for section in pe.sections:
                    section_name = section.Name.decode('utf-8', 'ignore').strip('\x00')
                    section_entropy = self._calculate_entropy(section.get_data())
                    
                    if section_entropy > 7.0:
                        high_entropy_sections.append(f"{section_name} ({section_entropy:.2f})")
                    
                    if section.SizeOfRawData == 0 and section.Misc_VirtualSize > 0:
                        suspicious_sections.append(f"{section_name} (Virtual)")
                        
                # 导入表分析
                suspicious_imports = []
                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        dll_name = entry.dll.decode('utf-8', 'ignore')
                        if any(x in dll_name.lower() for x in ['crypt', 'ssl', 'winhttp', 'socket']):
                            suspicious_imports.append(dll_name)
                
                # 入口点分析
                ep_bytes = pe.get_data(pe.OPTIONAL_HEADER.AddressOfEntryPoint, 16)
                ep_signature = ' '.join([f'{b:02X}' for b in ep_bytes])
                
                # TLS回调检测
                has_tls_callbacks = hasattr(pe, 'DIRECTORY_ENTRY_TLS') and pe.DIRECTORY_ENTRY_TLS is not None
                                
                pe_info = {
                    "sections": [s.Name.decode('utf-8', 'ignore').strip('\x00') for s in pe.sections],
                    "high_entropy_sections": high_entropy_sections,
                    "suspicious_sections": suspicious_sections,
                    "suspicious_imports": suspicious_imports,
                    "ep_signature": ep_signature,
                    "has_tls_callbacks": has_tls_callbacks
                }
            except Exception as e:
                pe_info = {"error": str(e)}
            
            # 添加额外检测
            additional_packers = self._additional_detection(file_path)
            if additional_packers:
                detected_packers.extend(additional_packers)
            
            if not detected_packers:
                detected_packers = ["Unknown/Custom Packer"]
            
            return {
                "file_path": file_path,
                "file_size": file_size,
                "md5": md5_hash,
                "detected_packers": list(set(detected_packers)),
                "pe_info": pe_info
            }
        except Exception as e:
            logging.error(f"Error analyzing {file_path}: {e}")
            return {
                "file_path": file_path,
                "error": str(e)
            }
    
    def _calculate_entropy(self, data):
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
            
    def _additional_detection(self, file_path):
        additional = []
        
        # 运行strings并查找特征
        try:
            strings_output = subprocess.check_output(['strings', file_path], stderr=subprocess.PIPE).decode('utf-8', 'ignore')
            
            if 'Microsoft .NET Runtime' in strings_output:
                additional.append('.NET Assembly')
                
            if 'python' in strings_output.lower() and ('import' in strings_output.lower() or 'module' in strings_output.lower()):
                additional.append('Python Packed')
                
            if 'Java' in strings_output and 'class' in strings_output:
                additional.append('Java JAR/Class')
        except:
            pass
            
        return additional

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <file_path>")
        sys.exit(1)
        
    file_path = sys.argv[1]
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        sys.exit(1)
        
    detector = PackerDetector()
    result = detector.analyze_file(file_path)
    
    print(f"\n{'=' * 50}")
    print(f"PACKER DETECTION REPORT")
    print(f"{'=' * 50}")
    print(f"File: {result['file_path']}")
    print(f"Size: {result['file_size']} bytes")
    print(f"MD5: {result['md5']}")
    print(f"\nDetected Protections:")
    for packer in result['detected_packers']:
        print(f"  - {packer}")
    
    if 'pe_info' in result:
        if 'high_entropy_sections' in result['pe_info'] and result['pe_info']['high_entropy_sections']:
            print("\nHigh Entropy Sections (possibly packed/encrypted):")
            for section in result['pe_info']['high_entropy_sections']:
                print(f"  - {section}")
                
        if 'suspicious_imports' in result['pe_info'] and result['pe_info']['suspicious_imports']:
            print("\nSuspicious Imports (possibly network/crypto protection):")
            for imp in result['pe_info']['suspicious_imports']:
                print(f"  - {imp}")
                
        if 'has_tls_callbacks' in result['pe_info'] and result['pe_info']['has_tls_callbacks']:
            print("\nWARNING: TLS callbacks detected (anti-debugging technique)")
            
    print(f"\nRecommended Unpacking Strategy:")
    if 'VMProtect' in result['detected_packers']:
        print("  - Use VMProtect specific unpacker with emulation")
    elif 'Themida_Winlicense' in result['detected_packers']:
        print("  - Use Themida specialized dumper with hardware breakpoints")
    elif 'UPX_Packer' in result['detected_packers']:
        print("  - Use standard UPX unpacker")
    elif '.NET Assembly' in result['detected_packers']:
        print("  - Use .NET deobfuscation tools")
    else:
        print("  - Use generic dynamic unpacking with memory dumping")
        
    print(f"{'=' * 50}\n")

if __name__ == "__main__":
    import math
    main()
