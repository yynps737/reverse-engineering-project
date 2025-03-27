#!/usr/bin/env python3
"""
逆向工程平台Web界面
提供文件上传、任务管理和分析报告查看功能
"""
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, send_file, abort, session # type: ignore
import os
import sys
import json
import uuid
import time
import logging
import threading
import subprocess
import tempfile
import shutil
import hashlib
from werkzeug.utils import secure_filename # type: ignore
from datetime import datetime, timedelta
from functools import wraps
from typing import Dict, List, Any, Optional, Tuple, Union

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("web_app.log")
    ]
)
logger = logging.getLogger(__name__)

# 创建Flask应用
app = Flask(__name__)

# 配置
app.config.update(
    SECRET_KEY=os.urandom(24),
    MAX_CONTENT_LENGTH=100 * 1024 * 1024,  # 最大上传100MB
    UPLOAD_FOLDER=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'uploads'),
    RESULT_FOLDER=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'results'),
    SESSION_COOKIE_SECURE=False,  # 本地开发设为False，生产环境设为True
    SESSION_COOKIE_HTTPONLY=True,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
    APP_VERSION="2.0.0"
)

# 确保目录存在
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['RESULT_FOLDER'], exist_ok=True)

# 活动分析任务
active_tasks = {}

# 文件后缀白名单
ALLOWED_EXTENSIONS = {'exe', 'dll', 'sys', 'bin', 'so', 'dylib', 'elf', 'pyc', 'class', 'apk', 'dex', 'jar'}

# 工具路径
TOOLS = {
    'shell_detector': os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'shell_detector.py')),
    'dynamic_analyzer': os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'dynamic_analyzer.py')),
    'universal_unpacker': os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'unpacker', 'universal_unpacker.py'))
}

# 安全检查装饰器
def validate_task_id(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        task_id = kwargs.get('task_id', '')
        # 确保task_id只包含字母、数字和下划线，避免目录遍历
        if not task_id or not task_id.replace('_', '').isalnum():
            flash('无效的任务ID')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    """首页 - 显示所有活动任务"""
    return render_template('index.html', active_tasks=active_tasks, app_version=app.config['APP_VERSION'])

@app.route('/upload', methods=['POST'])
def upload_file():
    """处理文件上传请求"""
    if 'file' not in request.files:
        flash('没有选择文件')
        return redirect(url_for('index'))
    
    file = request.files['file']
    if file.filename == '':
        flash('没有选择文件')
        return redirect(url_for('index'))
    
    if file and allowed_file(file.filename):
        # 生成唯一的任务ID
        task_id = str(int(time.time())) + '_' + str(uuid.uuid4())[:8]
        task_folder = os.path.join(app.config['RESULT_FOLDER'], task_id)
        os.makedirs(task_folder, exist_ok=True)
        
        # 保存上传的文件
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], f"{task_id}_{filename}")
        file.save(filepath)
        
        # 计算文件hash
        md5_hash = hashlib.md5()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                md5_hash.update(chunk)
        
        # 创建新任务
        active_tasks[task_id] = {
            'id': task_id,
            'filename': filename,
            'filepath': filepath,
            'status': 'uploaded',
            'result_dir': task_folder,
            'upload_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'size': os.path.getsize(filepath),
            'md5': md5_hash.hexdigest(),
            'analysis_results': {}
        }
        
        # 初步文件分析
        try:
            initial_analysis = perform_initial_analysis(filepath)
            active_tasks[task_id]['initial_analysis'] = initial_analysis
        except Exception as e:
            logger.error(f"初步分析错误: {str(e)}")
            active_tasks[task_id]['initial_analysis'] = {"error": str(e)}
        
        flash('文件已上传，可以开始分析')
        return redirect(url_for('task_detail', task_id=task_id))
    else:
        flash('不支持的文件类型')
        return redirect(url_for('index'))

@app.route('/task/<task_id>')
@validate_task_id
def task_detail(task_id):
    """显示任务详情页面"""
    if task_id not in active_tasks:
        flash('任务不存在')
        return redirect(url_for('index'))
    
    task = active_tasks[task_id]
    return render_template('task_detail.html', task=task)

@app.route('/api/analyze', methods=['POST'])
def start_analysis():
    """启动分析任务API"""
    data = request.json
    task_id = data.get('task_id')
    analysis_type = data.get('type', 'static')
    
    if task_id not in active_tasks:
        return jsonify({'status': 'error', 'message': '任务不存在'})
    
    task = active_tasks[task_id]
    
    # 防止重复启动分析
    if task['status'].startswith(f'analyzing_{analysis_type}'):
        return jsonify({'status': 'error', 'message': '此类型的分析已在进行中'})
    
    # 更新任务状态
    task['status'] = f'analyzing_{analysis_type}'
    
    # 在后台线程启动分析
    analysis_thread = threading.Thread(
        target=run_analysis,
        args=(task_id, analysis_type)
    )
    analysis_thread.daemon = True
    analysis_thread.start()
    
    return jsonify({
        'status': 'success', 
        'message': f'{analysis_type}分析已启动',
        'task_id': task_id
    })

@app.route('/api/status/<task_id>')
@validate_task_id
def task_status(task_id):
    """获取任务状态API"""
    if task_id not in active_tasks:
        return jsonify({'status': 'error', 'message': '任务不存在'})
    
    task = active_tasks[task_id]
    
    response = {
        'id': task['id'],
        'filename': task['filename'],
        'status': task['status'],
        'upload_time': task.get('upload_time', ''),
        'size': task.get('size', 0),
        'md5': task.get('md5', '')
    }
    
    # 如果分析完成，添加结果信息
    if task['status'].endswith('_completed'):
        analysis_type = task['status'].split('_')[1]  # 从状态中提取分析类型
        if analysis_type in task.get('analysis_results', {}):
            response['results'] = {
                'type': analysis_type,
                'summary': task['analysis_results'][analysis_type].get('summary', {}),
                'reports': task['analysis_results'][analysis_type].get('reports', [])
            }
    
    return jsonify(response)

@app.route('/api/result/<task_id>/<result_type>')
@validate_task_id
def get_result(task_id, result_type):
    """获取分析结果API"""
    if task_id not in active_tasks:
        return jsonify({'status': 'error', 'message': '任务不存在'})
    
    task = active_tasks[task_id]
    
    # 确保结果类型有效且分析已完成
    valid_types = ['static', 'dynamic', 'unpacked']
    if result_type not in valid_types:
        return jsonify({'status': 'error', 'message': '无效的结果类型'})
    
    if not task['status'].endswith('_completed'):
        return jsonify({'status': 'error', 'message': '分析尚未完成'})
    
    if result_type not in task.get('analysis_results', {}):
        return jsonify({'status': 'error', 'message': f'无{result_type}分析结果'})
    
    return jsonify({
        'status': 'success',
        'task_id': task_id,
        'result_type': result_type,
        'results': task['analysis_results'][result_type]
    })

@app.route('/api/download/<task_id>/<path:filename>')
@validate_task_id
def download_file(task_id, filename):
    """下载结果文件API"""
    if task_id not in active_tasks:
        return jsonify({'status': 'error', 'message': '任务不存在'})
    
    task = active_tasks[task_id]
    
    # 安全检查，防止目录遍历攻击
    safe_filename = secure_filename(os.path.basename(filename))
    
    # 构建文件路径
    file_path = os.path.join(task['result_dir'], safe_filename)
    
    # 检查文件是否存在
    if not os.path.exists(file_path) or not os.path.isfile(file_path):
        abort(404)
    
    # 发送文件
    return send_file(file_path, as_attachment=True)

@app.route('/api/delete/<task_id>', methods=['POST'])
@validate_task_id
def delete_task(task_id):
    """删除任务API"""
    if task_id not in active_tasks:
        return jsonify({'status': 'error', 'message': '任务不存在'})
    
    task = active_tasks[task_id]
    
    # 删除文件
    try:
        # 删除上传的文件
        if os.path.exists(task['filepath']):
            os.remove(task['filepath'])
        
        # 删除结果目录
        if os.path.exists(task['result_dir']):
            shutil.rmtree(task['result_dir'])
        
        # 从活动任务中移除
        del active_tasks[task_id]
        
        return jsonify({'status': 'success', 'message': '任务已删除'})
    except Exception as e:
        logger.error(f"删除任务错误: {str(e)}")
        return jsonify({'status': 'error', 'message': f'删除任务错误: {str(e)}'})

def perform_initial_analysis(filepath):
    """
    对上传的文件进行初步分析
    
    Args:
        filepath: 文件路径
        
    Returns:
        初步分析结果字典
    """
    result = {
        'file_type': 'Unknown',
        'arch': 'Unknown',
        'is_pe': False,
        'is_elf': False,
        'is_macho': False,
        'is_java': False,
        'is_python': False
    }
    
    try:
        # 读取文件头部
        with open(filepath, 'rb') as f:
            header = f.read(16)
        
        # 检测文件类型
        if header.startswith(b'MZ'):
            result['file_type'] = 'PE Executable'
            result['is_pe'] = True
            
            # 进一步分析PE文件
            try:
                import pefile # type: ignore
                pe = pefile.PE(filepath)
                
                # 获取架构信息
                if pe.FILE_HEADER.Machine == 0x14c:
                    result['arch'] = 'x86'
                elif pe.FILE_HEADER.Machine == 0x8664:
                    result['arch'] = 'x64'
                elif pe.FILE_HEADER.Machine == 0x1c0:
                    result['arch'] = 'ARM'
                elif pe.FILE_HEADER.Machine == 0xaa64:
                    result['arch'] = 'ARM64'
                
                # 检查是否为.NET程序
                if hasattr(pe, 'DIRECTORY_ENTRY_COM_DESCRIPTOR') and pe.DIRECTORY_ENTRY_COM_DESCRIPTOR:
                    result['file_type'] = '.NET Assembly'
                
                # 检查是DLL还是EXE
                if pe.is_dll():
                    result['file_type'] += ' (DLL)'
                elif pe.is_exe():
                    result['file_type'] += ' (EXE)'
                
                pe.close()
            except ImportError:
                logger.warning("未安装pefile模块，无法进行深入PE分析")
            except Exception as e:
                logger.warning(f"PE分析错误: {str(e)}")
        
        elif header.startswith(b'\x7fELF'):
            result['file_type'] = 'ELF Binary'
            result['is_elf'] = True
            
            # ELF架构检测
            if header[4] == 1:  # 32位
                result['arch'] = 'x86'
            elif header[4] == 2:  # 64位
                result['arch'] = 'x64'
        
        elif header.startswith(b'\xca\xfe\xba\xbe') or header.startswith(b'\xcf\xfa\xed\xfe'):
            result['file_type'] = 'Mach-O Binary'
            result['is_macho'] = True
        
        elif header.startswith(b'PK\x03\x04'):
            # 可能是JAR或ZIP
            result['file_type'] = 'ZIP/JAR Archive'
            
            # 检查是否为JAR
            try:
                import zipfile
                with zipfile.ZipFile(filepath) as zf:
                    if any(name.endswith('.class') for name in zf.namelist()):
                        result['file_type'] = 'Java JAR'
                        result['is_java'] = True
            except ImportError:
                logger.warning("未安装zipfile模块，无法检查JAR内容")
            except Exception as e:
                logger.warning(f"JAR分析错误: {str(e)}")
        
        elif filepath.endswith('.class'):
            result['file_type'] = 'Java Class'
            result['is_java'] = True
        
        elif filepath.endswith('.pyc'):
            result['file_type'] = 'Python Bytecode'
            result['is_python'] = True
        
        # 尝试使用file命令获取更多信息
        try:
            import subprocess
            file_output = subprocess.check_output(['file', '-b', filepath], stderr=subprocess.STDOUT)
            file_output = file_output.decode('utf-8', errors='ignore').strip()
            result['file_cmd_output'] = file_output
        except:
            logger.warning("无法使用file命令")
        
        return result
    except Exception as e:
        logger.error(f"初步分析错误: {str(e)}")
        return {'error': str(e)}

def run_analysis(task_id, analysis_type):
    """
    执行分析任务
    
    Args:
        task_id: 任务ID
        analysis_type: 分析类型 (static, dynamic, unpacker)
    """
    if task_id not in active_tasks:
        logger.error(f"任务不存在: {task_id}")
        return
    
    task = active_tasks[task_id]
    logger.info(f"开始{analysis_type}分析，任务ID: {task_id}, 文件: {task['filename']}")
    
    try:
        # 记录工具路径情况
        logger.info(f"执行工具路径检查: {TOOLS}")
        for tool_name, tool_path in TOOLS.items():
            if not os.path.exists(tool_path):
                logger.error(f"工具不存在: {tool_name} -> {tool_path}")
            else:
                logger.info(f"工具存在: {tool_name} -> {tool_path}")
        
        # 检查目录权限
        result_dir = task['result_dir']
        if not os.access(result_dir, os.W_OK):
            logger.error(f"没有结果目录的写入权限: {result_dir}")
        else:
            logger.info(f"结果目录检查通过: {result_dir}")
        
        # 根据分析类型执行相应的工具
        if analysis_type == 'static':
            result = run_static_analysis(task)
        elif analysis_type == 'dynamic':
            result = run_dynamic_analysis(task)
        elif analysis_type == 'unpacker':
            result = run_unpacker(task)
        else:
            raise ValueError(f"未知的分析类型: {analysis_type}")
        
        # 更新任务状态和结果
        task['status'] = f'{analysis_type}_completed'
        if 'analysis_results' not in task:
            task['analysis_results'] = {}
        
        task['analysis_results'][analysis_type] = result
        logger.info(f"{analysis_type}分析完成，任务ID: {task_id}")
    except Exception as e:
        # 记录完整的错误信息
        logger.error(f"{analysis_type}分析错误，任务ID: {task_id}，错误: {str(e)}")
        logger.error(traceback.format_exc())
        
        task['status'] = f'{analysis_type}_failed'
        if 'analysis_results' not in task:
            task['analysis_results'] = {}
        
        task['analysis_results'][analysis_type] = {
            'error': str(e),
            'summary': {'status': 'failed', 'error': str(e)},
            'reports': []
        }

def run_static_analysis(task):
    """
    执行静态分析
    
    Args:
        task: 任务数据
        
    Returns:
        分析结果字典
    """
    filepath = task['filepath']
    result_dir = task['result_dir']
    
    # 创建静态分析结果目录
    static_dir = os.path.join(result_dir, 'static')
    os.makedirs(static_dir, exist_ok=True)
    
    # 运行shell_detector.py
    shell_detector = TOOLS['shell_detector']
    report_path = os.path.join(static_dir, 'shell_detection_report.txt')
    json_report_path = os.path.join(static_dir, 'shell_detection_report.json')
    
    try:
        # 检查shell_detector是否存在
        if not os.path.exists(shell_detector):
            raise FileNotFoundError(f"未找到壳检测工具: {shell_detector}")
        
        # 运行shell_detector
        subprocess.run(
            ['python3', shell_detector, filepath, '-o', json_report_path, '-f', 'json'],
            stdout=open(report_path, 'w'),
            stderr=subprocess.STDOUT,
            check=True,
            timeout=300  # 5分钟超时
        )
        
        # 读取JSON报告
        detection_result = {}
        if os.path.exists(json_report_path):
            with open(json_report_path, 'r') as f:
                detection_result = json.load(f)
        
        # 解析检测结果
        detected_protections = detection_result.get('detected_packers', [])
        summary = {
            'status': 'completed',
            'detected_protections': detected_protections,
            'file_size': task['size'],
            'md5': task['md5']
        }
        
        # 生成报告列表
        reports = [
            {'name': 'Shell Detection Report (Text)', 'path': os.path.relpath(report_path, result_dir)},
            {'name': 'Shell Detection Report (JSON)', 'path': os.path.relpath(json_report_path, result_dir)}
        ]
        
        # 如果有HTML报告也添加
        html_report_path = os.path.join(static_dir, 'shell_detection_report.html')
        if os.path.exists(html_report_path):
            reports.append({
                'name': 'Shell Detection Report (HTML)', 
                'path': os.path.relpath(html_report_path, result_dir)
            })
        
        # 执行字符串提取
        strings_path = os.path.join(static_dir, 'strings.txt')
        try:
            subprocess.run(
                ['strings', filepath],
                stdout=open(strings_path, 'w'),
                stderr=subprocess.DEVNULL,
                check=True,
                timeout=60  # 1分钟超时
            )
            
            reports.append({
                'name': 'Extracted Strings', 
                'path': os.path.relpath(strings_path, result_dir)
            })
        except Exception as e:
            logger.warning(f"字符串提取失败: {str(e)}")
        
        # 返回结果
        return {
            'summary': summary,
            'reports': reports,
            'detected_protections': detected_protections,
            'raw_data': detection_result
        }
    except subprocess.TimeoutExpired:
        raise TimeoutError("静态分析超时")
    except Exception as e:
        raise RuntimeError(f"静态分析失败: {str(e)}")

def run_dynamic_analysis(task):
    """
    执行动态分析
    
    Args:
        task: 任务数据
        
    Returns:
        分析结果字典
    """
    filepath = task['filepath']
    result_dir = task['result_dir']
    
    # 创建动态分析结果目录
    dynamic_dir = os.path.join(result_dir, 'dynamic')
    os.makedirs(dynamic_dir, exist_ok=True)
    
    # 运行dynamic_analyzer.py
    dynamic_analyzer = TOOLS['dynamic_analyzer']
    
    try:
        # 检查dynamic_analyzer是否存在
        if not os.path.exists(dynamic_analyzer):
            raise FileNotFoundError(f"未找到动态分析工具: {dynamic_analyzer}")
        
        # 运行dynamic_analyzer
        subprocess.run(
            ['python3', dynamic_analyzer, filepath, '-o', dynamic_dir, '-t', '300', '-w'],
            stdout=open(os.path.join(dynamic_dir, 'analyzer_output.log'), 'w'),
            stderr=subprocess.STDOUT,
            check=True,
            timeout=600  # 10分钟超时
        )
        
        # 读取JSON报告
        json_report_path = os.path.join(dynamic_dir, 'analysis_report.json')
        analysis_result = {}
        
        if os.path.exists(json_report_path):
            with open(json_report_path, 'r') as f:
                analysis_result = json.load(f)
        
        # 解析分析结果
        protection_summary = analysis_result.get('protection_summary', {})
        protection_level = protection_summary.get('protection_level', 'Unknown')
        detected_protections = protection_summary.get('detected_protections', [])
        
        summary = {
            'status': 'completed',
            'protection_level': protection_level,
            'detected_protections': detected_protections,
            'file_size': task['size'],
            'md5': task['md5']
        }
        
        # 收集所有报告文件
        reports = []
        
        # HTML报告
        html_report_path = os.path.join(dynamic_dir, 'analysis_report.html')
        if os.path.exists(html_report_path):
            reports.append({
                'name': 'Dynamic Analysis Report (HTML)', 
                'path': os.path.relpath(html_report_path, result_dir)
            })
        
        # JSON报告
        if os.path.exists(json_report_path):
            reports.append({
                'name': 'Dynamic Analysis Report (JSON)', 
                'path': os.path.relpath(json_report_path, result_dir)
            })
        
        # 内存转储
        memory_dumps_dir = os.path.join(dynamic_dir, 'memory_dumps')
        if os.path.exists(memory_dumps_dir):
            dumps = [f for f in os.listdir(memory_dumps_dir) if f.endswith('.bin')]
            for i, dump in enumerate(dumps):
                reports.append({
                    'name': f'Memory Dump #{i+1}', 
                    'path': os.path.relpath(os.path.join(memory_dumps_dir, dump), result_dir)
                })
        
        # 网络捕获
        network_dir = os.path.join(dynamic_dir, 'network_data')
        if os.path.exists(network_dir):
            network_files = [f for f in os.listdir(network_dir) if os.path.isfile(os.path.join(network_dir, f))]
            for i, net_file in enumerate(network_files):
                reports.append({
                    'name': f'Network Capture #{i+1}', 
                    'path': os.path.relpath(os.path.join(network_dir, net_file), result_dir)
                })
        
        # 返回结果
        return {
            'summary': summary,
            'reports': reports,
            'protection_level': protection_level,
            'detected_protections': detected_protections,
            'raw_data': analysis_result
        }
    except subprocess.TimeoutExpired:
        raise TimeoutError("动态分析超时")
    except Exception as e:
        raise RuntimeError(f"动态分析失败: {str(e)}")

def run_unpacker(task):
    """
    执行脱壳操作
    
    Args:
        task: 任务数据
        
    Returns:
        脱壳结果字典
    """
    filepath = task['filepath']
    result_dir = task['result_dir']
    
    # 创建脱壳结果目录
    unpacker_dir = os.path.join(result_dir, 'unpacked')
    os.makedirs(unpacker_dir, exist_ok=True)
    
    # 运行universal_unpacker.py
    universal_unpacker = TOOLS['universal_unpacker']
    
    try:
        # 检查unpacker是否存在
        if not os.path.exists(universal_unpacker):
            raise FileNotFoundError(f"未找到脱壳工具: {universal_unpacker}")
        
        # 运行unpacker
        subprocess.run(
            ['python3', universal_unpacker, filepath, '-o', unpacker_dir],
            stdout=open(os.path.join(unpacker_dir, 'unpacker_output.log'), 'w'),
            stderr=subprocess.STDOUT,
            check=True,
            timeout=600  # 10分钟超时
        )
        
        # 读取JSON报告
        json_report_path = os.path.join(unpacker_dir, 'unpacking_report.json')
        unpacking_result = {}
        
        if os.path.exists(json_report_path):
            with open(json_report_path, 'r') as f:
                unpacking_result = json.load(f)
        
        # 解析脱壳结果
        success = unpacking_result.get('success', False)
        detected_protections = unpacking_result.get('detected_protections', [])
        unpacked_files = unpacking_result.get('unpacked_files', [])
        
        summary = {
            'status': 'completed',
            'success': success,
            'detected_protections': detected_protections,
            'unpacked_files_count': len(unpacked_files),
            'file_size': task['size'],
            'md5': task['md5']
        }
        
        # 收集报告文件
        reports = []
        
        # JSON报告
        if os.path.exists(json_report_path):
            reports.append({
                'name': 'Unpacking Report (JSON)', 
                'path': os.path.relpath(json_report_path, result_dir)
            })
        
        # HTML报告
        html_report_path = os.path.join(unpacker_dir, 'unpacking_report.html')
        if os.path.exists(html_report_path):
            reports.append({
                'name': 'Unpacking Report (HTML)', 
                'path': os.path.relpath(html_report_path, result_dir)
            })
        
        # 脱壳文件
        for i, unpacked in enumerate(unpacked_files):
            path = unpacked.get('path', '')
            if os.path.exists(path):
                reports.append({
                    'name': f'Unpacked File #{i+1}', 
                    'path': os.path.relpath(path, result_dir)
                })
        
        # 最佳脱壳结果
        if 'best_result' in unpacking_result and os.path.exists(unpacking_result['best_result']):
            reports.append({
                'name': 'Best Unpacked Result', 
                'path': os.path.relpath(unpacking_result['best_result'], result_dir)
            })
        
        # 返回结果
        return {
            'summary': summary,
            'reports': reports,
            'success': success,
            'detected_protections': detected_protections,
            'unpacked_files': unpacked_files,
            'raw_data': unpacking_result
        }
    except subprocess.TimeoutExpired:
        raise TimeoutError("脱壳操作超时")
    except Exception as e:
        raise RuntimeError(f"脱壳操作失败: {str(e)}")

@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', error_code=404, error_message="页面不存在"), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('error.html', error_code=500, error_message="服务器内部错误"), 500

@app.route('/about')
def about():
    """关于页面"""
    return render_template('about.html', app_version=app.config['APP_VERSION'])

if __name__ == '__main__':
    # 设置主机和端口
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 8080))
    debug = os.environ.get('DEBUG', 'False').lower() == 'true'
    
    # 检查工具是否存在
    for name, path in TOOLS.items():
        if not os.path.exists(path):
            logger.warning(f"工具不存在: {name} 在 {path}")
    
    # 启动应用
    logger.info(f"启动Web界面，地址: {host}:{port}, 调试模式: {debug}")
    app.run(host=host, port=port, debug=debug)