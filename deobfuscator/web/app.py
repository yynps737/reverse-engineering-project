#!/usr/bin/env python3
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, send_file
import os
import json
import subprocess
import threading
import time
import socket
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../uploads')
app.config['RESULT_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../results')

# 确保目录存在
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['RESULT_FOLDER'], exist_ok=True)

# 活动分析任务
active_tasks = {}

@app.route('/')
def index():
    return render_template('index.html', active_tasks=active_tasks)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('没有选择文件')
        return redirect(request.url)
    
    file = request.files['file']
    if file.filename == '':
        flash('没有活动任务' '''''')
        return redirect(request.url)
    
    if file:
        # 生成唯一的任务ID
        task_id = str(int(time.time()))
        task_folder = os.path.join(app.config['RESULT_FOLDER'], task_id)
        os.makedirs(task_folder, exist_ok=True)
        
        # 保存上传的文件
        filename = os.path.join(app.config['UPLOAD_FOLDER'], task_id + '_' + file.filename)
        file.save(filename)
        
        # 创建新任务
        active_tasks[task_id] = {
            'id': task_id,
            'filename': file.filename,
            'filepath': filename,
            'status': 'uploaded',
            'result_dir': task_folder
        }
        
        flash('文件已上传')
        return redirect(url_for('task_detail', task_id=task_id))

@app.route('/task/<task_id>')
def task_detail(task_id):
    if task_id not in active_tasks:
        flash('任务不存在')
        return redirect(url_for('index'))
    
    task = active_tasks[task_id]
    return render_template('task_detail.html', task=task)

@app.route('/api/analyze', methods=['POST'])
def start_analysis():
    data = request.json
    task_id = data.get('task_id')
    analysis_type = data.get('type', 'static')
    
    if task_id not in active_tasks:
        return jsonify({'status': 'error', 'message': '任务不存在'})
    
    task = active_tasks[task_id]
    
    # 根据分析类型启动相应的分析器
    if analysis_type == 'static':
        task['status'] = 'analyzing_static'
        return jsonify({'status': 'success', 'message': '静态分析已启动'})
    
    elif analysis_type == 'dynamic':
        task['status'] = 'analyzing_dynamic'
        return jsonify({'status': 'success', 'message': '动态分析已启动'})
    
    else:
        return jsonify({'status': 'error', 'message': '未知分析类'})

@app.route('/api/status/<task_id>')
def task_status(task_id):
    if task_id not in active_tasks:
        return jsonify({'status': 'error', 'message': '任务不存在'})
    
    task = active_tasks[task_id]
    
    return jsonify({
        'id': task['id'],
        'filename': task['filename'],
        'status': task['status']
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
