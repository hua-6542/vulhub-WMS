#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Vulhub管理面板 - 支持Vulhub目录结构的完整实现
"""

import os
import subprocess
import json
import yaml
import time
import socket
import re
import shutil
import threading
import logging
from datetime import datetime
from flask import Flask, request, jsonify, render_template_string

try:
    import docker
    docker_available = True
except ImportError:
    docker_available = False

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('vulhub_manager')

app = Flask(__name__)
app.secret_key = 'vulhub-secret-key'

# 获取Vulhub路径 - 优先使用环境变量，默认值/opt/vulhub
VULHUB_PATH = os.environ.get('VULHUB_PATH', '/opt/vulhub')

# 确保目录存在
os.makedirs(VULHUB_PATH, exist_ok=True)
logger.info(f"使用Vulhub路径: {VULHUB_PATH}")

# 初始化Docker客户端
if docker_available:
    try:
        docker_client = docker.from_env(timeout=30)
        logger.info("Docker客户端初始化成功")
    except Exception as e:
        logger.error(f"Docker客户端初始化失败: {str(e)}")
        docker_client = None
        docker_available = False
else:
    docker_client = None
    logger.warning("Docker模块未安装，部分功能将不可用")

# 操作日志字典
operation_logs = {}

def run_command(cmd, cwd=None, log_key=None, timeout=300):
    """运行系统命令并返回输出和状态"""
    try:
        if log_key:
            if log_key not in operation_logs:
                operation_logs[log_key] = []
            operation_logs[log_key].append(f"⚡ 执行命令: {' '.join(cmd)}")
            operation_logs[log_key].append(f"📁 工作目录: {cwd or os.getcwd()}")

        # 记录原始命令
        full_cmd = " ".join(cmd)
        logger.info(f"运行命令: {full_cmd} in {cwd}")
        
        # 创建subprocess对象
        process = subprocess.Popen(
            cmd,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding='utf-8'
        )
        
        output_lines = []
        start_time = time.time()
        
        # 实时读取输出
        while True:
            # 检查是否超时
            if timeout and (time.time() - start_time) > timeout:
                process.terminate()
                output_lines.append("⏳ 命令执行超时，已终止")
                if log_key:
                    operation_logs[log_key].append("⏳ 命令执行超时，已终止")
                break
            
            # 读取一行输出
            line = process.stdout.readline()
            if not line and process.poll() is not None:
                break
            if line:
                clean_line = line.strip()
                output_lines.append(clean_line)
                if log_key:
                    operation_logs[log_key].append(clean_line)
            
        # 获取剩余输出
        stdout, _ = process.communicate()
        if stdout:
            for line in stdout.splitlines():
                if line.strip():
                    clean_line = line.strip()
                    output_lines.append(clean_line)
                    if log_key:
                        operation_logs[log_key].append(clean_line)
        
        return_code = process.poll()
        result = '\n'.join(output_lines)
        
        # 记录结果
        if log_key:
            if return_code == 0:
                operation_logs[log_key].append("✅ 命令执行成功")
            else:
                operation_logs[log_key].append(f"❌ 命令失败，退出码: {return_code}")
        
        return return_code == 0, result
    except Exception as e:
        error_msg = f"命令执行出错: {str(e)}"
        logger.error(error_msg)
        if log_key:
            operation_logs[log_key].append(error_msg)
        return False, error_msg

def get_host_ip():
    """获取Docker宿主机IP"""
    try:
        # 尝试连接外部服务获取本机IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 53))  # Google Public DNS
            host_ip = s.getsockname()[0]
            return host_ip
        except Exception:
            return "127.0.0.1"
        finally:
            s.close()
    except:
        return "127.0.0.1"

def get_docker_containers():
    """获取Docker容器的详细信息"""
    if not docker_available or not docker_client:
        return []
    
    try:
        containers = docker_client.containers.list(all=True)
        container_list = []
        
        for container in containers:
            # 获取端口映射
            ports = []
            port_links = []
            if container.attrs.get('NetworkSettings', {}).get('Ports'):
                for container_port, host_config in container.attrs['NetworkSettings']['Ports'].items():
                    if host_config:
                        for config in host_config:
                            host_ip = config['HostIp'] or '0.0.0.0'
                            host_port = config['HostPort']
                            ports.append(f"{host_ip}:{host_port} → {container_port}")
                            
                            # 创建访问链接
                            if host_port in ["80", "8080", "443"]:
                                protocol = "https" if host_port == "443" else "http"
                                if host_ip in ['0.0.0.0', '::']:
                                    host_ip = get_host_ip()
                                port_links.append({
                                    "port": host_port,
                                    "url": f"{protocol}://{host_ip}:{host_port}"
                                })
            
            # 获取容器状态
            status = container.status
            if status == 'running':
                status_class = 'success'
                status_icon = '▶️'
            else:
                status_class = 'danger'
                status_icon = '⏹️'
            
            container_list.append({
                'id': container.id[:12],
                'name': container.name,
                'image': container.image.tags[0] if container.image.tags else container.image.short_id,
                'status': status,
                'status_icon': status_icon,
                'status_class': status_class,
                'ports': ports,
                'port_links': port_links,
                'created': datetime.fromtimestamp(container.attrs['Created']).strftime('%Y-%m-%d %H:%M')
            })
        
        return container_list
    except Exception as e:
        logger.error(f"获取容器列表失败: {e}")
        return []

def is_valid_vulhub_target(target_path):
    """检查是否为有效的Vulhub靶场目录"""
    try:
        basename = os.path.basename(target_path)
        
        # 跳过隐藏目录
        if basename.startswith('.'):
            return False
        
        # 跳过已知的非靶场目录
        skip_dirs = ['docs', 'examples', 'scripts', 'utils', 'test', '.git']
        if basename in skip_dirs:
            return False
        
        # 检查是否存在特定的Vulhub文件
        vulhub_files = ['docker-compose.yml', 'docker-compose.yaml', 'README.md']
        for file_name in vulhub_files:
            if os.path.exists(os.path.join(target_path, file_name)):
                return True
                
        # 检查子目录中是否存在docker-compose文件
        for root, _, files in os.walk(target_path, topdown=True):
            # 跳过隐藏目录
            root_basename = os.path.basename(root)
            if root_basename.startswith('.') or root_basename in skip_dirs:
                continue
            
            if 'docker-compose.yml' in files or 'docker-compose.yaml' in files:
                return True
                
        return False
    except Exception as e:
        logger.error(f"检查靶场目录出错: {target_path}, {e}")
        return False

def get_vulhub_targets():
    """获取Vulhub靶场目录列表及其状态"""
    logger.info(f"扫描Vulhub目录: {VULHUB_PATH}")
    targets = []
    
    if not os.path.exists(VULHUB_PATH):
        logger.error(f"Vulhub目录不存在: {VULHUB_PATH}")
        return targets
        
    try:
        # 获取所有子目录中的有效靶场
        for category in os.listdir(VULHUB_PATH):
            category_path = os.path.join(VULHUB_PATH, category)
            
            # 只处理目录
            if not os.path.isdir(category_path):
                continue
                
            # 跳过隐藏目录
            if category.startswith('.'):
                continue
                
            # 扫描类别中的漏洞环境
            for target_name in os.listdir(category_path):
                target_path = os.path.join(category_path, target_name)
                
                # 只处理目录
                if not os.path.isdir(target_path):
                    continue
                
                # 检查是否有效靶场
                if not is_valid_vulhub_target(target_path):
                    continue
                
                # 提取显示名称
                display_name = target_name.replace('_', ' ').replace('-', ' ').title()
                
                # 查找compose文件
                compose_files = find_compose_files(target_path)
                if not compose_files:
                    logger.warning(f"靶场 {category}/{target_name} 无docker-compose文件")
                    continue
                
                # 使用第一个compose文件作为主文件
                compose_file = compose_files[0]
                compose_dir = os.path.dirname(compose_file)
                
                # 检测运行状态
                running = check_target_running(compose_dir)
                
                # 获取端口信息
                ports_info = extract_ports_from_compose(compose_file)
                
                targets.append({
                    'id': f"{category}:{target_name}".lower(),
                    'category': category,
                    'name': target_name,
                    'path': target_path,
                    'display_name': display_name,
                    'compose_file': compose_file,
                    'compose_dir': compose_dir,
                    'running': running,
                    'ports': ports_info,
                    'created': datetime.fromtimestamp(os.path.getctime(target_path)).strftime('%Y-%m-%d')
                })
        
        # 按运行状态排序
        targets.sort(key=lambda x: (x['running'], x['name']), reverse=True)
        logger.info(f"找到 {len(targets)} 个有效Vulhub靶场")
        return targets
    except Exception as e:
        logger.error(f"获取靶场列表出错: {e}")
        return []

def find_compose_files(target_path):
    """在目录及其子目录中寻找docker-compose文件"""
    compose_files = []
    
    # 首先检查根目录
    for file_name in ['docker-compose.yml', 'docker-compose.yaml']:
        file_path = os.path.join(target_path, file_name)
        if os.path.isfile(file_path):
            compose_files.append(file_path)
    
    # 检查一级子目录
    for dir_name in os.listdir(target_path):
        dir_path = os.path.join(target_path, dir_name)
        
        if os.path.isdir(dir_path):
            for file_name in ['docker-compose.yml', 'docker-compose.yaml']:
                file_path = os.path.join(dir_path, file_name)
                if os.path.isfile(file_path):
                    compose_files.append(file_path)
    
    return compose_files

def extract_ports_from_compose(compose_file):
    """从docker-compose文件中提取端口信息"""
    try:
        with open(compose_file, 'r', encoding='utf-8') as f:
            compose_data = yaml.safe_load(f)
        
        ports_info = []
        
        if compose_data and 'services' in compose_data:
            for service_name, service_config in compose_data['services'].items():
                if 'ports' in service_config:
                    port_mappings = service_config['ports']
                    
                    # 格式化端口信息
                    for mapping in port_mappings:
                        if isinstance(mapping, str):
                            ports_info.append({
                                'service': service_name,
                                'mapping': mapping
                            })
                        elif isinstance(mapping, dict):
                            # 处理新格式的port定义
                            published = mapping.get('published', '?')
                            target_port = mapping.get('target', published)
                            proto = mapping.get('protocol', 'tcp')
                            
                            ports_info.append({
                                'service': service_name,
                                'mapping': f"{published} -> {target_port}/{proto}",
                                'published': published
                            })
        return ports_info
    except Exception as e:
        logger.error(f"解析docker-compose文件错误: {compose_file}, {e}")
        return [{'error': '无法解析端口信息'}]

def get_compose_project_dir(compose_file):
    """获取docker-compose项目的目录"""
    return os.path.dirname(compose_file)

def check_target_running(compose_dir):
    """检查靶场是否正在运行"""
    try:
        # 使用docker-compose ps检查状态
        success, output = run_command(
            ['docker-compose', 'ps'],
            cwd=compose_dir,
            timeout=10
        )
        
        if not success:
            return False
            
        # 检查输出中是否有运行的容器
        return any("Up" in line or "running" in line.lower() for line in output.splitlines())
    except Exception as e:
        logger.error(f"检查运行状态出错: {compose_dir}, {e}")
        return False

def start_target_async(log_key, compose_file, category, target_name):
    """后台启动靶场任务"""
    def task():
        # 记录开始
        operation_logs[log_key] = []
        operation_logs[log_key].append(f"🚀 启动Vulhub靶场: {category}/{target_name}")
        
        # 获取项目目录
        project_dir = get_compose_project_dir(compose_file)
        operation_logs[log_key].append(f"📂 工作目录: {project_dir}")
        
        # 运行docker-compose up
        success, output = run_command(
            ['docker-compose', 'up', '-d'],
            cwd=project_dir,
            log_key=log_key,
            timeout=300
        )
        
        # 记录结果
        if success:
            operation_logs[log_key].append("✅ 靶场启动成功！")
            operation_logs[log_key].append("🔌 容器已启动并运行")
        else:
            operation_logs[log_key].append("❌ 靶场启动失败！")
            operation_logs[log_key].append("请查看错误日志获取更多信息")
    
    # 启动后台线程执行任务
    thread = threading.Thread(target=task, daemon=True)
    thread.start()

def stop_target_async(log_key, compose_file, category, target_name):
    """后台停止靶场任务"""
    def task():
        # 记录开始
        operation_logs[log_key] = []
        operation_logs[log_key].append(f"🛑 停止Vulhub靶场: {category}/{target_name}")
        
        # 获取项目目录
        project_dir = get_compose_project_dir(compose_file)
        operation_logs[log_key].append(f"📂 工作目录: {project_dir}")
        
        # 运行docker-compose down
        success, output = run_command(
            ['docker-compose', 'down'],
            cwd=project_dir,
            log_key=log_key,
            timeout=180
        )
        
        # 记录结果
        if success:
            operation_logs[log_key].append("✅ 靶场已成功停止！")
            operation_logs[log_key].append("🛑 所有相关容器已移除")
        else:
            operation_logs[log_key].append("❌ 靶场停止失败！")
            operation_logs[log_key].append("请查看错误日志获取更多信息")
    
    # 启动后台线程执行任务
    thread = threading.Thread(target=task, daemon=True)
    thread.start()

@app.route('/')
def index():
    """应用主页面"""
    # 获取靶场列表和容器列表
    targets = get_vulhub_targets()
    containers = get_docker_containers() if docker_available else []
    
    # 计算统计数据
    stats = {
        'total_targets': len(targets),
        'running_targets': sum(1 for t in targets if t['running']),
        'total_containers': len(containers),
        'running_containers': sum(1 for c in containers if c['status'] == 'running')
    }
    
    # 渲染主页
    return render_template_string(HTML_TEMPLATE, 
                                 targets=targets, 
                                 containers=containers, 
                                 stats=stats,
                                 host_ip=get_host_ip(),
                                 current_date=datetime.now().strftime('%Y-%m-%d'))
@app.route('/api/targets/<id>/start')
def start_target(id):
    """启动指定靶场"""
    try:
        # 解析ID格式: "category:target_name"
        category, target_name = id.split(':')
        
        # 检查靶场是否存在
        target_path = os.path.join(VULHUB_PATH, category, target_name)
        if not os.path.exists(target_path):
            return jsonify({
                'success': False, 
                'message': f'靶场不存在: {category}/{target_name}'
            })
        
        # 生成唯一的日志key
        log_key = f"start-{category}-{target_name}-{int(time.time())}"
        
        # 查找compose文件
        compose_files = find_compose_files(target_path)
        if not compose_files:
            return jsonify({
                'success': False, 
                'message': '未找到docker-compose文件'
            })
        
        # 启动异步任务
        start_target_async(log_key, compose_files[0], category, target_name)
        
        return jsonify({
            'success': True,
            'message': '靶场正在启动中...',
            'log_key': log_key
        })
    except Exception as e:
        logger.error(f"启动靶场错误: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'启动失败: {str(e)}'
        })

@app.route('/api/targets/<id>/stop')
def stop_target(id):
    """停止指定靶场"""
    try:
        # 解析ID格式: "category:target_name"
        category, target_name = id.split(':')
        
        # 检查靶场是否存在
        target_path = os.path.join(VULHUB_PATH, category, target_name)
        if not os.path.exists(target_path):
            return jsonify({
                'success': False, 
                'message': f'靶场不存在: {category}/{target_name}'
            })
        
        # 生成唯一的日志key
        log_key = f"stop-{category}-{target_name}-{int(time.time())}"
        
        # 查找compose文件
        compose_files = find_compose_files(target_path)
        if not compose_files:
            return jsonify({
                'success': False, 
                'message': '未找到docker-compose文件'
            })
        
        # 启动异步任务
        stop_target_async(log_key, compose_files[0], category, target_name)
        
        return jsonify({
            'success': True,
            'message': '靶场正在停止中...',
            'log_key': log_key
        })
    except Exception as e:
        logger.error(f"停止靶场错误: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'停止失败: {str(e)}'
        })

@app.route('/api/logs/<log_key>')
def get_logs(log_key):
    """获取操作日志"""
    logs = operation_logs.get(log_key, [])
    return jsonify({
        'success': True,
        'logs': logs
    })

@app.route('/api/status')
def get_status():
    """获取系统状态"""
    targets = get_vulhub_targets()
    containers = get_docker_containers() if docker_available else []
    
    # 计算统计数据
    stats = {
        'total_targets': len(targets),
        'running_targets': sum(1 for t in targets if t['running']),
        'total_containers': len(containers),
        'running_containers': sum(1 for c in containers if c['status'] == 'running')
    }
    
    return jsonify({
        'success': True,
        'stats': stats,
        'targets': [{
            'id': t['id'],
            'category': t['category'],
            'name': t['name'],
            'display_name': t['display_name'],
            'running': t['running'],
            'ports': t['ports'],
            'created': t['created']
        } for t in targets],
        'containers': containers
    })

if __name__ == '__main__':
    port = int(os.environ.get('VULHUB_PORT', 5000))
    host_ip = get_host_ip()
    logger.info(f"启动Vulhub管理系统，访问地址: http://{host_ip}:{port}")
    app.run(host='0.0.0.0', port=port, debug=True, threaded=True, use_reloader=False)

# 完整的HTML模板 (简化版)
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulhub管理面板</title>
    <script src="https://cdn.jsdelivr.net/npm/vue@2.6.14/dist/vue.js"></script>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        :root {
            --primary: #3498db;
            --success: #2ecc71;
            --danger: #e74c3c;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background-color: #f8f9fa;
            padding-top: 20px;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            padding: 2rem 1rem;
            margin-bottom: 2rem;
            border-radius: 0 0 10px 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        
        .stats-card {
            transition: transform 0.3s ease;
            border: none;
            border-radius: 10px;
            overflow: hidden;
            margin-bottom: 20px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        
        .stats-card:hover {
            transform: translateY(-5px);
        }
        
        .stats-value {
            font-size: 2rem;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .stats-label {
            opacity: 0.8;
        }
        
        .target-list {
            margin-top: 2rem;
        }
        
        .target-card {
            margin-bottom: 1.5rem;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            transition: all 0.3s;
            border: 1px solid #eee;
        }
        
        .target-card:hover {
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        
        .target-card.running {
            border-left: 4px solid var(--success);
        }
        
        .target-card.stopped {
            border-left: 4px solid #dc3545;
        }
        
        .target-card .card-header {
            font-weight: 600;
        }
        
        .target-card .target-name {
            font-weight: 600;
            margin-bottom: 0.3rem;
        }
        
        .target-card .target-id {
            font-size: 0.9rem;
            opacity: 0.7;
        }
        
        .port-badge {
            margin-right: 5px;
            margin-bottom: 5px;
            padding: 5px 10px;
            background-color: #e9ecef;
            border-radius: 20px;
            display: inline-block;
            font-size: 0.85rem;
        }
        
        .log-output {
            background: #1e1e1e;
            color: #dcdcdc;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            max-height: 400px;
            overflow-y: auto;
            white-space: pre-wrap;
        }
        
        .status-badge {
            padding: 4px 8px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 500;
        }
        
        .running-badge {
            background-color: #28a74520;
            color: #28a745;
        }
        
        .stopped-badge {
            background-color: #dc354520;
            color: #dc3545;
        }
        
        .modal-content {
            border-radius: 10px;
            border: none;
        }
        
        .action-buttons a, .action-buttons button {
            margin-right: 5px;
        }
        
        .footer {
            padding: 20px 0;
            text-align: center;
            color: #6c757d;
            font-size: 0.9rem;
        }
    </style>
</head>
<body>
    <div id="app">
        <!-- 页头 -->
        <div class="header text-center">
            <div class="container">
                <h1><i class="fas fa-shield-alt"></i> Vulhub 管理面板</h1>
                <p class="lead">一站式管理您的安全测试环境</p>
            </div>
        </div>
        
        <div class="container">
            <!-- 统计数据 -->
            <div class="row">
                <div class="col-md-3">
                    <div class="stats-card card bg-white text-center">
                        <div class="card-body">
                            <div class="stats-value text-primary">{{ stats.total_targets }}</div>
                            <div class="stats-label">靶场总数</div>
                            <i class="fas fa-bullseye fa-2x text-primary mt-2"></i>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stats-card card bg-white text-center">
                        <div class="card-body">
                            <div class="stats-value text-success">{{ stats.running_targets }}</div>
                            <div class="stats-label">运行中靶场</div>
                            <i class="fas fa-play-circle fa-2x text-success mt-2"></i>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stats-card card bg-white text-center">
                        <div class="card-body">
                            <div class="stats-value text-info">{{ stats.total_containers }}</div>
                            <div class="stats-label">容器总数</div>
                            <i class="fas fa-server fa-2x text-info mt-2"></i>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stats-card card bg-white text-center">
                        <div class="card-body">
                            <div class="stats-value text-warning">{{ stats.running_containers }}</div>
                            <div class="stats-label">运行中容器</div>
                            <i class="fas fa-bolt fa-2x text-warning mt-2"></i>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- 操作和状态按钮 -->
            <div class="d-flex justify-content-between align-items-center mb-3">
                <h3>靶场列表</h3>
                <div>
                    <button class="btn btn-primary" @click="loadData">
                        <i class="fas fa-sync-alt"></i> 刷新状态
                    </button>
                </div>
            </div>
            
            <!-- 靶场列表 -->
            <div class="target-list">
                <div v-if="loading" class="text-center py-4">
                    <div class="spinner-border text-primary" role="status">
                        <span class="visually-hidden">加载中...</span>
                    </div>
                    <p class="mt-2">加载靶场列表...</p>
                </div>
                
                <div v-else-if="targets.length === 0" class="card">
                    <div class="card-body text-center py-5">
                        <i class="fas fa-inbox fa-3x text-muted mb-3"></i>
                        <h4>暂无靶场</h4>
                        <p>未在 {{ vulhubPath }} 目录中找到有效靶场</p>
                    </div>
                </div>
                
                <div v-else>
                    <div class="row">
                        <div class="col-md-6" v-for="target in targets" :key="target.id">
                            <div class="card target-card" :class="target.running ? 'running' : 'stopped'">
                                <div class="card-body">
                                    <h5 class="target-name">
                                        {{ target.display_name }}
                                        <span class="status-badge" :class="target.running ? 'running-badge' : 'stopped-badge'">
                                            {{ target.running ? '运行中' : '已停止' }}
                                        </span>
                                    </h5>
                                    <div class="target-id text-muted mb-3">
                                        {{ target.category }}/{{ target.name }}
                                    </div>
                                    
                                    <div class="mb-3">
                                        <span class="text-muted">创建时间:</span>
                                        {{ target.created }}
                                    </div>
                                    
                                    <div v-if="target.ports && target.ports.length" class="mb-3">
                                        <span class="text-muted">端口映射:</span>
                                        <div>
                                            <span v-for="(port, idx) in target.ports" :key="idx" class="port-badge">
                                                <i class="fas fa-network-wired"></i>
                                                {{ port.mapping || port }}
                                            </span>
                                        </div>
                                    </div>
                                    
                                    <div class="action-buttons">
                                        <button 
                                            v-if="!target.running"
                                            class="btn btn-success btn-sm"
                                            @click="startTarget(target.id)">
                                            <i class="fas fa-play"></i> 启动
                                        </button>
                                        <button 
                                            v-else
                                            class="btn btn-danger btn-sm"
                                            @click="stopTarget(target.id)">
                                            <i class="fas fa-stop"></i> 停止
                                        </button>
                                        <a 
                                            v-if="target.running && target.ports && target.ports.length" 
                                            :href="`http://${hostIp}:${target.ports[0].published || 8080}`" 
                                            target="_blank"
                                            class="btn btn-primary btn-sm">
                                            <i class="fas fa-external-link-alt"></i> 访问
                                        </a>
                                        <button 
                                            class="btn btn-outline-secondary btn-sm"
                                            @click="showLogs(target.id, target.category, target.name)">
                                            <i class="fas fa-terminal"></i> 日志
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- 容器状态 -->
            <div class="mt-5">
                <div class="d-flex justify-content-between align-items-center mb-3">
                    <h3>容器状态</h3>
                </div>
                
                <div class="card">
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-hover align-middle">
                                <thead>
                                    <tr>
                                        <th width="50">状态</th>
                                        <th>容器名称</th>
                                        <th>镜像</th>
                                        <th>端口映射</th>
                                        <th>操作</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <tr v-for="container in containers" :key="container.id">
                                        <td>
                                            <span :class="`text-${container.status_class}`" v-html="container.status_icon"></span>
                                        </td>
                                        <td>
                                            <strong>{{ container.name }}</strong>
                                            <div class="text-muted small">{{ container.id }}</div>
                                        </td>
                                        <td>{{ container.image || '-' }}</td>
                                        <td>
                                            <div v-for="(port, idx) in container.ports" :key="idx" class="port-badge">
                                                <i class="fas fa-plug"></i> {{ port }}
                                            </div>
                                        </td>
                                        <td>
                                            <div class="btn-group">
                                                <button 
                                                    v-if="container.status === 'running'"
                                                    class="btn btn-outline-danger btn-sm"
                                                    @click="stopContainer(container.id)">
                                                    <i class="fas fa-stop"></i> 停止
                                                </button>
                                                <button 
                                                    class="btn btn-outline-secondary btn-sm"
                                                    @click="showContainerLogs(container.id)">
                                                    <i class="fas fa-file-alt"></i> 日志
                                                </button>
                                                <a 
                                                    v-if="container.port_links.length" 
                                                    :href="container.port_links[0].url" 
                                                    target="_blank"
                                                    class="btn btn-outline-primary btn-sm">
                                                    <i class="fas fa-globe"></i> Web
                                                </a>
                                            </div>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- 底部信息 -->
        <div class="footer mt-5">
            <div class="container">
                <p>Vulhub管理面板 v2.0 | 服务器IP: {{ hostIp }} | {{ currentDate }}</p>
            </div>
        </div>
        
        <!-- 日志弹窗 -->
        <div class="modal fade" id="logModal" tabindex="-1">
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">操作日志 - {{ logContext }}</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <div v-if="logLoading" class="text-center py-4">
                            <div class="spinner-border text-primary" role="status">
                                <span class="visually-hidden">加载中...</span>
                            </div>
                        </div>
                        <div v-else class="log-output">
                            <p v-for="(logLine, idx) in logs" :key="idx">{{ logLine }}</p>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">关闭</button>
                        <button v-if="operationsRunning" type="button" class="btn btn-success" @click="loadLogs">
                            <i class="fas fa-sync"></i> 刷新日志
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- 引入Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    
    <script>
        // 初始化Vue应用
        const app = new Vue({
            el: '#app',
            data: {
                loading: true,
                targets: [],
                containers: [],
                stats: {
                    total_targets: 0,
                    running_targets: 0,
                    total_containers: 0,
                    running_containers: 0
                },
                hostIp: '',
                currentDate: '',
                vulhubPath: '${VULHUB_PATH}',
                logs: [],
                logLoading: false,
                logContext: '',
                operationsRunning: false,
                currentLogKey: null,
                logTimer: null
            },
            mounted() {
                this.loadData();
                this.hostIp = this.$el.dataset.hostIp;
                this.currentDate = new Date().toLocaleDateString('zh-CN');
                
                // 自动刷新数据
                setInterval(() => {
                    this.loadData();
                }, 30000); // 每30秒刷新一次
            },
            methods: {
                loadData() {
                    this.loading = true;
                    fetch('/api/status')
                        .then(res => res.json())
                        .then(data => {
                            if (data.success) {
                                this.targets = data.targets || [];
                                this.containers = data.containers || [];
                                this.stats = data.stats;
                                this.hostIp = data.host_ip || this.hostIp;
                            }
                            this.loading = false;
                        })
                        .catch(err => {
                            console.error('加载数据失败:', err);
                            this.loading = false;
                        });
                },
                startTarget(targetId) {
                    this.operationsRunning = true;
                    const startBtn = event.currentTarget;
                    startBtn.innerHTML = '<i class="fas fa-sync fa-spin"></i> 启动中...';
                    startBtn.disabled = true;
                    
                    fetch(`/api/targets/${targetId}/start`)
                        .then(res => res.json())
                        .then(data => {
                            if (data.success) {
                                this.currentLogKey = data.log_key;
                                this.logContext = `启动: ${targetId.split(':')[0]}/${targetId.split(':')[1]}`;
                                this.showLogModal();
                                this.monitorOperationProgress();
                            } else {
                                alert(`启动失败: ${data.message}`);
                                startBtn.innerHTML = '<i class="fas fa-play"></i> 启动';
                                startBtn.disabled = false;
                            }
                        });
                },
                stopTarget(targetId) {
                    this.operationsRunning = true;
                    const stopBtn = event.currentTarget;
                    stopBtn.innerHTML = '<i class="fas fa-sync fa-spin"></i> 停止中...';
                    stopBtn.disabled = true;
                    
                    fetch(`/api/targets/${targetId}/stop`)
                        .then(res => res.json())
                        .then(data => {
                            if (data.success) {
                                this.currentLogKey = data.log_key;
                                this.logContext = `停止: ${targetId.split(':')[0]}/${targetId.split(':')[1]}`;
                                this.showLogModal();
                                this.monitorOperationProgress();
                            } else {
                                alert(`停止失败: ${data.message}`);
                                stopBtn.innerHTML = '<i class="fas fa-stop"></i> 停止';
                                stopBtn.disabled = false;
                            }
                        });
                },
                stopContainer(containerId) {
                    if (!confirm(`确定要停止容器 ${containerId} 吗？`)) return;
                    
                    fetch(`/api/containers/${containerId}/stop`, {
                        method: 'POST'
                    })
                    .then(res => res.json())
                    .then(data => {
                        if (data.success) {
                            alert(`容器 ${containerId} 已停止`);
                            this.loadData();
                        } else {
                            alert(`停止容器失败: ${data.message}`);
                        }
                    });
                },
                showLogs(targetId, category, name) {
                    this.logContext = `查看日志: ${category}/${name}`;
                    this.currentLogKey = `view-${targetId}-logs`;
                    this.logs = [`正在加载 ${category}/${name} 的日志...`];
                    this.showLogModal();
                    
                    // 在实际应用中，这里应调用获取日志的API
                    setTimeout(() => {
                        this.logs = [
                            `[INFO] 加载 ${category}/${name} 相关日志`,
                            '==========================',
                            '2023-05-10 14:30:22 | 容器已启动',
                            '2023-05-10 14:31:05 | 服务初始化完成',
                            '2023-05-10 14:35:18 | 接受第一个连接请求',
                            '2023-05-10 15:00:45 | 安全审计事件: SQL注入攻击尝试'
                        ];
                    }, 1500);
                },
                showContainerLogs(containerId) {
                    this.logContext = `容器日志: ${containerId}`;
                    this.currentLogKey = `container-log-${containerId}`;
                    this.logs = [`正在加载容器 ${containerId} 的日志...`];
                    this.showLogModal();
                    
                    // 在实际应用中，这里应调用获取容器日志的API
                    setTimeout(() => {
                        this.logs = [
                            `[INFO] 容器 ${containerId} 日志`,
                            '==========================',
                            '[+] 初始化容器配置',
                            '[*] 启动 web 服务...',
                            '[+] 侦听端口: 0.0.0.0:80',
                            '[*] 数据库连接成功',
                            '[*] 服务已准备就绪',
                            '[*] 等待连接...'
                        ];
                    }, 1500);
                },
                showLogModal() {
                    // 初始化日志数据
                    this.logLoading = true;
                    this.logs = ['加载日志中...'];
                    
                    // 显示模态框
                    const modalEl = document.getElementById('logModal');
                    const modal = new bootstrap.Modal(modalEl);
                    modal.show();
                    
                    // 加载日志
                    this.loadLogs();
                },
                loadLogs() {
                    if (!this.currentLogKey) return;
                    
                    this.logLoading = true;
                    fetch(`/api/logs/${this.currentLogKey}`)
                        .then(res => res.json())
                        .then(data => {
                            this.logs = data.logs;
                            this.logLoading = false;
                            
                            // 滚动到底部
                            if (modalBody) {
                                modalBody.scrollTop = modalBody.scrollHeight;
                            }
                        });
                },
                monitorOperationProgress() {
                    // 每1.5秒检查一次日志
                    if (this.logTimer) clearInterval(this.logTimer);
                    
                    this.logTimer = setInterval(() => {
                        this.loadLogs();
                        
                        // 检查操作是否完成
                        if (this.logs.length > 0 && 
                           (this.logs[this.logs.length - 1].includes('✅') || 
                            this.logs[this.logs.length - 1].includes('❌'))) {
                            clearInterval(this.logTimer);
                            this.operationsRunning = false;
                            
                            // 刷新数据
                            this.loadData();
                        }
                    }, 1500);
                }
            }
        });
    </script>
</body>
</html>
'''
