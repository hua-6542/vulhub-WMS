#!/usr/bin/env python3
import os
import yaml
import subprocess
import docker
import platform
import sys
import socket
import json
import logging
import re
import shutil
import argparse
import datetime
import pwd
import grp
import time
import tempfile
from collections import defaultdict
import psutil  # 用于更可靠的端口检测

VULHUB_PATH = '/opt/vulhub'
LOG_FILE = "/var/log/vulhub_debug.log"
DEBUG_REPORT_DIR = "/var/log/vulhub_debug_reports"

# 设置日志
def setup_logger(log_level="INFO"):
    """设置日志记录器，支持动态日志级别"""
    # 确保目录存在
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    os.makedirs(DEBUG_REPORT_DIR, exist_ok=True)
    
    log_levels = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL
    }
    
    logger = logging.getLogger("vulhub_debug")
    logger.setLevel(log_levels.get(log_level.upper(), logging.INFO))
    
    # 防止重复添加处理器
    if not logger.handlers:
        # 控制台处理器
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter('%(levelname)s: %(message)s')
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)

        # 文件处理器
        file_formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(module)s.%(funcName)s: %(message)s')
        file_handler = logging.FileHandler(LOG_FILE)
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    
    return logger

# 全局logger实例
logger = setup_logger()

def get_color_code(level, use_color=True):
    """获取文本颜色代码"""
    if not use_color:
        return ""
    return {
        "ERROR": "\033[91m",    # 红色
        "WARNING": "\033[93m",  # 黄色
        "INFO": "\033[94m",     # 蓝色
        "SUCCESS": "\033[92m",  # 绿色
        "RESET": "\033[0m"
    }[level]

def colored_text(text, level="INFO", use_color=True):
    """创建带颜色的文本"""
    return f"{get_color_code(level, use_color)}{text}{get_color_code('RESET', use_color) if use_color else ''}"

def is_git_repo(path):
    """检查目录是否是Git仓库"""
    git_dir = os.path.join(path, '.git')
    return os.path.exists(git_dir) and os.path.isdir(git_dir)

def get_directory_info(path):
    """获取目录详细信息，包括所有权信息"""
    info = {
        'path': path,
        'exists': os.path.exists(path),
        'is_dir': False,
        'size': 0,
        'permissions': "",
        'owner': None,
        'group': None,
        'last_modified': None,
        'file_count': 0,
        'subdir_count': 0,
        'git_repo': False
    }
    
    if not info['exists']:
        return info
    
    try:
        stat_info = os.stat(path)
        info['last_modified'] = datetime.datetime.fromtimestamp(stat_info.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
        info['permissions'] = oct(stat_info.st_mode)[-3:]
        
        try:
            info['owner'] = pwd.getpwuid(stat_info.st_uid).pw_name
            info['group'] = grp.getgrgid(stat_info.st_gid).gr_name
        except KeyError:
            info['owner'] = stat_info.st_uid
            info['group'] = stat_info.st_gid
        
        if os.path.isdir(path):
            info['is_dir'] = True
            info['git_repo'] = is_git_repo(path)
            
            # 统计文件和目录数量
            file_count = 0
            dir_count = 0
            total_size = 0
            
            for entry in os.scandir(path):
                if entry.is_file():
                    file_count += 1
                    total_size += entry.stat().st_size
                elif entry.is_dir():
                    dir_count += 1
            
            info['file_count'] = file_count
            info['subdir_count'] = dir_count
            info['size'] = total_size // 1024  # KB
        else:
            info['size'] = os.path.getsize(path) // 1024  # KB
    
    except Exception as e:
        logger.error(f"获取目录信息错误: {str(e)}")
        info['error'] = str(e)
    
    return info

def parse_port_mapping(mapping):
    """解析端口映射定义，支持多种格式"""
    result = {}
    
    if isinstance(mapping, str):
        # 格式: "8080:80" 或 "0.0.0.0:8080:80/tcp"
        parts = mapping.split(':')
        protocol = 'tcp'
        
        if '/' in parts[-1]:
            port_part, protocol = parts[-1].split('/')
        else:
            port_part = parts[-1]
        
        try:
            result['container_port'] = int(port_part)
            
            if len(parts) == 2:
                result['host_port'] = int(parts[0])
                result['host_ip'] = '0.0.0.0'
            elif len(parts) == 3:
                result['host_ip'] = parts[0]
                result['host_port'] = int(parts[1])
            else:
                return None
                
            result['protocol'] = protocol
            return result
        except ValueError:
            pass
    
    elif isinstance(mapping, dict):
        # 格式: {"published": 8080, "target": 80, "protocol": "tcp"}
        try:
            return {
                'host_ip': '0.0.0.0',
                'host_port': mapping['published'],
                'container_port': mapping['target'],
                'protocol': mapping.get('protocol', 'tcp')
            }
        except KeyError:
            pass
    
    return None

def validate_compose_file(compose_file):
    """验证并分析docker-compose.yml文件"""
    results = {
        'path': compose_file,
        'exists': os.path.exists(compose_file),
        'valid': True,
        'errors': [],
        'warnings': [],
        'services': {},
        'ports': [],
        'volumes': [],
        'networks': [],
        'version': None
    }
    
    if not results['exists']:
        results['errors'].append("文件路径不存在")
        results['valid'] = False
        return results
    
    try:
        if os.path.getsize(compose_file) == 0:
            results['errors'].append("文件为空")
            results['valid'] = False
            return results
            
        with open(compose_file, 'r', encoding='utf-8') as f:
            content = f.read()
            
            # BOM字符检查
            if content.startswith('\ufeff'):
                results['warnings'].append("文件包含BOM字符(UTF-8签名)，可能导致解析问题")
                content = content.lstrip('\ufeff')  # 移除BOM字符
            
            # 尝试解析
            try:
                compose_data = yaml.safe_load(content)
                
                if not compose_data:
                    results['errors'].append("文件内容为空")
                    results['valid'] = False
                    return results
                
                # 获取版本
                results['version'] = compose_data.get('version', '1.0')
                
                # 解析服务
                services = compose_data.get('services', {})
                
                for service_name, service_config in services.items():
                    if not isinstance(service_config, dict):
                        results['warnings'].append(f"服务 '{service_name}' 配置无效")
                        continue
                    
                    service_info = {
                        'name': service_name,
                        'image': service_config.get('image', '未指定'),
                        'build': service_config.get('build', None),
                        'ports': [],
                        'volumes': [],
                        'networks': None,
                        'depends_on': [],
                        'env_file': service_config.get('env_file', []),
                        'environment': service_config.get('environment', []),
                        'healthcheck': service_config.get('healthcheck', None),
                        'working_dir': service_config.get('working_dir', None),
                        'user': service_config.get('user', None),
                        'cap_add': service_config.get('cap_add', [])
                    }
                    
                    # 解析端口
                    port_configs = service_config.get('ports', [])
                    if isinstance(port_configs, str):
                        port_configs = [port_configs]
                    
                    for port_config in port_configs:
                        port_info = parse_port_mapping(port_config)
                        if port_info:
                            service_info['ports'].append(port_info)
                            results['ports'].append({
                                'service': service_name,
                                **port_info
                            })
                    
                    # 解析卷
                    volume_configs = service_config.get('volumes', [])
                    if isinstance(volume_configs, str):
                        volume_configs = [volume_configs]
                    
                    for volume_config in volume_configs:
                        if isinstance(volume_config, str):
                            parts = volume_config.strip().replace('\\', '/').split(':', 2)
                            
                            if len(parts) == 1:
                                # 匿名卷
                                service_info['volumes'].append({
                                    'container_path': parts[0],
                                    'host_path': None,
                                    'mode': 'rw'
                                })
                            elif len(parts) >= 2:
                                # 绑定挂载
                                container_path = parts[1]
                                host_path = parts[0]
                                mode = parts[2] if len(parts) > 2 else 'rw'
                                
                                # 处理相对路径
                                if host_path and not os.path.isabs(host_path):
                                    host_path = os.path.normpath(os.path.join(
                                        os.path.dirname(compose_file), 
                                        host_path
                                    ))
                                
                                service_info['volumes'].append({
                                    'container_path': container_path,
                                    'host_path': host_path,
                                    'mode': mode
                                })
                                
                                results['volumes'].append({
                                    'service': service_name,
                                    'host_path': host_path
                                })
                    
                    # 解析网络
                    networks = service_config.get('networks', {})
                    
                    if isinstance(networks, dict):
                        service_info['networks'] = list(networks.keys())
                    elif isinstance(networks, list):
                        service_info['networks'] = networks
                    
                    # 解析依赖
                    depends_on = service_config.get('depends_on', [])
                    
                    if isinstance(depends_on, dict):
                        # v3格式
                        service_info['depends_on'] = [k for k, v in depends_on.items() if v['condition'] == 'service_started']
                    elif isinstance(depends_on, list):
                        service_info['depends_on'] = depends_on
                    
                    results['services'][service_name] = service_info
                
                # 解析网络定义
                for net_name, net_config in compose_data.get('networks', {}).items():
                    if isinstance(net_config, dict):
                        results['networks'].append({
                            'name': net_name,
                            'driver': net_config.get('driver', 'bridge'),
                            'external': net_config.get('external', False)
                        })
                
            except yaml.YAMLError as e:
                results['valid'] = False
                if hasattr(e, 'problem_mark'):
                    mark = e.problem_mark
                    error_msg = f"YAML解析错误 (行:{mark.line+1}, 列:{mark.column+1}): {str(e)}"
                else:
                    error_msg = f"YAML解析错误: {str(e)}"
                results['errors'].append(error_msg)
                logger.error(f"YAML解析错误: {compose_file} - {error_msg}")
            
            except Exception as e:
                results['valid'] = False
                results['errors'].append(f"解析过程中出错: {str(e)}")
                logger.exception(f"解析过程中出错: {str(e)}")
    
    except Exception as e:
        results['valid'] = False
        results['errors'].append(f"读取文件时出错: {str(e)}")
        logger.exception(f"读取文件时出错: {str(e)}")
    
    return results

def get_system_info():
    """获取详细的系统信息"""
    import psutil
    
    info = {
        'os': {
            'system': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
            'machine': platform.machine(),
            'processor': platform.processor()
        },
        'python': {
            'version': platform.python_version(),
            'implementation': platform.python_implementation(),
            'executable': sys.executable
        },
        'hostname': socket.gethostname(),
        'user': os.getlogin(),
        'uid': os.getuid(),
        'gid': os.getgid(),
        'ip_address': socket.gethostbyname(socket.gethostname()),
        'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'cpu': {
            'count': os.cpu_count(),
            'usage': psutil.cpu_percent(),
            'load_avg': [round(x, 2) for x in os.getloadavg()] if hasattr(os, 'getloadavg') else []
        },
        'memory': {
            'total': psutil.virtual_memory().total // (1024 * 1024),  # MB
            'available': psutil.virtual_memory().available // (1024 * 1024),  # MB
            'used': psutil.virtual_memory().used // (1024 * 1024)     # MB
        },
        'filesystem': {
            'free': psutil.disk_usage('/').free // (1024 * 1024),    # MB
            'used': psutil.disk_usage('/').used // (1024 * 1024)     # MB
        }
    }
    
    try:
        info['docker_info'] = docker.from_env().info()
    except Exception as e:
        info['docker_error'] = str(e)
    
    return info

def check_daemon_status():
    """检查Docker服务状态，并获取更多信息"""
    result = {'status': 'unknown', 'version': None}
    
    try:
        # 检查系统服务状态
        systemctl_exists = shutil.which('systemctl')
        if systemctl_exists:
            status_cmd = ['systemctl', 'is-active', 'docker']
            status_output = subprocess.run(
                status_cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True
            )
            
            if status_output.returncode == 0:
                result['status'] = status_output.stdout.strip()
            else:
                result['status'] = 'inactive'
        
        # 尝试连接Docker引擎
        client = docker.from_env(timeout=3)
        info = client.info()
        result.update({
            'version': info.get('ServerVersion'),
            'operating_system': info.get('OperatingSystem'),
            'driver': info.get('Driver'),
            'containers_total': info.get('Containers', 0),
            'containers_running': info.get('ContainersRunning', 0),
            'containers_paused': info.get('ContainersPaused', 0),
            'containers_stopped': info.get('ContainersStopped', 0),
            'images': info.get('Images', 0),
            'status': 'running' if result.get('status') == 'active' else 'inaccessible',
            'errors': None
        })
    
    except docker.errors.DockerException as e:
        result.update({
            'status': "error",
            'errors': f"Docker连接失败: {str(e)}"
        })
        logger.error(f"Docker连接失败: {str(e)}")
    except Exception as e:
        result.update({
            'status': "error",
            'errors': f"无法确定Docker状态: {str(e)}"
        })
        logger.exception(f"无法确定Docker状态: {str(e)}")
    
    return result

def is_port_in_use(port, protocol='tcp'):
    """检查指定端口和协议是否被占用"""
    try:
        port = int(port)
        if protocol == 'tcp':
            return next((conn for conn in psutil.net_connections('inet') 
                         if conn.laddr.port == port and conn.status == 'LISTEN'), None) is not None
        elif protocol == 'udp':
            udp_ports = [conn.laddr.port for conn in psutil.net_connections('inet6') 
                         if conn.status == 'NONE' and conn.type == psutil.SOCK_DGRAM]
            return port in udp_ports
        else:
            return False
    except Exception as e:
        logger.warning(f"检查端口 {port}/{protocol} 时出错: {str(e)}")
        return False

def check_port_conflicts(ports):
    """检查端口冲突，返回冲突列表"""
    conflicts = []
    
    for port_info in ports:
        port = port_info.get('host_port')
        ip = port_info.get('host_ip', '0.0.0.0')
        protocol = port_info.get('protocol', 'tcp')
        
        if port is None:
            continue
        
        if is_port_in_use(port, protocol):
            conflict_info = f"{port}/{protocol}"
            
            if ip != '0.0.0.0':
                conflict_info += f" on {ip}"
            
            conflicts.append({
                'port': port,
                'ip': ip,
                'protocol': protocol,
                'service': port_info['service']
            })
    
    return conflicts

def check_path_permissions(paths):
    """检查路径权限问题，返回问题列表"""
    issues = []
    
    for path_info in paths:
        path = path_info.get('host_path')
        service = path_info.get('service')
        
        if not path:
            continue
        
        if not os.path.exists(path):
            issues.append({
                'path': path,
                'service': service,
                'issue': '路径不存在',
                'severity': 'error'
            })
            continue
        if not os.path.isabs(path):
            issues.append({
                'path': path,
                'service': service,
                'issue': '必须使用绝对路径',
                'severity': 'error'
            })
            continue
        if not os.path.isdir(path):
            issues.append({
                'path': path,
                'service': service,
                'issue': '不是目录',
                'severity': 'warning'
            })
        if not os.access(path, os.R_OK):
            issues.append({
                'path': path,
                'service': service,
                'issue': '缺少读取权限',
                'severity': 'error'
            })
        if not os.access(path, os.W_OK):
            issues.append({
                'path': path,
                'service': service,
                'issue': '缺少写入权限',
                'severity': 'warning'
            })
        if not os.access(path, os.X_OK):
            issues.append({
                'path': path,
                'service': service,
                'issue': '缺少执行权限',
                'severity': 'warning'
            })
    
    return issues

def execute_test_command(cmd, cwd, timeout=300):
    """执行命令行并捕获输出"""
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=timeout
        )
        return {
            'command': ' '.join(cmd),
            'returncode': result.returncode,
            'output': result.stdout,
            'success': result.returncode == 0
        }
    except subprocess.TimeoutExpired as e:
        return {
            'command': ' '.join(cmd),
            'returncode': -1,
            'output': f"命令执行超时 ({timeout}秒)",
            'success': False
        }
    except Exception as e:
        return {
            'command': ' '.join(cmd),
            'returncode': -1,
            'output': f"执行错误: {str(e)}",
            'success': False
        }

def run_safe_tests(target_path):
    """在不影响生产环境的情况下运行安全测试"""
    results = {
        'directory_scan': [],
        'command_checks': [],
        'service_checks': []
    }
    
    # 1. 扫描重要文件
    for root, dirs, files in os.walk(target_path):
        for file in files:
            if file in ['.env', 'start.sh', 'build.sh']:
                file_path = os.path.join(root, file)
                results['directory_scan'].append({
                    'path': file_path,
                    'size': os.path.getsize(file_path) if os.path.exists(file_path) else -1,
                    'executable': os.access(file_path, os.X_OK) if os.path.exists(file_path) else False
                })
    
    # 2. 执行无害命令检查
    commands = [
        ['docker', '--version'],
        ['docker-compose', '--version'],
        ['docker', 'network', 'ls'],
        ['docker', 'volume', 'ls']
    ]
    
    for cmd in commands:
        results['command_checks'].append(execute_test_command(cmd, target_path, 30))
    
    return results

def generate_report(target_data, full_report=False, use_color=True):
    """生成诊断报告，支持详细/简洁两种模式"""
    # 提取基本信息
    target_info = target_data['target_info']
    docker_status = target_data['docker_status']
    
    report_lines = []
    
    # 标题部分
    report_lines.append(colored_text("=" * 80, "INFO", use_color))
    report_lines.append(colored_text(f"Vulhub 靶场诊断报告: {target_data['target']}", "INFO", use_color))
    report_lines.append(colored_text(f"时间: {target_data['system_info']['timestamp']}", "INFO", use_color))
    report_lines.append(colored_text("=" * 80, "INFO", use_color) + "\n")
    
    # 系统信息 (简洁模式)
    report_lines.append(colored_text("[系统信息]", "SUCCESS", use_color))
    report_lines.append(f"  操作系统: {target_data['system_info']['os']['system']} {target_data['system_info']['os']['release']}")
    report_lines.append(f"  主机名: {target_data['system_info']['hostname']}")
    report_lines.append(f"  IP地址: {target_data['system_info']['ip_address']}")
    report_lines.append(f"  用户: {target_data['system_info']['user']}")
    
    # Docker状态 (重要，显眼显示)
    if docker_status.get('status') == 'running':
        docker_text = f"Docker: {docker_status.get('version', '未知版本')} (运行中)"
        report_lines.append(colored_text("  ✓ " + docker_text, "SUCCESS", use_color))
    else:
        docker_text = f"Docker: 状态异常 ({docker_status.get('status', '未知')})"
        report_lines.append(colored_text("  ✗ " + docker_text, "ERROR", use_color))
        
        if docker_status.get('errors'):
            report_lines.append(f"     错误详情: {docker_status['errors']}")
    
    # 靶场目录信息
    report_lines.append("\n" + colored_text("[靶场目录]", "SUCCESS", use_color))
    if target_info.get('exists'):
        exists_text = "存在"
        report_lines.append(f"  路径: {target_info.get('path')}")
        report_lines.append(f"  状态: {exists_text}")
        
        if target_info.get('git_repo'):
            repo_text = "是 (Git仓库)"
            report_lines.append(colored_text(f"  ✓ {repo_text}", "SUCCESS", use_color))
        else:
            report_lines.append("  类型: 非Git仓库")
        
        report_lines.append(f"  大小: {target_info.get('size', 0)} KB")
        report_lines.append(f"  文件数: {target_info.get('file_count')}, 子目录数: {target_info.get('subdir_count')}")
        report_lines.append(f"  权限: {target_info.get('permissions')}, 所有者: {target_info.get('owner')}:{target_info.get('group')}")
        report_lines.append(f"  修改时间: {target_info.get('last_modified')}")
    else:
        report_lines.append(colored_text(f"  ✗ 路径不存在: {target_info.get('path')}", "ERROR", use_color))
    
    # 配置文件校验部分
    report_lines.append("\n" + colored_text("[配置文件校验]", "SUCCESS", use_color))
    
    if not target_data.get('compose_files'):
        report_lines.append(colored_text("  ! 未找到任何docker-compose文件", "WARNING", use_color))
    else:
        for compose_file in target_data['compose_files']:
            path = compose_file.get('path', '未知路径')
            version = compose_file.get('version', '未知版本')
            services = compose_file.get('services', {})
            
            report_lines.append(f"  文件: {path} (版本: {version})")
            
            if not compose_file.get('valid', True):
                report_lines.append(colored_text(f"  ✗ 配置文件无效！", "ERROR", use_color))
                
                for error in compose_file.get('errors', []):
                    report_lines.append(f"    - {error}")
            else:
                report_lines.append(colored_text("  ✓ 配置文件语法校验通过", "SUCCESS", use_color))
            
            if compose_file.get('warnings'):
                for warning in compose_file.get('warnings'):
                    report_lines.append(colored_text(f"    ! 警告: {warning}", "WARNING", use_color))
            
            # 显示服务摘要
            if services:
                report_lines.append(f"  服务数量: {len(services)}")
                
                if full_report:
                    for service_name, service in services.items():
                        report_lines.append(f"    - {service_name}: {service.get('image', '无镜像')}")
                        if service.get('ports'):
                            ports = ', '.join(
                                f"{p.get('host_ip', '*')}:{p.get('host_port')}->{p.get('container_port')}/{p.get('protocol')}"
                                for p in service.get('ports')
                            )
                            report_lines.append(f"      端口: {ports}")
                        if service.get('volumes'):
                            volumes = ', '.join(
                                f"{v.get('host_path', '<匿名>')}:{v.get('container_path')}"
                                for v in service.get('volumes')
                            )
                            report_lines.append(f"      卷: {volumes}")
    
    # 端口冲突检查
    report_lines.append("\n" + colored_text("[端口冲突检查]", "SUCCESS", use_color))
    
    if not target_data.get('port_conflicts'):
        report_lines.append(colored_text("  ✓ 未检测到端口冲突", "SUCCESS", use_color))
    else:
        report_lines.append(colored_text(f"  ✗ 检测到 {len(target_data['port_conflicts'])} 处端口冲突:", "ERROR", use_color))
        
        for conflict in target_data['port_conflicts']:
            report_lines.append(f"    - 端口: {conflict.get('port')}/{conflict.get('protocol')}")
            report_lines.append(f"      冲突服务: {conflict.get('service')}")
            report_lines.append(f"      主机IP: {conflict.get('ip')}")
    
    # 路径权限检查
    report_lines.append("\n" + colored_text("[路径权限检查]", "SUCCESS", use_color))
    
    if not target_data.get('path_issues'):
        report_lines.append(colored_text("  ✓ 文件路径权限正常", "SUCCESS", use_color))
    else:
        report_lines.append(colored_text(f"  ! 检测到 {len(target_data['path_issues'])} 个路径权限问题:", "WARNING", use_color))
        
        for issue in target_data['path_issues']:
            severity = issue.get('severity', 'warning')
            report_lines.append(
                colored_text(f"    - {issue.get('path')}: {issue.get('issue')} (服务: {issue.get('service')})", 
                           severity.upper(), use_color)
            )
    
    # 测试结果
    if target_data.get('test_results') and (full_report or target_data['test_results'].get('issues')):
        report_lines.append("\n" + colored_text("[诊断测试结果]", "SUCCESS", use_color))
        
        issues = target_data['test_results'].get('issues', [])
        scans = target_data['test_results'].get('directory_scan', [])
        commands = target_data['test_results'].get('command_checks', [])
        
        if issues:
            report_lines.append(colored_text("  ✗ 测试发现问题:", "ERROR", use_color))
            for issue in issues:
                report_lines.append(f"    - {issue.get('description')}")
        
        if full_report and scans:
            report_lines.append("  关键文件扫描:")
            for scan in scans:
                status = "存在" if os.path.exists(scan['path']) else "丢失"
                exec_flag = "可执行" if scan.get('executable') else "不可执行"
                report_lines.append(f"    - {scan['path']} ({status}, {exec_flag})")
        
        if commands:
            report_lines.append("  命令检查:")
            for cmd in commands:
                if cmd.get('success'):
                    report_lines.append(colored_text(f"    ✓ {cmd['command']} (成功)", "SUCCESS", use_color))
                else:
                    report_lines.append(colored_text(f"    ✗ {cmd['command']} (失败: {cmd['returncode']})", "ERROR", use_color))
    
    # 修复建议
    report_lines.append("\n" + colored_text("[修复建议]", "INFO", use_color))
    
    suggestions = ["1. 确保Docker服务正常运行"]
    
    if not target_info.get('exists'):
        suggestions.append(f"2. 检查靶场目录是否存在: {target_info.get('path')}")
    
    if target_data.get('path_issues'):
        suggestions.append("3. 修复文件权限问题:")
        for issue in target_data['path_issues']:
            suggestions.append(f"   - {issue['path']}: {issue['issue']}")
    
    if target_data.get('port_conflicts'):
        suggestions.append("4. 解决端口冲突:")
        for conflict in target_data['port_conflicts']:
            suggestions.append(f"   - 端口 {conflict['port']}/{conflict['protocol']} (服务: {conflict['service']})")
    
    for suggestion in suggestions:
        report_lines.append(f"  - {suggestion}")
    
    # 结束信息
    report_lines.append("\n" + colored_text("=" * 80, "INFO", use_color))
    report_lines.append(colored_text(f"报告已保存: {target_data['json_path']}", "INFO", use_color))
    if full_report:
        report_lines.append(colored_text(f"详细日志: {LOG_FILE}", "INFO", use_color))
    report_lines.append("\n")
    
    return "\n".join(report_lines)

def debug_target(target_name, run_tests=True, log_level="INFO"):
    """调试特定靶场"""
    global logger
    logger = setup_logger(log_level)
    
    logger.info("=" * 80)
    logger.info(f"开始诊断靶场: {target_name}")
    logger.info("=" * 80)
    
    # 确保日期时间准确
    start_time = datetime.datetime.now()
    report_file = f"{target_name}-{start_time.strftime('%Y%m%d-%H%M%S')}"
    json_path = os.path.join(DEBUG_REPORT_DIR, f"{report_file}.json")
    
    try:
        # 收集诊断数据
        report_data = {
            'target': target_name,
            'start_time': start_time.isoformat(),
            'end_time': None,
            'system_info': get_system_info(),
            'docker_status': check_daemon_status(),
            'target_info': get_directory_info(os.path.join(VULHUB_PATH, target_name)),
            'compose_files': [],
            'port_conflicts': [],
            'path_issues': [],
            'test_results': {},
            'json_path': json_path
        }
        
        logger.debug("系统信息: \n" + json.dumps(report_data['system_info'], indent=2))
        logger.debug("Docker状态: \n" + json.dumps(report_data['docker_status'], indent=2))
        logger.debug("靶场目录信息: \n" + json.dumps(report_data['target_info'], indent=2))
        
        # 如果目录存在，查找并分析配置文件
        target_path = os.path.join(VULHUB_PATH, target_name)
        port_list = []
        volume_paths = []
        
        if report_data['target_info']['exists'] and report_data['target_info']['is_dir']:
            # 搜索所有docker-compose.yml文件
            for root, dirs, files in os.walk(target_path):
                if 'docker-compose.yml' in files or 'docker-compose.yaml' in files:
                    file_name = 'docker-compose.yml' if 'docker-compose.yml' in files else 'docker-compose.yaml'
                    file_path = os.path.join(root, file_name)
                    validation = validate_compose_file(file_path)
                    
                    report_data['compose_files'].append(validation)
                    
                    # 收集端口和卷信息
                    port_list.extend(validation.get('ports', []))
                    volume_paths.extend([
                        vol['host_path'] for vol in validation.get('volumes', []) 
                        if vol.get('host_path') not in volume_paths
                    ])
                    
                    logger.info(f"分析配置文件: {file_path}")
            
            # 检查端口冲突
            if port_list:
                conflicts = check_port_conflicts(port_list)
                if conflicts:
                    report_data['port_conflicts'] = conflicts
                    logger.warning(f"检测到端口冲突: {json.dumps(conflicts, indent=2)}")
            
            # 检查卷路径权限
            if volume_paths:
                issues = check_path_permissions(volume_paths)
                if issues:
                    report_data['path_issues'] = issues
                    logger.warning(f"检测到路径权限问题: {json.dumps(issues, indent=2)}")
            
            # 执行安全测试
            if run_tests:
                logger.info("执行安全诊断测试...")
                report_data['test_results'] = run_safe_tests(target_path)
                
                if report_data['test_results'].get('issues'):
                    logger.warning(f"测试发现问题: {json.dumps(report_data['test_results']['issues'], indent=2)}")
        
        # 结束时间
        report_data['end_time'] = datetime.datetime.now().isoformat()
        
        # 保存报告
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"诊断完成，报告保存在: {json_path}")
        
        return report_data, generate_report(report_data)
    
    except Exception as e:
        error_report = {
            'error': str(e),
            'traceback': traceback.format_exc(),
            'timestamp': datetime.datetime.now().isoformat()
        }
        with open(json_path, 'w') as f:
            json.dump(error_report, f, indent=2)
        
        logger.critical(f"诊断过程中发生错误: {str(e)}")
        raise

def cleanup_old_reports(max_reports=10):
    """清理旧的诊断报告，限制保存数量"""
    try:
        files = [os.path.join(DEBUG_REPORT_DIR, f) for f in os.listdir(DEBUG_REPORT_DIR) 
                 if f.endswith('.json') or f.endswith('.log')]
        
        if len(files) <= max_reports:
            return
        
        # 按修改时间排序
        files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
        
        # 删除旧文件
        for file_path in files[max_reports:]:
            try:
                os.remove(file_path)
                logger.debug(f"清理旧报告: {file_path}")
            except Exception as e:
                logger.warning(f"清理旧报告失败: {file_path} - {str(e)}")
    
    except Exception as e:
        logger.warning(f"清理旧报告时出错: {str(e)}")

if __name__ == '__main__':
    cleanup_old_reports()
    
    parser = argparse.ArgumentParser(
        description='Vulhub靶场调试诊断工具',
        epilog="示例: debug_target.py struts2",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('target', help='要诊断的靶场名称')
    parser.add_argument('--no-tests', action='store_false', dest='run_tests', 
                       help='不执行诊断测试')
    parser.add_argument('--log-level', default='INFO', 
                       choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], 
                       help='设置日志详细程度')
    parser.add_argument('--json-only', action='store_true', 
                       help='只输出JSON报告，不生成文本报告')
    parser.add_argument('--full-report', action='store_true', 
                       help='生成完整诊断报告（包含详细信息）')
    parser.add_argument('--no-color', action='store_true', 
                       help='禁用报告中的颜色输出')
    
    args = parser.parse_args()
    
    try:
        report_data, text_report = debug_target(
            args.target, 
            run_tests=args.run_tests,
            log_level=args.log_level
        )
        
        if args.json_only:
            print(json.dumps(report_data, indent=2))
        else:
            print(text_report)
        
        sys.exit(0)
        
    except Exception as e:
        print(f"\n{colored_text('诊断发生严重错误!', 'ERROR', not args.no_color)}")
        print(f"请检查完整日志: {LOG_FILE}")
        traceback.print_exc()
        sys.exit(1)
