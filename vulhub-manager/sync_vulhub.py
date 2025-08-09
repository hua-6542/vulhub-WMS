#!/usr/bin/env python3
import os
import subprocess
import json
import shutil
from datetime import datetime

VULHUB_PATH = '/opt/vulhub'
BACKUP_PATH = '/opt/vulhub_backup'

def backup_existing():
    """备份现有的vulhub目录"""
    if os.path.exists(VULHUB_PATH):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_dir = f"{BACKUP_PATH}_{timestamp}"
        print(f"备份现有目录到: {backup_dir}")
        shutil.copytree(VULHUB_PATH, backup_dir)

def sync_from_gitee():
    """从码云同步Vulhub仓库"""
    try:
        # 删除现有目录
        if os.path.exists(VULHUB_PATH):
            shutil.rmtree(VULHUB_PATH)
        
        # 从码云克隆
        print("从码云克隆Vulhub仓库...")
        result = subprocess.run([
            'git', 'clone', 'https://gitee.com/mirrors/vulhub.git', VULHUB_PATH
        ], capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            print("✅ 成功从码云同步Vulhub")
            return True
        else:
            print(f"❌ 码云同步失败: {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ 码云同步异常: {e}")
        return False

def sync_from_zip():
    """从zip包同步"""
    try:
        import urllib.request
        import zipfile
        
        print("从码云下载zip包...")
        zip_url = "https://gitee.com/mirrors/vulhub/repository/archive/master.zip"
        zip_path = "/tmp/vulhub.zip"
        
        # 下载zip文件
        urllib.request.urlretrieve(zip_url, zip_path)
        
        # 解压
        if os.path.exists(VULHUB_PATH):
            shutil.rmtree(VULHUB_PATH)
            
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall("/tmp")
        
        # 移动解压后的目录
        extracted_dir = "/tmp/vulhub-master"
        if os.path.exists(extracted_dir):
            shutil.move(extracted_dir, VULHUB_PATH)
            print("✅ 成功从zip包同步Vulhub")
            return True
        else:
            print("❌ 解压后的目录不存在")
            return False
            
    except Exception as e:
        print(f"❌ zip包同步异常: {e}")
        return False

def get_target_info():
    """获取靶场信息"""
    targets = []
    if os.path.exists(VULHUB_PATH):
        for root, dirs, files in os.walk(VULHUB_PATH):
            # 跳过隐藏目录
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            
            if 'docker-compose.yml' in files:
                rel_path = os.path.relpath(root, VULHUB_PATH)
                if rel_path != '.':
                    targets.append({
                        'name': rel_path,
                        'path': root,
                        'compose_file': os.path.join(root, 'docker-compose.yml')
                    })
    return targets

def main():
    print("=== Vulhub自动同步工具 ===")
    
    # 创建备份目录
    os.makedirs(BACKUP_PATH, exist_ok=True)
    
    # 备份现有数据
    backup_existing()
    
    # 尝试多种同步方式
    success = False
    
    # 方式1: git clone
    print("尝试方式1: git clone (码云)...")
    success = sync_from_gitee()
    
    # 方式2: zip下载
    if not success:
        print("尝试方式2: zip包下载...")
        success = sync_from_zip()
    
    if success:
        # 显示同步结果
        targets = get_target_info()
        print(f"\n✅ 同步完成! 发现 {len(targets)} 个靶场:")
        for target in targets[:10]:  # 只显示前10个
            print(f"  - {target['name']}")
        if len(targets) > 10:
            print(f"  ... 还有 {len(targets) - 10} 个靶场")
    else:
        print("❌ 所有同步方式都失败了")

if __name__ == '__main__':
    main()
