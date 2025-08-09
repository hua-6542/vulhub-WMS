#!/bin/bash

echo "开始部署Vulhub管理系统..."

# 创建项目目录
mkdir -p /opt/vulhub-manager/
mkdir -p /opt/vulhub-manager/templates

# 复制应用文件
cp /tmp/vulhub-manager/app.py /opt/vulhub-manager/
cp /tmp/vulhub-manager/templates/index.html /opt/vulhub-manager/templates/
cp /tmp/vulhub-manager/debug_target.py /opt/vulhub-manager/
cp /tmp/vulhub-manager/sync_vulhub.py /opt/vulhub-manager/

# 设置权限
chmod +x /opt/vulhub-manager/app.py
chmod +x /opt/vulhub-manager/debug_target.py
chmod +x /opt/vulhub-manager/sync_vulhub.py
chown -R root:root /opt/vulhub-manager

# 启用并启动服务
systemctl daemon-reload
systemctl enable vulhub-manager.service
systemctl start vulhub-manager.service

echo "部署完成！"
echo "访问地址: http://$(hostname -I | awk '{print $1}'):5000"
echo "服务状态: systemctl status vulhub-manager.service"