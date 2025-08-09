# vulhub-WMS
一个简单的vulhub靶场的在线管理系统，提供基本的镜像拉取，靶场启动与关闭等服务。方便初学者快速上手vulhub。
<img width="2350" height="1091" alt="image" src="https://github.com/user-attachments/assets/a97b44e7-20a9-4e04-a681-9935c5770ee8" />

## 前提条件
1.主机有docker以及docker-compose等必要配置<br>
2.将官方的vulhub靶场源文件拉取至/opt目录下<br>
3.使用以下方法配置环境
```
# 更新系统
sudo yum update -y
# 安装必要的工具
sudo yum install -y git wget curl epel-release
# 安装Python 3.6的pip
sudo yum install -y python3-pip
# 安装Python依赖
pip3 install flask docker docker-compose
# 安装Node.js和npm（用于前端构建）
curl -sL https://rpm.nodesource.com/setup_14.x | sudo bash -
sudo yum install -y nodejs
```
* 注意根据自己的python版本进行配置
* 项目中的vulhub靶场不全
## 如何使用
1.将项目下载到本地<br>
2.创建/opt/vulhub-manager目录<br>
3.将主文件移动到创建的目录中：<br>
例：
```
cp /tmp/vulhub-manager/app.py /opt/vulhub-manager/
```
4.可以使用以下命令创建开机自启项，也可以将文件移动到/etc/systemd/system/目录下
```
# 创建服务文件
sudo cat > /etc/systemd/system/vulhub-manager.service << 'EOF'
[Unit]
Description=Vulhub Manager Service
After=network.target docker.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/vulhub-manager
ExecStart=/usr/bin/python3 /opt/vulhub-manager/app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
```
## 使用以下命令启动
```
# 重新加载systemd配置
sudo systemctl daemon-reload

# 启用服务开机自启
sudo systemctl enable vulhub-manager.service

# 启动服务
sudo systemctl start vulhub-manager.service

# 检查服务状态
sudo systemctl status vulhub-manager.service
```
如果显示如下页面则表明成功部署。
<img width="2129" height="1038" alt="image" src="https://github.com/user-attachments/assets/84078467-4d23-4d97-8584-c2b631805046" />

## 脚本的使用<br>
脚本文件deploy_vulhub_manager.sh
* 务必将项目下载到tmp目录下，不然无法使用。

输入如下命令使用脚本一键部署
```
给脚本文件赋予执行权限
  chmod +x deploy_vulhub_manager.sh
  使用如下命令
  sudo ./deploy_vulhub_manager.sh
或
sudo bash deploy_vulhub_manager.sh
```
# 好啦你已经完成vulhub管理系统的部署了，祝您学习愉快！
