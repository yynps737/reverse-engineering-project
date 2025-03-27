#!/bin/bash

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}======================================${NC}"
echo -e "${GREEN}启动终极逆向工程套件${NC}"
echo -e "${BLUE}======================================${NC}"

# 检查依赖
echo -e "${YELLOW}检查依赖...${NC}"

# 检查系统工具
for tool in python3 pip3 gdb radare2; do
  if ! command -v $tool &> /dev/null; then
    echo -e "${RED}未找到 $tool${NC}"
    echo -e "${YELLOW}请运行: sudo apt install -y $tool${NC}"
    exit 1
  fi
done

# 检查Python包
for pkg in frida flask pefile capstone; do
  if ! pip3 list | grep -q $pkg; then
    echo -e "${YELLOW}安装Python包: $pkg${NC}"
    pip3 install $pkg
  fi
done

echo -e "${GREEN}依赖检查完成${NC}"

# 确保工作
mkdir -p ~/deobfuscator/uploads
mkdir -p ~/deobfuscator/results

# 启动Web界面
echo -e "${YELLOW}启动Web界面...${NC}"

# 检查端口
if netstat -tuln | grep -q ":8080"; then
  echo -e "${RED}端口8080已被占用，请先释放该端口${NC}"
  exit 1
fi

# 启动Web应用
cd ~/deobfuscator/web/
python3 app.py &
WEB_PID=$!

# 等待服务启动
sleep 3

if ps -p $WEB_PID > /dev/null; then
  echo -e "${GREEN}Web界面已启动，访问 http://localhost:8080${NC}"
  
  # 显示IP地址
  echo -e "${BLUE}可通过以下地址访问:${NC}"
  ip addr | grep "inet " | grep -v "127.0.0.1" | awk '{print "http://" $2}' | cut -d/ -f1 | sed 's/$/:8080/'
  
  # 显示使用说明
  echo -e "\n${BLUE}使用说明:${NC}"
  echo -e "1. 通过浏览器访问上述地址"
  echo -e "2. 上传需要分析的可执行文""""""
  echo -e "3. 选择分析类型: 静态分析或动态分析"
"
  
  # 等待用户中断
  wait $WEB_PID
else
  echo -e "${RED}Web界面启动失败${NC}"
  exit 1
fi
