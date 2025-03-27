#!/bin/bash
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}===== 逆向工程环境完整性检查 =====${NC}"

# 检查核心目录结构
echo -e "\n${YELLOW}检查目录结构:${NC}"
DIRS=(
  "~/deobfuscator"
  "~/deobfuscator/web"
  "~/deobfuscator/web/templates"
  "~/deobfuscator/unpacker"
  "~/deobfuscator/engines"
  "~/deobfuscator/uploads"
  "~/deobfuscator/results"
)

for dir in "${DIRS[@]}"; do
  if [ -d $(eval echo $dir) ]; then
    echo -e "${GREEN}✓ 目录存在: $dir${NC}"
  else
    echo -e "${RED}✗ 目录缺失: $dir${NC}"
    mkdir -p $(eval echo $dir)
    echo -e "${GREEN}  已创建目录${NC}"
  fi
done

# 检查关'EOF'
echo -e "\n${YELLOW}检查关键文件:${NC}"
FILES=(
  "~/deobfuscator/shell_detector.py"
  "~/deobfuscator/dynamic_analyzer.py"
  "~/deobfuscator/web/app.py"
  "~/deobfuscator/web/templates/index.html"
  "~/deobfuscator/web/templates/task_detail.html"
  "~/deobfuscator/unpacker/universal_unpacker.py"
  "~/start_reverse_suite.sh"
)

MISSING=0
for file in "${FILES[@]}"; do
  if [ -f $(eval echo $file) ]; then
    echo -e "${GREEN}✓ 文件存在: $file${NC}"
  else
    echo -e "${RED}✗ 文件缺失: $file${NC}"
    MISSING=1
  fi
done

# 检查文件权限
echo -e "\n${YELLOW}检查执行>:${NC}"
EXEC_FILES=(
  "~/deobfuscator/shell_detector.py"
  "~/deobfuscator/dynamic_analyzer.py"
  "~/deobfuscator/unpacker/universal_unpacker.py"
  "~/start_reverse_suite.sh"
)

for file in "${EXEC_FILES[@]}"; do
  if [ -x $(eval echo $file) ]; then
    echo -e "${GREEN}✓ 执行权限正确: $file${NC}"
  else
    echo -e "${RED}✗ 缺少执行权限: $file${NC}"
    chmod +x $(eval echo $file)
    echo -e "${GREEN}  已>${NC}"
  fi
done

# 检查Python依赖
echo -e "\n${YELLOW}检查Python依赖:${NC}"
PYTHON_DEPS=(
  "frida"
  "flask"
  "pefile"
  "capstone"
  "unicorn"
  "keystone"
  "r2pipe"
  "requests"
)

for dep in "${PYTHON_DEPS[@]}"; do
  if pip3 list | grep -q $dep; then
    echo -e "${GREEN}✓ Python包已安装: $dep${NC}"
  else
    echo -e "${RED}✗ Python包缺失: $dep${NC}"
    echo "  运行以下命令安装: pip3 install $dep"
  fi
done

# 检查系统工具
echo -e "\n${YELLOW}检查系统工具:${NC}"
TOOLS=(
  "gdb"
  "radare2"
  "python3"
  "strings"
  "upx"
)

for tool in "${TOOLS[@]}"; do
  if command -v $tool &> /dev/null; then
    echo -e "${GREEN}✓ 工具已安装: $tool${NC}"
  else
    echo -e "${RED}✗ 工具缺失: $tool${NC}"
    echo "  运行以下命令安装: sudo apt install -y $tool"
  fi
done

if [ $MISSING -eq 1 ]; then
  echo -e "\n${RED}检测到缺失文件！请重新生成缺失的组件。${NC}"
else
  echo -e "\n${GREEN}文件检查完成！所有关键组件都存在。${NC}"
fi

# 检查网络连接
echo -e "\n${YELLOW}测试网络端口可用性:${NC}"
if command -v netstat &> /dev/null && netstat -tuln | grep -q ":8080"; then
  echo -e "${RED}✗ 端口8080已被占用${NC}"
  echo "  您需要关闭占用该端口的服务或修改web界面端口"
else
  echo -e "${GREEN}✓ 端口8080可用${NC}"
fi

echo -e "\n${YELLOW}环境检查完成！${NC}"
