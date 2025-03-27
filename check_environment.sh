#!/bin/bash
# 增强的逆向工程环境完整性检查脚本

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 配置
# 用户可以通过环境变量覆盖默认设置
ROOT_DIR=${REVERSE_ROOT_DIR:-"$HOME/deobfuscator"}
REQUIRED_TOOLS=("gdb" "radare2" "python3" "strings" "upx")
RECOMMENDED_TOOLS=("ltrace" "strace" "ghidra" "ida-free")
PYTHON_DEPS=("frida" "flask" "pefile" "capstone" "unicorn" "keystone" "r2pipe" "requests" "yara-python")

# 日志函数
log_info() {
    echo -e "${YELLOW}[INFO] $1${NC}"
}

log_success() {
    echo -e "${GREEN}[SUCCESS] $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

log_error() {
    echo -e "${RED}[ERROR] $1${NC}"
}

# 进度显示
show_progress() {
    local current=$1
    local total=$2
    local bar_size=40
    local filled=$(( current * bar_size / total ))
    local empty=$(( bar_size - filled ))
    
    printf "\r["
    printf "%${filled}s" '' | tr ' ' '#'
    printf "%${empty}s" '' | tr ' ' ' '
    printf "] %d%%" $(( current * 100 / total ))
}

# 标题显示
echo -e "\n${BLUE}===========================================${NC}"
echo -e "${GREEN}     逆向工程环境完整性检查工具 v2.0     ${NC}"
echo -e "${BLUE}===========================================${NC}\n"

# 检查核心目录结构
log_info "检查目录结构..."

DIRS=(
  "$ROOT_DIR"
  "$ROOT_DIR/web"
  "$ROOT_DIR/web/templates"
  "$ROOT_DIR/unpacker"
  "$ROOT_DIR/engines"
  "$ROOT_DIR/uploads"
  "$ROOT_DIR/results"
)

dir_count=0
total_dirs=${#DIRS[@]}

for dir in "${DIRS[@]}"; do
  ((dir_count++))
  show_progress $dir_count $total_dirs
  
  if [ -d "$dir" ]; then
    chmod 755 "$dir" &>/dev/null
  else
    mkdir -p "$dir" &>/dev/null
    chmod 755 "$dir" &>/dev/null
  fi
done

echo -e "\n"
log_success "所有必要目录已创建并设置正确权限"

# 检查关键文件
log_info "检查关键文件..."

FILES=(
  "$ROOT_DIR/shell_detector.py"
  "$ROOT_DIR/dynamic_analyzer.py"
  "$ROOT_DIR/web/app.py"
  "$ROOT_DIR/web/templates/index.html"
  "$ROOT_DIR/web/templates/task_detail.html"
  "$ROOT_DIR/unpacker/universal_unpacker.py"
  "$HOME/start_reverse_suite.sh"
)

missing_files=()
file_count=0
total_files=${#FILES[@]}

for file in "${FILES[@]}"; do
  ((file_count++))
  show_progress $file_count $total_files
  
  if [ -f "$file" ]; then
    continue
  else
    missing_files+=("$file")
  fi
done

echo -e "\n"
if [ ${#missing_files[@]} -eq 0 ]; then
  log_success "所有关键文件存在"
else
  log_error "以下文件缺失:"
  for file in "${missing_files[@]}"; do
    echo -e "  - $file"
  done
  echo -e "\n${YELLOW}您需要解决这些缺失文件才能继续${NC}"
fi

# 检查文件权限
log_info "检查执行权限..."

EXEC_FILES=(
  "$ROOT_DIR/shell_detector.py"
  "$ROOT_DIR/dynamic_analyzer.py"
  "$ROOT_DIR/unpacker/universal_unpacker.py"
  "$HOME/start_reverse_suite.sh"
)

exec_count=0
total_exec=${#EXEC_FILES[@]}

for file in "${EXEC_FILES[@]}"; do
  ((exec_count++))
  show_progress $exec_count $total_exec
  
  if [ -f "$file" ]; then
    if [ -x "$file" ]; then
      continue
    else
      chmod +x "$file" &>/dev/null
    fi
  fi
done

echo -e "\n"
log_success "所有可执行文件已设置正确权限"

# 检查Python依赖
log_info "检查Python依赖..."

missing_deps=()
installed_deps=()
pip_output=$(pip3 list 2>/dev/null)
dep_count=0
total_deps=${#PYTHON_DEPS[@]}

for dep in "${PYTHON_DEPS[@]}"; do
  ((dep_count++))
  show_progress $dep_count $total_deps
  
  if echo "$pip_output" | grep -q "$dep"; then
    installed_deps+=("$dep")
  else
    missing_deps+=("$dep")
  fi
done

echo -e "\n"
if [ ${#missing_deps[@]} -eq 0 ]; then
  log_success "所有Python依赖已安装"
else
  log_warning "缺少以下Python依赖:"
  for dep in "${missing_deps[@]}"; do
    echo -e "  - $dep"
  done
  
  read -p "是否安装缺失的依赖? (y/n): " choice
  if [[ $choice =~ ^[Yy]$ ]]; then
    for dep in "${missing_deps[@]}"; do
      echo -e "安装 $dep..."
      pip3 install $dep
    done
  else
    echo -e "您需要手动安装缺失的依赖"
  fi
fi

# 检查系统工具
log_info "检查系统工具..."

missing_tools=()
recommended_missing=()
tool_count=0
total_tools=$((${#REQUIRED_TOOLS[@]} + ${#RECOMMENDED_TOOLS[@]}))

for tool in "${REQUIRED_TOOLS[@]}"; do
  ((tool_count++))
  show_progress $tool_count $total_tools
  
  if command -v $tool &> /dev/null; then
    continue
  else
    missing_tools+=("$tool")
  fi
done

for tool in "${RECOMMENDED_TOOLS[@]}"; do
  ((tool_count++))
  show_progress $tool_count $total_tools
  
  if command -v $tool &> /dev/null; then
    continue
  else
    recommended_missing+=("$tool")
  fi
done

echo -e "\n"
if [ ${#missing_tools[@]} -eq 0 ]; then
  log_success "所有必要工具已安装"
else
  log_error "缺少以下必要工具:"
  for tool in "${missing_tools[@]}"; do
    echo -e "  - $tool"
  done
  
  echo -e "\n${YELLOW}您需要安装这些工具才能继续，例如:${NC}"
  echo -e "  sudo apt install -y ${missing_tools[*]}"
fi

if [ ${#recommended_missing[@]} -gt 0 ]; then
  log_warning "建议安装以下工具以提高功能:"
  for tool in "${recommended_missing[@]}"; do
    echo -e "  - $tool"
  done
fi

# 检查网络连接
log_info "测试网络端口可用性..."

if command -v netstat &> /dev/null; then
  if netstat -tuln | grep -q ":8080"; then
    log_error "端口8080已被占用"
    echo -e "  您需要关闭占用该端口的服务或修改web界面端口"
    lsof -i :8080 2>/dev/null || echo "无法确定占用端口的进程"
  else
    log_success "端口8080可用"
  fi
else
  log_warning "无法检查端口状态 (netstat未安装)"
fi

# 环境摘要
echo -e "\n${BLUE}===========================================${NC}"
echo -e "${GREEN}             环境检查摘要               ${NC}"
echo -e "${BLUE}===========================================${NC}"

echo -e "目录状态: ${#DIRS[@]}个已检查"
echo -e "文件状态: ${#FILES[@]}个已检查, ${#missing_files[@]}个缺失"
echo -e "Python依赖: ${#PYTHON_DEPS[@]}个已检查, ${#missing_deps[@]}个缺失"
echo -e "系统工具: ${#REQUIRED_TOOLS[@]}个必要, ${#missing_tools[@]}个缺失"
echo -e "推荐工具: ${#RECOMMENDED_TOOLS[@]}个推荐, ${#recommended_missing[@]}个未安装"

if [ ${#missing_files[@]} -eq 0 ] && [ ${#missing_tools[@]} -eq 0 ]; then
  echo -e "\n${GREEN}环境检查完成! 系统已准备就绪${NC}"
  echo -e "运行以下命令启动系统:"
  echo -e "  ${YELLOW}$HOME/start_reverse_suite.sh${NC}"
else
  echo -e "\n${RED}环境检查完成，但存在问题需要解决${NC}"
  echo -e "请解决上述问题后再启动系统"
fi

echo -e "${BLUE}===========================================${NC}\n"