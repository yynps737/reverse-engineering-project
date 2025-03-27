#!/bin/bash
#
# 高级逆向工程平台启动脚本
# 执行环境检查，安装依赖并启动Web界面
#

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 配置选项（可通过环境变量覆盖）
HOST=${HOST:-"0.0.0.0"}
PORT=${PORT:-8080}
DEBUG=${DEBUG:-"false"}
CHECK_DEPS=${CHECK_DEPS:-"true"}
INSTALL_DEPS=${INSTALL_DEPS:-"true"}
WEB_ONLY=${WEB_ONLY:-"false"}
VERBOSE=${VERBOSE:-"false"}

# 主目录
ROOT_DIR="$HOME/deobfuscator"

# 版本号
VERSION="2.0.0"

# 显示标题
show_banner() {
    echo -e "${BLUE}======================================================${NC}"
    echo -e "${GREEN}             高级逆向工程平台 v${VERSION}               ${NC}"
    echo -e "${BLUE}======================================================${NC}"
    echo -e "${YELLOW}  支持VMProtect, Themida等多种保护的逆向分析工具套件  ${NC}"
    echo -e "${BLUE}======================================================${NC}"
    echo ""
}

# 显示帮助信息
show_help() {
    echo -e "${CYAN}用法:${NC}"
    echo -e "  $0 [选项]"
    echo ""
    echo -e "${CYAN}选项:${NC}"
    echo -e "  --help, -h          显示此帮助信息"
    echo -e "  --no-check          跳过依赖检查"
    echo -e "  --no-install        不自动安装依赖"
    echo -e "  --web-only          仅启动Web界面，不执行其他服务"
    echo -e "  --host HOST         指定Web服务器主机 (默认: 0.0.0.0)"
    echo -e "  --port PORT         指定Web服务器端口 (默认: 8080)"
    echo -e "  --debug             启用调试模式"
    echo -e "  --verbose           启用详细输出"
    echo ""
}

# 处理命令行参数
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --help|-h)
                show_help
                exit 0
                ;;
            --no-check)
                CHECK_DEPS="false"
                shift
                ;;
            --no-install)
                INSTALL_DEPS="false"
                shift
                ;;
            --web-only)
                WEB_ONLY="true"
                shift
                ;;
            --host)
                HOST="$2"
                shift 2
                ;;
            --port)
                PORT="$2"
                shift 2
                ;;
            --debug)
                DEBUG="true"
                shift
                ;;
            --verbose)
                VERBOSE="true"
                shift
                ;;
            *)
                echo -e "${RED}未知选项: $1${NC}"
                show_help
                exit 1
                ;;
        esac
    done
}

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

log_debug() {
    if [[ "$VERBOSE" == "true" ]]; then
        echo -e "${BLUE}[DEBUG] $1${NC}"
    fi
}

# 检查依赖
check_dependencies() {
    log_info "检查依赖..."
    
    local missing_deps=0
    
    # 检查系统工具
    for tool in python3 pip3 gdb strings; do
        if ! command -v $tool &> /dev/null; then
            log_error "未找到: $tool"
            missing_deps=$((missing_deps + 1))
        else
            log_debug "已安装: $tool"
        fi
    done
    
    # 检查Python包
    local python_deps=("frida" "flask" "pefile" "werkzeug" "capstone")
    local missing_py_deps=()
    
    for pkg in "${python_deps[@]}"; do
        if ! python3 -c "import $pkg" &> /dev/null; then
            missing_py_deps+=("$pkg")
            missing_deps=$((missing_deps + 1))
        else
            log_debug "已安装Python包: $pkg"
        fi
    done
    
    # 显示缺失的Python包
    if [[ ${#missing_py_deps[@]} -gt 0 ]]; then
        log_warning "缺少Python包: ${missing_py_deps[*]}"
        
        if [[ "$INSTALL_DEPS" == "true" ]]; then
            log_info "正在安装Python包..."
            
            for pkg in "${missing_py_deps[@]}"; do
                log_info "安装 $pkg..."
                pip3 install $pkg
                
                if [[ $? -ne 0 ]]; then
                    log_error "安装 $pkg 失败"
                else
                    log_success "已安装 $pkg"
                    missing_deps=$((missing_deps - 1))
                fi
            done
        else
            log_warning "请手动安装缺少的Python包: pip3 install ${missing_py_deps[*]}"
        fi
    fi
    
    # 检查可选依赖
    local optional_tools=("radare2" "yara" "upx" "de4dot" "ghidra")
    local missing_opt=()
    
    for tool in "${optional_tools[@]}"; do
        if ! command -v $tool &> /dev/null; then
            missing_opt+=("$tool")
        else
            log_debug "已安装可选工具: $tool"
        fi
    done
    
    if [[ ${#missing_opt[@]} -gt 0 ]]; then
        log_warning "以下可选工具未安装: ${missing_opt[*]}"
        log_warning "安装这些工具可以增强分析功能"
    fi
    
    # 检查目录结构
    local dirs=("$ROOT_DIR" "$ROOT_DIR/web" "$ROOT_DIR/web/templates" "$ROOT_DIR/unpacker" "$ROOT_DIR/uploads" "$ROOT_DIR/results")
    
    for dir in "${dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            log_warning "目录不存在: $dir"
            
            mkdir -p "$dir"
            if [[ $? -eq 0 ]]; then
                log_success "已创建目录: $dir"
            else
                log_error "创建目录失败: $dir"
                missing_deps=$((missing_deps + 1))
            fi
        else
            log_debug "目录存在: $dir"
        fi
    done
    
    # 返回缺失依赖数量
    return $missing_deps
}

# 检查关键文件
check_key_files() {
    log_info "检查关键文件..."
    
    local missing_files=0
    local files=(
        "$ROOT_DIR/shell_detector.py"
        "$ROOT_DIR/dynamic_analyzer.py"
        "$ROOT_DIR/web/app.py"
        "$ROOT_DIR/web/templates/index.html"
        "$ROOT_DIR/web/templates/task_detail.html"
        "$ROOT_DIR/unpacker/universal_unpacker.py"
    )
    
    for file in "${files[@]}"; do
        if [[ ! -f "$file" ]]; then
            log_error "文件不存在: $file"
            missing_files=$((missing_files + 1))
        else
            log_debug "文件存在: $file"
            
            # 确保Python文件有执行权限
            if [[ "$file" == *.py ]]; then
                chmod +x "$file"
            fi
        fi
    done
    
    # 返回缺失文件数量
    return $missing_files
}

# 检查端口可用性
check_port() {
    local port=$1
    log_info "检查端口 $port 是否可用..."
    
    if command -v netstat &> /dev/null; then
        if netstat -tuln | grep -q ":$port\b"; then
            log_error "端口 $port 已被占用"
            if command -v lsof &> /dev/null; then
                log_info "正在使用端口 $port 的进程:"
                lsof -i :$port
            fi
            return 1
        else
            log_success "端口 $port 可用"
            return 0
        fi
    elif command -v ss &> /dev/null; then
        if ss -tuln | grep -q ":$port\b"; then
            log_error "端口 $port 已被占用"
            return 1
        else
            log_success "端口 $port 可用"
            return 0
        fi
    else
        log_warning "无法检查端口状态 (netstat/ss未安装)"
        return 0
    fi
}

# 启动Web界面
start_web_interface() {
    log_info "启动Web界面..."
    
    local web_app="$ROOT_DIR/web/app.py"
    
    if [[ ! -f "$web_app" ]]; then
        log_error "Web应用不存在: $web_app"
        return 1
    fi
    
    # 设置环境变量
    export HOST="$HOST"
    export PORT="$PORT"
    export DEBUG="$DEBUG"
    
    # 启动Web应用
    cd "$ROOT_DIR/web"
    
    if [[ "$DEBUG" == "true" ]]; then
        log_info "以调试模式启动Web界面..."
        python3 app.py &
    else
        log_info "以生产模式启动Web界面..."
        python3 app.py > /dev/null 2>&1 &
    fi
    
    WEB_PID=$!
    
    # 等待服务启动
    sleep 2
    
    # 检查进程是否存在
    if kill -0 $WEB_PID 2>/dev/null; then
        log_success "Web界面已启动，PID: $WEB_PID"
        
        # 保存PID到文件
        echo $WEB_PID > "$ROOT_DIR/web.pid"
        
        # 显示IP地址
        log_info "Web界面可通过以下地址访问:"
        if [[ "$HOST" == "0.0.0.0" ]]; then
            echo -e "${GREEN}本地访问: http://localhost:$PORT${NC}"
            
            # 显示所有网络接口
            if command -v ip &> /dev/null; then
                ip -4 addr show | grep "inet " | grep -v "127.0.0.1" | awk '{print "http://" $2}' | cut -d/ -f1 | sed "s/$/:$PORT/"
            elif command -v ifconfig &> /dev/null; then
                ifconfig | grep "inet " | grep -v "127.0.0.1" | awk '{print "http://" $2 ":'$PORT'"}' 
            fi
        else
            echo -e "${GREEN}http://$HOST:$PORT${NC}"
        fi
        
        return 0
    else
        log_error "Web界面启动失败"
        return 1
    fi
}

# 主函数
main() {
    show_banner
    parse_args "$@"
    
    # 检查依赖
    if [[ "$CHECK_DEPS" == "true" ]]; then
        check_dependencies
        local deps_result=$?
        
        if [[ $deps_result -gt 0 ]]; then
            log_warning "发现 $deps_result 个缺失的依赖"
        else
            log_success "所有必要依赖已安装"
        fi
        
        # 检查关键文件
        check_key_files
        local files_result=$?
        
        if [[ $files_result -gt 0 ]]; then
            log_error "发现 $files_result 个缺失的关键文件"
            log_error "请确保所有文件都在正确的位置"
            return 1
        else
            log_success "所有关键文件已就绪"
        fi
    fi
    
    # 检查端口
    check_port $PORT
    if [[ $? -ne 0 ]]; then
        log_error "无法启动Web界面: 端口 $PORT 不可用"
        return 1
    fi
    
    # 启动Web界面
    start_web_interface
    if [[ $? -ne 0 ]]; then
        log_error "启动Web界面失败"
        return 1
    fi
    
    # 显示使用说明
    echo -e "\n${BLUE}使用说明:${NC}"
    echo -e "1. 通过浏览器访问上述地址"
    echo -e "2. 上传需要分析的可执行文件"
    echo -e "3. 选择分析类型: 静态分析、动态分析或脱壳"
    echo -e "\n${YELLOW}按Ctrl+C停止服务${NC}"
    
    # 等待用户中断
    wait $WEB_PID
    
    return 0
}

# 清理函数 - 在脚本被中断时调用
cleanup() {
    echo -e "\n${YELLOW}正在停止服务...${NC}"
    
    # 停止Web服务
    if [[ -f "$ROOT_DIR/web.pid" ]]; then
        local pid=$(cat "$ROOT_DIR/web.pid")
        if [[ -n "$pid" ]]; then
            kill $pid 2>/dev/null
            rm "$ROOT_DIR/web.pid"
        fi
    fi
    
    log_success "服务已停止"
    exit 0
}

# 设置清理钩子
trap cleanup SIGINT SIGTERM

# 执行主函数
main "$@"
exit $?