#!/bin/bash

# 性能测试脚本 - 认证中间件负载测试
# Usage: ./load_test.sh [test_type] [duration] [connections]

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 默认配置
DEFAULT_URL="http://localhost:8080/api/test"
DEFAULT_DURATION="60s"
DEFAULT_THREADS=10
DEFAULT_CONNECTIONS=100
DEFAULT_TEST_TYPE="standard"

# 参数处理
TEST_TYPE=${1:-$DEFAULT_TEST_TYPE}
DURATION=${2:-$DEFAULT_DURATION}
CONNECTIONS=${3:-$DEFAULT_CONNECTIONS}
URL=${4:-$DEFAULT_URL}

# 打印配置
echo -e "${GREEN}=== 认证中间件性能测试 ===${NC}"
echo -e "测试类型: ${YELLOW}$TEST_TYPE${NC}"
echo -e "持续时间: ${YELLOW}$DURATION${NC}"
echo -e "并发连接: ${YELLOW}$CONNECTIONS${NC}"
echo -e "目标URL: ${YELLOW}$URL${NC}"
echo ""

# 检查依赖
check_dependencies() {
    local deps=("wrk" "jq" "curl")
    for dep in "${deps[@]}"; do
        if ! command -v $dep &> /dev/null; then
            echo -e "${RED}错误: 未找到 $dep，请先安装${NC}"
            exit 1
        fi
    done
}

# 获取测试token
get_test_token() {
    echo -e "${GREEN}获取测试Token...${NC}"
    TOKEN=$(curl -s -X POST http://localhost:8080/auth/token \
        -H "Content-Type: application/json" \
        -d '{"username":"test","password":"test"}' | jq -r .token)
    
    if [ -z "$TOKEN" ]; then
        echo -e "${RED}错误: 无法获取测试Token${NC}"
        exit 1
    fi
    echo -e "${GREEN}Token获取成功${NC}"
}

# 创建Lua脚本
create_lua_script() {
    cat > /tmp/auth_load_test.lua << 'EOF'
-- 认证中间件负载测试脚本

-- 初始化
local thread_id = 1
local request_count = 0
local error_count = 0

-- Token池
tokens = {}
token_index = 1

-- 初始化函数
function setup(thread)
    thread_id = thread
    
    -- 为每个线程生成不同的token
    for i = 1, 10 do
        tokens[i] = os.getenv("TEST_TOKEN") or "test-token-" .. thread_id .. "-" .. i
    end
    
    return thread
end

-- 请求函数
function request()
    -- 轮换使用token
    token_index = (token_index % #tokens) + 1
    local token = tokens[token_index]
    
    -- 构造请求
    local headers = {
        ["Authorization"] = "Bearer " .. token,
        ["Content-Type"] = "application/json",
        ["X-Request-ID"] = string.format("%d-%d", thread_id, request_count)
    }
    
    request_count = request_count + 1
    
    -- 随机选择不同的端点
    local paths = {"/api/users", "/api/products", "/api/orders", "/api/test"}
    local path = paths[math.random(#paths)]
    
    return wrk.format("GET", path, headers, nil)
end

-- 响应处理
function response(status, headers, body)
    if status ~= 200 then
        error_count = error_count + 1
    end
end

-- 统计输出
function done(summary, latency, requests)
    -- 计算统计数据
    local qps = summary.requests / summary.duration * 1000000
    local error_rate = (error_count / summary.requests) * 100
    
    -- 输出JSON格式的结果
    local result = {
        duration = summary.duration / 1000000,
        requests = summary.requests,
        bytes = summary.bytes,
        errors = {
            connect = summary.errors.connect,
            read = summary.errors.read,
            write = summary.errors.write,
            status = summary.errors.status,
            timeout = summary.errors.timeout,
            total = error_count
        },
        latency = {
            min = latency.min / 1000,
            max = latency.max / 1000,
            mean = latency.mean / 1000,
            stdev = latency.stdev / 1000,
            p50 = latency:percentile(50) / 1000,
            p90 = latency:percentile(90) / 1000,
            p95 = latency:percentile(95) / 1000,
            p99 = latency:percentile(99) / 1000,
            p999 = latency:percentile(99.9) / 1000
        },
        throughput = {
            qps = qps,
            bytes_per_sec = summary.bytes / (summary.duration / 1000000)
        },
        error_rate = error_rate
    }
    
    -- 打印结果
    print("\n" .. string.rep("=", 60))
    print("性能测试结果")
    print(string.rep("=", 60))
    print(string.format("总请求数: %d", result.requests))
    print(string.format("测试时长: %.2f 秒", result.duration))
    print(string.format("QPS: %.2f", result.qps))
    print(string.format("错误率: %.2f%%", result.error_rate))
    print("\n延迟统计 (ms):")
    print(string.format("  最小值: %.2f", result.latency.min))
    print(string.format("  最大值: %.2f", result.latency.max))
    print(string.format("  平均值: %.2f", result.latency.mean))
    print(string.format("  标准差: %.2f", result.latency.stdev))
    print(string.format("  P50: %.2f", result.latency.p50))
    print(string.format("  P90: %.2f", result.latency.p90))
    print(string.format("  P95: %.2f", result.latency.p95))
    print(string.format("  P99: %.2f", result.latency.p99))
    print(string.format("  P99.9: %.2f", result.latency.p999))
    print(string.rep("=", 60))
end
EOF
}

# 标准负载测试
run_standard_test() {
    echo -e "${GREEN}执行标准负载测试...${NC}"
    
    export TEST_TOKEN="$TOKEN"
    
    wrk -t$DEFAULT_THREADS \
        -c$CONNECTIONS \
        -d$DURATION \
        --script=/tmp/auth_load_test.lua \
        --latency \
        $URL
}

# 递增负载测试
run_ramp_test() {
    echo -e "${GREEN}执行递增负载测试...${NC}"
    
    local stages=(10 50 100 200 500 1000)
    
    for conn in "${stages[@]}"; do
        echo -e "\n${YELLOW}测试并发数: $conn${NC}"
        
        export TEST_TOKEN="$TOKEN"
        
        wrk -t$DEFAULT_THREADS \
            -c$conn \
            -d30s \
            --script=/tmp/auth_load_test.lua \
            --latency \
            $URL \
            2>&1 | tail -n 20
        
        echo -e "${GREEN}等待5秒后继续...${NC}"
        sleep 5
    done
}

# 压力测试
run_stress_test() {
    echo -e "${GREEN}执行压力测试...${NC}"
    echo -e "${YELLOW}警告: 这将产生极高负载${NC}"
    
    export TEST_TOKEN="$TOKEN"
    
    wrk -t50 \
        -c2000 \
        -d$DURATION \
        --script=/tmp/auth_load_test.lua \
        --latency \
        --timeout 30s \
        $URL
}

# 长时间稳定性测试
run_endurance_test() {
    echo -e "${GREEN}执行长时间稳定性测试...${NC}"
    echo -e "${YELLOW}测试将运行10分钟${NC}"
    
    export TEST_TOKEN="$TOKEN"
    
    wrk -t$DEFAULT_THREADS \
        -c$CONNECTIONS \
        -d600s \
        --script=/tmp/auth_load_test.lua \
        --latency \
        $URL
}

# 并发场景测试
run_scenario_test() {
    echo -e "${GREEN}执行并发场景测试...${NC}"
    
    # 启动多个并发测试进程
    local pids=()
    
    # 场景1: 高频小请求
    wrk -t5 -c50 -d$DURATION --script=/tmp/auth_load_test.lua $URL &
    pids+=($!)
    
    # 场景2: 中等负载
    wrk -t10 -c100 -d$DURATION --script=/tmp/auth_load_test.lua $URL &
    pids+=($!)
    
    # 场景3: 突发流量
    sleep 10
    wrk -t20 -c500 -d30s --script=/tmp/auth_load_test.lua $URL &
    pids+=($!)
    
    # 等待所有进程完成
    for pid in "${pids[@]}"; do
        wait $pid
    done
    
    echo -e "${GREEN}所有场景测试完成${NC}"
}

# 对比测试（有缓存 vs 无缓存）
run_comparison_test() {
    echo -e "${GREEN}执行对比测试...${NC}"
    
    # 测试无缓存情况
    echo -e "\n${YELLOW}测试1: 无缓存（使用不同token）${NC}"
    cat > /tmp/no_cache_test.lua << 'EOF'
function request()
    local token = "token-" .. math.random(10000)
    return wrk.format("GET", "/api/test", {["Authorization"] = "Bearer " .. token}, nil)
end
EOF
    
    wrk -t$DEFAULT_THREADS -c$CONNECTIONS -d30s \
        --script=/tmp/no_cache_test.lua --latency $URL
    
    sleep 5
    
    # 测试有缓存情况
    echo -e "\n${YELLOW}测试2: 有缓存（使用相同token）${NC}"
    export TEST_TOKEN="$TOKEN"
    
    wrk -t$DEFAULT_THREADS -c$CONNECTIONS -d30s \
        --script=/tmp/auth_load_test.lua --latency $URL
}

# 生成HTML报告
generate_html_report() {
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local report_file="auth_performance_report_${timestamp}.html"
    
    cat > $report_file << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>认证中间件性能测试报告</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .metric { 
            display: inline-block; 
            margin: 10px; 
            padding: 15px; 
            border: 1px solid #ddd; 
            border-radius: 5px;
        }
        .metric-value { font-size: 24px; font-weight: bold; color: #2196F3; }
        .chart-container { width: 48%; display: inline-block; margin: 1%; }
        h1 { color: #333; }
        h2 { color: #666; border-bottom: 2px solid #eee; padding-bottom: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>认证中间件性能测试报告</h1>
        <p>生成时间: <span id="timestamp"></span></p>
        
        <h2>关键指标</h2>
        <div id="metrics"></div>
        
        <h2>延迟分布</h2>
        <div class="chart-container">
            <canvas id="latencyChart"></canvas>
        </div>
        
        <h2>QPS趋势</h2>
        <div class="chart-container">
            <canvas id="qpsChart"></canvas>
        </div>
        
        <h2>测试配置</h2>
        <div id="config"></div>
    </div>
    
    <script>
        // 添加实际数据和图表逻辑
        document.getElementById('timestamp').textContent = new Date().toLocaleString();
    </script>
</body>
</html>
EOF
    
    echo -e "${GREEN}报告已生成: $report_file${NC}"
}

# 清理函数
cleanup() {
    rm -f /tmp/auth_load_test.lua
    rm -f /tmp/no_cache_test.lua
}

# 主函数
main() {
    # 检查依赖
    check_dependencies
    
    # 获取token
    get_test_token
    
    # 创建Lua脚本
    create_lua_script
    
    # 根据测试类型执行
    case $TEST_TYPE in
        standard)
            run_standard_test
            ;;
        ramp)
            run_ramp_test
            ;;
        stress)
            run_stress_test
            ;;
        endurance)
            run_endurance_test
            ;;
        scenario)
            run_scenario_test
            ;;
        comparison)
            run_comparison_test
            ;;
        all)
            run_standard_test
            echo -e "\n${YELLOW}休息10秒...${NC}\n"
            sleep 10
            run_ramp_test
            echo -e "\n${YELLOW}休息10秒...${NC}\n"
            sleep 10
            run_comparison_test
            ;;
        *)
            echo -e "${RED}未知的测试类型: $TEST_TYPE${NC}"
            echo "可用类型: standard, ramp, stress, endurance, scenario, comparison, all"
            exit 1
            ;;
    esac
    
    # 生成报告
    generate_html_report
    
    # 清理
    cleanup
    
    echo -e "\n${GREEN}测试完成！${NC}"
}

# 设置信号处理
trap cleanup EXIT

# 执行主函数
main