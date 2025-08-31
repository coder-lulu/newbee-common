#!/bin/bash

# JWT验证和上下文注入性能优化验证脚本
# Copyright 2024 The NewBee Authors

set -e

echo "🚀 JWT验证和上下文注入性能优化验证"
echo "====================================="

# 检查Go环境
if ! command -v go &> /dev/null; then
    echo "❌ 错误: Go环境未安装"
    exit 1
fi

# 检查当前目录
if [ ! -f "ultra_fast_jwt.go" ]; then
    echo "❌ 错误: 请在正确的目录下运行此脚本"
    echo "   当前目录应包含 ultra_fast_jwt.go 文件"
    exit 1
fi

echo "✅ 环境检查通过"

# 运行基准测试
echo ""
echo "📊 运行JWT验证性能基准测试..."
echo "================================"

go test -bench=BenchmarkJWTValidationPerformance -benchmem -benchtime=5s -timeout=10m

echo ""
echo "📊 运行中间件性能基准测试..."
echo "==============================="

go test -bench=BenchmarkMiddlewarePerformance -benchmem -benchtime=5s -timeout=10m

echo ""
echo "📊 运行并发性能测试..."
echo "====================="

go test -bench=BenchmarkConcurrentPerformance -benchmem -benchtime=5s -timeout=10m

echo ""
echo "📊 运行内存效率测试..."
echo "====================="

go test -bench=BenchmarkMemoryEfficiency -benchmem -benchtime=5s -timeout=10m

echo ""
echo "📊 运行缓存效率测试..."
echo "====================="

go test -bench=BenchmarkCacheEfficiency -benchmem -benchtime=5s -timeout=10m

# 运行功能测试
echo ""
echo "🧪 运行功能测试..."
echo "=================="

go test -run=TestUltraFastJWT -v -timeout=5m
go test -run=TestUltraPerformanceMiddleware -v -timeout=5m

# 运行负载测试（可选）
if [ "$1" = "--load-test" ]; then
    echo ""
    echo "🔥 运行负载测试..."
    echo "=================="
    
    go test -run=TestComprehensiveLoadTest -v -timeout=30m
    
    echo ""
    echo "🔍 运行内存泄漏检测..."
    echo "======================"
    
    go test -run=TestMemoryLeakDetection -v -timeout=30m
fi

# 启动演示服务器（可选）
if [ "$1" = "--demo" ]; then
    echo ""
    echo "🖥️  启动演示服务器..."
    echo "====================="
    
    echo "正在编译演示服务器..."
    go build -o demo_server demo_server.go
    
    echo "启动服务器在端口 8080..."
    echo "演示页面: http://localhost:8080/demo"
    echo "按 Ctrl+C 停止服务器"
    
    ./demo_server 8080
fi

echo ""
echo "✅ 性能验证完成!"
echo ""
echo "📈 预期性能指标:"
echo "• JWT验证延迟: <50μs (vs 原始150μs)"
echo "• 内存分配: <5次/请求 (vs 原始15次/请求)" 
echo "• 并发QPS: >10,000 (vs 原始2,000)"
echo "• P99延迟: <500μs (vs 原始2ms)"
echo "• 缓存命中率: >95%"
echo ""
echo "如果测试结果未达到预期，请检查:"
echo "1. 系统资源是否充足"
echo "2. Go版本是否为1.19+"
echo "3. 是否有其他程序占用CPU/内存"
echo ""
echo "运行选项:"
echo "  ./validate_performance.sh              # 基础性能测试"
echo "  ./validate_performance.sh --load-test  # 包含负载测试"
echo "  ./validate_performance.sh --demo       # 启动演示服务器"