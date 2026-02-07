#!/bin/bash

# CloudPhoneRiskKit 测试运行脚本
# 用途：运行所有单元测试并生成覆盖率报告

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 项目根目录
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTS_DIR="$PROJECT_ROOT/Tests/CloudPhoneRiskKitTests"

echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}    CloudPhoneRiskKit 单元测试套件${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""

# 检查 swift 是否可用
if ! command -v swift &> /dev/null; then
    echo -e "${RED}错误: Swift 未安装或不在 PATH 中${NC}"
    echo "请确保已安装 Xcode Command Line Tools"
    exit 1
fi

# 解析命令行参数
VERBOSE=false
COVERAGE=false
RUN_XCODE_BUILD=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -c|--coverage)
            COVERAGE=true
            shift
            ;;
        -x|--xcode)
            RUN_XCODE_BUILD=true
            shift
            ;;
        -h|--help)
            echo "用法: $0 [选项]"
            echo ""
            echo "选项:"
            echo "  -v, --verbose      显示详细输出"
            echo "  -c, --coverage     生成代码覆盖率报告"
            echo "  -x, --xcode        使用 xcodebuild 运行测试"
            echo "  -h, --help         显示此帮助信息"
            exit 0
            ;;
        *)
            echo -e "${RED}未知选项: $1${NC}"
            exit 1
            ;;
    esac
done

# 统计测试文件
TEST_FILES=(
    "ProviderTests.swift"
    "RiskScoringTests.swift"
    "DeviceAgeProviderTests.swift"
    "NetworkSignalsJSONTests.swift"
    "RiskHistoryStoreTests.swift"
    "BehaviorCouplingTests.swift"
    "FileDetectorTests.swift"
    "HookDetectorTests.swift"
    "DecisionEngineTests.swift"
    "TemporalAnalysisTests.swift"
)

echo -e "${GREEN}测试文件列表:${NC}"
for file in "${TEST_FILES[@]}"; do
    if [ -f "$TESTS_DIR/$file" ]; then
        echo -e "  ${GREEN}✓${NC} $file"
    else
        echo -e "  ${RED}✗${NC} $file (未找到)"
    fi
done
echo ""

# 如果使用 xcodebuild
if [ "$RUN_XCODE_BUILD" = true ]; then
    echo -e "${BLUE}使用 xcodebuild 运行测试...${NC}"
    
    # 查找项目或工作空间文件
    PROJECT_FILE=$(find "$PROJECT_ROOT" -name "*.xcodeproj" -maxdepth 1 | head -n 1)
    WORKSPACE_FILE=$(find "$PROJECT_ROOT" -name "*.xcworkspace" -maxdepth 1 | head -n 1)
    
    BUILD_CMD="xcodebuild test"
    
    if [ -n "$WORKSPACE_FILE" ]; then
        BUILD_CMD="$BUILD_CMD -workspace $(basename "$WORKSPACE_FILE")"
    elif [ -n "$PROJECT_FILE" ]; then
        BUILD_CMD="$BUILD_CMD -project $(basename "$PROJECT_FILE")"
    else
        echo -e "${RED}错误: 未找到 Xcode 项目文件${NC}"
        exit 1
    fi
    
    BUILD_CMD="$BUILD_CMD -scheme CloudPhoneRiskKit -destination 'platform=iOS Simulator,name=iPhone 15'"
    
    if [ "$COVERAGE" = true ]; then
        BUILD_CMD="$BUILD_CMD -enableCodeCoverage YES"
    fi
    
    if [ "$VERBOSE" = true ]; then
        BUILD_CMD="$BUILD_CMD -verbose"
    fi
    
    eval $BUILD_CMD
    exit $?
fi

# 使用 Swift Package Manager 运行测试
echo -e "${BLUE}使用 Swift Package Manager 运行测试...${NC}"
echo ""

cd "$PROJECT_ROOT"

SWIFT_TEST_CMD="swift test"

if [ "$VERBOSE" = true ]; then
    SWIFT_TEST_CMD="$SWIFT_TEST_CMD --verbose"
fi

run_swift_test_with_fallback() {
    local cmd="$1"
    local output
    local status

    set +e
    output=$(eval "$cmd" 2>&1)
    status=$?
    set -e
    echo "$output"

    if [ $status -ne 0 ] && [[ "$output" == *"sandbox-exec: sandbox_apply: Operation not permitted"* ]]; then
        local fallback_cmd="$cmd --disable-sandbox"
        echo ""
        echo -e "${YELLOW}检测到受限沙箱环境，自动重试: $fallback_cmd${NC}"
        echo ""

        set +e
        output=$(eval "$fallback_cmd" 2>&1)
        status=$?
        set -e
        echo "$output"
    fi

    return $status
}

echo -e "${YELLOW}执行: $SWIFT_TEST_CMD${NC}"
echo ""

# 运行测试
if run_swift_test_with_fallback "$SWIFT_TEST_CMD"; then
    echo ""
    echo -e "${GREEN}================================================${NC}"
    echo -e "${GREEN}    ✓ 所有测试通过！${NC}"
    echo -e "${GREEN}================================================${NC}"
    
    # 显示测试统计
    echo ""
    echo -e "${BLUE}测试统计:${NC}"
    echo "  总测试文件: ${#TEST_FILES[@]}"
    echo "  状态: 全部通过"
    
    exit 0
else
    echo ""
    echo -e "${RED}================================================${NC}"
    echo -e "${RED}    ✗ 测试失败${NC}"
    echo -e "${RED}================================================${NC}"
    echo ""
    echo -e "${YELLOW}提示: 使用 -v 参数查看详细输出${NC}"
    
    exit 1
fi
