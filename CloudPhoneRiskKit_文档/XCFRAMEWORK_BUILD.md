# CloudPhoneRiskKit XCFramework 构建指南

> 本文档详细描述如何将 CloudPhoneRiskKit 编译为 XCFramework 产物并完成签名、符号剥离与分发打包。

---

## 目录

1. [前置条件](#前置条件)
2. [构建目标矩阵](#构建目标矩阵)
3. [分步构建命令](#分步构建命令)
4. [创建 XCFramework](#创建-xcframework)
5. [代码签名](#代码签名)
6. [调试符号处理](#调试符号处理)
7. [分发打包](#分发打包)
8. [CI/CD 集成（GitHub Actions）](#cicd-集成github-actions)
9. [常见问题排查](#常见问题排查)

---

## 前置条件

| 依赖 | 最低版本 | 说明 |
|------|---------|------|
| Xcode | 15.0+ | 需支持 Swift 5.9 |
| macOS | 14.0+ (Sonoma) | Xcode 15 最低系统要求 |
| iOS Deployment Target | 14.0 | SDK 最低支持版本 |
| swift-tools-version | 5.9 | Package.swift 声明 |

确认开发环境：

```bash
xcodebuild -version
# Xcode 15.x / Build version 15xxx
swift --version
# swift-driver version 1.87.x / Apple Swift version 5.9.x
xcrun --sdk iphoneos --show-sdk-path
```

---

## 构建目标矩阵

| 平台 | SDK | 架构 | 用途 |
|------|-----|------|------|
| iOS 真机 | `iphoneos` | `arm64` | App Store / 企业分发 |
| iOS 模拟器 | `iphonesimulator` | `arm64,x86_64` | 开发 & 测试 |
| macOS (Catalyst) | `macosx` | `arm64,x86_64` | Mac Catalyst 应用（可选） |

---

## 分步构建命令

以下命令均从仓库根目录执行。

### 环境变量

```bash
export PROJECT_DIR="$(pwd)/RiskDetectorApp"
export SCHEME="CloudPhoneRiskKit"
export CONFIGURATION="Release"
export DERIVED_DATA="$(pwd)/.deriveddata-xcframework"
export ARCHIVE_DIR="$(pwd)/.archives"
export OUTPUT_DIR="$(pwd)/output"
mkdir -p "$ARCHIVE_DIR" "$OUTPUT_DIR"
```

### Step 1: 构建 iOS 真机 Archive

```bash
xcodebuild archive \
  -project "$PROJECT_DIR/RiskDetectorApp.xcodeproj" \
  -scheme "$SCHEME" \
  -configuration "$CONFIGURATION" \
  -destination "generic/platform=iOS" \
  -archivePath "$ARCHIVE_DIR/CloudPhoneRiskKit-iphoneos.xcarchive" \
  -derivedDataPath "$DERIVED_DATA" \
  SKIP_INSTALL=NO \
  BUILD_LIBRARY_FOR_DISTRIBUTION=YES \
  CODE_SIGNING_ALLOWED=NO \
  SWIFT_EMIT_MODULE_INTERFACE=YES
```

### Step 2: 构建 iOS 模拟器 Archive

```bash
xcodebuild archive \
  -project "$PROJECT_DIR/RiskDetectorApp.xcodeproj" \
  -scheme "$SCHEME" \
  -configuration "$CONFIGURATION" \
  -destination "generic/platform=iOS Simulator" \
  -archivePath "$ARCHIVE_DIR/CloudPhoneRiskKit-iphonesimulator.xcarchive" \
  -derivedDataPath "$DERIVED_DATA" \
  SKIP_INSTALL=NO \
  BUILD_LIBRARY_FOR_DISTRIBUTION=YES \
  CODE_SIGNING_ALLOWED=NO \
  SWIFT_EMIT_MODULE_INTERFACE=YES
```

### Step 3: 构建 macOS Archive（可选，用于 Catalyst）

```bash
xcodebuild archive \
  -project "$PROJECT_DIR/RiskDetectorApp.xcodeproj" \
  -scheme "$SCHEME" \
  -configuration "$CONFIGURATION" \
  -destination "generic/platform=macOS" \
  -archivePath "$ARCHIVE_DIR/CloudPhoneRiskKit-macos.xcarchive" \
  -derivedDataPath "$DERIVED_DATA" \
  SKIP_INSTALL=NO \
  BUILD_LIBRARY_FOR_DISTRIBUTION=YES \
  CODE_SIGNING_ALLOWED=NO \
  SWIFT_EMIT_MODULE_INTERFACE=YES
```

> **注意**：`BUILD_LIBRARY_FOR_DISTRIBUTION=YES` 开启 Module Stability，确保编译产物可跨 Swift 版本使用。`SWIFT_EMIT_MODULE_INTERFACE=YES` 生成 `.swiftinterface` 文件。

---

## 创建 XCFramework

### 仅 iOS（真机 + 模拟器）

```bash
xcodebuild -create-xcframework \
  -framework "$ARCHIVE_DIR/CloudPhoneRiskKit-iphoneos.xcarchive/Products/Library/Frameworks/CloudPhoneRiskKit.framework" \
  -debug-symbols "$ARCHIVE_DIR/CloudPhoneRiskKit-iphoneos.xcarchive/dSYMs/CloudPhoneRiskKit.framework.dSYM" \
  -framework "$ARCHIVE_DIR/CloudPhoneRiskKit-iphonesimulator.xcarchive/Products/Library/Frameworks/CloudPhoneRiskKit.framework" \
  -debug-symbols "$ARCHIVE_DIR/CloudPhoneRiskKit-iphonesimulator.xcarchive/dSYMs/CloudPhoneRiskKit.framework.dSYM" \
  -output "$OUTPUT_DIR/CloudPhoneRiskKit.xcframework"
```

### iOS + macOS（含 Catalyst）

```bash
xcodebuild -create-xcframework \
  -framework "$ARCHIVE_DIR/CloudPhoneRiskKit-iphoneos.xcarchive/Products/Library/Frameworks/CloudPhoneRiskKit.framework" \
  -debug-symbols "$ARCHIVE_DIR/CloudPhoneRiskKit-iphoneos.xcarchive/dSYMs/CloudPhoneRiskKit.framework.dSYM" \
  -framework "$ARCHIVE_DIR/CloudPhoneRiskKit-iphonesimulator.xcarchive/Products/Library/Frameworks/CloudPhoneRiskKit.framework" \
  -debug-symbols "$ARCHIVE_DIR/CloudPhoneRiskKit-iphonesimulator.xcarchive/dSYMs/CloudPhoneRiskKit.framework.dSYM" \
  -framework "$ARCHIVE_DIR/CloudPhoneRiskKit-macos.xcarchive/Products/Library/Frameworks/CloudPhoneRiskKit.framework" \
  -debug-symbols "$ARCHIVE_DIR/CloudPhoneRiskKit-macos.xcarchive/dSYMs/CloudPhoneRiskKit.framework.dSYM" \
  -output "$OUTPUT_DIR/CloudPhoneRiskKit.xcframework"
```

### 验证产物结构

```bash
ls -la "$OUTPUT_DIR/CloudPhoneRiskKit.xcframework/"
# 应包含：
#   Info.plist
#   ios-arm64/
#   ios-arm64_x86_64-simulator/
#   (macos-arm64_x86_64/)  — 若包含 macOS
```

---

## 代码签名

### 对 XCFramework 签名（分发前）

```bash
codesign --timestamp --sign "Apple Distribution: YourTeamName (TEAM_ID)" \
  "$OUTPUT_DIR/CloudPhoneRiskKit.xcframework"
```

### 验证签名

```bash
codesign --verify --deep --strict --verbose=2 \
  "$OUTPUT_DIR/CloudPhoneRiskKit.xcframework"
```

### 对内嵌 Framework 逐个签名（如需更精细控制）

```bash
for fw in "$OUTPUT_DIR/CloudPhoneRiskKit.xcframework"/*/CloudPhoneRiskKit.framework; do
  codesign --timestamp --sign "Apple Distribution: YourTeamName (TEAM_ID)" "$fw"
done
```

---

## 调试符号处理

### 保留 dSYM（用于崩溃解析）

dSYM 文件在 archive 阶段自动生成，路径为：

```
$ARCHIVE_DIR/CloudPhoneRiskKit-iphoneos.xcarchive/dSYMs/CloudPhoneRiskKit.framework.dSYM
```

将其与 XCFramework 一同分发，或上传至符号服务器。

### 剥离 Release 二进制中的调试符号

```bash
# 剥离非导出符号（保留 dynamic linker 需要的符号）
xcrun strip -x "$OUTPUT_DIR/CloudPhoneRiskKit.xcframework/ios-arm64/CloudPhoneRiskKit.framework/CloudPhoneRiskKit"

# 全量剥离（仅适用于 static library 场景）
xcrun strip -S "$OUTPUT_DIR/CloudPhoneRiskKit.xcframework/ios-arm64/CloudPhoneRiskKit.framework/CloudPhoneRiskKit"
```

### cprisk-armor 加固后的符号剥离

若使用 `cprisk-armor` 壳保护，在壳加固完成后执行全量 strip：

```bash
xcrun strip -x "$APP_BINARY"
xcrun strip "$APP_BINARY"
# 加固后 IDA 中所有 SDK 函数显示为 sub_XXXX
```

---

## 分发打包

### 压缩为 zip（SPM Binary Target 兼容格式）

```bash
cd "$OUTPUT_DIR"
zip -ry CloudPhoneRiskKit.xcframework.zip CloudPhoneRiskKit.xcframework
shasum -a 256 CloudPhoneRiskKit.xcframework.zip
# 记录 checksum，用于 Package.swift 中的 binaryTarget 声明
```

### 目录结构参考

```
output/
├── CloudPhoneRiskKit.xcframework/
│   ├── Info.plist
│   ├── ios-arm64/
│   │   └── CloudPhoneRiskKit.framework/
│   │       ├── CloudPhoneRiskKit            (二进制)
│   │       ├── Headers/
│   │       ├── Modules/
│   │       │   ├── CloudPhoneRiskKit.swiftmodule/
│   │       │   └── module.modulemap
│   │       └── Info.plist
│   └── ios-arm64_x86_64-simulator/
│       └── CloudPhoneRiskKit.framework/
│           └── ...
├── CloudPhoneRiskKit.xcframework.zip        (SPM binary target 分发)
├── dSYMs/
│   ├── CloudPhoneRiskKit-iphoneos.dSYM
│   └── CloudPhoneRiskKit-iphonesimulator.dSYM
└── CHECKSUM.txt
```

---

## CI/CD 集成（GitHub Actions）

以下为完整的 GitHub Actions workflow 示例，在推送 tag 时自动构建 XCFramework 并创建 Release：

```yaml
# .github/workflows/build-xcframework.yml
name: Build XCFramework

on:
  push:
    tags:
      - 'v*'
  workflow_dispatch:
    inputs:
      configuration:
        description: 'Build configuration'
        required: false
        default: 'Release'
        type: choice
        options:
          - Release
          - Debug

env:
  SCHEME: CloudPhoneRiskKit
  PROJECT_PATH: RiskDetectorApp/RiskDetectorApp.xcodeproj
  CONFIGURATION: ${{ github.event.inputs.configuration || 'Release' }}

jobs:
  build-xcframework:
    runs-on: macos-14
    timeout-minutes: 30

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Select Xcode
        run: sudo xcode-select -s /Applications/Xcode_15.4.app

      - name: Show Build Environment
        run: |
          xcodebuild -version
          swift --version
          echo "Tag: ${{ github.ref_name }}"

      - name: Archive iOS Device
        run: |
          xcodebuild archive \
            -project "$PROJECT_PATH" \
            -scheme "$SCHEME" \
            -configuration "$CONFIGURATION" \
            -destination "generic/platform=iOS" \
            -archivePath ".archives/CloudPhoneRiskKit-iphoneos.xcarchive" \
            SKIP_INSTALL=NO \
            BUILD_LIBRARY_FOR_DISTRIBUTION=YES \
            CODE_SIGNING_ALLOWED=NO \
            SWIFT_EMIT_MODULE_INTERFACE=YES

      - name: Archive iOS Simulator
        run: |
          xcodebuild archive \
            -project "$PROJECT_PATH" \
            -scheme "$SCHEME" \
            -configuration "$CONFIGURATION" \
            -destination "generic/platform=iOS Simulator" \
            -archivePath ".archives/CloudPhoneRiskKit-iphonesimulator.xcarchive" \
            SKIP_INSTALL=NO \
            BUILD_LIBRARY_FOR_DISTRIBUTION=YES \
            CODE_SIGNING_ALLOWED=NO \
            SWIFT_EMIT_MODULE_INTERFACE=YES

      - name: Create XCFramework
        run: |
          mkdir -p output
          xcodebuild -create-xcframework \
            -framework ".archives/CloudPhoneRiskKit-iphoneos.xcarchive/Products/Library/Frameworks/CloudPhoneRiskKit.framework" \
            -debug-symbols "$(pwd)/.archives/CloudPhoneRiskKit-iphoneos.xcarchive/dSYMs/CloudPhoneRiskKit.framework.dSYM" \
            -framework ".archives/CloudPhoneRiskKit-iphonesimulator.xcarchive/Products/Library/Frameworks/CloudPhoneRiskKit.framework" \
            -debug-symbols "$(pwd)/.archives/CloudPhoneRiskKit-iphonesimulator.xcarchive/dSYMs/CloudPhoneRiskKit.framework.dSYM" \
            -output "output/CloudPhoneRiskKit.xcframework"

      - name: Strip Debug Symbols
        run: |
          for fw in output/CloudPhoneRiskKit.xcframework/*/CloudPhoneRiskKit.framework/CloudPhoneRiskKit; do
            xcrun strip -x "$fw"
          done

      - name: Package for Distribution
        run: |
          cd output
          zip -ry CloudPhoneRiskKit.xcframework.zip CloudPhoneRiskKit.xcframework
          shasum -a 256 CloudPhoneRiskKit.xcframework.zip > CHECKSUM.txt
          cat CHECKSUM.txt

      - name: Collect dSYMs
        run: |
          mkdir -p output/dSYMs
          cp -R .archives/CloudPhoneRiskKit-iphoneos.xcarchive/dSYMs/*.dSYM output/dSYMs/ || true
          cp -R .archives/CloudPhoneRiskKit-iphonesimulator.xcarchive/dSYMs/*.dSYM output/dSYMs/ || true
          cd output/dSYMs && zip -ry ../dSYMs.zip . && cd ../..

      - name: Upload Artifacts
        uses: actions/upload-artifact@v4
        with:
          name: CloudPhoneRiskKit-${{ github.ref_name }}
          path: |
            output/CloudPhoneRiskKit.xcframework.zip
            output/dSYMs.zip
            output/CHECKSUM.txt
          retention-days: 90

      - name: Create GitHub Release
        if: startsWith(github.ref, 'refs/tags/v')
        uses: softprops/action-gh-release@v2
        with:
          files: |
            output/CloudPhoneRiskKit.xcframework.zip
            output/dSYMs.zip
            output/CHECKSUM.txt
          body: |
            ## CloudPhoneRiskKit ${{ github.ref_name }}

            ### 产物
            - `CloudPhoneRiskKit.xcframework.zip` — XCFramework (iOS device + simulator)
            - `dSYMs.zip` — 调试符号
            - `CHECKSUM.txt` — SHA-256 校验和

            ### 校验
            ```bash
            shasum -a 256 -c CHECKSUM.txt
            ```
          generate_release_notes: true
```

### CI 验证检查点

| 步骤 | 验证方式 |
|------|---------|
| Archive 完成 | `$ARCHIVE_DIR/*.xcarchive/Products/` 下存在 framework |
| XCFramework 生成 | `Info.plist` 中包含所有目标平台 |
| 符号剥离 | `nm <binary> \| wc -l` 应显著减少 |
| zip 完整性 | `unzip -t` 验证 |
| checksum | `shasum -a 256 -c CHECKSUM.txt` 通过 |

---

## 常见问题排查

### Q: `BUILD_LIBRARY_FOR_DISTRIBUTION` 导致编译错误

**原因**：Module Stability 要求所有 public API 必须是可序列化的 Swift Interface。若使用了无法表示的语法（如某些 property wrapper），需要调整接口。

**解决**：检查编译日志中的 `.swiftinterface` 生成错误，调整 public API 签名。

### Q: 模拟器 Archive 找不到 framework

**原因**：`SKIP_INSTALL=NO` 未设置，产物没有安装到 Archive 的 Products 目录。

**解决**：确保所有 archive 命令都包含 `SKIP_INSTALL=NO`。

### Q: `xcodebuild -create-xcframework` 报 "duplicate architecture"

**原因**：iOS 模拟器同时包含 arm64 和 x86_64，与 iOS 真机的 arm64 冲突。

**解决**：确保使用 `generic/platform=iOS` 和 `generic/platform=iOS Simulator` 作为 destination，xcodebuild 会自动处理架构分离。

### Q: codesign 报 "identity not found"

**原因**：Keychain 中没有对应的签名证书。

**解决**：
```bash
security find-identity -v -p codesigning
# 确认证书存在并使用正确的 identity 字符串
```

### Q: CI 环境下 CRiskCore C 模块编译失败

**原因**：CI runner 的 SDK 版本可能与本地不同，`cprisk_mte_guard` 等 MTE 相关代码需要 iPhoneOS 26+ SDK。

**解决**：在 CI workflow 中明确指定 Xcode 版本（`sudo xcode-select -s`），确保与开发环境一致。
