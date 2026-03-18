# Protected Release / Hikari 接入说明

本目录下的脚本实现的是一套**可选启用**的 Release 构建加固接入口，目标是：

- 默认不改变本地 Debug / 常规 Release 构建行为；
- 在显式开启时，给 Swift 目标增加真实可用的 metadata 收敛开关；
- 为 `CRiskCore` 的 Clang 编译和 Swift 目标预留 Hikari / 自定义编译器 wrapper 接入点；
- 缺少 Hikari toolchain 时打印 warning，并自动回退到系统 `swiftc` / `clang`。

## 环境变量

- `CPRISK_ENABLE_SWIFT_METADATA_CONVERGENCE=1`
  - 仅在 Release 生效。
  - 通过 `cprisk-swiftc-wrapper.sh` 为 Swift 目标追加：
    - `-Xfrontend -disable-reflection-metadata`
    - `-Xfrontend -disable-reflection-names`
  - 这会减少运行时反射元数据暴露，但可能影响依赖 `Mirror` 或字段名反射的代码。

- `CPRISK_ENABLE_HIKARI=1`
  - 仅在 Release 生效。
  - Xcode/XcodeGen 工程会尝试把：
    - Swift 目标切到 `HIKARI_SWIFTC`
    - `CRiskCore` 切到 `HIKARI_CLANG`
  - 若环境变量缺失或路径不可执行，脚本只打印 warning，不阻断构建。

- `HIKARI_SWIFTC=/path/to/custom-swiftc-or-wrapper`
  - 给 Swift 目标使用的自定义 `swiftc` / wrapper。

- `HIKARI_CLANG=/path/to/custom-clang-or-wrapper`
  - 给 `CRiskCore` 使用的自定义 `clang` / wrapper。

- `CPRISK_ARMOR_KEY=<64-char-hex>`
  - 继续用于 Release 末尾的 `cprisk-armor` 后处理。

## Xcode / XcodeGen

Release 时：

- `CloudPhoneRiskKit` / `CloudPhoneRiskAppCore` / `RiskDetectorApp` 使用 `cprisk-swiftc-wrapper.sh`
- `CRiskCore` 使用 `cprisk-clang-wrapper.sh`
- `RiskDetectorApp` 的 post-build 阶段使用 `cprisk-release-postbuild.sh`

示例：

```bash
export CPRISK_ENABLE_SWIFT_METADATA_CONVERGENCE=1
export CPRISK_ENABLE_HIKARI=1
export HIKARI_SWIFTC=/opt/hikari/bin/swiftc-wrapper
export HIKARI_CLANG=/opt/hikari/bin/clang-wrapper
export CPRISK_ARMOR_KEY=<64-char-hex>
export CPRISKKIT_ARMOR_ROOT_KEY_HEX="$CPRISK_ARMOR_KEY"
```

如果只想启用 Swift metadata 收敛，不启用 Hikari：

```bash
export CPRISK_ENABLE_SWIFT_METADATA_CONVERGENCE=1
unset CPRISK_ENABLE_HIKARI
unset HIKARI_SWIFTC
unset HIKARI_CLANG
```

## SwiftPM / Package.swift

`Package.swift` 当前能真实做到的有两点：

- 当 `CPRISK_ENABLE_SWIFT_METADATA_CONVERGENCE=1` 时，对 `CloudPhoneRiskKit` / `CloudPhoneRiskAppCore` 的 Release 构建追加同样的 Swift 前端 flag；
- 当 `CPRISK_ENABLE_HIKARI=1` 但没有通过 `SWIFT_EXEC` / `CC` 显式接入自定义编译器时，给出 warning，提示用户如何接入。

SwiftPM 不会自动消费 `HIKARI_SWIFTC` / `HIKARI_CLANG`，因此需要显式导出：

```bash
export CPRISK_ENABLE_HIKARI=1
export HIKARI_SWIFTC=/opt/hikari/bin/swiftc-wrapper
export HIKARI_CLANG=/opt/hikari/bin/clang-wrapper
export SWIFT_EXEC="$HIKARI_SWIFTC"
export CC="$HIKARI_CLANG"
swift build -c release
```

## 技术边界

- 这不是商业级的 Swift metadata obfuscation；它做的是**真实可落地的元数据收敛与编译接入口**。
- 对纯 Swift 代码，Hikari 是否真的生效，取决于你提供的自定义 `swiftc` / wrapper 能力；工程现在只负责“检测并接上，否则安全回退”。
- 对 `CRiskCore` 这类 C/ObjC/Clang 侧目标，`HIKARI_CLANG` 接入点是直接可用的。
