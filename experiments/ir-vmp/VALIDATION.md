# 本轮验证记录

日期：2026-10-01。环境：Linux，GCC 13.3.0；无 clang/opt/Xcode/iPhone。

| 验证 | 结果 | 可得结论 |
| --- | --- | --- |
| `python3 -m unittest discover -s experiments/ir-vmp -p 'test_*.py' -v` | 6 项通过 | 版本、provenance、逐函数报告、IR 结构、旧成功报告覆盖的门禁行为通过合成用例 |
| `run.py --mode baseline-only --cc cc` | `BASELINE_ONLY_PASS`；4,096 例 | GF2 原生/原生差分与已知答案通过 |
| `run.py --mode baseline-only --suite stack --cc cc` | `BASELINE_ONLY_PASS`；4,155 例 | 栈操作原生/原生差分通过 |
| `run.py --mode xollvm` | `BLOCKED_OR_FAILED`；缺少 clang | 未执行上游插件，`vmp_verified=false` |
| `verify_sources.py` | 通过 | 实验提取函数与固定 SDK 源码一致 |

没有对真实 xollvm 输出运行过结构门禁；合成测试不能代替该验收。没有生成已通过的 `HOST_VMP_PASS`，没有测定 VMP 性能、代码膨胀、抗逆向强度或 iOS 兼容性。默认 annotation 关闭字节码加密和额外加固，仅供正确性实验。

SDK 生产文件未修改。`full` 替换的既有阻断保持不变，当前改动不修复 Pass 13 的原生参数/返回/指令语义缺口。CI 仅运行未保护 baseline 和门禁测试，不构建或运行第三方插件。
