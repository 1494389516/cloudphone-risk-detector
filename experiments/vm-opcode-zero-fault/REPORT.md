# 零 fault mask 的 opcode 扰动修复

基线：`d07b76404e19cd3dffd790fae55158c329d164c0`（阶段 2A 远端提交）。
其 Git tree 与本地原提交 `263d0fd4945925e20421324ebaa4d7f97b1b5aab` 完全一致。

`cprisk_vmp_opcode_fault_byte_i` 在检查零值前先把 fault mask 与
`OPCODEFJ` 域常量异或，导致下层 dispatch helper 看不到“无故障”的零值。
本次在域混合前增加零值返回，生产代码仅增加此判断及说明。
非零 mask 的既有计算保持不变，包括 mask 恰好等于域常量时的结果。

这是独立的语义修复，不属于阶段 2A 的逐位等价提取。未改变 Loop A/B、
handler 返回方式、CPSV、ABI 或调用顺序；未进入阶段 2B。

## 验证

Linux x86_64，GCC 13.3.0，`-O2`。使用真实解释器、handler 和循环，复用
阶段 2A 的确定性平台替身。比较结果见 `evidence/report.json`。

| 检查 | 修复前 | 修复后 |
| --- | --- | --- |
| 零 mask：4 个函数 ID × 5 个 PC × 256 个 opcode | 5107 / 5120 失败 | 0 / 5120 失败 |
| NOP → HALT：lane 0/1/2 × opcode 加密开/关 | 6 / 6 失败 | 0 / 6 失败 |
| 非零 mask：上述组合 × 5 个 mask | 25600 个输出字节 | 逐字节完全一致 |

执行用例检查成功状态、零 poison、2 个 steps、最终 HALT 类及原始 opcode。
加密字节码使用独立的 producer 混合公式构造，没有按故障 decoder 反推输入。
非零 mask 包括 1、2、UINT64_MAX、域常量本身及固定混合值；结果并非断言
每个故障字节非零，而是逐字节验证已有注入行为没有变化。

复现：

```sh
python experiments/vm-opcode-zero-fault/run.py --cc gcc --output /tmp/vm-opcode-regression
```

脚本固定提取修复前解释器，分别编译它与工作树版本。平台依赖来自
`vm-post-handler-2a/harness.c`，不执行其旧 fixture。输出目录包含两个
可执行文件、输入源、非零 mask 的完整二进制输出和 JSON 报告。

阶段 2A 的历史等价证据仍对应其原提交；本修复有意改变正常解码行为，不能
把它冒充为与旧缺陷逐位等价。当前环境未提供 Apple SDK/Xcode，未完成
Apple ARM64 Release 验证或 evaluate() P95 测量，本报告不声称这些验收通过。
