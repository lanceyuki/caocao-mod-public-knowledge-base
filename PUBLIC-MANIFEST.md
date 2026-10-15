# 公共候选包文件清单

本清单定义候选包的内容边界。清单内由维护者原创且有权授权的文档、skill 文字、评估样例、工具参考脚本和本清单本身，适用 [LICENSE.md](./LICENSE.md) 所列自定义非商业许可；商业用途一律禁止。第三方材料与外部链接目标不因此纳入本许可或候选文件。

| 文件 | 内容 | 证据／发布说明 |
|---|---|---|
| `00-方法论/README.md` | 二进制引擎开发方法总览 | 串联行为契约、调用链分析、改动设计、分层验证、证据记录，以及从项目记录提炼公共知识并用清单和更新日志复核的方法；不增加目标专属地址或实现 |
| `02-数据结构/object-identifiers-and-records.md` | 对象类型与编号转换 | 区分战术单位、角色数据、Data 记录和调用帧局部值；样本地址与步长仅作定位线索 |
| `README.md` | 适用范围、许可说明和目录导航 | 含 6.5pl 样本范围声明、非商业互引规则，并明确允许非商业克隆和 Fork；不代表跨引擎验证 |
| `CHANGELOG.md` | 候选包内容更新记录 | 只记公开知识内容，不记项目内部进度 |
| `PUBLIC-MANIFEST.md` | 本文件 | 逐项限定发布内容 |
| `LICENSE.md` | 自定义非商业许可 | 明确允许非商业克隆/Fork、许可范围、署名要求、禁止的商业使用和第三方材料边界；不对应标准 SPDX 标识 |
| `01-核心引擎/core-engine.md` | 特技判定路径与返回值 | 单一样本的静态调用关系；地址仅作线索 |
| `01-核心引擎/stub-function.md` | 桩函数参数追踪方法 | 使用占位符示意，不提供可直接应用的补丁 |
| `01-核心引擎/dispatcher-function.md` | 调度和预检分支分析方法 | 样本静态控制流；不外推返回值语义 |
| `03-机制详解/attack-side-value-and-mp.md` | 普通物理路径中的攻击侧值与 MP 加成 | 单一样本的属性读取、候选加成和局部结果消费者；不提供完整伤害公式 |
| `03-机制详解/anomaly-status-groups.md` | 异常状态组字段与恢复阶段 | 静态读写链；精确画面回合数未确认 |
| `03-机制详解/critical-check-marker.md` | 暴击检定通过标记 | 静态概率与目标响应路径；事务区地址仅限样本定位，最终效果未做游戏内验收 |
| `05-教程指南/win32-control-tracing.md` | Win32 控件输入与文本刷新分析方法 | 引用 Microsoft Learn；不含特定引擎地址或运行记录 |
| `06-可复用Skills/engine-feature-development/SKILL.md` | 二进制引擎功能开发与移植工作流 | 通用方法；不含本地环境配置或目标文件指纹 |
| `06-可复用Skills/engine-feature-development/references/reverse-engineering-pitfalls.md` | 通用逆向与补丁教训 | 不含项目地址表或代码洞占用表 |
| `06-可复用Skills/engine-feature-development/evals/trigger-evals.json` | skill 触发范围评估样例 | 只用于说明何时应使用该 skill，不是行为验收结果 |
| `06-可复用Skills/x32dbg-debugging/SKILL.md` | x32dbg/x64dbg 通用动态调试指南 | 不含目标专属地址、数据布局、补丁分配或本地环境配置；引用官方文档 |
| `06-可复用Skills/x32dbg-debugging/evals/evals.json` | 动态调试 skill 的评估提示 | 待运行场景；不代表独立行为评估已经完成 |
| `07-工具参考/stub-scanner-reference/README.md` | 特技桩扫描器参考说明 | 明示可在非商业许可下克隆并自行适配；需用户填写配置并复核结果，不承诺跨版本直接运行 |
| `07-工具参考/stub-scanner-reference/scan_engine.py` | 扫描器命令行入口 | 只读调用扫描模块；输出候选记录，不写入输入引擎 |
| `07-工具参考/stub-scanner-reference/profile.example.json` | 用户配置模板 | 字段为空，不含目标地址；由使用者针对自己的文件填写 |
| `07-工具参考/stub-scanner-reference/requirements.txt` | 扫描器依赖声明 | 仅声明 Capstone 依赖，不含构建工具或完整 Toolbox 依赖 |
| `07-工具参考/stub-scanner-reference/core/__init__.py` | Python 模块入口 | 空文件 |
| `07-工具参考/stub-scanner-reference/core/pe.py` | PE32 文件读取辅助模块 | 读取 PE32/x86 头和节表；不提取或附带引擎内容 |
| `07-工具参考/stub-scanner-reference/core/stub_scan.py` | 调用目标与桩参数候选扫描 | 固定目标改为用户配置；省略依赖私有位置的源码定义/代码洞格式；保留样本启发式和误报、漏报限制 |
| `07-工具参考/stub-scanner-reference/core/arg_stub.py` | 配置循环桩范围分析 | 由调用者传入目标地址；结果是静态候选范围，需对照目标反汇编确认 |

## 明确排除

- 维护审计、内部更新记录、memory、开发时间线和私人工作过程。
- 完整引擎、完整引擎源码或映像、引擎压缩包，以及引擎附带或提取的图像、音频、字体、界面、场景等资产。
- 项目专属地址表、代码洞清单、补丁/特技编号占用表、内部文件哈希、本地路径和私有构建标识。工具参考脚本不含预填的目标地址；用户自己的适配配置应单独保存，不属于本包。
- 未列入本清单的任何其他仓库文件。
