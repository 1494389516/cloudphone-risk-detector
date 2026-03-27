# CloudPhoneRiskKit SDK Portal 设计规范

> 版本: 1.0 | 日期: 2026-03-27

---

## 目录

1. [概述](#1-概述)
2. [系统架构](#2-系统架构)
3. [功能模块](#3-功能模块)
4. [Portal 后端 API 设计](#4-portal-后端-api-设计)
5. [关键页面线框描述](#5-关键页面线框描述)
6. [数据模型](#6-数据模型)
7. [部署架构](#7-部署架构)
8. [安全设计](#8-安全设计)
9. [扩展规划](#9-扩展规划)

---

## 1. 概述

### 1.1 定位

SDK Portal 是 CloudPhoneRiskKit 的管理控制台，为 SDK 的接入方、运营方和管理方提供：

- **远程配置管理**：在线修改检测策略、阈值、开关，无需客户端发版
- **实时监控看板**：设备风险分布、检测精度、性能指标的实时可视化
- **密钥管理**：多租户密钥的生命周期管理（创建、轮换、撤销）
- **租户管理**：租户注册、权限分配、接入审批与配额管理

### 1.2 目标用户

| 角色 | 典型操作 |
|------|---------|
| **SDK 管理员** | 配置管理、Kill Switch、全局策略 |
| **租户运营** | 查看本租户数据、调整阈值 |
| **安全工程师** | 查看检测命中、红蓝对抗结果、告警 |
| **开发者** | 接入文档、SDK 版本管理、调试工具 |

---

## 2. 系统架构

### 2.1 总体架构

```
┌─────────────────────────────────────────────────────────────┐
│                     Portal Frontend                         │
│              (React / Next.js / TailwindCSS)                │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐      │
│  │ Dashboard │ │ Config   │ │ Key Mgmt │ │ Tenant   │      │
│  │ 监控面板  │ │ 配置管理  │ │ 密钥管理  │ │ 租户管理  │      │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘      │
│       └────────────┴────────────┴────────────┘              │
│                         │ REST / gRPC                       │
├─────────────────────────┼───────────────────────────────────┤
│                  Portal Backend                             │
│             (Go / Rust / Node.js)                           │
│  ┌────────────┐ ┌──────────────┐ ┌──────────────────┐      │
│  │ API Gateway │ │ Auth Service │ │ Audit Logger     │      │
│  │ 限流/鉴权   │ │ RBAC + MFA   │ │ 操作审计         │      │
│  └─────┬──────┘ └──────┬───────┘ └────────┬─────────┘      │
│        │               │                  │                 │
│  ┌─────┴──────┐ ┌──────┴───────┐ ┌───────┴──────────┐     │
│  │ Config Svc │ │ Monitor Svc  │ │ Key Mgmt Service │     │
│  │ 配置服务    │ │ 监控服务      │ │ 密钥服务         │     │
│  └─────┬──────┘ └──────┬───────┘ └───────┬──────────┘     │
│        │               │                  │                 │
├────────┼───────────────┼──────────────────┼─────────────────┤
│  ┌─────┴──────┐ ┌──────┴───────┐ ┌───────┴──────────┐     │
│  │ PostgreSQL │ │ ClickHouse / │ │ Vault / KMS      │     │
│  │ 配置+租户   │ │ TimescaleDB  │ │ 密钥安全存储      │     │
│  │            │ │ 监控时序数据   │ │                  │     │
│  └────────────┘ └──────────────┘ └──────────────────┘     │
│                     Storage Layer                           │
└─────────────────────────────────────────────────────────────┘
                          │
                          │ SDK 拉取配置 / 上报数据
                          ▼
                ┌──────────────────┐
                │ CloudPhoneRiskKit│
                │ (iOS SDK 端侧)   │
                └──────────────────┘
```

### 2.2 技术栈推荐

| 层级 | 推荐方案 | 备选 |
|------|---------|------|
| Frontend | Next.js + React + TailwindCSS | Vue 3 + Element Plus |
| Backend | Go (gin/fiber) | Rust (axum) / Node.js (Fastify) |
| API 协议 | REST (JSON) + gRPC (内部) | GraphQL |
| 配置存储 | PostgreSQL 16+ | MySQL 8+ |
| 时序数据 | ClickHouse | TimescaleDB / InfluxDB |
| 密钥存储 | HashiCorp Vault | AWS KMS / 阿里云 KMS |
| 缓存 | Redis 7+ | — |
| 消息队列 | Kafka | RabbitMQ / NATS |
| 认证 | OIDC + RBAC + MFA | — |

---

## 3. 功能模块

### 3.1 远程配置管理（Config Dashboard）

| 功能 | 说明 |
|------|------|
| **策略编辑器** | 可视化编辑 RemoteConfig JSON，支持 diff 预览 |
| **检测开关** | 开关各 Detector/Provider，支持按比例灰度 |
| **阈值调节** | 滑块式调节各场景 score 阈值 |
| **Kill Switch** | 一键启用/禁用 Kill Switch，需二次确认 + MFA |
| **配置版本管理** | 每次修改自动版本化，支持回滚到任意历史版本 |
| **配置签名** | 下发前自动使用服务端私钥签名 |
| **灰度发布** | 按 deviceID hash / 用户百分比 / 版本号灰度下发 |
| **AB 实验** | 配合 ExperimentConfig 进行分桶实验 |

### 3.2 实时监控看板（Monitoring）

| 指标 | 可视化方式 |
|------|----------|
| 设备风险分布 | 饼图/柱状图（低/中/高/严重） |
| 信号命中 TOP-N | 排行榜 + 趋势线 |
| evaluate() 耗时分布 | 直方图 + P50/P95/P99 |
| SDK 版本分布 | 环形图 |
| 检测精度趋势 | 折线图（TPR/FPR 周趋势） |
| Kill Switch 状态 | 状态灯 + 历史记录 |
| 异常告警 | 告警列表 + 严重等级标签 |

#### 告警规则示例

| 告警 | 条件 | 级别 |
|------|------|------|
| 高风险设备激增 | 高风险比例 > 日常 2 倍 | P1 |
| evaluate 延迟上升 | P95 > 300ms 持续 5 分钟 | P2 |
| SDK 崩溃率上升 | Crash-Free Rate < 99.99% | P0 |
| Kill Switch 被触发 | 状态变更 | P0 |
| 远程配置拉取失败率 | 失败率 > 5% 持续 10 分钟 | P1 |

### 3.3 密钥管理 UI（Key Management）

| 功能 | 说明 |
|------|------|
| **密钥列表** | 每个租户的全部密钥，含状态/版本/创建时间 |
| **密钥轮换** | 一键发起轮换，可视化 grace period 倒计时 |
| **密钥撤销** | 紧急撤销按钮，需管理员 MFA 确认 |
| **密钥到期提醒** | 7 天内到期的密钥高亮 + 邮件通知 |
| **签名密钥管理** | 管理 ReportEnvelope 签名验证密钥 |
| **审计日志** | 所有密钥操作的详细审计记录 |

### 3.4 租户管理（Tenant Management）

| 功能 | 说明 |
|------|------|
| **租户注册** | 创建新租户，分配 API Key 和默认配置 |
| **权限管理** | RBAC 角色分配（Admin/Operator/Viewer） |
| **配额管理** | 每日 evaluate 次数上限、并发限制 |
| **接入审批** | 新租户接入需管理员审批 |
| **租户隔离** | 配置/数据/密钥完全隔离 |
| **使用统计** | 按租户统计 evaluate 调用量/成功率/信号分布 |

---

## 4. Portal 后端 API 设计

### 4.1 认证与授权

所有 API 需携带 Bearer Token，采用 RBAC 权限模型。

```
Authorization: Bearer <jwt-token>
X-Tenant-ID: <tenant-id>
```

### 4.2 配置服务 API

#### 获取当前配置

```
GET /api/v1/config/{tenant_id}/current
Response 200:
{
  "version": 42,
  "config": { ... RemoteConfig JSON ... },
  "signature": "base64-hmac-sha256",
  "published_at": "2026-03-27T10:00:00Z",
  "publisher": "admin@example.com"
}
```

#### 更新配置

```
PUT /api/v1/config/{tenant_id}
Body:
{
  "config": { ... },
  "comment": "调高支付场景阈值到 65",
  "publish_mode": "immediate" | "canary" | "scheduled",
  "canary_percentage": 10,
  "scheduled_at": null
}
Response 200:
{
  "version": 43,
  "signature": "...",
  "status": "published"
}
```

#### 配置版本历史

```
GET /api/v1/config/{tenant_id}/history?page=1&size=20
Response 200:
{
  "items": [
    { "version": 43, "comment": "...", "publisher": "...", "published_at": "..." },
    ...
  ],
  "total": 43
}
```

#### 配置回滚

```
POST /api/v1/config/{tenant_id}/rollback
Body: { "target_version": 41, "reason": "误操作回滚" }
Response 200: { "version": 44, "rolled_back_from": 43, "rolled_back_to": 41 }
```

#### Kill Switch

```
POST /api/v1/config/{tenant_id}/killswitch
Body: { "enabled": true, "reason": "紧急误杀止血", "mfa_token": "123456" }
Response 200: { "status": "activated", "activated_at": "..." }
```

### 4.3 监控服务 API

#### 实时概览

```
GET /api/v1/monitor/{tenant_id}/overview
Response 200:
{
  "total_evaluations_24h": 1523400,
  "risk_distribution": { "low": 0.92, "medium": 0.05, "high": 0.03 },
  "avg_latency_ms": 72,
  "p95_latency_ms": 180,
  "error_rate": 0.0002,
  "kill_switch_active": false,
  "sdk_version_distribution": { "7.3.0": 0.85, "7.2.0": 0.12, "other": 0.03 }
}
```

#### 信号命中统计

```
GET /api/v1/monitor/{tenant_id}/signals?period=24h&top=20
Response 200:
{
  "signals": [
    { "id": "jailbreak", "count": 4521, "percentage": 0.003 },
    { "id": "hook_detected", "count": 2103, "percentage": 0.0014 },
    ...
  ]
}
```

#### 告警列表

```
GET /api/v1/monitor/{tenant_id}/alerts?status=open&severity=P0,P1
Response 200:
{
  "alerts": [
    {
      "id": "alert_001",
      "severity": "P1",
      "title": "高风险设备比例异常",
      "triggered_at": "...",
      "status": "open",
      "details": "高风险设备占比从 3% 升至 8%"
    }
  ]
}
```

### 4.4 密钥服务 API

#### 获取密钥列表

```
GET /api/v1/keys/{tenant_id}
Response 200:
{
  "keys": [
    {
      "key_id": "uuid",
      "version": 3,
      "state": "active",
      "algorithm": "AES-256-GCM",
      "created_at": "...",
      "activated_at": "...",
      "expires_at": "..."
    },
    ...
  ]
}
```

#### 发起密钥轮换

```
POST /api/v1/keys/{tenant_id}/rotate
Body: { "grace_period_seconds": 3600 }
Response 200:
{
  "pending_key_id": "uuid",
  "version": 4,
  "grace_period_ends_at": "..."
}
```

#### 提交密钥轮换

```
POST /api/v1/keys/{tenant_id}/rotate/commit
Response 200:
{
  "activated_key_id": "uuid",
  "retired_key_id": "uuid",
  "version": 4
}
```

#### 紧急撤销

```
POST /api/v1/keys/{tenant_id}/{key_id}/revoke
Body: { "reason": "密钥泄露", "mfa_token": "123456" }
Response 200: { "revoked_key_id": "...", "revoked_at": "..." }
```

### 4.5 租户管理 API

#### 创建租户

```
POST /api/v1/tenants
Body:
{
  "name": "Example Corp",
  "contact_email": "admin@example.com",
  "tier": "standard" | "enterprise",
  "daily_quota": 1000000
}
Response 201:
{
  "tenant_id": "uuid",
  "api_key": "cpk_live_...",
  "created_at": "..."
}
```

#### 获取租户信息

```
GET /api/v1/tenants/{tenant_id}
Response 200:
{
  "tenant_id": "...",
  "name": "Example Corp",
  "tier": "enterprise",
  "daily_quota": 1000000,
  "current_usage_24h": 523000,
  "active_key_count": 1,
  "config_version": 43,
  "created_at": "..."
}
```

---

## 5. 关键页面线框描述

### 5.1 Dashboard 首页

```
┌─────────────────────────────────────────────────────────┐
│ [Logo] CloudPhoneRiskKit Portal        [User ▼] [退出]  │
├────────┬────────────────────────────────────────────────┤
│        │                                                │
│ 导航栏  │  ┌─────────────────────────────────────────┐  │
│        │  │  24h 总评估量         实时 QPS            │  │
│ ▸ 首页  │  │  1,523,400 ▲12%     176 req/s           │  │
│ ▸ 配置  │  ├─────────────────────────────────────────┤  │
│ ▸ 监控  │  │  风险分布 (饼图)     │  P95 延迟 (折线)   │  │
│ ▸ 密钥  │  │  [低92%][中5%][高3%] │  [72ms → 180ms]  │  │
│ ▸ 租户  │  ├─────────────────────────────────────────┤  │
│ ▸ 审计  │  │  TOP-10 信号命中排行                      │  │
│ ▸ 文档  │  │  1. jailbreak       4,521 (0.3%)        │  │
│        │  │  2. hook_detected    2,103 (0.14%)       │  │
│        │  │  3. frida_module     1,887 (0.12%)       │  │
│        │  │  ...                                      │  │
│        │  ├─────────────────────────────────────────┤  │
│        │  │  活跃告警                                  │  │
│        │  │  🔴 P0: SDK 崩溃率上升   10 分钟前         │  │
│        │  │  🟡 P1: 配置拉取失败率 > 5%  25 分钟前     │  │
│        │  └─────────────────────────────────────────┘  │
└────────┴────────────────────────────────────────────────┘
```

### 5.2 配置管理页

```
┌─────────────────────────────────────────────────────────┐
│ 配置管理 — Tenant: Example Corp                          │
├─────────────────────────────────────────────────────────┤
│                                                         │
│ 当前版本: v43    发布者: admin    发布时间: 2026-03-27    │
│                                                         │
│ ┌───────────────────────────────────────────────────┐   │
│ │ 检测开关                                          │   │
│ │ ┌──────────────────────┬───────┬────────┐        │   │
│ │ │ 检测器                │ 状态  │ 灰度%   │        │   │
│ │ ├──────────────────────┼───────┼────────┤        │   │
│ │ │ 越狱检测              │ [✓开] │ 100%   │        │   │
│ │ │ Frida 检测            │ [✓开] │ 100%   │        │   │
│ │ │ 行为信号              │ [✓开] │ 100%   │        │   │
│ │ │ MIE/MTE 姿态          │ [✓开] │  50%   │        │   │
│ │ │ 图风控联动            │ [ 关] │  —     │        │   │
│ │ └──────────────────────┴───────┴────────┘        │   │
│ └───────────────────────────────────────────────────┘   │
│                                                         │
│ ┌───────────────────────────────────────────────────┐   │
│ │ 场景阈值                                          │   │
│ │  登录: ──●────────── 60                           │   │
│ │  支付: ────●──────── 55                           │   │
│ │  注册: ──────●────── 50                           │   │
│ │  默认: ──●────────── 60                           │   │
│ └───────────────────────────────────────────────────┘   │
│                                                         │
│ ┌─────────────────────┐                                 │
│ │ Kill Switch: [关闭]  │  [⚠️ 启用 Kill Switch]         │
│ └─────────────────────┘                                 │
│                                                         │
│ [保存草稿]  [预览 Diff]  [发布到 10% 灰度]  [全量发布]    │
│                                                         │
│ ─────── 历史版本 ───────                                 │
│ v43  2026-03-27  admin  "调高支付阈值"    [查看] [回滚]   │
│ v42  2026-03-26  ops    "启用 MTE 灰度"   [查看] [回滚]   │
│ v41  2026-03-25  admin  "关闭图联动"      [查看] [回滚]   │
└─────────────────────────────────────────────────────────┘
```

### 5.3 密钥管理页

```
┌─────────────────────────────────────────────────────────┐
│ 密钥管理 — Tenant: Example Corp                          │
├─────────────────────────────────────────────────────────┤
│                                                         │
│ ┌─ 当前密钥状态 ────────────────────────────────────┐   │
│ │                                                   │   │
│ │  🟢 Active: key_v3 (uuid-xxx)                    │   │
│ │     创建: 2026-01-15  激活: 2026-01-15            │   │
│ │     过期: 2026-04-15  (还有 19 天 ⚠️)             │   │
│ │                                                   │   │
│ │  ⚪ Retired: key_v2 (uuid-yyy)                   │   │
│ │     创建: 2025-10-10  退役: 2026-01-15            │   │
│ │                                                   │   │
│ │  🔴 Revoked: key_v1 (uuid-zzz)                  │   │
│ │     创建: 2025-07-01  撤销: 2025-10-10            │   │
│ │                                                   │   │
│ └───────────────────────────────────────────────────┘   │
│                                                         │
│ [🔄 发起密钥轮换]   [⚠️ 紧急撤销当前密钥]                 │
│                                                         │
│ ─── 轮换进度（如果有进行中的轮换）───                     │
│ ┌───────────────────────────────────────────────────┐   │
│ │  Pending: key_v4 (uuid-aaa)                      │   │
│ │  Grace Period: ████████░░ 80% (48 分钟 / 60 分钟)│   │
│ │  [取消轮换]  [立即提交（跳过 grace period）]       │   │
│ └───────────────────────────────────────────────────┘   │
│                                                         │
│ ─── 操作审计日志 ───                                     │
│ 2026-03-27 10:00  admin  "发起密钥轮换 v3→v4"           │
│ 2026-01-15 09:30  admin  "提交密钥轮换 v2→v3"           │
│ 2025-10-10 14:00  admin  "撤销密钥 v1 (安全事件)"        │
└─────────────────────────────────────────────────────────┘
```

### 5.4 租户管理页

```
┌─────────────────────────────────────────────────────────┐
│ 租户管理                                   [+ 创建租户]  │
├─────────────────────────────────────────────────────────┤
│ ┌─────────┬──────────┬────────┬──────────┬───────────┐ │
│ │ 租户名   │ Tier     │ 用量/配额 │ 活跃密钥 │ 操作     │ │
│ ├─────────┼──────────┼────────┼──────────┼───────────┤ │
│ │ Corp A  │ Enterprise│ 523K/1M│ 1        │ [管理]    │ │
│ │ Corp B  │ Standard │ 89K/100K│ 1        │ [管理]    │ │
│ │ Corp C  │ Standard │ 12K/100K│ 0 ⚠️    │ [管理]    │ │
│ └─────────┴──────────┴────────┴──────────┴───────────┘ │
│                                                         │
│ 分页: [< 1 2 3 >]                                       │
└─────────────────────────────────────────────────────────┘
```

---

## 6. 数据模型

### 6.1 核心实体

```
┌──────────────┐     ┌───────────────┐     ┌──────────────┐
│   Tenant     │────<│  ConfigVersion│     │  ManagedKey  │
│──────────────│     │───────────────│     │──────────────│
│ id (PK)      │     │ id (PK)       │     │ id (PK)      │
│ name         │     │ tenant_id (FK)│     │ tenant_id(FK)│
│ tier         │     │ version       │     │ version      │
│ contact_email│     │ config_json   │     │ state        │
│ daily_quota  │     │ signature     │     │ algorithm    │
│ api_key_hash │     │ comment       │     │ created_at   │
│ created_at   │     │ publisher     │     │ activated_at │
│ status       │     │ published_at  │     │ retired_at   │
└──────┬───────┘     │ publish_mode  │     │ revoked_at   │
       │             └───────────────┘     │ expires_at   │
       │                                   │ vault_ref    │
       │             ┌───────────────┐     └──────────────┘
       └────────────<│  AuditLog     │
                     │───────────────│
                     │ id (PK)       │
                     │ tenant_id (FK)│
                     │ actor         │
                     │ action        │
                     │ resource_type │
                     │ resource_id   │
                     │ details_json  │
                     │ ip_address    │
                     │ created_at    │
                     └───────────────┘
```

### 6.2 监控数据模型（时序）

```sql
-- ClickHouse 建表示例
CREATE TABLE sdk_evaluation_events (
    tenant_id     String,
    device_id     String,
    sdk_version   String,
    score         Float64,
    risk_level    Enum8('low'=0, 'medium'=1, 'high'=2, 'critical'=3),
    action        Enum8('allow'=0, 'challenge'=1, 'block'=2),
    latency_ms    UInt32,
    signal_ids    Array(String),
    scenario      String,
    config_version UInt32,
    created_at    DateTime64(3)
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(created_at)
ORDER BY (tenant_id, created_at, device_id)
TTL created_at + INTERVAL 90 DAY;
```

### 6.3 告警规则模型

```json
{
  "alert_rule": {
    "id": "rule_001",
    "tenant_id": "*",
    "name": "高风险设备激增",
    "metric": "risk_distribution.high",
    "condition": "value > baseline * 2",
    "window": "5m",
    "severity": "P1",
    "notification_channels": ["email", "slack", "pagerduty"],
    "cooldown_seconds": 300
  }
}
```

---

## 7. 部署架构

### 7.1 推荐部署拓扑

```
                    ┌─────────────┐
                    │   CDN/WAF   │
                    └──────┬──────┘
                           │
                    ┌──────┴──────┐
                    │  Nginx/ALB  │
                    │  (TLS终止)   │
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
        ┌─────┴─────┐ ┌───┴───┐ ┌─────┴─────┐
        │ Portal FE │ │ API   │ │ Config    │
        │ (静态资源)  │ │ Gateway│ │ Push      │
        │ 2 replicas │ │ 3 pods│ │ 2 pods    │
        └───────────┘ └───┬───┘ └───────────┘
                          │
           ┌──────────────┼──────────────┐
           │              │              │
     ┌─────┴─────┐ ┌─────┴─────┐ ┌─────┴─────┐
     │ Config    │ │ Monitor   │ │ Key Mgmt  │
     │ Service   │ │ Service   │ │ Service   │
     │ 3 pods    │ │ 2 pods    │ │ 2 pods    │
     └─────┬─────┘ └─────┬─────┘ └─────┬─────┘
           │              │              │
     ┌─────┴─────┐ ┌─────┴─────┐ ┌─────┴─────┐
     │ PostgreSQL│ │ ClickHouse│ │   Vault   │
     │ Primary + │ │ 3-node    │ │ HA Cluster│
     │ 2 Replica │ │ cluster   │ │           │
     └───────────┘ └───────────┘ └───────────┘
```

### 7.2 可用性目标

| 组件 | 可用性 | RTO | RPO |
|------|--------|-----|-----|
| Portal Frontend | 99.9% | 5 分钟 | N/A (无状态) |
| Config Service | 99.99% | 1 分钟 | 0 (同步复制) |
| Monitor Service | 99.9% | 5 分钟 | 1 分钟 |
| Key Mgmt Service | 99.99% | 1 分钟 | 0 |
| Vault | 99.99% | 30 秒 | 0 |

### 7.3 容器化部署

```yaml
# k8s deployment 示例（portal-api）
apiVersion: apps/v1
kind: Deployment
metadata:
  name: portal-api
spec:
  replicas: 3
  selector:
    matchLabels:
      app: portal-api
  template:
    spec:
      containers:
        - name: portal-api
          image: registry.example.com/riskkit-portal-api:latest
          ports:
            - containerPort: 8080
          env:
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: portal-secrets
                  key: database-url
            - name: VAULT_ADDR
              value: "https://vault.internal:8200"
          resources:
            requests:
              cpu: 500m
              memory: 512Mi
            limits:
              cpu: 2000m
              memory: 2Gi
          livenessProbe:
            httpGet:
              path: /healthz
              port: 8080
            initialDelaySeconds: 10
            periodSeconds: 15
          readinessProbe:
            httpGet:
              path: /readyz
              port: 8080
            initialDelaySeconds: 5
            periodSeconds: 10
```

---

## 8. 安全设计

### 8.1 认证与授权

| 机制 | 说明 |
|------|------|
| **OIDC / SSO** | 统一认证入口，对接企业 IdP |
| **RBAC** | 角色：SuperAdmin / TenantAdmin / Operator / Viewer |
| **MFA** | 高危操作（Kill Switch / 密钥撤销）强制 MFA |
| **API Key** | SDK 端侧使用 API Key 鉴权 |
| **IP 白名单** | Portal 管理端可限制访问 IP |

### 8.2 数据安全

| 措施 | 说明 |
|------|------|
| 传输加密 | TLS 1.3，HSTS |
| 存储加密 | AES-256 at rest（数据库 + 对象存储） |
| 密钥隔离 | Vault / KMS，密钥不出安全边界 |
| 审计日志 | 所有操作不可篡改记录 |
| 数据脱敏 | 设备信息在 Portal 中展示时部分脱敏 |

### 8.3 合规

- GDPR：支持数据导出与删除
- CCPA：支持用户数据访问请求
- 等保 2.0：满足三级要求

---

## 9. 扩展规划

### Phase 1（MVP, 4 周）

- [ ] 配置管理（CRUD + 版本 + 签名）
- [ ] Kill Switch
- [ ] 基础监控看板
- [ ] 租户 CRUD
- [ ] 认证（OIDC + RBAC）

### Phase 2（6 周）

- [ ] 密钥管理 UI
- [ ] 告警系统
- [ ] 灰度发布
- [ ] AB 实验
- [ ] 审计日志

### Phase 3（8 周）

- [ ] 高级监控（信号深度分析、设备画像）
- [ ] 自动化 SLA 报告
- [ ] 多集群部署
- [ ] SDK 远程调试工具
- [ ] API Marketplace（第三方 Detector 插件）
