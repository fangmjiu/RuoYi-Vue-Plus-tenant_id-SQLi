# RuoYi-Vue-Plus tenant_id SQL 注入复现 PoC

针对 **RuoYi-Vue-Plus 5.x** 多租户 `tenant_id` 未授权 SQL 注入漏洞的复现工具与分析

## 漏洞概述

| 项 | 说明 |
|---|---|
| 漏洞类型 | 未授权 SQL 注入（报错注入 / 时间盲注） |
| 触发入口 | `POST /auth/register` 请求体 `tenantId` 字段 |
| 根因 | `PlusTenantLineHandler.getTenantId()` 使用 `new StringValue(tenantId)` 将外部可控租户 ID 直接拼入 SQL 字面量，不做转义，`#{}` 参数化失效 |
| 影响 | 无需登录、无需验证码，绕过多租户隔离，可读取/篡改全库数据 |

## 功能

| 能力 | 说明 |
|---|---|
| 自动加密 | 请求返回 403("没有访问权限") 时，自动切换 `@ApiEncrypt`(RSA+AES) 加密请求体并重发 |
| `probe` | 先报错注入(`extractvalue`)，未回显则自动切换延时注入(`SLEEP(5)`) |
| `mysql` | 报错注入直接回显 MySQL 账号(`current_user`) 与密码哈希(`mysql.user.authentication_string`) |

## 用法

```bash
pip install requests pycryptodome

# 1) 探测注入是否存在
python3 ruoyi_tenant_sqli.py --target http://<TARGET_IP>:8080 probe

#    经 SOCKS5 代理（目标有 IP 白名单时）
python3 ruoyi_tenant_sqli.py --target http://<TARGET_IP>:8080 --proxy socks5h://<PROXY_IP>:10800 probe

# 2) 获取 MySQL 账号与密码哈希
python3 ruoyi_tenant_sqli.py --target http://<TARGET_IP>:8080 --proxy socks5h://<PROXY_IP>:10800 mysql
```

> `--proxy` 等全局参数必须放在子命令 `probe` / `mysql` **之前**。

```

## 免责声明

本工具仅用于**授权的**安全测试、漏洞研究与应急响应。使用者需确保对目标拥有合法测试授权，因滥用造成的后果与作者无关。
