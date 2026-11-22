# AdGuard Rules Merged

自动合并去重多个 AdGuard 规则源，每 8 小时更新一次。

## 订阅地址

规则文件发布在 `release` 分支，共 3 份（每份 < 20MB，符合 AdGuard 单文件上限）。

### 直连（国外网络）

```
https://raw.githubusercontent.com/baich110/adguard-rules-merged/release/part1.txt
https://raw.githubusercontent.com/baich110/adguard-rules-merged/release/part2.txt
https://raw.githubusercontent.com/baich110/adguard-rules-merged/release/part3.txt
```

### 走白茶代理（国内网络推荐）

把上面的 URL 进行 URL 编码后拼到代理后面：

```
https://dl.baichabuyu.asia/?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbaich110%2Fadguard-rules-merged%2Frelease%2Fpart1.txt
https://dl.baichabuyu.asia/?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbaich110%2Fadguard-rules-merged%2Frelease%2Fpart2.txt
https://dl.baichabuyu.asia/?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbaich110%2Fadguard-rules-merged%2Frelease%2Fpart3.txt
```

## 规则源（14 个）

| 名称 | 说明 |
|---|---|
| HaGeZi native.xiaomi | 小米系统遥测专项 |
| AdRules DNS List | 国内综合（百度/腾讯/字节/小米/视频平台） |
| OISD Small | 零误杀基础档 |
| AdGuard DNS Filter | AdGuard 官方核心 |
| miaoermua AdguardFilter | 小米广告专项 |
| AWAvenue Ads Rule | 秋风广告规则（开屏/摇一摇） |
| 2771936993/HG | 国内主流 App 开屏广告 |
| afwfv/DD-AD | 补充规则 + 白名单 |
| 217heidai/adblockfilters | 16 源合并大合集 |
| qq5460168/666 | 酷安广告规则 |
| xndeye/adblock_list | 中文区快速迭代 |
| HaGeZi TIF | 威胁情报（恶意软件/钓鱼/诈骗） |
| HaGeZi Multi Normal | 平衡档全能防护 |
| OISD Big | Small 超集，含恶意软件/勒索 |

## 处理逻辑

1. **所有源统一走 `dl.baichabuyu.asia` 代理下载**
2. **完全行去重**：一模一样的字符串只保留一条
3. **域名级语义去重**：`||a.com^`、`a.com`、`0.0.0.0 a.com` 视为同一域名
4. **不做 DNS 有效性校验**：避免误判导致漏拦
5. **按字节切分**：每份控制在 19MB 以内

## 更新频率

GitHub Actions 定时任务：每天 UTC 0:00 / 8:00 / 16:00（北京时间 8:00 / 16:00 / 24:00）

也可在 Actions 页面手动触发。

## 导入方法

AdGuard → 设置 → 过滤 → 过滤器 → 自定义过滤器 → 添加自定义过滤器

依次添加 3 个 URL。

**注意**：如果之前订阅了原始规则源，请先禁用或删除，避免重复加载。

## 本地运行

```bash
python3 merge_rules.py
```

输出在 `release/` 目录。
