#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AdGuard 规则合并去重
- 所有源统一走 dl.baichabuyu.asia 代理
- 完全行去重 + 域名级语义去重
- 不做 DNS 有效性校验（避免误判）
- 按字节数拆分为多份，每份 < 19MB（AdGuard 单文件上限 20MB）
"""
import os
import re
import sys
import time
import urllib.request
import urllib.parse
import urllib.error

# ============ 配置 ============
PROXY = 'https://dl.baichabuyu.asia/?url='

SOURCES = [
    ('01_hagezi_xiaomi',  'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.xiaomi.txt'),
    ('02_adrules',        'https://adrules.top/dns.txt'),
    ('03_oisd_small',     'https://small.oisd.nl/'),
    ('04_adguard_dns',    'https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt'),
    ('05_miaoermua',      'https://raw.githubusercontent.com/miaoermua/AdguardFilter/main/rule.txt'),
    ('06_awavenue',       'https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt'),
    ('07_hg',             'https://raw.githubusercontent.com/2771936993/HG/main/hg1.txt'),
    ('08_ddad',           'https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/DD-AD.txt'),
    ('09_217heidai',      'https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockfilters.txt'),
    ('10_kuan',           'https://raw.githubusercontent.com/qq5460168/666/master/rules.txt'),
    ('11_xndeye',         'https://raw.githubusercontent.com/xndeye/adblock_list/refs/heads/release/easylist.txt'),
    ('12_hagezi_tif',     'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.txt'),
    ('13_hagezi_multi',   'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/multi.txt'),
    ('14_oisd_big',       'https://big.oisd.nl/'),
]

OUTDIR = os.environ.get('OUTDIR', 'release')
LIMIT_BYTES = 19 * 1024 * 1024   # 每份上限 19MB

# ============ 正则 ============
RE_ABP_DOMAIN = re.compile(
    r'^\|\|([a-z0-9]([a-z0-9\-_]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-_]*[a-z0-9])?)+)\^$', re.I)
RE_PLAIN_DOMAIN = re.compile(
    r'^([a-z0-9]([a-z0-9\-_]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-_]*[a-z0-9])?)+)$', re.I)
RE_HOSTS = re.compile(
    r'^(?:0\.0\.0\.0|127\.0\.0\.1|::1)\s+([a-z0-9]([a-z0-9\-_]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-_]*[a-z0-9])?)+)\s*$', re.I)


def fetch(url, timeout=180):
    """通过代理下载"""
    proxied = PROXY + urllib.parse.quote(url, safe='')
    req = urllib.request.Request(proxied, headers={
        'User-Agent': 'Mozilla/5.0 (compatible; adguard-rules-merged)',
    })
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode('utf-8', errors='ignore')


def is_comment(s):
    if not s:
        return True
    if s.startswith('!') or s.startswith('['):
        return True
    if s.startswith('#') and not s.startswith('##') \
       and not s.startswith('#@#') and not s.startswith('#?#'):
        return True
    return False


def extract_domain(s):
    m = RE_ABP_DOMAIN.match(s)
    if m:
        return m.group(1).lower()
    m = RE_PLAIN_DOMAIN.match(s)
    if m:
        return m.group(1).lower()
    m = RE_HOSTS.match(s)
    if m:
        return m.group(1).lower()
    return None


def main():
    os.makedirs(OUTDIR, exist_ok=True)

    seen_line = set()
    seen_domain = set()
    seen_domain_allow = set()
    out_rules = []
    out_allow = []

    total_rules = 0
    dup_exact = 0
    dup_domain = 0

    print('=' * 66, flush=True)
    print('AdGuard 规则合并去重', flush=True)
    print('=' * 66, flush=True)

    for name, url in SOURCES:
        try:
            text = fetch(url)
        except Exception as e:
            print('%-20s 下载失败: %s' % (name, e), flush=True)
            continue

        n_read = n_kept = n_dl = n_dd = 0
        for line in text.splitlines():
            s = line.strip()
            if is_comment(s):
                continue
            total_rules += 1
            n_read += 1

            # 完全行去重
            if s in seen_line:
                n_dl += 1
                dup_exact += 1
                continue
            seen_line.add(s)

            # 域名级语义去重
            dom = extract_domain(s)
            if dom:
                if s.startswith('@@'):
                    if dom in seen_domain_allow:
                        n_dd += 1
                        dup_domain += 1
                        continue
                    seen_domain_allow.add(dom)
                    out_allow.append(s)
                else:
                    if dom in seen_domain:
                        n_dd += 1
                        dup_domain += 1
                        continue
                    seen_domain.add(dom)
                    out_rules.append(s)
            else:
                (out_allow if s.startswith('@@') else out_rules).append(s)
            n_kept += 1

        print('%-20s 读%8d 保留%8d 重复行%7d 重复域%7d'
              % (name, n_read, n_kept, n_dl, n_dd), flush=True)

    kept = len(out_rules) + len(out_allow)
    removed = total_rules - kept

    print('-' * 66, flush=True)
    print('有效规则数      : %d' % total_rules, flush=True)
    print('完全重复行      : %d' % dup_exact, flush=True)
    print('域名级重复      : %d' % dup_domain, flush=True)
    print('去重后保留      : %d (拦截 %d / 白名单 %d)'
          % (kept, len(out_rules), len(out_allow)), flush=True)
    print('去重率          : %.2f%%'
          % (100.0 * removed / total_rules if total_rules else 0), flush=True)

    # 拆分：白名单 + 拦截规则合并后按字节切分
    all_rules = out_allow + out_rules
    chunks = []
    cur = []
    cur_bytes = 0
    for r in all_rules:
        b = len(r.encode('utf-8')) + 1
        if cur and cur_bytes + b > LIMIT_BYTES:
            chunks.append(cur)
            cur = []
            cur_bytes = 0
        cur.append(r)
        cur_bytes += b
    if cur:
        chunks.append(cur)

    print('-' * 66, flush=True)
    print('拆分为 %d 份' % len(chunks), flush=True)

    # 清理旧文件
    for f in os.listdir(OUTDIR):
        if f.startswith('part') and f.endswith('.txt'):
            os.remove(os.path.join(OUTDIR, f))

    for i, chunk in enumerate(chunks, 1):
        path = os.path.join(OUTDIR, 'part%d.txt' % i)
        with open(path, 'w', encoding='utf-8') as fh:
            fh.write('[Adblock Plus]\n')
            fh.write('! Title: AdGuard Merged Part %d/%d\n' % (i, len(chunks)))
            fh.write('! Generated: %s\n' % time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()))
            fh.write('! Rules: %d\n' % len(chunk))
            fh.write('! Total after dedup: %d\n' % kept)
            fh.write('!' + '-' * 50 + '\n')
            for r in chunk:
                fh.write(r + '\n')
        size = os.path.getsize(path)
        print('part%d.txt  规则 %8d  %.2f MB'
              % (i, len(chunk), size / 1024.0 / 1024.0), flush=True)

    print('完成', flush=True)


if __name__ == '__main__':
    main()