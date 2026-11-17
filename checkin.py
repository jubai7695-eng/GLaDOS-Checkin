#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GLaDOS 自动签到脚本（适配 2026 年的 checkin challenge 协议）

背景：
    以前直接 POST /api/user/checkin 就能签到，现在服务端要求先 GET
    /api/user/checkin/challenge 拿到 nonce，等待约 2.5 秒后，
    提交 proof = sha256(f"{nonce}.glados-observe-v1") 才能拿到完整积分。
    本脚本按新协议实现，拿不到 challenge 时自动回退旧协议。

环境变量：
    GLADOS_COOKIE  必填，完整 Cookie；多账号用 & 或换行分隔
    GLADOS_DOMAIN  选填，账号所在域名，默认 glados.cloud
    GLADOS_UA      选填，必须与提取 Cookie 时浏览器的 UA 一致

运行：
    set GLADOS_COOKIE=koa:sess=xxx; koa:sess.sig=yyy
    python glados_checkin.py
"""

import hashlib
import os
import sys
import time
from datetime import datetime

import requests

# 去掉用户可能误填的 https:// 前缀和末尾斜杠，只留主机名
# 后面拼 URL 和 payload 的 token 都用这个值，二者必须一致
DOMAIN = os.environ.get('GLADOS_DOMAIN', 'glados.cloud').strip()
DOMAIN = DOMAIN.split('//')[-1].strip('/')
BASE = f'https://{DOMAIN}'

# UA 要和提取 Cookie 时的浏览器一致，否则服务端可能返回 device-mismatch
USER_AGENT = os.environ.get(
    'GLADOS_UA',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
)

# 服务端约定的 proof 后缀
CHALLENGE_SUFFIX = 'glados-observe-v1'

# 拿到 nonce 后必须等待的秒数，提前提交会被判无效
CHALLENGE_DELAY = 2.5

# Cookie 里至少要有一个会话字段，否则肯定签不上
SESSION_FIELDS = ('koa:sess=', 'gld:sess=')


def build_headers(cookie):
    """构造请求头：Cookie + UA + Origin（Origin 必须和域名匹配）"""
    return {
        'cookie': cookie,
        'user-agent': USER_AGENT,
        'origin': BASE,
    }


def fetch_challenge(headers):
    """
    第一步：GET challenge 拿 nonce。

    返回 nonce 字符串；拿不到（网络错误、Cookie 失效、接口变更）返回 None，
    由调用方回退到旧协议，不至于整个脚本直接崩掉。
    """
    try:
        resp = requests.get(f'{BASE}/api/user/checkin/challenge', headers=headers, timeout=30)
        data = resp.json()
    except Exception:
        return None

    # 正常响应形如 {"code":0,"nonce":"xxxx"}
    if not isinstance(data, dict) or data.get('code') != 0:
        return None
    nonce = data.get('nonce')
    return str(nonce) if nonce else None


def checkin_one(cookie):
    """
    单个账号签到。

    返回 (是否成功, 结果说明)。已签到也算成功，避免每天跑完都是红叉。
    """
    headers = build_headers(cookie)

    # token 必须等于当前域名，填成别的域名服务端会提示 please checkin via ...
    payload = {'token': DOMAIN}

    nonce = fetch_challenge(headers)
    if nonce:
        # 第二步：等服务端要求的间隔，再算 proof
        time.sleep(CHALLENGE_DELAY)
        payload['nonce'] = nonce
        payload['proof'] = hashlib.sha256(
            f'{nonce}.{CHALLENGE_SUFFIX}'.encode()
        ).hexdigest()

        # 有 challenge 时按网页端的方式用 JSON 提交
        resp = requests.post(f'{BASE}/api/user/checkin', headers=headers, json=payload, timeout=30)
    else:
        print('  ! 未获取 challenge，按旧协议提交（可能只拿到 1 积分）')
        resp = requests.post(f'{BASE}/api/user/checkin', headers=headers, json=payload, timeout=30)

    if resp.status_code != 200:
        return False, f'HTTP {resp.status_code}'

    try:
        data = resp.json()
    except ValueError:
        # 常见于 Cloudflare 拦截页
        return False, '响应不是 JSON，可能被 Cloudflare 拦截'

    code = data.get('code')
    message = str(data.get('message', '无消息'))
    points = data.get('points', '?')

    # 域名和 token 不一致时服务端给的提示
    if 'please checkin via' in message.lower():
        return False, f'签到域名不符：{message}（把 GLADOS_DOMAIN 改成提示里的域名）'

    # 设备不匹配：说明 UA 和提取 Cookie 的浏览器不是同一个
    if code == 4 and data.get('reason') == 'device-mismatch':
        return False, (
            f'设备不匹配（loginDevice={data.get("loginDevice")}），'
            '请把 GLADOS_UA 改成提取 Cookie 时的浏览器 UA'
        )

    # 已经签过：repeated=true / code=1 / checkedIn=true
    if data.get('repeated') is True or code == 1 or data.get('checkedIn') is True:
        return True, f'今日已签到（{message}）'

    if code == 0:
        return True, f'签到成功，+{points} 积分（{message}）'

    # code=-2 基本都是 Cookie 失效、域名不对或未登录
    if code == -2:
        return False, f'没有权限：Cookie 失效或域名不对（{message}）'

    # 其他情况把原始响应打出来，方便排查
    return False, f'code={code}, message={message}, raw={data}'


def fetch_status(headers):
    """查询邮箱和剩余天数，仅用于展示，失败不影响签到结论"""
    try:
        data = requests.get(f'{BASE}/api/user/status', headers=headers, timeout=30).json()
        # code 非 0 表示未登录，此时没有 data 字段，别把 0 天当成真实数据
        if data.get('code') != 0:
            return '未知', None
        info = data.get('data') or {}
        left = int(float(info.get('leftDays', 0)))
        return info.get('email', '未知'), left
    except Exception:
        return '未知', None


def load_cookies():
    """读取多账号 Cookie，支持 & 和换行两种分隔方式"""
    raw = os.environ.get('GLADOS_COOKIE', '').strip()
    if not raw:
        return []
    normalized = raw.replace('\r', '').replace('\n', '&')
    return [c.strip() for c in normalized.split('&') if c.strip()]


def main():
    cookies = load_cookies()
    if not cookies:
        print('X 未设置 GLADOS_COOKIE 环境变量')
        sys.exit(1)

    print('====== GLaDOS 自动签到 ======')
    print(f'时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
    print(f'域名: {DOMAIN}')
    print(f'账号数: {len(cookies)}\n')

    success = 0
    for index, cookie in enumerate(cookies, 1):
        print(f'[{index}/{len(cookies)}] 账号 {index}')

        # 提前拦掉明显不完整的 Cookie，省一次无效请求
        if not any(field in cookie for field in SESSION_FIELDS):
            print('  X Cookie 缺少 koa:sess / gld:sess，请整段复制')
            print()
            continue

        try:
            ok, message = checkin_one(cookie)
            print(f'  {"OK" if ok else "X"} {message}')
            if ok:
                success += 1

            email, left = fetch_status(build_headers(cookie))
            print(f'  邮箱: {email}', end='')
            if left is not None:
                print(f'  剩余: {left} 天')
            else:
                print('  剩余: 获取失败')
        except requests.exceptions.Timeout:
            print('  X 请求超时')
        except Exception as e:
            print(f'  X 异常: {e}')
        print()

    print('====== 签到完成 ======')
    print(f'成功: {success}/{len(cookies)}')

    # 全部失败时返回非 0，方便 GitHub Actions 把工作流标红
    if success == 0:
        sys.exit(1)


if __name__ == '__main__':
    main()
