#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Onion域名在线状态检测工具
用于检测单个或批量onion域名的在线状态
"""

import sys
import socket
import time
import argparse
import requests
import socks
import logging
from stem import Signal, SocketError
from stem.control import Controller
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import json
import csv
import os

# 默认配置
DEFAULT_TIMEOUT = 20          # 连接超时时间（秒）
DEFAULT_SOCKS_PORT = 9050     # Tor SOCKS 代理端口
DEFAULT_CONTROL_PORT = 9051   # Tor 控制端口
DEFAULT_THREADS = 10          # 默认并发线程数
MAX_RETRY = 3                 # 最大重试次数

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('onion_checker')

class OnionChecker:
    """Onion域名在线状态检测类"""

    def __init__(self,
                 timeout=DEFAULT_TIMEOUT,
                 socks_port=DEFAULT_SOCKS_PORT,
                 control_port=DEFAULT_CONTROL_PORT,
                 verbose=False,
                 retry=MAX_RETRY):
        self.timeout = timeout
        self.socks_port = socks_port
        self.control_port = control_port
        self.verbose = verbose
        self.retry = retry

        # 配置 SOCKS 代理（用于 requests）
        self._setup_proxy()
        # 检查 Tor 服务是否可用
        self._check_tor_service()

    def _setup_proxy(self):
        """配置 SOCKS5 代理，仅影响 HTTP 请求层面"""
        try:
            socks.set_default_proxy(socks.SOCKS5, '127.0.0.1', self.socks_port)
            if self.verbose:
                logger.info(f"已配置 SOCKS5 代理: 127.0.0.1:{self.socks_port}")
        except Exception as e:
            logger.error(f"配置 SOCKS5 代理失败: {e}")
            sys.exit(1)

    def _check_tor_service(self):
        """检查 Tor SOCKS 代理端口是否有监听"""
        try:
            native_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            native_sock.settimeout(3)
            native_sock.connect(('127.0.0.1', self.socks_port))
            native_sock.close()
            if self.verbose:
                logger.info("Tor SOCKS 代理服务正在运行")
        except Exception as e:
            logger.error(f"无法连接到 Tor SOCKS 代理 (127.0.0.1:{self.socks_port}): {e}")
            logger.error("请确保 Tor 服务已启动并监听正确端口")
            sys.exit(1)

    def _renew_tor_identity(self):
        """通过 ControlPort 请求新的 Tor 电路"""
        try:
            with Controller.from_port(port=self.control_port) as controller:
                controller.authenticate()
                controller.signal(Signal.NEWNYM)
                if self.verbose:
                    logger.info("已更新 Tor 身份")
                # 等待新的电路建立
                time.sleep(5)
                return True
        except SocketError:
            logger.warning(f"无法连接到 Tor 控制端口 (127.0.0.1:{self.control_port})")
            logger.warning("无法更新 Tor 身份，继续使用当前线路。")
            return False
        except Exception as e:
            logger.warning(f"更新 Tor 身份失败: {e}")
            return False

    def check_onion(self, onion_domain):
        """检测单个 onion 域名的在线状态"""
        if not onion_domain.endswith('.onion'):
            onion_domain = f"{onion_domain}.onion"

        result = {
            'domain': onion_domain,
            'status': 'offline',
            'response_time': None,
            'status_code': None,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'error': None,
            'retry_count': 0
        }

        for attempt in range(self.retry):
            try:
                url = f"http://{onion_domain}"
                start = time.time()
                response = requests.get(
                    url,
                    timeout=self.timeout,
                    proxies={
                        'http': f'socks5h://127.0.0.1:{self.socks_port}',
                        'https': f'socks5h://127.0.0.1:{self.socks_port}'
                    },
                    headers={'User-Agent': 'Mozilla/5.0'}
                )
                elapsed = time.time() - start
                result.update({
                    'status': 'online',
                    'response_time': round(elapsed, 2),
                    'status_code': response.status_code,
                    'retry_count': attempt
                })
                break
            except requests.exceptions.Timeout:
                result['error'] = '连接超时'
                if self.verbose and attempt < self.retry - 1:
                    logger.warning(f"{onion_domain} 连接超时，重试 ({attempt+1}/{self.retry})")
            except requests.exceptions.ConnectionError as e:
                result['error'] = f"连接错误: {e}"
                if self.verbose and attempt < self.retry - 1:
                    logger.warning(f"{onion_domain} 连接错误，重试 ({attempt+1}/{self.retry})")
            except Exception as e:
                result['error'] = f"未知错误: {e}"
                if self.verbose and attempt < self.retry - 1:
                    logger.warning(f"{onion_domain} 未知错误，重试 ({attempt+1}/{self.retry})")
            if attempt < self.retry - 1:
                time.sleep(2)
        return result

    def check_multiple(self, domains, threads=DEFAULT_THREADS, renew_identity=True):
        """批量检测多个 onion 域名状态"""
        results = []
        total = len(domains)
        processed = 0
        if self.verbose:
            logger.info(f"开始批量检测 {total} 个域名，使用 {threads} 线程")
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(self.check_onion, d) for d in domains]
            for fut in futures:
                res = fut.result()
                results.append(res)
                processed += 1
                if self.verbose:
                    logger.info(f"[{processed}/{total}] {res['domain']}: {res['status']}")
                if renew_identity and processed % 10 == 0 and processed < total:
                    self._renew_tor_identity()
        return results


def format_results(results, format_type='text'):
    """格式化检测结果为 text/json/csv"""
    if format_type == 'json':
        return json.dumps(results, indent=2, ensure_ascii=False)
    elif format_type == 'csv':
        output = []
        headers = ['domain', 'status', 'response_time', 'status_code', 'timestamp', 'error']
        output.append(','.join(headers))
        for r in results:
            row = [
                r['domain'],
                r['status'],
                str(r['response_time'] or ''),
                str(r['status_code'] or ''),
                r['timestamp'],
                r['error'] or ''
            ]
            output.append(','.join(row))
        return '\n'.join(output)
    else:
        lines = []
        lines.append('='*80)
        lines.append(f"{'域名':<45}{'状态':<10}{'响应时间(秒)':<15}{'状态码':<10}")
        lines.append('='*80)
        online = sum(1 for r in results if r['status']=='online')
        for r in results:
            lines.append(f"{r['domain']:<45}{r['status']:<10}{(r['response_time'] or '-'):<15}{(r['status_code'] or '-'):<10}")
        lines.append('='*80)
        lines.append(f"检测时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"总计: {len(results)} 个 (在线 {online}, 离线 {len(results)-online})")
        return '\n'.join(lines)


def save_results(results, output_file, format_type='text'):
    """保存检测结果到文件"""
    os.makedirs(os.path.dirname(output_file) or '.', exist_ok=True)
    if format_type == 'json':
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
    elif format_type == 'csv':
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['domain','status','response_time','status_code','timestamp','error'])
            writer.writeheader()
            writer.writerows(results)
    else:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(format_results(results, 'text'))
    logger.info(f"结果已保存到 {output_file}")


def main():
    parser = argparse.ArgumentParser(description='Onion域名在线状态检测工具')
    parser.add_argument('-d', '--domain', help='检测单个 onion 域名')
    parser.add_argument('-f', '--file', help='批量检测: 文件路径 (每行一个域名)')
    parser.add_argument('-o', '--output', help='保存结果到文件')
    parser.add_argument('-t', '--timeout', type=int, default=DEFAULT_TIMEOUT, help=f'超时 (秒), 默认 {DEFAULT_TIMEOUT}')
    parser.add_argument('-p', '--socks-port', type=int, default=DEFAULT_SOCKS_PORT, help=f'SOCKS 端口, 默认 {DEFAULT_SOCKS_PORT}')
    parser.add_argument('-c', '--control-port', type=int, default=DEFAULT_CONTROL_PORT, help=f'控制端口, 默认 {DEFAULT_CONTROL_PORT}')
    parser.add_argument('-n', '--threads', type=int, default=DEFAULT_THREADS, help=f'线程数, 默认 {DEFAULT_THREADS}')
    parser.add_argument('-r', '--retry', type=int, default=MAX_RETRY, help=f'重试次数, 默认 {MAX_RETRY}')
    parser.add_argument('-v', '--verbose', action='store_true', help='显示详细日志')
    parser.add_argument('--format', choices=['text','json','csv'], default='text', help='输出格式')
    parser.add_argument('--no-renew-identity', action='store_true', help='禁用定期更新身份')
    args = parser.parse_args()

    if not args.domain and not args.file:
        parser.print_help()
        logger.error("必须指定 -d 或 -f 参数")
        sys.exit(1)

    checker = OnionChecker(
        timeout=args.timeout,
        socks_port=args.socks_port,
        control_port=args.control_port,
        verbose=args.verbose,
        retry=args.retry
    )

    if args.domain:
        results = [checker.check_onion(args.domain)]
    else:
        try:
            with open(args.file, 'r', encoding='utf-8') as f:
                domains = [line.strip() for line in f if line.strip()]
            results = checker.check_multiple(domains, threads=args.threads, renew_identity=not args.no_renew_identity)
        except Exception as e:
            logger.error(f"读取文件失败: {e}")
            sys.exit(1)

    # 输出或保存结果
    output_str = format_results(results, args.format)
    if args.format == 'text':
        print(output_str)
    else:
        logger.info(f"检测完成, 共 {len(results)} 个域名")

    if args.output:
        save_results(results, args.output, args.format)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logger.info("用户中断, 退出")
        sys.exit(0)
    except Exception as e:
        logger.error(f"程序异常: {e}")
        sys.exit(1)
