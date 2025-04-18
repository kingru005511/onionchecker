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
import webbrowser
import platform
import threading
import shutil
import colorama
from colorama import Fore, Style

# 初始化colorama
colorama.init()

# 默认配置
DEFAULT_TIMEOUT = 20  # 连接超时时间（秒）
DEFAULT_SOCKS_PORT = 9050  # Tor SOCKS代理端口
DEFAULT_CONTROL_PORT = 9051  # Tor控制端口
DEFAULT_THREADS = 10  # 默认并发线程数
MAX_RETRY = 3  # 最大重试次数

# Tor安装和配置教程链接
TOR_SETUP_GUIDES = {
    "Windows": "https://tb-manual.torproject.org/installation/",
    "Linux": "https://community.torproject.org/onion-services/setup/install/",
    "Darwin": "https://tb-manual.torproject.org/installation/",
    "default": "https://www.torproject.org/download/"
}

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('onion_checker')

# 禁用警告输出
if not sys.warnoptions:
    import warnings
    warnings.simplefilter("ignore")

class ProgressBar:
    """进度条类，用于显示检测进度"""
    
    def __init__(self, total, prefix='', suffix='', decimals=1, length=50, fill='█'):
        """
        初始化进度条
        
        参数:
            total (int): 总任务数
            prefix (str): 前缀字符串
            suffix (str): 后缀字符串
            decimals (int): 百分比小数位数
            length (int): 进度条长度
            fill (str): 进度条填充字符
        """
        self.total = total
        self.prefix = prefix
        self.suffix = suffix
        self.decimals = decimals
        self.length = length
        self.fill = fill
        self.iteration = 0
        self._lock = threading.Lock()
        self.start_time = time.time()
        self.online_count = 0
        self.offline_count = 0
        self.unknown_count = 0
        self.last_domain = ""
        self.last_status = ""
        
        # 获取终端宽度
        try:
            self.terminal_width = shutil.get_terminal_size().columns
        except:
            self.terminal_width = 80
            
        # 初始化进度条显示
        print("", end="", flush=True)
    
    def update(self, domain="", status=""):
        """
        更新进度条
        
        参数:
            domain (str): 当前检测的域名
            status (str): 当前域名的状态
        """
        with self._lock:
            self.iteration += 1
            
            # 更新状态计数
            if status == "online":
                self.online_count += 1
            elif status == "offline":
                self.offline_count += 1
            elif status == "unknown":
                self.unknown_count += 1
                
            self.last_domain = domain
            self.last_status = status
            
            # 计算进度和剩余时间
            percent = ("{0:." + str(self.decimals) + "f}").format(100 * (self.iteration / float(self.total)))
            filled_length = int(self.length * self.iteration // self.total)
            bar = self.fill * filled_length + '-' * (self.length - filled_length)
            
            # 计算已用时间和预估剩余时间
            elapsed_time = time.time() - self.start_time
            if self.iteration > 0:
                eta = elapsed_time / self.iteration * (self.total - self.iteration)
                time_info = f"用时: {self._format_time(elapsed_time)} | 剩余: {self._format_time(eta)}"
            else:
                time_info = f"用时: {self._format_time(elapsed_time)}"
            
            # 构建状态信息
            status_info = f"在线: {self.online_count} | 离线: {self.offline_count} | 未知: {self.unknown_count}"
            
            # 打印进度条 - 单行显示并持续刷新
            progress_text = f"{self.prefix} |{bar}| {percent}% {self.suffix} [{self.iteration}/{self.total}] | {status_info} | {time_info}"
            
            # 确保进度条不超过终端宽度
            if len(progress_text) > self.terminal_width:
                progress_text = progress_text[:self.terminal_width-3] + "..."
            
            # 使用\r回车符实现单行刷新，确保没有换行符
            sys.stdout.write("\r" + " " * self.terminal_width)  # 清除整行
            sys.stdout.write("\r" + progress_text)
            sys.stdout.flush()
            
            # 如果完成，打印换行
            if self.iteration == self.total:
                print("\n")
    
    def _format_time(self, seconds):
        """格式化时间为人类可读格式"""
        if seconds < 60:
            return f"{seconds:.1f}秒"
        elif seconds < 3600:
            minutes = seconds // 60
            seconds %= 60
            return f"{int(minutes)}分{int(seconds)}秒"
        else:
            hours = seconds // 3600
            seconds %= 3600
            minutes = seconds // 60
            seconds %= 60
            return f"{int(hours)}时{int(minutes)}分{int(seconds)}秒"

class OnionChecker:
    """Onion域名在线状态检测类"""
    
    def __init__(self, timeout=DEFAULT_TIMEOUT, socks_port=DEFAULT_SOCKS_PORT, 
                 control_port=DEFAULT_CONTROL_PORT, verbose=False, retry=MAX_RETRY,
                 auto_open_guide=False, no_progress=False, quiet=False):
        """
        初始化OnionChecker
        
        参数:
            timeout (int): 连接超时时间（秒）
            socks_port (int): Tor SOCKS代理端口
            control_port (int): Tor控制端口
            verbose (bool): 是否显示详细信息
            retry (int): 最大重试次数
            auto_open_guide (bool): 是否自动打开Tor安装指南
            no_progress (bool): 是否禁用进度条
            quiet (bool): 是否禁用所有日志输出
        """
        self.timeout = timeout
        self.socks_port = socks_port
        self.control_port = control_port
        self.verbose = verbose
        self.retry = retry
        self.auto_open_guide = auto_open_guide
        self.no_progress = no_progress
        self.quiet = quiet
        self.tor_available = False
        self.progress_bar = None
        
        # 如果启用了quiet模式，禁用日志输出
        if self.quiet:
            logging.disable(logging.CRITICAL)
        
        # 检查Tor服务是否运行
        self.tor_available = self._check_tor_service()
        
        if self.tor_available:
            # 配置SOCKS代理
            self._setup_proxy()
        
    def _setup_proxy(self):
        """配置SOCKS代理"""
        try:
            # 配置socket使用SOCKS代理
            socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", self.socks_port)
            socket.socket = socks.socksocket
            
            if self.verbose and not self.quiet:
                logger.info(f"已配置SOCKS5代理: 127.0.0.1:{self.socks_port}")
        except Exception as e:
            if not self.quiet:
                logger.error(f"配置SOCKS5代理失败: {e}")
            self.tor_available = False
    
    def _check_tor_service(self):
        """
        检查Tor服务是否运行
        
        返回:
            bool: Tor服务是否可用
        """
        try:
            # 尝试连接到Tor SOCKS代理
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect(("127.0.0.1", self.socks_port))
            s.close()
            
            if self.verbose and not self.quiet:
                logger.info("Tor SOCKS代理服务正在运行")
            return True
            
        except Exception as e:
            if not self.quiet:
                logger.warning(f"无法连接到Tor SOCKS代理 (127.0.0.1:{self.socks_port}): {e}")
                logger.warning("本地没有检测到Tor SOCKS代理")
            
            # 获取操作系统类型
            system = platform.system()
            
            # 获取对应的Tor安装指南链接
            guide_url = TOR_SETUP_GUIDES.get(system, TOR_SETUP_GUIDES["default"])
            
            if not self.quiet:
                logger.info(f"您可以访问以下链接了解如何安装和配置Tor: {guide_url}")
            
            # 如果设置了自动打开指南，则打开浏览器
            if self.auto_open_guide:
                try:
                    webbrowser.open(guide_url)
                    if not self.quiet:
                        logger.info("已自动打开Tor安装指南网页")
                except Exception as e:
                    if not self.quiet:
                        logger.error(f"无法自动打开浏览器: {e}")
            
            return False
    
    def _renew_tor_identity(self):
        """
        更新Tor身份（获取新的出口节点）
        
        返回:
            bool: 是否成功更新Tor身份
        """
        if not self.tor_available:
            return False
            
        try:
            with Controller.from_port(port=self.control_port) as controller:
                controller.authenticate()
                controller.signal(Signal.NEWNYM)
                if self.verbose and not self.quiet:
                    logger.info("已更新Tor身份")
                time.sleep(5)  # 等待Tor建立新电路
                return True
        except SocketError:
            if not self.quiet:
                logger.warning(f"无法连接到Tor控制端口 (127.0.0.1:{self.control_port})")
                logger.warning("无法更新Tor身份，但将继续使用当前连接")
            return False
        except Exception as e:
            if not self.quiet:
                logger.warning(f"更新Tor身份失败: {e}")
            return False
    
    def check_onion(self, onion_domain):
        """
        检测单个onion域名的在线状态
        
        参数:
            onion_domain (str): 要检测的onion域名
        
        返回:
            dict: 包含检测结果的字典
        """
        # 如果Tor不可用，直接返回离线状态
        if not self.tor_available:
            return {
                'domain': onion_domain if onion_domain.endswith('.onion') else f"{onion_domain}.onion",
                'status': 'unknown',
                'response_time': None,
                'status_code': None,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'error': "Tor代理不可用，无法检测",
                'retry_count': 0
            }
        
        # 确保域名格式正确
        if not onion_domain.endswith('.onion'):
            onion_domain = f"{onion_domain}.onion"
        
        # 准备结果字典
        result = {
            'domain': onion_domain,
            'status': 'offline',
            'response_time': None,
            'status_code': None,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'error': None,
            'retry_count': 0
        }
        
        # 重试机制
        for attempt in range(self.retry):
            try:
                # 构建URL
                url = f"http://{onion_domain}"
                
                # 记录开始时间
                start_time = time.time()
                
                # 发送请求
                response = requests.get(
                    url, 
                    timeout=self.timeout,
                    proxies={
                        'http': f'socks5h://127.0.0.1:{self.socks_port}',
                        'https': f'socks5h://127.0.0.1:{self.socks_port}'
                    },
                    headers={
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0'
                    }
                )
                
                # 计算响应时间
                response_time = time.time() - start_time
                
                # 更新结果
                result['status'] = 'online'
                result['response_time'] = round(response_time, 2)
                result['status_code'] = response.status_code
                result['retry_count'] = attempt
                
                # 成功获取响应，跳出重试循环
                break
                
            except requests.exceptions.Timeout:
                result['error'] = "连接超时"
                if self.verbose and not self.quiet and attempt < self.retry - 1:
                    logger.warning(f"{onion_domain} 连接超时，尝试重试 ({attempt+1}/{self.retry})")
                
            except requests.exceptions.ConnectionError as e:
                result['error'] = f"连接错误: {str(e)}"
                if self.verbose and not self.quiet and attempt < self.retry - 1:
                    logger.warning(f"{onion_domain} 连接错误，尝试重试 ({attempt+1}/{self.retry})")
                
            except requests.exceptions.RequestException as e:
                result['error'] = f"请求错误: {str(e)}"
                if self.verbose and not self.quiet and attempt < self.retry - 1:
                    logger.warning(f"{onion_domain} 请求错误，尝试重试 ({attempt+1}/{self.retry})")
                
            except Exception as e:
                result['error'] = f"未知错误: {str(e)}"
                if self.verbose and not self.quiet and attempt < self.retry - 1:
                    logger.warning(f"{onion_domain} 未知错误，尝试重试 ({attempt+1}/{self.retry})")
            
            # 如果不是最后一次尝试，等待一段时间再重试
            if attempt < self.retry - 1:
                time.sleep(2)
        
        return result
    
    def check_multiple(self, domains, threads=DEFAULT_THREADS, renew_identity=True):
        """
        批量检测多个onion域名的在线状态
        
        参数:
            domains (list): 要检测的onion域名列表
            threads (int): 并发线程数
            renew_identity (bool): 是否定期更新Tor身份
            
        返回:
            list: 包含所有检测结果的列表
        """
        # 如果Tor不可用，直接返回所有域名为未知状态
        if not self.tor_available:
            return [{
                'domain': domain if domain.endswith('.onion') else f"{domain}.onion",
                'status': 'unknown',
                'response_time': None,
                'status_code': None,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'error': "Tor代理不可用，无法检测",
                'retry_count': 0
            } for domain in domains]
        
        results = []
        total_domains = len(domains)
        processed = 0
        
        if self.verbose and not self.quiet:
            logger.info(f"开始批量检测 {total_domains} 个域名，使用 {threads} 个线程")
        
        # 初始化进度条
        if not self.no_progress:
            self.progress_bar = ProgressBar(total_domains, prefix='检测进度:', suffix='完成', length=40)
        
        # 使用线程池并发检测
        with ThreadPoolExecutor(max_workers=threads) as executor:
            # 提交所有任务
            future_to_domain = {executor.submit(self.check_onion, domain): domain for domain in domains}
            
            # 收集结果
            for future in future_to_domain:
                try:
                    result = future.result()
                    results.append(result)
                    processed += 1
                    
                    # 更新进度条
                    if not self.no_progress:
                        self.progress_bar.update(result['domain'], result['status'])
                    
                    # 打印进度（如果没有进度条但启用了详细模式）
                    if self.no_progress and self.verbose and not self.quiet:
                        status = result['status']
                        domain = result['domain']
                        progress = f"[{processed}/{total_domains}]"
                        logger.info(f"{progress} {domain}: {status}")
                    
                    # 每检测一定数量的域名后更新Tor身份
                    if renew_identity and processed % 10 == 0 and processed < total_domains:
                        self._renew_tor_identity()
                        
                except Exception as e:
                    if self.verbose and not self.quiet:
                        logger.error(f"检测过程中出错: {e}")
        
        return results

def format_results(results, format_type='text'):
    """
    格式化检测结果
    
    参数:
        results (list): 检测结果列表
        format_type (str): 格式类型，可选 'text', 'json', 'csv'
        
    返回:
        str 或 dict: 格式化后的结果
    """
    if format_type == 'json':
        return json.dumps(results, indent=2)
    
    elif format_type == 'csv':
        output = []
        headers = ['domain', 'status', 'response_time', 'status_code', 'timestamp', 'error']
        output.append(','.join(headers))
        
        for result in results:
            row = [
                result['domain'],
                result['status'],
                str(result['response_time']) if result['response_time'] is not None else '',
                str(result['status_code']) if result['status_code'] is not None else '',
                result['timestamp'],
                result['error'] if result['error'] is not None else ''
            ]
            output.append(','.join(row))
        
        return '\n'.join(output)
    
    else:  # text
        output = []
        output.append("=" * 80)
        output.append(f"{'域名':<45} {'状态':<10} {'响应时间(秒)':<15} {'状态码':<10}")
        output.append("=" * 80)
        
        online_count = 0
        offline_count = 0
        unknown_count = 0
        
        for result in results:
            domain = result['domain']
            status = result['status']
            response_time = result['response_time'] if result['response_time'] is not None else '-'
            status_code = result['status_code'] if result['status_code'] is not None else '-'
            
            if status == 'online':
                status_colored = f"{Fore.GREEN}{status}{Style.RESET_ALL}"
                online_count += 1
            elif status == 'offline':
                status_colored = f"{Fore.RED}{status}{Style.RESET_ALL}"
                offline_count += 1
            else:  # unknown
                status_colored = f"{Fore.YELLOW}{status}{Style.RESET_ALL}"
                unknown_count += 1
            
            output.append(f"{domain:<45} {status_colored:<20} {response_time:<15} {status_code:<10}")
        
        output.append("=" * 80)
        output.append(f"检测时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        output.append(f"总计: {len(results)} 个域名 (在线: {Fore.GREEN}{online_count}{Style.RESET_ALL}, 离线: {Fore.RED}{offline_count}{Style.RESET_ALL}, 未知: {Fore.YELLOW}{unknown_count}{Style.RESET_ALL})")
        
        if unknown_count > 0:
            output.append("\n注意: 状态为'未知'的域名是因为本地没有检测到Tor SOCKS代理，无法进行检测")
            system = platform.system()
            guide_url = TOR_SETUP_GUIDES.get(system, TOR_SETUP_GUIDES["default"])
            output.append(f"您可以访问以下链接了解如何安装和配置Tor: {guide_url}")
        
        return "\n".join(output)

def save_results(results, output_file, format_type='text'):
    """
    保存检测结果到文件
    
    参数:
        results (list): 检测结果列表
        output_file (str): 输出文件路径
        format_type (str): 格式类型，可选 'text', 'json', 'csv'
    """
    try:
        # 确保输出目录存在
        output_dir = os.path.dirname(output_file)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        if format_type == 'json':
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
        
        elif format_type == 'csv':
            with open(output_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['domain', 'status', 'response_time', 'status_code', 'timestamp', 'error'])
                writer.writeheader()
                writer.writerows(results)
        
        else:  # text
            with open(output_file, 'w') as f:
                f.write(format_results(results, 'text'))
        
        logger.info(f"结果已保存到文件: {output_file}")
        
    except Exception as e:
        logger.error(f"保存结果到文件时出错: {e}")

def main():
    """主函数"""
    # 解析命令行参数
    parser = argparse.ArgumentParser(description='Onion域名在线状态检测工具')
    
    # 添加命令行参数
    parser.add_argument('-d', '--domain', help='要检测的单个onion域名')
    parser.add_argument('-f', '--file', help='包含多个onion域名的文件路径（每行一个域名）')
    parser.add_argument('-o', '--output', help='将结果保存到指定文件')
    parser.add_argument('-t', '--timeout', type=int, default=DEFAULT_TIMEOUT, help=f'连接超时时间（秒），默认{DEFAULT_TIMEOUT}秒')
    parser.add_argument('-p', '--socks-port', type=int, default=DEFAULT_SOCKS_PORT, help=f'Tor SOCKS代理端口，默认{DEFAULT_SOCKS_PORT}')
    parser.add_argument('-c', '--control-port', type=int, default=DEFAULT_CONTROL_PORT, help=f'Tor控制端口，默认{DEFAULT_CONTROL_PORT}')
    parser.add_argument('-n', '--threads', type=int, default=DEFAULT_THREADS, help=f'并发线程数，默认{DEFAULT_THREADS}')
    parser.add_argument('-r', '--retry', type=int, default=MAX_RETRY, help=f'连接失败时的最大重试次数，默认{MAX_RETRY}')
    parser.add_argument('-v', '--verbose', action='store_true', help='显示详细信息')
    parser.add_argument('--format', choices=['text', 'json', 'csv'], default='text', help='输出格式（text, json, csv），默认为text')
    parser.add_argument('--no-renew-identity', action='store_true', help='禁用定期更新Tor身份')
    parser.add_argument('--open-guide', action='store_true', help='如果Tor不可用，自动打开Tor安装指南网页')
    parser.add_argument('--no-progress', action='store_true', help='禁用进度条显示')
    parser.add_argument('--no-color', action='store_true', help='禁用彩色输出')
    parser.add_argument('--quiet', action='store_true', help='安静模式，禁用所有日志输出')
    
    args = parser.parse_args()
    
    # 如果禁用彩色输出，重置colorama
    if args.no_color:
        colorama.deinit()
    
    # 检查是否提供了域名或文件
    if not args.domain and not args.file:
        parser.print_help()
        if not args.quiet:
            logger.error("必须提供要检测的域名（-d）或包含域名的文件（-f）")
        sys.exit(1)
    
    # 创建检测器实例
    checker = OnionChecker(
        timeout=args.timeout,
        socks_port=args.socks_port,
        control_port=args.control_port,
        verbose=args.verbose,
        retry=args.retry,
        auto_open_guide=args.open_guide,
        no_progress=args.no_progress,
        quiet=args.quiet
    )
    
    # 根据输入方式执行检测
    if args.domain:
        # 检测单个域名
        if args.verbose and not args.quiet:
            logger.info(f"正在检测域名: {args.domain}")
        
        results = [checker.check_onion(args.domain)]
    else:
        # 从文件读取域名列表
        try:
            with open(args.file, 'r') as f:
                domains = [line.strip() for line in f if line.strip()]
            
            if args.verbose and not args.quiet:
                logger.info(f"从文件 {args.file} 中读取了 {len(domains)} 个域名")
            
            results = checker.check_multiple(
                domains, 
                threads=args.threads,
                renew_identity=not args.no_renew_identity
            )
        
        except FileNotFoundError:
            if not args.quiet:
                logger.error(f"找不到文件 {args.file}")
            sys.exit(1)
        
        except Exception as e:
            if not args.quiet:
                logger.error(f"读取文件时出错: {e}")
            sys.exit(1)
    
    # 格式化并输出结果
    formatted_results = format_results(results, args.format)
    if args.format == 'json' or args.format == 'csv':
        if not args.quiet:
            logger.info(f"检测完成，共 {len(results)} 个域名")
    else:
        print(formatted_results)
    
    # 如果指定了输出文件，将结果保存到文件
    if args.output:
        save_results(results, args.output, args.format)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}检测被用户中断{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        logger.error(f"程序执行出错: {e}")
        sys.exit(1)
