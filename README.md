# Onion域名批量检测工具

这是一个用于检测onion域名在线状态的Python工具，可以单个或批量检测onion域名是否在线，并提供响应时间和状态码等信息。

## 功能特点

- 支持单个onion域名检测
- 支持从文件批量检测多个onion域名
- 多线程并发检测，提高效率
- 自动重试机制，提高检测成功率
- 定期更新Tor身份，避免被封锁
- 支持多种输出格式（文本、JSON、CSV）
- 详细的日志记录和错误处理
- 命令行界面，易于使用和集成
- 自动检测Tor代理是否可用，无需手动配置

## 安装要求

- Python 3.6+
- 以下Python库：
  - stem
  - requests
  - pysocks

## 安装步骤

1. 安装所需的Python库：

```bash
pip3 install stem requests pysocks
```

2. 下载onion_checker.py脚本

## 使用方法

### 基本用法

检测单个onion域名：

```bash
python3 onion_checker.py -d duckduckgo.onion
```

从文件批量检测多个onion域名：

```bash
python3 onion_checker.py -f domains.txt
```

### 高级选项

```
usage: onion_checker.py [-h] [-d DOMAIN] [-f FILE] [-o OUTPUT] [-t TIMEOUT]
                        [-p SOCKS_PORT] [-c CONTROL_PORT] [-n THREADS]
                        [-r RETRY] [-v] [--format {text,json,csv}]
                        [--no-renew-identity] [--open-guide]

Onion域名在线状态检测工具

选项:
  -h, --help            显示帮助信息并退出
  -d DOMAIN, --domain DOMAIN
                        要检测的单个onion域名
  -f FILE, --file FILE  包含多个onion域名的文件路径（每行一个域名）
  -o OUTPUT, --output OUTPUT
                        将结果保存到指定文件
  -t TIMEOUT, --timeout TIMEOUT
                        连接超时时间（秒），默认20秒
  -p SOCKS_PORT, --socks-port SOCKS_PORT
                        Tor SOCKS代理端口，默认9050
  -c CONTROL_PORT, --control-port CONTROL_PORT
                        Tor控制端口，默认9051
  -n THREADS, --threads THREADS
                        并发线程数，默认10
  -r RETRY, --retry RETRY
                        连接失败时的最大重试次数，默认3
  -v, --verbose         显示详细信息
  --format {text,json,csv}
                        输出格式（text, json, csv），默认为text
  --no-renew-identity   禁用定期更新Tor身份
  --open-guide          如果Tor不可用，自动打开Tor安装指南网页
```

### 示例

1. 检测单个域名并显示详细信息：

```bash
python3 onion_checker.py -d duckduckgo.onion -v
```

2. 从文件批量检测域名，使用20个线程，并保存结果到output.txt：

```bash
python3 onion_checker.py -f domains.txt -n 20 -o output.txt
```

3. 批量检测域名，设置超时时间为30秒，最大重试次数为5：

```bash
python3 onion_checker.py -f domains.txt -t 30 -r 5
```

4. 以JSON格式输出结果：

```bash
python3 onion_checker.py -f domains.txt --format json -o results.json
```

5. 如果Tor不可用，自动打开Tor安装指南网页：

```bash
python3 onion_checker.py -f domains.txt --open-guide
```

## 输出示例

当Tor代理可用时：

```
================================================================================
域名                                            状态         响应时间(秒)         状态码       
================================================================================
duckduckgo.onion                              offline    -               -         
facebookcorewwwi.onion                        offline    -               -         
3g2upl4pq6kufc4m.onion                        offline    -               -         
protonmailrmez3lotccipshtkleegetolb73fuirgj7r4o4vfu7ozyd.onion online     4.6             200       
bbcnewsv2vjtpsuy.onion                        offline    -               -         
archivebyd3rzt3ehjpm4c3bjkyxv3hjleiytnvxcn7x32psn2kxcuid.onion offline    -               -         
thehiddenwiki.org.onion                       offline    -               -         
dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion online     2.9             200       
================================================================================
检测时间: 2025-04-17 23:08:25
总计: 8 个域名 (在线: 2, 离线: 6, 未知: 0)
```

当Tor代理不可用时：

```
================================================================================
域名                                            状态         响应时间(秒)         状态码       
================================================================================
duckduckgo.onion                              unknown    -               -         
facebookcorewwwi.onion                        unknown    -               -         
3g2upl4pq6kufc4m.onion                        unknown    -               -         
protonmailrmez3lotccipshtkleegetolb73fuirgj7r4o4vfu7ozyd.onion unknown    -               -         
bbcnewsv2vjtpsuy.onion                        unknown    -               -         
archivebyd3rzt3ehjpm4c3bjkyxv3hjleiytnvxcn7x32psn2kxcuid.onion unknown    -               -         
thehiddenwiki.org.onion                       unknown    -               -         
dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion unknown    -               -         
================================================================================
检测时间: 2025-04-18 11:15:30
总计: 8 个域名 (在线: 0, 离线: 0, 未知: 8)

注意: 状态为'未知'的域名是因为本地没有检测到Tor SOCKS代理，无法进行检测
您可以访问以下链接了解如何安装和配置Tor: https://tb-manual.torproject.org/installation/
```

## Tor安装指南

工具会根据您的操作系统提供相应的Tor安装指南链接：

- Windows: https://tb-manual.torproject.org/installation/
- Linux: https://community.torproject.org/onion-services/setup/install/
- macOS: https://tb-manual.torproject.org/installation/

## 注意事项

1. 工具会自动检测本地是否有Tor SOCKS代理服务
2. 如果没有检测到Tor代理，工具不会退出，而是将所有域名标记为"未知"状态，并提供Tor安装指南链接
3. 使用`--open-guide`选项可以在没有检测到Tor代理时自动打开浏览器访问安装指南
4. 默认情况下，工具使用Tor的SOCKS代理端口9050和控制端口9051
5. 如果您的Tor配置使用了不同的端口，请使用`--socks-port`和`--control-port`选项指定
6. 检测大量域名时，建议使用`-v`选项查看详细进度

## 故障排除

1. 如果所有域名显示为"未知"状态，这表示工具无法检测到本地的Tor SOCKS代理服务，请按照提供的链接安装和配置Tor

2. 如果出现"无法连接到Tor控制端口"警告，但域名状态不是"未知"，这表示Tor SOCKS代理可用但无法更新Tor身份，这不影响基本功能

3. 如果检测结果全部显示为离线，请尝试增加超时时间和重试次数：

```bash
python3 onion_checker.py -f domains.txt -t 60 -r 5
```



## 免责声明

本工具仅用于合法的网络测试和研究目的。用户应遵守所有适用的法律法规，对使用本工具的行为负全部责任。作者不对任何滥用或非法使用本工具的行为负责。
