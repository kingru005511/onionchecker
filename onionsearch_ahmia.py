import requests
from bs4 import BeautifulSoup
from tqdm import tqdm
import sys

TOR_PROXIES = {
    'http':  'socks5h://127.0.0.1:9051',
    'https': 'socks5h://127.0.0.1:9051'
}

def search_ahmia(keyword):
    url = f"https://ahmia.fi/search/?q={keyword}"
    headers = {"User-Agent": "Mozilla/5.0"}
    print(f"[INFO] 正在连接到 Ahmia 索引 ({url}) ...[Clearnet模式]")

    try:
        resp = requests.get(url, headers=headers, timeout=60)  # 不用代理！
    except Exception as e:
        print(f"[ERROR] 访问 Ahmia 失败: {e}")
        sys.exit(1)

    soup = BeautifulSoup(resp.content, "html.parser")
    onion_url = soup.select('cite')   # 直接获取连接
    print(type(onion_url))  # <class 'bs4.element.ResultSet'>
    print(f"[INFO] 共获得 {len(onion_url)} 条初步结果。")
    results = []
    for cite_link in tqdm(onion_url, desc="筛查 .onion 链接"):
        link = cite_link.get_text()
        # print(link)
        if '.onion' in link and link not in results:
            results.append(link)
    return results

# def check_onion_access(onion_url):
#     try:
#         resp = requests.get(onion_url, proxies=TOR_PROXIES, timeout=60)
#         return resp.status_code
#     except Exception as e:
#         return f"ERROR: {e}"

def save_results(results, filename):
    print(f"[INFO] 正在保存结果到 {filename} ...")
    with open(filename, "w", encoding="utf-8") as f:
        for r in results:
            f.write(r + "\n")
    print(f"[INFO] 保存完成，共写入 {len(results)} 条 .onion 站点。")

if __name__ == '__main__':
    keyword = input("输入关键词：")
    print(f"[INFO] 以 '{keyword}' 定向检索 Onion 资源 ...")
    onions = search_ahmia(keyword)
    if onions:
        save_results(onions, filename=f'{keyword}.txt')
        print(f"[SUCCESS] 所有流程完成。链接写入文件。")
    else:
        print("[WARN] 未匹配到任何 onion 链接。")