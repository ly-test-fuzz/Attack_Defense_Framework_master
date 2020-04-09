import os
from urllib.parse import urlparse

cwd_path = None


def log_success(log):
    print(("[+] %s" % log ))

def log_fail(log):
    print(("[-] %s" % log ))

def log_info(log):
    print("[*] %s" % log)

def log_split():
    print("_" * 50)

def get_exp_path(exp_name):
    global cwd_path
    if cwd_path == None:
        cwd_path = os.getcwd()
    return os.path.join(cwd_path , "exp" , exp_name , "exp.py")

def get_host_port(url):
    _url = urlparse(url)
    host = _url.hostname
    port = _url.port
    if port is None:
        port = 80
    port = str(port)
    return host , port

def get_exp_static_file_path(exp_name): # 获得 exp 的 静态文件路径
    path = get_exp_path(exp_name)
    return os.path.dirname(path)
