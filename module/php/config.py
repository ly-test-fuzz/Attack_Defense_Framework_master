#coding:utf-8
import configparser
import os
import traceback
from Attack_Defense_Framework_master import debug
from module.tool import log_fail

salt_key = "fantasy"
wait_time = 60
shell_timeout = 1 # core.php.shell


shell_conf_path = os.path.join( os.getcwd() , "module" , "php" , "shell.conf")

shell_key_list_table = "shell_key_list"

def save_shell_conf(shell_conf):
    global shell_conf_path,shell_key_list_table
    
    try:
        config = configparser.ConfigParser()
        # set shell_key_list table
        shell_conf_keys = list(shell_conf.keys())
        shell_conf_len = len(shell_conf_keys)
        config[shell_key_list_table] = {
            'shell_key_len' : shell_conf_len
        }
        
        for i in range(shell_conf_len):
            config[shell_key_list_table]["shell_key%d" % i] = shell_conf_keys[i]       
        # set shell conf detail
        for shell_key , shell_dict in list(shell_conf.items()):
            shell_len = len(shell_dict['shell_list'])
            config[shell_key] = {
                    "shell_len" : len(shell_dict["shell_list"]),
                    "shell_password" : shell_dict["shell_password"]
                }
            for shell_index in range(shell_len):
                config[shell_key]["shell%d" % shell_index] = shell_dict['shell_list'][shell_index]
        with open(shell_conf_path , "w+") as f:
            config.write(f)
        
    except Exception as e:
        log_fail("save conf fail")
        traceback.print_exc()
        return False
    return True

def get_shell_from_conf():
    global shell_conf_path,shell_key_list_table

    # init shell_conf
    shell_conf = {}
    try:
        # init configparser object
        config = configparser.ConfigParser()
        config.read(shell_conf_path ,encoding = 'utf-8')
    
        # write shell_key_list  table
        shell_key_list_len = int(config[shell_key_list_table]['shell_key_len'])
        shell_key_list = [config[shell_key_list_table]["shell_key%d" % i] for i in range(shell_key_list_len)]

        # write shell_key_detail
        for shell_key in shell_key_list:
            shell_len = int(config[shell_key]["shell_len"])
            shell_conf[shell_key] = {
                    "shell_list": [config[shell_key]["shell%d" % i] for i in range(shell_len) ],
                    "shell_password" : config[shell_key]["shell_password"]
                }
    except Exception as e:
        log_fail("get conf fail")

        # for i , j in config.items():
        #     print(i , j)
        if debug is True:
            traceback.print_exc()
        return {}
    if debug is True:
        print(shell_conf)
    return shell_conf

if __name__ == "__main__":
    save_shell_conf()