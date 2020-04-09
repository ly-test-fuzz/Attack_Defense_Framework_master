import os

def get_files(dir_name , file_list , filter_word_list ):
    dirs = []
    for temp_file in os.listdir(dir_name):
        now_file = os.path.join(dir_name , temp_file)
        if os.path.isdir(now_file):
        	  file_list = get_files(now_file , file_list , filter_word_list)
        else:
            for filter_word in filter_word_list:
                if filter_word in temp_file:
                    file_list.append(now_file)
                    break
    return file_list

def waf_setup(cms_path = "" , waf_path = ""):

    file_list = get_files(cms_path , [] ,[".php"])
    print(file_list)
    for file in file_list:
        lines = []
        with open(file , "r" ) as f:
            text = "".join(["<?php include_once(\"%s\");?>" % (waf_path) , f.read()])
        try:
        	with open(file , "w+" ) as f:
            		f.write(text)
		except Exception , e:
			print(e)
			print('[-] write waf failed {}'.format(file))



cms_path = "/var/www/html/8088/web/"
waf_path = "/var/www/html/phpwaf.php"
waf_setup(cms_path , waf_path)
