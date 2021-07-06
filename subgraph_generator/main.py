'''
第一个模块的启动py文件
完成对apk的fcg图构造，根据敏感API选择子图
根据训练样本完成对特征的构造
'''
from fcg_generate import generate_all_apks_method_graph
import threading
import time
from myThread import RunThread
from multiprocessing import Process
import os



if __name__ == '__main__':
    threshold_list = [0.6]
    node_num_list = [5, 6, 7]
    #node_num_list = [3, 4]
    benign_apk_type = "benign"
    benign_apk_dir = "E:\\oufan\\decodedApk\\benignApk\\benignApk"
    malware_apk_type = "malware"
    malware_apk_dir = "E:\\oufan\\decodedApk\\malwareApk\\Airpush"
    family_apk_type = "family"
    family_apk_dir = "E:\\oufan\\decodedApk\\malwareFamilyApk"
    id = 0
    #task(1, benign_apk_type, 1.0, 7, benign_apk_dir)
    #process1 = Process(target=task, args=(id, benign_apk_type, threshold, node_num, benign_apk_dir))
    for threshold in threshold_list:
        for node_num in node_num_list:
            #runThread = RunThread(id, family_apk_type, threshold, node_num, family_apk_dir)
            #runThread.start()
            family_dir = os.listdir(family_apk_dir)
            for family in family_dir:
                family_path = family_apk_dir + '\\' + family
                generate_all_apks_method_graph(id, family_apk_type, threshold, node_num, family_path)

    print("all processs end!!!")
