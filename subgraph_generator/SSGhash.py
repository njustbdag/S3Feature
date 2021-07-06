import networkx as nx
import os
from time import *

sensitive_set = set()

'''
当前的特征是可能包含也可能不包含敏感API数量的，也可能有多个敏感API数量
hash编码的方式：
节点数量，敏感API数量，敏感节点的标签，普通节点的标签
'''
def addSensitiveApi(sensitive_path_list):
    for sensitive_path in sensitive_path_list:
        with open(sensitive_path, 'r') as f:
            for line in f:
                line = line.strip().replace("\n", "")
                sensitive_set.add(line)




def getNodeFromGraph(ssg):
    node_list = ssg.nodes()
    normal_list = list()
    sensitive_list = list()
    for node in node_list:
        if node in sensitive_set:
            sensitive_list.append(node)
        else:
            normal_list.append(node)
    sensitive_list.sort()
    normal_list.sort()
    return sensitive_list, normal_list

def SSGtoHash(ssg_path):
    ssg = nx.read_gexf(ssg_path)
    start_time = time()
    sensitive_list, normal_list = getNodeFromGraph(ssg)
    sensitive_len = len(sensitive_list)
    normal_len = len(normal_list)
    sensitive_string = ""
    normal_string = ""
    for sensitive_api in sensitive_list:
        sensitive_string += sensitive_api
    for normal_api in normal_list:
        normal_string += normal_api
    ssgHash = str(sensitive_len) + ',' +  str(normal_len) + ',' + sensitive_string +',' + normal_string
    used_time = time() - start_time
    return ssgHash, used_time


def replaceHash(apk_path):
    ssg_list = os.listdir(apk_path)
    time_list = []
    with open(apk_path+"\\ssgHash.txt", 'a', encoding='utf-8') as f:
        for ssg in ssg_list:
            if ssg.endswith(".txt"):
                continue
            ssg_path = apk_path + "\\" + ssg
            ssgHash, used_time = SSGtoHash(ssg_path)
            time_list.append(used_time)
            f.write(ssgHash)
            f.write("\n")
    f.close()
    with open(apk_path+"\\ssgHashTime.txt", 'a') as f:
        time_add = 0
        for time_use in time_list:
            time_add += time_use
            f.write(str(time))
            f.write("\n")
        f.write("add_time:"+str(time_add))
    f.close()

if __name__ == '__main__':
    dapasa_api_path = "E:\\oufan\\FanDroid\\data\\sensitiveApiFromDAPASA.txt"
    pscout_api_path = "E:\\oufan\\FanDroid\\data\\sensitiveApiFromPscout.txt"
    sensitive_path_list = list()
    sensitive_path_list.append(dapasa_api_path)
    sensitive_path_list.append(pscout_api_path)
    addSensitiveApi(sensitive_path_list)
    threshold_list = [0.6]
    node_num_list = [5, 6, 7]
    apk_dir = "E:\\oufan\\FanDroid\\data"

    for threshold in threshold_list:
        for node_num in node_num_list:
            family_dir = "E:\\oufan\\FanDroid\\data\\{}\\{}\\benign".format(threshold, node_num)
            apk_list = os.listdir(family_dir)
            for apk in apk_list:
                apk_path = family_dir + "\\" + apk
                replaceHash(apk_path)





