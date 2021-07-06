'''
分析子图文件得到特征，然后对特征进行分析
'''
import os
import networkx as nx
from pathlib import Path
import threading
import time
from multiprocessing import Process


class RunProcess():
    def __init__(self, id, feature_save_path, apk_subgraph_dir, benign_apk_type, malware_apk_type):
        self.id = id
        self.feature_save_path = feature_save_path
        self.apk_subgraph_dir = apk_subgraph_dir
        self.benign_apk_type = benign_apk_type
        self.malware_apk_type = malware_apk_type

    def run(self):
        print("开始进程：" + str(self.id))
        analyse_subgraph(self.feature_save_path, self.apk_subgraph_dir, self.benign_apk_type, self.malware_apk_type)


class APK:



    def __init__(self, apk_name, apk_path):
        self.apk_name = apk_name
        self.apk_path = apk_path
        self.label_num = 0
        self.feature_vector = [0] * 10000





'''
分析一种(threshold, node_num)下的1)特征数目，2)每种特征分别在恶意和良性中的出现总数，
分析恶意和良性中每个apk的特征情况，包含特征3)稀疏程度，4)特征相关性？

实现思路：首先加载两种类型apk的所有子图，不同节点大小分别进行异构分析(先使用一个列表存储子图)，得到一个有序字典，
字典中键由子图表示，值由一个两个元素的数组组成，数组第一个元素为良性apk中特征出现次数，第二个元素为恶意apk中特征出现次数，完成1),2)实验任务要求

遍历字典的键，将apk中的子图，按照顺序进行异构分析，得到一个特征向量存储起来。这些特征将被存起来，然后分析3）
'''
def analyse_subgraph(feature_save_dir, apk_subgraph_dir, benign_apk_type, malware_apk_type):
    benign_apk_subgraph_dir = os.path.join(apk_subgraph_dir, benign_apk_type)
    malware_apk_subgraph_dir = os.path.join(apk_subgraph_dir, malware_apk_type)

    # 保存所有的子图，按照 key: subgraph  ---- value: (benign_apk_num, malware_apk_num)保存
    subgraph_dict = dict()

    # 用于保存所有apk的名字
    benign_apk_list = os.listdir(benign_apk_subgraph_dir)
    malware_apk_list = os.listdir(malware_apk_subgraph_dir)

    # 用于保存所有的APK类对象
    benign_APK_list = list()
    malware_APK_list = list()

    # 先加载良性的
    for benign_apk in benign_apk_list:
        benign_apk_path = os.path.join(benign_apk_subgraph_dir, benign_apk)
        apk = APK(benign_apk, benign_apk_path)
        gexf_file_list = os.listdir(benign_apk_path)
        for gexf_file in gexf_file_list:
            if gexf_file.startswith("message"):
                continue
            gexf_file_path = os.path.join(benign_apk_path, gexf_file)
            subgraph = nx.read_gexf(gexf_file_path)
            add_subgraph(subgraph, subgraph_dict, apk, 0)
        benign_APK_list.append(apk)
    # 然后加载恶意的
    for malware_apk in malware_apk_list:
        malware_apk_path = os.path.join(malware_apk_subgraph_dir, malware_apk)
        apk = APK(malware_apk, malware_apk_path)
        gexf_file_list = os.listdir(malware_apk_path)
        for gexf_file in gexf_file_list:
            if gexf_file.startswith("message"):
                continue
            gexf_file_path = os.path.join(malware_apk_path, gexf_file)
            subgraph = nx.read_gexf(gexf_file_path)
            add_subgraph(subgraph, subgraph_dict, apk, 1)
        malware_APK_list.append(apk)

    # 1)分析特征数量
    feature_vector_len = len(subgraph_dict)
    if not Path(feature_save_dir).is_dir():
        os.makedirs(feature_save_dir)
    with open(os.path.join(feature_save_dir, "feature_analyse.txt"), "w") as f:
        f.write("feature_vector_len:  {}".format(feature_vector_len))
        #print("{}\\{}\\".format(node_num, threshold) + str(feature_vector_len))
    #print("{}\\{}\\".format(node_num, threshold)+str(feature_vector_len))
    f.close()

    # 2)降序分析各种特征的出现次数

    sorted_benign_subgraph_dict = sorted(subgraph_dict.items(), key=lambda item: item[1][0], reverse=True)
    sorted_malware_subgraph_dict = sorted(subgraph_dict.items(), key=lambda item: item[1][1], reverse=True)

    preType = 0
    preNum = 0
    for subgraph_tuple in sorted_benign_subgraph_dict:
        curType = subgraph_tuple[1][0]
        if curType == preType:
            preNum += 1
        else:
            preType = curType
            preNum = 1
        #nx.write_gexf(subgraph_tuple[0], os.path.join(feature_save_dir, "benign_{}_{}.gexf".format(preType, preNum)))

    preType = 0
    preNum = 0
    for subgraph_tuple in sorted_malware_subgraph_dict:
        curType = subgraph_tuple[1][1]
        if curType == preType:
            preNum += 1
        else:
            preType = curType
            preNum = 1
        #nx.write_gexf(subgraph_tuple[0], os.path.join(feature_save_dir, "malware_{}_{}.gexf".format(preType, preNum)))

    # 3) 将apk的特征按照行的形式打为txt, arff 然后分析其稀疏性
    with open(os.path.join(feature_save_dir, "feature.txt"), "w") as f:
        for apk in benign_APK_list:
            f.write(apk.apk_name + ",")
            cut_list = apk.feature_vector[0:feature_vector_len]
            convert_list = [str(x) for x in cut_list]
            f.write(",".join(convert_list) + ",")
            f.write("benign,")
            f.write(str(apk.label_num))
            f.write("\n")
        for apk in malware_APK_list:
            f.write(apk.apk_name + ",")
            cut_list = apk.feature_vector[0:feature_vector_len]
            convert_list = [str(x) for x in cut_list]
            f.write(",".join(convert_list) + ",")
            f.write("malware,")
            f.write(str(apk.label_num))
            f.write("\n")
    f.close()

    with open(os.path.join(feature_save_dir, "feature.arff"), "w") as f:
        f.write("@relation FanDroid")
        f.write("\n")
        f.write("\n")
        for i in range(0, feature_vector_len):
            f.write("@attribute subgrapph{} numeric".format(i))
            f.write("\n")
        f.write("@attribute isMalware {benign,malware}")
        f.write("\n")
        f.write("\n")
        f.write("@data")
        f.write("\n")
        for apk in benign_APK_list:

            cut_list = apk.feature_vector[0:feature_vector_len]
            convert_list = [str(x) for x in cut_list]
            f.write(apk.apk_name + ",")
            f.write(",".join(convert_list) + ",")
            f.write("benign")
            f.write("\n")
        for apk in malware_APK_list:
            cut_list = apk.feature_vector[0:feature_vector_len]
            convert_list = [str(x) for x in cut_list]
            f.write(apk.apk_name + ",")
            f.write(",".join(convert_list) + ",")
            f.write("malware")
            f.write("\n")
    f.close()




def add_subgraph(subgraph, pattern_dict, apk, index):
    pattern_key_list = list(pattern_dict.keys())
    for i in range(len(pattern_key_list)):
        pattern = pattern_key_list[i]
        matcher = nx.isomorphism.DiGraphMatcher(subgraph, pattern)
        if matcher.is_isomorphic():
            pattern_dict[pattern][index] = pattern_dict[pattern][index] + 1
            apk.feature_vector[i] = 1
            apk.label_num += 1
            return
    pattern_num_list = [0]*2
    pattern_num_list[index] = 1
    pattern_dict[subgraph] = pattern_num_list
    pattern_dict_index = len(pattern_dict) - 1
    apk.feature_vector[pattern_dict_index] = 1
    apk.label_num += 1




if __name__ == "__main__":
    threshold_list = [0.7]
    node_num_list = [6]
    #node_num_list = [3]
    benign_apk_type = 'benign'
    malware_apk_type = 'malware'
    subgraph_dir = 'E:\\oufan\\FanDroid\\data'
    feature_save_dir = "E:\\oufan\\FanDroid\\data\\feature_analyse"
    id = 0
    for threshold in threshold_list:
        for node_num in node_num_list:
            id += 1
            subgraph_dict = dict()
            apk_subgraph_dir = os.path.join(subgraph_dir, str(threshold), str(node_num))
            feature_save_path = os.path.join(feature_save_dir, str(threshold), str(node_num))

            runProcess = RunProcess(id, feature_save_path, apk_subgraph_dir, benign_apk_type, malware_apk_type)
            runProcess.run()
