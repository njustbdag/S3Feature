'''
这个py文件完成三个任务：
1、对apk的粗分析
2、对apk的分类测试，基于2
'''

import networkx as nx
import os
from pathlib import Path
from networkx.algorithms import isomorphism
import matplotlib.pyplot as plt
import numpy as np
from sklearn.ensemble import RandomForestClassifier
import sklearn.ensemble as es
from sklearn.metrics import accuracy_score
from time import *


'''
函数：analyse_multi analyse_single
粗分析：
n-graph：恶意和良性的apk一起分析，将每个apk中的n-graph模式找出来，考虑不同apk的fcg大小不同，所以某种模式在某个apk中出现，则计算一次
分析3-graph中所有(最多13)模式在恶意apk中出现的情况和良性apk出现的情况对比(数量对比，先输出一个表格)
分析4-graph中出现次数够一定阈值(看情况而定)的模式.......
分析5-graph中出现次数够一定阈值(看情况而定)的模式.......
这里analyse_multi是某个模式下对应apk的数目都要计算，而analyse_single是无论apk数目多少，都只计算一
'''

# 打印整个字典的图
def write_graph_dict(graph_dict, path):
    index = 1
    graph_list = list(graph_dict.keys())
    for i in range(0, len(graph_list)):
        for j in range(i + 1, len(graph_list)):
            matcher = isomorphism.DiGraphMatcher(graph_list[i], graph_list[j])
            if matcher.is_isomorphic():
                print(True)
            else:
                print(False)
    for graph in graph_dict:
        plt.subplot(4, 4, index)
        pos = nx.spring_layout(graph)
        nx.draw(graph, pos, with_labels=True)
        if index > 15:
            break
        index += 1
    plt.show()


def read_message(message_path):
    three_graph_dict = dict()
    four_graph_dict = dict()
    five_graph_dict = dict()
    apk_name = None
    node_number = None
    edge_number = None
    fcg_graph_time = None
    dapasa_number = None
    pscout_number = None
    try:
        f = open(message_path, 'r', encoding='utf-8')
        for line in f:
            line = line.strip().replace("\n", "")
            line_list = line.strip().split(':')
            if line.startswith('apk_name'):
                apk_name = line_list[1]
                print(apk_name)
            elif line.startswith('node_number'):
                node_number = line_list[1]
            elif line.startswith('edge_number'):
                edge_number = line_list[1]
            elif line.startswith('fcg_graph_time'):
                fcg_graph_time = line_list[1]
            elif line.startswith('dapasa_number'):
                dapasa_number = line_list[1]
            elif line.startswith('pscout_number'):
                pscout_number = line_list[1]
            else:
                if line.startswith('3:'):
                    three_graph_dict[int(line_list[1])] = int(line_list[2])
                elif line.startswith('4:'):
                    four_graph_dict[int(line_list[1])] = int(line_list[2])
                elif line.startswith('5:'):
                    five_graph_dict[int(line_list[1])] = int(line_list[2])
        return three_graph_dict, four_graph_dict, five_graph_dict
    except FileNotFoundError:
        return three_graph_dict, four_graph_dict, five_graph_dict

# 判断在子图字典中是否有异构的子图
def add_graph_single(graph, graph_dict):
    if len(graph_dict) == 0:
        graph_dict[graph] = 1
        return
    for graph_in_dict in list(graph_dict.keys()):
        matcher = isomorphism.DiGraphMatcher(graph, graph_in_dict)
        if matcher.is_isomorphic():
            graph_dict[graph_in_dict] = graph_dict[graph_in_dict] + 1
            return
    graph_dict[graph] = 1

def add_graph_multi(graph, graph_dict, index, index_graph_dict):
    if len(graph_dict) == 0:
        graph_dict[graph] = index_graph_dict[index]
        return
    for graph_in_dict in list(graph_dict.keys()):
        matcher = isomorphism.DiGraphMatcher(graph, graph_in_dict)
        if matcher.is_isomorphic():
            graph_dict[graph_in_dict] = graph_dict[graph_in_dict] + index_graph_dict[index]
            return
    graph_dict[graph] = index_graph_dict[index]


# 输入恶意或者良性apk的subgraph所在目录，对每个apk的所有subgraph搜索，
# 输出3-graph的字典，4-graph的字典，5-graph的字典，键值对为:subgraph--number
def get_subgraph_single(subgraph_dir_path):
    three_graph_dict = dict()
    four_graph_dict = dict()
    five_graph_dict = dict()
    apk_list = os.listdir(subgraph_dir_path)
    # 加载apk目录
    apk_index = 0
    for apk in apk_list:
        apk_path = subgraph_dir_path + '\\' + apk
        apk_graph_list = os.listdir(apk_path)
        '''
        # 先加载message文件
        message_path = subgraph_dir_path + '\\' + apk + '\\' + 'message.txt'
        file = Path(message_path)
        if not file.exists():
            print("error: do not find message.txt in:"+apk_path)
            continue
        # 子图节点为3个，4个，5个的字典，键值对为:subgraph_index--number
        three_index_dict, four_index_dict, five_index_dict = read_message(message_path)
        '''
        # 加载apk目录下的subgraph目录
        for apk_graph in apk_graph_list:
            # 加载subgraph
            if apk_graph.endswith('.gexf'):
                apk_graph_path = apk_path + '\\' + apk_graph
                if apk_graph.startswith('3-'):
                    add_graph_single(nx.read_gexf(apk_graph_path), three_graph_dict)
                elif apk_graph.startswith('4-'):
                    add_graph_single(nx.read_gexf(apk_graph_path), four_graph_dict)
                elif apk_graph.startswith('5-'):
                    add_graph_single(nx.read_gexf(apk_graph_path), five_graph_dict)
        print(apk_index)
        apk_index += 1
    return three_graph_dict, four_graph_dict, five_graph_dict

def get_subgraph_multi(subgraph_dir_path):
    three_graph_dict = dict()
    four_graph_dict = dict()
    five_graph_dict = dict()
    apk_list = os.listdir(subgraph_dir_path)
    # 加载apk目录
    apk_index = 0
    for apk in apk_list:
        apk_path = subgraph_dir_path + '\\' + apk
        apk_graph_list = os.listdir(apk_path)

        # 先加载message文件
        message_path = subgraph_dir_path + '\\' + apk + '\\' + 'message.txt'
        file = Path(message_path)
        if not file.exists():
            print("error: do not find message.txt in:"+apk_path)
            continue
        # 子图节点为3个，4个，5个的字典，键值对为:subgraph_index--number
        three_index_dict, four_index_dict, five_index_dict = read_message(message_path)
        # 加载apk目录下的subgraph目录
        for apk_graph in apk_graph_list:
            # 加载subgraph
            if apk_graph.endswith('.gexf'):
                apk_graph_path = apk_path + '\\' + apk_graph
                apk_graph_path_list = apk_graph[:-5].split('-')
                if apk_graph.startswith('3-'):
                    add_graph_multi(nx.read_gexf(apk_graph_path), three_graph_dict, int(apk_graph_path_list[1]), three_index_dict)
                elif apk_graph.startswith('4-'):
                    add_graph_multi(nx.read_gexf(apk_graph_path), four_graph_dict, int(apk_graph_path_list[1]), four_index_dict)
                elif apk_graph.startswith('5-'):
                    add_graph_multi(nx.read_gexf(apk_graph_path), five_graph_dict, int(apk_graph_path_list[1]), five_index_dict)
        print(apk_index)
        apk_index += 1
    return three_graph_dict, four_graph_dict, five_graph_dict

def get_iso_graph(graph, graph_dict):
    for graph_in_dict in list(graph_dict.keys()):
        matcher = isomorphism.DiGraphMatcher(graph, graph_in_dict)
        if matcher.is_isomorphic():
            return graph_in_dict
    return None


def write_graph(sorted_graph_dict, other_graph_dict, top_file_path, gexf_path, graph_type):
    f = open(top_file_path, 'a+')
    f.write("graph_type, index, graph in this type number, graph in other type number")
    f.write("\n")
    index = 0
    for graph, value in list(sorted_graph_dict):
        nx.write_gexf(graph, gexf_path.format(index))
        iso_graph = get_iso_graph(graph, other_graph_dict)
        write_line = str(graph_type) + ',' + str(index) + ',' + str(value)
        if iso_graph is None:
            write_line = write_line + ',0'
        else:
            malware_number = other_graph_dict[iso_graph]
            write_line = write_line + ',' + str(malware_number)
        f.write(write_line)
        f.write("\n")
        index += 1
    f.close()

# 这个函数分析的结果在pattern_multi文件夹，某种模式在apk中出现几次就计几次
def analyse_multi():
    benign_apk_path = '..\\data\\benign'
    malware_apk_path = '..\\data\\malware'
    benign_three_graph_dict, benign_four_graph_dict, benign_five_graph_dict = get_subgraph_multi(benign_apk_path)
    malware_three_graph_dict, malware_four_graph_dict, malware_five_graph_dict = get_subgraph_multi(malware_apk_path)
    sorted_benign_three_graph_dict = sorted(benign_three_graph_dict.items(), key=lambda item: item[1], reverse=True)
    sorted_benign_four_graph_dict = sorted(benign_four_graph_dict.items(), key=lambda item: item[1], reverse=True)
    sorted_benign_five_graph_dict = sorted(benign_five_graph_dict.items(), key=lambda item: item[1], reverse=True)

    sorted_malware_three_graph_dict = sorted(malware_three_graph_dict.items(), key=lambda item: item[1], reverse=True)
    sorted_malware_four_graph_dict = sorted(malware_four_graph_dict.items(), key=lambda item: item[1], reverse=True)
    sorted_malware_five_graph_dict = sorted(malware_five_graph_dict.items(), key=lambda item: item[1], reverse=True)

    # write_graph_dict(benign_three_graph_dict, "1")
    # 先打印看看有多少种，最小的有多少
    print("benign_three_graph_type:" + str(len(benign_three_graph_dict.items())))
    print("benign_four_graph_type:" + str(len(benign_four_graph_dict.items())))
    print("benign_five_graph_type:" + str(len(benign_five_graph_dict.items())))
    print("malware_three_graph_type:" + str(len(malware_three_graph_dict.items())))
    print("malware_four_graph_type:" + str(len(malware_four_graph_dict.items())))
    print("malware_five_graph_type:" + str(len(malware_five_graph_dict.items())))

    top_file_path = '..\\data\\pattern_multi\\benign_top_20.txt'
    gexf_path = '..\\data\\pattern_multi\\benign\\3\\{}.gexf'
    write_graph(sorted_benign_three_graph_dict, malware_three_graph_dict, top_file_path, gexf_path, '3')

    gexf_path = '..\\data\\pattern_multi\\benign\\4\\{}.gexf'
    write_graph(sorted_benign_four_graph_dict, malware_four_graph_dict, top_file_path, gexf_path, '4')

    gexf_path = '..\\data\\pattern_multi\\benign\\5\\{}.gexf'
    write_graph(sorted_benign_five_graph_dict, malware_five_graph_dict, top_file_path, gexf_path, '5')

    top_file_path = '..\\data\\pattern_multi\\malware_top_20.txt'
    gexf_path = '..\\data\\pattern_multi\\malware\\3\\{}.gexf'
    write_graph(sorted_malware_three_graph_dict, benign_three_graph_dict, top_file_path, gexf_path, '3')

    gexf_path = '..\\data\\pattern_multi\\malware\\4\\{}.gexf'
    write_graph(sorted_malware_four_graph_dict, benign_four_graph_dict, top_file_path, gexf_path, '4')

    gexf_path = '..\\data\\pattern_multi\\malware\\5\\{}.gexf'
    write_graph(sorted_malware_five_graph_dict, benign_five_graph_dict, top_file_path, gexf_path, '5')

# 这个函数分析的结果在pattern_single文件夹，某种模式在某个apk中无论出现几次都计算一次
def analyse_single():
    benign_apk_path = '..\\data\\benign'
    malware_apk_path = '..\\data\\malware'
    benign_three_graph_dict, benign_four_graph_dict, benign_five_graph_dict = get_subgraph_single(benign_apk_path)
    malware_three_graph_dict, malware_four_graph_dict, malware_five_graph_dict = get_subgraph_single(malware_apk_path)
    sorted_benign_three_graph_dict = sorted(benign_three_graph_dict.items(), key=lambda item: item[1], reverse=True)
    sorted_benign_four_graph_dict = sorted(benign_four_graph_dict.items(), key=lambda item: item[1], reverse=True)
    sorted_benign_five_graph_dict = sorted(benign_five_graph_dict.items(), key=lambda item: item[1], reverse=True)

    sorted_malware_three_graph_dict = sorted(malware_three_graph_dict.items(), key=lambda item: item[1], reverse=True)
    sorted_malware_four_graph_dict = sorted(malware_four_graph_dict.items(), key=lambda item: item[1], reverse=True)
    sorted_malware_five_graph_dict = sorted(malware_five_graph_dict.items(), key=lambda item: item[1], reverse=True)

    write_graph_dict(benign_three_graph_dict, "1")
    # 先打印看看有多少种，最小的有多少
    print("benign_three_graph_type:"+str(len(benign_three_graph_dict.items())))
    print("benign_four_graph_type:" + str(len(benign_four_graph_dict.items())))
    print("benign_five_graph_type:" + str(len(benign_five_graph_dict.items())))
    print("malware_three_graph_type:" + str(len(malware_three_graph_dict.items())))
    print("malware_four_graph_type:" + str(len(malware_four_graph_dict.items())))
    print("malware_five_graph_type:" + str(len(malware_five_graph_dict.items())))

    top_file_path = '..\\data\\pattern_single\\benign_top_20.txt'
    gexf_path = '..\\data\\pattern_single\\benign\\3\\{}.gexf'
    write_graph(sorted_benign_three_graph_dict, malware_three_graph_dict, top_file_path, gexf_path, '3')

    gexf_path = '..\\data\\pattern_single\\benign\\4\\{}.gexf'
    write_graph(sorted_benign_four_graph_dict, malware_four_graph_dict, top_file_path, gexf_path, '4')

    gexf_path = '..\\data\\pattern_single\\benign\\5\\{}.gexf'
    write_graph(sorted_benign_five_graph_dict, malware_five_graph_dict, top_file_path, gexf_path, '5')

    top_file_path = '..\\data\\pattern_single\\malware_top_20.txt'
    gexf_path = '..\\data\\pattern_single\\malware\\3\\{}.gexf'
    write_graph(sorted_malware_three_graph_dict, benign_three_graph_dict, top_file_path, gexf_path, '3')

    gexf_path = '..\\data\\pattern_single\\malware\\4\\{}.gexf'
    write_graph(sorted_malware_four_graph_dict, benign_four_graph_dict, top_file_path, gexf_path, '4')

    gexf_path = '..\\data\\pattern_single\\malware\\5\\{}.gexf'
    write_graph(sorted_malware_five_graph_dict, benign_five_graph_dict, top_file_path, gexf_path, '5')


# 加载一个目录下的前16个图
def load_graph(dir_path):
    graph_path_list = os.listdir(dir_path)
    index = 1
    for graph_path in graph_path_list:
        path = dir_path + '\\' + graph_path
        graph = nx.read_gexf(path)
        plt.subplot(4, 4, index)
        pos = nx.spring_layout(graph)
        nx.draw(graph, pos, with_labels=False)
        if index > 15:
            break
        index += 1
    plt.show()

'''
函数：classify_multi classify_single
分类测试：
将所有apk的模式图加载作为特征，每个apk对应特征下的数目作为特征向量，训练分类器，得出分类准确率
这里classify_multi分类是某个模式下对应apk的数目都要计算，而classify_single是无论apk数目多少，都只计算一
'''
three_graph_list = []
four_graph_list = []
five_graph_list = []

apk_array = None

# 判断子图模式是否与某个列表中的模式同构，没有则加入列表
def add_pattern(graph_in_pattern, graph_list):
    if not graph_list:
        graph_list.append(graph_in_pattern)
        return
    else:
        for graph in graph_list:
            matcher = isomorphism.DiGraphMatcher(graph_in_pattern, graph)
            if matcher.is_isomorphic():
                return
        graph_list.append(graph_in_pattern)

# 加载一个目录下的子图模式
def load_pattern(pattern_dir, graph_list):
    pattern_list = os.listdir(pattern_dir)
    for pattern in pattern_list:
        pattern_path = pattern_dir + '\\' + pattern
        graph_in_pattern = nx.read_gexf(pattern_path)
        add_pattern(graph_in_pattern, graph_list)

# 先加载子图模式特征
def get_pattern_feature(benign_graph_dir, malware_graph_dir):
    global three_graph_list  # 需要使用 global 关键字声明
    global four_graph_list  # 需要使用 global 关键字声明
    global five_graph_list  # 需要使用 global 关键字声明
    # 先加载良性的
    benign_graph_type_list = os.listdir(benign_graph_dir)
    for benign_graph_type in benign_graph_type_list:
        benign_graph_type_path = benign_graph_dir + '\\' + benign_graph_type
        if benign_graph_type_path.endswith('3'):
            load_pattern(benign_graph_type_path, three_graph_list)
        elif benign_graph_type_path.endswith('4'):
            load_pattern(benign_graph_type_path, four_graph_list)
        elif benign_graph_type_path.endswith('5'):
            load_pattern(benign_graph_type_path, five_graph_list)

    # 再加载恶意的
    malware_graph_type_list = os.listdir(malware_graph_dir)
    for malware_graph_type in malware_graph_type_list:
        malware_graph_type_path = malware_graph_dir + '\\' + malware_graph_type
        if malware_graph_type_path.endswith('3'):
            load_pattern(malware_graph_type_path, three_graph_list)
        elif malware_graph_type_path.endswith('4'):
            load_pattern(malware_graph_type_path, four_graph_list)
        elif malware_graph_type_path.endswith('5'):
            load_pattern(malware_graph_type_path, five_graph_list)

def find_pattern(graph, graph_list, index, index_graph_dict, apk_index, start_index):
    global apk_array  # 需要使用 global 关键字声明
    graph_index = 0
    for graph_in_list in graph_list:
        matcher = isomorphism.DiGraphMatcher(graph, graph_in_list)
        if matcher.is_isomorphic():
            apk_array[apk_index, start_index + graph_index] = index_graph_dict[index]
            return
        graph_index += 1


def get_apk_pattern(apk_index, apk_path):
    global three_graph_list  # 需要使用 global 关键字声明
    global four_graph_list  # 需要使用 global 关键字声明
    global five_graph_list  # 需要使用 global 关键字声明
    list_length = len(three_graph_list) + len(four_graph_list) + len(five_graph_list)
    # 先加载message文件
    message_path = apk_path + '\\' + 'message.txt'
    file = Path(message_path)
    if not file.exists():
        print("error: do not find message.txt in:" + apk_path)

    # 子图节点为3个，4个，5个的字典，键值对为:subgraph_index--number
    three_index_dict, four_index_dict, five_index_dict = read_message(message_path)
    apk_graph_list = os.listdir(apk_path)
    # 加载apk目录下的subgraph目录
    for apk_graph in apk_graph_list:
        # 加载subgraph
        if apk_graph.endswith('.gexf'):
            apk_graph_path = apk_path + '\\' + apk_graph
            apk_graph_path_list = apk_graph[:-5].split('-')
            if apk_graph.startswith('3-'):
                find_pattern(nx.read_gexf(apk_graph_path), three_graph_list, int(apk_graph_path_list[1]),
                                three_index_dict, apk_index, 0)
            elif apk_graph.startswith('4-'):
                find_pattern(nx.read_gexf(apk_graph_path), four_graph_list, int(apk_graph_path_list[1]),
                                four_index_dict, apk_index, len(three_graph_list))
            elif apk_graph.startswith('5-'):
                find_pattern(nx.read_gexf(apk_graph_path), five_graph_list, int(apk_graph_path_list[1]),
                                five_index_dict, apk_index, len(three_graph_list) + len(four_graph_list))

def classify():
    benign_graph_dir = '..\\data\\pattern_multi\\benign'
    malware_graph_dir = '..\\data\\pattern_multi\\malware'
    get_pattern_feature(benign_graph_dir, malware_graph_dir)

    global three_graph_list  # 需要使用 global 关键字声明
    global four_graph_list  # 需要使用 global 关键字声明
    global five_graph_list  # 需要使用 global 关键字声明
    global apk_array  # 需要使用 global 关键字声明
    print("three_graph_list number:" + str(len(three_graph_list)))
    print("four_graph_list number:" + str(len(four_graph_list)))
    print("five_graph_list number:" + str(len(five_graph_list)))
    print("load pattern feature successfully")
    # 初始化数组
    graph_list_length = len(three_graph_list) + len(four_graph_list) + len(five_graph_list)
    apk_array = np.zeros((4000, graph_list_length + 1), dtype=np.int16)
    # 前两千个是良性apk, 后两千个是良性apk
    print(graph_list_length)
    for i in range(2000, 4000):
        apk_array[i, graph_list_length] = 1
    benign_apk_dir = '..\\data\\benign'
    malware_apk_dir = '..\\data\\malware'
    benign_apk_list = os.listdir(benign_apk_dir)
    malware_apk_list = os.listdir(malware_apk_dir)
    index = 0
    for benign_apk in benign_apk_list:
        benign_apk_path = benign_apk_dir + '\\' + benign_apk
        get_apk_pattern(index, benign_apk_path)
        index += 1
        print("benign:"+str(index))
    for malware_apk in malware_apk_list:
        malware_apk_path = malware_apk_dir + '\\' + malware_apk
        get_apk_pattern(index, malware_apk_path)
        index += 1
        print("malware:" + str(index))
    # 输出到txt
    feature_out_path = '..\\data\\pattern_multi\\feature.txt'
    f = open(feature_out_path, 'a+')
    for i in range(0, 2000):
        line = 'benign,'
        for j in range(graph_list_length + 1):
            line += str(apk_array[i, j]) + ','
        f.write(line)
        f.write('\n')
    for i in range(2000, 4000):
        line = 'malware,'
        for j in range(graph_list_length + 1):
            line += str(apk_array[i, j]) + ','
        f.write(line)
        f.write('\n')


    # 开始训练
    x = apk_array[:, :-1]
    y = apk_array[:, -1:]
    train_size = int(len(x) * 0.7)
    train_x, test_x, train_y, test_y = x[:train_size], x[train_size:], y[:train_size], y[train_size:]

    # 训练模型
    model = RandomForestClassifier(n_estimators = 10)
    model.fit(train_x, train_y)

    # 模型测试
    pred_test_y = model.predict(test_x)

    # 模型评估
    print('accuracy：', accuracy_score(test_y, pred_test_y))


def analyse_time(apk_dir, feature_dir, type):
    feature_list = os.listdir(feature_dir)
    apk_list = os.listdir(apk_dir)
    time_path = "E:\\oufan\\FanDroid\\time\\{}".format(type)
    graph_list = []
    for feature in feature_list:
        feature_path = feature_dir + '\\' + feature
        if feature.startswith("benign") or feature.startswith("malware"):
            graph_list.append(nx.read_gexf(feature_path))
    for apk in apk_list:
        apk_path = apk_dir + '\\' + apk
        file_list = os.listdir(apk_path)
        subgraph_list = []
        for file in file_list:
            subgraph_path = apk_path + '\\' + file
            if file.isdigit():
                subgraph_list.append(nx.read_gexf(subgraph_path))
        start_time = time()
        judge(graph_list, subgraph_list)
        cost_time = (time() - start_time)
        write_path = time_path + '\\' + apk + '\\message.txt'
        with open(write_path, "a+") as f:
            f.write("\n")
            f.write("analyse_time:" + str(cost_time))

def judge(graph_list, subgraph_list):
    feature_list = []
    for graph in graph_list:
        for subgraph in subgraph_list:
            matcher = nx.isomorphism.DiGraphMatcher(graph, subgraph)
            if matcher.is_isomorphic():
                feature_list.append(1)
    return feature_list



if __name__ == '__main__':
    #pass

    # classify()

    # analyse_multi()
    #analyse_single()
    # load_graph('..\\data\\pattern_multi\\malware\\5')
    #analyse_time("E:\\oufan\\FanDroid\\data\\0.6\\5\\family", "E:\\oufan\\FanDroid\\data\\feature_analyse\\0.6\\5", 5)
    analyse_time("E:\\oufan\\FanDroid\\data\\0.6\\6\\family", "E:\\oufan\\FanDroid\\data\\feature_analyse\\0.6\\6", 6)
    analyse_time("E:\\oufan\\FanDroid\\data\\0.6\\7\\family", "E:\\oufan\\FanDroid\\data\\feature_analyse\\0.6\\7", 7)

