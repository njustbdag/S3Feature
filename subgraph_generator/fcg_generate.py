from method_generator import gen_call_graph
from apk import Apk
import os
import networkx as nx
import matplotlib.pyplot as plt
from pathlib import Path
from pattern_find import search_subgraph_pattern
from time import *

# 测试生成的apk是否有敏感api
def test_api(apk):
    for api in apk.dapasa_api_list:
        print(api)
    for api in apk.pscout_api_list:
        print(api)

# 输出apk的信息到文件
def write_apk_message(apk):
    message_path = os.path.join(apk.save_dir, "message.txt")
    with open(message_path, "w") as f:
        f.write("apk_name:" + apk.apk_name)
        f.write("\n")
        f.write("node_number:" + str(apk.node_number))
        f.write("\n")
        f.write("edge_number:" + str(apk.edge_number))
        f.write("\n")
        f.write("fcg_graph_time:" + str(apk.fcg_graph_time))
        f.write("\n")
        f.write("pattern_find_time:" + str(apk.pattern_find_time))
        f.write("\n")
        f.write("dapasa_number:" + str(len(apk.dapasa_api_set)))
        f.write("\n")
        f.write("pscout_number:" + str(len(apk.pscout_api_set)))
        f.write("\n")
        f.write("subgraph_number:" + str(len(apk.subgraph_dict)))
    f.close()

# 生成所有apk的函数调用图,指定apk所在目录，表明这个目录下的apk类型
def generate_all_apks_method_graph(id, apk_type, threshold, node_num, apk_dir):
    try:
        file = Path(apk_dir)
        my_abs_path = file.resolve()
    except FileNotFoundError:
        # 不存在
        print("file or dir not exist")
        return
    else:
        typeApkFiles = os.listdir(apk_dir)
        for typeApkFile in typeApkFiles:
            print(typeApkFile)
            smali_loc = apk_dir + '\\' + typeApkFile
            apk_name = typeApkFile
            save_dir = 'E:\\oufan\\FanDroid\\data\\{}\\{}\\{}\\{}'.format(threshold, node_num, apk_type, apk_name)
            if not Path(save_dir).is_dir():
                os.makedirs(save_dir)
            print(apk_name)
            apk = Apk(apk_name, apk_type, threshold, save_dir)
            # 生成FCG图
            fcg_start_time = time()
            graph = generate_apk_method_graph(smali_loc, apk)
            print(str(id)+" generate apk fcg successfully")
            apk.fcg_graph_time = (time() - fcg_start_time)
            # test_api(apk)

            # 先创建一个存储apk信息的目录

            pattern_start_time = time()

            # 寻找子图模式
            search_subgraph_pattern(apk, graph, node_num)


            apk.pattern_find_time = (time() - pattern_start_time)

            print(str(id)+"find apk pattern successfully")

            # 统计信息，输出到文件
            write_apk_message(apk)
            # 展示一下生成的子图
            # print_opcode_graph(apk)



# 生成单个apk的函数调用图
def generate_apk_method_graph(smali_loc, apk):
    # 生成函数调用图
    sfcg = gen_call_graph(smali_loc, apk)
    # nx.write_gexf(sfcg, '.\\data\\' + type + 'ApkGexf\\{}.gexf'.format(typeApkFile))
    print("generating fcg graph over")
    return sfcg


# 生成的子图展示代码
def print_opcode_graph(apk):
    index = 1
    sorted_three_list = sorted(apk.three_graph_dict.items(), key=lambda item:item[1], reverse=True)
    sorted_four_list = sorted(apk.four_graph_dict.items(), key=lambda item: item[1], reverse=True)
    sorted_five_list = sorted(apk.five_graph_dict.items(), key=lambda item: item[1], reverse=True)
    three_index= 0
    for graph,value in list(sorted_three_list):
        plt.subplot(3, 3, index)
        print("three-graph-sorted:"+str(value))
        pos = nx.spring_layout(graph)
        nx.draw(graph, pos, with_labels=True)
        index += 1
        three_index += 1
        if three_index > 2:
            break
    four_index = 0
    for graph,value in list(sorted_four_list):
        plt.subplot(3, 3, index)
        print("four-graph-sorted:"+str(value))
        pos = nx.spring_layout(graph)
        nx.draw(graph, pos, with_labels=True)
        index += 1
        four_index += 1
        if four_index > 2:
            break
    five_index = 0
    for graph,value in list(sorted_five_list):
        plt.subplot(3, 3, index)
        print("five-graph-sorted:"+str(value))
        pos = nx.spring_layout(graph)
        nx.draw(graph, pos, with_labels=True)
        index += 1
        five_index += 1
        if five_index > 2:
            break
    plt.show()


