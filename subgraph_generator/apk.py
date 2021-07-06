'''
定义apk的属性
'''
import networkx as nx
from sen_api_generate import get_api_set

class Apk:
    def __init__(self, apk_name, apk_type, threshold, save_dir):
        # apk的基本信息统计
        self.apk_name = apk_name
        self.apk_type = apk_type
        self.node_number = 0
        self.edge_number = 0
        self.fcg_graph_time = 0
        self.pattern_find_time = 0
        self.save_dir = save_dir
        self.dapasa_api_set = set()
        self.pscout_api_set = set()

        # 存储子图的总数，键值对为:子图--数目
        self.subgraph_dict= dict()

        # 存储子图的存在磁盘上的路径名称，键值对为:id--子图
        # 可以存储到文件，方便后期的信息统计
        self.subgraph_id_dict = dict()

        # 用于比对的敏感API部分
        self.sen_dapasa_api_set = get_api_set("E:\\oufan\\FanDroid\\data\\sensitiveApiFromDAPASA.txt", threshold)
        self.sen_pscout_api_set = get_api_set("E:\\oufan\\FanDroid\\data\\sensitiveApiFromPscout.txt", threshold)



