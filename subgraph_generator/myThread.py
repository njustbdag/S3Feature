
from fcg_generate import generate_all_apks_method_graph
import threading
import time
import os

class RunThread (threading.Thread):
    def __init__(self, id, apk_type, threshold, node_num, apk_dir):
        threading.Thread.__init__(self)
        self.id = id
        self.apk_type = apk_type
        self.threshold = threshold
        self.node_num = node_num
        self.apk_dir = apk_dir

    def run(self):
        print("开始进程：" + str(self.id))
        if self.apk_type == "malware" or self.apk_type == "benign":
            generate_all_apks_method_graph(self.id, self.apk_type, self.threshold, self.node_num, self.apk_dir)
        elif self.apk_type == "family":
            family_dir = os.listdir(self.apk_dir)
            for family in family_dir:
                family_path = self.apk_dir + '\\' + family
                generate_all_apks_method_graph(self.id, self.apk_type, self.threshold, self.node_num, family_path)

