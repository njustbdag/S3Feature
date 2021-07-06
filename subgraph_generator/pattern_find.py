'''
寻找apk中的三点，四点，五点模式
'''
import networkx as nx
from networkx.algorithms import isomorphism
import os

# 根据已知点造子图
def make_graph(fcg, adj):
    H = nx.DiGraph()
    if len(adj) == 1:
        H.add_node(adj[0])
        return H
    for i in adj:
        for j in adj:
            if i == j:
                continue
            if not H.has_node(i):
                H.add_node(i)
            if not H.has_node(j):
                H.add_node(j)
            if fcg.has_edge(i, j):
                H.add_edge(i, j)
    return H


# 判断这个模式是否是与模式字典中的键异构
def judge_is_Iso(subgraph, apk):
    if not apk.subgraph_dict:
        apk.subgraph_dict[subgraph] = 1
        #apk.subgraph_id_dict[len(apk.subgraph_dict)] = subgraph
        nx.write_gexf(subgraph, os.path.join(apk.save_dir, str(len(apk.subgraph_dict))))
        return False
    for pattern in list(apk.subgraph_dict.keys()):
        matcher = isomorphism.DiGraphMatcher(subgraph, pattern)
        # if isomorphism add number 1
        if matcher.is_isomorphic():
            apk.subgraph_dict[pattern] = apk.subgraph_dict[pattern] + 1
            return True
    apk.subgraph_dict[subgraph] = 1
    nx.write_gexf(subgraph, os.path.join(apk.save_dir, str(len(apk.subgraph_dict))))
    return False

# 寻找子图模式
def search_subgraph_pattern(apk, graph, node_num):
    dapasa_api_set = apk.dapasa_api_set
    pscout_api_set = apk.pscout_api_set
    sen_api_len = len(dapasa_api_set) + len(pscout_api_set)
    if sen_api_len > 500:
        neigh_search_len = 2
    elif sen_api_len > 50:
        if node_num < 6:
            neigh_search_len = 4
        else:
            neigh_search_len = 2
    else:
        if node_num < 6:
            neigh_search_len = 5
        else:
            neigh_search_len = 3
    if node_num == 3:
        neigh_search_len = 8

    subgraph_node_set = set()
    for dapasa_api in dapasa_api_set:
        subgraph_node_set.add(dapasa_api)
        dfs(dapasa_api, graph, node_num, subgraph_node_set, neigh_search_len, apk)
        subgraph_node_set.remove(dapasa_api)

    for pscout_api in pscout_api_set:
        subgraph_node_set.add(pscout_api)
        dfs(pscout_api, graph, node_num, subgraph_node_set, neigh_search_len, apk)
        subgraph_node_set.remove(pscout_api)


# dfs搜索node_num深的图
def dfs(dapasa_api, fcg, node_num, subgraph_node_set, neigh_search_len, apk):
    # 子图节点数量大于规定子图节点数量，返回0,表示超过节点阈值，不找了
    if len(subgraph_node_set) > node_num:
        return
    # 子图节点数量等于规定子图节点数量，打印子图，
    if len(subgraph_node_set) == node_num:
        subgraph = make_graph(fcg, subgraph_node_set)
        judge_is_Iso(subgraph, apk)
        return
    # 子图数量小于规定子图节点数量，搜索。。
    neigh_list = list(fcg.successors(dapasa_api))
    neigh_list.extend(list(fcg.predecessors(dapasa_api)))
    neigh_searched_len = 0
    for neigh_node in neigh_list:
        # 邻居访问过，直接跳过
        if neigh_node in subgraph_node_set:
            continue
        # 访问当前节点，并继续dfs
        subgraph_node_set.add(neigh_node)
        dfs(neigh_node, fcg, node_num, subgraph_node_set, neigh_search_len, apk)
        subgraph_node_set.remove(neigh_node)
        neigh_searched_len += 1
        # 超过节点的访问范围，自动退出
        if neigh_searched_len > neigh_search_len:
            break