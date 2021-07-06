import shutil
import os
import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path
import random
import scipy
from scipy import signal

def copy_message(dir_path):
    node_num_list = os.listdir(dir_path)
    for node_num in range(5, 8):
        benign_dir_path = dir_path + "\\" + str(node_num)+"\\family"
        benign_apk_list = os.listdir(benign_dir_path)
        for benign_apk in benign_apk_list:
            benign_message_path = benign_dir_path + "\\" + benign_apk + "\\" +  "message.txt"
            save_dir = "E:\\oufan\\FanDroid\\time\\{}\\{}".format(node_num, benign_apk)
            if not Path(save_dir).is_dir():
                os.makedirs(save_dir)
            save_file = save_dir + "\\message.txt"
            shutil.copyfile(benign_message_path, save_file)

def analyse_pattern_time(node_num):
    apk_dir = "..\\time\\{}".format(node_num)
    apk_list = os.listdir(apk_dir)
    fcg_time_list = list()
    node_number_list = list()
    index = 0
    average_time = 0
    for apk in apk_list:
        message_path = apk_dir + "\\" + apk + "\\message.txt"
        f = open(message_path, "r")
        for line in f:
            if line.startswith("node_number"):
                array = line.strip().replace("\n", "").split(":")
                node_number = int(array[1])
                node_number_list.append(node_number)
                # if node_number in fcg_time_dict:
                # print("node_number exist {}".format(benign_apk))
                # break
            if line.startswith("pattern_find_time"):
                array = line.strip().replace("\n", "").split(":")
                fcg_time = float(array[1])
                average_time += fcg_time
                '''
                if fcg_time > 100:
                    fcg_time = float(array[1]) / 1.5
                if index > 20000:
                    fcg_time += random.random()
                '''
                #if fcg_time > 50:
                    #node_number_list.pop(-1)
                    #continue
                fcg_time_list.append(fcg_time)
                index += 1
    average_time /= len(fcg_time_list)
    print("aver:"+str(average_time))
    if (len(node_number_list) == len(fcg_time_list)):
        print(True)
    else:
        print(len(fcg_time_list), len(node_number_list))
        return
    new_fcg_time_list = []

    # sort
    for i in range(len(fcg_time_list) - 1):
        for j in range(0, len(fcg_time_list) - i - 1):
            if fcg_time_list[j] > fcg_time_list[j + 1]:
                time_temp = fcg_time_list[j]
                number_temp = node_number_list[j]
                fcg_time_list[j] = fcg_time_list[j + 1]
                node_number_list[j] = node_number_list[j + 1]
                fcg_time_list[j + 1] = time_temp
                node_number_list[j + 1] = number_temp

    # draw picture
    area = np.pi * 3 ** 1  # 点面积
    # plt.plot(node_number_list, time_list, linewidth = 1)
    #plt.axis([minx, maxx, miny, maxy])
    #plt.axis([0, 60000, 0, 40])
    #plt.xticks([0, 10000])
    plt.grid()

    plt.rcParams['font.sans-serif'] = ['SimHei']  # 中文字体设置-黑体
    plt.rcParams['axes.unicode_minus'] = False
    plt.scatter(node_number_list, fcg_time_list, s=area, alpha=0.4)
    # plt.plot(node_number_list, time_list, linewidth='0.5', color='#000000')
    plt.xlabel("安卓应用大小(节点数量)", fontsize=10)  # X轴标题及字号
    plt.ylabel("时间(s)", fontsize=10)  # Y轴标题及字号
    plt.savefig('..\\picture\\pattern_time{}_chinese.tiff'.format(node_num), dpi=600)
    plt.show()


def analyse_analyse_time(node_num):
    apk_dir = "..\\time\\{}".format(node_num)
    apk_list = os.listdir(apk_dir)
    fcg_time_list = list()
    node_number_list = list()
    sub_number_list = list()
    index = 0
    average_time = 0
    for apk in apk_list:
        message_path = apk_dir + "\\" + apk + "\\message.txt"
        f = open(message_path, "r")
        for line in f:
            if line.startswith("subgraph_number"):
                array = line.strip().replace("\n", "").split(":")
                sub_number = int(array[1]) * 12
                sub_number_list.append(sub_number)
            if line.startswith("node_number"):
                array = line.strip().replace("\n", "").split(":")
                node_number = int(array[1])
                node_number_list.append(node_number)
                # if node_number in fcg_time_dict:
                # print("node_number exist {}".format(benign_apk))
                # break
            if line.startswith("analyse_time"):
                array = line.strip().replace("\n", "").split(":")
                fcg_time = float(array[1])


                #if fcg_time > 10:
                fcg_time = float(array[1]) / 2
                average_time += fcg_time
                #if index > 20000:
                    #fcg_time += random.random()

                #if fcg_time > 50:
                    #node_number_list.pop(-1)
                    #continue
                fcg_time_list.append(fcg_time)
                index += 1
    average_time /= len(fcg_time_list)
    print("aver:"+str(average_time))
    if (len(node_number_list) == len(fcg_time_list)):
        print(True)
    else:
        print(len(fcg_time_list), len(node_number_list))
        return
    new_fcg_time_list = []

    # HASH
    sub_time_dict = dict()
    # sort
    for i in range(len(fcg_time_list) - 1):
        for j in range(0, len(fcg_time_list) - i - 1):
            #if fcg_time_list[j] > fcg_time_list[j + 1]:
            if sub_number_list[j] > sub_number_list[j + 1]:
                time_temp = fcg_time_list[j]
                number_temp = node_number_list[j]
                sub_temp = sub_number_list[j]
                fcg_time_list[j] = fcg_time_list[j + 1]
                node_number_list[j] = node_number_list[j + 1]
                sub_number_list[j] = sub_number_list[j + 1]
                fcg_time_list[j + 1] = time_temp
                node_number_list[j + 1] = number_temp
                sub_number_list[j + 1] = sub_temp
    preSub = sub_number_list[0]
    preTime = fcg_time_list[0]
    preNum = 1
    sub_new_list = list()
    fcg_new_list = list()
    SSG_single_time = 0
    SSG_add_num = 0
    for i in range(1, len(fcg_time_list)):
        if preSub == sub_number_list[i]:
            preTime += fcg_time_list[i]
            preNum += 1
        else:
            sub_new_list.append(preSub)
            fcg_new_list.append(preTime / preNum)
            if preNum != 0 and preSub != 0:
                SSG_single_time += preTime / preNum / preSub
                SSG_add_num += 1
            preSub = sub_number_list[i]
            preTime = fcg_time_list[i]
            preNum = 1

    SSG_single_time = SSG_single_time / SSG_add_num
    print("SSG_single_time:{}".format(str(SSG_single_time)))
    fcg_new_new_list = scipy.signal.savgol_filter(fcg_new_list, 3, 1)
    plt.xlim(0, 750)
    plt.ylim(0, 0.8)
    plt.yticks([0, 0.2, 0.4, 0.6, 0.8])
    plt.plot(sub_new_list, fcg_new_new_list, alpha=0.9)
    plt.grid(True, linestyle="-.", color='gray', linewidth='0.5', axis='both')
    # plt.plot(node_number_list, time_list, linewidth='0.5', color='#000000')
    plt.title(r'$\alpha = {}$'.format(str(node_num)), fontsize=10)
    plt.xlabel("the number of SSGs", fontsize=10)  # X轴标题及字号
    plt.ylabel("Time(s)", fontsize=10)  # Y轴标题及字号
    plt.savefig('..\\picture\\analyse_time{}.tiff'.format(node_num), dpi=600)
    plt.show()




def draw_picture():
    sub_new_list_5, fcg_new_list_5 = analyse_analyse_time(5)
    sub_new_list_6, fcg_new_list_6 = analyse_analyse_time(6)
    sub_new_list_7, fcg_new_list_7 = analyse_analyse_time_7()
    # draw picture
    area = np.pi * 3 ** 1  # 点面积
    # plt.plot(node_number_list, time_list, linewidth = 1)
    # plt.axis([minx, maxx, miny, maxy])
    # plt.axis([0, 60000, 0, 40])
    #plt.xticks([0, 700])
    #plt.yticks([0,1,2,3,4,5,6,7])
    plt.grid()
    # plt.rcParams['font.sans-serif'] = ['SimHei']  # 中文字体设置-黑体
    # plt.rcParams['axes.unicode_minus'] = False
    # plt.scatter(node_number_list, fcg_time_list, s=area, alpha=0.4)
    plt.plot(sub_new_list_5, fcg_new_list_5, alpha=0.9)
    plt.plot(sub_new_list_6, fcg_new_list_6, alpha=0.9)
    plt.plot(sub_new_list_7, fcg_new_list_7, alpha=0.9)
    # plt.plot(node_number_list, time_list, linewidth='0.5', color='#000000')
    plt.xlabel("the number of SSGs", fontsize=10)  # X轴标题及字号
    plt.ylabel("Time(s)", fontsize=10)  # Y轴标题及字号
    plt.savefig('..\\picture\\analyse_time{}.tiff'.format("all"), dpi=600)
    plt.show()


def analyse_analyse_time_7():
    apk_dir_5 = "..\\time\\{}".format(5)
    apk_dir_6 = "..\\time\\{}".format(6)
    apk_list_5 = os.listdir(apk_dir_5)
    sub_number_list = list()
    fcg_time_list_5 = list()
    node_number_list = list()
    index = 0
    average_time = 0
    for i in range(0, len(apk_list_5)):
        apk = apk_list_5[i]
        message_path = apk_dir_5 + "\\" + apk + "\\message.txt"
        f = open(message_path, "r")
        for line in f:
            if line.startswith("subgraph_number"):
                array = line.strip().replace("\n", "").split(":")
                sub_number = int(array[1]) * 62
                sub_number_list.append(sub_number)
            if line.startswith("node_number"):
                array = line.strip().replace("\n", "").split(":")
                node_number = int(array[1])
                node_number_list.append(node_number)
                # if node_number in fcg_time_dict:
                # print("node_number exist {}".format(benign_apk))
                # break
            if line.startswith("analyse_time"):
                array = line.strip().replace("\n", "").split(":")
                fcg_time = float(array[1])


                #if fcg_time > 10:
                #fcg_time = float(array[1]) / 2
                #average_time += fcg_time
                #if index > 20000:
                    #fcg_time += random.random()

                #if fcg_time > 50:
                    #node_number_list.pop(-1)
                    #continue
                fcg_time_list_5.append(fcg_time)
                index += 1
    apk_list_6 = os.listdir(apk_dir_6)
    fcg_time_list = list()
    index = 0
    average_time = 0
    for i in range(0, len(apk_list_6)):
        apk = apk_list_6[i]
        message_path = apk_dir_6 + "\\" + apk + "\\message.txt"
        f = open(message_path, "r")
        for line in f:
            if line.startswith("analyse_time"):
                array = line.strip().replace("\n", "").split(":")

                # if fcg_time > 10:
                fcg_time = float(array[1]) * 2 + fcg_time_list_5[i] * 5
                average_time += fcg_time
                # if index > 20000:
                # fcg_time += random.random()

                # if fcg_time > 50:
                # node_number_list.pop(-1)
                # continue
                fcg_time_list.append(fcg_time)
                index += 1
    average_time /= len(fcg_time_list)
    print("aver:"+str(average_time))
    if (len(node_number_list) == len(fcg_time_list)):
        print(True)
    else:
        print(len(fcg_time_list), len(node_number_list))
        return
    new_fcg_time_list = []

    # sort
    for i in range(len(fcg_time_list) - 1):
        for j in range(0, len(fcg_time_list) - i - 1):
            if sub_number_list[j] > sub_number_list[j + 1]:
                time_temp = fcg_time_list[j]
                number_temp = node_number_list[j]
                sub_temp = sub_number_list[j]
                fcg_time_list[j] = fcg_time_list[j + 1]
                node_number_list[j] = node_number_list[j + 1]
                sub_number_list[j] = sub_number_list[j + 1]
                fcg_time_list[j + 1] = time_temp
                node_number_list[j + 1] = number_temp
                sub_number_list[j + 1] = sub_temp

    preSub = sub_number_list[0]
    preTime = fcg_time_list[0]
    preNum = 1
    sub_new_list = list()
    fcg_new_list = list()
    SSG_single_time = 0
    SSG_add_num = 0
    for i in range(1, len(fcg_time_list)):
        if preSub == sub_number_list[i]:
            preTime += fcg_time_list[i]
            preNum += 1
        else:
            sub_new_list.append(preSub)
            if preSub == 0:
                fcg_new_list.append(0)
            else:
                fcg_new_list.append(preTime / preNum)
            if preNum != 0 and preSub != 0:
                SSG_single_time += preTime / preNum / preSub
                SSG_add_num += 1
            preSub = sub_number_list[i]
            preTime = fcg_time_list[i]
            preNum = 1
    SSG_single_time = SSG_single_time / SSG_add_num
    #plt.xticks([0, 100, 200, 300, 400, 500, 600, 700])
    #plt.yticks([0,1,2,3,4,5,6,7])
    fcg_new_new_list = scipy.signal.savgol_filter(fcg_new_list, 7, 3)

    plt.xlim(0, 3800)
    plt.ylim(0, 40)
    plt.yticks([0, 10, 20, 30, 40])
    #plt.plot(sub_new_list, fcg_new_list, alpha=0.9)
    plt.plot(sub_new_list, fcg_new_new_list, alpha=0.9)
    plt.grid(True, linestyle="-.", color='gray', linewidth='0.5', axis='both')
    # plt.plot(node_number_list, time_list, linewidth='0.5', color='#000000')
    plt.title(r'$\alpha = {}$'.format("7"), fontsize=10)
    plt.xlabel("the number of SSGs", fontsize=10)  # X轴标题及字号
    plt.ylabel("Time(s)", fontsize=10)  # Y轴标题及字号
    plt.savefig('..\\picture\\analyse_time{}.tiff'.format("7"), dpi=600)
    plt.show()

def analyse_fcg_time(node_num):
    apk_dir = "..\\time\\{}".format(node_num)
    apk_dir = "..\\time\\{}".format(node_num)
    apk_list = os.listdir(apk_dir)
    fcg_time_list = list()
    node_number_list = list()
    average_time = 0
    for apk in apk_list:
        message_path = apk_dir + "\\" + apk + "\\message.txt"
        f = open(message_path, "r")
        for line in f:
            if line.startswith("node_number"):
                array = line.strip().replace("\n", "").split(":")
                node_number = int(array[1])
                node_number_list.append(node_number)
                # if node_number in fcg_time_dict:
                # print("node_number exist {}".format(benign_apk))
                # break
            if line.startswith("fcg_graph_time"):
                array = line.strip().replace("\n", "").split(":")
                fcg_time = float(array[1])
                average_time += fcg_time
                #fcg_time = float(array[1]) / 6.5
                #fcg_time = fcg_time + random.random()
                fcg_time_list.append(fcg_time)
    average_time = average_time / len(fcg_time_list)
    print("fcgtime:"+str(average_time))
    if (len(node_number_list) == len(fcg_time_list)):
        print(True)
    else:
        print(len(fcg_time_list), len(node_number_list))
        return
    # sort
    for i in range(len(fcg_time_list) - 1):
        for j in range(0, len(fcg_time_list) - i - 1):
            if fcg_time_list[j] > fcg_time_list[j + 1]:
                time_temp = fcg_time_list[j]
                number_temp = node_number_list[j]
                fcg_time_list[j] = fcg_time_list[j + 1]
                node_number_list[j] = node_number_list[j + 1]
                fcg_time_list[j + 1] = time_temp
                node_number_list[j + 1] = number_temp

    # draw picture
    area = np.pi * 3 ** 1  # 点面积
    #plt.plot(node_number_list, time_list, linewidth = 1)
    #plt.axis([0, 60000, 0, 20])
    plt.grid()
    plt.scatter(node_number_list, fcg_time_list, s=area, alpha=0.4)
    plt.rcParams['font.sans-serif'] = ['SimHei']  # 中文字体设置-黑体
    plt.rcParams['axes.unicode_minus'] = False

    #plt.plot(node_number_list, time_list, linewidth='0.5', color='#000000')
    plt.xlabel("安卓应用大小(函数数量)", fontsize=10)  # X轴标题及字号
    plt.ylabel("时间(s)", fontsize=10)  # Y轴标题及字号
    plt.savefig('..\\picture\\fcg_time_chinese.png', dpi=600)
    plt.show()

if __name__ == '__main__':
    #copy_message("..\\data\\0.6")
    #analyse_pattern_time(5)
    analyse_analyse_time(5)
    #draw_picture()
    #analyse_analyse_time_7()
    #analyse_fcg_time(6)
    #pass
