'''
得到dapasa的敏感API，pscout的敏感API
'''

import random
from random import sample


def get_api_set(api_path, threshold):
    api_set = set()
    f = open(api_path, "r")
    for line in f:
        line = line.strip().replace("\n", "")
        api_set.add(line)
    choosed_api_len = int(threshold * len(api_set))
    choosed_api_set = set(random.sample(api_set, choosed_api_len))
    f.close()
    return choosed_api_set