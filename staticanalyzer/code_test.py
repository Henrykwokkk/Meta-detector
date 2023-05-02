from xml.etree import ElementTree
from xml.etree.ElementTree import Element
import re
import requests
import json
import os
import pickle


# for root,dirs,files in os.walk(r"./ext/output/policy"):
#     for file in files:
#         policy_list = pickle.load(open(os.path.join(root,file),'rb'))
#         num = 0
#         with open('{}/{}.json'.format(root,os.path.splitext(file)[0]), 'w') as w:
#             title = ('entity','action','data type','sentence','original action')
#             w.write(json.dumps(title))
#             w.write('\n')
#             for policy in policy_list:
#                 w.write(json.dumps(policy))
#                 w.write('\n')
#                 num += 1
#             print(num)

print('你好')

