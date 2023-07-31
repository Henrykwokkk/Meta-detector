#分析反编译的java代码和policy之间的冲突关系

import os
from collections import defaultdict
import yaml
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from androguard.core.analysis import analysis
from androguard.misc import AnalyzeAPK, Analysis
import json


class java_policy_analysis:

    @staticmethod
    def start(apk_path,appname):
        instance = java_policy_analysis()
        instance.__decompile(apk_path)
        pii_usage_function_list = instance.__search_sensitive_method()
        consistency_result = instance.__search_sensitive_policy(appname,pii_usage_function_list)
        instance.__generate_results(consistency_result,appname)


    def __init__(self):
        pass

    def __decompile(self, apk_path):
        print("start consistency analyse")
        a, df, dx = AnalyzeAPK(apk_path)  
        self.__apk: apk.APK = a  
        self.__df = df  
        self.__dx: Analysis = dx  


    def __search_sensitive_method(self):
        pii_keywords=['user','password','username','phone','id','email','location']
        pii_usage_function = defaultdict(list)
        for dfs in self.__df:
            class_list = dfs.get_classes()
            for c in class_list:    
                methods = c.get_methods()
                for m in methods:
                    method_name = m.get_name()
                    for pii_keyword in pii_keywords:
                        if pii_keyword in method_name:
                            pii_usage_function[pii_keyword].append(method_name)
        return pii_usage_function


    def __search_sensitive_policy(self,appname,functions):
        if os.path.exists('../results/policy/{}.json'.format(appname)):
            consistency_dict = {}
            for key in functions: 
                with open('../results/policy/{}.json'.format(appname)) as f:
                    for line in f:
                        mm = json.loads(line)
                        if mm[0] == 'entity':
                            continue
                        else:
                            if ('not' not in mm[1]) and (key in mm[3]):
                                consistency_dict['{}_conistency'.format(key)] = True
                            else:
                                consistency_dict['{}_conistency'.format(key)] = False
                        break
            return consistency_dict
        



    def __generate_results(self,result,appname):
        with open('../results/policy/policy_java_consistency/{}.json'.format(appname),'w') as f:
            f.write(json.dumps(result))








