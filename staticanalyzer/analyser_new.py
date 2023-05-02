#analyser including payment analysis
import os

import yaml
from androguard.core.bytecodes import apk
from androguard.misc import AnalyzeAPK, Analysis

from code_analyser import CodeAnalyser
from manifest_analyser import ManifestAnalyser
from root_analyser import RootAnalyser
from taint_analyser import TaintAnalyser
from payment_analyser import PaymentAnalyser


class Analyser_new_analysis:

    @staticmethod
    def start(apk_path, sdk_path):
        instance = Analyser_new_analysis()

        instance.__decompile(apk_path)
        instance.__root_detection__()
        instance.__analyse_manifest__()
        instance.__analyse_code__()
        instance.__dataflow_analysis__(apk_path, sdk_path)
        instance.__payment_analysis__(apk_path)
        instance.__generate_results__()

    email_list = []

    def __init__(self):
        pass

    def __del__(self):
        del self.__apk
        del self.__dx
        del self.__df
        del self.__manifest_analyser
        del self.__code_analyser
        del self.__root_analyser
        del self.__payment_analyser
        pass

    def __decompile(self, apk_path):
        print("start analyse")
        a, df, dx = AnalyzeAPK(apk_path)    #输出的分别是a: 一个APK对象、d:一个DalvikVMFormat对象数组和dx：Analysis对象。
        self.__apk: apk.APK = a     # apk 文件对象，其实就是读取 AndroidManifest.xml 文件, 了解过Android 的程序员应该知道，这个文件中就是清仓文件， 我们申请一些权限，注册 Activity, Service, Broadcast,ContentProvader 都在清仓文件中申请。
        self.__df = df      #解析出方法调用图
        self.__dx: Analysis = dx    #我们可以使用 dex 对象， 获取文件中所有类的，所有方法，所有的成员变量和字符串。注意， 这边获取的 dex 对象是一个 list


    def __analyse_manifest__(self):
        print("start analysing manifest")
        self.__manifest_analyser = ManifestAnalyser()
        self.__manifest_analyser.analyse(self.__apk)
        pass

    def __analyse_code__(self):
        print("start analysing code")
        self.__code_analyser = CodeAnalyser()
        self.__code_analyser.analyse(self.__apk, self.__dx)
        pass

    def __dataflow_analysis__(self, apk_path, sdk_path):
        print("start analysing dataflow")
        self.__taint_analyser = TaintAnalyser()
        self.__taint_analyser.analyse(self.__apk, self.__df[0], self.__dx, apk_path, sdk_path)
        pass

    def __payment_analysis__(self, apk_path):
        print("start analysing payment")
        self.__payment_analyser = PaymentAnalyser()
        self.__payment_analyser.analyse(apk_path)
        pass

    def __root_detection__(self):
        print("start root detection")
        self.__root_analyser = RootAnalyser()
        self.__root_analyser.analyse(self.__apk, self.__dx)     #检测使用root权限的危险函数及其调用函数
        pass

    def __generate_results__(self):
        print("start generating results")
        result = {
            'app': self.__manifest_analyser.reports(),
            'code_analysis': self.__code_analyser.reports(),
            'root_analysis': self.__root_analyser.reports(),
            'pii_taint_result': self.__taint_analyser.reports(),
            'payment_vulnerable':self.__payment_analyser.reports()
        }
        filename = self.__apk.get_filename() + ".yaml"
        filename = filename.split(os.path.sep)[-1]

        folder = '../'+ "results"
        if not os.path.exists(folder) or not os.path.isdir(folder):
            os.makedirs(folder, 0o777, True)
        with open(os.path.join(folder, filename), 'w') as file:
            yaml.dump(result, file)
        pass
