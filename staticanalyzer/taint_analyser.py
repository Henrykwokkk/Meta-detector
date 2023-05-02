import os
import re
import subprocess
from xml.etree import ElementTree
from xml.etree.ElementTree import Element

from androguard.core.analysis.analysis import Analysis
from androguard.core.bytecodes import apk
from androguard.core.bytecodes.dvm import DalvikVMFormat, ClassDefItem, EncodedField, EncodedValue


class TaintAnalyser:

    def analyse(self, a: apk.APK, d: DalvikVMFormat, dx: Analysis, apk_path: str, sdk_path: str):
        print("start taint analyser")
        self.__start_flowdroid__(apk_path, sdk_path)
        self.__edit_text_analyse__(a, d, dx)

    def reports(self):
        return {
            'leaked_keys': self.leak_id_names
        }

    def __init__(self):
        self.leak_id_names: [str] = []

    # using flowdroid
    def __start_flowdroid__(self, apk_path: str, sdk_path: str):
        print("Running Flowdroid")
        sdk_path += os.path.sep + "platforms"

        params = ['java',
                  '-jar',
                  os.path.join(os.path.dirname(__file__), "assets" + os.path.sep + "flowdroid_2.10.0.jar"),
                  '-p',
                  sdk_path,
                  '-a',
                  apk_path,
                  '-aa',
                  'FLOWSENSITIVE',
                  '-al',
                  '1000',
                  '-cg',
                  'AUTO',
                  '-ds',
                  'CONTEXTFLOWSENSITIVE',
                  '-mc',
                  '1000',
                  '-md',
                  '1000',
                  '-ct',
                  '3600',
                  '-dt',
                  '3600',
                  # '-t',
                  # os.path.join(os.path.dirname(__file__), "assets" + os.path.sep + 'EasyTaintWrapperSource.txt'),
                  # '-tw',
                  # 'MULTI',
                  '-sf',
                  'CONTEXTFLOWSENSITIVE',
                  '-r',
                  '-pa',
                  'CONTEXTSENSITIVE',
                  '-s',
                  os.path.join(os.path.dirname(__file__), "assets" + os.path.sep + "SourcesAndSinks.txt"),
                  '-o',
                  '../results' + os.path.sep + "flowdroid"]

        process = subprocess.Popen(params,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        _, stderr = process.communicate()
        if len(stderr) > 0:
            print(str(stderr))
        # os.system(" ".join(i for i in params))

    def __edit_text_analyse__(self, a: apk.APK, d: DalvikVMFormat, dx: Analysis):

        # load keywords
        with open(os.path.join(os.path.dirname(__file__), "assets" + os.path.sep + 'pii_keywords.txt'), 'r') as file:
            keywords: [str] = file.read().splitlines(False)

        # parse flowdroid results
        folder = "../" +"results" + os.path.sep + "flowdroid"

        file_name = a.get_filename().split(os.path.sep)[-1][:-4]    #获取app名称
        fd_path = os.path.join(folder, file_name + ".xml")      #获取flowdroid分析结果

        self.leak_id_names: [str] = []

        if not os.path.exists(fd_path):
            print("Flowdroid result doesn't exist")
            return

        resource_list = self.__analyse_flowdroid_result__(fd_path)

        resource_ids = []
        for s_id, s_method, s_statement, sink_method, sink_statement in resource_list:
            resource_ids.append(s_id)

        # find Resource class
        package_name = a.get_package()
        package_name = package_name.replace(".", "/")

        cls: ClassDefItem = d.get_class("L" + package_name + "/R$id;")  # find resource id R class里有不同资源的id
        if cls is None:
            print("This application doesn't have an R class")
            return

        fields: [EncodedField] = cls.get_fields()

        # match ids with keywords
        for field in fields:    #遍历R class的属性，即资源id
            field: EncodedField = field
            value: EncodedValue = field.get_init_value()

            # resource id -> resource name
            the_value = str(value.get_value())
            field_name = field.get_name()
            if the_value in resource_ids and field_name in keywords:
                self.leak_id_names.append(field_name)

    # search resource ids leaked
    def __analyse_flowdroid_result__(self, result_path):
        result_tuple: [(str, str, str, str, str)] = []  # s_id, s_method, s_statement, sink_method, sink_statement
        tree = ElementTree.parse(result_path)
        root = tree.getroot()   #得到根节点。返回根节点的element对象,一般是<DataFlowResults>
        results: Element = root.find('Results') #得到第一个匹配Results的子节点，match可以是一个标签名称或者是路径。返回个element
        idReg = re.compile(r'\((\d+?)\)')
        if results is None:
            return result_tuple

        for rs in results:  #遍历Results节点下的subElement，遍历results下的结果，每一个rs就是一组流向路径
            rs: Element = rs
            # sink
            sink = rs.find("Sink")  #找到第一个匹配的sink，即危险函数
            sink_attr = sink.attrib
            sink_stm = sink_attr['Statement']
            sink_mtd = sink_attr['Method'][1:-1]
            # sources
            sources = rs.findall('Sources') #获取所有流向这个sink的路径
            for scs in sources: #遍历每条路径，一个scs代表一条流向sink的路径
                scs: Element = scs
                children = list(scs)
                for c in children:  #遍历每条路径里的每个函数
                    c: Element = c
                    attr = c.attrib
                    statement = attr['Statement']
                    method = attr['Method'][1:-1]

                    # skip internal packages & not findViewById ["Landroid/", "Lcom/android/internal/util",
                    # "Ldalvik/", "Ljava/", "Ljavax/", "Lorg/apache/","Lorg/json/", "Lorg/w3c/dom/", "Lorg/xml/sax",
                    # "Lorg/xmlpull/v1/", "Ljunit/"]
                    if "findViewById" not in statement \
                            or method.startswith("android.") \
                            or method.startswith("androidx.") \
                            or method.startswith("com.android.internal.util") \
                            or method.startswith("dalvik") \
                            or method.startswith("java.") \
                            or method.startswith("javax.") \
                            or method.startswith("org.json."):
                        continue

                    # find resource id
                    rs_list = idReg.findall(statement)
                    if rs_list != []:
                        rs_id = rs_list[-1]
                        result_tuple.append((rs_id, method, statement, sink_mtd, sink_stm))
        return result_tuple
