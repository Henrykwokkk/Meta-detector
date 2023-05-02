import json
import os
import re

from androguard.core.analysis.analysis import Analysis, MethodClassAnalysis, ClassAnalysis, StringAnalysis, \
    ExternalMethod, FieldClassAnalysis
from androguard.core.bytecodes import apk
from androguard.core.bytecodes.dvm import EncodedMethod, Instruction

import utils
from assets.ip_regex import IPV4ADDR, IPV6ADDR, PRIVADDR


class CodeAnalyser:

    def analyse(self, a: apk.APK, dx: Analysis):
        print('start code analyser')
        self.__analyse_sql__(a, dx)
        self.__analyse_ip__(a, dx)
        self.__analyse_storage__(dx)
        self.__analyse_hardcode_keys__(a, dx)
        self.__analyse_improper_encryption__(a, dx)
        self.__analyse_insecure_secure_random__(a, dx)
        self.__analyse_insecure_hash_function__(a, dx)
        self.__analyse_remote_webview_debugging__(a, dx)
        self.__analyse_insecure_webview_implementation(dx)
        self.__analyse_insecure_certificate_validation__(dx)
        self.__analyse_trackers__(a, dx)

    def reports(self) -> dict:
        return {
            # sql raw_queries
            'sql_raw_queries': utils.generate_result_list(self.sql_raw_query_inject_methods),
            # sql hardcoded keys
            'sql_hardcoded_secrets': utils.generate_result_list(self.sql_encrypt_secret_hardcoded_methods),
            # ip disclosure
            'ip_disclosure': self.ipv4 + self.ipv6 + self.private_ip,

            # insecure random
            'insecure_random_generator': utils.generate_result_list(self.insecure_randoms),

            # broken or risky cryptographic algorithms, cwe-327
            'risky_cryptographic_algorithms': {
                # insecure hash functions
                'insecure_hash_functions': utils.generate_result_list(self.weak_hash),
                # improper encryption
                'improper_encrypt_functions': utils.generate_result_list(self.encryption_vuln_ecb)
                                              + utils.generate_result_list(self.encryption_vuln_rsa_no_oaep),
            },
            # remote webview debugging enabled
            'remote_webview_debugging': utils.generate_result_list(self.webview_debugs),
            # insecure webview implementation
            'insecure_webview_implementation': utils.generate_result_list(self.webview_insecure_implementation),
            'insecure_certificate_validation': utils.generate_result_list(self.insecure_certificate_validation),
            'trackers': self.trackers
        }

    # NOTE: these sql issues are "probably" issues.
    def __analyse_sql__(self, a: apk.APK, dx: Analysis):    #检测执行SQL操作的函数来检测是否有SQL注入的风险
        print("analysing sqlite")
        # raw query
        methods = dx.find_methods("Landroid/database/sqlite/.*", "execSQL|rawQuery")
        raw_query_injects: [(ClassAnalysis, EncodedMethod)] = []

        # cipher key hardcoded
        encrypts: [(ClassAnalysis, EncodedMethod)] = []
        # check whether variables/user inputs are involved in SQL statements (filter out constant values)
        for m in methods:
            # raw_query_injects.append(m)
            # 1. should implement code tracing variables
            # 2. find encryption entry. Hint: db.execSQL("PRAGMA key = 'secretkey'");
            m: MethodClassAnalysis = m
            p_list: [(ClassAnalysis, object, int)] = m.get_xref_from()
            for (p_class, p_method, _) in p_list:
                if type(p_method) is ExternalMethod:
                    continue
                p_method: EncodedMethod = p_method
                item = (p_class, p_method)
                if "PRAGMA key" in p_method.get_source():   #get_source表示获取该函数源码，pragma key表示带有"PRAGMA key"的数据库，要获取密钥
                    if item not in encrypts:  # may contain hardcoded keys
                        encrypts.append(item)
                elif item not in raw_query_injects:  # may leak
                    raw_query_injects.append(item)

                break

        self.sql_raw_query_inject_methods = raw_query_injects
        self.sql_encrypt_secret_hardcoded_methods = encrypts
        pass

    def __analyse_storage__(self, dx: Analysis):
        print("analysing storage issues")
        self.storage_issues: [(ClassAnalysis, EncodedMethod)] = []

        # storage寻找访问存储相关的函数
        rss = dx.find_methods("Landroid/os/Environment|Ljava/io/File|Landroid/content/Context",
                              r"getExternalStorage*|getExternalFilesDir|createTempFile|openFileOutput")
        for m in rss:
            m: MethodClassAnalysis = m
            p_list: [(ClassAnalysis, object, int)] = m.get_xref_from()
            for (p_class, p_method, _) in p_list:
                if type(p_method) is not EncodedMethod: #如果不可以映射到smail语言的方法直接跳过
                    continue

                # iterate parent methodsO
                item = (p_class, p_method)
                if item not in self.storage_issues:
                    self.storage_issues.append(item)
                break

    def __analyse_ip__(self, a: apk.APK, dx: Analysis):
        print("analysing ip disclosure")
        # private address
        priv: [str] = []
        privRe = re.compile(PRIVADDR)
        # ipv4
        ipv4: [str] = []
        rs: [StringAnalysis] = dx.find_strings(IPV4ADDR)  #寻找IPV4的地址哪些是私有地址
        for result in rs:
            result: StringAnalysis = result
            val = result.get_value()
            if privRe.match(val):
                priv.append(val)
            else:
                ipv4.append(val)
        self.ipv4 = ipv4

        # ipv6
        ipv6: [str] = []
        rs: [StringAnalysis] = dx.find_strings(IPV6ADDR)        #寻找IPV6的地址哪些是私有地址
        for result in rs:
            result: StringAnalysis = result
            val = result.get_value()
            if privRe.match(val):
                priv.append(val)
            else:
                ipv6.append(val)
        self.ipv6 = ipv6
        self.private_ip = priv
        pass

    def __analyse_hardcode_keys__(self, a: apk.APK, dx: Analysis):
        # CWE-312 Cleartext Storage
        pass

    def __analyse_improper_encryption__(self, a: apk.APK, dx: Analysis):
        print("analysing improper encryption")

        # check improper encryption
        self.encryption_vuln_ecb: [(ClassAnalysis, EncodedMethod)] = []
        self.encryption_vuln_rsa_no_oaep: [(ClassAnalysis, EncodedMethod)] = []
        methods = dx.find_methods("Ljavax/crypto/Cipher", "getInstance")

        reECB = re.compile(r'AES/ECB', re.IGNORECASE)  # The App uses ECB mode in Cryptographic encryption algorithm.
        reRsaNoPadding = re.compile(r'rsa/.+/nopadding',
                                    re.IGNORECASE)  # This App uses RSA Crypto without OAEP padding软件使用了RSA算法，但未使用最佳非对称加密填充方式（OAEP），而如果不使用OAEP，则攻击者只需较少的工作即可解密数据或从密文中推断出特征、模式。.

        for m in methods:
            # check its parent method to find wrong parameters
            m: MethodClassAnalysis = m
            p_list: [(ClassAnalysis, object, int)] = m.get_xref_from()
            for (p_class, p_method, _) in p_list:
                if type(p_method) is not EncodedMethod:
                    continue

                # iterate parent methods
                p_method: EncodedMethod = p_method
                # find wrong encryption options
                for ins in p_method.get_instructions(): #ins是指令的Dalvik指令（Smail语言）
                    ins: Instruction = ins
                    if ins.get_name() != 'const-string':
                        continue

                    output = ins.get_output()   #get_name表示命名的操作码，get_output则是指令后面的操作对象
                    item = (p_class, p_method)
                    if reECB.search(output):
                        if item not in self.encryption_vuln_ecb:
                            self.encryption_vuln_ecb.append(item)
                        break
                    elif reRsaNoPadding.search(output):
                        if item not in self.encryption_vuln_rsa_no_oaep:
                            self.encryption_vuln_rsa_no_oaep.append(item)
                        break
        pass

    def __analyse_insecure_secure_random__(self, a: apk.APK, dx: Analysis):
        print("analysing insecure random")
        # find java.util.Random采用不安全的随机数方法
        self.insecure_randoms: [(ClassAnalysis, EncodedMethod)] = []
        methods = dx.find_methods("Ljava/util/Random|Lkotlin/random/Random", r"next\s*")

        for m in methods:
            # check its parent method to find wrong parameters
            m: MethodClassAnalysis = m
            p_list: [(ClassAnalysis, object, int)] = m.get_xref_from()

            for (p_class, p_method, _) in p_list:
                # find first parent method
                p_class: ClassAnalysis = p_class
                class_name: str = p_class.name

                # jump out of kotlin packages过滤掉kotlin
                if p_method is ExternalMethod or class_name.startswith('Lkotlin'):
                    continue
                item = (p_class, p_method)
                if item not in self.insecure_randoms:
                    self.insecure_randoms.append(item)
                break
        pass

    def __analyse_insecure_hash_function__(self, a: apk.APK, dx: Analysis):
        print("analysing insecure hash function")
        # find all md4, rc2, rc4, md5, sha-1
        self.weak_hash: [(ClassAnalysis, EncodedMethod)] = []

        # find general weak hash
        methods = dx.find_methods("Ljava/security/MessageDigest", "getInstance") #搜索提供哈希方法的函数
        reWeakHash = re.compile(r'md5|md4|rc2|sha-1', re.IGNORECASE)
        for m in methods:
            # check its parent method to find wrong parameters
            m: MethodClassAnalysis = m
            p_list: [(ClassAnalysis, object, int)] = m.get_xref_from()
            for (p_class, p_method, _) in p_list:
                if type(p_method) is not EncodedMethod:
                    continue

                # iterate parent methods
                p_method: EncodedMethod = p_method
                # find wrong encryption options
                for ins in p_method.get_instructions():
                    ins: Instruction = ins
                    if ins.get_name() != 'const-string':
                        continue

                    output = ins.get_output()
                    item = (p_class, p_method)
                    if reWeakHash.search(output):
                        if item not in self.weak_hash:
                            self.weak_hash.append(item)
                        break

        methods = dx.find_methods("Lorg/apache/commons/codec/digest/DigestUtils", "md5|sha")
        for m in methods:
            # check its parent method to find wrong parameters
            m: MethodClassAnalysis = m
            p_list: [(ClassAnalysis, object, int)] = m.get_xref_from()
            for (p_class, p_method, _) in p_list:
                if type(p_method) is not EncodedMethod:
                    continue
                item = (p_class, p_method)
                if item not in self.weak_hash:
                    self.weak_hash.append((p_class, p_method))
                break

        pass

    def __analyse_remote_webview_debugging__(self, a: apk.APK, dx: Analysis):
        print("analysing webview debugging options")
        # find WebView debug function
        methods = dx.find_methods("Landroid/webkit/WebView", "setWebContentsDebuggingEnabled")
        self.webview_debugs: [(ClassAnalysis, EncodedMethod)] = []
        for m in methods:
            # check its parent method to find wrong parameters
            m: MethodClassAnalysis = m
            p_list: [(ClassAnalysis, object, int)] = m.get_xref_from()
            for (p_class, p_method, _) in p_list:
                if type(p_method) is not EncodedMethod:
                    continue

                # iterate parent methods
                p_method: EncodedMethod = p_method
                # find wrong encryption options
                code: str = p_method.get_source()
                item = (p_class, p_method)
                if "setWebContentsDebuggingEnabled(1)" in code:     #获取java源码后如果允许网页调试会有安全风险
                    if item not in self.webview_debugs:
                        self.webview_debugs.append(item)
                    break
        pass

    def __analyse_insecure_webview_implementation(self, dx: Analysis):
        print("analysing insecure webview implementation")
        methods = dx.find_methods("Landroid/webkit/WebViewClient", "onReceivedSslError")
        self.webview_insecure_implementation: [(ClassAnalysis, EncodedMethod)] = []
        for m in methods:
            # check its parent method to find wrong parameters
            m: MethodClassAnalysis = m
            p_list: [(ClassAnalysis, object, int)] = m.get_xref_from()
            for (p_class, p_method, _) in p_list:
                if type(p_method) is not EncodedMethod:
                    continue
                item = (p_class, p_method)
                if item not in self.webview_insecure_implementation:
                    self.webview_insecure_implementation.append(item)
                break

        pass

    def __analyse_insecure_certificate_validation__(self, dx: Analysis):
        print("analysing insecure certificate validation")
        methods = dx.find_methods("Ljavax/net/ssl/.*", "setDefaultHostnameVerifier")
        self.insecure_certificate_validation: [(ClassAnalysis, EncodedMethod)] = []
        for m in methods:
            # check its parent method to find wrong parameters
            m: MethodClassAnalysis = m
            p_list: [(ClassAnalysis, object, int)] = m.get_xref_from()
            for (p_class, p_method, _) in p_list:
                if type(p_method) is not EncodedMethod:
                    continue
                item = (p_class, p_method)
                if item not in self.insecure_certificate_validation:
                    self.insecure_certificate_validation.append(item)
                break

        pass

    def __analyse_trackers__(self, a: apk.APK, dx: Analysis):
        print("analysing trackers")
        self.trackers: [{str: str}] = []  # [{name : website}]
        # load trackers. We use exodus tracker list: https://etip.exodus-privacy.eu.org/trackers/all
        with open(os.path.join(os.path.dirname(__file__), "assets" + os.path.sep + 'trackers.json'), 'r') as file:
            json_obj = json.load(file)
            trackers = json_obj['trackers']
            # check the code signature
            for item in trackers:   #遍历tracker列表，将其code-signature替换成delvik字节码的格式，然后再和smail文件里的指令去做匹配
                name = item['name']
                website = item['website']
                code_signature: str = item['code_signature']
                code_signature = "L" + code_signature.replace('.', '/')
                if code_signature[-1] != '/':
                    code_signature = code_signature + '/'

                code_signature = code_signature + '.*'  # make the code signature as Lcom/example/.*
                results = dx.find_classes(code_signature, True)     #后面的true表示非外部类
                for _ in results:  # contains such tracker
                    self.trackers.append({name: website})
                    break
