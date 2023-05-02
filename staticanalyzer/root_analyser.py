from androguard.core.analysis.analysis import Analysis, StringAnalysis, ClassAnalysis, MethodClassAnalysis
from androguard.core.bytecodes import apk
from androguard.core.bytecodes.dvm import EncodedMethod

import utils


class RootAnalyser:

    def analyse(self, a: apk.APK, dx: Analysis):
        print("start root analyser")
        self.__detect_debug__(dx)   
        self.__detect_su_usage__(dx)    
        self.__detect_su_detection__(dx)    
        pass

    def reports(self) -> dict:
        return {
            # root detection
            'root_detections': utils.generate_result_list(self.su_detections),
            # root usage
            'root_usage': utils.generate_result_list(self.su_usages),
            # debug detection
            'debug_detections': utils.generate_result_list(self.debug_detections),
        }

    def __detect_su_detection__(self, dx: Analysis):
        print("analysing su detection")
        self.su_detections: [(ClassAnalysis, EncodedMethod)] = []

        # find methods that contains these su paths
        rs: [StringAnalysis] = dx.find_strings(r"/system/app/Superuser.apk|/system/bin/failsafe/su|/system/sd/xbin/su")
        for result in rs:
            result: StringAnalysis = result
            p_list: [(ClassAnalysis, object)] = result.get_xref_from()
            # find direct parent method who trigger this method
            for (p_class, p_method) in p_list:
                if type(p_method) is not EncodedMethod:
                    continue

                item = (p_class, p_method)
                if item not in self.su_detections:
                    self.su_detections.append(item)
                break

        # RootTools or Root detection
        rss: [MethodClassAnalysis] = dx.find_methods("Lcom/stericson/RootTools/RootTools|Ldexguard/util/RootDetector",
                                                     "isAccessGiven|isDeviceRooted")
        for rst in rss:
            rst: MethodClassAnalysis = rst
            p_list: [(ClassAnalysis, object, int)] = rst.get_xref_from()
            # find direct parent method who trigger this method
            for (p_class, p_method, _) in p_list:
                if type(p_method) is not EncodedMethod:
                    continue

                item = (p_class, p_method)
                if item not in self.su_detections:
                    self.su_detections.append(item)
                break

        pass

    def __detect_su_usage__(self, dx: Analysis):
        print("analysing root usage")
        # find out su root usage
        self.su_usages: [(ClassAnalysis, EncodedMethod)] = []
        # su packages
        rss: [MethodClassAnalysis] = dx.find_methods(
            "Lcom/noshufou/android/su/.*|Lcom/thirdparty/superuser/.*|Leu/chainfire/.*|Lcom/koushikdutta/superuser/.*")     
        for rst in rss:
            rst: MethodClassAnalysis = rst
            p_list: [(ClassAnalysis, object, int)] = rst.get_xref_from()
            # find direct parent method who trigger this method
            for (p_class, p_method, _) in p_list:
                if type(p_method) is not EncodedMethod:
                    continue

                item = (p_class, p_method)
                if item not in self.su_usages:
                    self.su_usages.append(item)
                break
        pass

    def __detect_debug__(self, dx: Analysis):
        print("analysing debugging detection")
        self.debug_detections: [(ClassAnalysis, EncodedMethod)] = []
        rss: [MethodClassAnalysis] = dx.find_methods("Ldexguard/util/.*",
                                                     "isDebuggable|isDebuggerConnected|isRunningInEmulator|isSignedWithDebugKey")   
        for rst in rss:
            rst: MethodClassAnalysis = rst
            p_list: [(ClassAnalysis, object, int)] = rst.get_xref_from()
            # find direct parent method who trigger this method
            for (p_class, p_method, _) in p_list:
                if type(p_method) is not EncodedMethod:
                    continue

                item = (p_class, p_method)
                if item not in self.su_detections:
                    self.debug_detections.append(item)
                break
        pass
