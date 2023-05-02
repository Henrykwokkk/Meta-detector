import os
import re
import subprocess
import json


class PaymentAnalyser:

    def analyse(self, apk_path: str):
        print("start payment analyser")
        self.__start_paymentscope__(apk_path)
        self.__analyse_paymentscope_result__(apk_path)

    def reports(self):
        return {
            'payment_vulnerability_type': self.payment_vulnerable
        }

    def __init__(self):
        self.payment_vulnerable: [str] = []

    # using paymentscope
    def __start_paymentscope__(self, apk_path: str):
        print("Running PaymentScope")
        os.makedirs(r'../results/paymentscope', exist_ok=True)
        params = ['python',
                  ".."+ os.path.sep + "PaymentScope" + os.path.sep + "src" + os.path.sep + "python"+ os.path.sep + "paymentScope.py",
                  '-n',
                  apk_path,
                  '-o',
                  '../results/paymentscope' + os.path.sep + os.path.basename(apk_path).split('.')[0],
                  '-p',
                  os.path.basename(apk_path).split('.')[0]
                  ]

        process = subprocess.Popen(params,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        _, stderr = process.communicate()
        if len(stderr) > 0:
            print(str(stderr))
        # os.system(" ".join(i for i in params))


    # search resource ids leaked
    def __analyse_paymentscope_result__(self,apk_path):
        if os.path.exists('../results/paymentscope' + os.path.sep + os.path.basename(apk_path).split('.')[0]+ os.path.sep + 'analysisRes.json'):
            with open('../results/paymentscope' + os.path.sep + os.path.basename(apk_path).split('.')[0]+ os.path.sep + 'analysisRes.json','r') as f:
                mm = json.load(f)
                self.payment_vulnerable.append(mm["isVulnerable"])
        elif not os.path.exists('../results/paymentscope' + os.path.sep + os.path.basename(apk_path).split('.')[0]+ os.path.sep + os.path.basename(apk_path).split('.')[0]+ '_libil2cpp.so'):
            self.payment_vulnerable.append('It is not UNITY-based app')
        else:
            self.payment_vulnerable.append('It is UNITY-based app, but there is no UNITY IAP in this app or this app is protected')
