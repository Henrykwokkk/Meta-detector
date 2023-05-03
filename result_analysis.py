import yaml
import os
from collections import defaultdict, Counter
import json

def get_all_file(dir_name):
    fullname_list = []
    for root, dirs, files in os.walk(dir_name):
        for filename in files:
            if '.yaml' in filename:
                fullname_list.append(os.path.join(root, filename))
    return fullname_list





def check_Unity_IAP(result_files):
    IAP_app_list = defaultdict(list)
    for result_file in result_files:
        with open(result_file, 'r') as f:
            mm = yaml.load(f)
            IAP_app_list[mm['payment_vulnerable ']['payment_vulnerability_type'][0]].append(mm['app']['app_name'])
    return IAP_app_list

def check_permission_method_incosistency():
    apk = defaultdict(list)
    for root, dirs, files in os.walk('./results/paymentscope'):
        for dir in dirs:
            if 'HAND' in dir:
                continue
            dir_path = os.path.join(root,dir)   
            for root_1, dirs_1, files_1 in os.walk(dir_path): 
                lib2cpp_filepath = dir + '_libil2cpp.so'
                if lib2cpp_filepath not in files_1:   
                    print(dir + 'is not an Unity app')
                    break
                elif 'script.json' not in files_1:
                    print(dir + ' is protected')
                    break
                else:
                    with open (dir_path+'/script.json','r') as f,open('./results/'+dir+'.apk.yaml','r') as g:
                        mm = json.load(f)
                        nn = yaml.load(g)
                        for method in mm['ScriptMethod']:
                            if method['Name'] == 'OVRHand$$OVRSkeleton.IOVRSkeletonDataProvider.GetSkeletonPoseData':
                                if 'HAND_TRACKING' not in nn['app']['permissions']['dangerous']:
                                    apk['hand_inconsistency'].append(dir)
                            if method['Name'] == 'OVRBody$$OVRSkeletonRenderer.IOVRSkeletonRendererDataProvider.GetSkeletonRendererData':
                                if 'BODY_TRACKING' not in nn['app']['permissions']['dangerous']:
                                    apk['body_inconsistency'].append(dir)
                            if method['Name'] == 'OVREyeGaze$$CalculateEyeRotation':
                                if 'EYE_TRACKING' not in nn['app']['permissions']['dangerous']:
                                    apk['eye_inconsistency'].append(dir)
                            if method['Name'] == 'OVRFaceExpressions$$ToArray':
                                if 'FACE_TRACKING' not in nn['app']['permissions']['dangerous']:
                                    apk['face_inconsistency'].append(dir)
                    break
        break
    return apk


result_files_list = get_all_file(os.path.dirname(__file__)+'/results')

IAP_app = check_Unity_IAP(result_files_list)
inconsistency_app_category = check_permission_method_incosistency() 
inconsistency_app = []
for app in inconsistency_app_category['hand_inconsistency']:
    if app not in inconsistency_app:
        inconsistency_app.append(app)
for app in inconsistency_app_category['body_inconsistency']:
    if app not in inconsistency_app:
        inconsistency_app.append(app)
for app in inconsistency_app_category['eye_inconsistency']:
    if app not in inconsistency_app:
        inconsistency_app.append(app)
for app in inconsistency_app_category['face_inconsistency']:
    if app not in inconsistency_app:
        inconsistency_app.append(app)
print(inconsistency_app)

