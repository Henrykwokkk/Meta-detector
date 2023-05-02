import argparse
import multiprocessing
import os
import subprocess
from itertools import repeat

import yaml

# from analyser import Analyser
from analyser_new import Analyser_new_analysis



def main():
    parser = argparse.ArgumentParser(
        description="MetaDetector: VR App Security and Privacy Analysis System")
    parser.add_argument('path', metavar='APK_or_directory', type=str,
                        help='Path to the APK file or a directory containing APK files')
    parser.add_argument('-n', metavar='parallel_number', type=str,
                        help='The number of parallel works, default is the number of CPU cores', default=0)

    args = parser.parse_args()
    path = args.path
    number = int(args.n)
    if number == 0:
        number = multiprocessing.cpu_count()

    # detect java (for flowdroid)
    # process = subprocess.Popen(['java', '--version'],
    #                            stdout=subprocess.PIPE,
    #                            stderr=subprocess.PIPE)
    # _, stderr = process.communicate()


#    if len(stderr) > 0:
#        print("Java environment is not detected.")
#        print("Please add Java into system Path")
#        exit(1)

    file_list: [str] = []

    # load apk files
    if os.path.isdir(path):
        for subdir, dirs, files in os.walk(path):
            for filename in files:
                if filename.endswith(".apk"):
                    file_list.append(subdir + os.sep + filename)
            break
    elif os.path.isfile(path):
        file_list.append(path)
    else:
        print('file path error')
        exit(1)

    # check the sdk path
    with open(os.path.join(os.path.dirname(__file__), "assets" + os.path.sep + 'config.yaml'), 'r') as file:
        result: {} = yaml.load(file, Loader=yaml.FullLoader)

    sdk_path = result['sdk']
    if sdk_path is None or sdk_path == "":
        print('Please fill in the proper absolute path of Android SDK in assets/config.yaml')
        exit(1)

    # create working dir
    folder = "../" + "results" + os.path.sep + "flowdroid"
    if not os.path.exists(folder) or not os.path.isdir(folder):
        os.makedirs(folder, 0o777, True)

    for file in file_list:
        print(os.path.split(file)[-1])
        run_(file,sdk_path)




def run_(path, sdk):
    Analyser_new_analysis.start(path, sdk)


if __name__ == '__main__':
    main()
