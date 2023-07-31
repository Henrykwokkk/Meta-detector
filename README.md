# Meta-detector
This is an automatic security and privacy evaluation tool for Metaverse-related VR apps.
## Requirements
Python 3.7

Pytorch 1.8

Java 11

Dotnet core 3.1

## Static Analysis Configuration
The configuration refers to [covid-guardian](https://github.com/covid-guardian/covid-guardian).

Firstly, fill in the proper absolute path of android sdk in `staticanalyzer/config.yaml`
```text
sdk: 'path_to_android_sdk'
```
The configuration of IAP vulnerability and biometric data collection usage detection refers to [PaymentScope](https://github.com/OSUSecLab/PaymentScope).

Download PaymentScope repository in and unzip PaymentScope folder.

The file `PaymentScope\src\ghidra_scripts` needs to be moved to `~/ghidra_scripts` for running which is required by Ghidra.

## Usage
command line 
```text
 $ python ./staticanalyzer/main.py APK_OR_DIRECTORY_PATH
```
## Result Analysis
The analysis results are generated in `results` file. Each app will be output in a `yaml` file. 

The IAP vulnerability analysis and inconsistency biometrc data collection function usage can be executed by running `result_analysis.py`

## Privacy Policy Analysis
1. Download the `HTML` file of the privacy policy from the app's homepage.

2. Use the following command line to transfer the `HTML` file to `txt` file.
```text
 $ python ./PolicyAnalysis/network-to-policy_consistency/Preprocessor.py --input ./ext/html_policies --outputdir ./ext/plaintext_policies
```

3.  Download the NLP model provided by the [original PolicyLint](https://github.com/benandow/PrivacyPolicyAnalysis) and extract the `tar.gz` file into ext/.

4. Use the following command line to use the NLP tool to generate `<entity, action, datatype>` stataments.
```text
 $ python ./PolicyAnalysis/network-to-policy_consistency/PatternExtractionNotebook.py ./ext
```
The process results are in `PolicyAnalysis/network-to-policy_consistency/ext/output`. Transfer the files in this path to JSON format and move the files to `results/policy`.
