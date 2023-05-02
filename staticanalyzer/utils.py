from androguard.core.analysis.analysis import ClassAnalysis
from androguard.core.bytecodes.dvm import EncodedMethod


def generate_result_list(the_list: [(ClassAnalysis, EncodedMethod)]) -> [str]:
    result: [str] = []
    for (_, p_method) in the_list:
        p_method: EncodedMethod = p_method
        result.append(p_method.get_class_name() + "." + p_method.get_name())
    return result
