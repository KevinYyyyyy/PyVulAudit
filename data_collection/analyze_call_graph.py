import json
from collections import defaultdict


def load_function_call_relations(json_file):
    """
    加载 JSON 文件中的函数调用关系。
    """
    try:
        with open(json_file, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError(f"文件 '{json_file}' 不存在。")
    except json.JSONDecodeError:
        raise ValueError(f"文件 '{json_file}' 不是有效的 JSON 格式。")


def analyze_function_calls(call_relations):
    """
    分析函数调用关系，构建调用图。
    """
    call_graph = defaultdict(set)
    for func, called_funcs in call_relations.items():
        call_graph[func].update(called_funcs)
    return call_graph


def find_truncated_call_chains(call_graph, start_func, target_keywords):
    """
    查找从指定函数开始的所有可能调用链，并在找到目标关键字时截断调用链。
    """
    all_chains = []

    def dfs(func, current_chain, visited):
        # 检查是否已经访问过当前函数（避免循环依赖）
        if func in visited:
            return
        visited.add(func)

        # 将当前函数加入调用链
        current_chain.append(func)

        # 检查是否满足目标关键字条件
        if all(keyword in " -> ".join(current_chain) for keyword in target_keywords):
            all_chains.append(list(current_chain))  # 保存当前调用链
            current_chain.pop()  # 回溯
            visited.remove(func)
            return

        # 继续递归查找
        for called_func in sorted(call_graph.get(func, [])):
            dfs(called_func, current_chain, visited)

        # 回溯：移除当前函数并标记为未访问
        current_chain.pop()
        visited.remove(func)

    # 开始递归查找
    dfs(start_func, [], set())
    return all_chains


def find_module_methods_and_chains_with_target(call_relations, module_prefix, target_keywords):
    """
    查找指定模块中的所有方法及其调用链，并筛选包含目标关键字的调用链。
    """
    # 筛选出属于指定模块的方法
    module_methods = {func for func in call_relations.keys() if func.startswith(module_prefix)}

    # 构建调用图
    call_graph = analyze_function_calls(call_relations)

    # 查找每个方法的所有可能调用链，并筛选符合条件的调用链
    method_chains_with_target = {}
    for method in sorted(module_methods):
        truncated_chains = find_truncated_call_chains(call_graph, method, target_keywords)
        if truncated_chains:
            method_chains_with_target[method] = truncated_chains

    return method_chains_with_target


# 示例用法
if __name__ == "__main__":
    # JSON 文件路径
    json_file = "./jarvis_outputs/numpy@1.8.1/sparselsh@1.1.3/sparselsh/lsh_PY/jarvis.json"

    # 模块前缀
    module_prefix = "sparselsh.lsh."

    # 目标关键字（例如 "load" 和 "numpy"）
    target_keywords = ["load", "numpy"]

    # 加载 JSON 文件
    call_relations = load_function_call_relations(json_file)

    # 查找模块中的方法及其符合条件的调用链
    method_chains_with_target = find_module_methods_and_chains_with_target(
        call_relations, module_prefix, target_keywords
    )

    # 打印结果
    print("模块 '{}' 中的方法调用链（包含 {} 的调用链）:".format(module_prefix, " 和 ".join(target_keywords)))
    for method, chains in method_chains_with_target.items():
        print(f"\n方法: {method}")
        for i, chain in enumerate(chains, 1):
            print(f"调用链 {i}: " + " -> ".join(chain))