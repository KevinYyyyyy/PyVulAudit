import os
from pathlib import Path
import json
import time
import tempfile
import requests
import glob
import shutil
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
from logger import logger
from constant import *
from itertools import chain
from joblib import Parallel, delayed
import subprocess
from collect_dependents import get_dependents_for_version,get_dependents_from_osi
from get_compatable_python_version import filter_versions
from pip._internal.models.wheel import Wheel
import fcntl
import contextlib
import pickle
import traceback
from my_utils import request_metadata_json_from_pypi,request_metadata_from_pypi, version_key,get_repo_name,get_modules_from_py_files
from collections import defaultdict
import docker
from packaging.version import parse
from packaging import version as py_version
from packaging.specifiers import SpecifierSet
import gc
import sys
from vul_analyze import find_vulnerable_calls,get_pkg2url,read_commit2methods,read_cve2advisory

from collect_pkg_metadata import get_all_upstream_versions,get_all_downstream_and_pairs, EnvAnalyzer
from visualize_stats import collect_stats, visualize_stats
from stdlib_list import stdlib_list
from tqdm import tqdm
from joblib import Parallel, delayed 
import networkx as nx


stdlib_modules = stdlib_list()



    
def get_direct_and_indirect_dependents(all_dependents, package, version):
    direct = all_dependents.get(package, {}).get(version, {}).get('direct', [])
    indirect = all_dependents.get(package, {}).get(version, {}).get('indirect', [])
    return direct, indirect

# 通过install获得更准确的path
def normalize_vulnerable_funcs(cve_id, vulnerable_funcs, upstream,workdir):

    #1. 常见的目录结构
    prefixes = ('src.', 'lib.', 'python.', 'pysrc.', 'Lib.', 'pylib.', 'python3.', 'master.', 'lib3.')

    def remove_first_prefix(name):
        for prefix in prefixes:
            if name.startswith(prefix):
                return name[len(prefix):]
        return name  # 没有匹配的前缀，返回原字符串

    vulnerable_funcs = [
        (func, remove_first_prefix(full_name))
        for func, full_name in vulnerable_funcs
    ]
    
    pkg, version = upstream

    package_dir = os.path.abspath(os.path.join(workdir, "pypi_packages", pkg, version))
    filtered_python_files =EnvAnalyzer.find_project_py_files(pkg, version,workdir=workdir)
        
    if len(filtered_python_files)==0 and upstream in all_upstream_with_py_file:
        print(filtered_python_files)
        print(upstream)
        assert False

    modules = get_modules_from_py_files(pkg, version, filtered_python_files)

    normalized_funcs = []
    # logger.debug(f"filtered_python_files:{filtered_python_files}")
    
    # 针对gradio，VF存在多个package，例如gradio-client和gradio
    # logger.debug(f"vulnerable_funcs:{vulnerable_funcs}")
    for func,full_name in vulnerable_funcs:
        # TODO: 处理top-level func
        find_match = None
        for module in modules:
            if full_name.startswith(module+'.'):
                find_match = module
                break
            elif '.'+module+'.' in full_name:
                print(f"module:{module}")
                print(full_name)
                print(modules)
                assert False
        if find_match:
            normalized_funcs.append((func, full_name))
        else:
            # 如果没有找到匹配的模块，保持丢弃
            # 例子，例如gradio会被打包成gradio和gradio_client两个包
            # logger.warning(f"Not found func:{func} full_name:{full_name} in {upstream}")
            # logger.debug(f"modules in {upstream}:{modules}")
            pass
            
                

    if len(normalized_funcs) < len(vulnerable_funcs):
        # logger.debug(f"vulnerable_funcs:{vulnerable_funcs}")
        # logger.debug(f"modules:{modules}")
        for func,full_name in vulnerable_funcs:
            if func not in [item[0] for item in normalized_funcs]:
                pass
                # logger.warning(f"Not found {func} {full_name} ")


    if len(normalized_funcs) == 0:
        logger.warning(f"Not found any VFs in {upstream}")

    # logger.debug(f"normalized_vulnerable_funcs:{normalized_funcs}")
    return normalized_funcs, modules


def import_analysis(call_graph, upstream_modules):
    # 检查upstream_modules是否出现在cg中
    all_nodes = set(call_graph.keys())
    in_cg = len(all_nodes.intersection(upstream_modules)) > 0
    return in_cg

def build_reverse_call_graph(call_graph):
    reverse_graph = defaultdict(set)

    for caller, callees in call_graph.items():
        for callee in callees:
            reverse_graph[callee].add(caller)
    
    # 确保所有节点都出现在 reverse_graph 中（包括没有被调用的）
    for node in call_graph:
        if node not in reverse_graph:
            reverse_graph[node] = []

    return reverse_graph

def get_all_call_chains(reverse_graph, target_func):
    paths = []

    def dfs(node, path, visited):
        if node in visited:
            return
        visited.add(node)
        path.append(node)
        tmp = reverse_graph.get(node, [])
        if len(set(tmp)-set(path)) == 0: #! 避免漏掉存在环的case
            paths.append(list(reversed(path)))
        else:
            for caller in reverse_graph.get(node, []):
                dfs(caller, path, visited)
        path.pop()
        visited.remove(node)

    dfs(target_func, [], set())
    return paths


def dfs_call_chain(graph, node, path=None, visited=None, max_depth=10):
    if path is None:
        path = []
    if visited is None:
        visited = set()

    path.append(node)
    visited.add(node)

    yield list(path)  # 👈 就是这里的 yield！

    if len(path) < max_depth:
        for succ in graph.get(node,[]):
            if succ not in visited:
                yield from dfs_call_chain(graph, succ, list(path), visited.copy())

def cg_analysis(call_graph, vulnerable_funcs,downstream_modules,downstream=None):
    all_nodes = set(call_graph.keys()) # 包含了module，class和func
    # TODO: 处理top-level func
    vulnerable_funcs_full_names = []
    top_level_func = {}
    for func,full_name in vulnerable_funcs:
        if '.<main>' in full_name:
            module_name = full_name.removesuffix('.<main>')
            # logger.warning(f"func,full_name:{func,full_name}")
            top_level_func[module_name] = full_name
            # assert False
            vulnerable_funcs_full_names.append(module_name)
        else:
            vulnerable_funcs_full_names.append(full_name)

    in_cg_funcs = all_nodes.intersection(vulnerable_funcs_full_names)

    # logger.debug(f"in_cg_funcs:{in_cg_funcs}, {len(vulnerable_funcs)}", )       
    if len(in_cg_funcs):
        # reverse_graph = build_reverse_call_graph(call_graph)

        G = nx.DiGraph()

         # reverse_graph 
        for src, dsts in call_graph.items():
            # if src =='mlflow_cratedb.patch.mlflow.settings':
            #     print(dsts)
            #     assert False
            for dst in dsts:
                G.add_edge(dst, src)
     
        # 得到downstream中的所有节点
        # 判断all nodes是否以任意一个module为前缀
        entry_funcs = set()
        for node in all_nodes:
            if any([node.startswith(module) for module in downstream_modules]) and node in G.nodes():
                entry_funcs.add(node)

        call_chains = []
        all_vulnerable_invocations_in_downstream=[]
        logger.info(f"getting call chains for {len(in_cg_funcs)} funcs, downstream {downstream}, {len(all_nodes)} nodes")
        logger.debug(f"in_cg_funcs:{in_cg_funcs}")
        for func in in_cg_funcs:
            for entry_func in entry_funcs:
                if nx.has_path(G, source=func, target=entry_func):
                    all_vulnerable_invocations_in_downstream.append(entry_func)
                    # shortest_path = nx.shortest_path(G, source=func, target=entry_func)
                    # # all_paths = nx.all_simple_edge_paths(G, source=func, target=entry_func, cutoff=10)
                    # for path_i, path in enumerate([shortest_path]):
                    #     if path_i>=10:
                    #         break
                    #     # reverse path
                    #     path = list(reversed(path))
                    #     path = [node if node not in top_level_func else top_level_func[node] for node in path]
                    #     call_chains.append(path)
            # assert len(call_chains) > 0
        # print(call_chains)
        def filter_call_chains(call_chains):
            # 去除子路径，只保留最长的路径
            filtered_chains = []
            for i, path1 in enumerate(call_chains):
                is_subpath = False
                for j, path2 in enumerate(call_chains):
                    if i != j and len(path1) < len(path2):
                        # 检查path1是否是path2的子路径
                        for k in range(len(path2) - len(path1) + 1):
                            if path2[k:k+len(path1)] == path1:
                                is_subpath = True
                                break
                    if is_subpath:
                        break
                if not is_subpath:
                    filtered_chains.append(path1)
            return filtered_chains
        # if len(call_chains) == 0:
         
        #     logger.debug(f"targets:{targets}")
        #     logger.debug(f"vulnerable_funcs: {vulnerable_funcs}")

        #     assert False
        # filtered_call_chains = filter_call_chains(call_chains)
        # logger.info(f"Found {len(filtered_call_chains)} call chains after filtering from {len(call_chains)} call chains , {len(all_vulnerable_invocations_in_downstream)} vulnerable invocations in downstream {downstream}")
    
        filtered_call_chains = []
        call_chains = filtered_call_chains
        # assert False
    else:
        call_chains=[]
        all_vulnerable_invocations_in_downstream = []
    # transform top-level func
    in_cg_funcs = [func if func not in top_level_func else top_level_func[func] for func in in_cg_funcs]

    return in_cg_funcs,call_chains,all_vulnerable_invocations_in_downstream


def check_cg(cve_id, upstream,downstream, vulnerable_funcs,upstream_modules,rewrite=False):
    package, version = downstream
    result_file = Path(f'./cg_results/{cve_id}/{"@".join(downstream)}_results.json')
    if not rewrite and result_file.exists():
        with open(result_file, 'r') as f:
            results = json.load(f)
            return downstream, "VF Found"
    
    #. load cg
    jarvis_output_file = os.path.abspath(str(CALL_GRAPH_DIR /package/version/ f'jarvis_cg.json'))
    jarvis_error_file = os.path.abspath(str(CALL_GRAPH_DIR /package/version/ f'ERROR'))

    if not os.path.exists(jarvis_output_file):
        if sys.platform == 'darwin':
            jarvis_output_file = os.path.abspath(str(CALL_GRAPH_DIR.parent / 'call_graphs_v1' /package/version/ f'jarvis_cg.json'))
            if not os.path.exists(jarvis_output_file):
                return downstream,"Jarvis Failed"
        else:
            if os.path.exists(jarvis_error_file):
                return downstream,"Jarvis Failed"
            else:
                return downstream, "Not Jarvis"

    try:
        with open(jarvis_output_file,'r') as f:
            call_graph = json.load(f)
    except:
        return downstream,"JSON Failed"
    
    #! 1. import-level过滤
    # TODO： 更准确的import-analysis
    import_result = import_analysis(call_graph, upstream_modules)
    if not import_result:
        # logger.debug(f"Not found upstream {upstream} in {downstream} cg")
        return downstream,"Import Failed"

    #! 2. func-level过滤
    def normalize_cg(call_graph, prefix):
        def normalize_func_name(func_name):
            if func_name.startswith(prefix):
                return func_name.removeprefix(prefix)
            else:
                return func_name
        def is_builtin_module(module_name):
            return module_name in sys.builtin_module_names
        def is_stdlib_module(module_name):
            return module_name in stdlib_modules
        new_cg = defaultdict(set)
        # normalize cg 防止key出现了多次
        # 如果出现docker前缀，则移除
        # simplify cg 移除标准库

        for func, all_callee in call_graph.items():
            if is_stdlib_module(func) or is_builtin_module(func):
                continue        
            new_cg[normalize_func_name(func)].update([normalize_func_name(callee) for callee in all_callee if not is_stdlib_module(callee) and not is_builtin_module(callee)])
        new_cg = {k:list(v) for k,v in new_cg.items()}
        return new_cg
    prefix = "...docker_workdir.pypi_packages." +  f"{package}.{version}."
    new_cg = normalize_cg(call_graph,prefix=prefix)

    #过滤call chain，只保留chain中包含downstream module的call chain
    filtered_python_files =EnvAnalyzer.find_project_py_files(package, version,workdir='../docker_workdir')
    downstream_modules = get_modules_from_py_files(package, version, filtered_python_files)
    try:
        in_cg_vfs, call_chains,all_vulnerable_invocations_in_downstream = cg_analysis(new_cg, vulnerable_funcs,downstream_modules, downstream)
    except:
        print(downstream)
        assert False
    if not len(in_cg_vfs):
        # logger.debug(f"Not found VFs in {downstream} cg")
        return downstream,"VF Not Found"
    else:
        # assert len(call_chains)
        pass


    logger.warning(f"Found vulnerable functions in call graph: {in_cg_vfs} for downstream {downstream}")
    result_data = {
            'cve_id': cve_id,
            'upstream_package': upstream[0],
            'upstream_version': upstream[1],
            'downstream_package': package,
            'downstream_version': version,
            'vulnerable_functions': [item[1] for item in vulnerable_funcs],
            'found_functions': list(in_cg_vfs),
            'call_chains': call_chains,
            'vulnerable_invocation':list(all_vulnerable_invocations_in_downstream)
        }
    if not result_file.parent.exists():
            result_file.parent.mkdir(parents=True, exist_ok=True)
        
    with open(result_file, 'w') as f:
        json.dump(result_data, f, indent=2)
    return downstream, "VF Found"


def check_reachability(results_file, rewrite_cve_results=False, rewrite_cg_results=False):
    
    all_results = dict()
    continue_ = True
    for idxx, (cve_id,advisory) in enumerate(cve2advisory.items()):
        # logger.info(f"Processing {cve_id} {idxx}/{len(cve2advisory)}")
        # if cve_id == 'CVE-2020-1747':
        #     continue_ = False
        # if continue_:
        #     continue
        cve_results_file = REACHABILITY_DIR_DATE / f'{cve_id}_results.json'
        
        # cve_results_file = Path(f'./cve_results/{cve_id}_results.json')
        if not rewrite_cve_results and cve_results_file.exists():
            with open(cve_results_file, 'r') as f:
                results = json.load(f)
                all_results[cve_id] = results
                continue
        cve_results = defaultdict(dict)
        pairs = all_pairs.get(cve_id, None)
        if not pairs:
            continue
        for idxxx,(upstream, all_downstream) in enumerate(pairs.items()):
            if specific_cve_id and cve_id != specific_cve_id:
                continue
            if len(all_downstream) == 0:
                continue
            logger.info(f"Processing upstream {upstream} with {len(all_downstream)} downstream for {cve_id} {idxx}/{len(cve2advisory)}")

            repo_url = pkg2url[upstream[0]]
            # 1. 根据upstream获得vulnerable funcs
            # 由于VF是从repo中获得的，所以需要normalize namespace
            vulnerable_funcs, code_changes = get_vulnerable_funcs_for_cve(cve_id, get_repo_name(repo_url),return_code_changes=True)
            # logger.info(f"vulnerable_funcs:{vulnerable_funcs}")
            # logger.info(f"code_changes:{code_changes}")
            normalized_vulnerable_funcs, all_upstream_modules = normalize_vulnerable_funcs(cve_id,vulnerable_funcs,upstream, workdir)
            # logger.debug(f"normalized_vulnerable_funcs:{normalized_vulnerable_funcs}")
            upstream_results = dict()
            if len(normalized_vulnerable_funcs) == 0:
                upstream_results['@'.join(upstream)] = "VF Not Found"
                continue

            results = Parallel(n_jobs=30, backend='threading', verbose=0)(
                delayed(check_cg)(cve_id, upstream ,downstream, normalized_vulnerable_funcs, all_upstream_modules,rewrite_cg_results) 
                for downstream in tqdm(all_downstream, desc=f"Processing upstream {upstream} ({idxxx}/{len(pairs)}) for {cve_id}")
            )
            for downstream, result in results:
                upstream_results['@'.join(downstream)] = result
            cve_results['@'.join(upstream)] = upstream_results
        all_results[cve_id] = cve_results
        # with open(cve_results_file, 'w') as f:
            # json.dump(cve_results, f)
        # assert False
    # Save overall results
    os.makedirs(os.path.dirname(results_file), exist_ok=True)
    # with open(results_file, 'w') as f:
    #     json.dump(all_results, f)



from graphviz import Digraph

def visualize_call_chains(call_chains, output_file,format_='png'):
    dot = Digraph(format='png')

    # 用于去重节点和边
    nodes = set()
    edges = set()

    for chain in call_chains:
        for i in range(len(chain) - 1):
            src = chain[i]
            dst = chain[i + 1]
            edges.add((src, dst))
            nodes.add(src)
            nodes.add(dst)

    # 添加所有节点和边到图中
    for node in nodes:
        dot.node(node)

    for src, dst in edges:
        dot.edge(src, dst)

    # 渲染输出
    dot.render(output_file, view=False)
    print(f"调用图已保存为 {output_file}.{format_}")

def cal_stats(cve2advisory,results_file,rewrite=False, show=False):
    import numpy as np

    with open(results_file, 'r') as f:
        all_results = json.load(f)
    total_cves = len(all_results)
    activte_cves = []
    total_pairs = 0
    activte_pairs = []
    success = 0
    total_downstream = set()
    affecting_downstream = set()
    reason_counter = defaultdict(int)

    all_call_chains = []
    all_call_chains_len = []

    all_vulnerable_invocation = []
    for cve_id, cve_results in all_results.items():
        logger.info(f"{cve_id} has {len(cve_results)} results")
        cve_affects_others = False
        
        for upstream, all_downstream in cve_results.items():
            if "VF Not Found" == all_downstream:
                # assert False
                ...
            total_pairs += len(all_downstream)
            total_downstream.update(all_downstream.keys())
            for downstream, reason in all_downstream.items():
                reason_counter[reason] += 1
                if reason == 'VF Found':
                    cve_affects_others = True
                    activte_pairs.append((upstream, downstream))
                    affecting_downstream.add(downstream)

                    result_file = Path(f'./cg_results/{cve_id}/{downstream}_results.json')

                    with open(result_file, 'r') as f:
                        result_data = json.load(f)
                    
                    # 1. 统计call chain
                    call_chains = result_data['call_chains']
                    if len(call_chains) ==0:
                        jarvis_output_file = os.path.abspath(str(CALL_GRAPH_DIR /downstream.split('@')[0]/downstream.split('@')[1]/ f'jarvis_cg.json'))
                        # print(jarvis_output_file)
                        # TODO:
                        # assert False, f"{jarvis_output_file} {result_file}"
                    else:
                        all_call_chains.append(len(call_chains))
                        # logger.debug(f"len(call_chains),result_file: {len(call_chains)}, {result_file}")
                        all_call_chains_len.append([len(call_chain) for call_chain in call_chains])
                        
                    #2. 统计downstream中 vulnerable invocation的数量
                    vulnerable_invocation = result_data['vulnerable_invocation']
                    all_vulnerable_invocation.append(len(vulnerable_invocation))

                    vis_file = Path(f'./cg_results/{cve_id}/{downstream}_vis.png')
                    if (vis_file.exists() and not rewrite) or sys.platform != 'darwin':
                        continue
                    
                    visualize_call_chains(call_chains, output_file=f'./cg_results/{cve_id}/{downstream}_vis', format_='png')
                                 
        if cve_affects_others:
            activte_cves.append(cve_id)
    
    # 打印统计信息
    total_cves = len(cve2advisory)
    print(f"CVE总数: {total_cves}")
    print(f"能影响其他项目的CVE数量: {len(activte_cves)}")
    print(f"影响率 cve-level: {len(activte_cves)}/{total_cves} ({len(activte_cves)/total_cves:.2%})")
    # print(f"activte_cves:{activte_cves}")
    print(f"影响率 (upstream, downstream)-level: {len(activte_pairs)}/{total_pairs} ({len(activte_pairs)/total_pairs:.2%})")
    print(f"成功影响的(上游，下游)对数: {len(activte_pairs)}")
    print(f"影响率 downstream-level: {len(affecting_downstream)}/{len(total_downstream)} ({len(affecting_downstream)/len(total_downstream):.2%})")

    # if total_pairs > 0:
    #     print(f"下游项目影响成功率: {len(activte_pairs)/total_pairs:.2%}")
    print("各原因统计：")
    for reason, count in reason_counter.items():
        print(f"{reason}: {count} ({count/total_pairs:.2%})")

    # print("call chain 统计：")
    # print(f"call chain 总数: {sum(all_call_chains)}")
    # print(f"call chain 平均数量: {sum(all_call_chains)/len(all_call_chains):.2f}")
    # #计算三分数
    # print(f"call chain 三分数: {np.percentile(all_call_chains, [25, 50, 75])}")
    # # outliers
    # # print(f"call chain 99%: {round(np.percentile(all_call_chains, 99),2)}")
    # print()
    # print("call chain 长度统计：")
    # print(f"call chain 长度总数: {sum([sum(chain) for chain in all_call_chains_len])}")
    # print(f"call chain 长度平均数量: {sum([sum(chain) for chain in all_call_chains_len])/sum(all_call_chains):.2f}")
    # #计算三分数
    # print(f"call chain 长度三分数: {np.percentile([sum(chain) for chain in all_call_chains_len], [25, 50, 75])}")
    # outliers
    # print(f"call chain 长度99%: {round(np.percentile([sum(chain) for chain in all_call_chains_len], 99),2)}")

    print()
    print("vulnerable invocation 统计：")
    print(f"vulnerable invocation 总数: {sum(all_vulnerable_invocation)}")
    print(f"vulnerable invocation 平均数量: {sum(all_vulnerable_invocation)/len(all_vulnerable_invocation):.2f}")
    #计算三分数
    print(f"vulnerable invocation 三分数: {np.percentile(all_vulnerable_invocation, [25, 50, 75])}")
    # outliers
    # print(f"vulnerable invocation 99%: {round(np.percentile(all_vulnerable_invocation, 99),2)}")

    print()
     # 统计一个downstream可能受upstream影响的个数
    downstream2upstream = defaultdict(set)
    for upstream, downstream in activte_pairs:
        downstream2upstream[downstream].add(upstream)
    all_upstream_cnt=[len(upstreams) for upstreams in downstream2upstream.values()]
    print(f"一个downstream可能受upstream影响的个数 总数: {sum(all_upstream_cnt)}")
    print(f"一个downstream可能受upstream影响的个数 平均数量: {sum(all_upstream_cnt)/len(all_upstream_cnt):.2f}")
    print(f"一个downstream可能受upstream影响的个数 三分数: {max(all_upstream_cnt)}")
    more_than_one_up_cnt = 0
    for i in all_upstream_cnt:
        if i>1:
            more_than_one_up_cnt += 1
    print(f"一个downstream可能受upstream影响的个数 大于1的个数: {more_than_one_up_cnt}")




    
     # 收集并保存统计数据
    stats = collect_stats(total_cves, activte_cves, total_pairs, activte_pairs, 
                         total_downstream, reason_counter, all_call_chains, 
                         all_call_chains_len, all_vulnerable_invocation)
    
    # 可视化统计数据
    if sys.platform == 'darwin':
        visualize_stats(stats, output_file = '../figs/cve_impact_analysis.png', show=show)


if __name__ == '__main__':
    workdir = Path('../docker_workdir')

    import argparse
    parser = argparse.ArgumentParser(description='Process CVE data.')
    parser.add_argument('--size', type=str, choices=['small','large','medium'], default='small', help='Size of the dataset')
    args = parser.parse_args()
    if args.size == 'small':
        install_tasks_file = workdir / 'install_tasks_small.json'
        metadata_file = Path('./all_metadata_small.json')
        cve2advisory  = read_cve2advisory(cve_has_vf=True)
        pairs_cache_file = workdir / 'get_all_downstream_and_pairs_results_small.pkl'
        pkg_with_py_file_cache_file = workdir / 'all_pkgs_with_py_file_small.pkl'
        results_file = './all_results_small.pkl'


    elif args.size == 'medium':
        install_tasks_file = workdir / 'install_tasks_medium.json'
        metadata_file = Path('./all_metadata_medium.json')
        cve2advisory  = read_cve2advisory(medium=True)
        pairs_cache_file = workdir / 'get_all_downstream_and_pairs_results_medium.pkl'
        pkg_with_py_file_cache_file = workdir / 'all_pkgs_with_py_file_medium.pkl'
        results_file = './all_results_medium.pkl'
    else:
        install_tasks_file = workdir / 'install_tasks.json'
        metadata_file = Path('./all_metadata_large.json')
        cve2advisory  = read_cve2advisory()
        pairs_cache_file = workdir / 'get_all_downstream_and_pairs_results_large.pkl'
        pkg_with_py_file_cache_file = workdir / 'all_pkgs_with_py_file_large.pkl'
        results_file = './all_results_large.pkl'

    

    if pairs_cache_file.exists() and True:
        with open(pairs_cache_file, 'rb') as f:
            _, all_pairs = pickle.load(f)
    else:
        assert False
    if pkg_with_py_file_cache_file.exists() and True:
        with open(pkg_with_py_file_cache_file, 'rb') as f:
            all_downstream_with_py_file, all_upstream_with_py_file = pickle.load(f)
    else:
        
        assert False
    all_upstream = list(set(chain.from_iterable(all_pairs.values())))
    
    pkg2url = get_pkg2url()
    specific_cve_id = None

    # 执行漏洞可达性分析：检查CVE漏洞在依赖关系图中的传播路径
    # rewrite_cve_results=True: 重新生成CVE结果文件
    # rewrite_cg_results=False: 不重新生成调用图结果，使用缓存
    # check_reachability(results_file,rewrite_cve_results=False,rewrite_cg_results=False)

    cal_stats(cve2advisory,results_file,rewrite=False)



   