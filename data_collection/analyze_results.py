from turtle import down
from typing import Dict, List, Tuple, Set, Optional, Any
import pickle
import json
from dataclasses import dataclass
from pathlib import Path
import networkx as nx
from tqdm import tqdm
from joblib import Parallel, delayed
from graphviz import Digraph
import numpy as np

from datetime import datetime
from logger import logger
from constant import CALL_GRAPH_DIR, DATA_DIR,REACHABILITY_DIR_DATE,CALL_GRAPH_DIR_DATE,CODE_CHANGES_DIR_DATE,REACHABILITY_RESULT_DIR_DATE,VUL_PACKAGES_DIR_DATE,SUFFIX,SNAPSHOT_DIR,CG_DIR_DATE
from my_utils import get_repo_name, get_modules_from_py_files
from vul_analyze import get_pkg2url, read_cve2advisory
from collections import defaultdict,deque

class StatisticsCalculator:
    """Calculates and displays analysis statistics with detailed reachability metrics."""
    
    def __init__(self,only_one_vf=False):
        # self.results_file = REACHABILITY_RESULT_DIR_DATE/f'all_results_backup.pkl'
        self.results_file = REACHABILITY_RESULT_DIR_DATE/f'all_results_large.json'
        self.all_results = self.load_results_flexible()
        self.only_one_vf=only_one_vf
    
        self.cve2advisory = read_cve2advisory(cve_has_vf=True, only_one_vf=self.only_one_vf)

        new_all_results = {}
        for cve_id, res in self.all_results.items():
            if cve_id not in self.cve2advisory:
                continue
            new_all_results[cve_id] = res
        self.all_results = new_all_results
    def load_results_flexible(self) -> Dict:
        """灵活加载结果数据的备选方式"""
        
        # 方式1: 尝试加载完整结果文件
        if self.results_file.exists():
            try:
                with self.results_file.open('r') as f:
                    return json.load(f)
            except Exception as e:
                pass
        
        # 方式2: 从单个CVE结果文件重建
        logger.info("Loading from individual CVE result files...")
        all_results = {}
        assert False, self.results_file
        
        for cve_result_file in REACHABILITY_DIR_DATE.glob('*_results.json'):
            cve_id = cve_result_file.stem.replace('_results', '')
            try:
                with open(cve_result_file, 'r') as f:
                    cve_results = json.load(f)
                all_results[cve_id] = cve_results
            except Exception as e:
                logger.warning(f"Failed to load {cve_result_file}: {e}")
        
        # 方式3: 从CG结果目录扫描重建
        if not all_results:
            assert False
            logger.info("Reconstructing from CG result directories...")
            for cve_dir in CG_DIR_DATE.iterdir():
                if not cve_dir.is_dir():
                    continue
                
                cve_id = cve_dir.name
                cve_results = defaultdict(dict)
                
                for result_file in cve_dir.glob('*_results.json'):
                    downstream = result_file.stem.replace('_results', '')
                    try:
                        with open(result_file, 'r') as f:
                            result_data = json.load(f)
                        
                        upstream = f"{result_data['upstream_package']}@{result_data['upstream_version']}"
                        cve_results[upstream][downstream] = 'VF Found'
                        
                    except Exception as e:
                        continue
                
                if cve_results:
                    all_results[cve_id] = dict(cve_results)
        
        return all_results

    def analyze_cve_downstream_impact(self, all_results: Dict) -> Dict[str, Any]:
        """统计CVE影响downstream包的情况，保留详细信息用于排序分析"""
        
        # 收集原始数据
        all_upstream_downstream_pairs = []  # (cve_id, upstream, downstream, status)
        all_cve_downstream_pairs = []       # (cve_id, downstream, has_reachable)
        
        # 用于统计唯一的downstream和upstream
        all_downstreams = set()
        all_upstreams = set() 
        impacted_downstreams = set()  # 被影响的downstream包（至少有一个reachable连接）
        impacting_upstreams = set()   # 有影响的upstream包（至少有一个reachable连接）
        
        for cve_id, cve_results in all_results.items():
            # 收集CVE级别的downstream影响
            cve_downstream_impact = {}  # downstream -> has_reachable
            
            for upstream, downstream_results in cve_results.items():
                if isinstance(downstream_results, str):
                    continue
                
                # 记录所有upstream
                all_upstreams.add(upstream)
                    
                for downstream, status in downstream_results.items():
                    # 记录所有downstream
                    all_downstreams.add(downstream)
                    
                    # 记录upstream-downstream pair
                    all_upstream_downstream_pairs.append((cve_id, upstream, downstream, status))
                    
                    # 更新CVE-downstream影响状态
                    if downstream not in cve_downstream_impact:
                        cve_downstream_impact[downstream] = False
                    if status == 'VF Found':
                        cve_downstream_impact[downstream] = True
                        # 记录有影响的包
                        impacted_downstreams.add(downstream)
                        impacting_upstreams.add(upstream)
            
            # 记录CVE-downstream pairs
            for downstream, has_reachable in cve_downstream_impact.items():
                all_cve_downstream_pairs.append((cve_id, downstream, has_reachable))
        
        # 统计分析
        reachable_upstream_downstream = [(cve, up, down) for cve, up, down, status in all_upstream_downstream_pairs if status == 'VF Found']
        reachable_cve_downstream = [(cve, down) for cve, down, reachable in all_cve_downstream_pairs if reachable]
        
        # CVE影响力排序
        cve_impact_ranking = self._rank_cve_impact(all_cve_downstream_pairs)
        upstream_impact_ranking = self._rank_upstream_impact(all_upstream_downstream_pairs)
        
        return {
            'raw_data': {
                'all_upstream_downstream_pairs': all_upstream_downstream_pairs,
                'all_cve_downstream_pairs': all_cve_downstream_pairs,
                'reachable_upstream_downstream_pairs': reachable_upstream_downstream,
                'reachable_cve_downstream_pairs': reachable_cve_downstream,
                'impacted_downstreams':impacted_downstreams,
                'impacting_upstreams':impacting_upstreams,
            },
            'summary_stats': {
                'total_cves': len(all_results),
                'total_upstream_downstream_pairs': len(all_upstream_downstream_pairs),
                'total_cve_downstream_pairs': len(all_cve_downstream_pairs),
                'reachable_upstream_downstream_pairs': len(reachable_upstream_downstream),
                'reachable_cve_downstream_pairs': len(reachable_cve_downstream),
                'impacting_cves': len(set(cve for cve, _, _ in reachable_upstream_downstream)),
                'impacting_cves_rate': round(len(set(cve for cve, _, _ in reachable_upstream_downstream)) * 100 / len(all_results), 2),
                
                # 新增的downstream和upstream统计
                'total_downstream_packages': len(all_downstreams),
                'total_upstream_packages': len(all_upstreams),
                'impacted_downstream_packages': len(impacted_downstreams),
                'impacting_upstream_packages': len(impacting_upstreams),
                'downstream_impact_rate': round(len(impacted_downstreams) * 100 / len(all_downstreams), 2) if len(all_downstreams) > 0 else 0,
                'upstream_impact_rate': round(len(impacting_upstreams) * 100 / len(all_upstreams), 2) if len(all_upstreams) > 0 else 0,
            },
            'impact_rankings': {
                'cve_impact_ranking': cve_impact_ranking,
                'upstream_impact_ranking': upstream_impact_ranking
            }
        }
    def _rank_cve_impact(self,cve_downstream_pairs: List) -> Dict:
        """分析CVE影响力排序"""
        cve_stats = defaultdict(lambda: {'total_upstream_downstream': 0, 'reachable_upstream_downstream': 0, 
                                        'total_cve_downstream': 0, 'reachable_cve_downstream': 0})
        
        
        # 统计cve-downstream级别
        for cve_id, downstream, has_reachable in cve_downstream_pairs:
            cve_stats[cve_id]['total_cve_downstream'] += 1
            if has_reachable:
                cve_stats[cve_id]['reachable_cve_downstream'] += 1
        
        # 排序
        cve_ranking = []
        for cve_id, stats in cve_stats.items():
            cve_ranking.append({
                'cve_id': cve_id,
                **stats,
                'cve_downstream_impact_rate': stats['reachable_cve_downstream'] / stats['total_cve_downstream'] if stats['total_cve_downstream'] > 0 else 0
            })
        
        return {
            'by_reachable_cve_downstream': sorted(cve_ranking, key=lambda x: x['reachable_cve_downstream'], reverse=True),
            'by_cve_downstream_rate': sorted(cve_ranking, key=lambda x: x['cve_downstream_impact_rate'], reverse=True)
        }
    
    def _rank_upstream_impact(self, upstream_downstream_pairs: List) -> List:
        """分析upstream影响力排序"""
        upstream_stats = defaultdict(lambda: {'total': 0, 'reachable': 0, 'affected_downstreams': set()})
        
        for cve_id, upstream, downstream, status in upstream_downstream_pairs:
            upstream_key = f"{upstream}@{cve_id}"
            upstream_stats[upstream_key]['total'] += 1
            upstream_stats[upstream_key]['affected_downstreams'].add(downstream)
            if status == 'VF Found':
                upstream_stats[upstream_key]['reachable'] += 1
        
        ranking = []
        for upstream_key, stats in upstream_stats.items():
            ranking.append({
                'upstream_cve': upstream_key,
                'total_downstream_pairs': stats['total'],
                'reachable_downstream_pairs': stats['reachable'],
                'unique_affected_downstreams': len(stats['affected_downstreams']),
                'impact_rate': stats['reachable'] / stats['total'] if stats['total'] > 0 else 0
            })
        
        return sorted(ranking, key=lambda x: x['reachable_downstream_pairs'], reverse=True)
    
    def calculate_true_positives(self, all_results: Dict) -> Dict[str, Any]:
        """
        计算CVE-Downstream对中有多少个是True Positive (VF Found)
        
        Returns:
            Dict containing true positive statistics
        """
        tp_stats = {
            'total_pairs': 0,
            'true_positives': 0,
            'true_positive_rate': 0.0,
            'status_breakdown': defaultdict(int),
            'cve_tp_breakdown': {}
        }
        
        for cve_id, cve_results in all_results.items():
            cve_total = 0
            cve_tp = 0
            
            for upstream, downstream_results in cve_results.items():
                if isinstance(downstream_results, str):
                    continue
                    
                for downstream, status in downstream_results.items():
                    tp_stats['total_pairs'] += 1
                    tp_stats['status_breakdown'][status] += 1
                    cve_total += 1
                    
                    if status == 'VF Found':
                        tp_stats['true_positives'] += 1
                        cve_tp += 1
            
            if cve_total > 0:
                # if cve_tp == cve_total:
                #     logger.warning(f"{cve_tp , cve_total,cve_tp / cve_total}")
                tp_stats['cve_tp_breakdown'][cve_id] = {
                    'total': cve_total,
                    'true_positives': cve_tp,
                    'tp_rate': cve_tp / cve_total
                }
        
        if tp_stats['total_pairs'] > 0:
            tp_stats['true_positive_rate'] = tp_stats['true_positives'] / tp_stats['total_pairs']
        
        return tp_stats
    
    def analyze_reachable_pairs_details(self, all_results: Dict) -> Dict[str, Any]:
        """分析reachable的pair，高效收集call chain信息"""
        
        def extract_call_chains(call_graph: Dict, found_functions: List, vulnerable_invocations: List) -> List[List[str]]:
            """精细化提取call chains，处理found_functions间的依赖关系"""
            if not found_functions or not vulnerable_invocations:
                return []
            
            # 构建NetworkX图进行高效路径分析
            
            G = nx.DiGraph()
            for caller, callees in call_graph.items():
                for callee in callees:
                    G.add_edge(caller, callee)
            # 1. 分析found_functions间的依赖关系
            def get_function_dependencies(funcs):
                """返回函数间的调用关系图"""
                func_deps = nx.DiGraph()
                for func in funcs:
                    func_deps.add_node(func)
                
                for f1 in funcs:
                    for f2 in funcs:
                        if f1 != f2 and G.has_edge(f1, f2):
                            func_deps.add_edge(f1, f2)
                return func_deps
            
            func_deps = get_function_dependencies(found_functions)
            logger.debug(f"func_deps:{func_deps.nodes()}")
            # 2. 找到独立的根函数（没有被其他found_function调用的函数）
            root_functions = None
            # root_functions = [f for f in found_functions if func_deps.in_degree(f) == 0]
            if not root_functions:
                root_functions = found_functions  # 如果存在循环依赖，使用所有函数
            logger.debug(f"root_functions:{root_functions}")
            
            # 3. 为每个vulnerable_invocation找到最优路径
            unique_chains = []
            covered_invocations = set()
            logger.debug(f"vulnerable_invocations:{vulnerable_invocations}")
            for target in vulnerable_invocations:
                if target in covered_invocations:
                    continue
                    
                best_chain = None
                best_score = float('inf')  # 优先选择最短路径
                
                for root_func in root_functions:
                    if not G.has_node(root_func) or not G.has_node(target):
                        continue
                    try:
                        # 使用NetworkX的最短路径算法
                        print(root_func,target)
                        path = nx.shortest_path(G, source=target, target=root_func)
                    except nx.NetworkXNoPath:
                        continue

                    # 评分：路径长度 + 覆盖的found_functions数量奖励
                    covered_funcs = len([f for f in path if f in found_functions])
                    score = len(path) - covered_funcs * 0.5  # 覆盖更多found_functions给予奖励
                    
                    if score < best_score:
                        best_score = score
                        best_chain = path
                            
                
                
                if best_chain:
                    unique_chains.append(best_chain)
                    covered_invocations.add(target)
                    
                    # 标记此路径覆盖的其他invocations，避免重复
                    for inv in vulnerable_invocations:
                        if inv in best_chain:
                            covered_invocations.add(inv)
            def cleanup_chain(chain: List[str]) -> List[str]:
                """清理call chain，移除冗余的module引用"""
                if len(chain) <= 1:
                    return chain
                
                cleaned = [chain[0]]  # 保留第一个元素
                
                for i in range(1, len(chain)):
                    current = chain[i]
                    prev = chain[i-1]
                    
                    # 如果当前元素是前一个元素的子模块，跳过前一个
                    if current.startswith(prev + '.'):
                        # 替换上一个元素为更具体的当前元素
                        cleaned[-1] = current
                    # 如果前一个元素是当前元素的子模块，跳过当前元素
                    elif prev.startswith(current + '.'):
                        continue
                    else:
                        cleaned.append(current)
                
                return cleaned
            logger.debug(f"covered_invocations:{covered_invocations}")
            # 4. 后处理：移除被其他路径完全包含的路径
            def is_subpath(chain1, chain2):
                """检查chain1是否为chain2的子路径"""
                if len(chain1) >= len(chain2):
                    return False
                for i in range(len(chain2) - len(chain1) + 1):
                    if chain2[i:i+len(chain1)] == chain1:
                        return True
                return False
            filtered_chains = []
            for i, chain in enumerate(unique_chains):
                is_redundant = False
                for j, other_chain in enumerate(unique_chains):
                    if i != j and is_subpath(chain, other_chain):
                        is_redundant = True
                        break
                if not is_redundant:
                    filtered_chains.append(chain)
            cleaned_chains = [cleanup_chain(chain) for chain in filtered_chains]
            logger.debug(f"unique_chains:{unique_chains}")
            logger.debug(f"filtered_chains:{filtered_chains}")
            
            logger.debug(f"cleaned_chains:{cleaned_chains}")
            return cleaned_chains
        
        stats = {
            'total_reachable_pairs': 0,
            'call_chain_stats': {'chain_lengths': [], 'total_chains': 0},
            'vulnerable_invocation_stats': {'invocation_counts': []},
            'function_reachability_stats': {'function_counts_per_pair': []},
            'detailed_pairs': [],
            # 新增：按调用链长度统计downstream
            'downstream_by_chain_length': {
                'length_1': set(),
                'length_2': set(), 
                'length_3': set(),
                'length_4': set(),
                'length_5_plus': set(),
                'no_chains': set()
            },
            'downstream_chain_length_stats': {}
        }
        
        for cve_id, cve_results in (all_results.items()):
            for upstream, downstream_results in cve_results.items():
                if isinstance(downstream_results, str):
                    continue
                    
                for downstream, status in (downstream_results.items()):
                    if status != 'VF Found':
                        continue
                    
                    stats['total_reachable_pairs'] += 1
                    result_file = CG_DIR_DATE / f'{cve_id}/{downstream}_results.json'
                    
                    if not result_file.exists():
                        continue
                    
                    with open(result_file, 'r') as f:
                        result = json.load(f)
                    if len(result['vulnerable_functions'] ) != 1:
                        break
                    
                    found_functions = result.get('found_functions', [])
                    vulnerable_invocations = result.get('vulnerable_invocation', [])
                    
                    # 加载call graph重新计算call chains
                    cg_file = Path(CALL_GRAPH_DIR) / downstream.split('@')[0] / downstream.split('@')[1] / 'jarvis_cg.json'
                    call_chains = []
                    call_chains_file = CG_DIR_DATE / f'{cve_id}/{downstream}_call_chains.json'
                    if cg_file.exists():
                        if not call_chains_file.exists() or True:
                            with open(cg_file, 'r') as f:
                                call_graph = json.load(f)
                            call_chains = extract_call_chains(call_graph, found_functions, vulnerable_invocations)
                            assert len(call_chains)
                            # print(call_chains)
                            call_chains_file.parent.mkdir(exist_ok=True, parents=True)
                            with call_chains_file.open('w') as f:
                                json.dump(call_chains,f)
                        else:
                            with call_chains_file.open('r') as f:
                                call_chains = json.load(f)
                    # 统计信息
                    stats['call_chain_stats']['total_chains'] += len(call_chains)
                    stats['call_chain_stats']['chain_lengths'].extend([len(chain)-1 for chain in call_chains])
                    stats['vulnerable_invocation_stats']['invocation_counts'].append(len(vulnerable_invocations))
                    stats['function_reachability_stats']['function_counts_per_pair'].append(len(found_functions))
                    
                    # 新增：根据最短调用链长度对downstream进行分类
                    if not call_chains:
                        assert False

                        stats['downstream_by_chain_length']['no_chains'].add(downstream)
                        min_chain_length = 0
                    else:
                        chain_lengths = [len(chain) - 1 for chain in call_chains]  # -1 因为要计算步数而不是节点数
                        min_chain_length = min(chain_lengths)
                        
                        if min_chain_length == 1:
                            stats['downstream_by_chain_length']['length_1'].add(downstream)
                        elif min_chain_length == 2:
                            stats['downstream_by_chain_length']['length_2'].add(downstream)
                        elif min_chain_length == 3:
                            stats['downstream_by_chain_length']['length_3'].add(downstream)
                        elif min_chain_length == 4:
                            stats['downstream_by_chain_length']['length_4'].add(downstream)
                        else:
                            stats['downstream_by_chain_length']['length_5_plus'].add(downstream)
                    
                    stats['detailed_pairs'].append({
                        'cve_id': cve_id,
                        'upstream': upstream,
                        'downstream': downstream,
                        'call_chain_count': len(call_chains),
                        'vulnerable_invocation_count': len(vulnerable_invocations),
                        'found_function_count': len(found_functions),
                        'min_chain_length': min_chain_length
                    })
                    
                
        
        # 计算统计值
        if stats['call_chain_stats']['chain_lengths']:
            stats['call_chain_stats']['avg_chain_length'] = np.mean(stats['call_chain_stats']['chain_lengths'])
            stats['call_chain_stats']['max_chain_length'] = max(stats['call_chain_stats']['chain_lengths'])
        
        if stats['vulnerable_invocation_stats']['invocation_counts']:
            stats['vulnerable_invocation_stats']['avg_invocations_per_pair'] = np.mean(stats['vulnerable_invocation_stats']['invocation_counts'])
        
        # 新增：计算downstream按调用链长度的统计
        total_reachable_downstreams = sum(len(downstreams) for downstreams in stats['downstream_by_chain_length'].values())
        
        stats['downstream_chain_length_stats'] = {
            'total_reachable_downstreams': total_reachable_downstreams,
            'length_distribution': {
                'length_1': {
                    'count': len(stats['downstream_by_chain_length']['length_1']),
                    'percentage': len(stats['downstream_by_chain_length']['length_1']) / total_reachable_downstreams * 100 if total_reachable_downstreams > 0 else 0
                },
                'length_2': {
                    'count': len(stats['downstream_by_chain_length']['length_2']),
                    'percentage': len(stats['downstream_by_chain_length']['length_2']) / total_reachable_downstreams * 100 if total_reachable_downstreams > 0 else 0
                },
                'length_3': {
                    'count': len(stats['downstream_by_chain_length']['length_3']),
                    'percentage': len(stats['downstream_by_chain_length']['length_3']) / total_reachable_downstreams * 100 if total_reachable_downstreams > 0 else 0
                },
                'length_4': {
                    'count': len(stats['downstream_by_chain_length']['length_4']),
                    'percentage': len(stats['downstream_by_chain_length']['length_4']) / total_reachable_downstreams * 100 if total_reachable_downstreams > 0 else 0
                },
                'length_5_plus': {
                    'count': len(stats['downstream_by_chain_length']['length_5_plus']),
                    'percentage': len(stats['downstream_by_chain_length']['length_5_plus']) / total_reachable_downstreams * 100 if total_reachable_downstreams > 0 else 0
                },
                'no_chains': {
                    'count': len(stats['downstream_by_chain_length']['no_chains']),
                    'percentage': len(stats['downstream_by_chain_length']['no_chains']) / total_reachable_downstreams * 100 if total_reachable_downstreams > 0 else 0
                }
            }
        }
        return stats

    def pretty_print_reachable_pairs_analysis(self, reachable_analysis: Dict) -> None:
        """Pretty print reachable pairs analysis results with enhanced chain length stats"""
        
        print("\n" + "="*80)
        print("REACHABLE PAIRS DETAILED ANALYSIS")
        print("="*80)
        
        # Overall statistics
        print(f"\nOVERALL REACHABILITY STATISTICS:")
        print(f"  Total reachable pairs: {reachable_analysis['total_reachable_pairs']:,}")
        
        # 新增：Downstream按调用链长度分布统计
        if 'downstream_chain_length_stats' in reachable_analysis:
            chain_length_stats = reachable_analysis['downstream_chain_length_stats']
            length_dist = chain_length_stats['length_distribution']
            
            print(f"\nDOWNSTREAM PACKAGES BY CALL CHAIN LENGTH:")
            print(f"  Total reachable downstream packages: {chain_length_stats['total_reachable_downstreams']:,}")
            print(f"  Distribution:")
            print(f"    Length 1 (Direct):     {length_dist['length_1']['count']:>4} ({length_dist['length_1']['percentage']:>5.1f}%)")
            print(f"    Length 2:              {length_dist['length_2']['count']:>4} ({length_dist['length_2']['percentage']:>5.1f}%)")
            print(f"    Length 3:              {length_dist['length_3']['count']:>4} ({length_dist['length_3']['percentage']:>5.1f}%)")
            print(f"    Length 4:              {length_dist['length_4']['count']:>4} ({length_dist['length_4']['percentage']:>5.1f}%)")
            print(f"    Length 5+:             {length_dist['length_5_plus']['count']:>4} ({length_dist['length_5_plus']['percentage']:>5.1f}%)")
            print(f"    No chains found:       {length_dist['no_chains']['count']:>4} ({length_dist['no_chains']['percentage']:>5.1f}%)")
            
            # 可视化分布
            print(f"\n  Chain Length Distribution (Visual):")
            max_count = max(info['count'] for info in length_dist.values())
            scale = 50 / max_count if max_count > 0 else 1
            
            for length, info in [
                ('Length 1', length_dist['length_1']),
                ('Length 2', length_dist['length_2']),
                ('Length 3', length_dist['length_3']),
                ('Length 4', length_dist['length_4']),
                ('Length 5+', length_dist['length_5_plus']),
                ('No chains', length_dist['no_chains'])
            ]:
                bar_length = int(info['count'] * scale)
                bar = "█" * bar_length + "░" * (50 - bar_length)
                print(f"    {length:<12} | {bar} | {info['count']:>4}")
        
        # Call chain statistics
        chain_stats = reachable_analysis['call_chain_stats']
        if chain_stats['total_chains'] > 0:
            print(f"\nCALL CHAIN ANALYSIS:")
            print(f"  Total call chains found: {chain_stats['total_chains']:,}")
            print(f"  Average chain length: {chain_stats['avg_chain_length']:.2f}")
            print(f"  Max chain length: {chain_stats['max_chain_length']}")
            
            if 'chain_lengths' in chain_stats and chain_stats['chain_lengths']:
                lengths = chain_stats['chain_lengths']
                print(f"  Chain length distribution:")
                print(f"    25th percentile: {np.percentile(lengths, 25):.1f}")
                print(f"    50th percentile: {np.percentile(lengths, 50):.1f}")
                print(f"    75th percentile: {np.percentile(lengths, 75):.1f}")
                print(f"    90th percentile: {np.percentile(lengths, 90):.1f}")
                
                # Chain length histogram
                print(f"  Chain length histogram:")
                max_len = min(max(lengths), 20)  # Cap at 20 for display
                for i in range(1, max_len + 1):
                    count = sum(1 for l in lengths if l == i)
                    if count > 0:
                        bar = "█" * min(count // 2, 30)  # Scale bars
                        print(f"    Length {i:2d}: {count:4d} {bar}")
        else:
            print(f"\nCALL CHAIN ANALYSIS:")
            print(f"  No call chains found in reachable pairs")
        
        # Vulnerable invocation statistics
        inv_stats = reachable_analysis['vulnerable_invocation_stats']
        if inv_stats['invocation_counts']:
            counts = inv_stats['invocation_counts']
            print(f"\nVULNERABLE INVOCATION ANALYSIS:")
            print(f"  Pairs with invocations: {len([c for c in counts if c > 0]):,}")
            print(f"  Average invocations per pair: {np.mean(counts):.2f}")
            print(f"  Max invocations in single pair: {max(counts):,}")
            print(f"  Invocation distribution:")
            print(f"    25th percentile: {np.percentile(counts, 25):.1f}")
            print(f"    50th percentile: {np.percentile(counts, 50):.1f}")
            print(f"    75th percentile: {np.percentile(counts, 75):.1f}")
            print(f"    90th percentile: {np.percentile(counts, 90):.1f}")
        
        # Function reachability statistics
        func_stats = reachable_analysis['function_reachability_stats']
        if func_stats['function_counts_per_pair']:
            func_counts = func_stats['function_counts_per_pair']
            print(f"\nFUNCTION REACHABILITY ANALYSIS:")
            print(f"  Average functions per pair: {np.mean(func_counts):.2f}")
            print(f"  Max functions in single pair: {max(func_counts):,}")
            print(f"  Function count distribution:")
            print(f"    25th percentile: {np.percentile(func_counts, 25):.1f}")
            print(f"    50th percentile: {np.percentile(func_counts, 50):.1f}")
            print(f"    75th percentile: {np.percentile(func_counts, 75):.1f}")
        
        # Top performing pairs
        detailed_pairs = reachable_analysis.get('detailed_pairs', [])
        if detailed_pairs:
            print(f"\nTOP 10 PAIRS BY CALL CHAIN COUNT:")
            print("-" * 70)
            top_by_chains = sorted(detailed_pairs, key=lambda x: x['call_chain_count'], reverse=True)[:10]
            for i, pair in enumerate(top_by_chains):
                print(f"{i+1:2d}. {pair['cve_id']:<15} | "
                        f"{pair['downstream']:<25} | "
                        f"Chains: {pair['call_chain_count']:>3} | "
                        f"Min Length: {pair.get('min_chain_length', 'N/A'):>3} | "
                        f"Invocations: {pair['vulnerable_invocation_count']:>3}")
            
            print(f"\nTOP 10 PAIRS BY VULNERABLE INVOCATION COUNT:")
            print("-" * 70)
            top_by_invocations = sorted(detailed_pairs, key=lambda x: x['vulnerable_invocation_count'], reverse=True)[:10]
            for i, pair in enumerate(top_by_invocations):
                print(f"{i+1:2d}. {pair['cve_id']:<15} | "
                        f"{pair['downstream']:<25} | "
                        f"Invocations: {pair['vulnerable_invocation_count']:>3} | "
                        f"Min Length: {pair.get('min_chain_length', 'N/A'):>3} | "
                        f"Functions: {pair['found_function_count']:>3}")
            
            # 新增：按最短调用链长度分组的Top pairs
            print(f"\nTOP PAIRS BY CHAIN LENGTH CATEGORIES:")
            print("-" * 70)
            
            # 按链长分组
            pairs_by_length = defaultdict(list)
            for pair in detailed_pairs:
                min_length = pair.get('min_chain_length', 0)
                if min_length == 0:
                    pairs_by_length['No chains'].append(pair)
                elif min_length <= 4:
                    pairs_by_length[f'Length {min_length}'].append(pair)
                else:
                    pairs_by_length['Length 5+'].append(pair)
            
            for category in ['Length 1', 'Length 2', 'Length 3', 'Length 4', 'Length 5+']:
                if category in pairs_by_length:
                    pairs = pairs_by_length[category]
                    print(f"\n  {category} ({len(pairs)} pairs):")
                    # 显示前3个最有代表性的pairs
                    top_pairs = sorted(pairs, key=lambda x: (x['call_chain_count'], x['vulnerable_invocation_count']), reverse=True)[:3]
                    for i, pair in enumerate(top_pairs):
                        print(f"    {i+1}. {pair['cve_id']:<15} | {pair['downstream']:<25} | "
                                f"Chains: {pair['call_chain_count']:>2} | Invocations: {pair['vulnerable_invocation_count']:>2}")

        # Summary insights
        if 'downstream_chain_length_stats' in reachable_analysis:
            print(f"\nKEY INSIGHTS:")
            chain_length_stats = reachable_analysis['downstream_chain_length_stats']
            length_dist = chain_length_stats['length_distribution']
            
            # 计算直接vs间接依赖的比例
            direct_count = length_dist['length_1']['count']
            indirect_count = sum(length_dist[key]['count'] for key in ['length_2', 'length_3', 'length_4', 'length_5_plus'])
            total_with_chains = direct_count + indirect_count
            
            if total_with_chains > 0:
                direct_percentage = direct_count / total_with_chains * 100
                print(f"  • Direct dependencies (length 1): {direct_percentage:.1f}% of packages with call chains")
                print(f"  • Indirect dependencies (length 2+): {100 - direct_percentage:.1f}% of packages with call chains")
            
            # 找出最常见的链长度
            max_category = max(length_dist.items(), key=lambda x: x[1]['count'] if x[0] != 'no_chains' else 0)
            if max_category[1]['count'] > 0:
                print(f"  • Most common call chain length: {max_category[0]} ({max_category[1]['count']} packages)")
            
            # 短链vs长链的比例
            short_chain_count = sum(length_dist[key]['count'] for key in ['length_1', 'length_2'])
            long_chain_count = sum(length_dist[key]['count'] for key in ['length_3', 'length_4', 'length_5_plus'])
            if total_with_chains > 0:
                short_percentage = short_chain_count / total_with_chains * 100
                print(f"  • Short chains (≤2 steps): {short_percentage:.1f}% vs Long chains (≥3 steps): {100 - short_percentage:.1f}%")

    def analyze_dependency_depth_and_type(self, all_results: Dict) -> Dict[str, Any]:
        """
        分析依赖深度和类型对漏洞传播的影响
        
        Returns:
            Dict containing dependency analysis results matching Table 6 format
            包含每个downstream的dependency depth信息
        """
        
        # 统计数据结构
        stats_by_depth = defaultdict(lambda: {
            'total_pairs': 0,
            'reachable_pairs': 0,
        })
        
        stats_by_type = defaultdict(lambda: {
            'total_pairs': 0,
            'reachable_pairs': 0,
        })
        
        # 用于记录所有pair的详细信息，包含dependency depth
        all_dependency_pairs = []
        
        # 新增：保存每个downstream的dependency depth信息
        downstream_depth_mapping = {}  # downstream -> {depth: int, dep_type: str}
        
        max_depths = -1
        for cve_id, cve_results in all_results.items():
            for upstream, downstream_results in cve_results.items():
                if isinstance(downstream_results, str):
                    continue
                    
                # 解析upstream信息
                upstream_parts = upstream.split('@')
                if len(upstream_parts) < 2:
                    continue
                upstream_name = upstream_parts[0]
                upstream_version = upstream_parts[1]
                
                for downstream, status in downstream_results.items():
                    # 计算依赖深度和类型（无论status如何）
                    depth, dep_type = self._calculate_dependency_depth_and_type(
                        upstream_name, upstream_version, downstream
                    )
                    if depth:
                        max_depths = max(depth, max_depths)

                    if depth is None:
                        # logger.info(f"{upstream, downstream}")
                        continue
                    
                    # 保存downstream的depth信息
                    if downstream not in downstream_depth_mapping:
                        downstream_depth_mapping[downstream] = {
                            'depth': depth,
                            'dep_type': dep_type,
                            'upstream_dependencies': []  # 记录所有相关的upstream依赖
                        }
                    
                    # 记录upstream依赖关系
                    downstream_depth_mapping[downstream]['upstream_dependencies'].append({
                        'upstream': upstream,
                        'cve_id': cve_id,
                        'depth': depth,
                        'dep_type': dep_type,
                        'status': status
                    })
                    
                    # 记录数据
                    pair_info = {
                        'cve_id': cve_id,
                        'upstream': upstream,
                        'downstream': downstream,
                        'depth': depth,
                        'dep_type': dep_type,
                        'status': status,
                    }
                    all_dependency_pairs.append(pair_info)
                    
                    # 按深度统计
                    depth_key = f"Depth {depth}" if depth < 10 else "Depth 10+"
                    stats_by_depth[depth_key]['total_pairs'] += 1
                    if status == 'VF Found':
                        stats_by_depth[depth_key]['reachable_pairs'] += 1
                    
                    # 按类型统计
                    type_key = "Direct Dependencies" if dep_type == "direct" else "Transitive Dependencies"
                    stats_by_type[type_key]['total_pairs'] += 1
                    if status == 'VF Found':
                        stats_by_type[type_key]['reachable_pairs'] += 1
        
        # 计算汇总统计
        summary_stats = self._calculate_dependency_summary_stats(stats_by_depth, stats_by_type)
        
        return {
            'dependency_pairs': all_dependency_pairs,
            'stats_by_depth': dict(stats_by_depth),
            'stats_by_type': dict(stats_by_type),
            'summary_table': summary_stats,
            'downstream_depth_mapping': downstream_depth_mapping,  # 新增：每个downstream的depth信息
            'detailed_analysis': {
                'depth_distribution': self._analyze_depth_distribution(all_dependency_pairs),
                'type_distribution': self._analyze_type_distribution(all_dependency_pairs),
                'downstream_depth_stats': self._analyze_downstream_depth_stats(downstream_depth_mapping)  # 新增分析
            }
        }

    def _analyze_downstream_depth_stats(self, downstream_depth_mapping: Dict) -> Dict:
        """
        分析downstream packages的dependency depth统计
        
        Args:
            downstream_depth_mapping: downstream -> depth信息的映射
            
        Returns:
            downstream depth统计分析
        """
        depth_counts = defaultdict(int)
        type_counts = defaultdict(int)
        
        # 统计每个downstream的depth分布
        for downstream, info in downstream_depth_mapping.items():
            depth = info['depth']
            dep_type = info['dep_type']
            
            if depth is not None:
                depth_key = f"Depth {depth}" if depth < 10 else "Depth 10+"
                depth_counts[depth_key] += 1
                
            if dep_type:
                type_key = "Direct" if dep_type == "direct" else "Transitive"
                type_counts[type_key] += 1
        
        # 计算受影响的downstream中各depth的占比
        total_downstreams = len(downstream_depth_mapping)
        
        return {
            'total_downstreams_with_depth': total_downstreams,
            'depth_distribution': {
                depth: {
                    'count': count,
                    'percentage': round(count * 100 / total_downstreams, 2) if total_downstreams > 0 else 0
                }
                for depth, count in depth_counts.items()
            },
            'type_distribution': {
                dep_type: {
                    'count': count,
                    'percentage': round(count * 100 / total_downstreams, 2) if total_downstreams > 0 else 0
                }
                for dep_type, count in type_counts.items()
            },
            'raw_depth_counts': dict(depth_counts),
            'raw_type_counts': dict(type_counts)
        }
    def _calculate_dependency_depth_and_type(self, upstream_name: str, upstream_version: str, downstream: str) -> tuple:
        """
        计算依赖深度和类型
        
        Args:
            upstream_name: upstream包名
            upstream_version: upstream版本
            downstream: downstream包名
            
        Returns:
            (depth, type) tuple, 如果无法计算返回 (None, None)
        """
            
        # 通过dependency graph计算深度
        dep_graph_file = SNAPSHOT_DIR / "dep_graphs" / f"{downstream}.json"
        if not dep_graph_file.exists():
            return (None, None)
        
        with open(dep_graph_file, 'r') as f:
            graph_data = json.load(f)
        
        # 使用BFS计算最短路径
        downstream_name, downstream_version=  downstream.split('@')
        if isinstance(graph_data, List):
            logger.warning('pkg may be inaccessible now.')
            return (None, None)
        elif len(graph_data['nodes']) == 0 or len(graph_data['edges']) == 0:
            logger.warning('OSI may be failed to resolve dependencies.')
            return (None, None)
        depth = self._find_shortest_path_in_graph(
            graph_data, downstream_name, downstream_version, upstream_name, upstream_version
        )
        
        if depth is not None and depth > 1:
            return (depth, "transitive")
        elif depth == 1:
            return (1, "direct")
        else:
            if downstream not in ['xiaobaisaf@1.1.0']:
                assert False
            return (None, None)
            
    
    def _find_shortest_path_in_graph(self,graph_data: dict,  downstream_name: str, downstream_version: str,
                                    upstream_name: str, upstream_version: str) -> int:
        """
        使用 networkx 在依赖图中查找从target_package到upstream的最短路径长度。
        """
        nodes = graph_data.get('nodes', {})
        edges = graph_data.get('edges', [])
        
        # 找到起始和目标节点的唯一ID
        start_node_id = None
        target_node_id = None
        for node_id, node_info in nodes.items():
            if (node_info['name'] == downstream_name and 
                node_info['version'] == downstream_version):
                start_node_id = node_info['name']
            if (node_info['name'] == upstream_name):
                target_node_id = node_info['name'] 
         # 构建有向图
        G = nx.DiGraph()
        G.add_nodes_from(nodes.keys())
        for edge in edges:
            source_name = edge['source'].split(' ')[0]
            target_name = edge['target'].split(' ')[0]
            G.add_edge(source_name,target_name)
        # 如果任一节点不存在，则返回 None
        if not start_node_id or not target_node_id:
            # logger.info(graph_data)

            # logger.info(f"{downstream_name, downstream_version, upstream_name, upstream_version}")
            # logger.info(f'{start_node_id, target_node_id}')

            return None

       
        # 使用 networkx.shortest_path_length 查找最短路径
        try:
            path_length = nx.shortest_path_length(G, source=start_node_id, target=target_node_id)
            return path_length
        except nx.NetworkXNoPath:
            # 如果没有路径，返回 None
            assert False
            return None
        except nx.NodeNotFound:
            # 如果节点不存在，也返回 None（尽管前面已经检查过）
            assert False

            return None
        assert False
        
    def _calculate_dependency_summary_stats(self, stats_by_depth: Dict, stats_by_type: Dict) -> Dict:
        """计算汇总统计表格"""
        import numpy as np
        
        summary_table = {}
        
        # 按依赖类型统计
        summary_table['By Dependency Type'] = {}
        for dep_type, stats in stats_by_type.items():
            total_pairs = stats['total_pairs']
            reachable_pairs = stats['reachable_pairs']
            propagation_rate = (reachable_pairs / total_pairs * 100) if total_pairs > 0 else 0
            
            
            summary_table['By Dependency Type'][dep_type] = {
                'Total Pairs': total_pairs,
                'Reachable Pairs': reachable_pairs,
                'Propagation Rate': f"{propagation_rate:.1f}%",
            }
        
        # 按依赖深度统计
        summary_table['By Dependency Depth'] = {}
        depth_order = ['Depth 1', 'Depth 2', 'Depth 3', 'Depth 4','Depth 5','Depth 6','Depth 7','Depth 8','Depth 9','Depth 10+']

        
        for depth_key in depth_order:
            if depth_key in stats_by_depth:
                stats = stats_by_depth[depth_key]
                total_pairs = stats['total_pairs']
                reachable_pairs = stats['reachable_pairs']
                propagation_rate = (reachable_pairs / total_pairs * 100) if total_pairs > 0 else 0
                
                
                summary_table['By Dependency Depth'][depth_key] = {
                    'Total Pairs': total_pairs,
                    'Reachable Pairs': reachable_pairs,
                    'Propagation Rate': f"{propagation_rate:.1f}%",
                }
        
        # 计算总计
        total_pairs = sum(stats['total_pairs'] for stats in stats_by_type.values())
        total_reachable = sum(stats['reachable_pairs'] for stats in stats_by_type.values())
        total_propagation_rate = (total_reachable / total_pairs * 100) if total_pairs > 0 else 0
        
        summary_table['Overall Total'] = {
            'Total Pairs': total_pairs,
            'Reachable Pairs': total_reachable,
            'Propagation Rate': f"{total_propagation_rate:.1f}%",
        }
        
        return summary_table

    def _analyze_depth_distribution(self, dependency_pairs: List) -> Dict:
        """分析深度分布"""
        depth_distribution = defaultdict(int)
        reachable_by_depth = defaultdict(int)
        
        for pair in dependency_pairs:
            if pair['depth'] is not None:
                depth = pair['depth']
                depth_key = f"Depth {depth}" if depth <= 3 else "Depth 4+"
                depth_distribution[depth_key] += 1
                
                if pair['status'] == 'VF Found':
                    reachable_by_depth[depth_key] += 1
        
        return {
            'total_by_depth': dict(depth_distribution),
            'reachable_by_depth': dict(reachable_by_depth)
        }

    def _analyze_type_distribution(self, dependency_pairs: List) -> Dict:
        """分析类型分布"""
        type_distribution = defaultdict(int)
        reachable_by_type = defaultdict(int)
        
        for pair in dependency_pairs:
            if pair['dep_type'] is not None:
                dep_type = "Direct" if pair['dep_type'] == "direct" else "Transitive"
                type_distribution[dep_type] += 1
                
                if pair['status'] == 'VF Found':
                    reachable_by_type[dep_type] += 1
        
        return {
            'total_by_type': dict(type_distribution),
            'reachable_by_type': dict(reachable_by_type)
        }

    def analyze_cwe_propagation_patterns(self, all_results: Dict) -> Dict[str, Any]:
        """
        分析CWE类型的漏洞传播模式
        
        Returns:
            Dict containing CWE propagation analysis results matching Table 7 format
        """
        
        # 统计数据结构
        cwe_stats = defaultdict(lambda: {
            'total_cves': set(),
            'reachable_cves': set(),
            'total_invocations': 0,
            'invocation_counts': [],
            'total_pairs': 0,
            'reachable_pairs': 0
        })
        
        # 获取CVE到CWE的映射
        cve2advisory = self.cve2advisory
        
        for cve_id, cve_results in all_results.items():
            # 获取CVE的CWE类型
            cwe_types = self._get_cwe_types_for_cve(cve_id, cve2advisory)
            if not cwe_types:
                continue
            
            # 检查该CVE是否有任何reachable的downstream
            cve_has_reachable = False
            cve_total_invocations = 0
            cve_invocation_counts = []
            cve_total_pairs = 0
            cve_reachable_pairs = 0
            
            for upstream, downstream_results in cve_results.items():
                if isinstance(downstream_results, str):
                    continue
                    
                for downstream, status in downstream_results.items():
                    cve_total_pairs += 1
                    
                    if status == 'VF Found':
                        cve_has_reachable = True
                        cve_reachable_pairs += 1
                        
                        # 获取invocation信息
                        result_file = CG_DIR_DATE / f'{cve_id}/{downstream}_results.json'
                        if result_file.exists():
                            try:
                                with open(result_file, 'r') as f:
                                    detailed_result = json.load(f)
                                
                                vulnerable_invocations = detailed_result.get('vulnerable_invocation', [])
                                invocation_count = len(vulnerable_invocations)
                                cve_total_invocations += invocation_count
                                if invocation_count > 0:
                                    cve_invocation_counts.append(invocation_count)
                                
                            except Exception as e:
                                logger.warning(f"Failed to load detailed results for {cve_id}/{downstream}: {e}")
            
            # 为每个CWE类型记录统计信息
            for cwe_type in cwe_types:
                cwe_stats[cwe_type]['total_cves'].add(cve_id)
                cwe_stats[cwe_type]['total_pairs'] += cve_total_pairs
                cwe_stats[cwe_type]['reachable_pairs'] += cve_reachable_pairs
                
                if cve_has_reachable:
                    cwe_stats[cwe_type]['reachable_cves'].add(cve_id)
                    cwe_stats[cwe_type]['total_invocations'] += cve_total_invocations
                    cwe_stats[cwe_type]['invocation_counts'].extend(cve_invocation_counts)
        
        # 计算汇总统计
        summary_stats = self._calculate_cwe_summary_stats(cwe_stats)
        
        return {
            'cwe_stats': {cwe: {
                'total_cves': len(stats['total_cves']),
                'reachable_cves': len(stats['reachable_cves']),
                'total_pairs': stats['total_pairs'],
                'reachable_pairs': stats['reachable_pairs'],
                'total_invocations': stats['total_invocations'],
                'invocation_counts': stats['invocation_counts']
            } for cwe, stats in cwe_stats.items()},
            'summary_table': summary_stats,
            'detailed_breakdown': {
                'cwe_distribution': self._analyze_cwe_distribution(cwe_stats),
                'propagation_effectiveness': self._analyze_propagation_effectiveness(cwe_stats)
            }
        }

    def _get_cwe_types_for_cve(self, cve_id: str, cve2advisory: Dict) -> List[str]:
        """
        从advisory中获取CVE的CWE类型
        
        Args:
            cve_id: CVE ID
            cve2advisory: CVE到advisory的映射
            
        Returns:
            CWE类型列表
        """
        if cve_id not in cve2advisory:
            assert False
            return []
        
        advisory = cve2advisory[cve_id]

        cwe_types = advisory.get('database_specific', []).get('cwe_ids')
        
        # 确保返回列表格式
        if isinstance(cwe_types, str):
            return [cwe_types]
        elif isinstance(cwe_types, list):
            return cwe_types
        else:
            return []

    def _calculate_cwe_summary_stats(self, cwe_stats: Dict) -> Dict:
        """计算CWE汇总统计表格"""
        import numpy as np
        
        summary_table = {}
        
        # 计算每个CWE类型的统计信息
        cwe_summary = []
        
        for cwe_type, stats in cwe_stats.items():
            total_cves = len(stats['total_cves'])
            reachable_cves = len(stats['reachable_cves'])
            propagation_rate = (reachable_cves / total_cves * 100) if total_cves > 0 else 0
            
            # 计算平均invocation数
            avg_invocations = np.mean(stats['invocation_counts']) if stats['invocation_counts'] else 0
            
            cwe_summary.append({
                'cwe_type': cwe_type,
                'total_cves': total_cves,
                'reachable_cves': reachable_cves,
                'propagation_rate': propagation_rate,
                'avg_invocations': avg_invocations,
                'total_pairs': stats['total_pairs'],
                'reachable_pairs': stats['reachable_pairs']
            })
        
        # 按reachable CVEs数量排序，取前10
        top_10_cwe = sorted(cwe_summary, key=lambda x: x['reachable_cves'], reverse=True)[:10]
        
        # 格式化表格数据
        summary_table['Top 10 CWE Types'] = {}
        for cwe_data in top_10_cwe:
            cwe_type = cwe_data['cwe_type']
            summary_table['Top 10 CWE Types'][cwe_type] = {
                'Total CVEs': cwe_data['total_cves'],
                'Reachable CVEs': cwe_data['reachable_cves'],
                'Propagation Rate': f"{cwe_data['propagation_rate']:.1f}%",
                'Avg. Invocations': f"{cwe_data['avg_invocations']:.1f}"
            }
        
        # 计算总计
        total_cves = len(set().union(*[stats['total_cves'] for stats in cwe_stats.values()]))
        total_reachable_cves = len(set().union(*[stats['reachable_cves'] for stats in cwe_stats.values()]))
        total_propagation_rate = (total_reachable_cves / total_cves * 100) if total_cves > 0 else 0
        
        all_invocations = []
        for stats in cwe_stats.values():
            all_invocations.extend(stats['invocation_counts'])
        avg_total_invocations = np.mean(all_invocations) if all_invocations else 0
        
        summary_table['Total'] = {
            'Total CVEs': total_cves,
            'Reachable CVEs': total_reachable_cves,
            'Propagation Rate': f"{total_propagation_rate:.1f}%",
            'Avg. Invocations': f"{avg_total_invocations:.1f}"
        }
        
        return summary_table

    def _analyze_cwe_distribution(self, cwe_stats: Dict) -> Dict:
        """分析CWE分布情况"""
        distribution = {}
        
        for cwe_type, stats in cwe_stats.items():
            total_cves = len(stats['total_cves'])
            reachable_cves = len(stats['reachable_cves'])
            
            distribution[cwe_type] = {
                'total_cves': total_cves,
                'reachable_cves': reachable_cves,
                'propagation_rate': (reachable_cves / total_cves * 100) if total_cves > 0 else 0
            }
        
        return distribution

    def _analyze_propagation_effectiveness(self, cwe_stats: Dict) -> Dict:
        """分析不同CWE类型的传播效果"""
        effectiveness = {}
        
        # 按传播率排序
        by_propagation_rate = sorted(
            [(cwe, len(stats['reachable_cves']) / len(stats['total_cves']) * 100 if len(stats['total_cves']) > 0 else 0)
            for cwe, stats in cwe_stats.items()],
            key=lambda x: x[1], reverse=True
        )
        
        # 按影响CVE数量排序
        by_impact_count = sorted(
            [(cwe, len(stats['reachable_cves'])) for cwe, stats in cwe_stats.items()],
            key=lambda x: x[1], reverse=True
        )
        
        effectiveness['by_propagation_rate'] = by_propagation_rate[:10]
        effectiveness['by_impact_count'] = by_impact_count[:10]
        
        return effectiveness

    def analyze_severity_distribution(self, all_results: Dict) -> Dict[str, Any]:
        """
        分析CVE严重程度分布及其漏洞传播情况
        
        Returns:
            Dict containing severity distribution analysis results
        """
        from collections import defaultdict
        import numpy as np
        
        # 统计数据结构
        severity_stats = defaultdict(lambda: {
            'total_cves': set(),
            'reachable_cves': set(),
            'total_pairs': 0,
            'reachable_pairs': 0,
            'total_invocations': 0,
            'invocation_counts': []
        })
        
        # 获取CVE到advisory的映射
        cve2advisory = self.cve2advisory
        
        for cve_id, cve_results in all_results.items():
            # 获取CVE的严重程度
            severity = self._get_severity_for_cve(cve_id, cve2advisory)
            if not severity:
                severity = "Unknown"  # 处理无法获取严重程度的情况
            
            # 标准化严重程度名称
            severity = self._normalize_severity(severity)
            
            # 统计该CVE的传播情况
            cve_has_reachable = False
            cve_total_pairs = 0
            cve_reachable_pairs = 0
            cve_total_invocations = 0
            cve_invocation_counts = []
            
            for upstream, downstream_results in cve_results.items():
                if isinstance(downstream_results, str):
                    continue
                    
                for downstream, status in downstream_results.items():
                    cve_total_pairs += 1
                    
                    if status == 'VF Found':
                        cve_has_reachable = True
                        cve_reachable_pairs += 1
                        
                        # 获取invocation信息（如果需要的话）
                        result_file = CG_DIR_DATE / f'{cve_id}/{downstream}_results.json'
                        if result_file.exists():
                            try:
                                with open(result_file, 'r') as f:
                                    detailed_result = json.load(f)
                                
                                vulnerable_invocations = detailed_result.get('vulnerable_invocation', [])
                                invocation_count = len(vulnerable_invocations)
                                cve_total_invocations += invocation_count
                                if invocation_count > 0:
                                    cve_invocation_counts.append(invocation_count)
                                    
                            except Exception as e:
                                logger.warning(f"Failed to load detailed results for {cve_id}/{downstream}: {e}")
            
            # 记录到对应严重程度的统计中
            severity_stats[severity]['total_cves'].add(cve_id)
            severity_stats[severity]['total_pairs'] += cve_total_pairs
            severity_stats[severity]['reachable_pairs'] += cve_reachable_pairs
            
            if cve_has_reachable:
                severity_stats[severity]['reachable_cves'].add(cve_id)
                severity_stats[severity]['total_invocations'] += cve_total_invocations
                severity_stats[severity]['invocation_counts'].extend(cve_invocation_counts)
        
        # 计算汇总统计
        summary_stats = self._calculate_severity_summary_stats(severity_stats)
        
        return {
            'severity_stats': {severity: {
                'total_cves': len(stats['total_cves']),
                'reachable_cves': len(stats['reachable_cves']),
                'total_pairs': stats['total_pairs'],
                'reachable_pairs': stats['reachable_pairs'],
                'total_invocations': stats['total_invocations'],
                'invocation_counts': stats['invocation_counts']
            } for severity, stats in severity_stats.items()},
            'summary_table': summary_stats,
            'detailed_breakdown': {
                'severity_distribution': self._analyze_severity_distribution_details(severity_stats),
                'propagation_by_severity': self._analyze_propagation_by_severity(severity_stats)
            }
        }

    def _get_severity_for_cve(self, cve_id: str, cve2advisory: Dict) -> str:
        """
        从advisory中获取CVE的严重程度
        
        Args:
            cve_id: CVE ID
            cve2advisory: CVE到advisory的映射
            
        Returns:
            严重程度字符串
        """
        if cve_id not in cve2advisory:
            return None
        
        advisory = cve2advisory[cve_id]
        severity = advisory.get('database_specific', {}).get('severity', None)
        
        return severity

    def _normalize_severity(self, severity: str) -> str:
        """
        标准化严重程度名称
        
        Args:
            severity: 原始严重程度字符串
            
        Returns:
            标准化后的严重程度
        """
        if not severity:
            return "Unknown"
        
        severity_lower = severity.lower().strip()
        
        # 标准化映射
        severity_mapping = {
            'critical': 'Critical',
            'high': 'High', 
            'medium': 'Medium',
            'moderate': 'Medium',  # 有些系统用moderate表示medium
            'low': 'Low',
            'unknown': 'Unknown',
            'none': 'None'
        }
        
        return severity_mapping.get(severity_lower, severity.title())

    def _calculate_severity_summary_stats(self, severity_stats: Dict) -> Dict:
        """计算严重程度汇总统计表格"""
        import numpy as np
        
        summary_table = {}
        
        # 定义严重程度顺序（从高到低）
        severity_order = ['Critical', 'High', 'Medium', 'Low', 'Unknown', 'None']
        
        # 计算每个严重程度的统计信息
        for severity in severity_order:
            if severity in severity_stats:
                stats = severity_stats[severity]
                total_cves = len(stats['total_cves'])
                reachable_cves = len(stats['reachable_cves'])
                total_pairs = stats['total_pairs']
                reachable_pairs = stats['reachable_pairs']
                
                # 计算传播率
                cve_propagation_rate = (reachable_cves / total_cves * 100) if total_cves > 0 else 0
                pair_propagation_rate = (reachable_pairs / total_pairs * 100) if total_pairs > 0 else 0
                
                # 计算平均invocation数
                avg_invocations = np.mean(stats['invocation_counts']) if stats['invocation_counts'] else 0
                
                summary_table[severity] = {
                    'Total CVEs': total_cves,
                    'Reachable CVEs': reachable_cves,
                    'CVE Propagation Rate': f"{cve_propagation_rate:.1f}%",
                    'Total Pairs': total_pairs,
                    'Reachable Pairs': reachable_pairs,
                    'Pair Propagation Rate': f"{pair_propagation_rate:.1f}%",
                    'Avg. Invocations': f"{avg_invocations:.1f}"
                }
        
        # 计算总计
        total_cves = len(set().union(*[stats['total_cves'] for stats in severity_stats.values()]))
        total_reachable_cves = len(set().union(*[stats['reachable_cves'] for stats in severity_stats.values()]))
        total_pairs = sum(stats['total_pairs'] for stats in severity_stats.values())
        total_reachable_pairs = sum(stats['reachable_pairs'] for stats in severity_stats.values())
        
        total_cve_propagation_rate = (total_reachable_cves / total_cves * 100) if total_cves > 0 else 0
        total_pair_propagation_rate = (total_reachable_pairs / total_pairs * 100) if total_pairs > 0 else 0
        
        all_invocations = []
        for stats in severity_stats.values():
            all_invocations.extend(stats['invocation_counts'])
        avg_total_invocations = np.mean(all_invocations) if all_invocations else 0
        
        summary_table['Total'] = {
            'Total CVEs': total_cves,
            'Reachable CVEs': total_reachable_cves,
            'CVE Propagation Rate': f"{total_cve_propagation_rate:.1f}%",
            'Total Pairs': total_pairs,
            'Reachable Pairs': total_reachable_pairs,
            'Pair Propagation Rate': f"{total_pair_propagation_rate:.1f}%",
            'Avg. Invocations': f"{avg_total_invocations:.1f}"
        }
        
        return summary_table

    def _analyze_severity_distribution_details(self, severity_stats: Dict) -> Dict:
        """分析严重程度分布详情"""
        distribution = {}
        
        for severity, stats in severity_stats.items():
            total_cves = len(stats['total_cves'])
            reachable_cves = len(stats['reachable_cves'])
            total_pairs = stats['total_pairs']
            reachable_pairs = stats['reachable_pairs']
            
            distribution[severity] = {
                'total_cves': total_cves,
                'reachable_cves': reachable_cves,
                'cve_propagation_rate': (reachable_cves / total_cves * 100) if total_cves > 0 else 0,
                'total_pairs': total_pairs,
                'reachable_pairs': reachable_pairs,
                'pair_propagation_rate': (reachable_pairs / total_pairs * 100) if total_pairs > 0 else 0
            }
        
        return distribution

    def _analyze_propagation_by_severity(self, severity_stats: Dict) -> Dict:
        """分析不同严重程度的传播效果"""
        propagation_analysis = {}
        
        # 按CVE传播率排序
        by_cve_propagation = []
        for severity, stats in severity_stats.items():
            total_cves = len(stats['total_cves'])
            reachable_cves = len(stats['reachable_cves'])
            if total_cves > 0:
                propagation_rate = reachable_cves / total_cves * 100
                by_cve_propagation.append((severity, propagation_rate, reachable_cves, total_cves))
        
        by_cve_propagation.sort(key=lambda x: x[1], reverse=True)
        
        # 按影响CVE数量排序
        by_impact_count = []
        for severity, stats in severity_stats.items():
            reachable_cves = len(stats['reachable_cves'])
            total_cves = len(stats['total_cves'])
            by_impact_count.append((severity, reachable_cves, total_cves))
        
        by_impact_count.sort(key=lambda x: x[1], reverse=True)
        
        propagation_analysis['by_cve_propagation_rate'] = by_cve_propagation
        propagation_analysis['by_impact_count'] = by_impact_count
        
        return propagation_analysis

    def analyze_owasp_cwe_coverage(self, all_results: Dict) -> Dict[str, Any]:
        """
        分析OWASP Top 10和CWE Top 25的覆盖率及其漏洞传播情况
        
        Returns:
            Dict containing OWASP/CWE coverage analysis results
        """
        from collections import Counter, defaultdict
        import json
        
        # OWASP Top 10 2021 CWE映射
        owasp_top_10_2021 = {
            "A01 - Broken Access Control": [
                "CWE-22", "CWE-23", "CWE-35", "CWE-59", "CWE-200", "CWE-201", "CWE-219", 
                "CWE-264", "CWE-275", "CWE-276", "CWE-284", "CWE-285", "CWE-352", "CWE-359", 
                "CWE-377", "CWE-402", "CWE-425", "CWE-441", "CWE-497", "CWE-538", "CWE-540", 
                "CWE-548", "CWE-552", "CWE-566", "CWE-601", "CWE-639", "CWE-651", "CWE-668", 
                "CWE-706", "CWE-862", "CWE-863", "CWE-913", "CWE-922", "CWE-1275"
            ],
            "A02 - Cryptographic Failures": [
                "CWE-259", "CWE-261", "CWE-296", "CWE-310", "CWE-319", "CWE-321", "CWE-322", 
                "CWE-323", "CWE-324", "CWE-325", "CWE-326", "CWE-327", "CWE-328", "CWE-329", 
                "CWE-330", "CWE-331", "CWE-335", "CWE-336", "CWE-337", "CWE-338", "CWE-340", 
                "CWE-347", "CWE-523", "CWE-720", "CWE-757", "CWE-759", "CWE-760", "CWE-780", 
                "CWE-818", "CWE-916"
            ],
            "A03 - Injection": [
                "CWE-20", "CWE-74", "CWE-75", "CWE-77", "CWE-78", "CWE-79", "CWE-80", "CWE-83", 
                "CWE-87", "CWE-88", "CWE-89", "CWE-90", "CWE-91", "CWE-93", "CWE-94", "CWE-95", 
                "CWE-96", "CWE-97", "CWE-98", "CWE-99", "CWE-100", "CWE-113", "CWE-116", "CWE-138", 
                "CWE-184", "CWE-470", "CWE-471", "CWE-564", "CWE-610", "CWE-643", "CWE-644", 
                "CWE-652", "CWE-917"
            ],
            "A04 - Insecure Design": [
                "CWE-73", "CWE-183", "CWE-209", "CWE-213", "CWE-235", "CWE-256", "CWE-257", 
                "CWE-266", "CWE-269", "CWE-280", "CWE-311", "CWE-312", "CWE-313", "CWE-316", 
                "CWE-419", "CWE-430", "CWE-434", "CWE-444", "CWE-451", "CWE-472", "CWE-501", 
                "CWE-522", "CWE-525", "CWE-539", "CWE-579", "CWE-598", "CWE-602", "CWE-642", 
                "CWE-646", "CWE-650", "CWE-653", "CWE-656", "CWE-657", "CWE-799", "CWE-807", 
                "CWE-840", "CWE-841", "CWE-927", "CWE-1021", "CWE-1173"
            ],
            "A05 - Security Misconfiguration": [
                "CWE-2", "CWE-11", "CWE-13", "CWE-15", "CWE-16", "CWE-260", "CWE-315", "CWE-520", 
                "CWE-526", "CWE-537", "CWE-541", "CWE-547", "CWE-611", "CWE-614", "CWE-756", 
                "CWE-776", "CWE-942", "CWE-1004", "CWE-1032", "CWE-1174"
            ],
            "A06 - Vulnerable and Outdated Components": [
                "CWE-937", "CWE-1035", "CWE-1104"
            ],
            "A07 - Identification and Authentication Failures": [
                "CWE-255", "CWE-259", "CWE-287", "CWE-288", "CWE-290", "CWE-294", "CWE-295", 
                "CWE-297", "CWE-300", "CWE-302", "CWE-304", "CWE-306", "CWE-307", "CWE-346", 
                "CWE-384", "CWE-521", "CWE-613", "CWE-620", "CWE-640", "CWE-798", "CWE-940", 
                "CWE-1216"
            ],
            "A08 - Software and Data Integrity Failures": [
                "CWE-345", "CWE-353", "CWE-426", "CWE-494", "CWE-502", "CWE-565", "CWE-784", 
                "CWE-829", "CWE-830", "CWE-915"
            ],
            "A09 - Security Logging and Monitoring Failures": [
                "CWE-117", "CWE-223", "CWE-532", "CWE-778"
            ],
            "A10 - Server-Side Request Forgery (SSRF)": [
                "CWE-918"
            ]
        }
        
        # CWE Top 25
        cwe_top_25_ids = set([
            "CWE-79", "CWE-787", "CWE-89", "CWE-352", "CWE-22", "CWE-125", "CWE-78", 
            "CWE-416", "CWE-862", "CWE-434", "CWE-94", "CWE-20", "CWE-77", "CWE-287", 
            "CWE-269", "CWE-502", "CWE-200", "CWE-863", "CWE-918", "CWE-119", "CWE-476", 
            "CWE-798", "CWE-190", "CWE-400", "CWE-306"
        ])
        
        # 展开OWASP Top 10所有CWE
        owasp_all_cwes = set([item for sublist in owasp_top_10_2021.values() for item in sublist])
        
        # 获取CVE到advisory的映射
        cve2advisory = self.cve2advisory
        
        # 分类CVE
        owasp_cves = {}
        cwe_top25_cves = {}
        owasp_category_cves = defaultdict(set)
        
        # 统计覆盖情况
        for cve_id, advisory in cve2advisory.items():
            cwe_ids = advisory.get('database_specific',{}).get('cwe_ids', [])
            
            if isinstance(cwe_ids, str):
                cwe_ids = [cwe_ids]
            
            cwe_ids_set = set(cwe_ids)
            
            # OWASP Top 10覆盖
            owasp_intersection = cwe_ids_set & owasp_all_cwes
            if owasp_intersection:
                owasp_cves[cve_id] = advisory
                
                # 分类到具体的OWASP类别
                for category, category_cwes in owasp_top_10_2021.items():
                    if cwe_ids_set & set(category_cwes):
                        owasp_category_cves[category].add(cve_id)
            
            # CWE Top 25覆盖
            cwe_top25_intersection = cwe_ids_set & cwe_top_25_ids
            if cwe_top25_intersection:
                cwe_top25_cves[cve_id] = advisory
        
        # 分析传播情况
        coverage_stats = self._analyze_coverage_propagation(
            all_results, owasp_cves, cwe_top25_cves, owasp_category_cves
        )
        
        # 计算覆盖率统计
        coverage_summary = self._calculate_coverage_summary(
            cve2advisory, owasp_cves, cwe_top25_cves, owasp_category_cves,
            owasp_all_cwes, cwe_top_25_ids
        )
        
        return {
            'coverage_summary': coverage_summary,
            'propagation_stats': coverage_stats,
            'owasp_cves': owasp_cves,
            'cwe_top25_cves': cwe_top25_cves,
            'owasp_category_breakdown': dict(owasp_category_cves)
        }

    def _analyze_coverage_propagation(self, all_results: Dict, owasp_cves: Dict, 
                                    cwe_top25_cves: Dict, owasp_category_cves: Dict) -> Dict:
        """分析覆盖CVE的传播情况"""
        
        # 统计传播情况
        def analyze_cve_set(cve_set, name):
            stats = {
                'total_cves': len(cve_set),
                'analyzed_cves': 0,
                'reachable_cves': 0,
                'total_pairs': 0,
                'reachable_pairs': 0,
                'total_invocations': 0,
                'invocation_counts': []
            }
            
            for cve_id in cve_set:
                if cve_id in all_results:
                    stats['analyzed_cves'] += 1
                    cve_has_reachable = False
                    
                    for upstream, downstream_results in all_results[cve_id].items():
                        if isinstance(downstream_results, str):
                            continue
                            
                        for downstream, status in downstream_results.items():
                            stats['total_pairs'] += 1
                            
                            if status == 'VF Found':
                                cve_has_reachable = True
                                stats['reachable_pairs'] += 1
                                
                                # 获取invocation信息
                                result_file = CG_DIR_DATE / f'{cve_id}/{downstream}_results.json'
                                if result_file.exists():
                                    try:
                                        with open(result_file, 'r') as f:
                                            detailed_result = json.load(f)
                                        
                                        vulnerable_invocations = detailed_result.get('vulnerable_invocation', [])
                                        invocation_count = len(vulnerable_invocations)
                                        stats['total_invocations'] += invocation_count
                                        if invocation_count > 0:
                                            stats['invocation_counts'].append(invocation_count)
                                            
                                    except Exception as e:
                                        continue
                    
                    if cve_has_reachable:
                        stats['reachable_cves'] += 1
            
            return stats
        
        propagation_stats = {}
        
        # 分析OWASP Top 10
        propagation_stats['owasp_top10'] = analyze_cve_set(set(owasp_cves.keys()), 'OWASP Top 10')
        
        # 分析CWE Top 25
        propagation_stats['cwe_top25'] = analyze_cve_set(set(cwe_top25_cves.keys()), 'CWE Top 25')
        
        # 分析OWASP各类别
        propagation_stats['owasp_categories'] = {}
        for category, cve_set in owasp_category_cves.items():
            propagation_stats['owasp_categories'][category] = analyze_cve_set(cve_set, category)
        
        # 分析总体情况
        all_analyzed_cves = set(all_results.keys())
        propagation_stats['all_cves'] = analyze_cve_set(all_analyzed_cves, 'All CVEs')
        
        return propagation_stats

    def _calculate_coverage_summary(self, cve2advisory: Dict, owasp_cves: Dict, 
                                cwe_top25_cves: Dict, owasp_category_cves: Dict,
                                owasp_all_cwes: set, cwe_top_25_ids: set) -> Dict:
        """计算覆盖率汇总统计"""
        
        def calculate_percentage(data):
            """计算百分比分布"""
            categories = set(data)
            percentage = {}
            total = len(data)
            for category in categories:
                count = data.count(category)
                percentage[category] = {
                    'count': count,
                    'percentage': round(count * 100 / total, 2) if total > 0 else 0
                }
            return percentage
        
        summary = {}
        
        # 基础统计
        total_cves = len(cve2advisory)
        owasp_cve_count = len(owasp_cves)
        cwe_top25_cve_count = len(cwe_top25_cves)
        
        summary['basic_stats'] = {
            'total_cves': total_cves,
            'owasp_top10_cves': owasp_cve_count,
            'owasp_coverage_rate': round(owasp_cve_count * 100 / total_cves, 2),
            'cwe_top25_cves': cwe_top25_cve_count,
            'cwe_top25_coverage_rate': round(cwe_top25_cve_count * 100 / total_cves, 2),
            'owasp_cwe_count': len(owasp_all_cwes),
            'cwe_top25_count': len(cwe_top_25_ids)
        }
        
        # 严重程度分布
        all_severities = [advisory.get('database_specific',{}).get('severity', 'Unknown') for advisory in cve2advisory.values()]
        owasp_severities = [advisory.get('database_specific',{}).get('severity', 'Unknown') for advisory in owasp_cves.values()]
        cwe_top25_severities = [advisory.get('database_specific',{}).get('severity', 'Unknown') for advisory in cwe_top25_cves.values()]
        
        summary['severity_distribution'] = {
            'all_cves': calculate_percentage(all_severities),
            'owasp_top10': calculate_percentage(owasp_severities),
            'cwe_top25': calculate_percentage(cwe_top25_severities)
        }
        
        # OWASP类别分布
        summary['owasp_category_distribution'] = {}
        for category, cve_set in owasp_category_cves.items():
            summary['owasp_category_distribution'][category] = {
                'cve_count': len(cve_set),
                'percentage': round(len(cve_set) * 100 / owasp_cve_count, 2) if owasp_cve_count > 0 else 0
            }
        
        return summary

    def pretty_print_owasp_cwe_coverage(self, coverage_analysis: Dict) -> None:
        """格式化打印OWASP/CWE覆盖分析结果"""
        
        print("\n" + "="*100)
        print("OWASP TOP 10 AND CWE TOP 25 COVERAGE ANALYSIS")
        print("="*100)
        
        summary = coverage_analysis['coverage_summary']
        propagation = coverage_analysis['propagation_stats']
        
        # 基础覆盖统计
        basic = summary['basic_stats']
        print(f"\nBASIC COVERAGE STATISTICS:")
        print(f"  Total CVEs in dataset: {basic['total_cves']:,}")
        print(f"  OWASP Top 10 CVEs: {basic['owasp_top10_cves']:,} ({basic['owasp_coverage_rate']:.1f}%)")
        print(f"  CWE Top 25 CVEs: {basic['cwe_top25_cves']:,} ({basic['cwe_top25_coverage_rate']:.1f}%)")
        print(f"  OWASP CWE types covered: {basic['owasp_cwe_count']} CWEs")
        print(f"  CWE Top 25 types: {basic['cwe_top25_count']} CWEs")
        
        # 传播效果对比
        print(f"\nPROPAGATION EFFECTIVENESS COMPARISON:")
        print(f"{'Category':<25} {'Total':<8} {'Analyzed':<9} {'Reachable':<10} {'Prop.Rate':<10} {'Pairs':<8} {'Reach.Pairs':<11}")
        print("-" * 85)
        
        categories = [
            ('All CVEs', propagation['all_cves']),
            ('OWASP Top 10', propagation['owasp_top10']),
            ('CWE Top 25', propagation['cwe_top25'])
        ]
        
        for name, stats in categories:
            prop_rate = (stats['reachable_cves'] / stats['analyzed_cves'] * 100) if stats['analyzed_cves'] > 0 else 0
            print(f"{name:<25} {stats['total_cves']:<8} {stats['analyzed_cves']:<9} {stats['reachable_cves']:<10} "
                f"{prop_rate:<9.1f}% {stats['total_pairs']:<8} {stats['reachable_pairs']:<11}")
        
        # OWASP类别详细分析
        print(f"\nOWASP TOP 10 CATEGORY BREAKDOWN:")
        print(f"{'Category':<45} {'CVEs':<6} {'%':<6} {'Analyzed':<9} {'Reachable':<10} {'Prop.Rate':<10}")
        print("-" * 90)
        
        owasp_cats = propagation['owasp_categories']
        category_dist = summary['owasp_category_distribution']
        
        # 按CVE数量排序
        sorted_categories = sorted(category_dist.items(), key=lambda x: x[1]['cve_count'], reverse=True)
        
        for category, dist_info in sorted_categories:
            if category in owasp_cats:
                stats = owasp_cats[category]
                prop_rate = (stats['reachable_cves'] / stats['analyzed_cves'] * 100) if stats['analyzed_cves'] > 0 else 0
                
                # 缩短类别名称显示
                short_category = category.replace(" - ", "-").replace("and ", "& ")
                if len(short_category) > 44:
                    short_category = short_category[:41] + "..."
                    
                print(f"{short_category:<45} {dist_info['cve_count']:<6} {dist_info['percentage']:<5.1f}% "
                    f"{stats['analyzed_cves']:<9} {stats['reachable_cves']:<10} {prop_rate:<9.1f}%")
        
        # 严重程度分布对比
        print(f"\nSEVERITY DISTRIBUTION COMPARISON:")
        severity_dist = summary['severity_distribution']
        
        print(f"{'Severity':<10} {'All CVEs':<15} {'OWASP Top 10':<15} {'CWE Top 25':<15}")
        print("-" * 60)
        
        all_severities = set()
        for dist in severity_dist.values():
            all_severities.update(dist.keys())
        
        severity_order = ['Critical', 'High', 'Medium', 'Low', 'Unknown']
        for severity in severity_order:
            if severity in all_severities:
                all_info = severity_dist['all_cves'].get(severity, {'count': 0, 'percentage': 0})
                owasp_info = severity_dist['owasp_top10'].get(severity, {'count': 0, 'percentage': 0})
                cwe_info = severity_dist['cwe_top25'].get(severity, {'count': 0, 'percentage': 0})
                
                print(f"{severity:<10} {all_info['count']:>6}({all_info['percentage']:>5.1f}%) "
                    f"{owasp_info['count']:>6}({owasp_info['percentage']:>5.1f}%) "
                    f"{cwe_info['count']:>6}({cwe_info['percentage']:>5.1f}%)")
        
        # 关键发现
        print(f"\nKEY FINDINGS:")
        owasp_stats = propagation['owasp_top10']
        cwe_stats = propagation['cwe_top25']
        all_stats = propagation['all_cves']
        
        owasp_prop_rate = (owasp_stats['reachable_cves'] / owasp_stats['analyzed_cves'] * 100) if owasp_stats['analyzed_cves'] > 0 else 0
        cwe_prop_rate = (cwe_stats['reachable_cves'] / cwe_stats['analyzed_cves'] * 100) if cwe_stats['analyzed_cves'] > 0 else 0
        all_prop_rate = (all_stats['reachable_cves'] / all_stats['analyzed_cves'] * 100) if all_stats['analyzed_cves'] > 0 else 0
        
        print(f"  • OWASP Top 10 CVEs have {owasp_prop_rate:.1f}% propagation rate vs {all_prop_rate:.1f}% overall")
        print(f"  • CWE Top 25 CVEs have {cwe_prop_rate:.1f}% propagation rate vs {all_prop_rate:.1f}% overall")
        
        # 找出传播率最高的OWASP类别
        best_category = max(owasp_cats.items(), 
                        key=lambda x: x[1]['reachable_cves'] / x[1]['analyzed_cves'] if x[1]['analyzed_cves'] > 0 else 0)
        best_rate = (best_category[1]['reachable_cves'] / best_category[1]['analyzed_cves'] * 100) if best_category[1]['analyzed_cves'] > 0 else 0
        print(f"  • Highest propagation OWASP category: {best_category[0]} ({best_rate:.1f}%)")

    def pretty_print_severity_analysis(self, severity_analysis: Dict) -> None:
        """格式化打印严重程度分析结果"""
        
        print("\n" + "="*120)
        print("VULNERABILITY PROPAGATION BY SEVERITY DISTRIBUTION")
        print("="*120)
        
        summary_table = severity_analysis['summary_table']
        
        # 打印表格标题
        print(f"\n{'Severity':<10} {'Total':<8} {'Reachable':<10} {'CVE Prop.':<10} {'Total':<8} {'Reachable':<10} {'Pair Prop.':<10} {'Avg.':<8}")
        print(f"{'Level':<10} {'CVEs':<8} {'CVEs':<10} {'Rate':<10} {'Pairs':<8} {'Pairs':<10} {'Rate':<10} {'Invocations':<8}")
        print("-" * 85)
        
        # 按严重程度顺序打印
        severity_order = ['Critical', 'High', 'Medium', 'Low', 'Unknown', 'None']
        for severity in severity_order:
            if severity in summary_table and severity != 'Total':
                stats = summary_table[severity]
                print(f"{severity:<10} {stats['Total CVEs']:<8} {stats['Reachable CVEs']:<10} "
                    f"{stats['CVE Propagation Rate']:<10} {stats['Total Pairs']:<8} "
                    f"{stats['Reachable Pairs']:<10} {stats['Pair Propagation Rate']:<10} "
                    f"{stats['Avg. Invocations']:<8}")
        
        print("-" * 85)
        
        # 打印总计
        if 'Total' in summary_table:
            total_stats = summary_table['Total']
            print(f"{'Total':<10} {total_stats['Total CVEs']:<8} {total_stats['Reachable CVEs']:<10} "
                f"{total_stats['CVE Propagation Rate']:<10} {total_stats['Total Pairs']:<8} "
                f"{total_stats['Reachable Pairs']:<10} {total_stats['Pair Propagation Rate']:<10} "
                f"{total_stats['Avg. Invocations']:<8}")
        
        # 详细分析
        detailed = severity_analysis['detailed_breakdown']
        propagation = detailed['propagation_by_severity']
        
        print(f"\nSEVERITY PROPAGATION EFFECTIVENESS:")
        print("-" * 60)
        
        print("By CVE Propagation Rate:")
        for i, (severity, rate, reachable, total) in enumerate(propagation['by_cve_propagation_rate'][:5]):
            print(f"  {i+1}. {severity}: {rate:.1f}% ({reachable}/{total} CVEs)")
        
        print("\nBy Impact Count (Reachable CVEs):")
        for i, (severity, reachable, total) in enumerate(propagation['by_impact_count'][:5]):
            print(f"  {i+1}. {severity}: {reachable} reachable CVEs (out of {total} total)")
        
        # 严重程度分布饼图数据
        print(f"\nSEVERITY DISTRIBUTION BREAKDOWN:")
        print("-" * 40)
        distribution = detailed['severity_distribution']
        total_all_cves = sum(dist['total_cves'] for dist in distribution.values())
        
        for severity in severity_order:
            if severity in distribution:
                dist = distribution[severity]
                percentage = (dist['total_cves'] / total_all_cves * 100) if total_all_cves > 0 else 0
                print(f"  {severity}: {dist['total_cves']} CVEs ({percentage:.1f}%)")
                print(f"    └─ Reachable: {dist['reachable_cves']} ({dist['cve_propagation_rate']:.1f}%)")

    def pretty_print_cwe_analysis(self, cwe_analysis: Dict) -> None:
        """格式化打印CWE分析结果"""
        
        print("\n" + "="*100)
        print("VULNERABILITY PROPAGATION PATTERNS BY CWE CATEGORY (TOP 10)")
        print("="*100)
        
        summary_table = cwe_analysis['summary_table']
        
        # 打印表格标题
        print(f"\n{'CWE Type':<40} {'Total':<8} {'Reachable':<10} {'Propagation':<12} {'Avg.':<8}")
        print(f"{'':40} {'CVEs':<8} {'CVEs':<10} {'Rate':<12} {'Invocations':<8}")
        print("-" * 80)
        
        # 打印Top 10 CWE类型
        for cwe_type, stats in summary_table['Top 10 CWE Types'].items():
            # 格式化CWE类型显示
            cwe_display = self._format_cwe_display(cwe_type)
            print(f"{cwe_display:<40} {stats['Total CVEs']:<8} {stats['Reachable CVEs']:<10} "
                f"{stats['Propagation Rate']:<12} {stats['Avg. Invocations']:<8}")
        
        print("-" * 80)
        
        # 打印总计
        total_stats = summary_table['Total']
        print(f"{'Total':<40} {total_stats['Total CVEs']:<8} {total_stats['Reachable CVEs']:<10} "
            f"{total_stats['Propagation Rate']:<12} {total_stats['Avg. Invocations']:<8}")
        
        # 详细分析
        detailed = cwe_analysis['detailed_breakdown']
        
        print(f"\nTOP CWE TYPES BY PROPAGATION EFFECTIVENESS:")
        print("-" * 60)
        effectiveness = detailed['propagation_effectiveness']
        
        print("By Propagation Rate:")
        for i, (cwe_type, rate) in enumerate(effectiveness['by_propagation_rate'][:5]):
            cwe_display = self._format_cwe_display(cwe_type)
            print(f"  {i+1}. {cwe_display}: {rate:.1f}%")
        
        print("\nBy Impact Count (Reachable CVEs):")
        for i, (cwe_type, count) in enumerate(effectiveness['by_impact_count'][:5]):
            cwe_display = self._format_cwe_display(cwe_type)
            print(f"  {i+1}. {cwe_display}: {count} CVEs")

    def _format_cwe_display(self, cwe_type: str) -> str:
        """格式化CWE类型显示名称"""
        # CWE映射字典，可以根据需要扩展
        cwe_descriptions = {
            'CWE-79': 'CWE-79 (Cross-site Scripting)',
            'CWE-22': 'CWE-22 (Path Traversal)', 
            'CWE-20': 'CWE-20 (Improper Input Validation)',
            'CWE-200': 'CWE-200 (Information Exposure)',
            'CWE-400': 'CWE-400 (Resource Consumption)',
            'CWE-94': 'CWE-94 (Code Injection)',
            'CWE-601': 'CWE-601 (URL Redirection)',
            'CWE-770': 'CWE-770 (Resource Allocation)',
            'CWE-89': 'CWE-89 (SQL Injection)',
            'CWE-502': 'CWE-502 (Deserialization)',
            'CWE-1333': 'CWE-1333 (Inefficient Regular Expression)',
            'CWE-74': 'CWE-74 (Improper Neutralization)'
        }
        
        return cwe_descriptions.get(cwe_type, cwe_type)


    def pretty_print_dependency_analysis(self, dependency_analysis: Dict) -> None:
        """格式化打印依赖分析结果"""
        
        print("\n" + "="*100)
        print("VULNERABILITY PROPAGATION BY DEPENDENCY TYPE AND DEPTH")
        print("="*100)
        
        summary_table = dependency_analysis['summary_table']
        
        # 打印表格标题
        print(f"\n{'Dependency Category':<25} {'Total':<8} {'Reachable':<10} {'Propagation':<12} {'Avg.':<8} {'Avg. Path':<10}")
        print(f"{'':25} {'Pairs':<8} {'Pairs':<10} {'Rate':<12} ")
        print("-" * 80)
        
        # 按依赖类型
        print("By Dependency Type")
        for dep_type, stats in summary_table['By Dependency Type'].items():
            print(f"{dep_type:<25} {stats['Total Pairs']:<8,} {stats['Reachable Pairs']:<10,} "
                f"{stats['Propagation Rate']:<12} ")
        
        print()
        
        # 按依赖深度
        print("By Dependency Depth")
        print()
        depth_order = ['Depth 1', 'Depth 2', 'Depth 3', 'Depth 4','Depth 5','Depth 6','Depth 7','Depth 8','Depth 9','Depth 10+']
        for depth_key in depth_order:
            if depth_key in summary_table['By Dependency Depth']:
                stats = summary_table['By Dependency Depth'][depth_key]
                display_name = f"{depth_key} (Direct)" if depth_key == 'Depth 1' else depth_key
                print(f"{display_name:<25} {stats['Total Pairs']:<8,} {stats['Reachable Pairs']:<10,} "
                    f"{stats['Propagation Rate']:<12}")
        
        print("-" * 80)
        
        # 总计
        total_stats = summary_table['Overall Total']
        print(f"{'Overall Total':<25} {total_stats['Total Pairs']:<8,} {total_stats['Reachable Pairs']:<10,} "
            f"{total_stats['Propagation Rate']:<12} ")
        
        # 详细分析
        detailed = dependency_analysis['detailed_analysis']
        
        print(f"\nDETAILED DISTRIBUTION ANALYSIS:")
        print(f"Depth Distribution: {detailed['depth_distribution']['total_by_depth']}")
        print(f"Type Distribution: {detailed['type_distribution']['total_by_type']}")
        print(f"Reachable by Depth: {detailed['depth_distribution']['reachable_by_depth']}")
        print(f"Reachable by Type: {detailed['type_distribution']['reachable_by_type']}")
    
    
    def pretty_print_impact_rankings(self,impact_rankings: Dict) -> None:
        
        """Pretty print impact rankings with CVE package names"""
        cve2advisory = self.cve2advisory
        def get_package_names_for_cve(cve_id: str) -> str:
            """从CVE advisory中提取package names"""
            if cve_id not in cve2advisory:
                return ""
            
            packages = list(cve2advisory[cve_id].get('available_affected', {}).keys())
            if len(packages) == 1:
                return packages[0]
            elif len(packages) <= 3:
                return ", ".join(packages)
            else:
                return f"{packages[0]}, {packages[1]}... (+{len(packages)-2})"
        
        print("\n" + "="*100)
        print("CVE AND UPSTREAM IMPACT RANKINGS")
        print("="*100)
        
        # CVE Rankings
        print("\nTOP 10 CVEs BY REACHABLE CVE-DOWNSTREAM PAIRS:")
        print("-" * 90)
        for i, cve_data in enumerate(impact_rankings['cve_impact_ranking']['by_reachable_cve_downstream'][:10]):
            package_names = get_package_names_for_cve(cve_data['cve_id'])
            print(f"{i+1:2d}. {cve_data['cve_id']:<15} | "
                    f"{package_names:<25} | "
                    f"Reachable: {cve_data['reachable_cve_downstream']:>4} / {cve_data['total_cve_downstream']:>4} | "
                    f"Rate: {cve_data['cve_downstream_impact_rate']:>6.1%}")
        
        print("\nTOP 10 CVEs BY HIGHEST IMPACT RATE (Upstream-Downstream):")
        print("-" * 90)
        high_impact_cves = [c for c in impact_rankings['cve_impact_ranking']['by_cve_downstream_rate'] 
                            if c['total_cve_downstream']][:10]
        for i, cve_data in enumerate(high_impact_cves):
            package_names = get_package_names_for_cve(cve_data['cve_id'])
            print(f"{i+1:2d}. {cve_data['cve_id']:<15} | "
                    f"{package_names:<25} | "
                    f"Rate: {cve_data['cve_downstream_impact_rate']:>6.1%} | "
                    f"Pairs: {cve_data['reachable_cve_downstream']:>3}/{cve_data['total_cve_downstream']:>3}")


        
        # Upstream Rankings
        print("\n🚀 TOP 10 UPSTREAM PACKAGES BY REACHABLE PAIRS:")
        print("-" * 70)
        for i, upstream_data in enumerate(impact_rankings['upstream_impact_ranking'][:10]):
            upstream_parts = upstream_data['upstream_cve'].split('@')
            if len(upstream_parts) >= 2:
                package_info = f"{upstream_parts[0]}@{upstream_parts[1]}"
                cve_info = f"CVE-{upstream_parts[-1].split('CVE-')[-1]}" if 'CVE-' in upstream_data['upstream_cve'] else ""
            else:
                package_info = upstream_data['upstream_cve']
                cve_info = ""
                
            print(f"{i+1:2d}. {package_info:<30} {cve_info:<15} | "
                    f"Reachable: {upstream_data['reachable_downstream_pairs']:>3} | "
                    f"Rate: {upstream_data['impact_rate']:>6.1%}")

    def pretty_print_true_positive_analysis(self,tp_analysis: Dict) -> None:
        """Pretty print true positive analysis results"""
        
        print("\n" + "="*80)
        print("TRUE POSITIVE ANALYSIS")
        print("="*80)
        
        # Summary statistics
        summary = tp_analysis
        print(f"\nOVERALL STATISTICS:")
        print(f"  Total CVE-Downstream pairs: {summary['total_pairs']:,}")
        print(f"  True positives (VF Found): {summary['true_positives']:,}")
        print(f"  True positive rate: {summary['true_positive_rate']:.2%}")
        
        # Status breakdown
        print(f"\nSTATUS BREAKDOWN:")
        print("-" * 50)
        status_breakdown = tp_analysis['status_breakdown']
        total = sum(status_breakdown.values())
        
        # Sort by count descending
        sorted_statuses = sorted(status_breakdown.items(), key=lambda x: x[1], reverse=True)
        
        for status, count in sorted_statuses:
            percentage = count / total * 100 if total > 0 else 0
            bar_length = int(percentage / 2)  # Scale bar to 50 chars max
            bar = "█" * bar_length + "░" * (50 - bar_length)
            print(f"  {status:<20} | {count:>8,} ({percentage:>5.1f}%) | {bar}")
        
        # CVE-level breakdown (top performers)
        print(f"\nTOP 10 CVEs BY TRUE POSITIVE COUNT:")
        print("-" * 60)
        cve_breakdown = tp_analysis.get('cve_tp_breakdown', {})
        top_cves = sorted(cve_breakdown.items(), key=lambda x: x[1]['true_positives'], reverse=True)[:15]
        
        for i, (cve_id, stats) in enumerate(top_cves):
            print(f"{i+1:2d}. {cve_id:<15} | "
                    f"TP: {stats['true_positives']:>4} / {stats['total']:>4} | "
                    f"Rate: {stats['tp_rate']:>6.1%}")
        
        # CVE-level breakdown (highest rates)
        print(f"\nTOP 10 CVEs BY TRUE POSITIVE RATE:")
        print("-" * 60)
        high_rate_cves = [
            (cve_id, stats) for cve_id, stats in cve_breakdown.items() 
            if stats['total']
        ]
        high_rate_cves = sorted(high_rate_cves, key=lambda x: x[1]['tp_rate'], reverse=True)[:15]
        
        for i, (cve_id, stats) in enumerate(high_rate_cves):
            print(f"{i+1:2d}. {cve_id:<15} | "
                    f"Rate: {stats['tp_rate']:>6.1%} | "
                    f"TP: {stats['true_positives']:>3} / {stats['total']:>3}")
        
        # Distribution analysis
        if cve_breakdown:
            tp_rates = [stats['tp_rate'] for stats in cve_breakdown.values()]
            tp_counts = [stats['true_positives'] for stats in cve_breakdown.values()]
            
            print(f"\nDISTRIBUTION ANALYSIS:")
            print(f"  CVEs with 0% TP rate: {sum(1 for rate in tp_rates if rate == 0):,}")
            print(f"  CVEs with 100% TP rate: {sum(1 for rate in tp_rates if rate == 1.0):,}")
            print(f"  CVEs with >50% TP rate: {sum(1 for rate in tp_rates if rate > 0.5):,}")
            print(f"  Average TP rate per CVE: {np.mean(tp_rates):.2%}")
            print(f"  Median TP count per CVE: {np.median(tp_counts):.1f}")

    def generate_comprehensive_report(self
                                    ) -> Dict[str, Any]:
        """
        生成综合分析报告
        
        Args:
            all_results: 分析结果
            cg_dir: call graph结果目录
            output_file: 可选的输出文件路径
            
        Returns:
            Complete analysis report
        """
        all_results = self.all_results
        
        cve_impact_analysis = self.analyze_cve_downstream_impact(all_results)
        print(cve_impact_analysis['summary_stats'])
        self.pretty_print_impact_rankings(cve_impact_analysis['impact_rankings'])
        impacting_upstreams, impacted_downstreams = cve_impact_analysis['raw_data']['impacting_upstreams'],cve_impact_analysis['raw_data']['impacted_downstreams']
        print(impacted_downstreams)
       

        # true_positive_analysis = self.calculate_true_positives(all_results)
        # self.pretty_print_true_positive_analysis(true_positive_analysis)

        # cwe_analysis_results = self.analyze_cwe_propagation_patterns(all_results)
        # self.pretty_print_cwe_analysis(cwe_analysis_results)

        # severity_analysis_results = self.analyze_severity_distribution(all_results)
        # self.pretty_print_severity_analysis(severity_analysis_results)

        # owasp_coverage_results = self.analyze_owasp_cwe_coverage(all_results)
        # self.pretty_print_owasp_cwe_coverage(owasp_coverage_results)
        # dep_analysis_results = self.analyze_dependency_depth_and_type(all_results)
        # self.pretty_print_dependency_analysis(dep_analysis_results)
        reachable_pairs_analysis = self.analyze_reachable_pairs_details(all_results)
        self.pretty_print_reachable_pairs_analysis(reachable_pairs_analysis)
        assert False
        
        report = {
            'cve_impact_analysis': cve_impact_analysis,
            'true_positive_analysis': true_positive_analysis,
            'reachable_pairs_analysis': reachable_pairs_analysis,
            'generation_timestamp': datetime.now().isoformat()
        }

        # 打印概要统计
        self._print_comprehensive_summary(report)
        
        # 保存到文件
        if False and output_file:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Comprehensive report saved to {output_file}")
        
        return report
    
    def _print_comprehensive_summary(self, report: Dict[str, Any]) -> None:
        """打印综合分析概要"""
        cve_analysis = report['cve_impact_analysis']
        tp_analysis = report['true_positive_analysis']
        reachable_analysis = report['reachable_pairs_analysis']
        
        print("\n" + "="*80)
        print("COMPREHENSIVE VULNERABILITY REACHABILITY ANALYSIS")
        print("="*80)
        
        # CVE影响统计
        print(f"\n📊 CVE IMPACT STATISTICS:")
        print(f"  Total CVEs analyzed: {cve_analysis['total_cves']:,}")
        print(f"  CVEs affecting downstream: {cve_analysis['impacting_cves']:,}")
        print(f"  CVE impact rate: {cve_analysis['impact_rate']:.2%}")
        
        # True Positive统计
        print(f"\n✅ TRUE POSITIVE ANALYSIS:")
        print(f"  Total CVE-Downstream pairs: {tp_analysis['total_pairs']:,}")
        print(f"  True positives (VF Found): {tp_analysis['true_positives']:,}")
        print(f"  True positive rate: {tp_analysis['true_positive_rate']:.2%}")
        
        # 可达性详细分析
        print(f"\n🔗 REACHABLE PAIRS DETAILED ANALYSIS:")
        print(f"  Total reachable pairs: {reachable_analysis['total_reachable_pairs']:,}")
        print(f"  Pairs with call chains: {reachable_analysis['pairs_with_call_chains']:,}")
        
        # Call chain统计
        chain_stats = reachable_analysis['call_chain_stats']
        if chain_stats['total_chains'] > 0:
            print(f"  Total call chains: {chain_stats['total_chains']:,}")
            print(f"  Avg chain length: {chain_stats['avg_chain_length']:.2f}")
            print(f"  Chain length range: {chain_stats['min_chain_length']} - {chain_stats['max_chain_length']}")
            
            if 'chain_length_percentiles' in chain_stats:
                percentiles = chain_stats['chain_length_percentiles']
                print(f"  Chain length percentiles (25/50/75/90): "
                      f"{percentiles['25th']:.1f}/{percentiles['50th']:.1f}/"
                      f"{percentiles['75th']:.1f}/{percentiles['90th']:.1f}")
        
        # Vulnerable invocation统计
        inv_stats = reachable_analysis['vulnerable_invocation_stats']
        if inv_stats['total_invocations'] > 0:
            print(f"  Total vulnerable invocations: {inv_stats['total_invocations']:,}")
            print(f"  Pairs with invocations: {inv_stats['pairs_with_invocations']:,}")
            print(f"  Avg invocations per pair: {inv_stats['avg_invocations_per_pair']:.2f}")
            print(f"  Max invocations in single pair: {inv_stats['max_invocations']:,}")
        
        # Function reachability统计
        func_stats = reachable_analysis['function_reachability_stats']
        if func_stats['total_found_functions'] > 0:
            print(f"  Total found functions: {func_stats['total_found_functions']:,}")
            print(f"  Avg functions per pair: {func_stats['avg_functions_per_pair']:.2f}")
        
        # Status breakdown
        print(f"\n📈 STATUS BREAKDOWN:")
        for status, count in sorted(tp_analysis['status_breakdown'].items()):
            percentage = count / tp_analysis['total_pairs'] * 100
            print(f"  {status}: {count:,} ({percentage:.2f}%)")


if __name__ == "__main__":

    calculator = StatisticsCalculator()


    calculator.generate_comprehensive_report()
