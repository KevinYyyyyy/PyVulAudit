"""
Vulnerability Reachability Analysis Pipeline

This module implements a comprehensive system for analyzing how security vulnerabilities
in upstream Python packages propagate to downstream dependents through call graph analysis.
"""

import os
import json
import sys
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Tuple, Set, Optional, Any
import pickle
import traceback
from dataclasses import dataclass

import networkx as nx
from tqdm import tqdm
from joblib import Parallel, delayed
from graphviz import Digraph
import numpy as np

from logger import logger
from constant import CALL_GRAPH_DIR, DATA_DIR,REACHABILITY_DIR_DATE,CALL_GRAPH_DIR_DATE,CODE_CHANGES_DIR_DATE,REACHABILITY_RESULT_DIR_DATE,VUL_PACKAGES_DIR_DATE,SUFFIX,SNAPSHOT_DIR,CG_DIR_DATE
from my_utils import get_repo_name, get_modules_from_py_files
from vul_analyze import get_pkg2url, read_cve2advisory
from collect_pkg_metadata import EnvAnalyzer
from visualize_stats import collect_stats, visualize_stats
from stdlib_list import stdlib_list
from collect_commits import  get_all_unique_affected_projects
from data_classes import VulnerablePackage

# Global constants
STDLIB_MODULES = stdlib_list()
MAX_PARALLEL_JOBS = 30

class VulnerabilityAnalyzer:
    """Main class for vulnerability reachability analysis."""
    
    def __init__(self, workdir: Path, dataset_size: str = 'small'):
        """Initialize the analyzer with configuration."""
        self.workdir = workdir
        self.dataset_size = dataset_size
        self._setup_paths()
        self._load_data()
    
    def _setup_paths(self) -> None:
        """Setup file paths based on dataset size."""
        size_suffix = self.dataset_size
        self.install_tasks_file = self.workdir / f'install_tasks_{size_suffix}.json'
        self.metadata_file = Path(f'./all_metadata_{size_suffix}.json')
        self.pairs_cache_file = DATA_DIR/ SUFFIX / f'get_all_downstream_and_pairs_results.pkl'
        self.pkg_with_py_file_cache_file = self.workdir / f'all_pkgs_with_py_file_{size_suffix}.pkl'
        self.results_file = REACHABILITY_RESULT_DIR_DATE/f'all_results_{size_suffix}.json'
        # 新增：保存VulnerablePackage实例的目录
        self.vulnerable_packages_dir = VUL_PACKAGES_DIR_DATE
        self.vulnerable_packages_dir.mkdir(exist_ok=True)
    
    def _load_data(self) -> None:
        """Load cached data and CVE information."""
        # Load CVE data
        kwargs = {self.dataset_size: True} if self.dataset_size != 'large' else {}
        self.cve2advisory = read_cve2advisory(cve_has_vf=True)
        active_cves =['CVE-2024-3772', 'CVE-2021-45116', 'CVE-2019-19844', 'CVE-2018-14574', 'CVE-2024-2206', 'CVE-2023-24580', 'CVE-2020-13757', 'CVE-2021-41213', 'CVE-2023-34239', 'CVE-2024-10188', 'CVE-2023-41164', 'CVE-2025-23217', 'CVE-2023-30798', 'CVE-2023-6015', 'CVE-2022-0736', 'CVE-2024-27318', 'CVE-2023-6977', 'CVE-2023-27476', 'CVE-2023-38325', 'CVE-2023-26145', 'CVE-2019-11324', 'CVE-2023-28370', 'CVE-2023-27586', 'CVE-2024-4941', 'CVE-2021-41127', 'CVE-2024-0964', 'CVE-2024-29073', 'CVE-2019-6975', 'CVE-2023-47641', 'CVE-2024-34072', 'CVE-2022-23651', 'CVE-2023-49083', 'CVE-2023-44271', 'CVE-2023-2800', 'CVE-2023-49082', 'CVE-2018-1000808', 'CVE-2021-29063', 'CVE-2024-55655', 'CVE-2024-28102', 'CVE-2021-37678', 'CVE-2015-2296', 'CVE-2025-27556', 'CVE-2024-1561', 'CVE-2023-38673', 'CVE-2023-6018', 'CVE-2020-7212', 'CVE-2024-53865', 'CVE-2024-27758', 'CVE-2017-12852', 'CVE-2024-1183', 'CVE-2024-23346', 'CVE-2021-41945', 'CVE-2024-9606', 'CVE-2021-21419', 'CVE-2021-34141', 'CVE-2024-32481', 'CVE-2023-49081', 'CVE-2020-1736', 'CVE-2016-10075', 'CVE-2024-53861', 'CVE-2021-44420', 'CVE-2018-25091', 'CVE-2016-2512', 'CVE-2023-31543', 'CVE-2024-21624', 'CVE-2017-7466', 'CVE-2023-36464', 'CVE-2020-25658', 'CVE-2023-41885', 'CVE-2024-37568', 'CVE-2024-21520', 'CVE-2024-41989', 'CVE-2023-51449', 'CVE-2022-21699', 'CVE-2021-25292', 'CVE-2023-47627', 'CVE-2024-27306', 'CVE-2024-41942', 'CVE-2024-37891', 'CVE-2024-4340', 'CVE-2023-36053', 'CVE-2019-7164', 'CVE-2023-43665', 'CVE-2023-29159', 'CVE-2024-27351', 'CVE-2023-48705', 'CVE-2023-43804', 'CVE-2024-21503', 'CVE-2021-32677', 'CVE-2024-24680', 'CVE-2019-12387', 'CVE-2015-8213', 'CVE-2023-42441', 'CVE-2024-29199', 'CVE-2023-23969', 'CVE-2023-41419', 'CVE-2024-47164', 'CVE-2023-41334', 'CVE-2024-30251', 'CVE-2023-6974', 'CVE-2024-26130', 'CVE-2024-23345', 'CVE-2023-46250', 'CVE-2023-6022', 'CVE-2023-45803', 'CVE-2024-3573', 'CVE-2020-36242', 'CVE-2023-50447', 'CVE-2023-23931', 'CVE-2024-56374', 'CVE-2022-45907', 'CVE-2024-34511', 'CVE-2024-23334', 'CVE-2022-24439', 'CVE-2019-14751', 'CVE-2023-6568', 'CVE-2018-10875', 'CVE-2018-1000807', 'CVE-2019-7548', 'CVE-2023-36830', 'CVE-2022-40023', 'CVE-2023-24816', 'CVE-2025-1550', 'CVE-2023-28858', 'CVE-2020-14330', 'CVE-2024-32152', 'CVE-2021-45452', 'CVE-2024-1727', 'CVE-2022-22817', 'CVE-2022-3102', 'CVE-2024-46455', 'CVE-2021-33503', 'CVE-2016-9964', 'CVE-2022-44900', 'CVE-2024-36039', 'CVE-2023-32681', 'CVE-2020-25659', 'CVE-2023-2780', 'CVE-2024-1729', 'CVE-2021-23437', 'CVE-2023-25658', 'CVE-2024-1728', 'CVE-2022-23833', 'CVE-2022-42966', 'CVE-2020-6802', 'CVE-2023-25578', 'CVE-2023-6976', 'CVE-2024-47874']
        # self.cve2advisory = {k:v for k,v in self.cve2advisory.items() if k in active_cves}
        # Load cached pairs
        # if not self.pairs_cache_file.exists():
        #     raise FileNotFoundError(f"Pairs cache file not found: {self.pairs_cache_file}")
        
        # with open(self.pairs_cache_file, 'rb') as f:
        #     _, self.all_pairs = pickle.load(f)
            # print(len(self.all_pairs))
            # for i in self.all_pairs:
            #     print(i)
        

        # print(len(set(cve_ids)&set(self.cve2advisory.keys())))
        
        
        # Load packages with Python files
        if not self.pkg_with_py_file_cache_file.exists():
            raise FileNotFoundError(f"Package cache file not found: {self.pkg_with_py_file_cache_file}")
        
        with open(self.pkg_with_py_file_cache_file, 'rb') as f:
            self.all_downstream_with_py_file, self.all_upstream_with_py_file = pickle.load(f)
        if not self.pairs_cache_file.exists() or True:
            self.regenerate_pairs_from_local_dependents()
        self.all_pairs = self._load_pairs_cache()
        print(len(self.all_pairs))
        # assert False

        # Load package URLs
        self.pkg2url = get_pkg2url()
    def regenerate_pairs_from_local_dependents(self,filter_downstream=False) -> None:
        """
        重新生成pairs，对于每个upstream读取本地保存的dependents
        
        Args:
            dependents_dir: 保存dependents数据的目录
        """
        logger.info("Regenerating pairs from local dependents data...")
        
        
        all_pairs = {}
        
        for idxx, (cve_id, advisory) in enumerate(self.cve2advisory.items()):
            # dependents_file = DEPENDENTS_DIR_DATE / f"{cve_id}.json"
            # if not dependents_file.exists():
            #     logger.warning(f"No dependents file found for CVE {cve_id}")
            #     continue
                
            # with open(dependents_file, 'r') as f:
                # dependents_data = json.load(f)
            cve_pairs = {}
            all_unique_affected_projects = get_all_unique_affected_projects(advisory)
            cve_pairs = {}
            
            for package_name, infos in advisory['available_affected'].items():
                fixing_commits = advisory['fixing_commits'].get(package_name, [])
                if len(fixing_commits) == 0:
                    continue
                # logger.info(f'{package_name}')
                # logger.info(f"{dependents_data.keys()}")
                
                for package_version in infos['versions']:

                    dependents_file = SNAPSHOT_DIR/ '@'.join([ package_name, package_version]) / 'dependents.json'
                    if not dependents_file.exists():
                        continue
                    with dependents_file.open('r') as f:
                        downstream_packages = json.load(f)
                    if filter_downstream:
                        downstream_packages = self._filter_packages_with_python_files(downstream_packages)
                        
                    if downstream_packages:
                        
                        cve_pairs[(package_name,package_version)] = downstream_packages
                            # logger.info(f"Found {len(downstream_packages)} dependents for {upstream}")
                
            if cve_pairs:
                all_pairs[cve_id] = cve_pairs
            if len(cve_pairs) == 0:
                logger.debug(f"CVE {cve_id} ({idxx}/{len(self.cve2advisory)}): {len(cve_pairs)} upstream packages with dependents")
            # if cve_id == 'CVE-2023-52323':
            #     assert False
        # 保存新的pairs到缓存文件
        self._save_pairs_cache(all_pairs)
        
        logger.info(f"Regenerated pairs for {len(all_pairs)} CVEs, {len(self.cve2advisory)}")
    def _filter_packages_with_python_files(self, packages: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
        """
        过滤掉没有Python文件的packages
        
        Args:
            packages: List of (package, version) tuples
            
        Returns:
            Filtered list of packages with Python files
        """
        filtered_packages = []
        
        for pkg, version in packages:
            # 检查是否在已知的有Python文件的packages中
            if (pkg, version) in self.analyzer.all_downstream_with_py_file:
                filtered_packages.append((pkg, version))
        
        return filtered_packages
    
    def _save_pairs_cache(self,all_pairs) -> None:
        """保存pairs到缓存文件"""

        
        with open(self.pairs_cache_file, 'wb') as f:
            pickle.dump(all_pairs, f)
        
        logger.info(f"Pairs cache saved to {self.pairs_cache_file}")
    def _load_pairs_cache(self) -> None:
        """保存pairs到缓存文件"""
        
        with open(self.pairs_cache_file, 'rb') as f:
            all_pairs = pickle.load(f)
        
        return all_pairs

class FunctionNormalizer:
    """Handles normalization of vulnerable function names."""
    
    # Common directory prefixes to remove
    PREFIXES = ('src.', 'lib.', 'python.', 'pysrc.', 'Lib.', 'pylib.', 
               'python3.', 'master.', 'lib3.')
    
    @classmethod
    def normalize_vulnerable_funcs(cls, cve_id: str, vulnerable_funcs: List[Tuple], 
                                 upstream: Tuple, workdir: Path, all_upstream_with_py_file:List) -> Tuple[List[Tuple], List[str]]:
        """
        Normalize vulnerable function names by removing common prefixes.
        
        Args:
            cve_id: CVE identifier
            vulnerable_funcs: List of (func_name, full_name) tuples
            upstream: (package, version) tuple
            workdir: Working directory path
        
        Returns:
            Tuple of (normalized_funcs, modules)
        """
        def remove_first_prefix(name: str) -> str:
            for prefix in cls.PREFIXES:
                if name.startswith(prefix):
                    return name[len(prefix):]
            return name
        vulnerable_funcs = [
            (full_name.split('.')[-1], remove_first_prefix(full_name))
            for full_name in vulnerable_funcs
        ]
        
        pkg, version = upstream
        
        # Find Python files in the package
        filtered_python_files = EnvAnalyzer.find_project_py_files(
            pkg, version, workdir=workdir
        )
        
        if not filtered_python_files:
            logger.warning(f"No Python files found for {upstream}")
        
        modules = get_modules_from_py_files(pkg, version, filtered_python_files)
        normalized_funcs = []
        
        # Match functions to modules
        for func, full_name in vulnerable_funcs:
            find_match = None
            func_ns = '.'.join(full_name.split('.')[:-1])
            # 1. 精确匹配：函数名以 module. 开头
            for module in modules:
                if full_name.startswith(f"{module}."):
                    find_match = module
                    break
            # 3. 宽松匹配：函数名包含 .module. or module.endswith(func_ns)
            if not find_match:
                for module in modules:
                    if f".{module}." in full_name or module.endswith(func_ns):
                        find_match = module
                        break
                
            if find_match:
                normalized_funcs.append((func, full_name))
        
        if len(normalized_funcs) < len(vulnerable_funcs):
            missed = len(vulnerable_funcs) - len(normalized_funcs)
            logger.info(f"Filtered out {missed} functions for {upstream}")
            logger.debug(f"modules: {modules}")

        
        if not normalized_funcs:
            logger.warning(f"No vulnerable functions found in {upstream}")
        logger.debug(f"normalized_funcs:{ normalized_funcs}")
        # logger.debug(f"modules:{ modules}")
        return normalized_funcs, modules
    
    @classmethod
    def create_vulnerable_package(cls, cve_id: str, package_name: str, upstream: Tuple,
                                vulnerable_funcs: List[Tuple], upstream_modules: List[str]) -> VulnerablePackage:
        """
        Create a VulnerablePackage instance from normalized data.
        
        Args:
            cve_id: CVE identifier
            package_name: Package name
            upstream: (package, version) tuple
            vulnerable_funcs: List of normalized vulnerable functions
            upstream_modules: List of upstream modules
            
        Returns:
            VulnerablePackage instance
        """
        # Extract just the function names (full names) from the tuples
        function_names = [full_name for _, full_name in vulnerable_funcs]
        
        return VulnerablePackage(
            cve_id=cve_id,
            package_name=upstream[0],  # Use upstream package name
            package_version=upstream[1],  # Use upstream package version
            vulnerable_functions=function_names,
            upstream_modules=upstream_modules
        )


class CallGraphAnalyzer:
    """Handles call graph analysis and reachability computation."""
    
    @staticmethod
    def import_analysis(call_graph: Dict, upstream_modules: List[str]) -> bool:
        """
        Check if upstream modules appear in the call graph.
        
        Args:
            call_graph: Call graph dictionary
            upstream_modules: List of upstream module names
        
        Returns:
            True if any upstream module is found in call graph
        """
        all_nodes = set(call_graph.keys())
        return len(all_nodes.intersection(upstream_modules)) > 0
    
    @staticmethod
    def normalize_call_graph(call_graph: Dict, prefix: str) -> Dict[str, List[str]]:
        """
        Normalize call graph by removing prefixes and filtering out standard library.
        
        Args:
            call_graph: Raw call graph
            prefix: Prefix to remove from function names
        
        Returns:
            Normalized call graph
        """
        def normalize_func_name(func_name: str) -> str:
            return func_name.removeprefix(prefix) if func_name.startswith(prefix) else func_name
        
        def is_system_module(module_name: str) -> bool:
            return (module_name in sys.builtin_module_names or 
                   module_name in STDLIB_MODULES)
        
        normalized_cg = defaultdict(set)
        
        for func, callees in call_graph.items():
            if is_system_module(func):
                continue
            
            normalized_func = normalize_func_name(func)
            normalized_callees = [
                normalize_func_name(callee) for callee in callees
                if not is_system_module(callee)
            ]
            normalized_cg[normalized_func].update(normalized_callees)
        
        return {k: list(v) for k, v in normalized_cg.items()}
    
    @staticmethod
    def analyze_reachability(call_graph: Dict, vulnerable_package: VulnerablePackage, 
                           downstream_modules: List[str], downstream: Tuple) -> Tuple:
        """
        Analyze reachability from vulnerable functions to downstream modules.
        
        Args:
            call_graph: Normalized call graph
            vulnerable_package: VulnerablePackage instance containing vulnerable functions
            downstream_modules: Downstream module names
            downstream: (package, version) tuple
        
        Returns:
            Tuple of (found_functions, call_chains, vulnerable_invocations)
        """
        all_nodes = set(call_graph.keys())
        
        # Handle top-level functions
        vulnerable_funcs_full_names = []
        top_level_func = {}
        
        for full_name in vulnerable_package.vulnerable_functions:
            if '.<main>' in full_name:
                module_name = full_name.removesuffix('.<main>')
                top_level_func[module_name] = full_name
                vulnerable_funcs_full_names.append(module_name)
            else:
                vulnerable_funcs_full_names.append(full_name)
        
        in_cg_funcs = all_nodes.intersection(vulnerable_funcs_full_names)
        
        if not in_cg_funcs:
            return [], [], []
        
        # Build reverse graph using NetworkX
        G = nx.DiGraph()
        for src, dsts in call_graph.items():
            for dst in dsts:
                G.add_edge(dst, src)
        
        # Find entry points in downstream modules
        entry_funcs = {
            node for node in all_nodes
            if any(node.startswith(module) for module in downstream_modules) and node in G.nodes()
        }
        
        vulnerable_invocations = []
        logger.info(f"Analyzing {len(in_cg_funcs)} functions for {downstream}")
        
        for func in in_cg_funcs:
            for entry_func in entry_funcs:
                if nx.has_path(G, source=func, target=entry_func):
                    vulnerable_invocations.append(entry_func)
        
        # Transform top-level functions back
        in_cg_funcs = [
            top_level_func.get(func, func) for func in in_cg_funcs
        ]
        
        return list(in_cg_funcs), [], list(vulnerable_invocations)


class ReachabilityChecker:
    """Main class for checking vulnerability reachability."""
    
    def __init__(self, analyzer: VulnerabilityAnalyzer):
        self.analyzer = analyzer
        self.normalizer = FunctionNormalizer()
        self.cg_analyzer = CallGraphAnalyzer()
    
    def _normalize_single_package_funcs(self, cve_id: str, package_name: str, repo_name: str, 
                                       upstream: Tuple, fixing_commits: List[str]) -> Optional[VulnerablePackage]:
        """
        Normalize vulnerable functions for a single package and return VulnerablePackage instance.
        
        Args:
            cve_id: CVE identifier
            package_name: Package name
            repo_name: Repository name
            upstream: (package, version) tuple
            fixing_commits: List of fixing commits
        
        Returns:
            VulnerablePackage instance or None if failed
        """
        # Load vulnerable functions for this package
        vulnerable_funcs = self._load_vulnerable_funcs_for_pkg(cve_id, repo_name, fixing_commits)
        
        if not vulnerable_funcs:
            logger.warning(f"No vulnerable functions found for {package_name}")
            return None
        
        # Normalize vulnerable functions
        normalized_vulnerable_funcs, upstream_modules = self.normalizer.normalize_vulnerable_funcs(
            cve_id, vulnerable_funcs, upstream, self.analyzer.workdir, 
            all_upstream_with_py_file=self.analyzer.all_upstream_with_py_file
        )
        
        if not normalized_vulnerable_funcs:
            logger.warning(f"Failed to normalize functions for {upstream}")
            # return None
        
        # Create VulnerablePackage instance
        vulnerable_package = self.normalizer.create_vulnerable_package(
            cve_id, package_name, upstream, normalized_vulnerable_funcs, upstream_modules
        )
        
        return vulnerable_package
    
    def _save_vulnerable_package(self, vulnerable_package: VulnerablePackage) -> None:
        """Save VulnerablePackage instance to disk."""
        save_file = (self.analyzer.vulnerable_packages_dir / 
                    f"{vulnerable_package.cve_id}_{vulnerable_package.package_name}@{vulnerable_package.package_version}.pkl")
        
        with open(save_file, 'wb') as f:
            pickle.dump(vulnerable_package, f)
    
    def _load_vulnerable_package(self, cve_id: str, package_name: str, package_version: str) -> Optional[VulnerablePackage]:
        """Load VulnerablePackage instance from disk."""
        save_file = (self.analyzer.vulnerable_packages_dir / 
                    f"{cve_id}_{package_name}@{package_version}.pkl")
        
        if not save_file.exists():
            return None
        
        try:
            with open(save_file, 'rb') as f:
                vulnerable_package = pickle.load(f)
            return vulnerable_package
        except:
            return None
    
    def preprocess_normalize_functions(self, rewrite: bool = False) -> None:
        """
        Stage 1: Parallel processing to normalize vulnerable functions for all packages.
        
        Args:
            rewrite: Whether to rewrite existing normalized functions
        """
        logger.info("Stage 1: Starting parallel normalization of vulnerable functions...")
        
        # Collect all tasks for normalization
        normalization_tasks = []
        for cve_id, advisory in self.analyzer.cve2advisory.items():
            # if cve_id not in ['CVE-2024-49767']:
            #     continue

            # all_unique_affected_projects = get_all_unique_affected_projects(advisory)
            # pairs = self.analyzer.all_pairs.get(cve_id)
            # logger.debug(f"pairs:{pairs}")
            
            # if not pairs:
            #     print(cve_id)
            #     continue
            # print(all_unique_affected_projects)
            for package_name, infos in advisory['available_affected'].items():
                fixing_commits = advisory['fixing_commits'].get(package_name, [])
                if len(fixing_commits) == 0:
                    logger.warning(f"No fixing commits for {package_name}")
                    continue
                repo_url = infos['repo_url']
                repo_name = get_repo_name(infos['repo_url'])
                for version in infos['versions']:
                    upstream = (package_name, version)
                    print(repo_url,upstream,package_name)

                    if upstream[0] != package_name:
                        continue
                    if upstream not in self.analyzer.all_upstream_with_py_file:
                        logger.info(f"upstream {upstream} without py_files")
                        continue
                    
                    # Check if already processed
                    existing_package = self._load_vulnerable_package(cve_id, upstream[0], upstream[1])
                    
                    if not rewrite and existing_package is not None:
                        continue
                    
                    normalization_tasks.append((cve_id, package_name, repo_name, upstream, fixing_commits))
        
        logger.info(f"Found {len(normalization_tasks)} normalization tasks")
        if not normalization_tasks:
            logger.info("No normalization tasks to process")
            return
        
        # Process normalization tasks in parallel
        def process_normalization_task(task):
            cve_id, package_name, repo_name, upstream, fixing_commits = task
            vulnerable_package = self._normalize_single_package_funcs(cve_id, package_name, repo_name, upstream, fixing_commits)
            if vulnerable_package is not None:
                self._save_vulnerable_package(vulnerable_package)
                return f"Success: {cve_id}_{package_name}_{upstream}"
            else:
                return f"Failed: {cve_id}_{package_name}_{upstream}"

        # Execute parallel processing
        results = Parallel(n_jobs=MAX_PARALLEL_JOBS, backend='threading')(
            delayed(process_normalization_task)(task) 
            for task in tqdm(normalization_tasks, desc="Normalizing vulnerable functions")
        )
        
        # Summary statistics
        success_count = sum(1 for result in results if result.startswith("Success"))
        failed_count = sum(1 for result in results if result.startswith("Failed"))
        error_count = sum(1 for result in results if result.startswith("Error"))
        
        logger.info(f"Normalization complete: {success_count} success, {failed_count} failed, {error_count} errors")

    def check_single_package(self, cve_id: str, upstream: Tuple, downstream: Tuple,
                           vulnerable_package: VulnerablePackage,
                           rewrite: bool = False) -> Tuple[Tuple, str]:
        """
        Check reachability for a single downstream package.
        
        Args:
            cve_id: CVE identifier
            upstream: (package, version) tuple
            downstream: (package, version) tuple
            vulnerable_package: VulnerablePackage instance
            rewrite: Whether to rewrite existing results
        
        Returns:
            Tuple of (downstream, result_status)
        """
        package, version = downstream
        result_file = CG_DIR_DATE /f'{cve_id}/{"@".join(downstream)}_results.json'
        
        if not rewrite and result_file.exists():
            return downstream, "VF Found"
        
        # Load call graph
        jarvis_output_file = Path(CALL_GRAPH_DIR / package / version / 'jarvis_cg.json')
        jarvis_error_file = Path(CALL_GRAPH_DIR / package / version / 'ERROR')
        
        if not jarvis_output_file.exists():
            if sys.platform == 'darwin':
                # Try alternative location
                alt_path = CALL_GRAPH_DIR.parent / 'call_graphs' / package / version / 'jarvis_cg.json'
                if not alt_path.exists():
                    return downstream, "Jarvis Failed"
                jarvis_output_file = alt_path
            else:
                return downstream, "Jarvis Failed" if jarvis_error_file.exists() else "Not Jarvis"
        
        # Load and parse call graph
        try:
            with open(jarvis_output_file, 'r') as f:
                call_graph = json.load(f)
        except (json.JSONDecodeError, IOError):
            return downstream, "JSON Failed"
        
        # Import-level filtering
        if not self.cg_analyzer.import_analysis(call_graph, vulnerable_package.upstream_modules):
            return downstream, "Import Failed"
        
        # Normalize call graph
        prefix = f"...docker_workdir.pypi_packages.{package}.{version}."
        normalized_cg = self.cg_analyzer.normalize_call_graph(call_graph, prefix)
        
        # Get downstream modules
        filtered_python_files = EnvAnalyzer.find_project_py_files(
            package, version, workdir='../docker_workdir'
        )
        downstream_modules = get_modules_from_py_files(package, version, filtered_python_files)
        
        # Analyze reachability
        try:
            in_cg_vfs, call_chains, vulnerable_invocations = self.cg_analyzer.analyze_reachability(
                normalized_cg, vulnerable_package, downstream_modules, downstream
            )
        except Exception as e:
            logger.error(f"Reachability analysis failed for {downstream}: {e}")
            return downstream, "Analysis Failed"
        
        if not in_cg_vfs:
            return downstream, "VF Not Found"
        
        logger.info(f"Found vulnerable functions in {downstream}: {in_cg_vfs}")
        
        # Save results
        result_data = {
            'cve_id': cve_id,
            'upstream_package': upstream[0],
            'upstream_version': upstream[1],
            'downstream_package': package,
            'downstream_version': version,
            'vulnerable_functions': vulnerable_package.vulnerable_functions,
            'found_functions': list(in_cg_vfs),
            'call_chains': call_chains,
            'vulnerable_invocation': list(vulnerable_invocations)
        }
        
        result_file.parent.mkdir(parents=True, exist_ok=True)
        with open(result_file, 'w') as f:
            json.dump(result_data, f, indent=2)
        
        return downstream, "VF Found"
    
    def _load_vulnerable_funcs_for_pkg(self,cve_id, repo_name,fixing_commits):
        code_changes_path = CODE_CHANGES_DIR_DATE / f'{cve_id}_{repo_name}.json'
        code_changes_dict_path = CODE_CHANGES_DIR_DATE / f'{cve_id}_{repo_name}_dict.pkl'
        # logger.info(f'Code changes for {cve_id}_{repo_name} already exists, skipping...')
        with code_changes_path.open('r') as f:
            commit2methods = json.load(f)
        with code_changes_dict_path.open('rb') as f:
            commit2methods_dict = pickle.load(f)
        vulnerable_funcs = set()
        for fixing_commit in fixing_commits:
            for file, methods in commit2methods[fixing_commit].items():
                vulnerable_funcs.update(methods)
        
        if len(vulnerable_funcs) == 0:
            if cve_id not in ['CVE-2015-3206']:
                assert False, f"{cve_id}, {commit2methods}"
        return vulnerable_funcs
    
    def process_downstream_reachability(self, rewrite_cg_results: bool = False) -> None:
        """
        Stage 2: Process downstream reachability using pre-normalized VulnerablePackage instances.
        
        Args:
            rewrite_cg_results: Whether to rewrite call graph results
        """
        logger.info("Stage 2: Starting downstream reachability analysis...")
        
        all_results = {}

        for idx, (cve_id, advisory) in enumerate(self.analyzer.cve2advisory.items()):
            logger.info(f"Processing CVE {cve_id} ({idx + 1}/{len(self.analyzer.cve2advisory)})")
            all_unique_affected_projects = get_all_unique_affected_projects(advisory)
            logger.debug(f"Found {len(all_unique_affected_projects)} unique affected projects: {all_unique_affected_projects}")
            
            cve_results = defaultdict(dict)
            pairs = self.analyzer.all_pairs.get(cve_id)
            if not pairs:
                continue
            
            for package_name, repo_url in all_unique_affected_projects:
                fixing_commits = advisory['fixing_commits'].get(package_name, [])
                if len(fixing_commits) == 0:
                    continue
                
                for upstream_idx, (upstream, all_downstream) in enumerate(pairs.items()):
                    if not all_downstream:
                        continue
                    
                    logger.info(f"Processing upstream {upstream} with {len(all_downstream)} downstream packages")
                    
                    # Load pre-normalized VulnerablePackage
                    vulnerable_package = self._load_vulnerable_package(cve_id, upstream[0], upstream[1])
                    if vulnerable_package is None:
                        logger.warning(f"No VulnerablePackage found for {cve_id}_{upstream[0]}@{upstream[1]}")
                        cve_results[f"{upstream[0]}@{upstream[1]}"] = "VF Not Found"
                        continue
                    
                    # Process downstream packages in parallel
                    results = Parallel(n_jobs=MAX_PARALLEL_JOBS, backend='threading', verbose=0)(
                        delayed(self.check_single_package)(
                            cve_id, upstream, downstream, vulnerable_package, rewrite_cg_results
                        )
                        for downstream in tqdm(all_downstream, 
                                            desc=f"Processing upstream {upstream} ({upstream_idx + 1}/{len(pairs)})")
                    )
                    
                    upstream_results = {f"{downstream[0]}@{downstream[1]}": result 
                                    for downstream, result in results}
                    cve_results[f"{upstream[0]}@{upstream[1]}"] = upstream_results
            
            all_results[cve_id] = cve_results
            
            # Save CVE results
            cve_results_file = REACHABILITY_DIR_DATE / f'{cve_id}_results.json'
            cve_results_file.parent.mkdir(parents=True, exist_ok=True)
            with open(cve_results_file, 'w') as f:
                json.dump(cve_results, f, indent=2)
        
        # Save overall results
        os.makedirs(os.path.dirname(self.analyzer.results_file), exist_ok=True)
        with open(self.analyzer.results_file, 'w') as f:
            json.dump(all_results, f, indent=2)

    def check_reachability(self, rewrite_cve_results: bool = False, 
                          rewrite_cg_results: bool = False,
                          rewrite_normalization: bool = False) -> None:
        """
        Main method to check reachability for all CVEs with two-stage processing.
        
        Args:
            rewrite_cve_results: Whether to rewrite CVE-level results
            rewrite_cg_results: Whether to rewrite call graph results
            rewrite_normalization: Whether to rewrite function normalization
        """
        # Stage 1: Parallel normalization of vulnerable functions
        self.preprocess_normalize_functions(rewrite=rewrite_normalization)
        
        # Stage 2: Process downstream reachability
        self.process_downstream_reachability(rewrite_cg_results=rewrite_cg_results)

    def get_vulnerable_packages_summary(self) -> Dict[str, Any]:
        """
        Get summary statistics of all VulnerablePackage instances.
        
        Returns:
            Dictionary containing summary statistics
        """
        vulnerable_packages = []
        
        # Load all VulnerablePackage instances
        for pkl_file in self.analyzer.vulnerable_packages_dir.glob("*.pkl"):
            try:
                with open(pkl_file, 'rb') as f:
                    vulnerable_package = pickle.load(f)
                    vulnerable_packages.append(vulnerable_package)
            except:
                logger.warning(f"Failed to load {pkl_file}")
                continue
        
        if not vulnerable_packages:
            return {"total_packages": 0}
        
        # Calculate statistics
        cve_counts = defaultdict(int)
        package_counts = defaultdict(int)
        function_counts = []
        module_counts = []
        
        for vp in vulnerable_packages:
            cve_counts[vp.cve_id] += 1
            package_counts[f"{vp.package_name}@{vp.package_version}"] += 1
            function_counts.append(len(vp.vulnerable_functions))
            module_counts.append(len(vp.upstream_modules))
        
        summary = {
            "total_packages": len(vulnerable_packages),
            "unique_cves": len(cve_counts),
            "unique_package_versions": len(package_counts),
            "function_stats": {
                "total_functions": sum(function_counts),
                "avg_functions_per_package": np.mean(function_counts) if function_counts else 0,
                "max_functions_per_package": max(function_counts) if function_counts else 0,
                "min_functions_per_package": min(function_counts) if function_counts else 0
            },
            "module_stats": {
                "total_modules": sum(module_counts),
                "avg_modules_per_package": np.mean(module_counts) if module_counts else 0,
                "max_modules_per_package": max(module_counts) if module_counts else 0,
                "min_modules_per_package": min(module_counts) if module_counts else 0
            },
            "top_cves_by_package_count": dict(sorted(cve_counts.items(), key=lambda x: x[1], reverse=True)[:10])
        }
        
        return summary

    def analyze_normalization_coverage(self, output_file: Optional[str] = None) -> Dict[str, Any]:
        """
        分析normalization覆盖率，找出哪些package没有normalized functions。
        
        Args:
            output_file: 可选的输出文件路径，用于保存详细结果
        
        Returns:
            Dict containing analysis results
        """
        logger.info("Starting normalization coverage analysis...")
        
        # 收集所有应该被处理的packages
        all_expected_packages = []
        all_upstream = set()
        packages_with_normalized_funcs = []
        packages_without_normalized_funcs = []
        
        for cve_id, advisory in self.analyzer.cve2advisory.items():
            all_unique_affected_projects = get_all_unique_affected_projects(advisory)
            pairs = self.analyzer.all_pairs.get(cve_id)
            # if cve_id not in ['CVE-2024-49767']:
            #     continue
            if not pairs:
                continue
            
            for package_name, repo_url in all_unique_affected_projects:
                fixing_commits = advisory['fixing_commits'].get(package_name, [])
                if len(fixing_commits) == 0:
                    logger.warning(f"No fixing commits for {package_name}")
                    continue
                
                repo_name = get_repo_name(repo_url)
                
                for upstream, all_downstream in pairs.items():
                    if upstream[0] != package_name:
                        continue
                    if not all_downstream:
                        continue
                    if upstream not in self.analyzer.all_upstream_with_py_file:
                        continue
                    all_upstream.add(upstream)
                    package_info = {
                        'cve_id': cve_id,
                        'package_name': package_name,
                        'repo_name': repo_name,
                        'upstream': upstream,
                        'fixing_commits': fixing_commits,
                        'downstream_count': len(all_downstream)
                    }
                    
                    all_expected_packages.append(package_info)
                    
                    # 检查是否存在VulnerablePackage实例
                    vulnerable_package = self._load_vulnerable_package(cve_id, upstream[0], upstream[1])
                    
                    if vulnerable_package is not None:
                        package_info.update({
                            'has_normalized_funcs': True,
                            'normalized_funcs': vulnerable_package.vulnerable_functions,
                            'upstream_modules': vulnerable_package.upstream_modules,
                            'normalized_func_count': len(vulnerable_package.vulnerable_functions),
                            'upstream_module_count': len(vulnerable_package.upstream_modules)
                        })
                        packages_with_normalized_funcs.append(package_info)
                    else:
                        raw_vulnerable_funcs = self._load_vulnerable_funcs_for_pkg(
                            cve_id, repo_name, fixing_commits
                        )
                        
                        # 获取package的modules
                        pkg, version = upstream
                        filtered_python_files = EnvAnalyzer.find_project_py_files(
                            pkg, version, workdir=self.analyzer.workdir
                        )
                        modules = get_modules_from_py_files(pkg, version, filtered_python_files)
                        print(pkg, version, upstream,package_info['package_name'])
                        print(f"package : {pkg}, version: {version}, upstream:{upstream}, package_info['package_name']:{package_info['package_name']}")
                        # print(modules)
                        
                            
                        package_info.update({
                            'has_normalized_funcs': False,
                            'raw_vulnerable_funcs': list(raw_vulnerable_funcs) if raw_vulnerable_funcs else [],
                            'package_modules': modules,
                            'raw_func_count': len(raw_vulnerable_funcs) if raw_vulnerable_funcs else 0,
                            'package_module_count': len(modules),
                            'failure_reason': 'No VulnerablePackage instance found'
                        })
                        packages_without_normalized_funcs.append(package_info)
        # 统计分析
        total_packages = len(all_expected_packages)
        successful_packages = len(packages_with_normalized_funcs)
        failed_packages = len(packages_without_normalized_funcs)
        
        success_rate = (successful_packages / total_packages * 100) if total_packages > 0 else 0
        
        # 按失败原因分组
        failure_reasons = defaultdict(int)
        cve_failure_stats = defaultdict(lambda: {'total': 0, 'failed': 0})
        
        for pkg in packages_without_normalized_funcs:
            failure_reasons[pkg.get('failure_reason', 'Unknown')] += 1
            cve_failure_stats[pkg['cve_id']]['failed'] += 1
        for pkg in all_expected_packages:
            cve_failure_stats[pkg['cve_id']]['total'] += 1
        
        # 创建统计报告
        analysis_result = {
            'summary': {
                'all_upstream':len(all_upstream),
                'total_expected_packages': total_packages,
                'packages_with_normalized_funcs': successful_packages,
                'packages_without_normalized_funcs': failed_packages,
                'success_rate_percent': round(success_rate, 2)
            },
            'failure_analysis': {
                'failure_reasons': dict(failure_reasons),
                'cve_failure_stats': {
                    cve_id: {
                        'total': stats['total'],
                        'failed': stats['failed'],
                        'success_rate': round((stats['total'] - stats['failed']) / stats['total'] * 100, 2)
                    }
                    for cve_id, stats in cve_failure_stats.items()
                }
            },
            'detailed_failures': packages_without_normalized_funcs,
            'successful_packages': packages_with_normalized_funcs
        }
        # print(packages_without_normalized_funcs)
        # 保存详细结果到文件
        if output_file:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump(analysis_result, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Detailed analysis results saved to {output_file}")
        
        # 打印概要统计
        self._print_normalization_summary(analysis_result)
        
        return analysis_result
    
    def _print_normalization_summary(self, analysis_result: Dict[str, Any]) -> None:
        """打印normalization分析的概要信息"""
        summary = analysis_result['summary']
        failure_analysis = analysis_result['failure_analysis']
        
        print("\n" + "="*70)
        print("NORMALIZATION COVERAGE ANALYSIS")
        print("="*70)
        
        print(f"📊 OVERVIEW:")
        print(f"  all_upstream: {summary['all_upstream']}")
        print(f"  Total Expected Packages: {summary['total_expected_packages']:,}")
        print(f"  ✅ Successfully Normalized: {summary['packages_with_normalized_funcs']:,}")
        print(f"  ❌ Failed to Normalize: {summary['packages_without_normalized_funcs']:,}")
        print(f"  📈 Success Rate: {summary['success_rate_percent']:.2f}%")
        
        print(f"\n🔍 FAILURE REASONS:")
        for reason, count in failure_analysis['failure_reasons'].items():
            percentage = count / summary['total_expected_packages'] * 100
            print(f"  • {reason}: {count:,} ({percentage:.2f}%)")
        
        print(f"\n📋 TOP CVEs BY FAILURE COUNT:")
        cve_failures = [(cve_id, stats['failed']) for cve_id, stats in 
                        failure_analysis['cve_failure_stats'].items()]
        cve_failures.sort(key=lambda x: x[1], reverse=True)
        
        for cve_id, failed_count in cve_failures[:10]:
            stats = failure_analysis['cve_failure_stats'][cve_id]
            print(f"  • {cve_id}: {failed_count}/{stats['total']} failed "
                    f"({100-stats['success_rate']:.1f}% failure rate)")
        
        # 显示一些失败的详细例子
        failed_packages = analysis_result['detailed_failures']
        if failed_packages:
            print(f"\n❌ EXAMPLE FAILED PACKAGES:")
            for i, pkg in enumerate(failed_packages[:5]):
                print(f"  {i+1}. {pkg['cve_id']} - {pkg['package_name']} ({pkg['upstream'][0]}@{pkg['upstream'][1]})")
                print(f"     Raw Functions: {pkg['raw_func_count']}, Modules: {pkg['package_module_count']}")
                print(f"     Reason: {pkg['failure_reason']}")
                if pkg['raw_vulnerable_funcs']:
                    funcs_preview = pkg['raw_vulnerable_funcs'][:3]
                    more_text = f" (and {len(pkg['raw_vulnerable_funcs'])-3} more)" if len(pkg['raw_vulnerable_funcs']) > 3 else ""
                    print(f"     Raw Functions: {funcs_preview}{more_text}")
                print()

    def export_normalization_analysis(self, output_dir: str = "./normalization_analysis") -> None:
        """
        导出详细的normalization分析结果到多个文件
        
        Args:
            output_dir: 输出目录
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # 完整分析
        analysis_result = self.analyze_normalization_coverage()
        
        # 保存完整结果
        with open(output_path / "full_analysis.json", 'w') as f:
            json.dump(analysis_result, f, indent=2, ensure_ascii=False)
        
        # 保存失败的packages
        with open(output_path / "failed_packages.json", 'w') as f:
            json.dump(analysis_result['detailed_failures'], f, indent=2, ensure_ascii=False)
        
        # 保存成功的packages
        with open(output_path / "successful_packages.json", 'w') as f:
            json.dump(analysis_result['successful_packages'], f, indent=2, ensure_ascii=False)
        
        # 生成CSV报告
        try:
            import pandas as pd
            
            # 失败packages的CSV
            if analysis_result['detailed_failures']:
                failed_df = pd.DataFrame(analysis_result['detailed_failures'])
                failed_df.to_csv(output_path / "failed_packages.csv", index=False)
            
            # CVE统计的CSV
            cve_stats = []
            for cve_id, stats in analysis_result['failure_analysis']['cve_failure_stats'].items():
                cve_stats.append({
                    'cve_id': cve_id,
                    'total_packages': stats['total'],
                    'failed_packages': stats['failed'],
                    'success_rate': stats['success_rate']
                })
            
            cve_df = pd.DataFrame(cve_stats)
            cve_df.to_csv(output_path / "cve_statistics.csv", index=False)
            
            logger.info(f"CSV files generated successfully")
            
        except ImportError:
            logger.warning("pandas not available, skipping CSV generation")
        
        logger.info(f"Normalization analysis exported to {output_dir}")

    def export_vulnerable_packages_to_json(self, output_file: str) -> None:
        """
        Export all VulnerablePackage instances to a JSON file.
        
        Args:
            output_file: Path to output JSON file
        """
        vulnerable_packages_data = []
        
        # Load all VulnerablePackage instances
        for pkl_file in self.analyzer.vulnerable_packages_dir.glob("*.pkl"):
            try:
                with open(pkl_file, 'rb') as f:
                    vulnerable_package = pickle.load(f)
                    vulnerable_packages_data.append(vulnerable_package.to_dict())
            except:
                logger.warning(f"Failed to load {pkl_file}")
                continue
        
        # Sort by CVE ID and package name
        vulnerable_packages_data.sort(key=lambda x: (x['cve_id'], x['package_name'], x['package_version']))
        
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w') as f:
            json.dump(vulnerable_packages_data, f, indent=2)
        
        logger.info(f"Exported {len(vulnerable_packages_data)} vulnerable packages to {output_file}")

class StatisticsCalculator:
    """Calculates and displays analysis statistics with detailed reachability metrics."""
    
    def __init__(self):
        self.results_cache = {}
        
    def analyze_cve_downstream_impact(self, all_results: Dict) -> Dict[str, Any]:
        """统计CVE影响downstream包的情况，保留详细信息用于排序分析"""
        
        # 收集原始数据
        all_upstream_downstream_pairs = []  # (cve_id, upstream, downstream, status)
        all_cve_downstream_pairs = []       # (cve_id, downstream, has_reachable)
        
        for cve_id, cve_results in all_results.items():
            # 收集CVE级别的downstream影响
            cve_downstream_impact = {}  # downstream -> has_reachable
            
            for upstream, downstream_results in cve_results.items():
                if isinstance(downstream_results, str):
                    continue
                    
                for downstream, status in downstream_results.items():
                    # 记录upstream-downstream pair
                    all_upstream_downstream_pairs.append((cve_id, upstream, downstream, status))
                    
                    # 更新CVE-downstream影响状态
                    if downstream not in cve_downstream_impact:
                        cve_downstream_impact[downstream] = False
                    if status == 'VF Found':
                        cve_downstream_impact[downstream] = True
            
            # 记录CVE-downstream pairs
            for downstream, has_reachable in cve_downstream_impact.items():
                all_cve_downstream_pairs.append((cve_id, downstream, has_reachable))
        
        # 统计分析
        reachable_upstream_downstream = [(cve, up, down) for cve, up, down, status in all_upstream_downstream_pairs if status == 'VF Found']
        reachable_cve_downstream = [(cve, down) for cve, down, reachable in all_cve_downstream_pairs if reachable]
        
        # CVE影响力排序
        cve_impact_ranking = self._rank_cve_impact(all_upstream_downstream_pairs, all_cve_downstream_pairs)
        upstream_impact_ranking = self._rank_upstream_impact(all_upstream_downstream_pairs)
        
        return {
            'raw_data': {
                'all_upstream_downstream_pairs': all_upstream_downstream_pairs,
                'all_cve_downstream_pairs': all_cve_downstream_pairs,
                'reachable_upstream_downstream_pairs': reachable_upstream_downstream,
                'reachable_cve_downstream_pairs': reachable_cve_downstream
            },
            'summary_stats': {
                'total_cves': len(all_results),
                'total_upstream_downstream_pairs': len(all_upstream_downstream_pairs),
                'total_cve_downstream_pairs': len(all_cve_downstream_pairs),
                'reachable_upstream_downstream_pairs': len(reachable_upstream_downstream),
                'reachable_cve_downstream_pairs': len(reachable_cve_downstream),
                'impacting_cves': len(set(cve for cve, _, _ in reachable_upstream_downstream))
            },
            'impact_rankings': {
                'cve_impact_ranking': cve_impact_ranking,
                'upstream_impact_ranking': upstream_impact_ranking
            }
        }
    
    def _rank_cve_impact(self, upstream_downstream_pairs: List, cve_downstream_pairs: List) -> Dict:
        """分析CVE影响力排序"""
        cve_stats = defaultdict(lambda: {'total_upstream_downstream': 0, 'reachable_upstream_downstream': 0, 
                                        'total_cve_downstream': 0, 'reachable_cve_downstream': 0})
        
        # 统计upstream-downstream级别
        for cve_id, upstream, downstream, status in upstream_downstream_pairs:
            cve_stats[cve_id]['total_upstream_downstream'] += 1
            if status == 'VF Found':
                cve_stats[cve_id]['reachable_upstream_downstream'] += 1
        
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
                'upstream_downstream_impact_rate': stats['reachable_upstream_downstream'] / stats['total_upstream_downstream'] if stats['total_upstream_downstream'] > 0 else 0,
                'cve_downstream_impact_rate': stats['reachable_cve_downstream'] / stats['total_cve_downstream'] if stats['total_cve_downstream'] > 0 else 0
            })
        
        return {
            'by_reachable_upstream_downstream': sorted(cve_ranking, key=lambda x: x['reachable_upstream_downstream'], reverse=True),
            'by_reachable_cve_downstream': sorted(cve_ranking, key=lambda x: x['reachable_cve_downstream'], reverse=True),
            'by_upstream_downstream_rate': sorted(cve_ranking, key=lambda x: x['upstream_downstream_impact_rate'], reverse=True),
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
                tp_stats['cve_tp_breakdown'][cve_id] = {
                    'total': cve_total,
                    'true_positives': cve_tp,
                    'tp_rate': cve_tp / cve_total
                }
        
        if tp_stats['total_pairs'] > 0:
            tp_stats['true_positive_rate'] = tp_stats['true_positives'] / tp_stats['total_pairs']
        
        return tp_stats
    
    def analyze_reachable_pairs_details(self, all_results: Dict, cg_dir: Path) -> Dict[str, Any]:
        """
        专门分析reachable的pair，统计call chain信息
        
        Args:
            all_results: 分析结果
            cg_dir: call graph结果目录
            
        Returns:
            Dict containing detailed reachable pairs analysis
        """
        reachable_analysis = {
            'total_reachable_pairs': 0,
            'pairs_with_call_chains': 0,
            'call_chain_stats': {
                'total_chains': 0,
                'chain_lengths': [],
                'avg_chain_length': 0.0,
                'max_chain_length': 0,
                'min_chain_length': float('inf')
            },
            'vulnerable_invocation_stats': {
                'total_invocations': 0,
                'invocation_counts': [],
                'avg_invocations_per_pair': 0.0,
                'max_invocations': 0,
                'pairs_with_invocations': 0
            },
            'detailed_pairs': [],
            'function_reachability_stats': {
                'total_found_functions': 0,
                'function_counts_per_pair': [],
                'avg_functions_per_pair': 0.0
            }
        }
        
        for cve_id, cve_results in all_results.items():
            for upstream, downstream_results in cve_results.items():
                if isinstance(downstream_results, str):
                    continue
                    
                for downstream, status in downstream_results.items():
                    if status != 'VF Found':
                        continue
                    
                    reachable_analysis['total_reachable_pairs'] += 1
                    
                    # 加载详细结果文件
                    result_file = cg_dir / f'{cve_id}/{downstream}_results.json'
                    if not result_file.exists():
                        continue
                    
                    try:
                        with open(result_file, 'r') as f:
                            detailed_result = json.load(f)
                        
                        # 分析call chains
                        call_chains = detailed_result.get('call_chains', [])
                        vulnerable_invocations = detailed_result.get('vulnerable_invocation', [])
                        found_functions = detailed_result.get('found_functions', [])
                        
                        pair_info = {
                            'cve_id': cve_id,
                            'upstream': upstream,
                            'downstream': downstream,
                            'call_chain_count': len(call_chains),
                            'vulnerable_invocation_count': len(vulnerable_invocations),
                            'found_function_count': len(found_functions),
                            'call_chains': call_chains,
                            'vulnerable_invocations': vulnerable_invocations,
                            'found_functions': found_functions
                        }
                        
                        # 统计call chain长度
                        if call_chains:
                            reachable_analysis['pairs_with_call_chains'] += 1
                            reachable_analysis['call_chain_stats']['total_chains'] += len(call_chains)
                            
                            for chain in call_chains:
                                chain_length = len(chain)
                                reachable_analysis['call_chain_stats']['chain_lengths'].append(chain_length)
                                reachable_analysis['call_chain_stats']['max_chain_length'] = max(
                                    reachable_analysis['call_chain_stats']['max_chain_length'], chain_length
                                )
                                reachable_analysis['call_chain_stats']['min_chain_length'] = min(
                                    reachable_analysis['call_chain_stats']['min_chain_length'], chain_length
                                )
                        
                        # 统计vulnerable invocations
                        if vulnerable_invocations:
                            reachable_analysis['vulnerable_invocation_stats']['pairs_with_invocations'] += 1
                            reachable_analysis['vulnerable_invocation_stats']['total_invocations'] += len(vulnerable_invocations)
                            reachable_analysis['vulnerable_invocation_stats']['invocation_counts'].append(len(vulnerable_invocations))
                            reachable_analysis['vulnerable_invocation_stats']['max_invocations'] = max(
                                reachable_analysis['vulnerable_invocation_stats']['max_invocations'], 
                                len(vulnerable_invocations)
                            )
                        
                        # 统计found functions
                        if found_functions:
                            reachable_analysis['function_reachability_stats']['total_found_functions'] += len(found_functions)
                            reachable_analysis['function_reachability_stats']['function_counts_per_pair'].append(len(found_functions))
                        
                        reachable_analysis['detailed_pairs'].append(pair_info)
                        
                    except Exception as e:
                        logger.warning(f"Failed to load detailed results for {cve_id}/{downstream}: {e}")
                        continue
        
        # 计算平均值和统计数据
        chain_lengths = reachable_analysis['call_chain_stats']['chain_lengths']
        if chain_lengths:
            reachable_analysis['call_chain_stats']['avg_chain_length'] = np.mean(chain_lengths)
            reachable_analysis['call_chain_stats']['chain_length_percentiles'] = {
                '25th': np.percentile(chain_lengths, 25),
                '50th': np.percentile(chain_lengths, 50),
                '75th': np.percentile(chain_lengths, 75),
                '90th': np.percentile(chain_lengths, 90)
            }
        else:
            reachable_analysis['call_chain_stats']['min_chain_length'] = 0
        
        invocation_counts = reachable_analysis['vulnerable_invocation_stats']['invocation_counts']
        if invocation_counts:
            reachable_analysis['vulnerable_invocation_stats']['avg_invocations_per_pair'] = np.mean(invocation_counts)
            reachable_analysis['vulnerable_invocation_stats']['invocation_percentiles'] = {
                '25th': np.percentile(invocation_counts, 25),
                '50th': np.percentile(invocation_counts, 50),
                '75th': np.percentile(invocation_counts, 75),
                '90th': np.percentile(invocation_counts, 90)
            }
        
        function_counts = reachable_analysis['function_reachability_stats']['function_counts_per_pair']
        if function_counts:
            reachable_analysis['function_reachability_stats']['avg_functions_per_pair'] = np.mean(function_counts)
        
        return reachable_analysis
    
    def generate_comprehensive_report(self, all_results: Dict, cg_dir: Path, 
                                    output_file: Optional[str] = None) -> Dict[str, Any]:
        """
        生成综合分析报告
        
        Args:
            all_results: 分析结果
            cg_dir: call graph结果目录
            output_file: 可选的输出文件路径
            
        Returns:
            Complete analysis report
        """
        report = {
            'cve_impact_analysis': self.analyze_cve_downstream_impact(all_results),
            'true_positive_analysis': self.calculate_true_positives(all_results),
            'reachable_pairs_analysis': self.analyze_reachable_pairs_details(all_results, cg_dir),
            'generation_timestamp': datetime.now().isoformat()
        }
        
        # 打印概要统计
        self._print_comprehensive_summary(report)
        
        # 保存到文件
        if output_file:
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


def main():
    """Main function to run the vulnerability analysis pipeline."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Vulnerability Reachability Analysis Pipeline')
    parser.add_argument('--size', type=str, choices=['small', 'medium', 'large'], 
                       default='large', help='Dataset size')
    parser.add_argument('--rewrite-cve', action='store_true', 
                       help='Rewrite CVE-level results')
    parser.add_argument('--rewrite-cg', action='store_true', 
                       help='Rewrite call graph results')
    parser.add_argument('--rewrite-normalization', action='store_true',
                       help='Rewrite function normalization results')
    parser.add_argument('--show-viz', action='store_true', 
                       help='Show visualizations')
    parser.add_argument('--stage', type=str, choices=['normalize', 'downstream', 'both', 'summary', 'coverage'], 
                       default='both', help='Which stage to run')
    parser.add_argument('--export-json', type=str, 
                       help='Export vulnerable packages to JSON file')
    parser.add_argument('--coverage-output', type=str,
                       help='Output file for normalization coverage analysis')
    parser.add_argument('--export-coverage', type=str,
                       help='Export normalization coverage analysis to directory')
    
    args = parser.parse_args()
    
    workdir = Path('../docker_workdir')
    
    # Initialize analyzer
    analyzer = VulnerabilityAnalyzer(workdir, args.size)
    checker = ReachabilityChecker(analyzer)
    calculator = StatisticsCalculator()
    
    # Run analysis based on stage selection
    if args.stage in ['normalize', 'both']:
        logger.info("Running function normalization stage...")
        checker.preprocess_normalize_functions(rewrite=args.rewrite_normalization)
    
    if args.stage in ['downstream', 'both']:
        logger.info("Running downstream reachability analysis stage...")
        checker.process_downstream_reachability(rewrite_cg_results=args.rewrite_cg)
    
    if args.stage == 'summary':
        logger.info("Generating vulnerable packages summary...")
        summary = checker.get_vulnerable_packages_summary()
        print("\n=== VULNERABLE PACKAGES SUMMARY ===")
        print(json.dumps(summary, indent=2))
    
    if args.stage == 'coverage':
        logger.info("Analyzing normalization coverage...")
        checker.analyze_normalization_coverage(output_file=args.coverage_output)
    
    # Export coverage analysis if requested
    if args.export_coverage:
        logger.info(f"Exporting coverage analysis to {args.export_coverage}...")
        checker.export_normalization_analysis(output_dir=args.export_coverage)
    
    # Export to JSON if requested
    if args.export_json:
        logger.info(f"Exporting vulnerable packages to {args.export_json}...")
        checker.export_vulnerable_packages_to_json(args.export_json)
    
    logger.info("Analysis complete!")


if __name__ == '__main__':
    
    main()