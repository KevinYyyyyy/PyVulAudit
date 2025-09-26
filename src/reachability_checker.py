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
from itertools import chain

import networkx as nx
from tqdm import tqdm
from joblib import Parallel, delayed
import numpy as np

# Add the data_collection directory to the path to import modules
PROJECT_ROOT = Path(__file__).parent.parent.absolute()
sys.path.append(str(PROJECT_ROOT))

from data_collection.logger import logger
from src.constant import (
    CALL_GRAPH_DIR, DATA_DIR, REACHABILITY_DIR_DATE, CALL_GRAPH_DIR_DATE,
    CODE_CHANGES_DIR_DATE, REACHABILITY_RESULT_DIR_DATE, VUL_PACKAGES_DIR_DATE,
    SUFFIX, SNAPSHOT_DIR, CG_DIR_DATE
)
from src.install_pkg import EnvAnalyzer
from data_collection.my_utils import get_repo_name, get_modules_from_py_files,normalize_package_name
from data_collection.vul_analyze import get_pkg2url, read_cve2advisory
from src.install_pkg import EnvAnalyzer
from data_collection.collect_commits import get_all_unique_affected_projects
from data_collection.data_classes import VulnerablePackage
from stdlib_list import stdlib_list
# Global constants
STDLIB_MODULES = stdlib_list()
MAX_PARALLEL_JOBS = 30


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
    def analyze_reachability(call_graph: Dict, vulnerable_functions: List[str], 
                           downstream_modules: List[str], downstream: Tuple) -> Tuple:
        """
        Analyze reachability from vulnerable functions to downstream modules.
        
        Args:
            call_graph: Normalized call graph
            vulnerable_functions: Vulnerable_functions
            downstream_modules: Downstream module names
            downstream: (package, version) tuple
        
        Returns:
            Tuple of (found_functions, call_chains, vulnerable_invocations)
        """
        all_nodes = set(call_graph.keys())
        
        # Handle top-level functions
        vulnerable_funcs_full_names = []
        top_level_func = {}
        
        for full_name in vulnerable_functions:
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
    
    def __init__(self,workdir):
        self.cg_analyzer = CallGraphAnalyzer()
        self.workdir= Path(workdir)
        pairs_cache_file = self.workdir / 'filtered_pairs.pkl'
        with pairs_cache_file.open('rb') as f:
            all_pairs = pickle.load(f)
        self.all_pairs = all_pairs
        pkg2repo_file = PROJECT_ROOT / "src/pkg2repo.json"
        with pkg2repo_file.open('r') as f:
            pkg2repo_mapping = json.load(f)
        self.pkg2repo_mapping = pkg2repo_mapping
    
    def _load_vulnerable_funcs_for_pkg(self, cve_id: str, repo_name: str, fixing_commits: List[str]) -> Set[str]:
        """
        Load vulnerable functions for a package from code changes.
        
        Args:
            cve_id: CVE identifier
            repo_name: Repository name
            fixing_commits: List of fixing commits
            
        Returns:
            Set of vulnerable function names
        """
        code_changes_path = CODE_CHANGES_DIR_DATE / f'{cve_id}_{repo_name}.json'
        code_changes_dict_path = CODE_CHANGES_DIR_DATE / f'{cve_id}_{repo_name}_dict.pkl'
        
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

    def check_single_package(self, cve_id: str, upstream: Tuple, downstream: Tuple, normalized_vulnerable_funcs: List[str], rewrite: bool = False) -> Tuple[Tuple, str]:
        """
        Check reachability for a single downstream package.
        
        Args:
            cve_id: CVE identifier
            upstream: (package, version) tuple
            downstream: (package, version) tuple
            rewrite: Whether to rewrite existing results
        
        Returns:
            Tuple of (downstream, result_status)
        """
        package, version = downstream
        result_file = CG_DIR_DATE / f'{cve_id}/{"@".join(downstream)}_results.json'
        
        if not rewrite and result_file.exists():
            return downstream, "VF Found"
        
        # Load call graph
        jarvis_output_file = Path(CALL_GRAPH_DIR_DATE / package / version / 'jarvis_cg.json')
        jarvis_error_file = Path(CALL_GRAPH_DIR_DATE / package / version / 'ERROR')
        
        if not jarvis_output_file.exists():
            
            return downstream, "Jarvis Failed" if jarvis_error_file.exists() else "Not Jarvis"
        
        # Load and parse call graph
        try:
            with open(jarvis_output_file, 'r') as f:
                call_graph = json.load(f)
        except (json.JSONDecodeError, IOError):
            return downstream, "JSON Failed"
        
        # Import-level filtering
        # Find Python files in the package
        filtered_python_files = EnvAnalyzer.find_project_py_files(
            package, version, workdir=self.workdir
        )
        if not filtered_python_files:
            logger.warning(f"No Python files found for {upstream}")
        
        upstream_modules = get_modules_from_py_files(package, version, filtered_python_files)
        if not self.cg_analyzer.import_analysis(call_graph, upstream_modules):
            return downstream, "Import Failed"
        
        # Normalize call graph
        prefix = f"...{str(self.workdir).split('/')[-1]}.pypi_packages.{package}.{version}."
        normalized_cg = self.cg_analyzer.normalize_call_graph(call_graph, prefix)
        
        # Get downstream modules
        filtered_python_files = EnvAnalyzer.find_project_py_files(
            package, version, workdir=self.workdir
        )
        downstream_modules = get_modules_from_py_files(package, version, filtered_python_files)

        vulnerable_functions = [full_name for _, full_name in  normalized_vulnerable_funcs]
        # Analyze reachability
        try:
            in_cg_vfs, call_chains, vulnerable_invocations = self.cg_analyzer.analyze_reachability(
                normalized_cg, vulnerable_functions, downstream_modules, downstream
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
            'vulnerable_functions': vulnerable_functions,
            'found_functions': list(in_cg_vfs),
            'call_chains': call_chains,
            'vulnerable_invocation': list(vulnerable_invocations)
        }
        
        result_file.parent.mkdir(parents=True, exist_ok=True)
        with open(result_file, 'w') as f:
            json.dump(result_data, f, indent=2)
        
        return downstream, "VF Found"

    def process_downstream_reachability(self, cve2advisory: Dict[str, Dict],rewrite_cg_results: bool = False) -> None:
        """
        Process downstream reachability using pre-normalized VulnerablePackage instances.
        
        Args:
            rewrite_cg_results: Whether to rewrite call graph results
        """
        logger.info("Starting downstream reachability analysis...")
        
        all_results = {}
        
        for idx, (cve_id, advisory) in enumerate(cve2advisory.items()):
            logger.info(f"Processing CVE {cve_id} ({idx + 1}/{len(cve2advisory)})")
            all_unique_affected_projects = get_all_unique_affected_projects(advisory,normalized=False)
            logger.debug(f"Found {len(all_unique_affected_projects)} unique affected projects: {all_unique_affected_projects}")
            
            cve_results = defaultdict(dict)
            pairs = self.all_pairs.get(cve_id)
            if not pairs:
                continue
            
            for package_name, repo_url in all_unique_affected_projects:
                repo_url = self.pkg2repo_mapping[package_name]
                repo_name = get_repo_name(repo_url)
                
                
                for upstream_idx, (upstream, all_downstream) in enumerate(pairs.items()):
                    normalized_vulnerable_funcs_file = CODE_CHANGES_DIR_DATE / f'{cve_id}_{repo_name}_{upstream}_normalized.json'
                    with normalized_vulnerable_funcs_file.open('r') as f:
                        normalized_vulnerable_funcs = json.load(f)
                    
                    if not all_downstream:

                        continue
                    
                    logger.info(f"Processing upstream {upstream} with {len(all_downstream)} downstream packages")
                    
                    # Process downstream packages in parallel
                    results = Parallel(n_jobs=MAX_PARALLEL_JOBS, backend='threading', verbose=0)(
                        delayed(self.check_single_package)(
                            cve_id, upstream, downstream, normalized_vulnerable_funcs,rewrite_cg_results
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
            print(cve_results)
            
        
        # Save overall results
        os.makedirs(os.path.dirname(self.results_file), exist_ok=True)
        with open(self.analyzer.results_file, 'w') as f:
            json.dump(all_results, f, indent=2)
        assert False


def main():
    """Main function for running reachability analysis."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Vulnerability Reachability Analysis')
    parser.add_argument('--size', type=str, choices=['small', 'medium', 'large'], 
                       default='small', help='Dataset size')
    parser.add_argument('--rewrite-cg', action='store_true', 
                       help='Rewrite call graph results')
    
    args = parser.parse_args()
    
    workdir = Path('../docker_workdir_new')
    output_dir = DATA_DIR/SUFFIX
    cvf_output_file = output_dir / "cve2advisory_enhanced.pkl"
    with cvf_output_file.open('rb') as f:
        cve2advisory = pickle.load(f)
    samples = list(cve2advisory.keys())[:5]  # 测试时使用少量样本
    cve2advisory = {k: v for k, v in cve2advisory.items() if k in samples}
    # Initialize checker
    checker = ReachabilityChecker(workdir)
    
    # Run downstream reachability analysis
    logger.info("Running downstream reachability analysis stage...")
    checker.process_downstream_reachability(cve2advisory=cve2advisory,rewrite_cg_results=args.rewrite_cg)
    
    logger.info("Analysis complete!")


if __name__ == '__main__':
    main()