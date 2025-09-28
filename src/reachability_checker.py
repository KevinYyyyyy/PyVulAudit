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
import argparse
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


class CallGraphAnalyzer:
    """Handles call graph analysis and reachability computation."""
    
    @staticmethod
    def import_analysis(downstream: str, call_graph: Dict, upstream_modules: List[str]) -> bool:
        """
        Check if upstream modules appear in the call graph.
        
        Args:
            call_graph: Call graph dictionary
            upstream_modules: List of upstream module names
        
        Returns:
            True if any upstream module is found in call graph
        """
        all_nodes = set(call_graph.keys())
        intersection = all_nodes.intersection(upstream_modules)
        print(f"🔍 Import Analysis: Found {len(intersection)}/{len(upstream_modules)} upstream modules in {':'.join(downstream)} cg")
        return len(intersection) > 0
    
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
        filtered_system_count = 0
        
        for func, callees in call_graph.items():
            if is_system_module(func):
                filtered_system_count += 1
                continue
            
            normalized_func = normalize_func_name(func)
            normalized_callees = [
                normalize_func_name(callee) for callee in callees
                if not is_system_module(callee)
            ]
            normalized_cg[normalized_func].update(normalized_callees)
        
        result = {k: list(v) for k, v in normalized_cg.items()}
        # print(f"🔧 Normalized call graph: {len(call_graph)} → {len(result)} nodes")
        return result
    
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
            return [], [], [], []
        
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
        invocation_paths = {}  # Store shortest paths for each invocation
        logger.info(f"Analyzing {len(in_cg_funcs)} functions for {downstream}")
        found_functions=set()
        for func in in_cg_funcs:
            for entry_func in entry_funcs:
                if nx.has_path(G, source=func, target=entry_func):
                    vulnerable_invocations.append(entry_func)
                    # Calculate shortest path (in reverse graph, so reverse the result)
                    shortest_path = nx.shortest_path(G, source=func, target=entry_func)
                    # Reverse the path to show entry_func -> ... -> func
                    reversed_path = shortest_path[::-1]
                    invocation_paths[entry_func] = {
                        'source_function': entry_func,
                        'target_function': func,
                        'path': reversed_path,
                        'path_length': len(reversed_path) - 1
                    }
                    found_functions.add(func)

                    
        
        # Transform top-level functions back
        top_in_cg_funcs = [
            top_level_func.get(func, func) for func in in_cg_funcs
        ]
        found_functions.update(top_in_cg_funcs)
        if len(found_functions) < len(in_cg_funcs):
            assert False
        print(f"🎯 Reachability: {len(in_cg_funcs)}/{len(vulnerable_funcs_full_names)} functions found, {len(vulnerable_invocations)} invocations")
            
        
        return list(found_functions), [], list(vulnerable_invocations), invocation_paths


class ReachabilityChecker:
    """Main class for checking vulnerability reachability."""
    
    def __init__(self, workdir, show_paths=False):
        print(f"🚀 Initializing ReachabilityChecker")
        self.cg_analyzer = CallGraphAnalyzer()
        self.workdir = Path(workdir)
        self.show_paths = show_paths
        
        # Load filtered pairs cache
        filtered_pairs_cache_file = self.workdir / 'filtered_pairs.pkl'
        with filtered_pairs_cache_file.open('rb') as f:
            all_filtered_pairs = pickle.load(f)
        self.all_filtered_pairs = all_filtered_pairs
        
        # Load all pairs cache
        pairs_cache_file = self.workdir / 'get_all_downstream_and_pairs_results.pkl'
        with pairs_cache_file.open('rb') as f:
            _,all_pairs = pickle.load(f)
        self.all_pairs = all_pairs
        
        # Load package to repository mapping
        pkg2repo_file = PROJECT_ROOT / "src/pkg2repo.json"
        with pkg2repo_file.open('r') as f:
            pkg2repo_mapping = json.load(f)
        self.pkg2repo_mapping = pkg2repo_mapping
        print(f"📂 Loaded data: {len(all_filtered_pairs)} filtered pairs, {len(all_pairs)} total pairs")
    
    def check_cached_results(self, cve2advisory: Dict[str, Dict]) -> Dict[str, bool]:
        """
        Check if cached results exist for the given CVEs.
        
        Args:
            cve2advisory: Dictionary mapping CVE IDs to advisory data
            
        Returns:
            Dictionary mapping CVE IDs to whether cached results exist
        """
        cached_status = {}
        for cve_id in cve2advisory.keys():
            cve_results_file = REACHABILITY_DIR_DATE / f'{cve_id}_results.json'
            cached_status[cve_id] = cve_results_file.exists()
        return cached_status
    
    def display_cached_report(self, cve_id: str) -> bool:
        """
        Display the cached analysis report for a specific CVE.
        
        Args:
            cve_id: CVE identifier
            
        Returns:
            True if report was displayed successfully, False otherwise
        """
        cve_results_file = REACHABILITY_DIR_DATE / f'{cve_id}_results.json'
        
        if not cve_results_file.exists():
            return False
            
        try:
            with open(cve_results_file, 'r') as f:
                results = json.load(f)
            print(f"\n📋 Cached Analysis Report for {cve_id}")
            print("=" * 60)
            
            total_upstream = len(results)
            total_downstream = 0
            reachable_pairs = 0
            
            for upstream_key, downstream_results in results.items():
                if isinstance(downstream_results, dict):
                    total_downstream += len(downstream_results)
                    
                    # Count reachable packages
                    reachable_packages = []
                    for pkg_key, status in downstream_results.items():
                        if status == "VF Found":
                            reachable_pairs += 1
                            reachable_packages.append(pkg_key)
                    
                    print(f"\n🔍 Upstream Package: {upstream_key}")
                    print(f"   Total downstream packages: {len(downstream_results)}")
                    print(f"   Reachable packages: {len(reachable_packages)}")
                    
                    if reachable_packages:
                        print(f"   Reachable package list:")
                        for pkg in reachable_packages[:5]:
                            print(f"        - {pkg}")
                            
                            # Try to load detailed results for this package to show invocations and paths
                            detailed_result_file = CG_DIR_DATE / f'{cve_id}/{pkg}_results.json'
                            if detailed_result_file.exists():
                                try:
                                    with open(detailed_result_file, 'r') as df:
                                        detailed_data = json.load(df)
                                    vulnerable_invocations = detailed_data.get('vulnerable_invocation', [])
                                    invocation_paths = detailed_data.get('invocation_paths', {})
                                    
                                    if vulnerable_invocations:
                                        print(f"          🎯 Vulnerable invocations ({len(vulnerable_invocations)}):")
                                        for invocation in vulnerable_invocations[:3]:  # Show first 3
                                            print(f"            - {invocation}")
                                            if self.show_paths and invocation in invocation_paths:
                                                path_info = invocation_paths[invocation]
                                                path_length = path_info.get('path_length', 'unknown')
                                                path = path_info.get('path', [])
                                                print(f"              🔗 Shortest path (length {path_length}): {' -> '.join(path)}")
                                        
                                        if len(vulnerable_invocations) > 3:
                                            print(f"            ... and {len(vulnerable_invocations) - 3} more invocations")
                                    
                                except (json.JSONDecodeError, IOError) as e:
                                    logger.warning(f"Failed to load detailed results for {pkg}: {e}")
                        
                        if len(reachable_packages) > 5:
                            print(f"        ... and {len(reachable_packages) - 5} more packages")
            
            print("=" * 60)
            print(f"✅ Report display completed")
            return True
            
        except (json.JSONDecodeError, IOError) as e:
            print(f"❌ Failed to read cached results: {e}")
            return False

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
            if fixing_commit in commit2methods:
                for file, methods in commit2methods[fixing_commit].items():
                    vulnerable_funcs.update(methods)
        
        
        return vulnerable_funcs

    def check_single_package(self, cve_id: str, upstream: Tuple, downstream: Tuple, normalized_vulnerable_funcs: List[str], rewrite: bool = False) -> Tuple[Tuple, str]:
        """
        Check reachability for a single downstream package.
        
        Args:
            cve_id: CVE identifier
            upstream: (package, version) tuple
            downstream: (package, version) tuple
            normalized_vulnerable_funcs: List of normalized vulnerable functions
            rewrite: Whether to rewrite existing results
        
        Returns:
            Tuple of (downstream, result_status)
        """
        package, version = downstream
        
        result_file = CG_DIR_DATE / f'{cve_id}/{"@".join(downstream)}_results.json'
        
        if not rewrite and result_file.exists():
            
            return downstream, "VF Found"
        
        # Load call graph
        CALL_GRAPH_DIR_DATE = Path('/home/kevin/PyVul/data_collection/202509/call_graphs/')
        jarvis_output_file = CALL_GRAPH_DIR_DATE / package / version / 'jarvis_cg.json'
        jarvis_error_file = CALL_GRAPH_DIR_DATE / package / version / 'ERROR'
        
        if not jarvis_output_file.exists():
            if jarvis_error_file.exists():
                return downstream, "Jarvis Failed"
            else:
                return downstream, "Not Jarvis"
        
        # Load and parse call graph
        try:
            with open(jarvis_output_file, 'r') as f:
                call_graph = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            return downstream, "JSON Failed"
        
        # Import-level filtering
        # Find Python files in the package
        filtered_python_files = EnvAnalyzer.find_project_py_files(
            package, version, workdir=self.workdir
        )
        if not filtered_python_files:
            logger.warning(f"No Python files found for {upstream}")
        
        upstream_modules = get_modules_from_py_files(package, version, filtered_python_files)
        
        if not self.cg_analyzer.import_analysis(downstream, call_graph, upstream_modules):
            return downstream, "Import Failed"
        
        # Normalize call graph
        prefix = f"...{str(self.workdir).split('/')[-1]}.pypi_packages.{package}.{version}."
        normalized_cg = self.cg_analyzer.normalize_call_graph(call_graph, prefix)
        # Get downstream modules
        print(f"🔍 Function Invoke Analysis:  {':'.join(downstream)} cg")

        downstream_package, downstream_version = downstream
        filtered_python_files = EnvAnalyzer.find_project_py_files(
            downstream_package, downstream_version, workdir=self.workdir
        )
        downstream_modules = get_modules_from_py_files(downstream_package, downstream_version, filtered_python_files)
        

        vulnerable_functions = [full_name for _, full_name in  normalized_vulnerable_funcs]
        
        # Analyze reachability
        in_cg_vfs, call_chains, vulnerable_invocations, invocation_paths = self.cg_analyzer.analyze_reachability(
            normalized_cg, vulnerable_functions, downstream_modules, downstream
        )


        if not in_cg_vfs:
            print(f"   No vulnerable functions found")
            return downstream, "VF Not Found"
        
        print(f"   Found {len(in_cg_vfs)} vulnerable functions")
        print(f"   Found {len(vulnerable_invocations)} vulnerable invocations")
        logger.info(f"Found vulnerable functions in {downstream}: {in_cg_vfs}")
        logger.info(f"Found vulnerable invocations in {downstream}: {len(vulnerable_invocations)}")
        
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
            'vulnerable_invocation': list(vulnerable_invocations),
            'invocation_paths': invocation_paths
        }
        
        result_file.parent.mkdir(parents=True, exist_ok=True)
        with open(result_file, 'w') as f:
            json.dump(result_data, f, indent=2)
        
        return downstream, "VF Found"

    def process_downstream_reachability(self, cve2advisory: Dict[str, Dict], rewrite_cg_results: bool = False) -> None:
        """
        Process downstream reachability using pre-normalized VulnerablePackage instances.
        
        Args:
            cve2advisory: Dictionary mapping CVE IDs to advisory data
            rewrite_cg_results: Whether to rewrite call graph results
        """
        print(f"Processing {len(cve2advisory)} CVEs")
        
        logger.info("Starting downstream reachability analysis...")
        
        all_results = {}
        
        for idx, (cve_id, advisory) in enumerate(cve2advisory.items()):
            print(f"Processing {cve_id} ({idx + 1}/{len(cve2advisory)})")
            logger.info(f"Processing {cve_id} ({idx + 1}/{len(cve2advisory)})")
            
            all_unique_affected_projects = get_all_unique_affected_projects(advisory,normalized=False)
            
            cve_results = defaultdict(dict)
            # pairs = self.all_filtered_pairs.get(cve_id)
            # if not pairs:
            #     pairs = self.all_pairs.get(cve_id)
            #     if not pairs:
            #         assert False
            #         continue
            available_affected = advisory.get('available_affected', {})
            vulnerable_packages=set()
            for package_name, infos in available_affected.items():
                versions = infos['versions']
                repo_url = infos['repo_url']
                for version in versions:
                    vulnerable_packages.add(((package_name, version), repo_url))
            for upstream_idx,( upstream ,repo_url )in enumerate(vulnerable_packages):
                upstream_pkg, upstream_version = upstream
                
            # for package_name, repo_url in all_unique_affected_projects:
                repo_url = self.pkg2repo_mapping[upstream_pkg]
                repo_name = get_repo_name(repo_url)
                snapshot_dir = DATA_DIR/SUFFIX/'snapshots/0927' 
                # snapshot_dir = Path('/home/kevin/PyVul/data_collection/research_snapshots/202508')
                snapshot_file = snapshot_dir/f'{"@".join([ upstream_pkg,upstream_version])}'/'dependents.json'
                if not snapshot_file.exists():
                    continue
                with open(snapshot_file, 'r') as f:
                    all_downstream = json.load(f)
                direct = all_downstream['direct']
                indirect = all_downstream['indirect']
                
                all_downstream = direct + indirect
                # for upstream_idx, (upstream, all_downstream) in enumerate(pairs.items()):
                    
                normalized_vulnerable_funcs_file = CODE_CHANGES_DIR_DATE / f'{cve_id}_{repo_name}_{"_".join(upstream)}_normalized.json'
                print(normalized_vulnerable_funcs_file)
                # Check if normalized vulnerable functions file exists
                if not normalized_vulnerable_funcs_file.exists():
                    continue
                with normalized_vulnerable_funcs_file.open('r') as f:
                    normalized_vulnerable_funcs = json.load(f)
                   
                
                if not all_downstream:
                    assert False

                    continue
                
                logger.info(f"Processing upstream {upstream} with {len(all_downstream)} downstream packages")
                # Process downstream packages in parallel
                results = Parallel(n_jobs=MAX_PARALLEL_JOBS, backend='threading', verbose=0)(
                    delayed(self.check_single_package)(
                        cve_id, upstream, downstream, normalized_vulnerable_funcs, rewrite_cg_results
                    )
                    for downstream in tqdm(all_downstream, 
                                        desc=f"Processing upstream {upstream} ({upstream_idx + 1}/{len(vulnerable_packages)})")
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
        results_file = REACHABILITY_DIR_DATE / 'all_results.json'
        os.makedirs(os.path.dirname(results_file), exist_ok=True)
        with open(results_file, 'w') as f:
            json.dump(all_results, f, indent=2)


def create_parser():
    """
    Create command line argument parser for vulnerability reachability analysis.
    """
    parser = argparse.ArgumentParser(
        description='Vulnerability Reachability Analysis Pipeline',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  
  python reachability_checker.py                                    # Run analysis on all CVEs
  python reachability_checker.py --cve CVE-2020-13757              # Run analysis on specific CVE  
  python reachability_checker.py --package Django                   # Run analysis on specific package
  python reachability_checker.py --cve CVE-2020-13757 --show-paths  # Show paths for specific CVE

        """
    )
    
    # Main analysis options
    parser.add_argument('--rewrite-cg', action='store_true', 
                       help='Rewrite existing call graph results')
    parser.add_argument('--workdir', type=str, default='../docker_workdir_new',
                       help='Working directory path (default: ../docker_workdir_new)')
    parser.add_argument('--force-update', action='store_true',
                       help='Force update of existing analysis results, ignoring cached data')
    
    # Analysis target options (mutually exclusive)
    target_group = parser.add_mutually_exclusive_group()
    target_group.add_argument('--cve', type=str,nargs='*',
                             help='Analyze specific CVE (supports multiple CVEs)')
    target_group.add_argument('--package', type=str,nargs='*',
                             help='Analyze specific package (supports multiple packages)')
    
    # Output options
    parser.add_argument('--output-dir', type=str,
                       help='Custom output directory for results')
    parser.add_argument('--show-paths', action='store_true',
                       help='Show detailed call paths in vulnerability reports (may produce verbose output)')
    
    # Verbosity options (mutually exclusive)
    verbosity_group = parser.add_mutually_exclusive_group()
    verbosity_group.add_argument('--verbose', '-v', action='store_true',
                                help='Enable verbose output for debugging')
    verbosity_group.add_argument('--quiet', '-q', action='store_true',
                                help='Suppress non-essential output (useful for automation)')
    
    # Performance options
    parser.add_argument('--max-jobs', type=int, default=30,
                       help='Maximum number of parallel jobs (default: 30)')
    
    return parser


def main():
    """Main function for running reachability analysis."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Configure logging based on verbosity
    if args.quiet:
        logger.setLevel('WARNING')
    elif args.verbose:
        logger.setLevel('DEBUG')
    
    print("Starting Vulnerability Reachability Analysis Pipeline")
    
    # Update global max jobs
    global MAX_PARALLEL_JOBS
    MAX_PARALLEL_JOBS = args.max_jobs
    
    workdir = Path(args.workdir)
    output_dir = DATA_DIR/SUFFIX
    cvf_output_file = output_dir / "cve2advisory_enhanced.pkl"
    
    with cvf_output_file.open('rb') as f:
        cve2advisory = pickle.load(f)
    
    print(f"Loaded {len(cve2advisory)} CVEs")
    
    # Filter CVEs based on command line arguments
    if args.cve:
        if isinstance(args.cve, list):
            cve2advisory = {k: v for k, v in cve2advisory.items() if k in args.cve}
        else:
            cve2advisory = {k: v for k, v in cve2advisory.items() if k == args.cve}
    elif args.package:
        if isinstance(args.package, list):
            # Filter CVEs that affect any of the specified packages
            filtered_cves = {}
            for cve_id, advisory in cve2advisory.items():
                affected_projects = get_all_unique_affected_projects(advisory, normalized=False)
                if any(pkg_name in args.package for pkg_name, _ in affected_projects):
                    filtered_cves[cve_id] = advisory
            cve2advisory = filtered_cves
            print(f"Found {len(cve2advisory)} CVEs affecting specified packages")
        else:
            # Filter CVEs that affect the specified package
            filtered_cves = {}
            for cve_id, advisory in cve2advisory.items():
                affected_projects = get_all_unique_affected_projects(advisory, normalized=False)
                if any(pkg_name == args.package for pkg_name, _ in affected_projects):
                    filtered_cves[cve_id] = advisory
            cve2advisory = filtered_cves
            print(f"Found {len(cve2advisory)} CVEs affecting {args.package}")
    else:
        # Use active CVEs by default
        cve2advisory = {k: v for k, v in cve2advisory.items()}

    print(f"Processing {len(cve2advisory)} CVEs")
    
    if not cve2advisory:
        print("No CVEs to process after filtering. Exiting.")
        return

    # Initialize checker
    checker = ReachabilityChecker(workdir, show_paths=args.show_paths)
    
    if args.force_update:
        print(f"\n🔄 Force update enabled - re-analyzing all {len(cve2advisory)} CVE(s)")
        # Run analysis for all CVEs, ignoring cached results
        logger.info("Running downstream reachability analysis stage (force update)...")
        checker.process_downstream_reachability(cve2advisory=cve2advisory, rewrite_cg_results=args.rewrite_cg)
    else:
        # Check for cached results
        cached_status = checker.check_cached_results(cve2advisory)
        if not args.rewrite_cg:
            cached_cves = [cve_id for cve_id, is_cached in cached_status.items() if is_cached]
            uncached_cves = [cve_id for cve_id, is_cached in cached_status.items() if not is_cached]
        else:
            cached_cves = []
            uncached_cves = [cve_id for cve_id, is_cached in cached_status.items()]

        
        if cached_cves :
            print(f"\n🔍 Found {len(cached_cves)} CVE(s) with cached results:")
            for cve_id in cached_cves:
                print(f"  - {cve_id}")
            
        if uncached_cves:
            print(f"\n🆕 Need to analyze {len(uncached_cves)} new CVE(s):")
            for cve_id in uncached_cves:
                print(f"  - {cve_id}")
            
            # Filter to only analyze uncached CVEs
            uncached_cve2advisory = {cve_id: cve2advisory[cve_id] for cve_id in uncached_cves}
            
            # Run downstream reachability analysis for uncached CVEs only
            logger.info("Running downstream reachability analysis stage...")
            checker.process_downstream_reachability(cve2advisory=uncached_cve2advisory, rewrite_cg_results=args.rewrite_cg)
        else:
            print(f"\n✅ All CVEs have cached results, no need to re-analyze")
    
    
    print(f"\n📋 Displaying analysis reports...")
    for cve_id in cve2advisory:
        success = checker.display_cached_report(cve_id)
        if not success:
            print(f"❌ Failed to display cached report for {cve_id}")
    print("Analysis complete!")
    logger.info("Analysis complete!")


if __name__ == '__main__':
    main()