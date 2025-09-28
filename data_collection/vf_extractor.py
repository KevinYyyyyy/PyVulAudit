#!/usr/bin/env python3
"""
CVE Fixing Commit and Vulnerable Function Extractor

Usage:
    python cve_extractor.py CVE-2023-12345
    python cve_extractor.py CVE-2023-12345 --verbose
    python cve_extractor.py CVE-2023-12345 --output json
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional
import pickle

# Import your existing modules (adjust imports based on your project structure)
try:
    from vul_analyze import read_cve2advisory
    from collect_commits import get_all_unique_affected_projects
    from my_utils import get_repo_name
    from data_collection.constant import CODE_CHANGES_DIR_DATE, COMMITS_DIR_DATE
    from logger import logger
except ImportError as e:
    print(f"Error importing required modules: {e}")
    print("Please ensure all required modules are available in your Python path")
    sys.exit(1)


class CVEExtractor:
    """Extract fixing commits and vulnerable functions for a given CVE"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.cve2advisory = None
        
    def load_cve_data(self) -> None:
        """Load CVE advisory data"""
        try:
            if self.verbose:
                print("Loading CVE advisory data...")
            self.cve2advisory = read_cve2advisory(valid_py_cve=True, specific_date=True, cve_has_vfc=True)
            if self.verbose:
                print(f"Loaded {len(self.cve2advisory)} CVE entries")
        except Exception as e:
            print(f"Error loading CVE data: {e}")
            sys.exit(1)
    
    def extract_fixing_commits(self, cve_id: str) -> Dict[str, List[str]]:
        """Extract fixing commit URLs for a CVE"""
        if not self.cve2advisory:
            self.load_cve_data()
            
        if cve_id not in self.cve2advisory:
            return {}
            
        advisory = self.cve2advisory[cve_id]
        return advisory.get('fixing_commits', {})
    
    def extract_vulnerable_functions(self, cve_id: str) -> Dict[str, Any]:
        """Extract vulnerable functions for a CVE"""
        if not self.cve2advisory:
            self.load_cve_data()
            
        if cve_id not in self.cve2advisory:
            return {}
            
        advisory = self.cve2advisory[cve_id]
        all_unique_affected_projects = get_all_unique_affected_projects(advisory)
        
        vf_results = {}
        
        for package_name, repo_url in all_unique_affected_projects:
            fixing_commits = advisory['fixing_commits'].get(package_name, [])
            if len(fixing_commits) == 0:
                continue
                
            repo_name = get_repo_name(repo_url)
            
            # Load vulnerable functions from cached files
            code_changes_path = CODE_CHANGES_DIR_DATE / f'{cve_id}_{repo_name}.json'
            code_changes_dict_path = CODE_CHANGES_DIR_DATE / f'{cve_id}_{repo_name}_dict.pkl'
            
            if not code_changes_path.exists() or not code_changes_dict_path.exists():
                if self.verbose:
                    print(f"Warning: No cached data found for {cve_id}_{repo_name}")
                continue
            
            try:
                # Load function names
                with code_changes_path.open('r') as f:
                    commit2methods = json.load(f)
                
                # Load detailed vulnerability categorization
                with code_changes_dict_path.open('rb') as f:
                    commit2methods_dict = pickle.load(f)
                
                package_vf = {
                    'repo_url': repo_url,
                    'package_name': package_name,
                    'commits': {}
                }
                
                for fixing_commit in fixing_commits:
                    if fixing_commit in commit2methods:
                        commit_vf = {
                            'commit_url': fixing_commit,
                            'files': {},
                            'total_functions': 0,
                            'vulnerability_categories': {}
                        }
                        
                        total_functions = 0
                        for file_path, methods in commit2methods[fixing_commit].items():
                            commit_vf['files'][file_path] = {
                                'function_names': methods,
                                'function_count': len(methods)
                            }
                            total_functions += len(methods)
                        
                        commit_vf['total_functions'] = total_functions
                        
                        # Add vulnerability categorization if available
                        if fixing_commit in commit2methods_dict:
                            categories = {}
                            for file_path, vfs_dict in commit2methods_dict[fixing_commit].items():
                                file_categories = {}
                                for category, functions in vfs_dict.items():
                                    if len(functions) > 0:
                                        file_categories[category] = (len(functions), [func.long_name for func in functions])
                                if file_categories:
                                    categories[file_path] = file_categories
                            
                            if categories:
                                commit_vf['vulnerability_categories'] = categories
                        
                        if total_functions > 0:
                            commit_vf_id = fixing_commit.split('/')[-1]
                            package_vf['commits'][commit_vf_id] = commit_vf
                
                if package_vf['commits']:
                    vf_results[package_name] = package_vf
                    
            except Exception as e:
                if self.verbose:
                    print(f"Error processing {cve_id}_{repo_name}: {e}")
                continue
        
        return vf_results
    
    def print_results(self, cve_id: str, output_format: str = 'text') -> None:
        """Print extraction results for a CVE"""
        print(f"\n{'='*60}")
        print(f"CVE Analysis: {cve_id}")
        print(f"{'='*60}")
        
        # Extract fixing commits
        fixing_commits = self.extract_fixing_commits(cve_id)
        
        if not fixing_commits:
            print(f"No fixing commits found for {cve_id}")
            return
        
        # Extract vulnerable functions
        vf_results = self.extract_vulnerable_functions(cve_id)
        
        if output_format == 'json':
            self._print_json_results(cve_id, fixing_commits, vf_results)
        else:
            self._print_text_results(cve_id, fixing_commits, vf_results)
    
    def _print_text_results(self, cve_id: str, fixing_commits: Dict, vf_results: Dict) -> None:
        """Print results in human-readable text format"""
        print(f"\nFIXING COMMITS:")
        print("-" * 40)
        
        total_commits = 0
        for package_name, commits in fixing_commits.items():
            print(f"\nPackage: {package_name}")
            print(f"  Commits ({len(commits)}):")
            for commit_url in commits:
                print(f"    - {commit_url}")
                total_commits += 1
        
        print(f"\nTotal fixing commits: {total_commits}")
        
        print(f"\nVULNERABLE FUNCTIONS:")
        print("-" * 40)
        
        if not vf_results:
            print("No vulnerable functions extracted")
            return
        
        total_functions = 0
        for package_name, package_data in vf_results.items():
            print(f"\nPackage: {package_name}")
            print(f"Repository: {package_data['repo_url']}")
            
            for commit_id, commit_data in package_data['commits'].items():
                print(f"\n  Commit: {commit_id}")
                print(f"  URL: {commit_data['commit_url']}")
                print(f"  Total functions: {commit_data['total_functions']}")
                
                if commit_data['total_functions'] > 0:
                    print(f"  Modified files:")
                    for file_path, file_data in commit_data['files'].items():
                        print(f"    - {file_path} ({file_data['function_count']} functions)")
                        if self.verbose:
                            for func_name in file_data['function_names']:
                                print(f"      • {func_name}")
                
                # Print vulnerability categories if available
                if 'vulnerability_categories' in commit_data and commit_data['vulnerability_categories']:
                    print(f"  Vulnerability categories:")
                    for file_path, categories in commit_data['vulnerability_categories'].items():
                        print(f"    {file_path}:")
                        for category, (count, funcs) in categories.items():
                            print(f"      - {category}: {count} functions: {funcs}")
                
                total_functions += commit_data['total_functions']
        
        print(f"\nSUMMARY:")
        print("-" * 40)
        print(f"Total packages: {len(vf_results)}")
        print(f"Total commits with VF: {sum(len(pkg['commits']) for pkg in vf_results.values())}")
        print(f"Total vulnerable functions: {total_functions}")
    
    def _print_json_results(self, cve_id: str, fixing_commits: Dict, vf_results: Dict) -> None:
        """Print results in JSON format"""
        results = {
            'cve_id': cve_id,
            'fixing_commits': fixing_commits,
            'vulnerable_functions': vf_results,
            'summary': {
                'total_packages': len(fixing_commits),
                'total_commits': sum(len(commits) for commits in fixing_commits.values()),
                'packages_with_vf': len(vf_results),
                'commits_with_vf': sum(len(pkg['commits']) for pkg in vf_results.values()),
                'total_vulnerable_functions': sum(
                    commit_data['total_functions'] 
                    for pkg in vf_results.values() 
                    for commit_data in pkg['commits'].values()
                )
            }
        }
        
        print(json.dumps(results, indent=2))


def main():
    parser = argparse.ArgumentParser(
        description='Extract fixing commits and vulnerable functions for a CVE',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cve_extractor.py CVE-2023-12345
  python cve_extractor.py CVE-2023-12345 --verbose
  python cve_extractor.py CVE-2023-12345 --output json
        """
    )
    
    parser.add_argument('cve_id', help='CVE ID to analyze (e.g., CVE-2023-12345)')
    parser.add_argument('--verbose', '-v', action='store_true', 
                       help='Enable verbose output')
    parser.add_argument('--output', '-o', choices=['text', 'json'], default='text',
                       help='Output format (default: text)')
    
    args = parser.parse_args()
    
    # Validate CVE ID format
    if not args.cve_id.startswith('CVE-'):
        print(f"Error: Invalid CVE ID format. Expected format: CVE-YYYY-NNNNN")
        sys.exit(1)
    
    try:
        extractor = CVEExtractor(verbose=args.verbose)
        extractor.print_results(args.cve_id, args.output)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()