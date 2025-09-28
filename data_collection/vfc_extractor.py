#!/usr/bin/env python3
"""
CVE Fixing Commits Extractor
Extract and display fixing commit URLs for a specific CVE with source information
"""

import argparse
import json
import sys
from pathlib import Path
from collections import defaultdict
import pickle

# Import your existing modules (adjust imports based on your project structure)
try:
    from vul_analyze import read_cve2advisory
    from collect_commits import get_all_unique_affected_projects
    from my_utils import get_repo_name
    from data_collection.constant import CODE_CHANGES_DIR_DATE, COMMITS_DIR_DATE,POSSIBLE_COMMITS_DIR_DATE
    from logger import logger
except ImportError as e:
    print(f"Error importing required modules: {e}")
    print("Please ensure all required modules are available in your Python path")
    sys.exit(1)

def load_cve_data(cve_advisory_file=None):
    """Load CVE advisory data from pickle file"""
    try:
        if cve_advisory_file and Path(cve_advisory_file).exists():
            with open(cve_advisory_file, 'rb') as f:
                return pickle.load(f)
        else:
            # Fallback to your existing function
            return read_cve2advisory(cve_has_vfc=True)
    except Exception as e:
        print(f"Error loading CVE data: {e}")
        return {}

def extract_fixing_commits_from_urls(extracted_urls, repo_url):
    """Extract fixing commits for a specific repository from extracted URLs"""
    extracted_urls_for_repo = {}
    for source, urls in extracted_urls.items():
        commit_urls = set()
        for url in urls:
            url = url.rstrip('.').rstrip('.patch')
            if url.lower().startswith(repo_url.lower()):
                commit_urls.add(url)
        if commit_urls:
            extracted_urls_for_repo[source] = commit_urls
    return extracted_urls_for_repo

def get_final_fixing_commits(cve_id, cve2advisory):
    """Get final fixing commits from advisory data"""
    if cve_id not in cve2advisory:
        return {}
    
    advisory = cve2advisory[cve_id]
    fixing_commits = advisory.get('fixing_commits', {})
    assert len(fixing_commits), fixing_commits
    # Process fixing commits into standardized format
    final_commits = {}
    for repo_name, commits_data in fixing_commits.items():
        if not commits_data:
            continue
            
        # Initialize the structure
        final_commits[repo_name] = {
            'repo_url': '',
            'commits': [],
            'commit_count': 0
        }
        
        # Extract repo URL if available
        if 'available_affected' in advisory:
            for pkg, info in advisory['available_affected'].items():
                print(pkg)
                if pkg == repo_name or repo_name in pkg:
                    final_commits[repo_name]['repo_url'] = info.get('repo_url', '')
                    break
        
        # Process commits based on data structure
        commits_list = []
  
        for commit, info in commits_data.items():
            commits_list.append((commit,info))
        
        
        final_commits[repo_name]['commits'] = commits_list
        final_commits[repo_name]['commit_count'] = len(commits_list)
    return final_commits

def get_cve_fixing_commits(cve_id, cve2advisory):
    """Extract fixing commit URLs for a specific CVE"""
    if cve_id not in cve2advisory:
        return None, f"CVE {cve_id} not found in advisory data"
    
    advisory = cve2advisory[cve_id]
    
    # Load possible commits from file
    possible_commit_file = POSSIBLE_COMMITS_DIR_DATE /f"{cve_id}.json"

    if not possible_commit_file.exists():
        return None, f"No extracted URLs file found for {cve_id}"
    
    try:
        with open(possible_commit_file, 'r') as f:
            extracted_urls = json.load(f)
    except Exception as e:
        return None, f"Error reading URLs file: {e}"
    
    # Get affected projects
    try:
        if 'available_affected' in advisory:
            all_unique_affected_projects = set()
            for pkg, info in advisory['available_affected'].items():
                repo_url = info.get('repo_url')
                if repo_url:
                    all_unique_affected_projects.add((pkg, repo_url))
        else:
            return None, "No affected projects found in advisory"
    except Exception as e:
        return None, f"Error processing affected projects: {e}"
    
    # Get final fixing commits
    final_fixing_commits = get_final_fixing_commits(cve_id, cve2advisory)
    
    results = {
        'cve_id': cve_id,
        'total_urls_by_source': {},
        'raw_extracted_repos': {},
        'final_fixing_commits': final_fixing_commits
    }
    
    # Count total URLs by source
    for source, urls in extracted_urls.items():
        results['total_urls_by_source'][source] = len(urls)
    
    # Process each affected repository for raw extracted commits
    for package_name, repo_url in all_unique_affected_projects:
        repo_commits = extract_fixing_commits_from_urls(extracted_urls, repo_url)
        
        if repo_commits:
            results['raw_extracted_repos'][package_name] = {
                'repo_url': repo_url,
                'commits_by_source': {}
            }
            
            for source, commit_urls in repo_commits.items():
                results['raw_extracted_repos'][package_name]['commits_by_source'][source] = list(commit_urls)
    
    return results, None

def print_fixing_commits(results):
    """Print fixing commits in a formatted way"""
    cve_id = results['cve_id']
    
    print(f"\n{'='*80}")
    print(f"FIXING COMMITS FOR {cve_id}")
    print(f"{'='*80}")
    
    # Print total URLs by source
    print(f"\nTOTAL EXTRACTED URLs BY SOURCE:")
    print(f"{'='*50}")
    total_urls = 0
    for source, count in results['total_urls_by_source'].items():
        print(f"  {source.upper():<15}: {count:>4} URLs")
        total_urls += count
    print(f"  {'TOTAL':<15}: {total_urls:>4} URLs")
    
    # Print raw extracted commits by repository
    if results['raw_extracted_repos']:
        print(f"\nRAW EXTRACTED COMMITS BY REPOSITORY:")
        print(f"{'='*50}")
        
        for package_name, repo_info in results['raw_extracted_repos'].items():
            repo_url = repo_info['repo_url']
            commits_by_source = repo_info['commits_by_source']
            
            print(f"\nPackage: {package_name}")
            print(f"Repository: {repo_url}")
            print(f"{'─'*60}")
            
            total_repo_commits = sum(len(commits) for commits in commits_by_source.values())
            
            if total_repo_commits == 0:
                print("   No raw commits found for this repository")
                continue
            
            for source, commit_urls in commits_by_source.items():
                if commit_urls:
                    print(f"\n   {source.upper()} ({len(commit_urls)} commits):")
                    for i, commit_url in enumerate(commit_urls, 1):
                        commit_hash = commit_url.split('/')[-1]
                        print(f"      {i:>2}. {commit_hash} - {commit_url}")
            
            print(f"\n   Total raw commits for {package_name}: {total_repo_commits}")
    else:
        print(f"\nNo raw extracted commits found for any repositories")
    
    # Print final fixing commits
    print(f"\nFINAL FIXING COMMITS (After filtering):")
    print(f"{'='*50}")
    
    if not results['final_fixing_commits']:
        print("No final fixing commits found after filtering")
        return
    
    total_final_commits = 0
    for package_name, commit_info in results['final_fixing_commits'].items():
        repo_url = commit_info['repo_url']
        commits = commit_info['commits']
        commit_count = commit_info['commit_count']
        
        print(f"\nPackage: {package_name}")
        if repo_url:
            print(f"Repository: {repo_url}")
        print(f"{'─'*60}")
        
        if commit_count == 0:
            print("   No final fixing commits for this package")
            continue
        
        print(f"   Final commits ({commit_count} commits):")
        for i, (commit_url, info) in enumerate(commits, 1):
            commit_hash = commit_url.split('/')[-1]
            print(f"      {i:>2}. {commit_hash} - {commit_url}")
        
        total_final_commits += commit_count
        print(f"\n   Total final commits for {package_name}: {commit_count}")
    
    print(f"\nSUMMARY:")
    print(f"{'='*50}")
    print(f"Total raw extracted URLs: {total_urls}")
    print(f"Total final fixing commits: {total_final_commits}")
    print(f"Packages with final commits: {len([p for p in results['final_fixing_commits'].values() if p['commit_count'] > 0])}")
    if total_urls > 0:
        filtering_efficiency = (total_final_commits / total_urls) * 100
        print(f"Filtering efficiency: {filtering_efficiency:.1f}% ({total_final_commits}/{total_urls})")

def main():
    parser = argparse.ArgumentParser(
        description="Extract and display fixing commit URLs for a specific CVE",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cve_commits_extractor.py CVE-2023-12345
  python cve_commits_extractor.py CVE-2023-12345 --advisory-file /path/to/cve2advisory.pkl
  python cve_commits_extractor.py CVE-2023-12345 --commits-dir /path/to/possible_commits
        """
    )
    
    parser.add_argument(
        'cve_id',
        help='CVE identifier (e.g., CVE-2023-12345)'
    )
    
    parser.add_argument(
        '--advisory-file',
        default=None,
        help='Path to CVE advisory pickle file (default: use built-in function)'
    )
    
    parser.add_argument(
        '--commits-dir',
        default='./possible_commits_2024_08_15',  # Adjust based on your POSSIBLE_COMMITS_DIR_DATE
        help='Directory containing extracted commit URLs (default: ./possible_commits_2024_08_15)'
    )
    
    parser.add_argument(
        '--json-output',
        action='store_true',
        help='Output results in JSON format'
    )
    
    args = parser.parse_args()
    
    # Validate CVE format
    cve_id = args.cve_id.upper()
    if not cve_id.startswith('CVE-'):
        print(f"Error: Invalid CVE format. Expected format: CVE-YYYY-XXXXX")
        sys.exit(1)
    
    # Load CVE data
    print(f"Loading CVE advisory data...")
    cve2advisory = read_cve2advisory(cve_has_vfc=True)
    for idd, advisory in cve2advisory.items():
        if idd != args.cve_id:
            continue
    if not cve2advisory:
        print("Error: Failed to load CVE advisory data")
        sys.exit(1)
    
    print(f"Loaded {len(cve2advisory)} CVE advisories")
    
    # Extract fixing commits
    print(f"Extracting fixing commits for {cve_id}...")
    results, error = get_cve_fixing_commits(cve_id, cve2advisory)
    
    if error:
        print(f"Error: {error}")
        sys.exit(1)
    
    # Output results
    if args.json_output:
        print(json.dumps(results, indent=2, default=str))
    else:
        print_fixing_commits(results)

if __name__ == '__main__':
    main()