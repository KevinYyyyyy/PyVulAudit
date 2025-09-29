#!/usr/bin/env python3
"""
Patch Parser Module

This module provides functionality to analyze patches and code changes
for vulnerability fixes, including commit analysis and AST-based change detection.

Based on data_collection/collect_commits.py and collect_changes.py functionality.
"""

import os
import sys
import ast
import json
import pickle
import pandas as pd
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Set, Any
from urllib.parse import urlparse
import re
from collections import defaultdict, Counter
from itertools import chain
from tqdm import tqdm
from joblib import Parallel, delayed
import multiprocessing
import subprocess
import argparse

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent.absolute()
sys.path.append(str(PROJECT_ROOT))

from data_collection.logger import logger
from src.constant import (
    DATA_DIR, SUFFIX, COMMITS_DIR_DATE, CODE_CHANGES_DIR_DATE, 
    POSSIBLE_COMMITS_DIR_DATE, REPO_DIR, DIFF_CACHE_DIR_DATE,
    SCOPE_CACHE_DIR_DATE, AST_TYPE_CACHE_DIR_DATE,REPO_DIR_DATE
)
from data_collection.my_utils import get_repo_url, get_repo_name, normalize_package_name, is_source_code_file, request_metadata_json_from_pypi

from data_collection.clone_repos import clone_repo
from data_collection.collect_commits import (
    get_all_unique_affected_projects, get_extracted_urls_for_repo,
    is_fix_commit, is_squash_commit,
    is_exclude_commit, adjust_message
)
from data_collection.collect_changes import (
    ScopeAnalyzer, get_code_change_scope,
    find_minimal_enclosing_scope, get_methods
)
from data_collection.constant import exclude_dirs, exclude_suffixes
from pydriller import Repository, Git
from pydriller.domain.commit import Commit, ModifiedFile,ModificationType

import tree_sitter_python as tspython
from tree_sitter import Language, Parser
from data_collection.dependency_track import ScopeAwareDependencyTracker


# Initialize Tree-sitter for Python
PY_LANGUAGE = Language(tspython.language())


class FunctionBodyComparator:
    def __init__(self):
        self.parser = Parser(PY_LANGUAGE)
    
    def normalize_function_body(self, code: str) -> str:
        """
        Normalize function code by removing comments, empty lines, and standardizing whitespace.
        """
        try:
            # Parse the code with tree-sitter
            tree = self.parser.parse(bytes(code, "utf8"))
            root_node = tree.root_node
            
            # Find the function body
            function_node = self._find_function_node(root_node)
            if not function_node:
                # If no function found, treat entire code as body
                return self._normalize_node(root_node, code)
            
            # Get function body (skip def line, parameters, etc.)
            body_node = function_node.child_by_field_name('body')
            if not body_node:
                return ""
            
            return self._normalize_node(body_node, code)
            
        except Exception as e:
            print(f"Error parsing code with tree-sitter: {e}")
            # Fallback to regex-based normalization
            return self._fallback_normalize(code)
            
    def _find_function_node(self, node):
        """Find the first function definition node."""
        if node.type == 'function_definition':
            return node
        
        for child in node.children:
            result = self._find_function_node(child)
            if result:
                return result
        
        return None
    
    def _normalize_node(self, node, source_code: str) -> str:
        """
        Normalize a tree-sitter node by extracting meaningful code elements.
        """
        normalized_parts = []
        self._extract_meaningful_content(node, source_code, normalized_parts)
        
        # Join all parts and normalize whitespace
        result = ' '.join(normalized_parts)
        # Remove extra whitespace
        result = re.sub(r'\s+', ' ', result).strip()
        
        return result
    
    def _extract_meaningful_content(self, node, source_code: str, parts: List[str]):
        """
        Recursively extract meaningful content from AST nodes, skipping comments.
        """
        # Skip comment nodes
        if node.type == 'comment':
            return
        
        # Skip docstring nodes (string literals at the beginning of function body)
        if self._is_docstring(node):
            return
        
        # For leaf nodes (terminals), extract text
        if len(node.children) == 0:
            text = self._get_node_text(node, source_code).strip()
            if text and not text.startswith('#'):
                parts.append(text)
        else:
            # For non-leaf nodes, recurse into children
            for child in node.children:
                self._extract_meaningful_content(child, source_code, parts)
    
    def _is_docstring(self, node) -> bool:
        """
        Check if a node is likely a docstring.
        """
        if node.type != 'expression_statement':
            return False
        
        # Check if it's a string literal at the start of a function/class body
        for child in node.children:
            if child.type == 'string':
                # Check if this is the first statement in a function/class body
                parent = node.parent
                if parent and parent.type == 'block':
                    # Find position in block
                    siblings = [child for child in parent.children if child.type in ['expression_statement', 'simple_statements']]
                    if siblings and siblings[0] == node:
                        return True
        
        return False
    
    def _get_node_text(self, node, source_code: str) -> str:
        """Extract text content from a tree-sitter node."""
        start_byte = node.start_byte
        end_byte = node.end_byte
        return source_code.encode('utf8')[start_byte:end_byte].decode('utf8')
    
    def _fallback_normalize(self, code: str) -> str:
        """
        Fallback normalization using regex when tree-sitter fails.
        """
        lines = code.split('\n')
        normalized_lines = []
        
        in_multiline_string = False
        in_docstring = False
        docstring_quotes = None
        
        for i, line in enumerate(lines):
            # Skip empty lines
            stripped = line.strip()
            if not stripped:
                continue
            
            # Handle docstrings
            if i == 0 or (i == 1 and lines[0].strip().startswith('def ')):
                # Check for docstring start
                docstring_match = re.match(r'\s*(""".*?"""|\'\'\'.+?\'\'\'|".*?"|\'.*?\')\s*$', stripped)
                if docstring_match or stripped.startswith('"""') or stripped.startswith("'''"):
                    if not (stripped.startswith('"""') and stripped.endswith('"""') and len(stripped) > 6):
                        in_docstring = True
                        docstring_quotes = '"""' if '"""' in stripped else "'''"
                    continue
            
            # Handle multiline docstring end
            if in_docstring:
                if docstring_quotes in stripped:
                    in_docstring = False
                continue
            
            # Skip single-line comments
            if stripped.startswith('#'):
                continue
            
            # Remove inline comments (simple approach)
            if '#' in stripped:
                # More sophisticated comment removal would need proper parsing
                code_part = stripped.split('#')[0].strip()
                if code_part:
                    normalized_lines.append(code_part)
            else:
                normalized_lines.append(stripped)
        
        # Join lines and normalize whitespace
        result = ' '.join(normalized_lines)
        result = re.sub(r'\s+', ' ', result)
        
        return result.strip()

class CommitProcessor:
    """
    Processes commits to extract vulnerability fix information
    Based on collect_commits.py functionality
    """
    
    def __init__(self, pkg2repo_mapping: Optional[Dict[str, str]] = None):
        """Initialize CommitProcessor"""
        self.pkg2repo_mapping = pkg2repo_mapping or {}
        self.func_comparator = FunctionBodyComparator()
        
    def extract_commit_urls_from_advisory(self, advisory: Dict) -> Dict[str, List[str]]:
        """
        Extract commit URLs from security advisory references
        Based on extract_all_possible_urls from collect_commits.py
        
        Args:
            advisory: Security advisory dictionary
            
        Returns:
            Dictionary with commit URLs categorized by source type
        """
        from data_collection.collect_commits import extract_all_possible_urls
        
        url_result, netlocs = extract_all_possible_urls(advisory)
        return url_result

    def get_extracted_urls_for_repo(self, extracted_urls: Dict, repo_url: str, filter_large: bool = False) -> Dict[str, Set[str]]:
        """
        Get extracted URLs for a specific repository
        Based on get_extracted_urls_for_repo from collect_commits.py
        
        Args:
            extracted_urls: Dictionary of extracted URLs by source
            repo_url: Repository URL to filter for
            filter_large: Whether to filter large PR/Issue sources
            
        Returns:
            Dictionary of URLs filtered for the specific repository
        """
        return get_extracted_urls_for_repo(extracted_urls, repo_url, filter_large)

    def clone_repository(self, repo_url: str, repo_path: Path) -> bool:
        """
        Clone a repository if it doesn't exist
        Based on clone_repo from clone_repos.py
        
        Args:
            repo_url: Repository URL to clone
            repo_path: Local path to clone to
            
        Returns:
            bool: Success status
        """
        if repo_path.exists():
            logger.info(f'Repo {repo_url} already exists, skipping...')
            return True
            
        logger.info(f'Repo {repo_url} not found, cloning...')
        return clone_repo(repo_url, repo_path)

    def is_valid_fix_commit(self, commit: Commit) -> bool:
        """
        Check if a commit is a valid fix commit
        Based on is_fix_commit from collect_commits.py
        
        Args:
            commit: Commit object to check
            
        Returns:
            bool: True if commit is a valid fix
        """
        return is_fix_commit(commit) and not is_exclude_commit(commit) and not is_squash_commit(commit)

    def get_modified_source_files(self, commit: Commit) -> List[ModifiedFile]:
        """
        Get modified source code files from a commit
        Based on get_modification_files_for_vfc from collect_commits.py
        
        Args:
            commit: Commit object
            
        Returns:
            List of modified source files
        """
        modified_files = []
        for file in commit.modified_files:
            if file.filename and is_source_code_file(file.filename, exclude_dirs):
                if file.filename.endswith('.py'):
                    modified_files.append(file)
        return modified_files

    def identify_vulnerable_location(self, fixing_commits: List[str], repo_path: str, 
                                   cve_id: str, extracted_urls_for_repo: Optional[Dict] = None) -> Tuple[Dict, List, List, Dict]:
        """
        Identify vulnerable locations in the codebase from fixing commits.
        
        Args:
            fixing_commits: List of fixing commit URLs
            repo_path: Path to the repository
            cve_id: CVE identifier for caching
            extracted_urls_for_repo: Dictionary of extracted URLs by source type
            
        Returns:
            Tuple of (commit2methods, modified_non_py_files, modified_py_files, all_vul_dict)
        """
        if extracted_urls_for_repo is None:
            extracted_urls_for_repo = {}
            
        repo = Git(repo_path)
        commit2methods = defaultdict(dict)
        modified_non_py_files, modified_py_files = [], []
        vulnerable_funcs_cnt = 0
        all_vul_dict = defaultdict(list)
        
        for fixing_commit in fixing_commits:
            logger.info(f'Processing commit {fixing_commit}')
            commit_hash_ = fixing_commit.split('/')[-1]
            
            # Cache commit objects
            diff_cached = DIFF_CACHE_DIR_DATE / f"{cve_id}/{commit_hash_}.pkl"
            if not diff_cached.parent.exists():
                diff_cached.parent.mkdir(parents=True, exist_ok=True)
            
            modified_files = None
            if diff_cached.exists():
                try:
                    logger.info(f'Loading commit {commit_hash_} from cache...')
                    with open(diff_cached, 'rb') as f:
                        commit_hash, modified_files = pickle.load(f)
                except Exception as e:
                    continue
                    
            if not modified_files:
                try:
                    commit = repo.get_commit(commit_hash_)
                    commit_hash = commit.hash
                except Exception as e:
                    logger.warning(f'Commit {commit_hash_} not found, skipping...')
                    continue
                
                # Extract code changes using get_modified_files from vul_analyze
                logger.debug(f'Extracting code changes for commit {commit_hash}...')
                from data_collection.vul_analyze import get_modified_files
                modified_files = get_modified_files(commit)
                try:
                    with open(diff_cached, 'wb') as f:
                        pickle.dump((commit_hash, modified_files), f)
                except Exception as e:
                    continue
            
            try:
                if not modified_files:
                    continue
                modified_non_py_files, modified_py_files = modified_files
                
                if len(modified_files) == 0:
                    logger.warning(f'No files modified in commit {commit_hash}')
                
                for file in modified_py_files:
                    logger.info(f'Processing file {file.old_path} in {commit_hash}')
                    # Use get_methods function from collect_changes
                    from data_collection.collect_changes import get_methods
                    all_vulnerable_methods = get_methods(file)
                    vulnerable_funcs_cnt += len(all_vulnerable_methods)
                    
                    # Process vul_dict
                    if hasattr(file, 'vul_dict'):
                        for type_, funcs in file.vul_dict.items():
                            if type_ in all_vul_dict:
                                all_vul_dict[type_].extend(funcs)
                    
                    commit2methods[fixing_commit][file.old_path] = all_vulnerable_methods
                    
                for file in modified_non_py_files:
                    commit2methods[fixing_commit][file.old_path] = []
                    
            except Exception as e:
                logger.error(f'Extracting {commit_hash} code changes error {cve_id}, skipping...')
                continue
        
        if vulnerable_funcs_cnt == 0:
            logger.debug(f"commit2methods:{commit2methods}")
            for file in modified_py_files:
                if (hasattr(file, 'changed_class_vars') and hasattr(file, 'changed_class_vars_before') and
                    hasattr(file, 'changed_global_vars') and hasattr(file, 'changed_global_vars_before')):
                    if (len(file.changed_class_vars) or len(file.changed_class_vars_before) or 
                        len(file.changed_global_vars) or len(file.changed_global_vars_before)):
                        logger.debug(f"changed_class_vars:{file.changed_class_vars}")
                        logger.debug(f"changed_class_vars_before:{file.changed_class_vars_before}")
                        logger.debug(f"changed_global_vars:{file.changed_global_vars}")
                        logger.debug(f"changed_global_vars_before:{file.changed_global_vars_before}")
        
        # Extract modified methods by source type
        commit2methods = self.extract_changed_methods_group_by_source_type(commit2methods, extracted_urls_for_repo)
        
        return commit2methods, modified_non_py_files, modified_py_files, all_vul_dict
    
    def extract_changed_methods_group_by_source_type(self, commit2methods: Dict, possible_urls: Dict) -> Dict:
        """
        Extract changed methods grouped by source type (commit, pull, issue).
        
        Args:
            commit2methods: Dictionary mapping commit URLs to their changed methods
            possible_urls: Dictionary of possible URLs categorized by source type
            
        Returns:
            Dictionary of changed methods prioritized by source type
        """
        commit_urls = possible_urls.get('commit', [])
        pull_urls = possible_urls.get('pull', [])
        issue_urls = possible_urls.get('issue', [])
        
        changed_methods_from_commit = {fixing_commit: commit2methods[fixing_commit] 
                                    for fixing_commit in commit_urls 
                                      if fixing_commit in commit2methods}
        
        if len(changed_methods_from_commit):
            return changed_methods_from_commit
        logger.warning(f'No code changes from commit')
        
        changed_methods_from_issue = {fixing_commit: commit2methods[fixing_commit] 
                                    for fixing_commit in issue_urls 
                                    if fixing_commit in commit2methods}
        if len(changed_methods_from_issue):
            return changed_methods_from_issue
        
        changed_methods_from_pull = {fixing_commit: commit2methods[fixing_commit] 
                                for fixing_commit in pull_urls 
                                if fixing_commit in commit2methods}
        if len(changed_methods_from_pull):
            return changed_methods_from_pull
        
        return {}

    def get_modified_files(self, commit: Commit) -> Tuple[List[ModifiedFile], List[ModifiedFile]]:
        """
        Get modified files from a commit, separated by Python and non-Python files.
        
        Args:
            commit: Commit object to analyze
            
        Returns:
            Tuple of (modified_non_py_files, modified_py_files)
        """
        try:
            modified_files = commit.modified_files
            if len(modified_files) == 0:
                logger.debug(f'No files modified in commit {commit.hash}')
                return [], []
            
            # Filter files using filter_files function from vul_analyze
            from data_collection.vul_analyze import filter_files
            modified_non_py_files, modified_py_files = filter_files(modified_files)
            return modified_non_py_files, modified_py_files
            
        except Exception as e:
            logger.warning(f'Error processing commit {commit.hash}: {e}')
            return [], []

    def filter_commits_by_criteria(self, candidate_vfc_infos: Dict[str, Any], 
                                  extracted_urls: Dict,
                                  repo_url: str,
                                  filter_large_vfcs: bool = True,
                                  priority_commit: bool = True,
                                  filter_large_files: bool = True) -> Dict[str, Any]:
        """
        Filter commits based on various criteria
        Based on filtering logic from collect_commits.py
        
        Args:
            candidate_vfc_infos: Candidate VFC information
            filter_large_vfcs: Filter commits with too many changes
            priority_commit: Prioritize direct commit references
            filter_large_files: Filter commits with large file changes
            
        Returns:
            Filtered VFC information
        """
        filtered_vfcs = {}
        fixing_commit2info={}
        for commit_url, commit_info in candidate_vfc_infos.items():
            if commit_info.get('get_commit_error', False):
                continue
            # Apply filtering criteria
            is_merge = commit_info.get('is_merge', False)
            has_source_code = commit_info.get('passed_source_code_check', False)
            has_py_source_code = commit_info.get('passed_py_source_code_check', False)
            not_has_exclude = commit_info.get('passed_exclude_check', False)
            if is_merge or not not_has_exclude or not has_py_source_code:
                continue
            if filter_large_files and commit_info['file_type_stats'].get('.py',0) > 10:
                logger.debug(f"Filtering VFC with large files: {commit_url}")
                continue
            fixing_commit2info[commit_url]=commit_info
        extracted_urls_for_repo = get_extracted_urls_for_repo(extracted_urls,repo_url)
        urls_from_commit = extracted_urls_for_repo.get('commit',[])
        new_fixing_commit2info = {}
        if priority_commit:
            for url in urls_from_commit:
                if url in fixing_commit2info:
                    new_fixing_commit2info[url]=fixing_commit2info[url]
            if len(new_fixing_commit2info):
                fixing_commit2info=new_fixing_commit2info

        if filter_large_vfcs and len(fixing_commit2info) > 10:
             return {}
        return fixing_commit2info

    def get_modification_files_for_vfc(self, fixing_commit_obj: Commit, fixing_commit_url: str, 
                                      cve_id: Optional[str] = None, rewrite: bool = False) -> Tuple[str, List[ModifiedFile]]:
        """
        Get modification files for vulnerability fixing commit with caching support.
        
        Args:
            fixing_commit_obj: The commit object to analyze
            fixing_commit_url: URL of the fixing commit
            cve_id: CVE identifier for cache organization
            rewrite: Whether to force rewrite cache
            
        Returns:
            Tuple of (commit_hash, modified_files)
        """
        logger.info(f'Processing commit {fixing_commit_url}')
        commit_hash = fixing_commit_obj.hash

        # Cache diff objects
        commit_hash_ = fixing_commit_url.split('/')[-1]
        diff_cached = DIFF_CACHE_DIR_DATE / f"{cve_id}/{commit_hash_}.pkl"
        if not diff_cached.parent.exists():
            diff_cached.parent.mkdir(parents=True, exist_ok=True)

        modified_files = None
        if diff_cached.exists() and not rewrite:
            logger.info(f'Loading commit {commit_hash} from cache...')
            try:
                with open(diff_cached, 'rb') as f:
                    commit_hash, modified_files = pickle.load(f)
            except Exception as e:
                logger.warning(f'Failed to load cache for {commit_hash}: {e}')
                modified_files = None
        
        if modified_files is None:        
            # Extract code changes
            logger.debug(f'Extracting {fixing_commit_url} code changes...')
            modified_files = fixing_commit_obj.modified_files
            try:
                with open(diff_cached, 'wb') as f:
                    pickle.dump((commit_hash, modified_files), f)
            except Exception as e:
                logger.warning(f'Failed to cache diff for {commit_hash}: {e}')
                try:
                    with open(diff_cached, 'wb') as f:
                        pickle.dump((commit_hash, []), f)
                except Exception:
                    pass  # If we can't cache, continue without caching
                    
        return commit_hash, modified_files
    
    def _is_source_code_file(self, file: ModifiedFile) -> bool:
        """
        Check if a modified file is a source code file that should be analyzed.
        
        Args:
            file: Modified file object
            
        Returns:
            bool: True if file should be analyzed
        """
        
        # Skip added or renamed files without old_path
        if file.change_type == ModificationType.ADD or not file.old_path or file.change_type == ModificationType.RENAME:
            return False
            
        # Skip files in excluded directories
        if any(f"{dir_}" in file.old_path.lower().split('/')[:-1] for dir_ in exclude_dirs):
            return False
            
        # Skip test files
        if 'test' in file.filename.lower():
            return False
            
        # Skip setup files
        if file.filename.lower() in ['setup.py', 'setup.cfg']:
            return False
        
        # Skip files with excluded suffixes
        if file.filename.lower().endswith(tuple(exclude_suffixes)):
            return False
            
        return True
    
    def filter_files(self, file_changes: List[ModifiedFile]) -> Tuple[List[ModifiedFile], List[ModifiedFile]]:
        """
        Filter file list to keep only source code files excluding test/example/documentation directories.
        
        Args:
            file_changes: List of modified files
            
        Returns:
            Tuple of (non_python_files, python_files)
        """
        filtered_files = [file for file in file_changes if self._is_source_code_file(file)]
        
        # Separate Python and non-Python files
        filtered_py = [file for file in filtered_files if file.filename.endswith('.py')]
        filtered_non_py = [file for file in filtered_files if not file.filename.endswith('.py')]
        
        logger.debug([file.filename for file in filtered_py])
        return filtered_non_py, filtered_py

    def is_source_code_modified(self, modified_files: List[ModifiedFile]) -> Tuple[List[ModifiedFile], List[ModifiedFile]]:
        """
        Check if source code files are modified in the commit.
        
        Args:
            modified_files: List of modified files
            
        Returns:
            Tuple of (modified_non_py_files, modified_py_files)
        """
        # logger.debug([file.new_path for file in modified_files])
        modified_non_py_files, modified_py_files = self.filter_files(modified_files)
        # logger.debug([file.new_path for file in modified_py_files])
        
        return modified_non_py_files, modified_py_files

    def extract_candidate_fixing_commit_infos(self, all_possible_urls: Set[str], repo_path: Path, 
                                            repo_url: str, advisory: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Extract candidate vulnerability fixing commit information from security advisory.
        
        Args:
            all_possible_urls: Set of possible commit URLs
            repo_path: Local repository path
            repo_url: Repository URL
            advisory: Security advisory information
            
        Returns:
            Dictionary containing VFC analysis results for each commit URL
        """
        # Initialize tracking variables
        if not hasattr(self, 'merge_commits'):
            self.merge_commits = defaultdict(list)
        if not hasattr(self, 'failed_repos_file'):
            self.failed_repos_file = 'failed_repos.txt'
            
        repo = Git(repo_path)
        all_vfc_infos = {}
        
        for commit_url in all_possible_urls:
            all_vfc_infos[commit_url] = {
                'passed_source_code_check': False,
                'passed_py_source_code_check': False,
                'passed_fix_check': False,
                'passed_exclude_check': False,
                'get_commit_error': False,
                'msg': '',
                'is_merge': False,
                'is_squash': False,
                'file_type_stats': {}
            }
            
            commit_hash = commit_url.rstrip('.').rstrip('.patch').split('/')[-1]
            
            # Validate commit URL matches repository
            if not str(commit_url).lower().startswith(str(repo_url).lower()):
                logger.error(f'Commit {commit_url} does not start with repo path {repo_url}')
                continue
                
            try:
                commit = repo.get_commit(commit_hash)
            except Exception as e:
                logger.warning(f'Commit {commit_hash} not found: {e}')
                try:
                    with open(self.failed_repos_file, 'a') as f:
                        f.write(f"{commit_url}\t{repo_path}\n")
                except Exception:
                    pass  # Continue if we can't write to failed repos file
                all_vfc_infos[commit_url]['get_commit_error'] = True
                continue
                
            # Check if merge commit
            if commit.merge:
                all_vfc_infos[commit_url]['is_merge'] = True
                msg = commit.msg
                if advisory:
                    self.merge_commits[advisory['id']].append({
                        'commit_url': commit_url,
                        'msg': msg,
                        'total_urls': len(all_possible_urls), 
                        'cve_id': advisory.get('cve_id', '')
                    })
                    
            # Check if squash commit
            if is_squash_commit(commit):
                all_vfc_infos[commit_url]['is_squash'] = True
                
            # Check commit message for fix keywords
            if is_fix_commit(commit):
                all_vfc_infos[commit_url]['passed_fix_check'] = True
            
            if not is_exclude_commit(commit):
                all_vfc_infos[commit_url]['passed_exclude_check'] = True
                
            # Check if source code is modified
            _, modified_files = self.get_modification_files_for_vfc(
                fixing_commit_obj=commit, 
                fixing_commit_url=commit_url, 
                cve_id=advisory.get('cve_id') if advisory else None,
                rewrite=True
            )
            
            modified_non_py_files, modified_py_files = self.is_source_code_modified(modified_files)
            
            logger.info(f"commit_url:{commit_url} modified_files:"
                       f"{[file.new_path for file in modified_non_py_files]} "
                       f"{[file.new_path for file in modified_py_files]}")

            # Calculate file type statistics
            file_type_stats = {}
            for file in modified_non_py_files + modified_py_files:
                file_path = Path(file.filename)
                file_ext = file_path.suffix if file_path.suffix else file_path.name
                file_type_stats[file_ext] = file_type_stats.get(file_ext, 0) + 1
                
            if modified_non_py_files or modified_py_files:
                all_vfc_infos[commit_url]['passed_source_code_check'] = True
                all_vfc_infos[commit_url]['passed_py_source_code_check'] = len(modified_py_files) > 0
                all_vfc_infos[commit_url]['file_type_stats'] = file_type_stats
                
            all_vfc_infos[commit_url]['msg'] = commit.msg.split('\n')
        # logger.info(all_vfc_infos)
        return all_vfc_infos
    def process_modified_file_joblib(self,modified_file):
        """Process a single modified file using joblib"""
        deleted_line_scope, added_line_scope = modified_file.get_code_changes_scopes()

        key_components = (
            getattr(modified_file, '_commit_hash', ''),
            modified_file.change_type.name,
            modified_file.old_path or '',
            modified_file.new_path or '',
        )
        file_id = '|'.join(key_components)
        logger.info(file_id)
        return (file_id, [deleted_line_scope, added_line_scope])
    def get_code_change_scope_for_all(self, cve_id: str, fixing_commits: List[str], 
                                     repo_path: str, rewrite: bool = False) -> Dict[str, Any]:
        """
        Get code change scope for all fixing commits of a CVE.
        
        Args:
            cve_id: CVE identifier
            fixing_commits: List of fixing commit URLs
            repo_path: Path to the repository
            rewrite: Whether to rewrite existing cache
            
        Returns:
            Dictionary containing scope analysis for all commits
        """
        scope_cache_dir = Path(SCOPE_CACHE_DIR_DATE)
        scope_cache_dir.mkdir(parents=True, exist_ok=True)
        scope_cache_file = scope_cache_dir / f"{cve_id}.json"
        
        commit2file2scope = defaultdict(dict)
        git_repo = Git(repo_path)
        for fixing_commit in fixing_commits:
            fixing_commit_ = fixing_commit.split('/')[-1]
            diff_cached = DIFF_CACHE_DIR_DATE / f"{cve_id}/{fixing_commit_}.pkl"
            logger.info(f"processing {fixing_commit}")
            with open(diff_cached, 'rb') as f:
                commit_hash,modified_files = pickle.load(f)
            _, modified_py_files = self.is_source_code_modified(modified_files)
            if len(modified_py_files) ==0:
                continue
            scope_cached = SCOPE_CACHE_DIR_DATE / f"{cve_id}/{fixing_commit_}.pkl"
            if not scope_cached.parent.exists():
                scope_cached.parent.mkdir(parents=True, exist_ok=True)
            if scope_cached.exists() and True:
                with open(scope_cached, 'rb') as f:
                    file2scope = pickle.load(f)
                commit2file2scope[fixing_commit_] = file2scope
            else:
                file2scope = {}
                results = Parallel(n_jobs=1,backend='threading')(
                        delayed(self.process_modified_file_joblib)(mf) for mf in modified_py_files
                    )
                
                # Build result dictionary
                file2scope = {}
                for result in results:
                    if result:
                        file_id, scope_data = result
                        file2scope[file_id] = scope_data
                logger.info(file2scope)
                with open(scope_cached,'wb') as f:
                    pickle.dump(file2scope,f)
                commit2file2scope[fixing_commit_]=file2scope
        return commit2file2scope
        


    def extract_vulnerable_funcs_for_func_scope(self,file:ModifiedFile):
        vfs_dict = {
                'old_method_direct_modified_by_deleted_lines':set(),
                'old_method_only_modified_by_added_lines':set(),
                'special_method_only_existed_in_new_file':set(),
                'added_methods_replace_same_name_old_methods':set(),
            }
        
        logger.debug(f"changed line, added:{file.cleaned_added_lines}, deleted:{file.cleaned_deleted_lines}")
        # get func, class, and vars
        # file.get_class_and_function_and_var_list()
        old_methods_changed:List[Method] = file.methods_changed_old
        new_methods_changed:List[Method] = file.methods_changed_new
        old_methods:List[Method] = file.methods_before
        new_methods:List[Method] = file.methods
        # 1. function-scope 
        # 1.1 functions modified by deleted lines (may modified by added lines  simultaneously)
        old_methods_changed_long_names:List[str] = {
            y.long_name
            for y in old_methods_changed
        }
        # vul_dict['old_method_direct_modified_by_deleted_lines'] = {old_method.long_name for old_method in old_methods_changed}
        vfs_dict['old_method_direct_modified_by_deleted_lines'] = {old_method for old_method in old_methods_changed}
        vulnerable_methods= set(old_methods_changed)

        # 1.2 functions explicitly declared in old file, ONLY modified by added lines.
        new_changed_method_long_names:List[Str] = {
            y.long_name
            for y in new_methods_changed
        }
        for old_method in old_methods:
            # if only modified by by added lines.
            if old_method.long_name in new_changed_method_long_names and old_method.long_name not in old_methods_changed_long_names:
                vulnerable_methods.add(old_method)
                # vulnerable_methods_long_names.add(method.long_name)
                vfs_dict['old_method_only_modified_by_added_lines'].add(old_method)
        
        # 1.3 functions implicitly declared in old file, such as special methods (which ONLY explicitly be declared only in new file), for a class existed in old file.
        # classes existed in old file.
        classes_before_long_names:List[str] = [cls.long_name for cls in file.classes_before]
        logger.debug(f"classes_before:{classes_before_long_names}")

        # methods changed by added lines->modified special methods.
        for method in new_methods_changed:
            if not file._is_special_method(method):
                continue
            
            # ONLY focus the classes existed in old file
            first_parent_class = method.first_parent_class
            if not first_parent_class or first_parent_class not in classes_before_long_names:
                continue
            
            # vulnerable_methods_long_names.add(method.long_name)
            vulnerable_methods.add(method)
            vfs_dict['special_method_only_existed_in_new_file'].add(method)

        # 1.4 Newly added functions replace existing functions in the old file with the same name, and other existing functions in the old file call the added functions
        old_method_long_names = {
            y.long_name
            for y in old_methods
        }
        # get the added functions
        added_methods = []
        for method_long_name in new_changed_method_long_names:
            if method_long_name not in old_method_long_names:
                added_methods.append(method_long_name)
        logger.info(f"added_methods:{added_methods}")
        # search the caller in old_file for added_methods based on the CG for new_file
        for new_method in new_methods:
            caller = new_method.long_name
            # check if method with the same long name as new_method exists in old_file
            logger.info(f"caller:{caller}, {caller not in old_method_long_names or caller in added_methods}")
            if caller not in old_method_long_names or caller in added_methods:
                continue
            callees = file.cg.get(caller,[])
            logger.info(f"callees:{callees}")
            inter = set(callees)&set(added_methods)
            if inter:
                # vulnerable_methods_long_names.add(caller)
                # vulnerable_methods.add(method)
                # get_old_method_obj:
                for old_method in old_methods:
                    if old_method.long_name == caller:
                        old_method_obj = old_method
                        break
                if old_method in vulnerable_methods:
                    # has been capture by previous steps:
                    continue
                # print(caller)
                # print(file.cg)
                vfs_dict['added_methods_replace_same_name_old_methods'].add(old_method_obj)
        return vfs_dict

    def filter_vulnerable_methods(self,file:ModifiedFile,vulnerable_methods):
        filtered_methods = []

        # Check if they are exactly the same after removing whitespace characters
        methods_changed_new = {
            new_method.long_name:new_method
            for new_method in  file.methods_changed_new
        }
        methods_changed_old = {
            old_method.long_name:old_method
            for old_method in  file.methods_changed_old
        }
        
        for method in vulnerable_methods:
            if not method.long_name:  # Handle empty name case
                continue
                
            old_method = methods_changed_old.get(method.long_name)
            new_method = methods_changed_new.get(method.long_name)
            
            if old_method and new_method:  # Ensure both methods exist
                code1 = old_method.code
                code2 = new_method.code
                # print(code1)
                # print(code2)
                normalized1 = self.func_comparator.normalize_function_body(code1)
                normalized2 = self.func_comparator.normalize_function_body(code2)
                # print(normalized1)
                # print(normalized2)
                    
                if normalized1 != normalized2:
                    filtered_methods.append(method)
            else:
                filtered_methods.append(method)
        return filtered_methods

    def get_vulnerable_funcs_for_file(self, file:ModifiedFile,scope_lines):
        vfs_dict = {
                'old_method_direct_modified_by_deleted_lines':set(),
                'old_method_only_modified_by_added_lines':set(),
                'special_method_only_existed_in_new_file':set(),
                'added_methods_replace_same_name_old_methods':set(),
                'module_vars_impact_functions':set(),
                'class_vars_impact_functions':set(),
                'module_called_functions':set(),
            }
    
        # !1.function-scope
        file.get_code_changes_scopes()
        vfs_dict_func:Dict[List[Method]]= self.extract_vulnerable_funcs_for_func_scope(file=file)
        vfs_dict.update(vfs_dict_func)
        # !1.1 filter_methods, since functions has dependency with vars may keep the same body.
        vulnerable_methods = set()
        for cate, methods in vfs_dict.items():
            vulnerable_methods.update(methods)
        # Judge whether there are real changes based on the body to reduce FP (refactoring, docs, multi-line comments)
        filtered_vulnerable_methods = self.filter_vulnerable_methods(file,vulnerable_methods)
        filtered_vulnerable_methods_long_names = [method.long_name for method in filtered_vulnerable_methods]
        # !2.class-scope, module-scope, e.g., CVE-2024-27351
        # Ensure code changes scopes are analyzed before accessing the attributes
        file.get_code_changes_scopes()
        changed_module_vars = file.changed_module_vars
        changed_class_vars = file.changed_class_vars

        logger.debug(f"changed_module_vars: {[var.long_name for var in changed_module_vars]}")
        logger.debug(f"changed_class_vars: {[var.long_name for var in changed_class_vars]}")
        # 2.1 find the vars existed in the old file

        if len(changed_module_vars) or len(changed_class_vars):
            # 1. for each function, get use-def
            var_tracker = ScopeAwareDependencyTracker(file=file)
            module_impact_functions,class_impact_functions = var_tracker.analyze_variable_impact_functions()
            if len(module_impact_functions):
                logger.info(f"module_impact_functions: {[func.long_name for func in module_impact_functions]}")
                vfs_dict['module_vars_impact_functions'] = module_impact_functions
                filtered_vulnerable_methods.extend(module_impact_functions)
                filtered_vulnerable_methods_long_names.extend([func.long_name for func in module_impact_functions])
            if len(class_impact_functions):
                logger.info(f"class_impact_functions: {[func.long_name for func in class_impact_functions]}")
                vfs_dict['class_vars_impact_functions'] = class_impact_functions
                filtered_vulnerable_methods.extend(class_impact_functions)
                filtered_vulnerable_methods_long_names.extend([func.long_name for func in class_impact_functions])
        
        filtered_vulnerable_methods = list(set(filtered_vulnerable_methods))
        filtered_vulnerable_methods_long_names = list(set(filtered_vulnerable_methods_long_names))
        # ! 4. methods called at module-level
        module_level_callee = file._function_list_before_called_top_level
        
        for callee in module_level_callee:
            if callee in filtered_vulnerable_methods_long_names:
                main_func = file._generate_module_main()
                filtered_vulnerable_methods.append(main_func)
                filtered_vulnerable_methods_long_names.append(main_func.long_name)
                vfs_dict['module_called_functions'].add(callee)
        if len(module_level_callee) and len(vfs_dict['module_called_functions']):
            logger.debug(f"module_level_callee: {module_level_callee}")
            logger.debug(f"vul_dict['module_called_functions']:{vfs_dict['module_called_functions']}")
            # assert False
        return filtered_vulnerable_methods,vulnerable_methods,vfs_dict


    def get_vulnerable_functions_for_all(self, cve_id: str, fixing_commits: List[str], commit2file2scope: Dict[str,Dict],
                                       repo_url: str, rewrite: bool = False) -> Dict[str, Any]:
        """
        Get vulnerable functions for all fixing commits of a CVE.
        
        Args:
            cve_id: CVE identifier
            fixing_commits: List of fixing commit URLs
            repo_path: Path to the repository
            rewrite: Whether to rewrite existing cache
            
        Returns:
            Dictionary containing vulnerable functions analysis
        """
        vul_func_cache_dir = Path(DATA_DIR) / "vulnerable_functions" / COMMITS_DIR_DATE
        vul_func_cache_dir.mkdir(parents=True, exist_ok=True)
        vul_func_cache_file = vul_func_cache_dir / f"{cve_id}.json"
        
        if vul_func_cache_file.exists() and not rewrite:
            try:
                with open(vul_func_cache_file, 'r', encoding='utf-8') as f:
                    cached_data = json.load(f)
                logger.info(f"Loaded cached vulnerable functions data for {cve_id}")
                return cached_data
            except Exception as e:
                logger.warning(f"Failed to load cached vulnerable functions data for {cve_id}: {e}")

        repo_name = get_repo_name(repo_url)
        
        logger.debug(f'Processing {repo_url}, {len(fixing_commits)} fixing_commits')
        code_changes_path = CODE_CHANGES_DIR_DATE / f'{cve_id}_{repo_name}.json'
        code_changes_dict_path = CODE_CHANGES_DIR_DATE / f'{cve_id}_{repo_name}_dict.pkl'
        if not code_changes_path.parent.exists():
                code_changes_path.parent.mkdir(parents=True)
        if code_changes_path.exists() and code_changes_dict_path.exists() and True:
            logger.info(f'Code changes for {cve_id} {repo_name} already exists, skipping...')
            with code_changes_dict_path.open('rb') as f:
                commit2methods_dict = pickle.load(f)
        else:
            commit2methods=defaultdict(dict)
            commit2methods_dict=defaultdict(dict)
            cves_has_filter_func=set()
            for fixing_commit in fixing_commits:
                logger.debug(f"Processing {fixing_commit}")
                commit_hash_ = fixing_commit.split('/')[-1]
                diff_cached = DIFF_CACHE_DIR_DATE / f"{cve_id}/{commit_hash_}.pkl" # may different commit_hash_ getting from git command
                with open(diff_cached, 'rb') as f:
                    _, modified_files  = pickle.load(f)
                _, modified_py_files = self.is_source_code_modified(modified_files)
                if len(modified_py_files) == 0:
                    continue
                file2scope = commit2file2scope[commit_hash_]
                file2methods = {}
                file2methods_dict={}
                for modified_file in modified_py_files:
                    key_components = (
                            getattr(modified_file, '_commit_hash', ''),
                            modified_file.change_type.name,
                            modified_file.old_path or '',
                            modified_file.new_path or '',
                        )
                    file_id = '|'.join(key_components)
                    # print(file2scope, cve_id)
                    filtered_vulnerable_funcs, vulnerable_funcs,vfs_dict  = self.get_vulnerable_funcs_for_file(modified_file,file2scope[file_id])
                    if len(filtered_vulnerable_funcs) < len(vulnerable_funcs):
                        cves_has_filter_func.add(cve_id)
                    if len(filtered_vulnerable_funcs):
                        file2methods[modified_file.filename] = [method.long_name for method in filtered_vulnerable_funcs]
                        file2methods_dict[modified_file.filename] = vfs_dict
                commit2methods[fixing_commit]=file2methods
                commit2methods_dict[fixing_commit]=file2methods_dict
            with open(code_changes_path, 'w') as f:
                json.dump((commit2methods), f)
            with open(code_changes_dict_path, 'wb') as f:
                pickle.dump((commit2methods_dict), f)
            with code_changes_path.open('r') as f:
                commit2methods = json.load(f)
            with code_changes_dict_path.open('rb') as f:
                commit2methods_dict = pickle.load(f)
        return commit2methods_dict

    def extract_repo_url_from_package(self, package_name: str, advisory: Dict) -> Optional[str]:
        """
        Extract repository URL for a package from pkg2repo mapping, PyPI metadata and advisory references
        Based on collect_vuls.py logic
        
        Args:
            package_name: Package name
            advisory: Advisory information
            
        Returns:
            Repository URL or None if not found
        """
        
        try:
            # First, check pkg2repo mapping
            package_name_lower = package_name.lower()
            if package_name_lower in self.pkg2repo_mapping:
                repo_url = self.pkg2repo_mapping[package_name_lower]
                logger.info(f"Found repository URL for {package_name} in pkg2repo mapping: {repo_url}")
                return repo_url
            
            # If not found in mapping, fall back to PyPI metadata and advisory references
            logger.info(f"Package {package_name} not found in pkg2repo mapping, trying PyPI metadata")
            
            # Get references from advisory
            refs = advisory.get('references', [])
            refs = [ref['url'] if isinstance(ref, dict) else ref for ref in refs]
            
            # Get metadata from PyPI
            response = request_metadata_json_from_pypi(package_name)
            if response.status_code != 200:
                logger.warning(f'Failed to get PyPI metadata for {package_name}')
                all_possible_urls = refs
            else:
                response_data = response.json()
                if 'info' in response_data:
                    info = response_data['info']
                    project_urls = info.get('project_urls', {})
                    homepage = info.get('home_page', '')
                    
                    all_possible_urls = [homepage] if homepage else []
                    if project_urls:
                        if project_urls.get('Source'):
                            all_possible_urls.append(project_urls.get('Source'))
                        else:
                            all_possible_urls.extend(list(project_urls.values()))
                    
                    # Use advisory references as primary source
                    all_possible_urls = refs
                else:
                    all_possible_urls = refs
            
            # Filter GitHub URLs
            github_urls = set([url for url in all_possible_urls 
                             if url and urlparse(url).netloc == 'github.com'])
            
            if not github_urls:
                return None
            
            def get_repository_from_url(url):
                """Extract repository URL from GitHub URL"""
                parsed_url = urlparse(url)
                path_parts = parsed_url.path.strip('/').split('/')
                
                # Skip sponsor URLs
                if path_parts[0] == 'sponsors':
                    return None
                    
                if len(path_parts) >= 2:
                    return ('https://github.com/' + '/'.join(path_parts[0:2])).removesuffix('.git')
                return None
            
            repo_urls = set([url.lower() for url in 
                           [get_repository_from_url(url) for url in github_urls] if url])
            repo_urls = [url for url in repo_urls if 'pypa' not in url and 
            'advisory-database' not in url]
            
            if len(repo_urls) > 1:
                logger.warning(f'Multiple repo URLs found for {package_name}: {repo_urls}')
                # Take the first one for now
                return repo_urls.pop()
            elif len(repo_urls) == 1:
                return repo_urls.pop()
            else:
                return None
                
        except Exception as e:
            logger.error(f'Error extracting repo URL for {package_name}: {e}')
            return None

    def process_cve_commits(self, cve_id: str, advisory: Dict, 
                           rewrite_all_fixing_commits: bool = False,
                           filter_large_source: bool = False) -> Dict[str, Dict]:
        """
        Process commits for a single CVE
        Based on the main processing logic from collect_commits.py
        
        Args:
            cve_id: CVE identifier
            advisory: Advisory information
            rewrite_all_fixing_commits: Whether to rewrite existing commit files
            filter_large_source: Whether to filter large PR/Issue sources
            
        Returns:
            Dictionary mapping package names to VFC information
        """
        logger.info(f"Processing commits for {cve_id}")
        
        # Get possible commit URLs
        possible_commit_file = POSSIBLE_COMMITS_DIR_DATE / f"{cve_id}.json"
        if not possible_commit_file.exists():
            logger.warning(f'No possible commits file found for {cve_id}')
            return cve_id, {}, {}
            
        with possible_commit_file.open('r') as f:
            extracted_urls = json.load(f)
        
        # Extract repo URLs for all affected packages and update advisory structure
        advisory_copy = advisory.copy()
        available_affected = advisory_copy.get('available_affected', {})
        if len(available_affected) == 0:
            return cve_id, {}, {}
        # Process each package to extract repo_url and update advisory structure
        updated_available_affected = {}
        for package_name, versions in available_affected.items():
            logger.info(f"Extracting repo URL for package: {package_name}")
            
            # Extract repo URL
            repo_url = self.extract_repo_url_from_package(package_name, advisory_copy)
            
            if repo_url:
                # Update the advisory structure to include repo_url
                self.pkg2repo_mapping[package_name]=repo_url
                updated_available_affected[package_name] = {
                    'repo_url': repo_url,
                    'versions': versions if isinstance(versions, list) else [versions]
                }
                logger.info(f"Found repo URL for {package_name}: {repo_url}")
            else:
                logger.warning(f"No repo URL found for {package_name}")
        
        # Update advisory with only packages that have repo_url
        advisory_copy['available_affected'] = updated_available_affected
        
        if not advisory_copy['available_affected']:
            logger.warning(f"No packages with repo URLs found for {cve_id}")
            return cve_id, {}, {}
        
        # Get all unique affected projects using the same logic as collect_commits.py
        all_unique_affected_projects = get_all_unique_affected_projects(advisory_copy)
        logger.info(f"Found {len(all_unique_affected_projects)} unique affected projects")
        
        cve_vfc_infos = {}
        
        # Process each package with extracted repo URL
        for package_name, repo_url in all_unique_affected_projects:
            logger.info(f"Processing package: {package_name}, repo: {repo_url}")
            
            candidate_vfc_info_file = COMMITS_DIR_DATE / f'{cve_id}_{package_name}_candidate_vfc_infos.json'
            
            if not candidate_vfc_info_file.parent.exists():
                candidate_vfc_info_file.parent.mkdir(parents=True, exist_ok=True)
                
            if not rewrite_all_fixing_commits and candidate_vfc_info_file.exists() and True:
                # Load existing candidate VFC infos
                with candidate_vfc_info_file.open('r') as f:
                    candidate_vfc_infos = json.load(f)
            else:
                # Extract new candidate VFC infos
                if repo_url is None:
                    logger.warning(f'No repo url found for {package_name}')
                    continue
                    
                repo_path = REPO_DIR_DATE / get_repo_name(repo_url)
                
                # Get extracted URLs for this repository
                extracted_urls_for_repo = get_extracted_urls_for_repo(
                    extracted_urls, repo_url, filter_large=filter_large_source
                )
                
                if sum(len(urls) for urls in extracted_urls_for_repo.values()) == 0:
                    logger.warning(f'No fixing commits found for {package_name}')
                    candidate_vfc_infos = {}
                else:
                    logger.debug(f'Found {sum(len(urls) for urls in extracted_urls_for_repo.values())} fixing commits for {package_name}')
                    
                    # Clone repository if needed
                    # if repo_path.exists():
                    if not self.clone_repository(repo_url, repo_path):
                        continue
                        
                    # Extract candidate VFC infos
                    all_possible_urls = set(chain.from_iterable(extracted_urls_for_repo.values()))
                    candidate_vfc_infos = self.extract_candidate_fixing_commit_infos(
                        all_possible_urls, repo_path, repo_url, advisory
                    )
                
                # Save candidate VFC infos
                with open(candidate_vfc_info_file, 'w') as f:
                    json.dump(candidate_vfc_infos, f)
                
            
            if candidate_vfc_infos:
                cve_vfc_infos[package_name] = (repo_url, candidate_vfc_infos)
                
        return cve_id, cve_vfc_infos, advisory_copy


class PatchParser:
    """
    Main class for parsing patches and analyzing vulnerability fixes
    Integrates CommitProcessor and PatchAnalyzer functionality
    """
    
    def __init__(self, output_dir: Optional[Path] = None):
        """
        Initialize PatchParser
        
        Args:
            output_dir: Directory to store analysis results
        """
        self.output_dir = output_dir or (DATA_DIR / SUFFIX)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # File paths
        self.commits_analysis_file = self.output_dir / "commits_analysis.json"
        self.changes_analysis_file = self.output_dir / "changes_analysis.json"

        # cve2advisory file
        self.cve2advisory_file = self.output_dir / f"cve2advisory.pkl"
        self.new_cve2advisory_file = self.output_dir / f"cve2advisory_enhanced.pkl"
        
        # Load pkg2repo mapping
        self.pkg2repo_mapping = self._load_pkg2repo_mapping()

        # Initialize processors
        self.commit_processor = CommitProcessor(self.pkg2repo_mapping)        

    def _load_pkg2repo_mapping(self) -> Dict[str, str]:
        """
        Load package to repository URL mapping from pkg2repo.json file
        
        Returns:
            Dictionary mapping package names to repository URLs
        """
        pkg2repo_file = PROJECT_ROOT / "src/pkg2repo.json"
        
        if pkg2repo_file.exists():
            try:
                with open(pkg2repo_file, 'r', encoding='utf-8') as f:
                    pkg2repo = json.load(f)
                    # Convert keys to lowercase for case-insensitive lookup
                    pkg2repo = {k.lower(): v for k, v in pkg2repo.items()}
                    logger.info(f"Loaded {len(pkg2repo)} package-to-repo mappings from {pkg2repo_file}")
                    return pkg2repo
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Failed to load pkg2repo mapping from {pkg2repo_file}: {e}")
                return {}
        else:
            logger.warning(f"pkg2repo.json file not found at {pkg2repo_file}")
            return {}
    def _save_pkg2repo_mapping(self) -> Dict[str, str]:
        """
        Save package to repository URL mapping to pkg2repo.json file
        
        Returns:
            Dictionary mapping package names to repository URLs
        """
        pkg2repo_file = PROJECT_ROOT / "src/pkg2repo.json"
        with pkg2repo_file.open('w') as f:
            json.dump(self.pkg2repo_mapping,f)
    def load_cve2advisory(self, force_update: bool = False) -> Optional[Dict[str, Dict]]:
        """
        Load CVE to advisory mapping from cached file
        Reference the fetch_vul_records_from_osv method in vulnerability_collector.py
        
        Args:
            force_update: Force re-download and re-process data (not implemented here)
            
        Returns:
            Dictionary mapping CVE IDs to advisory information, or None if not found
        """

        if not self.cve2advisory_file.exists():
            logger.warning(f"CVE2advisory file not found at {self.cve2advisory_file}")
            logger.info("Please run vulnerability_collector.py first to generate the CVE2advisory mapping")
            print("Error: CVE2advisory file not found, please run vulnerability_collector.py first to generate data")
            return None
            
        try:
            logger.info(f"Loading cached CVE2advisory mapping from {self.cve2advisory_file}")
            with open(self.cve2advisory_file, 'rb') as f:
                cve2advisory = pickle.load(f)
            
            logger.info(f"Loaded {len(cve2advisory)} CVE records")
            return cve2advisory
            
        except Exception as e:
            logger.error(f"Failed to load CVE2advisory mapping: {e}")
            print(f"Error: Failed to load CVE2advisory mapping: {e}")
            return None
        

    def process_possible_commit_urls(self, cve2advisory: Dict[str, Dict], 
                                   rewrite_all_fixing_commits: bool = False,
                                   filter_large_source: bool = False,
                                   n_jobs: int = 1) -> Dict[str, Dict]:
        """
        Process possible commit URLs collected by vulnerability_collector.py
        Based on the main processing logic from collect_commits.py
        
        Args:
            cve2advisory: Dictionary mapping CVE IDs to advisory information
            rewrite_all_fixing_commits: Whether to rewrite existing commit files
            filter_large_source: Whether to filter large PR/Issue sources
            n_jobs: Number of parallel jobs
            
        Returns:
            Dictionary mapping CVE IDs to processed commit information
        """
        logger.info(f"Processing possible commit URLs for {len(cve2advisory)} CVEs...")
        print(f"Processing possible commit URLs for {len(cve2advisory)} CVEs...")
        
        # Sequential processing
        print("Using sequential processing mode for commits...")
        processed_commits = {}
        new_cve2advisory = {}

        for cve_id, advisory in tqdm(cve2advisory.items(), desc="Processing CVE commits"):
            ret = self.commit_processor.process_cve_commits(
                cve_id, advisory, rewrite_all_fixing_commits, filter_large_source
            )
            if len(ret[1]):
                processed_commits[ret[0]] = ret[1]
                new_cve2advisory[ret[0]] = ret[-1]

        
        logger.info(f"Completed processing commits for {len(processed_commits)} CVEs")
        print(f"Completed processing commit information for {len(processed_commits)} CVEs")
        self._save_pkg2repo_mapping()
        with self.new_cve2advisory_file.open('wb') as f:
            pickle.dump(new_cve2advisory,f)
        print(f"Save new cve2advisory to {self.new_cve2advisory_file}")
        return processed_commits

    def analyze_code_changes(self, processed_commits: Dict[str, Dict]) -> Dict[str, Dict]:
        """
        Analyze code changes in the processed commits
        Based on functionality from collect_changes.py
        
        Args:
            processed_commits: Processed commit information
            
        Returns:
            Dictionary containing code change analysis results
        """
        logger.info("Analyzing code changes...")
        print("Analyzing code changes...")
        
        changes_analysis = {}
        
        for cve_id, cve_commits in tqdm(processed_commits.items(), desc="Analyzing changes"):
            cve_changes = {}
            
            for package_name, (repo_url, commit_infos) in cve_commits.items():
                package_changes = {}
                
                for fixing_commit, commit_info in commit_infos.items():
                    commit_changes = {
                        'files': [],
                        'scope_summary': {'function': 0, 'class': 0, 'module': 0},
                        'vulnerable_functions': [],
                        'ast_changes': []
                    }
                    logger.info(f'Processing commit {fixing_commit}')
                    commit_hash_ = fixing_commit.split('/')[-1]
                    # logger.info(f'Processing commit {commit_hash}')
                    diff_cached = DIFF_CACHE_DIR_DATE / f"{cve_id}/{commit_hash_}.pkl"
                    if not diff_cached.parent.exists():
                        diff_cached.parent.mkdir(parents=True, exist_ok=True)
                    
                    modified_files = None
                    if diff_cached.exists():
                        try:
                            logger.info(f'Loading commit {commit_hash_} from cache...')
                            with open(diff_cached, 'rb') as f:
                                commit_hash,modified_files = pickle.load(f)
                        except Exception as e:
                            continue
                    # Analyze each modified file
                    for file_info in modified_files:
                        if file_info.get('filename', '').endswith('.py'):
                            file_analysis = {
                                'filename': file_info.get('filename'),
                                'scope': 'unknown',  # Would need full file content to determine
                                'vulnerable_functions': [],
                                'ast_changes': {}
                            }
                            
                            commit_changes['files'].append(file_analysis)
                    
                    package_changes[fixing_commit] = commit_changes
                
                cve_changes[package_name] = package_changes
            
            changes_analysis[cve_id] = cve_changes
        
        logger.info(f"Completed code change analysis for {len(changes_analysis)} CVEs")
        print(f"Completed code change analysis for {len(changes_analysis)} CVEs")
        return changes_analysis

    def analyze_code_change_scope_for_all(self, processed_commits: Dict[str, Dict], 
                                        rewrite: bool = False) -> Dict[str, Dict]:
        """
        Analyze code change scope for all processed commits.
        
        Args:
            processed_commits: Processed commit information
            rewrite: Whether to rewrite existing cache
            
        Returns:
            Dictionary containing scope analysis for all CVEs
        """
        logger.info("Analyzing code change scope for all CVEs...")
        
        scope_analysis_results = {}
        
        for cve_id, cve_commits in tqdm(processed_commits.items(), desc="Analyzing scope"):
            cve_scope_data = {}
            
            for package_name, (repo_url, commit_infos) in cve_commits.items():
                # Get repository path
                repo_name = get_repo_name(repo_url)
                repo_path = REPO_DIR_DATE / repo_name
                
                if not repo_path.exists():
                    logger.warning(f"Repository not found: {repo_path}")
                    continue
                
                # Get fixing commits
                fixing_commits = list(commit_infos.keys())
                
                # Analyze scope for this package
                commit2file2scope = self.commit_processor.get_code_change_scope_for_all(
                    cve_id, fixing_commits, str(repo_path), rewrite
                )
                
                cve_scope_data[package_name] = commit2file2scope
            
            scope_analysis_results[cve_id] = cve_scope_data
        logger.info(f"Completed scope analysis for {len(scope_analysis_results)} CVEs")
        return scope_analysis_results

    def analyze_vulnerable_functions_for_all(self, processed_commits: Dict[str, Dict], scope_analysis: Dict[str, Dict],
                                           rewrite: bool = False) -> Dict[str, Dict]:
        """
        Analyze vulnerable functions for all processed commits.
        
        Args:
            processed_commits: Processed commit information
            rewrite: Whether to rewrite existing cache
            
        Returns:
            Dictionary containing vulnerable functions analysis for all CVEs
        """
        logger.info("Analyzing vulnerable functions for all CVEs...")
        
        vul_func_results = {}
        
        for cve_id, cve_commits in tqdm(processed_commits.items(), desc="Analyzing vulnerable functions"):
            cve_vul_data = {}
            
            for package_name, (repo_url, commit_infos) in cve_commits.items():
                # Get repository path
                repo_name = get_repo_name(repo_url)
                repo_path = REPO_DIR_DATE / repo_name
                
                if not repo_path.exists():
                    logger.warning(f"Repository not found: {repo_path}")
                    continue
                
                # Get fixing commits
                fixing_commits = list(commit_infos.keys())
                
                # Analyze vulnerable functions for this package
                commit2file2scope = scope_analysis[cve_id][package_name]
                vul_func_data = self.commit_processor.get_vulnerable_functions_for_all(
                    cve_id, fixing_commits, commit2file2scope, repo_url, rewrite
                )
                cve_vul_data[package_name] = {
                    'repo_url': repo_url,
                    'vulnerable_functions_data': vul_func_data
                }

            
            vul_func_results[cve_id] = cve_vul_data
        
        logger.info(f"Completed vulnerable functions analysis for {len(vul_func_results)} CVEs")
        return vul_func_results

    def print_vulnerable_functions_summary(self, vul_func_analysis: Dict[str, Dict]):
        """
        Print a detailed summary of vulnerable functions for all CVEs.
        
        Args:
            vul_func_analysis: Vulnerable functions analysis results
        """
        print("\n" + "="*80)
        print("📋 VULNERABLE FUNCTIONS SUMMARY")
        print("="*80)
        
        total_cves = len(vul_func_analysis)
        total_functions = 0
        cves_with_functions = 0
        
        for cve_id, cve_data in vul_func_analysis.items():
            cve_functions = 0
            cve_packages = 0
            
            print(f"\n🔍 CVE: {cve_id}")
            print("-" * 60)
            
            for package_name, package_data in cve_data.items():
                if 'vulnerable_functions_data' not in package_data:
                    continue
                    
                cve_packages += 1
                vf_data = package_data['vulnerable_functions_data']
                repo_url = package_data['repo_url']
                
                package_functions = 0
                print(f"  📦 Package: {package_name}")
                print(f"     Repository: {repo_url}")
                
                for fixing_commit, commit_data in vf_data.items():
                    if not isinstance(commit_data, dict):
                        continue
                    
                    commit_functions = 0
                    commit_short = fixing_commit.split('/')[-1][:8] if '/' in fixing_commit else fixing_commit[:8]
                    
                    for file_name, file_vf_data in commit_data.items():
                        if not isinstance(file_vf_data, dict):
                            continue
                        
                        file_functions = 0
                        function_details = []
                        
                        for strategy, functions in file_vf_data.items():
                            if functions and len(functions) > 0:
                                file_functions += len(functions)
                                # Extract function names if they are objects with long_name attribute
                                func_names = []
                                for func in functions:
                                    if hasattr(func, 'long_name'):
                                        func_names.append(func.long_name)
                                    elif isinstance(func, str):
                                        func_names.append(func)
                                    else:
                                        func_names.append(str(func))
                                
                                if func_names:
                                    function_details.append(f"{strategy}: {', '.join(func_names)}")
                        
                        if file_functions > 0:
                            print(f"     📄 {file_name} ({file_functions} functions)")
                            for detail in function_details:
                                print(f"        • {detail}")
                            commit_functions += file_functions
                    
                    if commit_functions > 0:
                        print(f"     🔧 Commit {commit_short}: {commit_functions} functions")
                        package_functions += commit_functions
                
                if package_functions > 0:
                    print(f"     ✅ Total functions in package: {package_functions}")
                    cve_functions += package_functions
                else:
                    print(f"     ❌ No vulnerable functions found in package")
            
            if cve_functions > 0:
                print(f"  🎯 CVE Total: {cve_functions} functions across {cve_packages} packages")
                cves_with_functions += 1
                total_functions += cve_functions
            else:
                print(f"  ❌ No vulnerable functions found in CVE")
        
        print("\n" + "="*80)
        print("📊 OVERALL STATISTICS")
        print("="*80)
        print(f"Total CVEs analyzed: {total_cves}")
        print(f"CVEs with vulnerable functions: {cves_with_functions}")
        print(f"CVEs without vulnerable functions: {total_cves - cves_with_functions}")
        print(f"Total vulnerable functions extracted: {total_functions}")
        if total_cves > 0:
            print(f"Coverage: {cves_with_functions/total_cves*100:.1f}%")
        if cves_with_functions > 0:
            print(f"Average functions per CVE (with functions): {total_functions/cves_with_functions:.2f}")
        print("="*80)

    def filter_and_prioritize_commits(self, processed_commits: Dict[str, Dict],
                                    filter_large_vfcs: bool = True,
                                    priority_commit: bool = True,
                                    filter_large_files: bool = True) -> Dict[str, Dict]:
        """
        Filter and prioritize commits based on various criteria
        Based on filtering logic from collect_commits.py
        
        Args:
            processed_commits: Processed commit information
            filter_large_vfcs: Filter commits with too many changes
            priority_commit: Prioritize direct commit references
            filter_large_files: Filter commits with large file changes
            
        Returns:
            Filtered and prioritized commit information
        """
        logger.info("Filtering and prioritizing commits...")
        print("Filtering and prioritizing commits...")
        
        filtered_commits = {}
        for cve_id, cve_commits in processed_commits.items():
            filtered_cve_commits = {}
            possible_commit_file = POSSIBLE_COMMITS_DIR_DATE / f"{cve_id}.json"
            if not possible_commit_file.exists():
                logger.warning(f'No possible commits file found for {cve_id}')
                return {}
                
            with possible_commit_file.open('r') as f:
                extracted_urls = json.load(f)
            for package_name, (repo_url,commit_infos) in cve_commits.items():
                
                filtered_commit_infos = self.commit_processor.filter_commits_by_criteria(
                    commit_infos, extracted_urls, repo_url, filter_large_vfcs, priority_commit, filter_large_files
                )
                
                if filtered_commit_infos:
                    filtered_cve_commits[package_name] = (repo_url, filtered_commit_infos)
            
            if filtered_cve_commits:
                filtered_commits[cve_id] = filtered_cve_commits
        
        logger.info(f"Filtered commits: {len(filtered_commits)} CVEs remaining")
        print(f"Filtered commits: {len(filtered_commits)} CVEs remaining")
        return filtered_commits

    def save_analysis_results(self, commits_analysis: Dict[str, Dict], 
                            changes_analysis: Dict[str, Dict]):
        """
        Save analysis results to files
        
        Args:
            commits_analysis: Commit analysis results
            changes_analysis: Code change analysis results
        """
        logger.info("Saving analysis results...")
        
        # Save commits analysis
        with open(self.commits_analysis_file, 'w') as f:
            json.dump(commits_analysis, f, indent=2)
        
        # Save changes analysis
        with open(self.changes_analysis_file, 'w') as f:
            json.dump(changes_analysis, f, indent=2)
        
        logger.info(f"Analysis results saved to {self.output_dir}")

    def load_analysis_results(self) -> Tuple[Optional[Dict], Optional[Dict]]:
        """
        Load previously saved analysis results
        
        Returns:
            Tuple of (commits_analysis, changes_analysis)
        """
        commits_analysis = None
        changes_analysis = None
        
        if self.commits_analysis_file.exists():
            with open(self.commits_analysis_file, 'r') as f:
                commits_analysis = json.load(f)
        
        if self.changes_analysis_file.exists():
            with open(self.changes_analysis_file, 'r') as f:
                changes_analysis = json.load(f)
        
        return commits_analysis, changes_analysis
    def save_cves_has_vulnerable_functions(self, cve2advisory: Dict[str,Dict], vul_func_analysis: Dict[str, Dict]):
        """
        Filter and save CVEs that contain vulnerable functions to a pickle file.
        
        Args:
            cve2advisory: Mapping of CVE IDs to advisory information
            vul_func_analysis: Vulnerable function analysis results containing
                function data for each CVE, package, commit, and file
        
        Returns:
            Filtered cve2advisory dictionary containing only CVEs with vulnerable functions
        
        Side Effects:
            Creates cve2advisory_cvf.pkl file in output directory
        """
        # Filter CVEs that have vulnerable functions and save to cve2advisory_cvf.pkl
        logger.info("Filtering CVEs with vulnerable functions...")
        print("\n🔍 Filtering CVEs with vulnerable functions...")
        cves_with_vf = set()
        cve_function_counts = {}
        
        # Check which CVEs have vulnerable functions and count them
        for cve_id, cve_data in vul_func_analysis.items():
            has_vf = False
            total_functions = 0
            
            for package_name, package_data in cve_data.items():
                if 'vulnerable_functions_data' not in package_data:
                    continue
                vf_data = package_data['vulnerable_functions_data']
                repo_url = package_data['repo_url']
                
                # Count functions for this package
                package_functions = 0
                for fixing_commit, commit_data in vf_data.items():
                    if not isinstance(commit_data, dict):
                        continue
                    
                    # Check if any file has vulnerable functions
                    for file_name, file_vf_data in commit_data.items():
                        if not isinstance(file_vf_data, dict):
                            continue
                        
                        # Check if any strategy has functions
                        for strategy, functions in file_vf_data.items():
                            if functions and len(functions) > 0:
                                has_vf = True
                                package_functions += len(functions)
                
                total_functions += package_functions
            
            if has_vf:
                cves_with_vf.add(cve_id)
                cve_function_counts[cve_id] = total_functions
        
        # Print CVE filtering statistics
        # print("\n" + "="*80)
        # print("📊 CVE FILTERING STATISTICS")
        # print("="*80)
        
        # # Sort CVEs by function count for better display
        # sorted_cves = sorted(cve_function_counts.items(), key=lambda x: x[1], reverse=True)
        
        # print(f"CVEs with vulnerable functions: {len(cves_with_vf)}")
        # print(f"CVEs without vulnerable functions: {len(vul_func_analysis) - len(cves_with_vf)}")
        print(f"Total functions found: {sum(cve_function_counts.values())}")
        
        # if sorted_cves:
        #     print("\n🎯 Top CVEs by function count:")
        #     for i, (cve_id, count) in enumerate(sorted_cves[:10]):  # Show top 10
        #         print(f"  {i+1:2d}. {cve_id}: {count} functions")
            
        #     if len(sorted_cves) > 10:
        #         print(f"  ... and {len(sorted_cves) - 10} more CVEs")
        
        # Filter cve2advisory to only include CVEs with vulnerable functions
        cve2advisory_cvf = {cve_id: advisory for cve_id, advisory in cve2advisory.items() 
                           if cve_id in cves_with_vf}
        
        # Save the filtered cve2advisory to pickle file
        cvf_output_file = self.output_dir / "cve2advisory_vf.pkl"
        with open(cvf_output_file, 'wb') as f:
            pickle.dump(cve2advisory_cvf, f)
        
        print(f"\n✅ Saved {len(cve2advisory_cvf)} CVEs with vulnerable functions to {cvf_output_file}")
        print(f"📈 Coverage: {len(cve2advisory_cvf)}/{len(cve2advisory)} ({len(cve2advisory_cvf)/len(cve2advisory)*100:.1f}%)")
        print("="*80)
        
        logger.info(f"Saved {len(cve2advisory_cvf)} CVEs with vulnerable functions to {cvf_output_file}")
        logger.info(f"Total CVEs: {len(cve2advisory)}, CVEs with VF: {len(cve2advisory_cvf)}, "
                   f"Coverage: {len(cve2advisory_cvf)/len(cve2advisory)*100:.1f}%")
    def analyze_patches(self, cve2advisory: Dict[str, Dict], 
                       force_update: bool = False,
                       rewrite_commits: bool = None,
                       rewrite_scope: bool = None,
                       rewrite_functions: bool = None,
                       filter_large_source: bool = False,
                       filter_large_vfcs: bool = True,
                       priority_commit: bool = True,
                       filter_large_files: bool = True,
                       n_jobs: int = 1) -> Tuple[Dict[str, Dict], Dict[str, Dict]]:
        """
        Main method to analyze patches for vulnerability fixes
        
        Args:
            cve2advisory: Dictionary mapping CVE IDs to advisory information
            force_update: Whether to force update existing analysis (deprecated, use specific rewrite_* params)
            rewrite_commits: Whether to rewrite commit processing cache (None means use force_update)
            rewrite_scope: Whether to rewrite scope analysis cache (None means use force_update)
            rewrite_functions: Whether to rewrite vulnerable functions cache (None means use force_update)
            filter_large_source: Whether to filter large PR/Issue sources
            filter_large_vfcs: Filter commits with too many changes
            priority_commit: Prioritize direct commit references
            filter_large_files: Filter commits with large file changes
            n_jobs: Number of parallel jobs
            
        Returns:
            Tuple of (commits_analysis, changes_analysis)
        """
        print("🚀 Starting patch analysis workflow...")
        logger.info("Starting patch analysis...")
        
        # Handle backward compatibility and set default values for rewrite parameters
        if rewrite_commits is None:
            rewrite_commits = force_update
        if rewrite_scope is None:
            rewrite_scope = force_update
        if rewrite_functions is None:
            rewrite_functions = force_update
            
        logger.info(f"Rewrite settings - commits: {rewrite_commits}, scope: {rewrite_scope}, functions: {rewrite_functions}")
        
        # Check if results already exist
        # if not force_update:
        #     commits_analysis, changes_analysis = self.load_analysis_results()
        #     if commits_analysis is not None and changes_analysis is not None:
        #         logger.info("Loaded existing analysis results")
        #         return commits_analysis, changes_analysis
        
        # Step 1: Process possible commit URLs
        print("📝 Step 1: Processing possible commit URLs...")
        processed_commits = self.process_possible_commit_urls(
            cve2advisory, 
            rewrite_all_fixing_commits=rewrite_commits,
            filter_large_source=filter_large_source,
            n_jobs=n_jobs
        )
        print(f"✅ Processed commit information for {len(processed_commits)} CVEs")
        
        # Print detailed commit processing statistics
        total_commits = 0
        total_packages = 0
        for cve_id, cve_data in processed_commits.items():
            total_packages += len(cve_data)
            for package_name, (repo_url, commit_data) in cve_data.items():
                total_commits += len(commit_data)
        
        print(f"   📊 Total packages processed: {total_packages}")
        print(f"   📊 Total commits found: {total_commits}")
        if total_packages > 0:
            print(f"   📊 Average commits per package: {total_commits/total_packages:.2f}")
        
        # Step 2: Filter and prioritize commits
        print("🔍 Step 2: Filtering and prioritizing commits...")
        filtered_commits = self.filter_and_prioritize_commits(
            processed_commits,
            filter_large_vfcs=filter_large_vfcs,
            priority_commit=priority_commit,
            filter_large_files=filter_large_files
        )
        print(f"✅ {len(filtered_commits)} CVEs remaining after filtering")
        
        # Print filtering statistics
        filtered_packages = set()
        total_filtered_commits = 0
        for cve_id, cve_data in filtered_commits.items():
            for pkg_name, pkg_data in cve_data.items():
                filtered_packages.add(pkg_name)
                total_filtered_commits += len(pkg_data[1])
        
        print(f"📊 Filtering Statistics:")
        print(f"   - Packages after filtering: {len(filtered_packages)}")
        print(f"   - Total commits after filtering: {total_filtered_commits}")
        print(f"   - Average commits per CVE: {total_filtered_commits / len(filtered_commits):.2f}")
        print(f"   - Average commits per package: {total_filtered_commits / len(filtered_packages):.2f}")

        # Step 3: Analyze code change scope for all CVEs
        print("🔬 Step 3: Analyzing code change scope...")
        scope_analysis = self.analyze_code_change_scope_for_all(filtered_commits, rewrite=rewrite_scope)
        print(f"✅ Completed scope analysis for {len(scope_analysis)} CVEs")
        
        # Print scope analysis statistics
        total_vfcs = 0
        total_modified_files = 0
        cves_with_scope = 0
        for cve_id, cve_data in scope_analysis.items():
            if cve_data:
                cves_with_scope += 1
                for pkg_name, pkg_data in cve_data.items():
                    total_vfcs += len(pkg_data)

                    for commit_hash, commit_data in pkg_data.items():
                        total_modified_files += len(commit_data)
        
        print(f"📊 Scope Analysis Statistics:")
        print(f"   - CVEs with scope analysis: {cves_with_scope}/{len(scope_analysis)}")
        print(f"   - Total VFCs (Vulnerable File Changes): {total_vfcs}")
        print(f"   - Total modified files: {total_modified_files}")
        if cves_with_scope > 0:
            print(f"   - Average VFCs per CVE: {total_vfcs / cves_with_scope:.2f}")
            print(f"   - Average modified files per CVE: {total_modified_files / cves_with_scope:.2f}")
        
        # Step 4: Analyze vulnerable functions for all CVEs
        print("🎯 Step 4: Analyzing vulnerable functions...")
        vul_func_analysis = self.analyze_vulnerable_functions_for_all(filtered_commits, scope_analysis, rewrite=rewrite_functions)
        print(f"✅ Completed vulnerable function analysis for {len(vul_func_analysis)} CVEs")
        # Print vulnerable function analysis statistics
        total_vulnerable_functions = 0
        cves_with_functions = 0
        function_types = defaultdict(int)
        for cve_id, cve_data in vul_func_analysis.items():
            if cve_data:
                has_functions = False
                for pkg_name, pkg_data in cve_data.items():
                    # Extract vulnerable_functions_data from package data
                    if 'vulnerable_functions_data' in pkg_data:
                        vul_func_data = pkg_data['vulnerable_functions_data']
                        for commit_hash, commit_data in vul_func_data.items():
                            # commit_data is a dict with filename as keys and vfs_dict as values
                            for filename, file_vfs_dict in commit_data.items():
                                # file_vfs_dict contains different categories of vulnerable functions
                                for category, methods in file_vfs_dict.items():
                                    if methods:  # Check if the set/list is not empty
                                        has_functions = True
                                        if isinstance(methods, (set, list)):
                                            total_vulnerable_functions += len(methods)
                                            # Count function types based on category
                                            function_types[category] += len(methods)
                if has_functions:
                    cves_with_functions += 1
        
        print(f"📊 Vulnerable Function Analysis Statistics:")
        print(f"   - CVEs with vulnerable functions: {cves_with_functions}/{len(vul_func_analysis)}")
        print(f"   - Total vulnerable functions: {total_vulnerable_functions}")
        if cves_with_functions > 0:
            print(f"   - Average functions per CVE: {total_vulnerable_functions / cves_with_functions:.2f}")
        if function_types:
            print(f"   - Function types distribution:")
            for func_type, count in sorted(function_types.items()):
                print(f"     * {func_type}: {count}")
        
        # Save vulnerable functions for all CVEs
        self.save_cves_has_vulnerable_functions(cve2advisory,vul_func_analysis)

        
        # Step 5: Evaluate the scope analysis and vulnerable functions
        print("📊 Step 5: Evaluating analysis results...")
        logger.info("Step 5: Evaluating scope analysis and vulnerable functions...")
        
        # 5.1: Evaluate scope analysis statistics
        scope_evaluation = self.evaluate_scope_analysis(scope_analysis)
        print("✅ Scope analysis evaluation completed")
        logger.info("Scope analysis evaluation completed")
        
        # 5.2: Evaluate vulnerable functions statistics  
        vf_evaluation = self.evaluate_vulnerable_functions(vul_func_analysis)
        print("✅ Vulnerable function evaluation completed")
        logger.info("Vulnerable functions evaluation completed")
        
        # Save evaluation statistics
        print("💾 Saving evaluation results...")
        evaluation_results = {
            'scope_evaluation': scope_evaluation,
            'vulnerable_functions_evaluation': vf_evaluation
        }
        vul_func_analysis_file = self.output_dir / "vul_func_analysis.pkl"
        with vul_func_analysis_file.open('wb') as f:
            pickle.dump(vul_func_analysis, f)
        evaluation_file = self.output_dir / "evaluation_results.json"
        with evaluation_file.open('w', encoding='utf-8') as f:
            json.dump(evaluation_results, f, indent=2, ensure_ascii=False)
        print(f"✅ Evaluation results saved to {evaluation_file}")
        logger.info(f"Evaluation results saved to {evaluation_file}")
        
        print("🏁 Patch analysis workflow completed!")
        logger.info("Patch analysis completed successfully")
        return filtered_commits,vul_func_analysis

    def evaluate_scope_analysis(self, scope_analysis: Dict[str, Dict]) -> Dict[str, Any]:
        """
        Evaluate scope analysis results to provide basic statistics.
        
        Args:
            scope_analysis: Scope analysis results from analyze_code_change_scope_for_all
                           Structure: CVE -> package -> file_id -> [deleted_scope, added_scope]
            
        Returns:
            Dictionary containing evaluation statistics
        """
        logger.info("Evaluating scope analysis results...")
        
        # Initialize statistics
        total_cves = len(scope_analysis)
        total_packages = 0
        total_files = 0
        total_scopes = 0
        
        # Scope type statistics
        scope_type_stats = defaultdict(int)
        
        # CVE-level statistics for scope types
        cves_with_function_changes = set()
        cves_with_module_changes = set()
        cves_with_class_changes = set()
        
        # CVE-level statistics
        cve_stats = {}
        
        for cve_id, cve_data in scope_analysis.items():
            cve_packages = len(cve_data)
            cve_files = 0
            cve_scopes = 0
            
            # Track scope types for this CVE
            cve_has_function = False
            cve_has_module = False
            cve_has_class = False
            
            total_packages += cve_packages
            
            for package_name, package_data in cve_data.items():
                for fixing_commit, commit_data in package_data.items():
                    commit_files = len(commit_data)
                    cve_files += commit_files
                    total_files += commit_files
                    for file_id, scope_data in commit_data.items():
                        # scope_data should be [deleted_scope, added_scope]
                        deleted_scope, added_scope = scope_data
                        
                        # Count scopes in deleted_scope
                        for scope, changes in deleted_scope.items():
                            scope_count = len(changes)
                            scope_type_stats[scope] += scope_count
                            cve_scopes += scope_count
                            total_scopes += scope_count
                            
                            # Track scope types for CVE-level statistics (only if there are actual changes)
                            if scope_count > 0:
                                if scope == 'function':
                                    cve_has_function = True
                                elif scope == 'module':
                                    cve_has_module = True
                                elif scope == 'class':
                                    cve_has_class = True
                        
                        # Count scopes in added_scope
                        for scope, changes in added_scope.items():
                            scope_count = len(changes)
                            scope_type_stats[scope] += scope_count
                            cve_scopes += scope_count
                            total_scopes += scope_count
                            
                            # Track scope types for CVE-level statistics (only if there are actual changes)
                            if scope_count > 0:
                                if scope == 'function':
                                    cve_has_function = True
                                elif scope == 'module':
                                    cve_has_module = True
                                elif scope == 'class':
                                    cve_has_class = True
            
            # Add CVE to appropriate sets
            if cve_has_function:
                cves_with_function_changes.add(cve_id)
            if cve_has_module:
                cves_with_module_changes.add(cve_id)
            if cve_has_class:
                cves_with_class_changes.add(cve_id)
            
            cve_stats[cve_id] = {
                'packages': cve_packages,
                'files': cve_files,
                'scopes': cve_scopes,
                'has_function_changes': cve_has_function,
                'has_module_changes': cve_has_module,
                'has_class_changes': cve_has_class
            }
        
        # Calculate averages
        avg_packages_per_cve = total_packages / total_cves if total_cves > 0 else 0
        avg_files_per_cve = total_files / total_cves if total_cves > 0 else 0
        avg_scopes_per_cve = total_scopes / total_cves if total_cves > 0 else 0
        avg_files_per_package = total_files / total_packages if total_packages > 0 else 0
        avg_scopes_per_file = total_scopes / total_files if total_files > 0 else 0
        
        # Calculate scope type statistics
        num_cves_with_function = len(cves_with_function_changes)
        num_cves_with_module = len(cves_with_module_changes)
        num_cves_with_class = len(cves_with_class_changes)
        
        evaluation_results = {
            'global_stats': {
                'total_cves': total_cves,
                'total_packages': total_packages,
                'total_files': total_files,
                'total_scopes': total_scopes,
                'avg_packages_per_cve': round(avg_packages_per_cve, 2),
                'avg_files_per_cve': round(avg_files_per_cve, 2),
                'avg_scopes_per_cve': round(avg_scopes_per_cve, 2),
                'avg_files_per_package': round(avg_files_per_package, 2),
                'avg_scopes_per_file': round(avg_scopes_per_file, 2)
            },
            'scope_type_distribution': dict(scope_type_stats),
            'cve_scope_type_stats': {
                'cves_with_function_changes': num_cves_with_function,
                'cves_with_module_changes': num_cves_with_module,
                'cves_with_class_changes': num_cves_with_class,
                'percentage_cves_with_function': round(num_cves_with_function / total_cves * 100, 2) if total_cves > 0 else 0,
                'percentage_cves_with_module': round(num_cves_with_module / total_cves * 100, 2) if total_cves > 0 else 0,
                'percentage_cves_with_class': round(num_cves_with_class / total_cves * 100, 2) if total_cves > 0 else 0,
                'function_changes_list': list(cves_with_function_changes),
                'module_changes_list': list(cves_with_module_changes),
                'class_changes_list': list(cves_with_class_changes)
            },
            'cve_level_stats': cve_stats
        }
        
        logger.info(f"Scope analysis evaluation completed for {total_cves} CVEs")
        logger.info(f"CVEs with function changes: {num_cves_with_function}")
        logger.info(f"CVEs with module changes: {num_cves_with_module}")
        logger.info(f"CVEs with class changes: {num_cves_with_class}")
        
        return evaluation_results

    def evaluate_vulnerable_functions(self, vul_func_analysis: Dict[str, Dict]) -> Dict[str, Any]:
        """
        Evaluate vulnerable functions statistics
        
        Args:
            vul_func_analysis: vulnerable functions analysis results
                              Structure: CVE -> package -> {'repo_url': str, 'vulnerable_functions_data': Dict}
            
        Returns:
            Dict: Dictionary containing vulnerable functions statistics
        """
        logger.info("Starting evaluation of vulnerable functions...")
        cve_with_vf={}
        
        # Initialize statistical counters
        total_cves = len(vul_func_analysis)
        total_packages = 0
        total_vfcs = 0
        total_vulnerable_functions = 0
        
        # CVE-level statistics
        cves_with_functions = set()
        cves_without_functions = set()
        cve_function_counts = {}
        
        # VFC-level statistics
        vfcs_with_functions = set()
        vfcs_without_functions = set()
        vfc_function_counts = {}
        # Strategy-level statistics
        strategy_stats = {
            'old_method_direct_modified_by_deleted_lines': {'cves': set(), 'vfcs': set(), 'functions': 0},
            'old_method_only_modified_by_added_lines': {'cves': set(), 'vfcs': set(), 'functions': 0},
            'special_method_only_existed_in_new_file': {'cves': set(), 'vfcs': set(), 'functions': 0},
            'added_methods_replace_same_name_old_methods': {'cves': set(), 'vfcs': set(), 'functions': 0},
            'module_vars_impact_functions': {'cves': set(), 'vfcs': set(), 'functions': 0},
            'class_vars_impact_functions': {'cves': set(), 'vfcs': set(), 'functions': 0},
            'module_called_functions': {'cves': set(), 'vfcs': set(), 'functions': 0}
        }
        
        # Traverse vulnerable functions analysis results
        for cve_id, cve_data in tqdm(vul_func_analysis.items(), desc="Evaluating vulnerable functions"):
            cve_total_functions = 0
            cve_has_functions = False
            
            for package_name, package_data in cve_data.items():
                total_packages += 1
                if 'vulnerable_functions_data' not in package_data:
                    continue
                    
                vf_data = package_data['vulnerable_functions_data']
                
                # Traverse vulnerable functions for each fixing commit
                for fixing_commit, commit_data in vf_data.items():
                    total_vfcs += 1
                    fixing_commit_hash = fixing_commit.split('/')[-1]
                    vfc_key = f"{cve_id}_{fixing_commit_hash}"
                    
                    vfc_total_functions = 0
                    vfc_has_functions = False
                    
                    # Traverse vulnerable functions for each file
                    for file_name, file_vf_data in commit_data.items():
                        if not isinstance(file_vf_data, dict):
                            continue
                            
                        # Count functions for each strategy
                        for strategy, functions in file_vf_data.items():
                            if strategy in strategy_stats and functions:
                                function_count = len(functions) if isinstance(functions, (list, set)) else 1
                                strategy_stats[strategy]['functions'] += function_count
                                strategy_stats[strategy]['cves'].add(cve_id)
                                strategy_stats[strategy]['vfcs'].add(vfc_key)
                                
                                vfc_total_functions += function_count
                                vfc_has_functions = True
                    
                    # Record VFC-level statistics
                    vfc_function_counts[vfc_key] = vfc_total_functions
                    if vfc_has_functions:
                        vfcs_with_functions.add(vfc_key)
                    else:
                        vfcs_without_functions.add(vfc_key)
                    
                    cve_total_functions += vfc_total_functions
                    if vfc_has_functions:
                        cve_has_functions = True
            
            # Record CVE-level statistics
            cve_function_counts[cve_id] = cve_total_functions
            total_vulnerable_functions += cve_total_functions
            
            if cve_has_functions:
                cves_with_functions.add(cve_id)
            else:
                cves_without_functions.add(cve_id)

        
        # Calculate statistical results
        cves_with_functions_count = len(cves_with_functions)
        cves_without_functions_count = len(cves_without_functions)
        vfcs_with_functions_count = len(vfcs_with_functions)
        vfcs_without_functions_count = len(vfcs_without_functions)
        
        # Calculate averages
        avg_functions_per_cve = total_vulnerable_functions / total_cves if total_cves > 0 else 0
        avg_functions_per_vfc = total_vulnerable_functions / total_vfcs if total_vfcs > 0 else 0
        avg_functions_per_cve_with_functions = (
            total_vulnerable_functions / cves_with_functions_count 
            if cves_with_functions_count > 0 else 0
        )
        
        # Build global statistics
        global_stats = {
            'total_cves': total_cves,
            'total_packages': total_packages,
            'total_vfcs': total_vfcs,
            'total_vulnerable_functions': total_vulnerable_functions,
            
            'cves_with_functions': cves_with_functions_count,
            'cves_without_functions': cves_without_functions_count,
            'cve_extraction_rate': cves_with_functions_count / total_cves if total_cves > 0 else 0,
            
            'vfcs_with_functions': vfcs_with_functions_count,
            'vfcs_without_functions': vfcs_without_functions_count,
            'vfc_extraction_rate': vfcs_with_functions_count / total_vfcs if total_vfcs > 0 else 0,
            
            'avg_functions_per_cve': round(avg_functions_per_cve, 2),
            'avg_functions_per_vfc': round(avg_functions_per_vfc, 2),
            'avg_functions_per_cve_with_functions': round(avg_functions_per_cve_with_functions, 2)
        }
        
        # Build strategy statistics
        strategy_summary = {}
        for strategy, stats in strategy_stats.items():
            strategy_summary[strategy] = {
                'total_functions': stats['functions'],
                'cves_count': len(stats['cves']),
                'vfcs_count': len(stats['vfcs']),
                'cve_coverage_rate': len(stats['cves']) / total_cves if total_cves > 0 else 0,
                'vfc_coverage_rate': len(stats['vfcs']) / total_vfcs if total_vfcs > 0 else 0,
                'function_percentage': stats['functions'] / total_vulnerable_functions if total_vulnerable_functions > 0 else 0,
                'cve_list': list(stats['cves']),
                'vfc_list': list(stats['vfcs'])
            }
        
        # Output statistics to console
        print(f"\n📊 === Vulnerable Functions Overall Statistics ===")
        print(f"   - Total CVEs: {total_cves}")
        print(f"   - Total packages: {total_packages}")
        print(f"   - Total VFCs: {total_vfcs}")
        print(f"   - Total vulnerable functions: {total_vulnerable_functions}")
        
        print(f"\n📊 === CVE-level Function Statistics ===")
        print(f"   - CVEs with extractable functions: {cves_with_functions_count}/{total_cves} ({cves_with_functions_count/total_cves*100:.1f}%)")
        print(f"   - CVEs without extractable functions: {cves_without_functions_count}/{total_cves} ({cves_without_functions_count/total_cves*100:.1f}%)")
        print(f"   - Average functions per CVE: {avg_functions_per_cve:.2f}")
        print(f"   - Average functions per CVE with functions: {avg_functions_per_cve_with_functions:.2f}")
        
        print(f"\n📊 === VFC-level Function Statistics ===")
        print(f"   - VFCs with extractable functions: {vfcs_with_functions_count}/{total_vfcs} ({vfcs_with_functions_count/total_vfcs*100:.1f}%)")
        print(f"   - VFCs without extractable functions: {vfcs_without_functions_count}/{total_vfcs} ({vfcs_without_functions_count/total_vfcs*100:.1f}%)")
        print(f"   - Average functions per VFC: {avg_functions_per_vfc:.2f}")
        
        print(f"\n📊 === Top Function Extraction Strategies ===")
        # Sort strategies by function count and show top 5
        sorted_strategies = sorted(strategy_summary.items(), key=lambda x: x[1]['total_functions'], reverse=True)
        for i, (strategy, summary) in enumerate(sorted_strategies[:]):
            if summary['total_functions'] > 0:
                print(f"   {i+1}. {strategy}:")
                print(f"      - Functions: {summary['total_functions']} ({summary['function_percentage']*100:.1f}%)")
                print(f"      - CVE coverage: {summary['cves_count']} ({summary['cve_coverage_rate']*100:.1f}%)")
                print(f"      - VFC coverage: {summary['vfcs_count']} ({summary['vfc_coverage_rate']*100:.1f}%)")
        
        # Strategy group analysis
        strategy_groups = {
            'Method Modification Strategies': [
                'old_method_direct_modified_by_deleted_lines',
                'old_method_only_modified_by_added_lines',
                'special_method_only_existed_in_new_file',
                'added_methods_replace_same_name_old_methods'
            ],
            'Variable Impact Strategies': [
                'module_vars_impact_functions',
                'class_vars_impact_functions'
            ],
            'Function Call Strategies': [
                'module_called_functions'
            ]
        }
        
        print(f"\n📊 === Strategy Group Analysis ===")
        for group_name, strategies in strategy_groups.items():
            print(f"\n   🔍 {group_name}:")
            
            # Collect CVEs for each strategy in the group
            strategy_cves = {}
            total_group_functions = 0
            
            for strategy in strategies:
                if strategy in strategy_summary:
                    strategy_cves[strategy] = set(strategy_summary[strategy]['cve_list'])
                    total_group_functions += strategy_summary[strategy]['total_functions']
                    print(f"      - {strategy}: {len(strategy_cves[strategy])} CVEs ({len(strategy_cves[strategy])/total_cves*100:.1f}%)")
                else:
                    strategy_cves[strategy] = set()
                    print(f"      - {strategy}: 0 CVEs (0.0%)")
            
            # Calculate combined statistics for this group
            if strategy_cves:
                all_group_cves = set()
                for cves in strategy_cves.values():
                    all_group_cves.update(cves)
                
                group_cve_count = len(all_group_cves)
                group_cve_rate = group_cve_count / total_cves if total_cves > 0 else 0
                
                print(f"      📈 Group Summary:")
                print(f"         - Combined unique CVEs: {group_cve_count} ({group_cve_rate*100:.1f}%)")
                print(f"         - Total functions: {total_group_functions}")
                
                # Calculate overlaps within the group
                if len(strategies) > 1:
                    overlaps = []
                    strategy_list = list(strategy_cves.keys())
                    for i in range(len(strategy_list)):
                        for j in range(i+1, len(strategy_list)):
                            overlap = strategy_cves[strategy_list[i]].intersection(strategy_cves[strategy_list[j]])
                            if overlap:
                                overlaps.append(f"{strategy_list[i]} ∩ {strategy_list[j]}: {len(overlap)}")
                    
                    # if overlaps:
                    #     print(f"         - Strategy overlaps: {', '.join(overlaps)}")
                    # else:
                    #     print(f"         - No overlaps between strategies")
        
        # Output statistics to logger
        logger.info(f"\n=== Vulnerable Functions Overall Statistics ===")
        logger.info(f"Total CVEs: {total_cves}")
        logger.info(f"Total packages: {total_packages}")
        logger.info(f"Total VFCs: {total_vfcs}")
        logger.info(f"Total vulnerable functions: {total_vulnerable_functions}")
        
        logger.info(f"\n=== CVE-level Statistics ===")
        logger.info(f"CVEs with extractable functions: {cves_with_functions_count} ({cves_with_functions_count/total_cves*100:.1f}%)")
        logger.info(f"CVEs without extractable functions: {cves_without_functions_count} ({cves_without_functions_count/total_cves*100:.1f}%)")
        logger.info(f"Average functions per CVE: {avg_functions_per_cve:.2f}")
        logger.info(f"Average functions per CVE with functions: {avg_functions_per_cve_with_functions:.2f}")
        
        logger.info(f"\n=== VFC-level Statistics ===")
        logger.info(f"VFCs with extractable functions: {vfcs_with_functions_count} ({vfcs_with_functions_count/total_vfcs*100:.1f}%)")
        logger.info(f"VFCs without extractable functions: {vfcs_without_functions_count} ({vfcs_without_functions_count/total_vfcs*100:.1f}%)")
        logger.info(f"Average functions per VFC: {avg_functions_per_vfc:.2f}")
        
        logger.info(f"\n=== Strategy Contribution Statistics ===")
        for strategy, summary in strategy_summary.items():
            if summary['total_functions'] > 0:
                logger.info(f"{strategy}:")
                logger.info(f"  Functions: {summary['total_functions']} ({summary['function_percentage']*100:.1f}%)")
                logger.info(f"  CVE coverage: {summary['cves_count']} ({summary['cve_coverage_rate']*100:.1f}%)")
                logger.info(f"  VFC coverage: {summary['vfcs_count']} ({summary['vfc_coverage_rate']*100:.1f}%)")
        
        # Build return results
        result = {
            'global_stats': global_stats,
            'strategy_stats': strategy_summary,
            'detailed_stats': {
                'cves_with_functions': list(cves_with_functions),
                'cves_without_functions': list(cves_without_functions),
                'cve_function_counts': cve_function_counts,
                'vfc_function_counts': vfc_function_counts
            }
        }
        
        logger.info("Vulnerable functions evaluation completed")
        return result

    def filter_cves_by_vulnerable_functions(self, cve2advisory: Dict[str, Dict], 
                                          min_functions: int = 1, 
                                          max_functions: Optional[int] = None,
                                          min_vfcs: Optional[int] = None,
                                          max_vfcs: Optional[int] = None,
                                          required_categories: Optional[List[str]] = None,
                                          excluded_categories: Optional[List[str]] = None) -> Tuple[Dict[str, Dict], Dict[str, Any]]:
        """
        Filter CVEs based on the number and type of vulnerable functions
        Based on the filter_cves_by_vulnerable_functions function in collect_changes.py
        
        Args:
            cve2advisory: Mapping of CVE to advisory
            min_functions: Minimum number of vulnerable functions
            max_functions: Maximum number of vulnerable functions
            min_vfcs: Minimum number of VFCs
            max_vfcs: Maximum number of VFCs
            required_categories: Required vulnerability categories
            excluded_categories: Excluded vulnerability categories
            
        Returns:
            Tuple[Dict, Dict]: Filtered CVE dictionary and statistics
        """
        logger.info(f"Starting CVE filtering with conditions: min_functions={min_functions}, max_functions={max_functions}")
        
        filtered_cves = {}
        filter_stats = {
            'original_count': len(cve2advisory),
            'filtered_count': 0,
            'filter_reasons': defaultdict(int)
        }
        
        for cve_id, advisory in tqdm(cve2advisory.items(), desc="Filtering CVEs"):
            all_unique_affected_projects = get_all_unique_affected_projects(advisory)
            
            total_vfs = 0
            total_vfcs = 0
            should_include = True
            filter_reason = None
            
            for package_name, repo_url in all_unique_affected_projects:
                if package_name not in advisory['fixing_commits']:
                    continue
                    
                fixing_commits = advisory['fixing_commits'][package_name]
                total_vfcs += len(fixing_commits)
                
                # Check vulnerable functions file
                vf_file = CODE_CHANGES_DIR_DATE / f'{cve_id}_{package_name}_vulnerable_functions.json'
                if not vf_file.exists():
                    continue
                
                with vf_file.open('r') as f:
                    vf_data = json.load(f)
                
                for fixing_commit in fixing_commits:
                    vfc_vfs = vf_data.get(fixing_commit, {}).get('vulnerable_functions', [])
                    total_vfs += len(vfc_vfs)
            
            # Apply filtering conditions
            if total_vfs < min_functions:
                should_include = False
                filter_reason = f"insufficient_functions_{total_vfs}"
            elif max_functions is not None and total_vfs > max_functions:
                should_include = False
                filter_reason = f"too_many_functions_{total_vfs}"
            elif min_vfcs is not None and total_vfcs < min_vfcs:
                should_include = False
                filter_reason = f"insufficient_vfcs_{total_vfcs}"
            elif max_vfcs is not None and total_vfcs > max_vfcs:
                should_include = False
                filter_reason = f"too_many_vfcs_{total_vfcs}"
            
            # Check vulnerability categories (if provided)
            if should_include and (required_categories or excluded_categories):
                # Category checking logic can be added here as needed
                pass
            
            if should_include:
                filtered_cves[cve_id] = advisory
                filter_stats['filtered_count'] += 1
            else:
                filter_stats['filter_reasons'][filter_reason] += 1
        
        logger.info(f"Filtering completed: Original CVE count {filter_stats['original_count']}, Filtered CVE count {filter_stats['filtered_count']}")
        logger.info(f"Filter reason statistics: {dict(filter_stats['filter_reasons'])}")
        
        return filtered_cves, filter_stats


def create_parser():
    """
    Create command line argument parser for patch analysis.
    """
    parser = argparse.ArgumentParser(
        description='Patch Parser - Analyze patches and code changes for vulnerability fixes',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python patch_parser.py                              # Analyze patches (default mode)
  python patch_parser.py --cve CVE-2020-13757        # Analyze specific CVE
  python patch_parser.py --package Django             # Analyze specific package
  python patch_parser.py --analyze                    # Explicit analyze mode
        """
    )
    
    parser.add_argument(
        '--analyze',
        action='store_true',
        help='Analyze patches and code changes for vulnerability fixes (default if no other mode specified)'
    )
    
    parser.add_argument(
        '--cve',
        type=str,
        nargs='*',
        help='Specific CVE IDs to analyze (supports multiple CVEs)'
    )
    
    parser.add_argument(
        '--package',
        type=str,
        nargs='*',
        help='Specific package name to analyze'
    )
    
    parser.add_argument(
        '--force-update',
        action='store_true',
        help='Force update of existing analysis results (deprecated, use specific rewrite options)'
    )
    
    parser.add_argument(
        '--rewrite-commits',
        action='store_true',
        help='Force rewrite of commit analysis results'
    )
    
    parser.add_argument(
        '--rewrite-scope',
        action='store_true',
        help='Force rewrite of code change scope analysis results'
    )
    
    parser.add_argument(
        '--rewrite-functions',
        action='store_true',
        help='Force rewrite of vulnerable function analysis results'
    )
    
    parser.add_argument(
        '--filter-large-source',
        action='store_true',
        help='Filter out large Pull Requests/Issues during analysis'
    )

    parser.add_argument(
        '--filter-large-vfcs',
        action='store_true',
        default=True,
        help='Filter cves with too many vulnerability fixing commits (default: True)'
    )
    
    parser.add_argument(
        '--priority-commit',
        action='store_true',
        default=True,
        help='Prioritize commits based on certain criteria (default: True)'
    )
    
    parser.add_argument(
        '--filter-large-files',
        action='store_true',
        default=True,
        help=' Filter commits with large file changes(default: True)'
    )
    
    parser.add_argument(
        '--output',
        type=str,
        help='Output directory for analysis results'
    )
    
    parser.add_argument(
        '--jobs',
        type=int,
        default=1,
        help='Number of parallel jobs for processing (default: 1)'
    )
    
    parser.add_argument(
        '--print-vulnerable-summary',
        action='store_true',
        help='Print detailed summary of vulnerable functions after analysis'
    )
    
    return parser


def main():
    """
    Main function for patch analysis with command line interface.
    """
    parser = create_parser()
    args = parser.parse_args()
    
    # If no specific operation is requested, default to analyze mode
    if not args.analyze:
        print("No operation mode specified, defaulting to --analyze mode...")
        args.analyze = True
    
    print("🔍 Starting patch analysis...")
    logger.info("Starting patch analysis...")
    
    # Initialize PatchParser with optional output directory
    patch_parser = PatchParser(output_dir=DATA_DIR/SUFFIX)
    
    # Load CVE data
    print("📊 Loading CVE data...")
    cve2advisory = patch_parser.load_cve2advisory(force_update=args.force_update)
    if not cve2advisory:
        print("❌ Failed to load CVE advisory data")
        logger.error("Failed to load CVE advisory data")
        return
    
    print(f"✅ Successfully loaded {len(cve2advisory)} CVE records")
    logger.info(f"Loaded {len(cve2advisory)} CVE advisories")
    
    # Print detailed statistics about loaded CVE data
    print("\n📊 === CVE Dataset Statistics ===")
    total_packages = set()
    cve_package_count = {}
    
    for cve_id, advisory in cve2advisory.items():
        affected_packages = advisory.get('affected', [])
        cve_packages = set()
        for affected in affected_packages:
            package_name = affected.get('package', {}).get('name', '')
            if package_name:
                total_packages.add(package_name)
                cve_packages.add(package_name)
        cve_package_count[cve_id] = len(cve_packages)
    
    print(f"📦 Total unique packages: {len(total_packages)}")
    print(f"🔢 Total CVEs: {len(cve2advisory)}")
    if cve_package_count:
        avg_packages_per_cve = sum(cve_package_count.values()) / len(cve_package_count)
        print(f"📈 Average packages per CVE: {avg_packages_per_cve:.2f}")
    print("=" * 40)
    
    # Filter CVE data based on command line parameters
    filtered_cve2advisory = cve2advisory
    
    # Filter by specific CVEs if requested
    if args.cve:
        print(f"🔍 Filtering by specified CVEs: {args.cve}")
        logger.info(f"Filtering by specific CVEs: {args.cve}")
        filtered_cve2advisory = {
            cve: advisory for cve, advisory in cve2advisory.items()
            if cve in args.cve
        }
        if not filtered_cve2advisory:
            print(f"⚠️ Specified CVEs not found: {args.cve}")
            logger.warning(f"None of the specified CVEs {args.cve} were found in the dataset")
            return
        print(f"✅ {len(filtered_cve2advisory)} CVEs remaining after filtering")
        logger.info(f"Filtered to {len(filtered_cve2advisory)} CVEs")
    
    # Filter by specific packages if requested
    if args.package:
        print(f"📦 Filtering by package names: {args.package}")
        logger.info(f"Filtering by packages: {args.package}")
        package_filtered_cves = {}
        for cve, advisory in filtered_cve2advisory.items():
            # Check if any affected package matches the requested packages
            affected_packages = advisory.get('affected', [])
            for affected in affected_packages:
                package_name = affected.get('package', {}).get('name', '')
                if any(pkg.lower() in package_name.lower() for pkg in args.package):
                    package_filtered_cves[cve] = advisory
                    break
        
        filtered_cve2advisory = package_filtered_cves
        if not filtered_cve2advisory:
            print(f"⚠️ No CVEs found for specified packages: {args.package}")
            logger.warning(f"No CVEs found for packages: {args.package}")
            return
        print(f"✅ {len(filtered_cve2advisory)} CVEs remaining after filtering")
        logger.info(f"Filtered to {len(filtered_cve2advisory)} CVEs for specified packages")
    
    # Analyze patches with command line parameters
    print("🔧 Starting patch analysis processing...")
    commits_analysis, vul_func_analysis = patch_parser.analyze_patches(
        cve2advisory=filtered_cve2advisory,
        force_update=args.force_update,  # For backward compatibility
        rewrite_commits=args.rewrite_commits,
        rewrite_scope=args.rewrite_scope,
        rewrite_functions=args.rewrite_functions,
        filter_large_source=args.filter_large_source,
        filter_large_vfcs=args.filter_large_vfcs,
        priority_commit=args.priority_commit,
        filter_large_files=args.filter_large_files,
        n_jobs=args.jobs
    )

    if args.print_vulnerable_summary:
        patch_parser.print_vulnerable_functions_summary(vul_func_analysis)

    
    print("🎉 Patch analysis completed!")
    print(f"📈 Analyzed commit information for {len(commits_analysis)} CVEs")
    logger.info("Patch analysis completed successfully")
    logger.info(f"Analyzed {len(commits_analysis)} CVEs for commits")
    


if __name__ == '__main__':
    main()


   