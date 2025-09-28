from pathlib import Path
from datetime import datetime

# 获取项目根目录的绝对路径
# SUFFIX = datetime.now().strftime('%Y%m')
# SUFFIX = 'icse_demo'

PROJECT_ROOT = Path(__file__).parent.parent.absolute()
DATA_DIR = PROJECT_ROOT / 'data'
SUFFIX = 'icse_demo'
# PROJECT_ROOT = Path(__file__).parent.parent.absolute()

CVE2ADVISORY_FILE = DATA_DIR / f'cve2advisory.pkl'
COMMITS_FILE_NO_CHECKS = DATA_DIR / "extracted_commits_for_cves.json"
COMMITS_DIR = DATA_DIR / "fixing_commits"
POSSIBLE_COMMITS_DIR = DATA_DIR / "possible_fixing_commits"
URLS_FILE = DATA_DIR / "extracted_possible_commit_urls_for_cves.json"
SNYK_URLS_DIR = DATA_DIR / "snyk_urls"
SNYK_COMMITS_DIR = DATA_DIR / "snyk_fixing_commits"
DEP_DIR = DATA_DIR / "dependency_graphs"
PAIRS_DIR = DATA_DIR / "pairs"
REPO_DIR = Path('../data_collection') / 'repos'
CODE_CHANGES_DIR = DATA_DIR / 'code_changes'
MODULE_DIR = DATA_DIR / 'modules'
CALL_GRAPH_DIR = DATA_DIR / "call_graphs"
DEPENDENTS_DIR= DATA_DIR / "dependents"
REF_DIR= DATA_DIR / "ref"
DOWNLOADS_DIR = DATA_DIR / "downloads"
EXTRACT_DIR = DATA_DIR / "extracted"

DIFF_CACHE_DIR = DATA_DIR / "cached_diff"


CVE2ADVISORY_FILE_DATE = DATA_DIR / SUFFIX / f'cve2advisory.pkl'
CVE2ADVISORY_VFC_FILE_DATE = DATA_DIR / SUFFIX / f'cve2advisory_vfc.pkl'
CVE2ADVISORY_VF_FILE_DATE = DATA_DIR / SUFFIX / f'cve2advisory_vf.pkl'
COMMITS_FILE_NO_CHECKS_DATE = DATA_DIR / SUFFIX / "extracted_commits_for_cves.json"
COMMITS_DIR_DATE = DATA_DIR / SUFFIX / "fixing_commits"
POSSIBLE_COMMITS_DIR_DATE = DATA_DIR / SUFFIX / "possible_fixing_commits"
URLS_FILE_DATE = DATA_DIR / SUFFIX / "extracted_possible_commit_urls_for_cves.json"
SNYK_URLS_DIR_DATE = DATA_DIR / SUFFIX / "snyk_urls"
SNYK_COMMITS_DIR_DATE = DATA_DIR / SUFFIX / "snyk_fixing_commits"
DEP_DIR_DATE = DATA_DIR / SUFFIX / "dependency_graphs"
PAIRS_DIR_DATE = DATA_DIR / SUFFIX / "pairs"
REPO_DIR_DATE = DATA_DIR / SUFFIX / "repos"
CODE_CHANGES_DIR_DATE = DATA_DIR / SUFFIX / "code_changes"
MODULE_DIR_DATE = DATA_DIR / SUFFIX / "modules"
CALL_GRAPH_DIR_DATE = DATA_DIR / SUFFIX / "call_graphs"
DEPENDENTS_DIR_DATE= DATA_DIR / SUFFIX / "dependents"
REF_DIR_DATE= DATA_DIR / SUFFIX / "ref"
DOWNLOADS_DIR_DATE = DATA_DIR / SUFFIX / "downloads"
EXTRACT_DIR_DATE = DATA_DIR / SUFFIX / "extracted"
DIFF_CACHE_DIR_DATE = DATA_DIR / SUFFIX / "cached_diff"
SCOPE_CACHE_DIR_DATE = DATA_DIR / SUFFIX / "cached_scope"
AST_TYPE_CACHE_DIR_DATE = DATA_DIR / SUFFIX / "cached_ast_type"
SCOPE_CVE_CACHE_DIR_DATE = DATA_DIR / SUFFIX / "cached_scoped_cve"
REACHABILITY_DIR_DATE = DATA_DIR / SUFFIX / "reach_cve_results"
REACHABILITY_RESULT_DIR_DATE = DATA_DIR / SUFFIX / "all_reach_cve_results"
NORMALIZED_FUNC_DIR_DATE =  DATA_DIR / SUFFIX / "normalized_funcs"
VUL_PACKAGES_DIR_DATE = DATA_DIR / SUFFIX / "vulnerable_packages"
CG_DIR_DATE = DATA_DIR / SUFFIX / "cg_results"
filtered_cves_by_available_versions_file = 'filtered_cves_by_available_versions.pickle'
SNAPSHOT_DIR = DATA_DIR /'research_snapshots'/'20250831'

exclude_dirs = ['doc', 'docs', 'test', 'tests', 
                'testcase', 'testcases', 'testing', 'unittest',
                'build', 'dist',
                'example', 'examples','demo','demos']
exclude_suffixes = {'.md', '.rst', '.txt','.feature'}

CASE_STUDY = ["CVE-2019-6446"]
# CASE_STUDY = ["CVE-2024-9902", "CVE-2025-24357", "CVE-2023-31146", "CVE-2014-0482", "CVE-2014-3730","CVE-2019-6446"]
if not CALL_GRAPH_DIR.exists():
    CALL_GRAPH_DIR.mkdir(parents=True, exist_ok=True)
if not MODULE_DIR.exists():
    MODULE_DIR.mkdir(parents=True, exist_ok=True)