from pathlib import Path
import os
import multiprocessing
from joblib import Parallel, delayed
from data_collection.logger import logger
from data_collection.constant import CVE2ADVISORY_FILE, COMMITS_FILE_NO_CHECKS, REPO_DIR, filtered_cves_by_available_versions_file
from data_collection.get_compatable_python_version import filter_versions
import json
import pickle
import re
from tqdm import tqdm
import subprocess
def get_repo_url(commit_url):
    # commit_url = "https://github.com/toastdriven/django-tastypie/commit/e8af315211b07c8f48f32a063233cc3f76dd5bc2"
    repo_url = commit_url.split('/commit')[0]
    return repo_url
def get_repo_name(repo_url):
    """从仓库URL获取仓库名称"""
    return '_'.join(repo_url.split('/')[-2:])

def clone_repo(repo_url, repo_dest_path):
    """克隆单个仓库"""
    try:
        logger.info(f"Cloning from remote: {repo_url}")
        repo_url = repo_url.rstrip('/')
        if ".git" not in repo_url:
            # cmd = ["git", "clone", "--filter=blob:none","--mirror", f"{repo_url}.git", str(repo_dest_path)]
            # cmd = ["git", "clone","--mirror", "--filter=tree:0",f"{repo_url}.git", str(repo_dest_path)]
            cmd = ["git", "clone","--mirror",f"{repo_url}.git", str(repo_dest_path)]
        else:
            # cmd = ["git", "clone", "--filter=blob:none","--mirror", repo_url, str(repo_dest_path)]
            # cmd = ["git", "clone","--mirror", "--filter=tree:0",f"{repo_url}", str(repo_dest_path)]
            cmd = ["git", "clone","--mirror", f"{repo_url}", str(repo_dest_path)]
        logger.debug("Running command: " + " ".join(cmd))
        
        # 第一次尝试
        result = subprocess.run(cmd,text=True)
        if result.returncode != 0:
            logger.warning(f"First attempt failed, trying with SSL verification disabled")
            logger.debug(f"Error output: {result.stderr}")
            
            # 第二次尝试禁用SSL验证
            cmd.insert(1, "-c")
            cmd.insert(2, "http.sslVerify=false")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
        if result.returncode == 0:
            logger.info(f"Cloning done: {repo_url}")
            return True
        else:
            logger.error(f"Failed to clone {repo_url}. Error: {result.stderr}")
            return False
            
    except Exception as e:
        logger.error(f"Failed to clone {repo_url}: {str(e)}")
        return False
def clone_repo_parallel(repo_url,repo_dest_path):
    """并行克隆仓库的包装函数"""
    try:
        clone_repo(repo_url, repo_dest_path)
        return True
    except Exception as e:
        logger.error(f"Failed to clone {repo_url}: {str(e)}")
        return False
def clone_repos_parallel(repo_urls, repo_dir, max_workers=4):
    """并行克隆多个仓库"""
    if not repo_urls:
        return []
        
    logger.info(f"Starting parallel cloning of {len(repo_urls)} repos")
    
    # 准备参数列表
    clone_tasks = []
    for repo_url in repo_urls:
        repo_url = repo_url.strip()
        repo_path = repo_dir / get_repo_name(repo_url)
        clone_tasks.append((repo_url, repo_path))
    
    # 并行执行克隆
    # assert False
    num_cores = multiprocessing.cpu_count()
    results = Parallel(n_jobs=min(num_cores, max_workers))(
        delayed(clone_repo)(url, path) for url, path in clone_tasks
    )
    
    logger.info(f"Finished parallel cloning, success: {sum(results)}/{len(results)}")
    return results

if __name__ == '__main__':
    # read data from COMMITS_FILE_NO_CHECKS
    with open(COMMITS_FILE_NO_CHECKS, 'r') as f:
        adv2commits = json.load(f)
    # read data from CVE2ADVISORY_FILE
    with open(CVE2ADVISORY_FILE, "rb") as f:
        cve2advisory = pickle.load(f)
      
    # create cve2advisory_id
    for cve_id, advisory in cve2advisory.items():
        advisory_id = advisory['id']
        if advisory_id not in adv2commits:
            cve2advisory[cve_id]['fix_commits'] = []
            # logger.info(f'No commits found for {advisory_id}')
        else:
            cve2advisory[cve_id]['fix_commits'] = adv2commits[advisory_id]['urls']
    
    cve2advisory = {cve_id:advisory for cve_id, advisory in cve2advisory.items() if len( cve2advisory[cve_id]['fix_commits']) > 0}
    # 统计repo的数量
    repo_urls = set()
    repo_urls_file = 'repo_urls.txt'
    if os.path.exists(repo_urls_file):
        with open(repo_urls_file, 'r') as f:
            repo_urls = set(f.read().split('\n'))
    else:
        with open('repo_urls.txt', 'w') as f:
            pass
        for cve_id, advisory in tqdm(cve2advisory.items()):
            find_available_versions = False
        
            for affected_version in advisory['affected']:
                package = affected_version['package']['name']
                versions = affected_version['versions']
                # 只保留在pypi中还可用的版本
                # logger.debug(f'Filtering versions for {package}, versions: {versions}')
                versions = filter_versions(package,versions)
                if len(versions) > 0:
                    find_available_versions = True
                    break
            if not find_available_versions:
                # no available versions, skip 
                logger.info(f'No available versions for {cve_id}')
                logger.info(f'advisory: {advisory}')
                continue
            fixing_commits = advisory['fix_commits']
            with open('repo_urls.txt', 'a') as f:
                for commit in fixing_commits:
                    repo_url = get_repo_url(commit)
                    if repo_url not in repo_urls:
                        repo_urls.add(repo_url)
                        f.write(repo_url + '\n')
    logger.info(f'Found {len(repo_urls)} repos in {repo_urls_file}')
    

    
    filtered_cves_by_available_versions_file = 'filtered_cves_by_available_versions.pickle'
    if not os.path.exists(filtered_cves_by_available_versions_file):
        with open(filtered_cves_by_available_versions_file, 'rb') as f:
            filtered_cves_by_available_versions = pickle.load(f)
    else:
        # 统计过滤掉多少个CVE
        with open('./logs_cache/clone_repos_with_no_available_version_cves.log', 'r') as f:
            log = f.read()
            log = log.split('\n')
            # for lineno,l in enumerate(log):
            #     print(lineno,l)
            log = [l for l in log if 'No available versions for' in l]
            # 使用正则表达式提取所有CVE ID
            cve_pattern = r'No available versions for (CVE-\d{4}-\d{4,})'
            filtered_cves_by_available_versions = []
            for line in log:
                match = re.search(cve_pattern, line)
                if match:
                    filtered_cves_by_available_versions.append(match.group(1))
            with open(filtered_cves_by_available_versions_file, 'wb') as f:
                pickle.dump(filtered_cves_by_available_versions,f)
    logger.info(f"过滤掉 {len(filtered_cves_by_available_versions)} CVE ID列表: {filtered_cves_by_available_versions}")
    clone_tasks = []
    for repo_url in repo_urls:
        repo_path = REPO_DIR / get_repo_name(repo_url)
        if not repo_path.exists():
            logger.info(f'Repo {repo_url} not found, cloning...')
            clone_tasks.append((repo_url, repo_path))
        else:
            logger.info(f'Repo {repo_url} already exists, skipping...')
    num_cores = multiprocessing.cpu_count()
    logger.info(f"Starting parallel cloning of {len(clone_tasks)} repos")
    for url, path in clone_tasks:
        clone_repo(url, path)
    assert False
    results = Parallel(n_jobs=min(num_cores, 4))(  # 限制最大4个并行
            delayed(clone_repo_parallel)(url, path) for url, path in clone_tasks
        )
    logger.info(f"Finished parallel cloning, success: {sum(results)}/{len(results)}")