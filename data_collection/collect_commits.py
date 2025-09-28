from pathlib import Path
import sys
import pickle
from urllib.parse import urlparse

sys.path.append(Path(__file__).parent.parent.as_posix())
from data_collection.github_utils import find_potential_commits_from_github, is_commit_url
import random
from data_collection.constant import COMMITS_DIR_DATE, CVE2ADVISORY_FILE,COMMITS_DIR, POSSIBLE_COMMITS_DIR_DATE, URLS_FILE,REPO_DIR,POSSIBLE_COMMITS_DIR, URLS_FILE_DATE,CVE2ADVISORY_VFC_FILE_DATE,DIFF_CACHE_DIR_DATE
from collections import defaultdict,Counter
import json
import re
# import matplotlib.pyplot as plt
random.seed(42)
import datetime
from tqdm import tqdm
from data_collection.vul_analyze import read_cve2advisory,get_pkg2url,get_modified_files,filter_files
from data_collection.my_utils import get_repo_url, get_repo_name,normalize_package_name,request_metadata_json_from_pypi,get_url_priority
from pydriller import Git
from itertools import chain
# 在文件顶部添加导入
from data_collection.logger import logger
from joblib import Parallel, delayed
from data_collection.clone_repos import clone_repo


def get_all_unique_affected_projects(advisory,normalized=True):
    all_unique_affected_projects = set()
    available_pkgs = advisory['available_affected']
    for affected_pkg, infos in available_pkgs.items():
        repo_url = infos['repo_url']
        if normalized:
            all_unique_affected_projects.add((normalize_package_name(affected_pkg),repo_url))
        else:
            all_unique_affected_projects.add((affected_pkg,repo_url))
            
    # for affected_version in advisory['affected']:
    #     package_name = affected_version['package']['name'].lower()
    #     all_unique_affected_projects.add((normalize_package_name(package_name),pkg2url[package_name]))
    # all_unique_affected_projects = list(all_unique_affected_projects)
    return all_unique_affected_projects
def get_extracted_urls_for_repo(extracted_urls:dict,repo_url:str, filter_large=False):
    # logger.info(extracted_urls)
    extracted_urls_for_repo = {}
    for source, urls in extracted_urls.items():
        commit_urls = set()
        for url in urls:
            url = url.rstrip('.').rstrip('.patch')
            if url.lower().startswith(repo_url.lower()):
                commit_urls.add(url)
        if filter_large and source != 'commit' and len(commit_urls) > 10:
            logger.warning(f'ignore PR and Issue with a large number of commits:{len(commit_urls)} mined commit links')
            continue
        
        extracted_urls_for_repo[source] = commit_urls
    return extracted_urls_for_repo
 # 根据URL内容关键词排序


def extract_all_possible_urls(advisory):

    """
    从安全公告中提取所有可能的修复提交URL。

    该函数解析安全公告中的引用链接，识别并提取GitHub上的潜在修复提交URL。
    主要处理commit、pull request和issue等类型的链接，并按优先级排序。

    参数:
    advisory (dict): 包含安全公告信息的字典，至少包含'references'键。

    返回:
    defaultdict(list): 键为来源（如'commit'、'pull'、'issue'），值为对应URL列表的字典。
    """
    url_result = defaultdict(list)

    # 1. 从OSV中提取可能存在的urls
    refs = advisory.get('references', [])
    assert refs != []
    netlocs = set()
    # 2. 按URL内容关键词排序
    sorted_refs = sorted(refs, key=lambda x: get_url_priority(x.get('url', '')))
    visited_pull_ids = []
    for ref in sorted_refs:
        # GHSA-cqhg-xjhh-p8hf 包含了snyk。会有很多commit，原因是这个pull是比较atomic commit的格式
        # 对于同时出现commit和pull的情况，认为commit为fixing commit，, GHSA-hhpg-v63p-wp7w
        # 也不能简单的通过release后的版本进行，因为并不是所有的commit都是和该CVE有关

        # solution:
        # 如果有commit直接出现在refs中，则认为这些即是fixing commit
        url = ref.get('url')
        # 1. find commit URL
        parsed_url = urlparse(url)
        nloc = parsed_url.netloc
        if nloc == 'github.com':
            source, commit_urls =  find_potential_commits_from_github(logger, url, visited_pull_ids)
            if source:   
                url_result[source].extend(commit_urls)
        else:
            # TODO: handle gitlab and bitbucket
            pass
        netlocs.add(nloc)

    
    # 从snyk收集可能的urls
    # snyk_urls = get_snyk_urls(advisory)
    return url_result,netlocs
# 维护一个全局的merge commit字典
merge_commit_file = Path('./merge_commits.json')
# if merge_commit_file.exists():
#     with open(merge_commit_file, 'r') as f:
#         merge_commits = json.load(f)
# else:
merge_commits = defaultdict(list)
FAILED_REPOS_FILE = 'failed_repos.txt'
with open(FAILED_REPOS_FILE, 'w') as f:
    f.write('')
def is_squash_commit(commit):
    msg = commit.msg.lower()
    if 'squash' in msg:
        return True
    lines = msg.strip().split('\n')
        
    # 至少需要3行（标题 + 2个以上的bullet point）
    if len(lines) < 3:
        return False
    
    # 统计以 * 或 - 开头的行数
    bullet_count = 0
    for line in lines[1:]:  # 跳过第一行（通常是标题）
        stripped = line.strip()
        if stripped.startswith('* '):
            bullet_count += 1
        elif stripped.startswith('*') and len(stripped) > 1:  # *xxx格式
            bullet_count += 1
    # 如果有2个以上的bullet point，很可能是squash commit
    return bullet_count >= 2
def adjust_message(message):
    # 去除回车符和多余的换行符，替换制表符和逗号为空格，去除前后空格
    message_no_carriage = message.replace("\r", "\n")
    message_no_carriage = '\n'.join(message_no_carriage.splitlines()[:3])
    one_newline_message = re.sub(r"\n+", "\n", message_no_carriage)
    clear_message = one_newline_message.replace("\n", "").replace("\t", " ").replace(",", " ").replace("\"", "'").replace('.', " ")
    stripped_message = clear_message.strip()
    return re.sub(r" +", " ", stripped_message)
def is_fix_commit(commit):
    msg = commit.msg.lower()
    # fixing_keywords
    bugfixing_keywords = {'fix', 'repair', 'error', 'bug', 'issue', 'cve', 'prevent', 'vulnerability', 'defect', 'patch','fault','incorrect','flaw','mistake'}
    # 'feat':https://github.com/dpgaspar/Flask-AppBuilder/commit/3030e881d2e44f4021764e18e489fe940a9b3636
    msg = adjust_message(msg).lower().split()
    for k in bugfixing_keywords:
        if k in msg:
            return True
    return False
def is_exclude_commit(commit):
    msg = commit.msg.lower()
    exclude_keywords_set = {'refactor', 'rename',  'wip', 'update','typo','readme','cleanup','bump'}
    # 'feat':https://github.com/dpgaspar/Flask-AppBuilder/commit/3030e881d2e44f4021764e18e489fe940a9b3636
    # logger.info(msg)
    msg = adjust_message(msg)
    # logger.info(msg)

    msg = msg.lower().split()
    # logger.info(msg)

    # assert False
    for k in exclude_keywords_set:
        if k in msg:
            return True
    return False

def get_modification_files_for_vfc(fixing_commit_obj, fixing_commit_url, cve_id=None,rewrite=False):
    logger.info(f'Processing commit {fixing_commit_url}')
    commit_hash = fixing_commit_obj.hash

    # 缓存diff对象
    commit_hash_ = fixing_commit_url.split('/')[-1]
    diff_cached = DIFF_CACHE_DIR_DATE / f"{cve_id}/{commit_hash_}.pkl"
    if not diff_cached.parent.exists():
        diff_cached.parent.mkdir(parents=True, exist_ok=True)

    
    modified_files = None
    if diff_cached.exists() and not rewrite:
        logger.info(f'Loading commit {commit_hash} from cache...')
        with open(diff_cached, 'rb') as f:
            commit_hash,modified_files = pickle.load(f)
    else:        
        # 提取代码变化
        logger.debug(f'Extracting {fixing_commit_url} code changes...')
        modified_files = fixing_commit_obj.modified_files
        try:
            with open(diff_cached, 'wb') as f:
                pickle.dump((commit_hash,modified_files), f)
        except Exception as e:
            with open(diff_cached, 'wb') as f:
                pickle.dump((commit_hash,[]), f)
        with open(diff_cached, 'rb') as f:
            commit_hash,modified_files = pickle.load(f)
        # print(modified_files)
        # assert False
    return commit_hash, modified_files

def is_source_code_modified(modified_files):    

    logger.debug([file.new_path for file in modified_files])
    modified_non_py_files,modified_py_files = filter_files(modified_files)
    logger.debug([file.new_path for file in modified_py_files])

        
    return modified_non_py_files,modified_py_files

def extract_candidate_fixing_commit_infos(all_possible_urls,repo_path,repo_url,advisory=None):
    """从安全公告中提取修复提交"""
    repo = Git(repo_path)
    all_vfc_infos = {}
    for commit_url in all_possible_urls:
        all_vfc_infos[commit_url] = {
            'passed_source_code_check': False,
            'passed_py_source_code_check':False,
            'passed_fix_check': False,
            'passed_exclude_check': False,
            'get_commit_error': False,
            'msg':'',
            'is_merge':False,
            'is_squash':False,
            'file_type_stats':{}
        }
        commit_hash = commit_url.rstrip('.').rstrip('.patch').split('/')[-1]
        # 过滤掉commit_url不以repo_url为前缀的情况# 例如"GHSA-m5vv-6r4h-3vj9"
        if not str(commit_url).lower().startswith(str(repo_url).lower()):
            logger.error(f'Commit {commit_url} does not start with repo path {repo_url}')
            assert False
        try:
            commit = repo.get_commit(commit_hash)
        except Exception as e:
            logger.warning(f'Commit {commit_hash} not found, skipping...')
            with open(FAILED_REPOS_FILE, 'a') as f:
                f.write(f"{commit_url}\t{repo_path}\n")
            all_vfc_infos[commit_url]['get_commit_error'] = True
            # assert False, commit_url
            continue
        #! 1. 对于merge commit要特殊处理
        if commit.merge:
            print(commit.merge)
            all_vfc_infos[commit_url]['is_merge'] = True
            msg = commit.msg
            # 将commit_url, aid,msg 写入json文件
            merge_commits[advisory['id']].append({'commit_url':commit_url,'msg':msg,'total_urls':len(all_possible_urls), 'cve_id':advisory['cve_id']})
        # ! 2. 是否是squash commit
        if is_squash_commit(commit):
            all_vfc_infos[commit_url]['is_squash'] = True
            # print(commit.msg)
            # assert False
        # ! 3. 检查commit msg是否包含修复关键字
        # 2. 根据是否有修复关键字过滤
        if is_fix_commit(commit):
            all_vfc_infos[commit_url]['passed_fix_check'] = True
        
        if not is_exclude_commit(commit):
            all_vfc_infos[commit_url]['passed_exclude_check'] = True
            
        # ! 4. 是否修改了source code
        _,modified_files = get_modification_files_for_vfc(fixing_commit_obj=commit, fixing_commit_url=commit_url, cve_id=advisory['cve_id'],rewrite=True)
        ret = is_source_code_modified(modified_files)
        modified_non_py_files,modified_py_files = ret  
        
        logger.info(f"commit_url:{commit_url} modified_files:{[file.new_path for file in modified_non_py_files]} {[file.new_path for file in modified_py_files]} ")

        # all_vfc_infos[commit_url]['modified_non_py_files'] = modified_non_py_files
        # all_vfc_infos[commit_url]['modified_py_files'] = modified_py_files
        file_type_stats = {}
        for file in modified_non_py_files+modified_py_files:
            file_path = file.filename
            file_path = Path(file_path)
            file_ext = file_path.suffix
            if len(file_ext.strip()) == 0:
                file_ext = file_path.name
            
            if file_ext not in file_type_stats:
                file_type_stats[file_ext] = 0
            file_type_stats[file_ext] += 1
        if ret:
            all_vfc_infos[commit_url]['passed_source_code_check'] = True
            all_vfc_infos[commit_url]['passed_py_source_code_check'] = len(modified_py_files)>0
            all_vfc_infos[commit_url]['file_type_stats'] = file_type_stats
        # else:
        #     logger.debug(f'Commit {commit_url} is not modified source code, {"merge commit" if commit.merge else ""}skipping...')
        all_vfc_infos[commit_url]['msg'] = commit.msg.split('\n')
    return all_vfc_infos



def load_results(file, rewrite=False):
    """加载处理结果"""
    if rewrite:
        return {}
    try:
        with open(file, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_result(results, aid, urls):
    """保存单个处理结果"""
    results[aid] = {
        'success': len(urls) > 0,
        'urls': list(urls) if urls else [],
        'timestamp': datetime.datetime.now().isoformat()
    }
    return results

def save_all_results(file, results):
    """保存所有处理结果"""
    with open(file, 'w') as f:
        json.dump(results, f, indent=2)

    # 在文件顶部添加导入
    import matplotlib.pyplot as plt
    import matplotlib
    matplotlib.rcParams['font.sans-serif'] = ['SimHei', 'Arial Unicode MS', 'DejaVu Sans']
    matplotlib.rcParams['axes.unicode_minus'] = False
    
    # 修改统计函数，添加可视化功能
def analyze_vfc_count_distribution_with_plot(cve2advisory, show_=False):
    """
    统计CVE的candidate VFCs数量分布，并生成详细的柱状图
    """
    print("\n=== CVE Candidate VFCs数量分布统计 ===")
    
    detailed_distribution = defaultdict(int)  # 精确的数量分布
    cve_details = {}  # 每个CVE的详细信息
    
    total_cves = set()
    total_vfcs = 0
    
    for cve_id, advisory in tqdm(cve2advisory.items(), desc="统计VFC数量"):
        all_unique_affected_projects = get_all_unique_affected_projects(advisory)
        
        cve_total_vfcs = 0
        cve_repo_info = []
        all_fixing_commits = advisory['fixing_commits']
        # 统计该CVE在所有repo中的candidate VFCs总数
        for package_name, repo_url in all_unique_affected_projects:
            if package_name not in all_fixing_commits:
                continue
            fixing_commits = all_fixing_commits[package_name]
            if len(fixing_commits) > 0:
                # if len(fixing_commits) > 10:
                #     assert False
                total_cves.add(cve_id)
                valid_vfc_count = len(fixing_commits)
                repo_vfc_count = valid_vfc_count
                cve_total_vfcs += repo_vfc_count
                cve_repo_info.append({
                    'package': package_name,
                    'repo_url': repo_url,
                    'vfc_count': repo_vfc_count
                })
        
        # 记录该CVE的详细信息
        cve_details[cve_id] = {
            'total_vfcs': cve_total_vfcs,
            'repo_count': len(cve_repo_info),
            'repo_info': cve_repo_info
        }
        
        # 更新统计
        total_vfcs += cve_total_vfcs
        detailed_distribution[cve_total_vfcs] += 1
    total_cves = len(total_cves)
    # 输出基本统计
    print(f"总CVE数量: {total_cves}")
    print(f"总candidate VFCs数量: {total_vfcs}")
    print(f"平均每个CVE的VFC数量: {total_vfcs/total_cves:.2f}")
    if show_:
    
        # 准备绘图数据
        max_vfc_count = max(detailed_distribution.keys()) if detailed_distribution else 0
        
        # 创建完整的VFC数量序列（0到最大值）
        vfc_counts = list(range(0, max_vfc_count + 1))
        cve_numbers = [detailed_distribution.get(count, 0) for count in vfc_counts]
        
        # 创建柱状图
        plt.figure(figsize=(15, 8))
        
        # 绘制柱状图
        bars = plt.bar(vfc_counts, cve_numbers, alpha=0.7, color='steelblue', edgecolor='black', linewidth=0.5)
        
        # 设置图表标题和标签
        plt.title('CVE Candidate VFCs Distribution', fontsize=16, fontweight='bold', pad=20)
        plt.xlabel('#Candidate VFCs', fontsize=14)
        plt.ylabel('#CVE', fontsize=14)
        
        # 设置x轴刻度
        if max_vfc_count <= 20:
            plt.xticks(vfc_counts)
        else:
            # 如果数量太多，只显示部分刻度
            step = max(1, max_vfc_count // 20)
            plt.xticks(range(0, max_vfc_count + 1, step))
        
        # 在柱子上方显示数值（只显示非零值）
        for i, (count, number) in enumerate(zip(vfc_counts, cve_numbers)):
            if number > 0:
                plt.text(count, number + max(cve_numbers) * 0.01, str(number), 
                        ha='center', va='bottom', fontsize=10)
        
        # 添加网格
        plt.grid(axis='y', alpha=0.3, linestyle='--')
        
        # 设置y轴从0开始
        plt.ylim(bottom=0)
        
        # 调整布局
        plt.tight_layout()
        
        # 保存图表
        plot_file = COMMITS_DIR_DATE / 'vfc_distribution_plot.png'
        plt.savefig(plot_file, dpi=300, bbox_inches='tight')
        print(f"\n柱状图已保存到: {plot_file}")
        
        # 显示图表
        plt.show()
        
        # 创建第二个图：只显示前20个VFC数量的详细分布
        if max_vfc_count > 20:
            plt.figure(figsize=(12, 6))
            
            # 只显示前20个
            vfc_counts_subset = vfc_counts[:21]  # 0-20
            cve_numbers_subset = cve_numbers[:21]
            
            bars = plt.bar(vfc_counts_subset, cve_numbers_subset, alpha=0.7, 
                            color='lightcoral', edgecolor='black', linewidth=0.5)
            
            plt.title('CVE Candidate VFCs数量分布 (0-20个VFC)', fontsize=16, fontweight='bold', pad=20)
            plt.xlabel('Candidate VFCs数量', fontsize=14)
            plt.ylabel('CVE数量', fontsize=14)
            plt.xticks(vfc_counts_subset)
            
            # 在柱子上方显示数值
            for i, (count, number) in enumerate(zip(vfc_counts_subset, cve_numbers_subset)):
                if number > 0:
                    plt.text(count, number + max(cve_numbers_subset) * 0.01, str(number), 
                            ha='center', va='bottom', fontsize=10)
            
            plt.grid(axis='y', alpha=0.3, linestyle='--')
            plt.ylim(bottom=0)
            plt.tight_layout()
            
            # 保存详细图表
            plot_file_detail = COMMITS_DIR_DATE / 'vfc_distribution_detail_plot.png'
            plt.savefig(plot_file_detail, dpi=300, bbox_inches='tight')
            print(f"详细柱状图已保存到: {plot_file_detail}")
            plt.show()
    
    # 输出详细的数值统计表
    print("\n=== 详细VFC数量分布表 ===")
    print(f"{'VFC数量':<8} {'CVE数量':<8} {'百分比':<10} {'累计数量':<10} {'累计百分比':<12}")
    print("-" * 60)
    
    cumulative_count = 0
    for vfc_count in sorted(detailed_distribution.keys()):
        cve_count = detailed_distribution[vfc_count]
        percentage = cve_count / total_cves * 100
        cumulative_count += cve_count
        cumulative_pct = cumulative_count / total_cves * 100
        
        print(f"{vfc_count:<8} {cve_count:<8} {percentage:<10.1f}% {cumulative_count:<10} {cumulative_pct:<12.1f}%")
    
    
    return detailed_distribution
    

def analyze_vfc_threshold_stats(cve2advisory, max_n=10):
    """
    统计VFC数量小于n的CVE占总CVE的百分比和数量
    
    Args:
        cve2advisory: CVE字典
        max_n: 最大阈值，默认统计到10
    """
    print("\n=== VFC数量阈值统计 ===")
    
    # 统计每个CVE的VFC总数
    cve_vfc_counts = {}
    total_cves = set()
    for cve_id, advisory in tqdm(cve2advisory.items(), desc="统计VFC数量"):
        all_unique_affected_projects = get_all_unique_affected_projects(advisory)
        
        cve_total_vfcs = 0
        
        all_fixing_commits = advisory['fixing_commits']
        # 统计该CVE在所有repo中的candidate VFCs总数
        for package_name, repo_url in all_unique_affected_projects:
            if package_name not in all_fixing_commits:
                continue
            fixing_commits = all_fixing_commits[package_name]
            if len(fixing_commits) > 0:
                # if len(fixing_commits) > 10:
                #     assert False
                cve_total_vfcs += len(fixing_commits)
                total_cves.add(cve_id)
        cve_vfc_counts[cve_id] = cve_total_vfcs
    
    total_cves = len(total_cves)
    
    # 输出阈值统计
    print(f"{'阈值(VFC<n)':<12} {'CVE数量':<10} {'百分比':<10}")
    print("-" * 35)
    
    for n in range(1, max_n + 1):
        count_below_n = sum(1 for count in cve_vfc_counts.values() if count < n)
        percentage = count_below_n / total_cves * 100
        print(f"VFC < {n:<8} {count_below_n:<10} {percentage:<10.1f}%")
    
    # 额外统计一些特殊阈值
    special_thresholds = [15, 20, 25, 30, 50]
    print("\n=== 特殊阈值统计 ===")
    print(f"{'阈值(VFC<n)':<12} {'CVE数量':<10} {'百分比':<10}")
    print("-" * 35)
    
    for n in special_thresholds:
        count_below_n = sum(1 for count in cve_vfc_counts.values() if count < n)
        percentage = count_below_n / total_cves * 100
        print(f"VFC < {n:<8} {count_below_n:<10} {percentage:<10.1f}%")
    
    # 保存结果
    threshold_stats = {}
    for n in range(1, max_n + 1):
        count_below_n = sum(1 for count in cve_vfc_counts.values() if count < n)
        threshold_stats[f'vfc_less_than_{n}'] = {
            'count': count_below_n,
            'percentage': count_below_n / total_cves * 100
        }
    
    # 添加特殊阈值
    for n in special_thresholds:
        count_below_n = sum(1 for count in cve_vfc_counts.values() if count < n)
        threshold_stats[f'vfc_less_than_{n}'] = {
            'count': count_below_n,
            'percentage': count_below_n / total_cves * 100
        }
    
    
    return threshold_stats



def evaluate_candidate_fixing_commit_dist(cve2advisory):
    """评估修复提交的分布"""
    cve2commit = defaultdict(list)
    cve2candidate_vfcs = defaultdict(dict)
    for idxx, (cve_id, advisory) in enumerate(tqdm(cve2advisory.items())):
        aid = advisory['id']
        possible_commit_file = POSSIBLE_COMMITS_DIR_DATE /f"{cve_id}.json"
        
        with possible_commit_file.open('r') as f:
            extracted_urls = json.load(f)

        url_sources = {'commit':[],'pull':[],'issue':[]}
        for source in extracted_urls:
            url_sources[source].append(extracted_urls[source])
        print(url_sources)
        cve2candidate_vfcs[cve_id] = url_sources
    # 统计每个cve的commit,pr,issue的数量
        # 统计每个cve的commit,pr,issue的数量
    cve2commit_num = defaultdict(dict)
    
    # 统计各种来源的CVE数量
    commit_cves = set()  # 能够通过commit直接获得VFCs的CVE
    pr_cves = set()      # 能够通过PR获得VFCs的CVE  
    issue_cves = set()   # 能够通过issue获得VFCs的CVE
    
    # 统计各来源的URL总数
    total_commits = 0
    total_prs = 0
    total_issues = 0
    
    for cve_id in cve2candidate_vfcs:
        cve_stats = {}
        for source in cve2candidate_vfcs[cve_id]:
            url_count = len(cve2candidate_vfcs[cve_id][source])
            cve_stats[source] = url_count
            
            # 记录有该来源的CVE
            if url_count > 0:
                if source == 'commit':
                    commit_cves.add(cve_id)
                    total_commits += url_count
                elif source == 'pull':
                    pr_cves.add(cve_id)
                    total_prs += url_count
                elif source == 'issue':
                    issue_cves.add(cve_id)
                    total_issues += url_count
        
        cve2commit_num[cve_id] = cve_stats
    
    # 打印统计结果
    print(f"\n=== CVE来源统计 ===")
    print(f"总CVE数量: {len(cve2candidate_vfcs)}")
    print(f"能通过commit直接获得VFCs的CVE数量: {len(commit_cves)} ({len(commit_cves)/len(cve2candidate_vfcs)*100:.1f}%)")
    print(f"能通过PR获得VFCs的CVE数量: {len(pr_cves)} ({len(pr_cves)/len(cve2candidate_vfcs)*100:.1f}%)")
    print(f"能通过issue获得VFCs的CVE数量: {len(issue_cves)} ({len(issue_cves)/len(cve2candidate_vfcs)*100:.1f}%)")
    
    print(f"\n=== URL数量统计 ===")
    print(f"总commit URL数量: {total_commits}")
    print(f"总PR URL数量: {total_prs}")
    print(f"总issue URL数量: {total_issues}")
    
    # 交集分析
    commit_only = commit_cves - pr_cves - issue_cves
    pr_only = pr_cves - commit_cves - issue_cves
    issue_only = issue_cves - commit_cves - pr_cves
    commit_and_pr = commit_cves & pr_cves - issue_cves
    commit_and_issue = commit_cves & issue_cves - pr_cves
    pr_and_issue = pr_cves & issue_cves - commit_cves
    commit_pr_issue = pr_cves & issue_cves & commit_cves
    all_ = commit_cves | pr_cves | issue_cves
    
    print(f"\n=== 来源重叠分析 ===")
    print(f"仅能通过commit的CVE: {len(commit_only)}")
    print(f"仅能通过PR的CVE: {len(pr_only)}")
    print(f"仅能通过issue的CVE: {len(issue_only)}")
    print(f"同时有commit和PR的CVE: {len(commit_and_pr)}")
    print(f"同时有commit和issue的CVE: {len(commit_and_issue)}")
    print(f"同时有PR和issue的CVE: {len(pr_and_issue)}")
    print(f"同时有commit,PR和issue的CVE: {len(commit_pr_issue)}")

    print(f"能获得VFCs的CVE数量: {len(all_)}")

    # 统计cve拥有的candidate vfcs数量
    # 重要的信息是我想查看只有1个VFC的有多少个case，以及2，3，和大于5个的 
    # 调用统计函数
    # threshold_results = analyze_vfc_threshold_stats(cve2advisory)

    # vfc_stats = analyze_vfc_count_distribution_with_plot(cve2advisory)

    # 调用统计函数
    # 输出关键结果摘要
    # print("\n=== 关键统计摘要 ===")
    # print(f"只有1个VFC的CVE: {vfc_stats['one_vfc']} 个")
    # print(f"只有2个VFC的CVE: {vfc_stats['two_vfc']} 个")
    # print(f"只有3个VFC的CVE: {vfc_stats['three_vfc']} 个")
    # print(f"只有4个VFC的CVE: {vfc_stats['four_vfc']} 个")
    # print(f"只有5个VFC的CVE: {vfc_stats['five_vfc']} 个")
    # print(f"大于5个VFC的CVE: {vfc_stats['more_than_five_vfc']} 个")
    # print(f"总共有VFC的CVE: {vfc_stats['total_with_vfcs']} 个")
    return all_

    
def evaluate_modified_file_type(cve2advisory):
    """
    分析修改的文件类型分布
    1. 统计所有文件类型的分布（Top 10）
    2. 重点分析Python和C/C++文件的修改情况
    """
    print("\n=== 修改文件类型分析 ===")
    
    # 统计所有文件类型
    all_file_types = defaultdict(int)
    
    # 统计CVE级别的文件类型组合
    cve_file_type_combinations = {
        'only_python': set(),
        'only_c_cpp': set(), 
        'python_and_c_cpp': set(),
        'python_and_others': set(),
        'c_cpp_and_others': set(),
        'only_others': set(),
        'python_c_cpp_others': set()
    }
    
    # 统计commit级别的文件类型
    commit_file_types = {
        'only_python': 0,
        'only_c_cpp': 0,
        'python_and_c_cpp': 0,
        'python_and_others': 0,
        'c_cpp_and_others': 0,
        'only_others': 0,
        'python_c_cpp_others': 0
    }
    
    # 定义文件类型分类
    python_extensions = {'.py', '.pyx', '.pyi'}
    c_cpp_extensions = {'.c', '.cpp', '.cc', '.cxx', '.h', '.hpp', '.hxx'}
    
    total_commits = 0
    total_cves_with_files = 0
    total_cves_with_infos = set()
    valid_cves = set()
    for cve_id, advisory in tqdm(cve2advisory.items(), desc="分析文件类型"):
        all_unique_affected_projects = get_all_unique_affected_projects(advisory)
        
        cve_has_python = False
        cve_has_c_cpp = False
        cve_has_others = False
        cve_all_file_types = set()
        # logger.debug(f"all_unique_affected_projects:{all_unique_affected_projects}")
        for package_name, repo_url in all_unique_affected_projects:
            candidate_vfc_info_file = COMMITS_DIR_DATE/f'{cve_id}_{package_name}_candidate_vfc_infos.json'
            
            if not candidate_vfc_info_file.exists():
                continue
                
            with candidate_vfc_info_file.open('r') as f:
                candidate_vfc_infos = json.load(f)
            
            if len(candidate_vfc_infos) == 0:
                continue

            
            # 分析每个commit的文件类型
            for commit_url, info in candidate_vfc_infos.items():
                if info.get('get_commit_error', False):
                    continue
                # is_merge = info.get('is_merge', False) or info.get('is_squash', False)
                is_merge = info.get('is_merge', False)

                has_source_code = info.get('passed_source_code_check', False)
                has_py_source_code = info.get('passed_py_source_code_check', False)

                # 获取关键词检查结果
                has_fixing = info.get('passed_fix_check', False)
                not_has_exclude = info.get('passed_exclude_check', False)
                file_type_stats = info.get('file_type_stats',{})
                
                if is_merge or not has_source_code or not not_has_exclude:
                    continue
                total_commits += 1
                if has_py_source_code:
                    
                    valid_cves.add(cve_id)
                # if cve_id == 'CVE-2020-1735':
                #     print(info)
                #     print(has_py_source_code)
                if cve_id in SEP_CVE:
                    diff_cached = DIFF_CACHE_DIR_DATE / f"{cve_id}/{commit_url.split('/')[-1]}.pkl"
                    with open(diff_cached, 'rb') as f:
                        commit_hash,modified_files = pickle.load(f)
                    ret = is_source_code_modified(modified_files)
                    print(has_py_source_code)
                    print(ret)
                    print(commit_url)
                    # assert False
 
                
                total_cves_with_infos.add(cve_id)
                
                if not info.get('passed_source_code_check', False):
                    continue
                
                file_type_stats = info.get('file_type_stats', {})
                if not file_type_stats:
                    continue
                
                
                # 统计全局文件类型分布
                for file_ext, count in file_type_stats.items():
                    all_file_types[file_ext] += count
                # 分析该commit的文件类型组合
                commit_extensions = set(file_type_stats.keys())
                cve_all_file_types.update(commit_extensions)
                
                has_python = bool(commit_extensions & python_extensions)
                has_c_cpp = bool(commit_extensions & c_cpp_extensions)
                has_others = bool(commit_extensions - python_extensions - c_cpp_extensions)
                
                # 更新CVE级别的标记
                if has_python:
                    cve_has_python = True
                if has_c_cpp:
                    cve_has_c_cpp = True
                if has_others:
                    cve_has_others = True
                
                # 统计commit级别的文件类型组合
                if has_python and has_c_cpp and has_others:
                    commit_file_types['python_c_cpp_others'] += 1
                elif has_python and has_c_cpp:
                    commit_file_types['python_and_c_cpp'] += 1
                elif has_python and has_others:
                    commit_file_types['python_and_others'] += 1
                elif has_c_cpp and has_others:
                    commit_file_types['c_cpp_and_others'] += 1
                elif has_python:
                    commit_file_types['only_python'] += 1
                elif has_c_cpp:
                    commit_file_types['only_c_cpp'] += 1
                elif has_others:
                    commit_file_types['only_others'] += 1
        
        # 统计CVE级别的文件类型组合
        if cve_all_file_types:  # 该CVE有修改文件
            total_cves_with_files += 1
            
            if cve_has_python and cve_has_c_cpp and cve_has_others:
                cve_file_type_combinations['python_c_cpp_others'].add(cve_id)
            elif cve_has_python and cve_has_c_cpp:
                cve_file_type_combinations['python_and_c_cpp'].add(cve_id)
            elif cve_has_python and cve_has_others:
                cve_file_type_combinations['python_and_others'].add(cve_id)
            elif cve_has_c_cpp and cve_has_others:
                cve_file_type_combinations['c_cpp_and_others'].add(cve_id)
            elif cve_has_python:
                cve_file_type_combinations['only_python'].add(cve_id)
            elif cve_has_c_cpp:
                cve_file_type_combinations['only_c_cpp'].add(cve_id)
            elif cve_has_others:
                cve_file_type_combinations['only_others'].add(cve_id)
    # if 'CVE-2020-1735' in valid_cves:
    #     assert False
    # 输出统计结果
    print(f"\n=== 文件类型分布统计 ===")
    print(f"总计分析的commit数量: {total_commits}")
    print(f"总计有修改文件的CVE数量: {total_cves_with_files}, {len(valid_cves)}")
    print(f"原始CVE数量:{len(total_cves_with_infos)}")
    
    # Top 10 文件类型
    print(f"\n=== Top 10 文件类型 ===")
    sorted_file_types = sorted(all_file_types.items(), key=lambda x: x[1], reverse=True)
    print(f"{'文件类型':<15} {'修改次数':<10} {'占比':<10}")
    print("-" * 40)
    
    total_file_modifications = sum(all_file_types.values())
    for i, (file_ext, count) in enumerate(sorted_file_types[:10]):
        percentage = count / total_file_modifications * 100
        print(f"{file_ext:<15} {count:<10} {percentage:<10.2f}%")
    
    # Python和C/C++文件分析
    print(f"\n=== Python和C/C++文件修改分析 ===")
    
    # Commit级别统计
    print(f"\n--- Commit级别统计 ---")
    print(f"{'类型':<25} {'Commit数量':<12} {'占比':<10}")
    print("-" * 50)
    
    for category, count in commit_file_types.items():
        percentage = count / total_commits * 100 if total_commits > 0 else 0
        category_name = {
            'only_python': '仅修改Python文件',
            'only_c_cpp': '仅修改C/C++文件', 
            'python_and_c_cpp': '同时修改Python和C/C++',
            'python_and_others': 'Python和其他文件',
            'c_cpp_and_others': 'C/C++和其他文件',
            'only_others': '仅修改其他文件',
            'python_c_cpp_others': 'Python、C/C++和其他'
        }[category]
        print(f"{category_name:<25} {count:<12} {percentage:<10.2f}%")
    
    # CVE级别统计
    print(f"\n--- CVE级别统计 ---")
    print(f"{'类型':<25} {'CVE数量':<12} {'占比':<10}")
    print("-" * 50)
    
    for category, cve_set in cve_file_type_combinations.items():
        count = len(cve_set)
        percentage = count / total_cves_with_files * 100 if total_cves_with_files > 0 else 0
        category_name = {
            'only_python': '仅修改Python文件',
            'only_c_cpp': '仅修改C/C++文件',
            'python_and_c_cpp': '同时修改Python和C/C++', 
            'python_and_others': 'Python和其他文件',
            'c_cpp_and_others': 'C/C++和其他文件',
            'only_others': '仅修改其他文件',
            'python_c_cpp_others': 'Python、C/C++和其他'
        }[category]
        print(f"{category_name:<25} {count:<12} {percentage:<10.2f}%")
    
    # 重点关注Python和C/C++
    python_commits = (commit_file_types['only_python'] + 
                     commit_file_types['python_and_c_cpp'] + 
                     commit_file_types['python_and_others'] + 
                     commit_file_types['python_c_cpp_others'])
    
    c_cpp_commits = (commit_file_types['only_c_cpp'] + 
                    commit_file_types['python_and_c_cpp'] + 
                    commit_file_types['c_cpp_and_others'] + 
                    commit_file_types['python_c_cpp_others'])
    
    python_cves = len(cve_file_type_combinations['only_python'] | 
                     cve_file_type_combinations['python_and_c_cpp'] | 
                     cve_file_type_combinations['python_and_others'] | 
                     cve_file_type_combinations['python_c_cpp_others'])
    
    c_cpp_cves = len(cve_file_type_combinations['only_c_cpp'] | 
                    cve_file_type_combinations['python_and_c_cpp'] | 
                    cve_file_type_combinations['c_cpp_and_others'] | 
                    cve_file_type_combinations['python_c_cpp_others'])
    
    print(f"\n=== 重点统计摘要 ===")
    print(f"涉及Python文件的commit: {python_commits} ({python_commits/total_commits*100:.2f}%)")
    print(f"涉及C/C++文件的commit: {c_cpp_commits} ({c_cpp_commits/total_commits*100:.2f}%)")
    print(f"涉及Python文件的CVE: {python_cves} ({python_cves/total_cves_with_files*100:.2f}%)")
    print(f"涉及C/C++文件的CVE: {c_cpp_cves} ({c_cpp_cves/total_cves_with_files*100:.2f}%)")
    
    return valid_cves

def evaluate_tangled_filtering(cve2advisory):
    """
    专门分析merge commit和source code条件的过滤效果
    统计四种组合情况：
    1. 有source code + 非merge commit
    2. 有source code + merge commit  
    3. 无source code + 非merge commit
    4. 无source code + merge commit
    """
    print("\n=== Merge Commit和Source Code过滤分析 ===")
    
    # 统计四种组合的CVE-Repo对
    source_code_no_merge_cve_repo = set()  # 有源码修改且非merge
    source_code_merge_cve_repo = set()     # 有源码修改且是merge
    no_source_code_no_merge_cve_repo = set()  # 无源码修改且非merge
    no_source_code_merge_cve_repo = set()     # 无源码修改且是merge
    not_merge_cve_repo = set()
    not_merge_has_source_code_cve_repo = set()
    
    # 统计commit级别的数据
    commit_stats = {
        'source_code_no_merge': 0,
        'source_code_merge': 0,
        'no_source_code_no_merge': 0,
        'no_source_code_merge': 0,
        'not_merge':0,
        'not_merge_has_source_code':0,
        'get_commit_error': 0,
        'total_commits': 0
    }
    
    # 详细统计信息
    detailed_stats = {
        'cves_with_candidates': set(),
        'total_original_commits': 0
    }
    valid_cves = set()
    for cve_id, advisory in tqdm(cve2advisory.items(), desc="分析merge和source code过滤"):
        all_unique_affected_projects = get_all_unique_affected_projects(advisory)
        
        for package_name, repo_url in all_unique_affected_projects:
            candidate_vfc_info_file = COMMITS_DIR_DATE/f'{cve_id}_{package_name}_candidate_vfc_infos.json'

            
            if not candidate_vfc_info_file.exists():
                continue
                
            with candidate_vfc_info_file.open('r') as f:
                candidate_vfc_infos = json.load(f)
            
            if len(candidate_vfc_infos) == 0:
                continue
            
            detailed_stats['cves_with_candidates'].add(cve_id)
            detailed_stats['total_original_commits'] += len(candidate_vfc_infos)
            
            # 分析每个commit的merge和source code状态
            for commit_url, info in candidate_vfc_infos.items():
                commit_stats['total_commits'] += 1
                
                # 检查get_commit_error
                if info.get('get_commit_error', False):
                    commit_stats['get_commit_error'] += 1
                    continue
                
                # 获取merge和source code状态
                # is_merge = info.get('is_merge', False) or info.get('is_squash', False)
                is_merge = info.get('is_merge', False)                
                if not is_merge:
                    valid_cves.add(cve_id)
                has_source_code = info.get('passed_source_code_check', False)
                
                # 分类统计
                if not is_merge:
                    commit_stats['not_merge'] +=1
                    not_merge_cve_repo.add((cve_id, package_name))
                if not is_merge and has_source_code:
                    commit_stats['not_merge_has_source_code']+=1
                    not_merge_has_source_code_cve_repo.add((cve_id, package_name))

                if has_source_code and not is_merge:
                    commit_stats['source_code_no_merge'] += 1
                    source_code_no_merge_cve_repo.add((cve_id, package_name))
                elif has_source_code and is_merge:
                    commit_stats['source_code_merge'] += 1
                    source_code_merge_cve_repo.add((cve_id, package_name))
                elif not has_source_code and not is_merge:
                    commit_stats['no_source_code_no_merge'] += 1
                    no_source_code_no_merge_cve_repo.add((cve_id, package_name))
                elif not has_source_code and is_merge:
                    commit_stats['no_source_code_merge'] += 1
                    no_source_code_merge_cve_repo.add((cve_id, package_name))
    
    # 计算有效commit数量（排除get_commit_error）
    valid_commits = commit_stats['total_commits'] - commit_stats['get_commit_error']
    
    # 输出统计结果
    print(f"\n=== 基本统计信息 ===")
    print(f"总CVE数量: {len(cve2advisory)}")
    print(f"有候选VFC的CVE数量: {len(detailed_stats['cves_with_candidates'])}")
    print(f"总commit数量: {commit_stats['total_commits']}")
    print(f"Get commit error数量: {commit_stats['get_commit_error']}")
    print(f"有效commit数量: {valid_commits}")

    print(f"pass_merge commit:{commit_stats['not_merge']}, removing {valid_commits-commit_stats['not_merge']}")
    print(f"pass_merge_and_source_code:{commit_stats['not_merge_has_source_code']}, removing {commit_stats['not_merge']-commit_stats['not_merge_has_source_code']}")
    #CVE-level
    print(f"pass_merge CVE:{len(set(cve_id for (cve_id, _) in not_merge_cve_repo))}, removing {len(detailed_stats['cves_with_candidates'])-len(set(cve_id for (cve_id, _) in not_merge_cve_repo))} CVEs")
    print(f"pass_merge_source_code CVE:{len(set(cve_id for (cve_id, _) in not_merge_has_source_code_cve_repo))}, removing {len(set(cve_id for (cve_id, _) in not_merge_cve_repo))-len(set(cve_id for (cve_id, _) in not_merge_has_source_code_cve_repo))} CVEs")
    return valid_cves
    
    

def evaluate_bugfixing_keywords_impact(cve2advisory):
    """
    分析bugfixing-keywords和non-bugfixing-keywords对VFC过滤的影响
    直接使用candidate_vfc_infos中的passed_fix_check和passed_non_fix_check字段
    """
    print("\n=== Bugfixing Keywords过滤影响分析 ===")
    
    # 统计四种消息类型的组合
    message_type_stats = {
        'has_fixing_no_exclude': 0,      # 有fixing关键词，无non-fixing关键词
        'no_fixing_no_exclude': 0,       # 无fixing关键词，无non-fixing关键词
        'has_fixing_has_exclude': 0,     # 有fixing关键词，有non-fixing关键词
        'no_fixing_has_exclude': 0,      # 无fixing关键词，有non-fixing关键词
        'get_commit_error': 0,
        'total_commits': 0
    }
    
    # CVE-Repo对级别的统计
    cve_repo_message_stats = {
        'has_fixing_no_exclude': set(),
        'no_fixing_no_exclude': set(),
        'has_fixing_has_exclude': set(),
        'no_fixing_has_exclude': set()
    }
    
    # 关键词影响统计
    keyword_impact = {
        'total_with_fixing_keywords': 0,
        'total_with_exclude_keywords': 0,
        'total_valid_commits': 0,
        'cves_with_candidates': set()
    }
    
    # 详细的关键词分析
    detailed_analysis = {
        'commits_passed_fixing_filter': 0,      # 通过fixing关键词过滤的commit
        'commits_failed_fixing_filter': 0,      # 未通过fixing关键词过滤的commit
        'commits_passed_exclude_filter': 0,  # 通过non-fixing关键词过滤的commit
        'commits_failed_exclude_filter': 0   # 未通过non-fixing关键词过滤的commit
    }
    only_one_vfc_cve_repo=set()
    vfc_count_after_merge_and_source = set()
    valid_cves = set()
    for cve_id, advisory in tqdm(cve2advisory.items(), desc="分析bugfixing关键词影响"):
        all_unique_affected_projects = get_all_unique_affected_projects(advisory)
        
        for package_name, repo_url in all_unique_affected_projects:
            candidate_vfc_info_file = COMMITS_DIR_DATE/f'{cve_id}_{package_name}_candidate_vfc_infos.json'
            
            if not candidate_vfc_info_file.exists():
                continue
                
            with candidate_vfc_info_file.open('r') as f:
                candidate_vfc_infos = json.load(f)
            
            if len(candidate_vfc_infos) == 0:
                continue
            
            
            # 分析每个commit的关键词状态
            for commit_url, info in candidate_vfc_infos.items():
                # is_merge = info.get('is_merge', False) or info.get('is_squash', False)
                is_merge = info.get('is_merge', False)
                has_source_code = info.get('passed_source_code_check', False)
                file_type_stats = info.get('file_type_stats',{})
                is_modified_py = file_type_stats.get('.py',0)>0
                not_has_exclude = info.get('passed_exclude_check', False)
                if is_merge or not has_source_code:
                    continue
                if not_has_exclude:
                    valid_cves.add(cve_id)
                vfc_count_after_merge_and_source.add((cve_id,commit_url))
                if len(candidate_vfc_infos)==1:
                    only_one_vfc_cve_repo.add((cve_id, package_name))
                    # continue

                keyword_impact['cves_with_candidates'].add(cve_id)
                message_type_stats['total_commits'] += 1
                
                # 检查get_commit_error
                if info.get('get_commit_error', False):
                    message_type_stats['get_commit_error'] += 1
                    continue
                
                
                # 获取关键词检查结果
                has_fixing = info.get('passed_fix_check', False)
                not_has_exclude = info.get('passed_exclude_check', False)
                
                if not_has_exclude:
                    keyword_impact['total_valid_commits'] += 1

                # 统计关键词出现情况
                if has_fixing:
                    keyword_impact['total_with_fixing_keywords'] += 1
                    detailed_analysis['commits_passed_fixing_filter'] += 1
                else:
                    # print(info)
                    # print(cve_id)
                    # assert False
                    detailed_analysis['commits_failed_fixing_filter'] += 1
                
                if not not_has_exclude:
                    keyword_impact['total_with_exclude_keywords'] += 1
                    detailed_analysis['commits_failed_exclude_filter'] += 1
                    # print(info)
                    # assert False
                else:
                    detailed_analysis['commits_passed_exclude_filter'] += 1
                
                # 分类统计四种组合
                if has_fixing and not_has_exclude:
                    message_type_stats['has_fixing_no_exclude'] += 1
                    cve_repo_message_stats['has_fixing_no_exclude'].add((cve_id, package_name))
                elif not has_fixing and not_has_exclude:
                    message_type_stats['no_fixing_no_exclude'] += 1
                    cve_repo_message_stats['no_fixing_no_exclude'].add((cve_id, package_name))
                elif has_fixing and not not_has_exclude:
                    message_type_stats['has_fixing_has_exclude'] += 1
                    cve_repo_message_stats['has_fixing_has_exclude'].add((cve_id, package_name))
                    
                elif not has_fixing and not not_has_exclude:
                    message_type_stats['no_fixing_has_exclude'] += 1
                    cve_repo_message_stats['no_fixing_has_exclude'].add((cve_id, package_name))
    
    # 输出统计结果
    print(f"\n=== 基本统计信息 ===")
    print(f"经过merge和source后的VFCs:{len(vfc_count_after_merge_and_source)}")
    print(f"经过merge和source后的CVEs:{len(set([cve_id for cve_id, _ in vfc_count_after_merge_and_source]))}")
    print(f"只有一个VFCs的CVE:{len(set([cve_id for cve_id,_ in only_one_vfc_cve_repo]))}")
    print(f"有多个候选VFC的CVE数量: {len(keyword_impact['cves_with_candidates'])}")
    print(f"总commit数量: {message_type_stats['total_commits']}")
    print(f"Get commit error数量: {message_type_stats['get_commit_error']}")
    print(f"有效commit数量: {keyword_impact['total_valid_commits']}")
    print(f"过滤后CVE数量: {len(valid_cves)} 原始CVE数量: {len(cve2advisory)}")
    
    
    print(f"\n=== 关键词出现统计 ===")
    valid_commits = keyword_impact['total_valid_commits']
    fixing_ratio = keyword_impact['total_with_fixing_keywords'] / valid_commits * 100 if valid_commits > 0 else 0
    exclude_ratio = keyword_impact['total_with_exclude_keywords'] / valid_commits * 100 if valid_commits > 0 else 0
    
    print(f"包含fixing关键词的commit: {keyword_impact['total_with_fixing_keywords']} ({fixing_ratio:.2f}%)")
    print(f"包含non-fixing关键词的commit: {keyword_impact['total_with_exclude_keywords']} ({exclude_ratio:.2f}%)")
    print(f"不包含non-fixing关键词的commit: {keyword_impact['total_valid_commits']-keyword_impact['total_with_exclude_keywords']} ({(100-exclude_ratio):.2f}%)")

    
    print(f"\n=== Commit级别消息类型分析 ===")
    print(f"{'消息类型':<30} {'Commit数量':<12} {'占比(有效)':<12}")
    print("-" * 60)
    
    categories = [
        ('有fixing + 无non-fixing', 'has_fixing_no_exclude'),
        ('无fixing + 无non-fixing', 'no_fixing_no_exclude'),
        ('有fixing + 有non-fixing', 'has_fixing_has_exclude'),
        ('无fixing + 有non-fixing', 'no_fixing_has_exclude')
    ]
    
    for category_name, key in categories:
        count = message_type_stats[key]
        ratio = count / valid_commits * 100 if valid_commits > 0 else 0
        print(f"{category_name:<30} {count:<12} {ratio:<12.2f}%")
    
    print(f"\n=== CVE-Repo对级别消息类型分析 ===")
    print(f"{'消息类型':<30} {'CVE-Repo对数':<12} {'唯一CVE数':<12}")
    print("-" * 60)
    
    for category_name, key in categories:
        cve_repo_set = cve_repo_message_stats[key]
        cve_repo_count = len(cve_repo_set)
        unique_cves = len(set(cve_id for cve_id, _ in cve_repo_set))
        print(f"{category_name:<30} {cve_repo_count:<12} {unique_cves:<12}")
    
    print(f"\n=== 关键词过滤效果分析 ===")
    
    # 计算理想的fixing关键词过滤效果（只保留有fixing且无non-fixing的）
    ideal_fixing_commits = message_type_stats['has_fixing_no_exclude']
    
    # 计算实际的fixing关键词过滤效果（排除有non-fixing的）
    commits_without_exclude = (message_type_stats['has_fixing_no_exclude'] + 
                                 message_type_stats['no_fixing_no_exclude'])
    
    print(f"理想fixing过滤结果 (有fixing + 无non-fixing): {ideal_fixing_commits} ({ideal_fixing_commits/valid_commits*100:.2f}%)")
    print(f"理想fixing过滤结果 (无non-fixing): {ideal_fixing_commits} ({ideal_fixing_commits/valid_commits*100:.2f}%)")
    print(f"排除non-fixing后的commit: {commits_without_exclude} ({commits_without_exclude/valid_commits*100:.2f}%)")
    
    # 分析过滤损失
    lost_by_no_fixing = message_type_stats['no_fixing_no_exclude']
    lost_by_exclude = message_type_stats['has_fixing_has_exclude']
    lost_by_both = message_type_stats['no_fixing_has_exclude']
    
    print(f"\n=== 过滤损失分析 ===")
    print(f"因缺少fixing关键词损失: {lost_by_no_fixing} ({lost_by_no_fixing/valid_commits*100:.2f}%)")
    print(f"因包含non-fixing关键词损失: {lost_by_exclude} ({lost_by_exclude/valid_commits*100:.2f}%)")
    print(f"因两个原因都有损失: {lost_by_both} ({lost_by_both/valid_commits*100:.2f}%)")
    
    
    return valid_cves
def process_mining_candidate_vfcs_joblib(cve_id, advisory,rewrite_all_possible_urls=False):
    # 1. mining possible urls from advisories
    possible_commit_file = POSSIBLE_COMMITS_DIR_DATE / f"{cve_id}.json"
    if not possible_commit_file.parent.exists():
        possible_commit_file.parent.mkdir(parents=True, exist_ok=True)
        
    if not rewrite_all_possible_urls and possible_commit_file.exists():
        with possible_commit_file.open('r') as f:
            extracted_urls = json.load(f)
        return []  # 没有新的netlocs
    else:
        extracted_urls, netlocs = extract_all_possible_urls(advisory)
        with possible_commit_file.open('w') as f:
            json.dump(extracted_urls, f)
    return netlocs

def mining_candidate_vfcs(cve2advisory):


    results = Parallel(n_jobs=5)(
        delayed(process_mining_candidate_vfcs_joblib)(cve_id, advisory,rewrite_all_possible_urls) for (cve_id, advisory) in cve2advisory.items()
    )
    # 合并所有netlocs结果
    all_netlocs = set()
    for netlocs in results:
        all_netlocs.update(netlocs)
    # for idxx, (cve, advisory) in enumerate(tqdm(cve2advisory.items())):
        # if idxx >= 3000:
        #     continue
        # if cve != 'CVE-2023-37276':
        #     continue
        # aid = advisory['id']
        # logger.info(f"Processing {cve} - {aid}")

        # 1. mining possible urls from advisories
        # possible_commit_file = POSSIBLE_COMMITS_DIR_DATE /f"{cve}.json"
        # if not possible_commit_file.parent.exists():
        #     possible_commit_file.parent.mkdir(parents=True, exist_ok=True)
        # if not rewrite_all_possible_urls and possible_commit_file.exists() and True:
        #     with possible_commit_file.open('r') as f:
        #         extracted_urls = json.load(f)
        # else:
        #     extracted_urls, netlocs = extract_all_possible_urls(advisory)
        #     all_netlocs.extend(netlocs)
        #     with possible_commit_file.open('w') as f:
        #         json.dump(extracted_urls, f)
    return all_netlocs

if __name__ == '__main__':
    # 在文件顶部修改常量定义
    DEBUG_FILE = "/Users/keviny/Desktop/Research/ANU/Projects/PyVul/data_collection/no_url_found_debug.txt"
    SUCCESS_FILE = "/Users/keviny/Desktop/Research/ANU/Projects/PyVul/data_collection/url_found_success.txt"
    
    # cve2advisory = read_cve2advisory()
    cve2advisory = read_cve2advisory(valid_py_cve=False,specific_date=True)

    # cves_filter_by_available_versions= read_cves_filter_by_available_versions()
    SPE_CVE = ['CVE-2024-41950','CVE-2020-17495']

    samples = list(cve2advisory.keys())[:]
    cve2advisory = {k:v for k,v in cve2advisory.items() if k in samples}
    
    rewrite_all_possible_urls = False
    rewrite_all_fixing_commits = True
    # all_possible_urls = load_results(URLS_FILE_DATE,rewrite=rewrite_all_possible_urls)
    # all_fixing_commits = load_results(COMMITS_FILE,rewrite=rewrite_all_fixing_commits)

        # logger.info(extracted_urls)
    all_netlocs = mining_candidate_vfcs(cve2advisory)
    all_netlocs = Counter(all_netlocs)
    logger.info(f'top 10 netlocs:{all_netlocs.most_common(10)}')

    # all_cve_with_vfcs = evaluate_candidate_fixing_commit_dist(cve2advisory)
    # assert False
    # pkg2url = get_pkg2url()
 

    samples = list(cve2advisory.keys())[:]
    cve2advisory = {k:v for k,v in cve2advisory.items() if k in samples}
    no_candidate_vfcs = defaultdict(list)
    filter_large_source = False
    for idxx, (cve_id, advisory) in enumerate(tqdm(cve2advisory.items())):
        # if cve_id not in SPE_CVE:
        #     continue
        # if cve_id !='CVE-2020-15265':
        #     continue
        possible_commit_file = POSSIBLE_COMMITS_DIR_DATE /f"{cve_id}.json"
        with possible_commit_file.open('r') as f:
            extracted_urls = json.load(f)
        all_unique_affected_projects = get_all_unique_affected_projects(advisory)

        # logger.info(f'all_unique_affected_projects:{all_unique_affected_projects}')

        for package_name,repo_url in all_unique_affected_projects:
            candidate_vfc_info_file = COMMITS_DIR_DATE/f'{cve_id}_{package_name}_candidate_vfc_infos.json'

                
            extracted_urls_for_repo = []
            if not candidate_vfc_info_file.parent.exists():
                candidate_vfc_info_file.parent.mkdir(parents=True, exist_ok=True)
            if not rewrite_all_fixing_commits and candidate_vfc_info_file.exists() and True:
                # print(f"Loading {candidate_vfc_info_file}")
                with candidate_vfc_info_file.open('r') as f:
                    candidate_vfc_infos = json.load(f)
            else:
                extracted_urls_for_repo = []
                if repo_url is None:
                    logger.warning(f'No repo url found for {package_name}')
                    continue
                repo_path = REPO_DIR / get_repo_name(repo_url)
                # 1. 从extracted_urls_for_package中找到所有的repo commit urls
                extracted_urls_for_repo = get_extracted_urls_for_repo(extracted_urls,repo_url,filter_large=filter_large_source)
                logger.debug(f'found {extracted_urls_for_repo}')
                
                if sum( len(urls) for urls in extracted_urls_for_repo.values())==0:
                    logger.warning(f'No fixing commits found for {package_name}')
                    candidate_vfc_infos = {}
                else:
                    logger.debug(f'found {sum( len(urls) for urls in extracted_urls_for_repo.values())} fixing commits for {package_name}')
                
                    # 2. 分别进行fixing commit解析
                    logger.info(f"Processing repo_url: {repo_url}")
                    if not repo_path.exists():
                        # assert False
                        success = clone_repo(repo_url, repo_path)
                        if not success:
                            continue
                    all_possible_urls = set(chain.from_iterable(extracted_urls_for_repo.values()))
                    candidate_vfc_infos = extract_candidate_fixing_commit_infos(all_possible_urls, repo_path, repo_url,advisory)
                # if cve_id == 'CVE-2024-41950':
                #     print(candidate_vfc_infos)
                with open(candidate_vfc_info_file, 'w') as f:
                    json.dump(candidate_vfc_infos, f)
            if len(candidate_vfc_infos) == 0:
                no_candidate_vfcs[cve_id].append(package_name)
        # assert False
    
    logger.info(f'no_candidate_vfcs_cves:{len(no_candidate_vfcs)}')
    # cve2advisory = {k:v for k,v in cve2advisory.items() if k not in no_candidate_vfcs}
    valid_cves_1=evaluate_tangled_filtering(cve2advisory=cve2advisory)
    cve2advisory = {cve_id:adi for cve_id,adi in cve2advisory.items() if cve_id in valid_cves_1}

    valid_cves_2 = evaluate_bugfixing_keywords_impact(cve2advisory=cve2advisory)
    cve2advisory = {cve_id:adi for cve_id,adi in cve2advisory.items() if cve_id in valid_cves_2}
    SEP_CVE = [ 'CVE-2010-4340']

    valid_cves_3 = evaluate_modified_file_type(cve2advisory=cve2advisory)
    # for  i in valid_cves_3:
    #     if 'CVE-2020-1735'  in i :
    #         print(i)
    #         assert False
    cve2advisory = {cve_id:adi for cve_id,adi in cve2advisory.items() if cve_id in valid_cves_3}

    print(len(valid_cves_2), len(valid_cves_3), len(valid_cves_2&valid_cves_3))
    
    def store_vfcs(cve2advisory=cve2advisory, filter_large_vfcs=True, priority_commit=True, filter_large_files=True):
        new_cve2advisory = {}
        for idxx, (cve_id, advisory) in enumerate(tqdm(cve2advisory.items())):
            fixing_commits = defaultdict(dict)
            advisory = advisory.copy()
            all_unique_affected_projects = get_all_unique_affected_projects(advisory)
            possible_commit_file = POSSIBLE_COMMITS_DIR_DATE /f"{cve_id}.json"
            with possible_commit_file.open('r') as f:
                extracted_urls = json.load(f)
            for package_name, repo_url in all_unique_affected_projects:
                
                candidate_vfc_info_file = COMMITS_DIR_DATE/f'{cve_id}_{package_name}_candidate_vfc_infos.json'
        
                
                with candidate_vfc_info_file.open('r') as f:
                    candidate_vfc_infos = json.load(f)
                fixing_commit2info = {}
                for commit_url, info in candidate_vfc_infos.items():
                    if info.get('get_commit_error', False):
                        continue
                    # is_merge = info.get('is_merge', False) or info.get('is_squash', False)
                    is_merge = info.get('is_merge', False)
                    has_source_code = info.get('passed_source_code_check', False)
                    has_py_source_code = info.get('passed_py_source_code_check', False)
                    # 获取关键词检查结果
                    has_fixing = info.get('passed_fix_check', False)
                    not_has_exclude = info.get('passed_exclude_check', False)
                    if is_merge or not not_has_exclude or not has_py_source_code:
                        continue
                    if filter_large_files and info['file_type_stats'].get('.py',0) > 10:
                        continue
                        
                    fixing_commit2info[commit_url]=info
                extracted_urls_for_repo = get_extracted_urls_for_repo(extracted_urls,repo_url)
                urls_from_commit = extracted_urls_for_repo.get('commit',[])

                new_fixing_commit2info = {}
                if priority_commit:
                    for url in urls_from_commit:
                        if url in fixing_commit2info:
                            new_fixing_commit2info[url]=fixing_commit2info[url]
                if len(new_fixing_commit2info):
                    fixing_commits[package_name]=new_fixing_commit2info
                else:
                    fixing_commits[package_name]=fixing_commit2info


            new_fixing_commit = {}
            for package_name, VFCs in fixing_commits.items():
                if filter_large_vfcs and len(VFCs) > 10:
                        continue
                
                new_fixing_commit[package_name] = VFCs
            advisory['fixing_commits'] = new_fixing_commit
            if len(new_fixing_commit):
                new_cve2advisory[cve_id] = advisory
                
        return new_cve2advisory
    tmp1_cve2advisory = store_vfcs(cve2advisory=cve2advisory,filter_large_vfcs=False,priority_commit=False,filter_large_files=False)
    tmp2_cve2advisory = store_vfcs(cve2advisory=cve2advisory,filter_large_vfcs=False,priority_commit=False,filter_large_files=True)
    tmp3_cve2advisory = store_vfcs(cve2advisory=cve2advisory,filter_large_vfcs=True,priority_commit=False,filter_large_files=True)


    # analyze_vfc_threshold_stats(cve2advisory=tmp1_cve2advisory)
    # analyze_vfc_threshold_stats(cve2advisory=tmp2_cve2advisory)
    
    cve2advisory = store_vfcs(cve2advisory=cve2advisory,filter_large_vfcs=True,priority_commit=True)
    # analyze_vfc_count_distribution_with_plot(cve2advisory=cve2advisory)
    # analyze_vfc_threshold_stats(cve2advisory=cve2advisory)
    
    for dataset in [tmp1_cve2advisory, tmp2_cve2advisory,tmp3_cve2advisory,cve2advisory]:
        vfc_count = 0
        cve_count = 0
        pkg_count = set()
        for cve_id, advisory in dataset.items():
            if len(advisory['fixing_commits'].items()):
                cve_count+=1
            for pkg,vfcs in advisory['fixing_commits'].items():
                vfc_count += len(vfcs)
                if pkg in advisory['available_affected']:
                    pkg_count.update((pkg, version) for version in advisory['available_affected'][pkg]['versions'])
    
        logger.info(f"vfc_count: {vfc_count}, cve_count: {cve_count}, pkg_count {len(pkg_count)}")

    with open(CVE2ADVISORY_VFC_FILE_DATE,'wb') as f:
        pickle.dump(cve2advisory, f)


