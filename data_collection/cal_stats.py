from ast import mod
import json
from operator import le
import pickle
from pathlib import Path
from unittest import result
from logger import logger
from constant import *
from get_compatable_python_version import filter_versions
from tqdm import tqdm
import matplotlib.pyplot as plt
import numpy as np
from collections import defaultdict, Counter
from vul_analyze import read_cve2advisory,read_fixing_commits,get_pkg2url,read_commit2methods,get_dependents
from my_utils import get_repo_name, request_metadata_json_from_pypi
from collect_changes import get_all_unique_affected_projects,get_vulnerable_funcs_for_cve
from collect_pkg_metadata import get_all_upstream_versions,get_direct_and_indirect_dependents
import sys
import pandas as pd


def get_status_for_cve(cve_id, advisory):
    all_unique_affected_projects = get_all_unique_affected_projects(advisory)

    status = {
        'fix_commits': None,
        'available_versions': None,
        'dependents_cnt': None,
        'original_versions':0,
        'available_versions':0,
        'vfs':None,
        'modified_any_files': None,
        'modified_py_files': None,

    }
    all_modified_files = set()
    all_fixing_commit = set()


    
    # 1. 统计是否存在available affected version
    all_upstream_versions = set()
    all_available_upstream_versions = set()
    for affected_item in advisory['affected']:
        package = affected_item['package']['name']
        versions = affected_item['versions']
        for version in versions:
            full_info = f"{package}-{version}"
            all_upstream_versions.add(full_info)
        try:
            available_versions = filter_versions(package, versions)
            for version in available_versions:
                full_info = f"{package}-{version}"
                all_available_upstream_versions.add(full_info)
        except Exception as e:
            logger.error(f"Error filtering versions for {package} {advisory_id}: {e}")
    status['original_versions'] += len(all_upstream_versions)
    status['available_versions'] += len(all_available_upstream_versions)


    # 2. 统计是否存在fixing commits
    fixing_commits = read_fixing_commits(cve_id)
    status['fix_commits'] = fixing_commits

    # 3. 统计是否修改了.py文件
    # 4. 统计是否有VFs
    vfs = set()
    py_files = set()
    non_files = set()

    for _,repo_url in all_unique_affected_projects:            
        repo_name = get_repo_name(repo_url)
        modified_files_path = CODE_CHANGES_DIR / f'{cve_id}_{repo_name}_modified_files.pkl'
        if not modified_files_path.exists():
            continue
        # with open(modified_files_path, 'rb') as f:
        #     modified_non_py_files,modified_py_files,vul_dict = pickle.load(f)
        # modified_py_files = [f.old_path for f in modified_py_files]
        # modified_non_py_files = [f.old_path for f in modified_non_py_files]
        # py_files.update(modified_py_files)
        # non_files.update(modified_non_py_files)
        vulnerable_funcs, code_changes = get_vulnerable_funcs_for_cve(cve_id, repo_name,return_code_changes=True)
        vfs.update(vulnerable_funcs)
    status['vfs'] =vfs
    status['modified_any_files'] =py_files|non_files
    status['modified_py_files'] = py_files


    # 5. 统计是否存在available dependents (package-level results)
    cve_dependents, all_dependents = get_dependents(cve_id,advisory)
    status['dependents_cnt'] = cve_dependents
    # print(all_dependents)
    all_direct = set()
    all_indirect = set()
    for pkg,versions in all_dependents.items():
        for version in versions:
            direct, indirect = get_direct_and_indirect_dependents(all_dependents, pkg, version)
            direct = [item['package']+'@'+item['version'] for item in direct]
            indirect = [item['package']+'@'+item['version'] for item in indirect]
            all_direct.update(direct)
            all_indirect.update(indirect)

    if advisory.get('ecosystem_specific'):
        assert False
    database_specific = advisory['database_specific']
    cwe_ids = database_specific['cwe_ids']
    status['cwe_ids'] =cwe_ids
    severity = database_specific['severity']
    status['severity'] = severity
    status['indirect_dependents'] = list(all_direct)
    status['direct_dependents'] = list(all_indirect)
    return cve_id, status


def print_status(status):
    stats = {
        'total_CVEs': len(cve_status),
        'with_available_versions': sum(1 for s in cve_status.values() if s['available_versions']),
        'with_dependents': sum(1 for s in cve_status.values() if s['dependents_cnt'] and s['available_versions'] and s['vfs']),
        'with_fix_commits': sum(1 for s in cve_status.values() if s['fix_commits']),
        'with_fix_commits_py': sum(1 for s in cve_status.values() if s['modified_py_files']),
        'with_vfs': sum(1 for s in cve_status.values() if s['vfs']),
        'valid_cve': sum(1 for s in cve_status.values() if is_valid_cve(s)),
        'with_fix_commits_any_file': sum(1 for s in cve_status.values() if s['modified_any_files'])

    }
    logger.info(f"Original CVEs: {stats['total_CVEs']}")
    logger.info(f"CVEs with available versions: {stats['with_available_versions']}")
    logger.info(f"\n")
    logger.info(f"CVEs with fix commits: {stats['with_fix_commits']}")
    logger.info(f"CVEs with Python fix commits: {stats['with_fix_commits_py']}")
    logger.info(f"CVEs with VFs: {stats['with_vfs']}")
    logger.info(f"Valid CVEs: {stats['valid_cve']}")
    
    logger.info(f"\n")

    logger.info(f"CVEs with dependents (Package-level reachability): {stats['with_dependents']}")
    logger.info(f"\n")

    logger.info(f"with_fix_commits_any_file: {stats['with_fix_commits_any_file']}")


    return stats

def get_cve_stats(output_file, func, rewrite=False):
    """统计CVE相关数据"""
    CVE_STATS_FILE = output_file
    if CVE_STATS_FILE.exists() and not rewrite:
        with CVE_STATS_FILE.open('rb') as f:
            cve_status = pickle.load(f)
        return cve_status
    # for cve_id, advisory in tqdm(cve2advisory.items()):
    #     cve_status[cve_id] = get_all_unique_affected_projects
    from joblib import Parallel, delayed

    results = Parallel(n_jobs=20, backend='threading', verbose=0)(
        delayed(func)(cve_id,advisory)
        for cve_id, advisory in tqdm(cve2advisory.items())
    )
    cve_status = {cve_id:status for cve_id,status in results}
    
    # 保存结果
    with CVE_STATS_FILE.open('wb') as f:
        pickle.dump(cve_status, f)
    return cve_status

def create_funnel_chart(labels, values, title,cve_status):
    percentages = [f"{v/len(cve_status):.1%}" for v in values]

    # 创建图表
    fig, ax = plt.subplots(figsize=(10, 6))
    
    # 绘制漏斗图
    for i, (label, value, percent) in enumerate(zip(labels, values, percentages)):
        # print(label, value, percent) 

        ax.barh(label, value, color='skyblue')
        ax.text(value/2, i, f"{value}\n({percent})", 
                ha='center', va='center', color='black', fontsize=10)
    # 设置图表属性
    ax.set_title(title, pad=20, fontsize=14)
    ax.set_xlabel('Count')
    ax.set_xlim(0, len(cve_status) * 1.1)
    ax.grid(axis='x', linestyle='--', alpha=0.7)
    ax.invert_yaxis()  # 反转Y轴使漏斗从上到下
    
    plt.tight_layout()
    
    return fig, ax

def plot_cve_stats(cve_status):
    """绘制CVE过滤过程的漏斗图"""
    # 数据准备
    stages = [
        'Original CVEs',
        'CVEs with Available Versions',
        'CVEs with Fix Commits',
        'CVEs with Fix Commits modified any files',
        'CVEs with Fix Commits modified .py files',
        'CVEs with VFs',
        'Valid CVEs',
        '(Package-level) affecting CVEs',

    ]
    cve_with_available_versions = []
    cve_with_fixing_commits = []
    cve_with_fixing_commits_py = []
    cve_with_dependents = []
    cve_with_fixing_commits_any_files = []
    cve_with_vfs = []
    cve_with_available_versions_and_dependents = []
    cve_with_available_versions_and_dependents_and_fixing_commits = []
    cve_with_available_versions_and_dependents_and_fixing_commits_and_pyvfs = []
    cve_with_available_versions_and_fixing_commits_and_pyvfs = []

    for cve_id, stat in cve_status.items(): 
        if stat['available_versions']:
            cve_with_available_versions.append(cve_id)
        if stat['dependents_cnt']:
            cve_with_dependents.append(cve_id)
        if stat['fix_commits']:
            cve_with_fixing_commits.append(cve_id)
        if stat['modified_py_files']:
            cve_with_fixing_commits_py.append(cve_id)
        if stat['modified_any_files']:
            cve_with_fixing_commits_any_files.append(cve_id)
        if stat['vfs']:
            cve_with_vfs.append(cve_id)
        
    
        if stat['available_versions'] and stat['dependents_cnt']:
            cve_with_available_versions_and_dependents.append(cve_id)
        if stat['available_versions'] and stat['dependents_cnt'] and stat['fix_commits']:
            cve_with_available_versions_and_dependents_and_fixing_commits.append(cve_id)
        if stat['available_versions'] and stat['vfs']:
            cve_with_available_versions_and_fixing_commits_and_pyvfs.append(cve_id)
        if stat['available_versions'] and stat['vfs'] and stat['dependents_cnt']:
            cve_with_available_versions_and_dependents_and_fixing_commits_and_pyvfs.append(cve_id)

    # 修改values数组以匹配新的stages顺序
    values = [
        len(cve_status),
        len(cve_with_available_versions),
        len(cve_with_fixing_commits),
        len(cve_with_fixing_commits_any_files),
        len(cve_with_fixing_commits_py),
        len(cve_with_vfs),
        len(cve_with_available_versions_and_fixing_commits_and_pyvfs),
        len(cve_with_available_versions_and_dependents_and_fixing_commits_and_pyvfs)
    ]
    # print(values)
    fig, ax = create_funnel_chart(stages, values, title='CVE Filtering Process',cve_status=cve_status)
    plt.savefig(f'../figs/{sys.platform}/cve_stats.png',dpi=300)


    # 修改：打印没有.py修复commit的包名称
    # if packages_without_py_fixes:
    #     import math
    #     print("\nPackages without .py fixes:")
    #     # 修正：使用items()获取键值对，并按值(CVE列表)的长度排序
    #     sorted_packages = sorted(packages_without_py_fixes.items(), 
    #                            key=lambda x: len(x[1]), 
    #                            reverse=True)
    #     for package, cve_list in sorted_packages:
    #         ratio = len(cve_list)/len(package_total_cves[package])*100
    #         print(f"{package}: {len(cve_list)}/{len(package_total_cves[package])}, {ratio:.2f}%")
    # print(packages_without_py_fixes['opencv-python'])

    
def plot_cve_by_year(stats):
    """绘制按年份统计的CVE数据"""
    # 按年份绘制CVE统计数据的柱状图
    # 按年份分组
    year_stats = {}
    for cve_id, stat in cve_status.items():
        year = cve_id.split('-')[1]
        if year not in year_stats:
            year_stats[year] = {
                'Original CVEs': 0,
                'With Available Versions': 0,
                'With Fix Commits': 0,
                'With Dependents': 0,
                'Valid CVEs': 0,
                'With Fix Commits (.py)': 0,
                'Valid CVEs (.py)': 0,
                'With VFs (.py)': 0
            }
        
        year_stats[year]['Original CVEs'] += 1
        if stat['available_versions']:  # 修复：使用正确的字段名
            year_stats[year]['With Available Versions'] += 1
        if stat['fix_commits']:  # 修复：使用正确的字段名
            year_stats[year]['With Fix Commits'] += 1
        if stat['modified_py_files']:  # 修复：使用正确的字段名
            year_stats[year]['With Fix Commits (.py)'] += 1
        if stat['dependents_cnt']:  # 修复：使用正确的字段名
            year_stats[year]['With Dependents'] += 1
        if stat['vfs']:  # 修复：使用正确的字段名
            year_stats[year]['With VFs (.py)'] += 1
        if stat['available_versions'] and stat['vfs'] and stat['dependents_cnt']:  # 修复：使用正确的字段名
            year_stats[year]['Valid CVEs (.py)'] += 1

    # 准备绘图数据
    years = sorted(year_stats.keys())
    

    # 第一张图：Original CVEs vs Valid CVEs (.py)
    fig1, ax1 = plt.subplots(figsize=(12, 6))
    
    bar_width = 0.35
    x_pos = np.arange(len(years))
    
    # 数据准备
    total_cves = [year_stats[year]['Original CVEs'] for year in years]
    valid_cves_py = [year_stats[year]['Valid CVEs (.py)'] for year in years]
    
    # 绘制柱状图
    ax1.bar(x_pos - bar_width/2, total_cves, bar_width, label='Original CVEs', alpha=0.8, color='lightblue')
    ax1.bar(x_pos + bar_width/2, valid_cves_py, bar_width, label='Valid CVEs (.py)', alpha=0.8, color='darkblue')
    
    # 设置图表属性
    ax1.set_title('Original CVEs vs Valid CVEs (.py) by Year', fontsize=14, pad=20)
    ax1.set_xlabel('Year')
    ax1.set_ylabel('Count')
    ax1.set_xticks(x_pos)
    ax1.set_xticklabels(years, rotation=45)
    ax1.legend()
    ax1.grid(axis='y', linestyle='--', alpha=0.7)
    
    # 在柱状图上显示数值
    for i, (total, valid) in enumerate(zip(total_cves, valid_cves_py)):
        ax1.text(i - bar_width/2, total + max(total_cves)*0.01, str(total), ha='center', va='bottom', fontsize=9)
        ax1.text(i + bar_width/2, valid + max(valid_cves_py)*0.01, str(valid), ha='center', va='bottom', fontsize=9)
    
    plt.tight_layout()
    
    # 第二张图：包含两个子图
    fig2, (ax2, ax3) = plt.subplots(2, 1, figsize=(14, 10))
    
    # 子图1：Original CVEs, Available Versions, Dependents (三列)
    bar_width = 0.25
    x_pos = np.arange(len(years))
    
    total_cves_2 = [year_stats[year]['Original CVEs'] for year in years]
    available_versions = [year_stats[year]['With Available Versions'] for year in years]
    with_dependents = [year_stats[year]['With Dependents'] for year in years]
    
    ax2.bar(x_pos - bar_width, total_cves_2, bar_width, label='Original CVEs', alpha=0.8, color='lightblue')
    ax2.bar(x_pos, available_versions, bar_width, label='With Available Versions', alpha=0.8, color='lightgreen')
    ax2.bar(x_pos + bar_width, with_dependents, bar_width, label='With Dependents', alpha=0.8, color='orange')
    
    ax2.set_title('Original CVEs, Available Versions & Dependents by Year', fontsize=12)
    ax2.set_xlabel('Year')
    ax2.set_ylabel('Count')
    ax2.set_xticks(x_pos)
    ax2.set_xticklabels(years, rotation=45)
    ax2.legend()
    ax2.grid(axis='y', linestyle='--', alpha=0.7)
    
    # 在柱状图上显示数值
    for i, (total, avail, deps) in enumerate(zip(total_cves_2, available_versions, with_dependents)):
        ax2.text(i - bar_width, total + max(total_cves_2)*0.01, str(total), ha='center', va='bottom', fontsize=9)
        # ax2.text(i, avail + max(available_versions)*0.01, str(avail), ha='center', va='bottom', fontsize=9)
        ax2.text(i + bar_width, deps + max(with_dependents)*0.01, str(deps), ha='center', va='bottom', fontsize=9)
    
    # 子图2：Fix Commits and VFs (三列)
    fix_commits = [year_stats[year]['With Fix Commits'] for year in years]
    fix_commits_py = [year_stats[year]['With Fix Commits (.py)'] for year in years]
    vfs_py = [year_stats[year]['With VFs (.py)'] for year in years]

    ax3.bar(x_pos - bar_width, total_cves_2, bar_width, label='Original CVEs', alpha=0.8, color='lightblue')
    ax3.bar(x_pos - bar_width, available_versions, bar_width, label='With Available Versions', alpha=0.8, color='skyblue')
    
    ax3.bar(x_pos - bar_width, fix_commits, bar_width, label='With Fix Commits (Any)', alpha=0.8, color='blue')
    ax3.bar(x_pos, fix_commits_py, bar_width, label='With Fix Commits (.py)', alpha=0.8, color='lightcoral')
    ax3.bar(x_pos + bar_width, vfs_py, bar_width, label='With VFs (.py)', alpha=0.8, color='lightgreen')
    
    ax3.set_title('Fix Commits & VFs by Year', fontsize=12)
    ax3.set_xlabel('Year')
    ax3.set_ylabel('Count')
    ax3.set_xticks(x_pos)
    ax3.set_xticklabels(years, rotation=45)
    ax3.legend()
    ax3.grid(axis='y', linestyle='--', alpha=0.7)
    
    # 在柱状图上显示数值
    for i, (total, fix, fix_py, vfs) in enumerate(zip(total_cves_2, fix_commits, fix_commits_py, vfs_py)):
        ax3.text(i - bar_width, total + max(total_cves_2)*0.01, str(total), ha='center', va='bottom', fontsize=9)
        ax3.text(i - bar_width, fix + max(fix_commits)*0.01, str(fix), ha='center', va='bottom', fontsize=9)
        # ax3.text(i, fix_py + max(fix_commits_py)*0.01, str(fix_py), ha='center', va='bottom', fontsize=9)
        ax3.text(i + bar_width, vfs + max(vfs_py)*0.01, str(vfs), ha='center', va='bottom', fontsize=9)
    
    plt.tight_layout()
    plt.savefig(f'../figs/{sys.platform}/cve_res_stats_by_year.png', dpi=300)
    # 显示图表
    # plt.show()

def plot_dependents_by_year(cve_status):
    """
    Plot CVEs with dependents by year using two subplots: bar chart and line chart
    :param cve_status: CVE status dictionary
    """
    from collections import defaultdict
    import numpy as np
    import matplotlib.pyplot as plt
    
    year_dependents = defaultdict(dict)
    for cve_id, stat in cve_status.items():
        year = cve_id.split('-')[1]
        direct = stat['direct_dependents']
        indirect = stat['indirect_dependents']
        year_dependents[year]['direct'] = year_dependents[year].get('direct', set()) | set(direct)
        year_dependents[year]['indirect'] = year_dependents[year].get('indirect', set()) | set(indirect)
    
    for year in year_dependents:
        year_dependents[year]['all'] = year_dependents[year].get('indirect', set()) | year_dependents[year].get('direct', set())

    if not year_dependents:
        print("No CVEs with dependents found to plot.")
        return

    # Prepare data
    years = sorted(year_dependents.keys())
    direct_counts = [len(year_dependents[year].get('direct', set())) for year in years]
    indirect_counts = [len(year_dependents[year].get('indirect', set())) for year in years]
    all_counts = [len(year_dependents[year].get('all', set())) for year in years]
    
    # Calculate overlaps
    overlap_counts = []
    for year in years:
        direct_set = year_dependents[year].get('direct', set())
        indirect_set = year_dependents[year].get('indirect', set())
        overlap_counts.append(len(direct_set & indirect_set))

    # Create figure with two subplots
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))
    
    # Subplot 1: Grouped Bar Chart
    x = np.arange(len(years))
    width = 0.25
    
    bars1 = ax1.bar(x - width, direct_counts, width, label='Direct Dependents', alpha=0.8, color='#2E86AB')
    bars2 = ax1.bar(x, indirect_counts, width, label='Indirect Dependents', alpha=0.8, color='#A23B72')
    bars3 = ax1.bar(x + width, all_counts, width, label='Total (Unique)', alpha=0.8, color='#F18F01')
    
    ax1.set_xlabel('Year')
    ax1.set_ylabel('Number of CVEs')
    ax1.set_title('CVEs with Dependents Distribution by Year (Bar Chart)')
    ax1.set_xticks(x)
    ax1.set_xticklabels(years, rotation=45)
    ax1.legend()
    ax1.grid(True, alpha=0.3)
    
    # Add value labels on bars
    def add_value_labels(bars):
        for bar in bars:
            height = bar.get_height()
            if height > 0:
                ax1.annotate(f'{int(height)}',
                           xy=(bar.get_x() + bar.get_width() / 2, height),
                           xytext=(0, 3),  # 3 points vertical offset
                           textcoords="offset points",
                           ha='center', va='bottom', fontsize=8)
    
    add_value_labels(bars1)
    add_value_labels(bars2)
    add_value_labels(bars3)
    
    # Subplot 2: Line Chart
    ax2.plot(years, direct_counts, marker='o', linewidth=2, markersize=6, 
             label='Direct Dependents', color='#2E86AB')
    ax2.plot(years, indirect_counts, marker='s', linewidth=2, markersize=6, 
             label='Indirect Dependents', color='#A23B72')
    ax2.plot(years, all_counts, marker='^', linewidth=2, markersize=6, 
             label='Total (Unique)', color='#F18F01')
    ax2.plot(years, overlap_counts, marker='d', linewidth=2, markersize=6, 
             label='Overlap (Both Direct & Indirect)', color='#C73E1D', linestyle='--')
    
    ax2.set_xlabel('Year')
    ax2.set_ylabel('Number of CVEs')
    ax2.set_title('CVEs with Dependents Trend by Year (Line Chart)')
    ax2.legend()
    ax2.grid(True, alpha=0.3)
    ax2.set_xticks(years[::2])  # Show every other year to avoid crowding
    
    # Add value annotations on line chart
    for i, year in enumerate(years):
        if i % 2 == 0:  # Annotate every other point to avoid crowding
            ax2.annotate(f'{direct_counts[i]}', (year, direct_counts[i]), 
                        textcoords="offset points", xytext=(0,10), ha='center', fontsize=7)
            ax2.annotate(f'{all_counts[i]}', (year, all_counts[i]), 
                        textcoords="offset points", xytext=(0,10), ha='center', fontsize=7)
    
    plt.tight_layout()
    plt.savefig(f'../figs/{sys.platform}/dependents_by_year_subplots.png', dpi=300, bbox_inches='tight')
    
    # Print detailed statistics
    print("\n=== Dependents Statistics by Year ===")
    print(f"{'Year':<6} {'Direct':<8} {'Indirect':<10} {'All':<8} {'Overlap':<8}")
    print("-" * 45)
    
    for year in years:
        direct_set = year_dependents[year].get('direct', set())
        indirect_set = year_dependents[year].get('indirect', set())
        all_set = year_dependents[year].get('all', set())
        overlap = len(direct_set & indirect_set)
        
        print(f"{year:<6} {len(direct_set):<8} {len(indirect_set):<10} {len(all_set):<8} {overlap:<8}")
    
    # Calculate overall statistics
    total_direct = set()
    total_indirect = set()
    for year_data in year_dependents.values():
        total_direct.update(year_data.get('direct', set()))
        total_indirect.update(year_data.get('indirect', set()))
    
    total_all = total_direct | total_indirect
    total_overlap = len(total_direct & total_indirect)
    
    print("-" * 45)
    print(f"{'Total':<6} {len(total_direct):<8} {len(total_indirect):<10} {len(total_all):<8} {total_overlap:<8}")
    print(f"\nNote: Overlap shows packages that appear as both direct and indirect dependents")
    print(f"Overlap Rate: {total_overlap/max(len(total_direct), len(total_indirect))*100:.1f}%")
    print(f"Total Unique CVEs: {len(total_all)}")



def plot_reachability_results_by_year(cve_status, cve_reach_status):
    # 按年份分组
    year_stats = {}
    downstream_counts = {}  # 新增：统计每年受影响的downstream总数
    
    for cve_id, stat in cve_status.items():
        year = cve_id.split('-')[1]
        if year not in year_stats:
            year_stats[year] = {
                'Original CVEs': 0,
                'With Available Versions': 0,
                'With Fix Commits': 0,
                'With Dependents': 0,
                'Valid CVEs': 0,
                'With Fix Commits (.py)': 0,
                'Valid CVEs (.py)': 0,
                'With VFs (.py)': 0,
                'func_level_res':0,
                'affected_downstream':0,
                'active_upstream':0,
                'pkg_level_res':0
            }
            downstream_counts[year] = 0
        
        year_stats[year]['Original CVEs'] += 1
        if stat['available_versions']:
            year_stats[year]['With Available Versions'] += 1
        if stat['fix_commits']:
            year_stats[year]['With Fix Commits'] += 1
        if stat['modified_py_files']:
            year_stats[year]['With Fix Commits (.py)'] += 1
        if stat['dependents_cnt']:
            year_stats[year]['With Dependents'] += 1
            # 累加每年受影响的downstream数量
            if isinstance(stat['dependents_cnt'], int):
                downstream_counts[year] += stat['dependents_cnt']
            else:
                downstream_counts[year] += len(stat['dependents_cnt']) if stat['dependents_cnt'] else 0
        if stat['vfs']:
            year_stats[year]['With VFs (.py)'] += 1
        if stat['available_versions'] and stat['vfs'] and stat['dependents_cnt']:
            year_stats[year]['Valid CVEs (.py)'] += 1
        if cve_id not in cve_reach_status:
            continue
        if stat['dependents_cnt'] and stat['available_versions'] and stat['vfs']:
            year_stats[year]['pkg_level_res'] +=1
        if cve_reach_status[cve_id]['cg_result']:
            year_stats[year]['func_level_res'] +=1
        if len(cve_reach_status[cve_id]['affected_downstream']):
            year_stats[year]['affected_downstream'] += len(cve_reach_status[cve_id]['affected_downstream'])
        if len(cve_reach_status[cve_id]['active_upstream']):
            year_stats[year]['active_upstream'] += len(cve_reach_status[cve_id]['active_upstream'])
    
    # 准备绘图数据
    years = sorted(year_stats.keys())
    
    # 创建包含两个子图的图形
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 10))
    
    bar_width = 0.25
    
    # 数据准备
    total_cves = [year_stats[year]['Original CVEs'] for year in years]
    with_dependents = [year_stats[year]['pkg_level_res'] for year in years]
    func_level_res = [year_stats[year]['func_level_res'] for year in years]
    downstream_data = [year_stats[year]['affected_downstream'] for year in years]
    active_upstream_data = [year_stats[year]['active_upstream'] for year in years] 
    
    for idx, (cve_cnt, dependents_cnt) in enumerate(zip(total_cves, with_dependents)):
        if dependents_cnt:
            break
    total_cves = total_cves[idx:]
    pkg_level_res = with_dependents[idx:]
    years = years[idx:]
    func_level_res = func_level_res[idx:]
    downstream_data = downstream_data[idx:]
    active_upstream_data = active_upstream_data[idx:]
    
    x_pos = np.arange(len(years))
    
    # 第一个子图：柱状图
    ax1.bar(x_pos - bar_width, total_cves, bar_width, label='Original CVEs', alpha=0.8, color='lightblue')
    ax1.bar(x_pos, pkg_level_res, bar_width, label='Package-level', alpha=0.8, color='lightgreen')
    ax1.bar(x_pos + bar_width, func_level_res, bar_width, label='Func-level', alpha=0.8, color='orange')
    
    # 设置第一个子图属性
    ax1.set_title('CVE Reachability Results by Year', fontsize=14, pad=20)
    ax1.set_xlabel('Year')
    ax1.set_ylabel('Count')
    ax1.set_xticks(x_pos)
    ax1.set_xticklabels(years, rotation=45)
    ax1.legend(loc='upper left')
    ax1.grid(axis='y', linestyle='--', alpha=0.7)
    
    # 在第一个子图的柱状图上显示数值
    for i, (total, deps, downs) in enumerate(zip(total_cves, pkg_level_res, func_level_res)):
        ax1.text(i - bar_width, total + max(total_cves)*0.01, str(total), ha='center', va='bottom', fontsize=9)
        ax1.text(i, deps + max(pkg_level_res)*0.01, str(deps), ha='center', va='bottom', fontsize=9)
        ax1.text(i + bar_width, downs + max(func_level_res)*0.01, str(downs), ha='center', va='bottom', fontsize=9)
    
    # 第二个子图：折线图
    ax2.plot(x_pos, downstream_data, color='lightcoral', marker='o', linewidth=2, markersize=6, 
             label='Affected Downstreams', alpha=0.8)
    ax2.plot(x_pos, active_upstream_data, color='plum', marker='s', linewidth=2, markersize=6, 
             label='Active Upstreams', alpha=0.8, linestyle='--')
    
    # 设置第二个子图属性
    ax2.set_title('Affected/Vulnerable Packages by Year', fontsize=14, pad=20)
    ax2.set_xlabel('Year')
    ax2.set_ylabel('Number of Affected/Vulnerable Packages')
    ax2.set_xticks(x_pos)
    ax2.set_xticklabels(years, rotation=45)
    ax2.legend(loc='upper left')
    ax2.grid(axis='y', linestyle='--', alpha=0.7)
    
    # 在第二个子图的折线图上显示数值
    for i, (downstream_count, upstream_count) in enumerate(zip(downstream_data, active_upstream_data)):
        ax2.text(i, downstream_count + max(downstream_data)*0.02, str(downstream_count), ha='center', va='bottom', fontsize=9, color='lightcoral')
        ax2.text(i, upstream_count + max(active_upstream_data)*0.02, str(upstream_count), ha='center', va='bottom', fontsize=9, color='plum')
    
    plt.tight_layout()
    plt.savefig(f'../figs/{sys.platform}/cve_reachability_stats_by_year.png', dpi=300)
    return fig, (ax1, ax2)

def get_res_for_cve(cve_id, advisory):
    # cve日期
    # 严重程度
    # upstream的类型
    # CWE

    status = {
        'cg_result':None,
        'active_upstream':set(),
        'affected_downstream':set(),
        'cwe_ids':None,
        'severity':None,
        'topics':set(),
        'FP_upstream':[]
    }
    cve_results_file = Path(f'./cve_results/{cve_id}_results.json')
    if cve_results_file.exists():
        with cve_results_file.open('r') as f:
            res = json.load(f)
        for upstream, upstream_results in res.items():
            if isinstance(upstream_results, str):
                status['FP_upstream'].append(upstream)
                # return cve_id, status
            elif len(upstream_results):
                for downstream, result in upstream_results.items():
                    if result == 'VF Found':
                        status['active_upstream'].add(upstream)
                        status['affected_downstream'].add(downstream)
       
    status['cg_result'] =  len(status['affected_downstream']) > 0
    return cve_id, status

def simplify_topic(topic, level=2):
    if not topic.startswith("Topic :: "):
        return None
    parts = topic.split(" :: ")
    if len(parts) < level + 1:
        return  " :: ".join(parts[1:level + 1])
    return " :: ".join(parts[1:level + 1])

def get_topics_for_pkg(package_name, simplify=False):
    response = request_metadata_json_from_pypi(package_name)
    if response.status_code == 200:
        metadata = response.json()

    elif response.status_code == 404:
        logger.warning(f"Package '{package_name}'  not found on PyPI.{response.status_code}")
        return False, None
    else:
        print(f"Package '{package_name}'error.{response.status_code}")
        assert False

    # 1. classifiers 收集py versions and topics
    topics = []
    for classifier in metadata['info']['classifiers']:
        if classifier.startswith('Topic ::'):
            topics.append(classifier)
    return topics


def plot_top_n_distribution(cve_status, column_name, top_n=10,sub_title=''):
    """
    绘制 Top N 分布的水平条形图
    :param cve_status: CVE 状态字典
    :param column_name: 要分析的字段名 ('topic' 或 'cwe_id')
    :param top_n: 显示 Top N 的结果
    """
    # 提取数据并过滤空值
    # data_list = [stat[column_name] for stat in cve_status.values() if stat.get(column_name)]
    data_list = []
    for stat in cve_status.values():
        data = stat.get(column_name)
        if data:
            if isinstance(data, set):
                data_list.extend(list(data))
            elif isinstance(data,list):
                data_list.extend(data)
            else:
                data_list.append(data)
    if not data_list:
        print(f"No data found for column '{column_name}'. Skipping plot.")
        return

    # 统计频率

    # print(data_list)
    counter = Counter(data_list)
    top_items = counter.most_common(top_n)

    # 准备绘图数据
    labels = [item[0] for item in top_items]
    counts = [item[1] for item in top_items]

    # 创建图形
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.barh(labels, counts, color='skyblue')

    # 设置图表属性
    ax.set_title(f'Top {top_n} {column_name.capitalize()} Distribution  {sub_title}', fontsize=14)

    ax.set_xlabel('Frequency')
    ax.set_ylabel(column_name.capitalize())
    ax.invert_yaxis()  # 将最高频的放在顶部

    # 在条形上显示数值
    for index, value in enumerate(counts):
        ax.text(value, index, f' {value}', va='center')

    plt.tight_layout()
    plt.savefig(f'../figs/{sys.platform}/{column_name}_top_{top_n}_distribution_{sub_title}.png', dpi=300)
    print(f"Saved {column_name} distribution plot.")
    # plt.show()
    # assert False
    # plt.close(fig)

def plot_severity_by_year(cve_status,sub_title=''):
    """
    按年份绘制漏洞严重性的堆叠条形图
    :param cve_status: CVE 状态字典
    """
    year_severity = {}
    for cve_id, stat in cve_status.items():
        year = cve_id.split('-')[1]
        severity = stat.get('severity', 'UNKNOWN') # 处理缺失严重性的情况
        if year not in year_severity:
            year_severity[year] = Counter()
        year_severity[year][severity] += 1

    # 转换为 DataFrame
    df = pd.DataFrame(year_severity).fillna(0).T
    df = df.sort_index()
    
    # 确保包含所有严重性级别，并排序
    # severity_levels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']
    severity_levels = ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    for level in severity_levels:
        if level not in df.columns:
            df[level] = 0
    df = df[severity_levels]

    # 绘制堆叠条形图
    ax = df.plot(kind='bar', stacked=True, figsize=(12, 7), 
                     color = {
    'CRITICAL': 'darkred', 
    'HIGH': '#d32f2f',    
    'MEDIUM': '#f44336',   
    'LOW': '#ffcdd2',      
    'UNKNOWN': '#9e9e9e'    
})
     # 在每个堆叠部分显示数值
    for c in ax.containers:
        labels = [f'{v.get_height():.0f}' if v.get_height() > 0 else '' for v in c]
        ax.bar_label(c, labels=labels, label_type='center')
    # 设置图表属性
    ax.set_title(f'Vulnerability Severity Distribution by Year {sub_title}', fontsize=14)
    ax.set_xlabel('Year')
    ax.set_ylabel('Number of CVEs')
    ax.tick_params(axis='x', rotation=45)
    ax.legend(title='Severity')

    plt.tight_layout()
    plt.savefig(f'../figs/{sys.platform}/severity_by_year_{sub_title}.png', dpi=300)
    
    print("Saved severity by year plot.")
    # plt.close()

def plot_severity_distribution(cve_status,sub_title=''):
    """
    绘制漏洞严重性总体分布的饼图
    :param cve_status: CVE 状态字典
    """
    # print(cve_status)
    severities = [stat.get('severity', 'UNKNOWN') for stat in cve_status.values()]
    counter = Counter(severities)

    # 准备数据
    labels = list(counter.keys())
    sizes = list(counter.values())
    colors = {
    'CRITICAL': 'darkred',  # 深深红（Material Deep Orange 900 类似）
    'HIGH': '#d32f2f',      # 深红（Material Red 700）
    'MEDIUM': '#f44336',    # 红色（标准红色）
    'LOW': '#ffcdd2',       # 浅红（Material Red 100）
    'UNKNOWN': '#9e9e9e'    # 灰色（Material Gray 500）
}
    pie_colors = [colors.get(label, 'grey') for label in labels]

    # 绘制饼图
    fig, ax = plt.subplots(figsize=(8, 8))
    ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140, colors=pie_colors)
    ax.axis('equal')  # 确保饼图是圆的

    ax.set_title(f'Overall Vulnerability Severity Distribution {sub_title}', fontsize=14)

    plt.tight_layout()
    plt.savefig(f'../figs/{sys.platform}/severity_overall_distribution_{sub_title}.png', dpi=300)
    print("Saved overall severity distribution plot.")
    # plt.close(fig)

def plot_downstream_cve_impact(cve_status):
    """
    统计并可视化下游项目受CVE影响的情况
    同时提供带版本和不带版本的统计
    """
    print("\n=== Downstream CVE Impact Analysis ===")
    
    # 统计每个下游包受到的CVE影响（带版本）
    downstream_cve_count_with_version = defaultdict(set)
    # 统计每个下游包受到的CVE影响（不带版本，只保留包名）
    downstream_cve_count_package_only = defaultdict(set)
    
    for cve, status in cve_status.items():
        if not status.get('available_versions') or not status.get('vfs'):
            continue
            
        # 收集所有依赖项（直接和间接）
        direct_deps = status.get('direct_dependents', [])
        indirect_deps = status.get('indirect_dependents', [])
        all_deps = set(direct_deps + indirect_deps)
        
        # 为每个依赖项记录受到的CVE影响
        for dep in all_deps:
            # 带版本的统计
            downstream_cve_count_with_version[dep].add(cve)
            
            # 不带版本的统计（提取包名）
            if '@' in dep:
                package_name = dep.split('@')[0]
            else:
                package_name = dep
            
            downstream_cve_count_package_only[package_name].add(cve)
    
    if not downstream_cve_count_with_version:
        print("No downstream impact data found.")
        return None
    
    # 转换为影响数量列表
    impact_counts_with_version = [len(cves) for cves in downstream_cve_count_with_version.values()]
    impact_counts_package_only = [len(cves) for cves in downstream_cve_count_package_only.values()]
    
    # 统计影响分布
    impact_distribution_with_version = defaultdict(int)
    for count in impact_counts_with_version:
        impact_distribution_with_version[count] += 1
        
    impact_distribution_package_only = defaultdict(int)
    for count in impact_counts_package_only:
        impact_distribution_package_only[count] += 1
    
    # 打印统计信息
    print(f"\n=== With Version Statistics ===")
    print(f"Total downstream packages affected (with version): {len(downstream_cve_count_with_version)}")
    print(f"Average CVEs per package: {np.mean(impact_counts_with_version):.2f}")
    print(f"Median CVEs per package: {np.median(impact_counts_with_version):.1f}")
    print(f"Max CVEs affecting single package: {max(impact_counts_with_version)}")
    
    print(f"\n=== Package Name Only Statistics ===")
    print(f"Total downstream packages affected (package name only): {len(downstream_cve_count_package_only)}")
    print(f"Average CVEs per package: {np.mean(impact_counts_package_only):.2f}")
    print(f"Median CVEs per package: {np.median(impact_counts_package_only):.1f}")
    print(f"Max CVEs affecting single package: {max(impact_counts_package_only)}")
    
    # 找出受影响最严重的包（两种统计方式）
    top_affected_with_version = sorted([(pkg, len(cves)) for pkg, cves in downstream_cve_count_with_version.items()], 
                                      key=lambda x: x[1], reverse=True)[:20]
    top_affected_package_only = sorted([(pkg, len(cves)) for pkg, cves in downstream_cve_count_package_only.items()], 
                                      key=lambda x: x[1], reverse=True)[:20]
    
    print("\nTop 20 Most Affected Downstream Packages (with version):")
    for i, (pkg, count) in enumerate(top_affected_with_version, 1):
        print(f"  {i:2d}. {pkg}: {count} CVEs")
        
    print("\nTop 20 Most Affected Downstream Packages (package name only):")
    for i, (pkg, count) in enumerate(top_affected_package_only, 1):
        print(f"  {i:2d}. {pkg}: {count} CVEs")
    
    # 创建可视化图表 - 2行2列布局
    fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(20, 14))
    fig.suptitle('Downstream CVE Impact Analysis - With Version vs Package Name Only', fontsize=16, fontweight='bold')
    
    # 1. CVE影响数量分布直方图（带版本）
    ax1.hist(impact_counts_with_version, bins=min(50, max(impact_counts_with_version)), 
             alpha=0.7, color='skyblue', edgecolor='black')
    ax1.set_xlabel('Number of CVEs Affecting Package')
    ax1.set_ylabel('Number of Downstream Packages')
    ax1.set_title('Distribution of CVE Impact (With Version)')
    ax1.grid(True, alpha=0.3)
    
    # 2. CVE影响范围统计（使用图例的饼图）
    ranges = [(1, 1), (2, 5), (6, 10), (11, 20), (21, 50), (51, float('inf'))]
    range_labels = ['1 CVE', '2-5 CVEs', '6-10 CVEs', '11-20 CVEs', '21-50 CVEs', '50+ CVEs']
    range_counts = []
    
    for min_val, max_val in ranges:
        count = sum(1 for c in impact_counts_with_version if min_val <= c <= max_val)
        range_counts.append(count)
    
    # 只显示非零的范围
    non_zero_indices = [i for i, count in enumerate(range_counts) if count > 0]
    filtered_labels = [range_labels[i] for i in non_zero_indices]
    filtered_counts = [range_counts[i] for i in non_zero_indices]
    
    if filtered_counts:
        colors = plt.cm.Set3(np.linspace(0, 1, len(filtered_counts)))
        # 使用图例替代直接标签，完全避免重叠
        wedges, texts = ax2.pie(filtered_counts, 
                               colors=colors, 
                               startangle=90,
                               explode=[0.05] * len(filtered_counts))  # 轻微分离各扇形
        
        # 添加百分比标签在扇形内部
        for i, (wedge, count) in enumerate(zip(wedges, filtered_counts)):
            angle = (wedge.theta2 + wedge.theta1) / 2
            x = 0.6 * np.cos(np.radians(angle))
            y = 0.6 * np.sin(np.radians(angle))
            percentage = count / sum(filtered_counts) * 100
            ax2.text(x, y, f'{percentage:.1f}%', 
                    ha='center', va='center', 
                    fontweight='bold', fontsize=10, color='white')
        
        # 在图的右侧添加图例
        ax2.legend(wedges, [f'{label} ({count} packages)' for label, count in zip(filtered_labels, filtered_counts)],
                  title="CVE Impact Ranges",
                  loc="center left",
                  bbox_to_anchor=(1, 0, 0.5, 1),
                  fontsize=9)
        
        ax2.set_title('Distribution by CVE Impact Range', pad=20)
    # 3. Top 20受影响最严重的包（带版本）
    if len(top_affected_with_version) > 0:
        top_20_with_version = top_affected_with_version[:20]
        packages_with_version = [pkg[:25] + '...' if len(pkg) > 25 else pkg for pkg, _ in top_20_with_version]
        counts_with_version = [count for _, count in top_20_with_version]
        
        bars = ax3.barh(range(len(packages_with_version)), counts_with_version, color='lightcoral')
        ax3.set_yticks(range(len(packages_with_version)))
        ax3.set_yticklabels(packages_with_version, fontsize=8)
        ax3.set_xlabel('Number of CVEs')
        ax3.set_title('Top 20 Most Affected Packages (With Version)')
        ax3.grid(True, alpha=0.3, axis='x')
        
        # 添加数值标签
        for i, bar in enumerate(bars):
            width = bar.get_width()
            ax3.text(width + 0.1, bar.get_y() + bar.get_height()/2, 
                    f'{int(width)}', ha='left', va='center', fontsize=8)
    
    # 4. Top 20受影响最严重的包（包名）
    if len(top_affected_package_only) > 0:
        top_20_package_only = top_affected_package_only[:20]
        packages_only = [pkg[:25] + '...' if len(pkg) > 25 else pkg for pkg, _ in top_20_package_only]
        counts_only = [count for _, count in top_20_package_only]
        
        bars = ax4.barh(range(len(packages_only)), counts_only, color='orange')
        ax4.set_yticks(range(len(packages_only)))
        ax4.set_yticklabels(packages_only, fontsize=8)
        ax4.set_xlabel('Number of CVEs')
        ax4.set_title('Top 20 Most Affected Packages (Package Name Only)')
        ax4.grid(True, alpha=0.3, axis='x')
        
        # 添加数值标签
        for i, bar in enumerate(bars):
            width = bar.get_width()
            ax4.text(width + 0.1, bar.get_y() + bar.get_height()/2, 
                    f'{int(width)}', ha='left', va='center', fontsize=8)
    
    plt.tight_layout()
    plt.savefig(f'../figs/{sys.platform}/downstream_cve_impact_analysis.png', dpi=300, bbox_inches='tight')
    print(f"\nVisualization saved as 'downstream_cve_impact_analysis.png'")
    
    # 返回统计数据供进一步分析
    return {
        'downstream_cve_count_with_version': dict(downstream_cve_count_with_version),
        'downstream_cve_count_package_only': dict(downstream_cve_count_package_only),
        'impact_distribution_with_version': dict(impact_distribution_with_version),
        'impact_distribution_package_only': dict(impact_distribution_package_only),
        'top_affected_with_version': top_affected_with_version,
        'top_affected_package_only': top_affected_package_only,
        'total_packages_with_version': len(downstream_cve_count_with_version),
        'total_packages_package_only': len(downstream_cve_count_package_only),
        'total_cves': len([cve for cve, status in cve_status.items() if status.get('available_versions') and status.get('vfs')])
    }

if __name__ == '__main__':
    # 通过命令行传递参数
    import argparse
    parser = argparse.ArgumentParser(description='Process CVE data.')
    parser.add_argument('--size', type=str, choices=['small','large','medium'], default='small', help='Size of the dataset')

    args = parser.parse_args()
    cve2advisory = read_cve2advisory(valid_py_cve=False)
    print(len(cve2advisory))
    # !. 统计confidence
    # 1. https://owasp.org/Top10/
    owasp_top_10_2021 = {
        "A01 - Broken Access Control": [
            "CWE-22", "CWE-23", "CWE-35", "CWE-59", "CWE-200", "CWE-201", "CWE-219", "CWE-264", "CWE-275", "CWE-276", "CWE-284", "CWE-285", "CWE-352", "CWE-359", "CWE-377", "CWE-402", "CWE-425", "CWE-441", "CWE-497", "CWE-538", "CWE-540", "CWE-548", "CWE-552", "CWE-566", "CWE-601", "CWE-639", "CWE-651", "CWE-668", "CWE-706", "CWE-862", "CWE-863", "CWE-913", "CWE-922", "CWE-1275"
        ],
        "A02 - Cryptographic Failures": [
            "CWE-259", "CWE-261", "CWE-296", "CWE-310", "CWE-319", "CWE-321", "CWE-322", "CWE-323", "CWE-324", "CWE-325", "CWE-326", "CWE-327", "CWE-328", "CWE-329", "CWE-330", "CWE-331", "CWE-335", "CWE-336", "CWE-337", "CWE-338", "CWE-340", "CWE-347", "CWE-523", "CWE-720", "CWE-757", "CWE-759", "CWE-760", "CWE-780", "CWE-818", "CWE-916"
        ],
        "A03 - Injection": [
            "CWE-20", "CWE-74", "CWE-75", "CWE-77", "CWE-78", "CWE-79", "CWE-80", "CWE-83", "CWE-87", "CWE-88", "CWE-89", "CWE-90", "CWE-91", "CWE-93", "CWE-94", "CWE-95", "CWE-96", "CWE-97", "CWE-98", "CWE-99", "CWE-100", "CWE-113", "CWE-116", "CWE-138", "CWE-184", "CWE-470", "CWE-471", "CWE-564", "CWE-610", "CWE-643", "CWE-644", "CWE-652", "CWE-917"
        ],
        "A04 - Insecure Design": [
            "CWE-73", "CWE-183", "CWE-209", "CWE-213", "CWE-235", "CWE-256", "CWE-257", "CWE-266", "CWE-269", "CWE-280", "CWE-311", "CWE-312", "CWE-313", "CWE-316", "CWE-419", "CWE-430", "CWE-434", "CWE-444", "CWE-451", "CWE-472", "CWE-501", "CWE-522", "CWE-525", "CWE-539", "CWE-579", "CWE-598", "CWE-602", "CWE-642", "CWE-646", "CWE-650", "CWE-653", "CWE-656", "CWE-657", "CWE-799", "CWE-807", "CWE-840", "CWE-841", "CWE-927", "CWE-1021", "CWE-1173"
        ],
        "A05 - Security Misconfiguration": [
            "CWE-2", "CWE-11", "CWE-13", "CWE-15", "CWE-16", "CWE-260", "CWE-315", "CWE-520", "CWE-526", "CWE-537", "CWE-541", "CWE-547", "CWE-611", "CWE-614", "CWE-756", "CWE-776", "CWE-942", "CWE-1004", "CWE-1032", "CWE-1174"
        ],
        "A06 - Vulnerable and Outdated Components": [
            "CWE-937", "CWE-1035", "CWE-1104"
        ],
        "A07 - Identification and Authentication Failures": [
            "CWE-255", "CWE-259", "CWE-287", "CWE-288", "CWE-290", "CWE-294", "CWE-295", "CWE-297", "CWE-300", "CWE-302", "CWE-304", "CWE-306", "CWE-307", "CWE-346", "CWE-384", "CWE-521", "CWE-613", "CWE-620", "CWE-640", "CWE-798", "CWE-940", "CWE-1216"
        ],
        "A08 - Software and Data Integrity Failures": [
            "CWE-345", "CWE-353", "CWE-426", "CWE-494", "CWE-502", "CWE-565", "CWE-784", "CWE-829", "CWE-830", "CWE-915"
        ],
        "A09 - Security Logging and Monitoring Failures": [
            "CWE-117", "CWE-223", "CWE-532", "CWE-778"
        ],
        "A10 - Server-Side Request Forgery (SSRF)": [
            "CWE-918"
        ]
    }
    # 只保留value
    owasp_top_10_2021 = set([item for sublist in owasp_top_10_2021.values() for item in sublist])
    # 2.https://cwe.mitre.org/top25/
    cwe_top_25_ids = set(
        ["CWE-79", "CWE-787", "CWE-89", "CWE-352", "CWE-22", "CWE-125", "CWE-78", 
        "CWE-416", "CWE-862", "CWE-434", "CWE-94", "CWE-20", "CWE-77", "CWE-287", 
        "CWE-269", "CWE-502", "CWE-200", "CWE-863", "CWE-918", "CWE-119", "CWE-476", 
        "CWE-798", "CWE-190", "CWE-400", "CWE-306"]
    )


    def get_confidence(advisory, cwes):
        ret = []
        cwe_ids = advisory['database_specific']['cwe_ids']
        intersection = set(cwe_ids)&cwes
        if len(intersection) > 0:
            ret = intersection
        return ret
    cwe_counter = Counter()
    owsap_counter = Counter()
    cwe_top25_advisories = {}
    owsap_top10_advisories = {}
    for cve_id,advisory in cve2advisory.items():
        confidence = get_confidence(advisory, cwe_top_25_ids)
        cwe_counter.update(confidence)
        if len(confidence):
            cwe_top25_advisories[cve_id] = advisory
        confidence = get_confidence(advisory, owasp_top_10_2021)
        owsap_counter.update(confidence)
        if len(confidence):
            owsap_top10_advisories[cve_id] = advisory
    logger.info(f'owsap top10 cwe count:{len(owasp_top_10_2021)}')
    logger.info(f'cwe top25 cwe count:{len(cwe_top_25_ids)}')
    logger.info(f'cve2advisory count:{len(cve2advisory)}')
    
    # ! 1. dataset statistics affected version, fixing commits, dependents, vfs(.py)
    func = get_status_for_cve
    CVE_STATS_FILE = Path('./cve_stats.pkl')
    cve_status = get_cve_stats(output_file=CVE_STATS_FILE,func=get_status_for_cve,rewrite=False)
    # assert False
    #! 获得有效的CVE
    def is_valid_cve(s):
        return s['available_versions'] and s['vfs']
        # return s['available_versions'] and s['dependents_cnt'] and s['vfs']
    valid_cves = [(cve_id, s) 
                 for cve_id, s in cve_status.items() 
                 if is_valid_cve(s)]
    valid_cve_ids = [cve_id for cve_id, _ in valid_cves]

    valid_owsap_cve_ids = [cve_id for cve_id in valid_cve_ids if cve_id in owsap_top10_advisories]
    valid_cwe_cve_ids = [cve_id for cve_id in valid_cve_ids if cve_id in cwe_top25_advisories]
    print('valid_cves:', len(valid_cve_ids),len(valid_owsap_cve_ids), len(valid_cwe_cve_ids), len(set(valid_owsap_cve_ids+valid_owsap_cve_ids)))

    #统计保留和被过滤掉的serverity分布
    valid_cve_severity = [s['severity'] for cve_id, s in valid_cves]
    valid_owsap_cve_severity = [s['severity'] for cve_id, s in valid_cves if cve_id in valid_owsap_cve_ids]
    valid_cwe_cve_severity = [s['severity'] for cve_id, s in valid_cves if cve_id in valid_cwe_cve_ids]
    def cal_percentage(data):
        categories = set(data)
        percentage = {}
        for category in categories:
            percentage[category] = round(data.count(category)*100 / len(data), 2)
        return percentage
    print('valid_cves_severity:', cal_percentage(valid_cve_severity))
    print('valid_owsap_cve_severity:', cal_percentage(valid_owsap_cve_severity))
    print('valid_cwe_cve_severity:', cal_percentage(valid_cwe_cve_severity))

    package_level_cve_ids = []
    for cve_id in valid_cve_ids:
        if cve_status[cve_id]['dependents_cnt'] > 0:
            package_level_cve_ids.append(cve_id)
    print('package_level_cve_ids:',len(package_level_cve_ids))
    package_level_cve_ids_in_cwe = set(package_level_cve_ids) & set(valid_cwe_cve_ids)
    print('package_level_cve_ids_in_cwe:',len(package_level_cve_ids_in_cwe))
    package_level_cve_ids_in_owsap = set(package_level_cve_ids) & set(valid_owsap_cve_ids)
    print('package_level_cve_ids_in_owsap:',len(package_level_cve_ids_in_owsap))

    # assert False
    from datetime import datetime
    timestamp = datetime.now().strftime('%Y%m%d')
    # with open(f'../tests/generated_samples/valid_py_cve_ids_20250619' + '.txt', 'w') as f:
    #     f.write('\n'.join(valid_cve_ids))
    


    # ! reachability stats
    cve2advisory = read_cve2advisory(valid_py_cve=False)
    CVE_RES_STATS_FILE = Path('./cve_res_stats.pkl')
    if args.size == 'small':
        metadata_file_for_upstream = Path('./all_metadata_file_for_upstream_small.json')
    elif args.size == 'medium':
        metadata_file_for_upstream = Path('./all_metadata_file_for_upstream_medium.json')
    elif args.size == 'large':
        metadata_file_for_upstream = Path('./all_metadata_file_for_upstream_large.json')
    with open(metadata_file_for_upstream, 'r') as f:
        all_upstream_metadata = json.load(f)
    func = get_res_for_cve
    cve_reach_status = get_cve_stats(output_file=CVE_RES_STATS_FILE,func=func,rewrite=True)

    #! topics for each CVE, upstream
    new_cve_reach_status = {}
    all_upstream_topics_cache_file = Path('./all_upstream_topics_cache.json')
    if all_upstream_topics_cache_file.exists():
        with open(all_upstream_topics_cache_file, 'r') as f:
            all_upstream_topics_cache = json.load(f)
    else:
        all_upstream_topics_cache = {}
    for cve_id, status in cve_reach_status.items():
        if not status['cg_result']:
            continue
        upstream_pkgs = set()
        for upstream in status.get('active_upstream', []):
            # print(upstream)
            upstream_pkg, upstream_version = upstream.split('@')
            upstream_pkgs.add(upstream_pkg)
        for upstream_pkg in upstream_pkgs:
            # 1. 获得upstream的类型
            if upstream_pkg in all_upstream_topics_cache:
                topics = all_upstream_topics_cache[upstream_pkg]
            else:
                topics = get_topics_for_pkg(upstream_pkg, simplify=False)
                all_upstream_topics_cache[upstream_pkg] = topics
            status['topics'].update([simplify_topic(topic) for topic in topics])


        advisory = cve2advisory[cve_id]
        if advisory.get('ecosystem_specific'):
            assert False
        database_specific = advisory['database_specific']
        cwe_ids = database_specific['cwe_ids']
        status['cwe_ids'] =cwe_ids
        # if len(cwe_ids)>1:
        #     print(cwe_ids)
        #     assert False
        severity = database_specific['severity']
        status['severity'] = severity
        new_cve_reach_status[cve_id] = status
    print('new_cve_reach_status:',len(new_cve_reach_status))
    new_cve_reach_cve_ids = new_cve_reach_status.keys()
    new_cve_reach_cve_ids_in_cwe = set(new_cve_reach_cve_ids) & set(valid_cwe_cve_ids)
    print('new_cve_reach_cve_ids_in_cwe:',len(new_cve_reach_cve_ids_in_cwe))
    new_cve_reach_cve_ids_in_owsap = set(new_cve_reach_cve_ids) & set(valid_owsap_cve_ids)
    print('new_cve_reach_cve_ids_in_owsap:',len(new_cve_reach_cve_ids_in_owsap))

    
    assert False
    # with open(all_upstream_topics_cache_file, 'w') as f:
    #     json.dump(all_upstream_topics_cache, f)
    logger.info(f"Total new_cve_reach_status: {len(new_cve_reach_status)}/ {len(cve_reach_status)}")
    plot_reachability_results_by_year(cve_status, new_cve_reach_status)

    # 统计有多少个FP upstream
    cve2FP = dict()
    for cve_id, cve_reach_status in new_cve_reach_status.items():
        FP_upstream = cve_reach_status.get('FP_upstream', [])
        if len(FP_upstream):
            cve2FP[cve_id] = FP_upstream
    logger.warning(f"cve2FP:{cve2FP}")

    # ! 打印数据集stats
    # print_status(status=cve_status)
    # plot_cve_stats(cve_status)  
    # plot_cve_by_year(cve_status)

    valid_cve_status = {cve_id: s for cve_id, s in cve_status.items() if is_valid_cve(s)}
    all_direct = set()
    all_indirect = set()
    for cve_id, status in valid_cve_status.items():
        all_direct.update(status['direct_dependents'])
        all_indirect.update(status['indirect_dependents'])
    print(len(all_direct),len(all_indirect), len(all_direct | all_indirect))
    plot_dependents_by_year(valid_cve_status)
    plot_downstream_cve_impact(valid_cve_status)

    # if sys.platform == 'darwin':
    #     plt.show()
    #     pass
    # 绘制 Top 10 Topic 分布
    plot_top_n_distribution(new_cve_reach_status, 'topics', top_n=100,sub_title='cg')
    # plot_top_n_distribution(cve_status, 'topics', top_n=10,cg_result=False)

    # 绘制 Top 10 CWE ID 分布
    plot_top_n_distribution(new_cve_reach_status, 'cwe_ids', top_n=10,sub_title='cg')
    plot_top_n_distribution(valid_cve_status, 'cwe_ids', top_n=10,sub_title='valid_cve')
    plot_top_n_distribution(cve_status, 'cwe_ids', top_n=10,sub_title='original_cve')

    # # 绘制按年份的严重性分布
    plot_severity_by_year(new_cve_reach_status,sub_title='cg')
    plot_severity_by_year(valid_cve_status,sub_title='valid_cve')
    plot_severity_by_year(cve_status,sub_title='original_cve')

    # # 绘制总体严重性分布饼图
    plot_severity_distribution(new_cve_reach_status,sub_title='cg')
    plot_severity_distribution(valid_cve_status,sub_title='valid_cve')
    plot_severity_distribution(cve_status,sub_title='original_cve')

    if sys.platform == 'darwin':
        plt.show()
        pass

    assert False
    def cal_vf_hit_types():
        results_dir = Path('./cg_results')
        for dir_ in results_dir.iterdir():
            for result_file in (results_dir/dir_).iterdir():
                with open(result_file, 'r') as f:
                    res = json.loads()
                vulnerable_functions = res['vulnerable_functions']
                found_functions = res['found_functions']


