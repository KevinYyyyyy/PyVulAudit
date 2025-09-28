import requests
import pypistats
import json
from datetime import datetime, timedelta
import numpy as np
from collections import defaultdict
from joblib import Parallel, delayed
import time
import random
from pathlib import Path

from constant import CG_DIR_DATE, DATA_DIR, SUFFIX
from analyze_results import StatisticsCalculator  
def extract_package_names(impacted_downstreams):
    """提取所有唯一的包名"""
    package_names = set()
    name_to_versions = defaultdict(list)
    
    for pkg in impacted_downstreams:
        try:
            pkg_name, pkg_version = pkg.split('@')
            package_names.add(pkg_name)
            name_to_versions[pkg_name].append(pkg_version)
        except ValueError:
            print(f"Skipping invalid package format: {pkg}")
            continue
    
    return list(package_names), dict(name_to_versions)

def get_package_name_info(pkg_name, retry_count=3, max_delay=30):
    """获取单个包名的信息（下载量和PyPI数据）"""
    
    # 随机延迟，避免同时请求
    initial_delay = random.uniform(0.5, 2.0)
    time.sleep(initial_delay)
    
    for attempt in range(retry_count):
        try:
            # 1. 获取下载统计
            download_stats = None
            monthly_downloads = 0
            try:
                download_stats_raw = pypistats.recent(pkg_name, "month", format="json")
                download_stats = json.loads(download_stats_raw)
                monthly_downloads = download_stats.get('data', {}).get('last_month', 0)
            except Exception as e:
                error_msg = str(e)
                if "429" in error_msg or "TOO MANY REQUESTS" in error_msg:
                    delay = min(max_delay, (2 ** attempt) * 5 + random.uniform(1, 5))
                    print(f"  Rate limited for {pkg_name}, waiting {delay:.1f}s (attempt {attempt + 1})")
                    time.sleep(delay)
                    if attempt < retry_count - 1:
                        continue
                else:
                    print(f"  Download stats failed for {pkg_name}: {e}")
                monthly_downloads = 0
            
            # 2. 获取PyPI包信息
            pypi_url = f"https://pypi.org/pypi/{pkg_name}/json"
            pypi_response = requests.get(pypi_url, timeout=10)
            
            if pypi_response.status_code == 429:
                delay = min(max_delay, (2 ** attempt) * 3 + random.uniform(1, 3))
                print(f"  PyPI rate limited for {pkg_name}, waiting {delay:.1f}s")
                time.sleep(delay)
                if attempt < retry_count - 1:
                    continue
                return None
            elif pypi_response.status_code != 200:
                print(f"  PyPI API failed for {pkg_name}: {pypi_response.status_code}")
                return None
                
            pypi_data = pypi_response.json()
            
            return {
                'pkg_name': pkg_name,
                'monthly_downloads': monthly_downloads,
                'pypi_data': pypi_data,
                'download_stats': download_stats
            }
            
        except Exception as e:
            print(f"  Attempt {attempt + 1} failed for {pkg_name}: {e}")
            if attempt < retry_count - 1:
                delay = min(max_delay, (2 ** attempt) * 2 + random.uniform(1, 3))
                time.sleep(delay)
            continue
    
    return None

def batch_get_package_name_info_joblib(package_names, n_jobs=2, batch_size=10):
    """使用joblib分批处理包名信息，避免速率限制"""
    print(f"Fetching info for {len(package_names)} remaining package names...")
    print(f"Using {n_jobs} jobs with batch size {batch_size}")
    
    name_info_dict = {}
    failed_names = []
    
    # 分批处理
    for i in range(0, len(package_names), batch_size):
        batch = package_names[i:i + batch_size]
        print(f"\nProcessing batch {i//batch_size + 1}/{(len(package_names) + batch_size - 1)//batch_size} ({len(batch)} packages)")
        
        # 对每个批次使用joblib
        results = Parallel(n_jobs=n_jobs, verbose=0)(
            delayed(get_package_name_info)(name) for name in batch
        )
        
        # 处理结果
        for j, result in enumerate(results):
            pkg_name = batch[j]
            if result:
                name_info_dict[pkg_name] = result
                print(f"  ✓ {pkg_name} - Downloads: {result['monthly_downloads']:,}")
            else:
                failed_names.append(pkg_name)
                print(f"  ✗ {pkg_name} - Failed")
        
        # 批次之间的延迟
        if i + batch_size < len(package_names):
            delay = random.uniform(2, 5)
            print(f"  Waiting {delay:.1f}s before next batch...")
            time.sleep(delay)
    
    print(f"\nBatch processing complete:")
    print(f"  Successful: {len(name_info_dict)}")
    print(f"  Failed: {len(failed_names)}")
    
    return name_info_dict, failed_names

def process_package_version(pkg, name_info_dict, name_to_versions):
    """处理单个包版本的信息"""
    try:
        pkg_name, pkg_version = pkg.split('@')
    except ValueError:
        return None
    
    if pkg_name not in name_info_dict:
        return None
    
    name_info = name_info_dict[pkg_name]
    pypi_data = name_info['pypi_data']
    
    # 提取版本相关信息
    info = pypi_data.get('info', {})
    releases = pypi_data.get('releases', {})
    
    # 获取当前版本发布时间
    version_release_date = None
    if pkg_version in releases and releases[pkg_version]:
        version_release_date = releases[pkg_version][0].get('upload_time', '')
    
    # 获取最新版本和发布时间
    latest_version = info.get('version', '')
    latest_release_date = None
    if latest_version in releases and releases[latest_version]:
        latest_release_date = releases[latest_version][0].get('upload_time', '')
    
    # 计算版本位置（在所有版本中的相对位置）
    all_versions = list(releases.keys())
    version_position_score = 1.0
    if pkg_version in all_versions and len(all_versions) > 1:
        try:
            version_times = []
            for v in all_versions:
                if releases[v]:
                    upload_time = releases[v][0].get('upload_time', '')
                    if upload_time:
                        version_times.append((v, upload_time))
            
            if version_times:
                version_times.sort(key=lambda x: x[1])
                sorted_versions = [v[0] for v in version_times]
                
                if pkg_version in sorted_versions:
                    position = sorted_versions.index(pkg_version)
                    version_position_score = position / (len(sorted_versions) - 1) if len(sorted_versions) > 1 else 1.0
        except:
            version_position_score = 0.5
    
    package_info = {
        'package': pkg,
        'pkg_name': pkg_name,
        'pkg_version': pkg_version,
        'monthly_downloads': name_info['monthly_downloads'],
        'version_release_date': version_release_date,
        'latest_version': latest_version,
        'latest_release_date': latest_release_date,
        'total_versions': len(releases),
        'version_position_score': version_position_score,
        'description': info.get('summary', ''),
        'keywords': info.get('keywords', ''),
        'home_page': info.get('home_page', ''),
        'maintainer': info.get('maintainer', ''),
        'author': info.get('author', '')
    }
    
    return package_info

def calculate_maintenance_freshness_score(package_info):
    """计算维护新鲜度得分"""
    if not package_info or not package_info['version_release_date']:
        return 0.1
    
    try:
        release_date = datetime.fromisoformat(package_info['version_release_date'].replace('T', ' ').replace('Z', ''))
        days_since_release = (datetime.now() - release_date).days
        
        if days_since_release <= 90:
            return 1.0
        elif days_since_release <= 180:
            return 0.8
        elif days_since_release <= 365:
            return 0.6
        elif days_since_release <= 730:
            return 0.4
        else:
            return 0.2
    except:
        return 0.1

def calculate_version_recency_score(package_info):
    """计算版本相对新旧程度得分"""
    if not package_info:
        return 0.5
    return package_info.get('version_position_score', 0.5)

def calculate_popularity_score(monthly_downloads):
    """计算受欢迎程度得分"""
    if monthly_downloads <= 0:
        return 0.0
    elif monthly_downloads < 100:
        return 0.1
    elif monthly_downloads < 1000:
        return 0.3
    elif monthly_downloads < 10000:
        return 0.5
    elif monthly_downloads < 100000:
        return 0.7
    elif monthly_downloads < 1000000:
        return 0.9
    else:
        return 1.0

def calculate_complexity_score(package_info):
    """
    Calculate complexity score considering both dependency depth and call chain length distribution
    """
    
    # If no complexity info available, return default
    if 'depth' not in package_info or 'upstream_dependencies' not in package_info:
        return 0.5
    
    depth = package_info['depth']
    upstream_deps = package_info['upstream_dependencies']
    
    # 1. Dependency depth score (adjusted to reflect actual distribution)
    if depth == 1:
        depth_score = 1.0  # Still good but not overwhelmingly preferred
    elif depth == 2:
        depth_score = 0.8  # Slightly prefer length 2 for better representation
    elif depth == 3:
        depth_score = 0.6  # Peak score for most common short chains
    elif depth == 4:
        depth_score = 0.4  # Still very good
    else:
        depth_score = 0.2  # Very long chains still usable but less preferred
    
    # 2. Vulnerability discovery effectiveness
    if not upstream_deps:
        vulnerability_score = 0.0
    else:
        vf_found_deps = [dep for dep in upstream_deps if dep.get('status') == 'VF Found']
        total_deps = len(upstream_deps)
        vf_found_count = len(vf_found_deps)
        
        if total_deps == 0:
            vulnerability_score = 0.0
        else:
            # Count score: reward packages with multiple VF findings
            count_score = min(vf_found_count / 3.0, 1.0)  # 3 VF findings = full score
            
            # Rate score: prefer high success rate
            rate_score = vf_found_count / total_deps
            
            # Diversity score: reward packages with multiple different CVEs
            unique_cves = len(set(dep.get('cve_id', '') for dep in vf_found_deps))
            diversity_score = min(unique_cves / 2.0, 1.0)  # 2+ CVEs = full score
            
            vulnerability_score = (count_score * 0.4 + rate_score * 0.4 + diversity_score * 0.2)
    
    # 3. Call chain length consideration (if available)
    chain_length_score = 0.0  # Default

    if 'min_chain_length' in package_info:
        # min_chain_length = package_info['min_chain_length']
        min_chain_length = package_info['max_chain_length']
        
        # Prefer packages that represent common call chain lengths
        if min_chain_length == 1:

            chain_length_score = 0.2  # Underrepresented but important
        elif min_chain_length == 2:
            chain_length_score = 0.9  # Good representation
        elif min_chain_length == 3:
            chain_length_score = 0.9  # Most common short chain
        elif min_chain_length == 4:
            chain_length_score = 0.5  # Good representation
        elif 5 <= min_chain_length <= 7:
            chain_length_score = 0.4  # Common longer chains
        elif min_chain_length >= 8:
            chain_length_score = 0.2  # Very long chains
        else:
            chain_length_score = -10  # No chain found
    
    # 4. Dependency type score
    dep_type = package_info.get('dep_type', 'unknown')
    if dep_type == 'direct':
        type_score = 1.0
    elif dep_type == 'transitive':
        type_score = 0.8  # Don't penalize transitive too much
    else:
        type_score = 0.5
    
    # Combine scores with adjusted weights
    complexity_score = (
        depth_score * 0.25 +            # Dependency depth 30%
        vulnerability_score * 0.15 +     # Vulnerability effectiveness 40%
        chain_length_score * 0.35 +      # Call chain representation 20%
        type_score * 0.25               # Dependency type 10%
    )
    
    return complexity_score
def calculate_scores_for_package(package_info):
    """为单个包计算所有得分"""
    maintenance_score = calculate_maintenance_freshness_score(package_info)
    version_score = calculate_version_recency_score(package_info)
    popularity_score = calculate_popularity_score(package_info['monthly_downloads'])
    complexity_score = calculate_complexity_score(package_info)
    
    composite_score = (
        maintenance_score * 0.35 +    # 维护新鲜度 25%
        popularity_score * 0.15 +     # 受欢迎程度 25%
        version_score * 0.1 +        # 版本相对新旧 15%
        complexity_score * 0.4      # 复杂度/漏洞相关性 35%
    )
    
    return {
        **package_info,
        'maintenance_score': maintenance_score,
        'popularity_score': popularity_score,
        'version_score': version_score,
        'complexity_score': complexity_score,
        'composite_score': composite_score
    }


def enrich_package_info_with_complexity(package_infos, downstream_depths,downstream_call_chains):
    """为包信息添加复杂度数据"""
    
    enriched_packages = []
    
    for pkg_info in package_infos:
        pkg_key = pkg_info['package']  # 格式如 "package@version"
        complexity_data = downstream_depths.get(pkg_key, {})
        call_chains_data = downstream_call_chains.get(pkg_key, {})
        # assert min_chain_length, pkg_key
        if complexity_data:
            # 添加复杂度信息
            enriched_pkg = {
                **pkg_info,
                'depth': complexity_data.get('depth'),
                'dep_type': complexity_data.get('dep_type'),
                'upstream_dependencies': complexity_data.get('upstream_dependencies', []),
               # Call chains info
                'call_chains_by_cve': call_chains_data.get('call_chains_by_cve', {}),
                'all_call_chains': call_chains_data.get('all_call_chains', []),
                'chain_lengths': call_chains_data.get('chain_lengths', []),
                'min_chain_length': call_chains_data.get('min_chain_length', 0),
                'max_chain_length': call_chains_data.get('max_chain_length', 0),
                'avg_chain_length': call_chains_data.get('avg_chain_length', 0),
                'total_chains': call_chains_data.get('total_chains', 0)
            }
        else:
            # 没有复杂度信息的包
            enriched_pkg = {
                **pkg_info,
                'depth': None,
                'dep_type': None,
                'upstream_dependencies': [],
                'call_chains_by_cve': {},
                'all_call_chains': [],
                'chain_lengths': [],
                'min_chain_length': 0,
                'max_chain_length': 0,
                'avg_chain_length': 0,
                'total_chains': 0
            }
        
        enriched_packages.append(enriched_pkg)
    
    return enriched_packages
def load_call_chains_for_packages(all_results, CG_DIR_DATE):
    """
    Load actual call chains for each downstream package
    """
    downstream_call_chains = {}
    
    for cve_id, cve_results in all_results.items():
        for upstream, downstream_results in cve_results.items():
            if isinstance(downstream_results, str):
                continue
                
            for downstream, status in downstream_results.items():
                if status != 'VF Found':
                    continue
                
                # Load call chains from file
                call_chains_file = CG_DIR_DATE / f'{cve_id}/{downstream}_call_chains.json'
                
                if call_chains_file.exists():
                    try:
                        with call_chains_file.open('r') as f:
                            call_chains = json.load(f)
                        
                        # Store call chains with context
                        if downstream not in downstream_call_chains:
                            downstream_call_chains[downstream] = {
                                'call_chains_by_cve': {},
                                'all_call_chains': [],
                                'chain_lengths': [],
                                'min_chain_length': float('inf'),
                                'max_chain_length': 0,
                                'avg_chain_length': 0,
                                'total_chains': 0
                            }
                        
                        # Store chains for this specific CVE-upstream pair
                        chain_key = f"{cve_id}@{upstream}"
                        downstream_call_chains[downstream]['call_chains_by_cve'][chain_key] = call_chains
                        
                        # Update aggregate statistics
                        if call_chains:
                            chain_lengths = [len(chain) - 1 for chain in call_chains]  # -1 for step count
                            downstream_call_chains[downstream]['all_call_chains'].extend(call_chains)
                            downstream_call_chains[downstream]['chain_lengths'].extend(chain_lengths)
                            
                            min_length = min(chain_lengths)
                            max_length = max(chain_lengths)
                            
                            downstream_call_chains[downstream]['min_chain_length'] = min(
                                downstream_call_chains[downstream]['min_chain_length'], 
                                min_length
                            )
                            downstream_call_chains[downstream]['max_chain_length'] = max(
                                downstream_call_chains[downstream]['max_chain_length'], 
                                max_length
                            )
                            downstream_call_chains[downstream]['total_chains'] += len(call_chains)
                        
                    except Exception as e:
                        pass  # Silent error handling
    
    # Calculate average chain lengths
    for downstream, chain_info in downstream_call_chains.items():
        if chain_info['chain_lengths']:
            chain_info['avg_chain_length'] = sum(chain_info['chain_lengths']) / len(chain_info['chain_lengths'])
        else:
            chain_info['min_chain_length'] = 0
            
    return downstream_call_chains


def print_detailed_package_analysis(selected_packages, top_n=10):
    """
    Print detailed analysis of selected packages including call chains
    """
    print(f"\n=== DETAILED ANALYSIS OF TOP {top_n} SELECTED PACKAGES ===")
    
    for i, pkg in enumerate(selected_packages[:top_n]):
        print(f"\n{i+1}. Package: {pkg['package']}")
        print(f"   Composite Score: {pkg['composite_score']:.3f}")
        print(f"   Monthly Downloads: {pkg['monthly_downloads']:,}")
        print(f"   Dependency Depth: {pkg.get('depth', 'N/A')}")
        print(f"   Dependency Type: {pkg.get('dep_type', 'N/A')}")
        print(f"   Position Score: {pkg['version_position_score']}")
              

        
        # Call chain summary
        total_chains = pkg.get('total_chains', 0)
        min_length = pkg.get('min_chain_length', 0)
        max_length = pkg.get('max_chain_length', 0)
        avg_length = pkg.get('avg_chain_length', 0)
        
        print(f"   Call Chains: {total_chains} total, lengths {min_length}-{max_length} (avg: {avg_length:.1f})")
        
        # CVE breakdown
        call_chains_by_cve = pkg.get('call_chains_by_cve', {})
        if call_chains_by_cve:
            print(f"   CVE Coverage: {len(call_chains_by_cve)} CVE-upstream pairs")
            for j, (cve_upstream, chains) in enumerate(list(call_chains_by_cve.items())[:3]):
                cve_id = cve_upstream.split('@')[0] if '@' in cve_upstream else cve_upstream
                print(f"     {cve_id}: {len(chains)} call chains")
            if len(call_chains_by_cve) > 3:
                print(f"     ... and {len(call_chains_by_cve) - 3} more CVEs")
        
        # VF Found summary
        vf_count = sum(1 for dep in pkg.get('upstream_dependencies', []) 
                      if dep.get('status') == 'VF Found')
        print(f"   VF Found Dependencies: {vf_count}")
        
        # Sample call chain
        all_chains = pkg.get('all_call_chains', [])
        if all_chains:
            sample_chain = all_chains[0]
        for sample_chain in all_chains:
            chain_display = ' -> '.join(sample_chain[:5])
            if len(sample_chain) > 5:
                chain_display += f" -> ... ({len(sample_chain)} total)"
            print(f"   Sample Call Chain from {len(all_chains)}: {chain_display}")

def select_representative_packages_with_cache(DATA_DIR, SUFFIX, target_count=10, 
                                            max_packages=1000, n_jobs=2, batch_size=10):
    """带缓存的代表性包选择"""
    
    print("=== REPRESENTATIVE PACKAGE SELECTION WITH CACHING ===")
    
    # 第一步：获取或加载 impacted_downstreams
    impacted_downstreams_file = DATA_DIR / SUFFIX / 'impacted_downstreams.json'
    impacted_downstreams_dep_analysis_file = DATA_DIR / SUFFIX / 'impacted_downstreams_dep_analysis.json'
    impacted_downstreams_call_chain_analysis_file = DATA_DIR / SUFFIX / 'impacted_downstreams_call_chain_analysis.json'

    
    if impacted_downstreams_file.exists() and impacted_downstreams_dep_analysis_file.exists() and impacted_downstreams_call_chain_analysis_file.exists() and False:
        print("Loading cached impacted downstreams...")
        with impacted_downstreams_file.open('r') as f:
            impacted_downstreams = json.load(f)
        with impacted_downstreams_dep_analysis_file.open('r') as f:
            dep_analysis_results = json.load(f)
        with impacted_downstreams_call_chain_analysis_file.open('r') as f:
            call_chain_results = json.load(f)
    else:
        print("Computing impacted downstreams...")
        impacted_downstreams_file.parent.mkdir(parents=True, exist_ok=True)
        
        calculator = StatisticsCalculator(only_one_vf=False)
        cve_impact_analysis = calculator.analyze_cve_downstream_impact(calculator.all_results)
        dep_analysis_results = calculator.analyze_dependency_depth_and_type(calculator.all_results)
        call_chain_results = load_call_chains_for_packages(all_results=calculator.all_results, CG_DIR_DATE=CG_DIR_DATE)
        # # Extract call chain length information for packages
        # chain_length_mapping = {}
        # for pair in reachable_analysis.get('detailed_pairs', []):
        #     downstream = pair['downstream']
        #     min_chain_length = pair.get('min_chain_length', 0)
            
        #     if downstream not in chain_length_mapping:
        #         chain_length_mapping[downstream] = min_chain_length
        #     else:
        #         # Keep the minimum chain length if multiple entries
        #         chain_length_mapping[downstream] = min(
        #             chain_length_mapping[downstream], 
        #             min_chain_length
        #         )
        impacted_downstreams = list(cve_impact_analysis['raw_data']['impacted_downstreams'])
        
        with impacted_downstreams_file.open('w') as f:
            json.dump(impacted_downstreams, f)
        with impacted_downstreams_dep_analysis_file.open('w') as f:
            json.dump(dep_analysis_results, f)
        with impacted_downstreams_call_chain_analysis_file.open('w') as f:
            json.dump(call_chain_results, f)
    
    print(f"Found {len(impacted_downstreams)} impacted downstream packages")
    downstream_depths = dep_analysis_results['downstream_depth_mapping']

    
    
    # print(downstream_depths.keys())
    # 提取包名
    package_names, name_to_versions = extract_package_names(impacted_downstreams)
    print(f"Found {len(package_names)} unique package names")
    
    # 限制处理的包数量（用于测试或资源限制）
    if max_packages and len(package_names) > max_packages:
        print(f"Limiting to first {max_packages} packages for processing")
        package_names = package_names[:max_packages]
    
    # 第二步：使用缓存批量获取包名信息
    results_file = DATA_DIR / SUFFIX / 'package_info_for_selection.json'
    if results_file.exists():
        print("Loading cached package info...")
        with results_file.open('r') as f:
            old_name_info_dict = json.load(f)
        package_names_remain = [pkg_name for pkg_name in package_names if pkg_name not in old_name_info_dict]
        print(f"Found {len(old_name_info_dict)} cached, {len(package_names_remain)} remaining to fetch")
    else:
        print("No cache found, will fetch all package info...")
        package_names_remain = package_names
        old_name_info_dict = {}
        results_file.parent.mkdir(parents=True, exist_ok=True)
    
    # 获取剩余的包信息
    if package_names_remain:
        print(f"Fetching info for {len(package_names_remain)} new packages...")
        name_info_dict, failed_names = batch_get_package_name_info_joblib(
            package_names_remain, n_jobs=n_jobs, batch_size=batch_size
        )
        
        # 合并新旧数据
        name_info_dict.update(old_name_info_dict)
        print(f"Total package info available: {len(name_info_dict)}")
        
        # 保存更新后的缓存
        print("Saving updated package info cache...")
        with results_file.open('w') as f:
            json.dump(name_info_dict, f)
    else:
        print("All package info available in cache")
        name_info_dict = old_name_info_dict
    
    if not name_info_dict:
        print("No package info available. Exiting.")
        return []
    
    # 第三步：处理所有包版本
    print(f"Processing {len(impacted_downstreams)} package versions...")
    package_infos = []
    
    for pkg in impacted_downstreams:
        package_info = process_package_version(pkg, name_info_dict, name_to_versions)
        if package_info:
            package_infos.append(package_info)
    
    print(f"Successfully processed: {len(package_infos)}/{len(impacted_downstreams)} packages")
    
    if not package_infos:
        print("No package versions processed successfully.")
        return []
    
    # 第四步：加载复杂度信息并合并
    print("Loading vulnerability complexity information...")
    
    enriched_packages = enrich_package_info_with_complexity(package_infos, downstream_depths,call_chain_results)
    
    # 第五步：计算包含复杂度的得分
    print("Calculating scores with complexity evaluation...")
    package_scores = Parallel(n_jobs=n_jobs*2, verbose=1)(
        delayed(calculate_scores_for_package)(pkg_info) 
        for pkg_info in enriched_packages
    )
    
    # 排序和选择
    package_scores.sort(key=lambda x: x['composite_score'], reverse=True)
    
    # 输出统计信息
    print(f"\n=== SELECTION RESULTS WITH COMPLEXITY ===")
    print(f"Successfully scored: {len(package_scores)} packages")
    
    if package_scores:
        print(f"Score range: {package_scores[-1]['composite_score']:.3f} - {package_scores[0]['composite_score']:.3f}")
        
        # 复杂度相关统计
        with_complexity = [p for p in package_scores if p['depth'] is not None]
        print(f"Packages with complexity info: {len(with_complexity)}/{len(package_scores)}")
        
        if with_complexity:
            depth_dist = {}
            for p in with_complexity:
                depth = p['depth']
                depth_key = f"Depth {depth}"
                depth_dist[depth_key] = depth_dist.get(depth_key, 0) + 1
            
            vf_found_dist = {}
            for p in with_complexity:
                vf_count = sum(1 for dep in p['upstream_dependencies'] if dep.get('status') == 'VF Found')
                vf_key = f"VF_Found_{vf_count}"
                vf_found_dist[vf_key] = vf_found_dist.get(vf_key, 0) + 1
            
            print(f"Depth distribution: {depth_dist}")
            print(f"VF Found distribution: {vf_found_dist}")
        
        # 传统统计
        download_dist = {
            'high': sum(1 for p in package_scores if p['monthly_downloads'] > 100000),
            'medium': sum(1 for p in package_scores if 1000 <= p['monthly_downloads'] <= 100000),
            'low': sum(1 for p in package_scores if p['monthly_downloads'] < 1000)
        }
        
        print(f"Download distribution - High: {download_dist['high']}, Medium: {download_dist['medium']}, Low: {download_dist['low']}")

        maintenance_distribution = {
            'recent': sum(1 for p in package_scores if p['maintenance_score'] >= 0.8),
            'moderate': sum(1 for p in package_scores if 0.4 <= p['maintenance_score'] < 0.8),
            'old': sum(1 for p in package_scores if p['maintenance_score'] < 0.4)
        }
        print(f"Maintenance distribution: Recent: {maintenance_distribution['recent']}, "
              f"Moderate: {maintenance_distribution['moderate']}, Old: {maintenance_distribution['old']}")
    
    
    # 选择代表性包
    selected = package_scores[:min(target_count, len(package_scores))]
    
    print(f"\nTop {min(target_count, len(selected))} selected packages:")
    m_score2years = {
            '1.0':'<3 Ms',
            '0.8':'<6 Ms',
            '0.6':'<1 Ys',
            '0.4':'<2 Ys',
            '0.2':'>2 Ys',
            '0.1':'ERROR',
        }
    for i, pkg in enumerate(selected[:target_count]):
        vf_count = sum(1 for dep in pkg.get('upstream_dependencies', []) if dep.get('status') == 'VF Found')
        depth = pkg.get('depth', 'N/A')
        chain_length = pkg.get('min_chain_length', 'N/A')
        
        
        print(f"  {i+1:2d}. {pkg['package']:<35} | "
              f"Score: {pkg['composite_score']:.3f} | "
               f"Depth: {depth} | Chain: {chain_length} | "
              f"VF_Found: {vf_count} | "
              f"Maintenance: {m_score2years[str(pkg['maintenance_score'])]} | "
              f"Downloads: {pkg['monthly_downloads']:>10,} | "

            #   f"Upstreams: {', '.join({(dep['upstream']) for dep in pkg.get('upstream_dependencies', []) if dep.get('status') == 'VF Found'})} | "
            #   f"CVEs: {', '.join({(dep['cve_id']) for dep in pkg.get('upstream_dependencies', []) if dep.get('status') == 'VF Found'})} | "

              )
    
    # 保存选择结果
    selected_file = DATA_DIR / SUFFIX / 'selected_representative_packages_with_complexity.json'
    with selected_file.open('w') as f:
        json.dump(selected, f, indent=2)
    
    print(f"\nResults saved to {selected_file}")
    
    return selected

# 使用示例
if __name__ == "__main__":
    
    selected_packages = select_representative_packages_with_cache(
        DATA_DIR=DATA_DIR,
        SUFFIX=SUFFIX,
        target_count=10,
        max_packages=None,  # 限制处理数量，设为None处理全部
        n_jobs=2,
        batch_size=20
    )
    
    print(f"\nSelected {len(selected_packages)} representative packages for experimental analysis")
    print_detailed_package_analysis(selected_packages)