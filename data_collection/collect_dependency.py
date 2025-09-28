import os
from pathlib import Path
import json
import time
import tempfile
import requests
import glob
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
from data_collection.vul_analyze import read_cve2advisory
from logger import logger
from constant import *
from itertools import chain
from joblib import Parallel, delayed
import subprocess
from collect_dependents import cve2advisory, get_dependents_for_version,get_dependents_from_osi
from get_compatable_python_version import filter_versions
from pip._internal.models.wheel import Wheel
import fcntl
import contextlib
import pickle
import traceback





def get_dependencies_from_osi(package, version):

    url = f"https://api.deps.dev/v3alpha/systems/pypi/packages/{package}/versions/{version}:dependencies"
    try:
        response = session.get(url, timeout=10)
        response.raise_for_status()
        return response
    except requests.exceptions.SSLError:
        logger.warning("SSL验证失败，尝试不验证SSL证书...")
        response = session.get(url, verify=False, timeout=10)
        data = response.json()
        return data['dependentCount']

    except Exception as e:
        logger.error(f"获取dependents数量失败: {str(e)}")
        return []


def parse_dependency_graph(package_name, version, rewrite=False):
    """解析依赖图数据(通过API方式)"""
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    
    graph_data = {
        'nodes': {},
        'edges': []
    }
    file_path = DEP_DIR / f"{package_name}_{version}.json"
    
    if file_path.exists() and not rewrite:
        with open(file_path, 'r') as f:
            graph_data = json.load(f)
        logger.info(f"依赖图数据加载: {file_path}")
        return graph_data
        
    # 配置重试策略
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    session.mount('https://', HTTPAdapter(max_retries=retries))
    
    url = f"https://api.deps.dev/v3alpha/systems/pypi/packages/{package_name}/versions/{version}:dependencies"
    
    try:
        logger.info(f"正在通过API获取依赖数据: {url}")
        response = session.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.SSLError:
        logger.warning("SSL验证失败，尝试不验证SSL证书...")
        try:
            response = session.get(url, verify=False, timeout=10)
            response.raise_for_status()
            data = response.json()
        except Exception as e:
            logger.error(f"获取dependentcy graph失败: {str(e)}")
            failed_cases_file = Path('./failed_cases/failed_cases_get_dependency_graph.json')
            save_failed_case(
                failed_cases_file,
                f"{package_name}=={version}",
                {
                    'reason': 'failed to get dependency graph',
                    'error': str(e)
                }
            )
            return []    
    # 解析节点
    nodes_map = {}  # 用于存储包名到节点的映射
    for idx, node in enumerate(data['nodes']):
        pkg_name = node['versionKey']['name']
        pkg_version = node['versionKey']['version']
        pkg_system = node['versionKey']['system']
        node_name = f"{pkg_name} {pkg_version}"
        
        node_data = {
            # 'full_name':node_name,
            'name': pkg_name,
            'version': pkg_version,
            'system': pkg_system,
        }
        graph_data['nodes'][node_name]=node_data
        nodes_map[idx] = node_data
        
    # 解析边关系
    for edge in data['edges']:
        source_node = nodes_map[edge['fromNode']]
        target_node = nodes_map[edge['toNode']]

        source_name = f"{source_node['name']} {source_node['version']}"
        target_name = f"{target_node['name']} {target_node['version']}"
        edge_data = {
            'source': source_name,
            'target': target_name,
            'requirement': edge.get('requirement', '')
        }
        graph_data['edges'].append(edge_data)
        
    # 保存数据
    with open(file_path, 'w') as f:
        json.dump(graph_data, f, indent=2)
    logger.info(f"依赖图数据已保存到: {file_path}")
    
    return graph_data
    
    

def extract_dependent(downloaded_file, dependent_name, dependent_version):
    """解压下载的依赖包
    
    参数:
        downloaded_file (Path): 下载的文件路径
        extract_dir (Path): 解压目录，默认为None(自动生成)
        
    返回:
        tuple: (解压是否成功, 解压后的路径) 或 (False, None)
    """

    extract_dir = EXTRACT_DIR / dependent_name / dependent_version
    if extract_dir.exists() and any(extract_dir.iterdir()):
        logger.debug(f"{dependent_name}=={dependent_version} 已存在，跳过解压 {extract_dir}")
        return True, extract_dir
    extract_dir.mkdir(parents=True, exist_ok=True)
    if not isinstance(downloaded_file, Path):
        downloaded_file = Path(downloaded_file)
    
    if downloaded_file.suffix in ('.whl', '.zip'):
        cmd = f"unzip -q -o {downloaded_file} -d {extract_dir} 2>/dev/null"
    elif downloaded_file.suffix in ('.tar.gz', '.tgz', '.gz'):
        cmd = f"tar -xzf {downloaded_file} -C {extract_dir} 2>/dev/null"
    elif downloaded_file.suffix == '.tar':
        cmd = f"tar -xf {downloaded_file} -C {extract_dir} 2>/dev/null"
    elif downloaded_file.suffix == '.bz2':
        cmd = f"tar -xjf {downloaded_file} -C {extract_dir} 2>/dev/null"
    else:
        logger.error(f"不支持的文件类型: {downloaded_file.suffix}")
        assert False
    
    result = subprocess.run(cmd, shell=True, check=False)
    if result.returncode == 0:
        logger.debug(f"成功解压 {downloaded_file} 到 {extract_dir}")
        return True, extract_dir
    logger.error(f"解压命令执行失败，返回码: {result.returncode}")
    return False, None

def find_paths_to_upstream(graph_data, start_package, target_package):
    """
    通过反向搜索查找从起始包到目标上游包的所有路径
    
    Args:
        graph_data: 依赖图数据
        start_package: 起始包名
        target_package: 目标上游包名
    
    Returns:
        list: 包含所有可能路径的列表，每个路径是一个包名列表
    """
    import signal

    class TimeoutException(Exception):
        pass

    def handler(signum, frame):
        raise TimeoutException()


    signal.signal(signal.SIGALRM, handler)
    timeout_s = 5
    signal.alarm(timeout_s)  # 设置超时时间为60秒

    try:
        # 构建反向图
        reverse_edges = {}
        for edge in graph_data['edges']:
            target = edge['target']
            source = edge['source']
            if target not in reverse_edges:
                reverse_edges[target] = []
            reverse_edges[target].append(source)
        
        def reverse_dfs(current, target, path, visited, all_paths):
            if current.startswith(target):
                all_paths.append(path[::-1])
                return
            if current not in reverse_edges:
                return
            for dependent in reverse_edges[current]:
                if dependent not in visited:
                    # 只在递归进入时添加，不在递归返回时移除
                    reverse_dfs(dependent, target, path + [dependent], visited | {dependent}, all_paths)
        all_paths = []
        reverse_dfs(target_package, start_package, [target_package], {target_package}, all_paths)
        signal.alarm(0)  # 取消定时器
        return all_paths
    except TimeoutException:
        logger.warning(f"查找从 {start_package} 到 {target_package} 的路径超时(超过{timeout_s}秒)，返回空列表")
        return []
    finally:
        signal.alarm(0)  # 保证无论如何都取消定时器


def get_external_pkgs(upstream_package, upstream_version, downstream_package, downstream_version,cve_id=None, advisory=None,rewrite=False):
    """
    获取外部依赖包的路径
    """
    max_retries = 3
    retry_count = 0
    
    while retry_count < max_retries:
        try:
            # 尝试获取dependency graph

            down_dep_graph = parse_dependency_graph(downstream_package, downstream_version, rewrite=rewrite or retry_count>0)

            # TODO minimize the dependency graph

            # 
            # 查找路径
            start_package = f"{downstream_package} {downstream_version}"
            target_package = f"{upstream_package} {upstream_version}"
            logger.info(f"正在查找从 {start_package} 到 {target_package} 的路径...")
            paths = find_paths_to_upstream(down_dep_graph, start_package, target_package)
            
            if len(paths) == 0:
                retry_count += 1
                logger.debug(f"第{retry_count}次尝试未找到从 {start_package} 到 {target_package} 的路径，将重试...")
                assert False
                time.sleep(1)  # 添加延迟避免频繁请求
                continue
            
            # 找到路径，处理结果
            # 输出依赖图信息
            logger.info(f"Dependency graph for {downstream_package}=={downstream_version}:")
            logger.info(f"Nodes: {len(down_dep_graph['nodes'])}")
            logger.info(f"Edges: {len(down_dep_graph['edges'])}")
            logger.info(f"找到从 {start_package} 到 {target_package} 的 {len(paths)} 路径：")
            # for i, path in enumerate(paths, 1):
            #     logger.info(f"路径 {i}: {' -> '.join(path)}")
                
            all_external_pkgs = chain.from_iterable(paths)
            # 使用字典推导式去重，保证package和version的组合唯一
            all_external_pkgs = [pkg 
                                for pkg in all_external_pkgs 
                                if pkg != downstream_package]
            # 去除非PYPI的包
            #TODO: 后面可能需要考虑其他ecosystem的package
            all_external_pkgs = [pkg
                                for pkg in all_external_pkgs
                                if down_dep_graph['nodes'][pkg]['system'] == 'PYPI']
            # 转换回列表格式
            all_external_pkgs = [{'package': down_dep_graph['nodes'][pkg]['name'], 'version': down_dep_graph['nodes'][pkg]['version']} 
                                for pkg in all_external_pkgs]
            # logger.info(f"all_external_pkgs (去重后): {all_external_pkgs}")
            return all_external_pkgs
        except Exception as e:
            retry_count += 1
            logger.error(f"获取外部依赖包失败 (尝试 {retry_count}/{max_retries}): {str(e)}")
            if retry_count < max_retries:
                time.sleep(2)  # 添加延迟避免频繁请求
                continue
    return []   
    
    
def process_package(package, version, cve_id=None):
    """Process a single package download and extraction"""
    if not package or not version:
        return False, (package, version)
        
    package_dir = EXTRACT_DIR / package / version
    if package_dir.exists() and any(package_dir.iterdir()):
        logger.debug(f"{package}=={version} already exists, skipping")
        return True, (package, version)
    logger.info(f"正在下载 {package}=={version} {package_dir.exists()} ")
    success = download_and_extract(package, version)
    # if success:
    #     logger.info(f"Successfully processed {package}=={version}")
    # else:
    #     logger.error(f"Failed to process {package}=={version}")
        
    #     # 保存失败案例到JSON文件
    #     failed_cases_file = Path('./failed_cases/failed_cases_package_processing.json')
    #     save_failed_case(
    #         failed_cases_file,
    #         f"{package}=={version}",
    #         {
    #             'cve_id': cve_id,
    #             'reason': 'process_package_failed'
    #         }
    #     )
            
    return success, (package, version)


def download_packages_parallel(items, n_jobs=10):
    """Process multiple packages in parallel using joblib"""
    results = Parallel(n_jobs=n_jobs, verbose=0)(
        delayed(process_package)(
            item['package'], 
            item['version']
        ) for item in items
    )
    # results包含了成功与否
    return results

def download_dependent_by_pip(dependent_name, dependent_version, platform="linux_x86_64"):
    """下载指定依赖包
    
    参数:
        dependent_name (str): 依赖包名称
        dependent_version (str): 依赖包版本
        platform (str): 目标平台，默认为linux_x86_64
        
    返回:
        tuple: (下载是否成功, 下载的文件路径) 或 (False, None)
    """
    download_dir = DOWNLOADS_DIR /dependent_name/dependent_version
    if download_dir.exists() and any(download_dir.iterdir()):
        logger.debug(f"{dependent_name}=={dependent_version} 已存在，跳过下载 {download_dir}")
    else:
        download_dir.mkdir(parents=True, exist_ok=True)
        try:
            # 先尝试二进制包
            cmd = [
                "pip", "download",
                f"{dependent_name}=={dependent_version}",
                "--platform", platform,
                "--only-binary=:all:",
                "--no-deps",
                "-d", str(download_dir)
            ]
            subprocess.run(cmd, check=True, capture_output=True)
            logger.debug(f"成功下载二进制包 {dependent_name}=={dependent_version}, download_dir: {download_dir}")
        except subprocess.CalledProcessError:
            try:
                # 再尝试源码包
                cmd = [
                    "pip", "download",
                    f"{dependent_name}=={dependent_version}",
                    "--no-binary=:all:",
                    "--no-deps",
                    "-d", str(download_dir)
                ]
                subprocess.run(cmd, check=True, capture_output=True)
                logger.debug(f"成功下载二进制包 {dependent_name}=={dependent_version}, download_dir: {download_dir}")
            except subprocess.CalledProcessError as e:
                logger.error(f"下载 {dependent_name}=={dependent_version} 失败: {e.stderr.decode()}")
                return False, None
    
    # 返回下载的文件路径
    downloaded_files = list(download_dir.glob("*"))
    if downloaded_files:
        return True, downloaded_files[0]
    return False, None

def download_dependent(dependent_name, dependent_version):
    # Get json information from pypi
    extract_dir = EXTRACT_DIR / dependent_name / dependent_version
    if extract_dir.exists() and any(extract_dir.iterdir()):
        logger.debug(f"{dependent_name}=={dependent_version} 已存在，跳过下载和解压 {extract_dir}")
        return True, extract_dir
    logger.info(f"正在下载 {dependent_name}=={dependent_version}")
    url = f"https://pypi.org/pypi/{dependent_name}/{dependent_version}/json"
    response = requests.get(url)
    if response.status_code != 200:
        if response.status_code == 404:
            logger.warning(f"Package {dependent_name} {dependent_version} not found on PyPI")
            return False, None
        logger.warning(f"Failed to get package information for {dependent_name} {dependent_version} from {url}, resonse status code: {response.status_code}")

        return
    
    package_json_info = response.json()
    package_name = package_json_info["info"]["name"].lower()
    files_urls = package_json_info["urls"]
    files = []
    if dependent_name == 'djorm-ext-pgfulltext' and dependent_version == '0.9.3':
        files.append('https://files.pythonhosted.org/packages/a8/c9/91bd36f2b3f594d51339273d8c02879f39de185bafe68470953b2e93e741/djorm_ext_pgfulltext-0.9.3-py2.py3-none-any.whl')

    for item in files_urls:
        if item['packagetype'] in ["bdist_wheel", "bdist_egg", "sdist"]:
            files.append(item['url'])
    if len(files) == 0:
        logger.warning(f"Failed to find any files for {dependent_name} {dependent_version} from {url}")
            #     # 保存失败案例到JSON文件
        failed_cases_file = Path('./failed_cases/failed_cases_package_processing.json')
        save_failed_case(
            failed_cases_file,
            f"{package}=={version}",
            {
                'cve_id': cve_id,
                'reason': 'failed_get_downloadable_urls'
            }
        )
        assert False  
        return False, None
    # bdist_wheel, bdist_egg, sdist order
    def get_suffix_order(file_name):
        if file_name.endswith(".whl"):
            return 1
        elif file_name.endswith(".egg"):
            return 2
        elif file_name.endswith(".tar.gz"):
            return 3
        elif file_name.endswith(".zip"):
            return 4
        else:
            return 5
    def get_pyvers(file_name):
        try:
            wheel_meta = Wheel(file_name)
        except:
            return 3
        if wheel_meta.pyversions == ['py2.py3'] or wheel_meta.pyversions == ['py3'] or wheel_meta.pyversions == ['any']:
            return 1
        else:
            return 2
    def get_platform(file_name):
        try:
            wheel_meta = Wheel(file_name)
        except:
            return 3
        if 'any' in wheel_meta.plats or 'linux_x86_64' in wheel_meta.plats:
            return 1
        else:
            return 2
    files.sort(key=lambda x: (get_suffix_order(x), get_pyvers(x), get_platform(x)))

    # download file
    res = []
    
    for url in files:
        # 创建下载目录
        download_dir = DOWNLOADS_DIR / dependent_name / dependent_version
        download_dir.mkdir(parents=True, exist_ok=True)
        # 获取文件名
        filename = url.split("/")[-1]
        file_path = download_dir / filename
        
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = os.path.join(temp_dir, url.split("/")[-1])
            with open(file_path, "wb") as f:
                f.write(requests.get(url).content)
            success, extract_dir =  extract_dependent(file_path, package_name, dependent_version)
            if success:
                return True,extract_dir
    return False, None

@contextlib.contextmanager
def file_lock(file_path):
    """文件锁上下文管理器"""
    lock_file = str(file_path) + '.lock'
    with open(lock_file, 'w') as f:
        try:
            fcntl.flock(f, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)
            
def save_failed_case(failed_cases_file, key, data):
    """保存失败案例到JSON文件
    
    Args:
        failed_cases_file (Path): 失败案例文件路径
        key (str): 失败案例的键
        data (dict): 失败案例的数据
    """
    failed_cases_file.parent.mkdir(parents=True, exist_ok=True)
    
    with file_lock(failed_cases_file):
        if failed_cases_file.exists():
            with failed_cases_file.open('r') as f:
                try:
                    failed_cases = json.load(f)
                except json.JSONDecodeError:
                    # 如果文件损坏，创建新的字典
                    failed_cases = {}
        else:
            failed_cases = {}
        
        failed_cases[key] = {
            **data,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # 使用临时文件来保证写入的原子性
        temp_file = failed_cases_file.with_suffix('.tmp')
        with temp_file.open('w') as f:
            json.dump(failed_cases, f, indent=2)
        
        # 原子性地替换原文件
        temp_file.replace(failed_cases_file)


def download_and_extract(package, version, dumy=False):
    """下载并解压依赖包"""
    if dumy:
        return
    success, downloaded_file = download_dependent(package, version)
    if not success:
        pass
    return success


def parse_all_dependents(advisory, package, version):
    all_need_download_dependents = advisory['all_need_download_dependents']
    direct = all_need_download_dependents.get(package, {}).get(version, {}).get('direct', [])
    indirect = all_need_download_dependents.get(package, {}).get(version, {}).get('indirect', [])
    return direct, indirect
def get_direct_and_indirect_dependents(all_dependents, package, version):
    direct = all_dependents.get(package, {}).get(version, {}).get('direct', [])
    indirect = all_dependents.get(package, {}).get(version, {}).get('indirect', [])
    return direct, indirect
    

def main():
    # with open('../tests/one_method_dataset.pkl', 'rb') as f:
    #     cve2advisory_1 = pickle.load(f)
    # with open('../tests/more_than_one_dataset.pkl', 'rb') as f:
    #     cve2advisory_2 = pickle.load(f)
    # cve2advisory = {**cve2advisory_1, **cve2advisory_2}
    # one_method_file = '../tests/generated_samples/one_method_samples_20250504' + '.json'
    # more_than_one_method_file = '../tests/generated_samples/more_than_one_samples_20250504' + '.json'
    # with open(one_method_file, 'r') as f:
    #     cve2advisory_1 = json.load(f)
    # with open(more_than_one_method_file, 'r') as f:
    #     cve2advisory_2 = json.load(f)
    # cve2advisory = {**cve2advisory_1, **cve2advisory_2}
    cve2advisory = read_cve2advisory(cve_has_vf=True)
    try:
        # 初始化WebDriver
        for idxx,(cve_id, advisory) in enumerate(cve2advisory.items()):
            # 获取依赖信息
            cve_dependents, all_dependents = advisory['cve_dependents']
            
            # if cve_id != 'CVE-2020-7212':
            #     continue
            # 如果没有dependents则跳过
            if cve_dependents == 0:
                logger.warning(f"{cve_id} has no dependents, skipping")
                continue
            # 如果dependents过多则暂时跳过
            # TODO 处理dependetns较多的CVE
            # elif cve_dependents > 1000:
            #     logger.warning(f"{cve_id} has too many dependents, skipping")
            #     continue

            pairs_file = PAIRS_DIR_DATE / f'{cve_id}.json'
            pairs_file.parent.mkdir(parents=True, exist_ok=True)
            if pairs_file.exists() and True:
                logger.info(f"{cve_id} already has extracted pairs, skipping")
                continue    
            logger.info(f"Processing CVE:{cve_id} ({idxx}/{len(cve2advisory)}) with {cve_dependents} dependents, advisory: {advisory['id']}")
            

            # 得到所有需要下载的upstream version并行化处理
            logger.info(f"Getting all upstream versions for {cve_id}")

            
            def get_all_upstream_versions(cve_id, advisory, all_dependents):
                """获取所有需要下载的upstream version"""

                all_upstream_versions_with_dependents = []
                for affected_version in advisory['affected']:
                    upstream_package = affected_version['package']['name']
                    versions = affected_version['versions']
                    filtered_versions = filter_versions(upstream_package,versions)
                    
                    for upstream_version in versions:
                        # ret =  get_dependents_from_osi(upstream_package, upstream_version)
                        # direct, indirect = ret['direct'], ret['indirect']

                        
                        direct, indirect = get_direct_and_indirect_dependents(all_dependents, upstream_package, upstream_version)
                        total_dependents_for_version = len(direct) + len(indirect)
                  
                        if len(direct) or len(indirect):
                            all_upstream_versions_with_dependents.append({
                                'package': upstream_package,
                                'version': upstream_version,
                            })
                    return all_upstream_versions_with_dependents
            
            all_upstream_versions_with_dependents = get_all_upstream_versions(cve_id, advisory, all_dependents)
            results = download_packages_parallel(all_upstream_versions_with_dependents, n_jobs=20)
            # 得到下载成功的upstream versions
            success_upstream_versions = [item[1] for item in results if item[0]]
            logger.debug(f"Downloaded {len(success_upstream_versions)} upstream versions")
            

            all_successful_pairs = {}
            for upstream_package, upstream_version in success_upstream_versions:
                # if package != 'apache-airflow' and version!= '2.4.3':
                #     continue
                def process_one_dependent(upstream_package, upstream_version, down_package, down_version, cve_id=None, advisory=None):
                    """处理单个依赖包，通过dependency graph获取外部依赖包"""
                    external_pkgs = get_external_pkgs(upstream_package, upstream_version, down_package, down_version, cve_id, advisory)
                    if len(external_pkgs) == 0:
                        logger.debug(f"Not find external packages for {down_package}=={down_version}")
                        failed_cases_file = Path('./failed_cases/downloading_external_pkgs.json')
                        save_failed_case(
                            failed_cases_file,
                            f"{down_package}=={down_version}",
                            {   'cve_id': cve_id,
                                'upstream_package': upstream_package,
                                'upstream_version': upstream_version,
                                'reason': 'not_find_available_external_packages',
                                'external_pkgs_count': len(external_pkgs)
                            }
                        )
                    find_upstream_package = False
                    for item in external_pkgs:
                        package, version = item['package'], item['version']
                        if package == upstream_package and version == upstream_version:
                            find_upstream_package = True
                            break
                    if not find_upstream_package:
                        logger.warning(f"Not find upstream package {upstream_package}=={upstream_version} in external pkgs")
                        failed_cases_file = Path('./failed_cases/downloading_external_pkgs.json')
                        save_failed_case(
                            failed_cases_file,
                            f"{down_package}=={down_version}",
                            {   'cve_id': cve_id,
                                'upstream_package': upstream_package,
                                'upstream_version': upstream_version,
                                'reason': 'not_find_upstream_package_in_external_packages',
                                'external_pkgs_count': len(external_pkgs)
                            }
                        )
                        # assert False
                        
                        return False, (upstream_package, upstream_version), (down_package, down_version)
                        
                    if len(external_pkgs) > 100:
                        failed_cases_file = Path('./failed_cases/failed_cases_get_external_pgks.json')
                        save_failed_case(
                            failed_cases_file,
                            f"{down_package}=={down_version}",
                            {   'cve_id': cve_id,
                                'upstream_package': upstream_package,
                                'upstream_version': upstream_version,
                                'downstream_package': down_package,
                                'downstream_version': down_version,
                                'reason': f'too_many_external_pkgs',
                                'external_pkgs_count': len(external_pkgs)
                            }
                        )
                        return False, (upstream_package, upstream_version), (down_package, down_version)
                    # 下载external pkgs
                    logger.info(f"{(upstream_package, upstream_version), (down_package, down_version)}  has {len(external_pkgs)} external dependencies in parallel")
                    download_packages_parallel(external_pkgs, n_jobs=20)
                    # logger.info(f"Finished downloading {len(external_pkgs)} external dependencies for {down_package}=={down_version}")
                    return True, (upstream_package, upstream_version), (down_package, down_version)
                
                def process_dependents_parallel(direct, indirect, upstream_package, upstream_version, n_jobs=10, cve_id=None, advisory=None):
                    """并行处理多个依赖包"""
                    items = [(upstream_package, upstream_version, item['package'], item['version'], cve_id, advisory) 
                                for item in direct + indirect]
                    
                    results = Parallel(n_jobs=n_jobs, verbose=0)(
                        delayed(process_one_dependent)(*item) for item in items
                    )
                    return results
            
                direct, indirect = get_direct_and_indirect_dependents(all_dependents, upstream_package, upstream_version)
                # download all dependents
                # if len(direct):
                #     logger.info(f"Downloading {len(direct)} direct dependencies in parallel")
                #     results = download_packages_parallel(direct, n_jobs=20)
            
                # if len(indirect):
                #     logger.info(f"Downloading {len(indirect)} indirect dependencies in parallel")
                #     results = download_packages_parallel(indirect, n_jobs=20)
                logger.info(f"{upstream_package}=={upstream_version} has {len(direct)} direct dependencies and {len(indirect)} indirect dependencies")
                download_dependents = direct + indirect
                download_dependents = {f"{item['package']}@{item['version']}" for item in download_dependents}
                download_dependents = [{'package': item.split('@')[0],'version': item.split('@')[1]} for item in download_dependents]
                # download_dependents = [{'package': item['package'], 'version': item['version']} for item in download_dependents if package== 'agentml' and version== '0.2.0a1']
                results = download_packages_parallel(download_dependents, n_jobs=20)
                
                # 对于每个dependents，通过dependency graph收集external pkgs
                results = process_dependents_parallel(direct, indirect, upstream_package, upstream_version, cve_id=cve_id, advisory=advisory)
                successful_pairs = [item[1:] for item in results if item[0]]
                logger.info(f"{upstream_package}=={upstream_version} has {len(successful_pairs)} pairs")
                logger.info(successful_pairs)
                # assert False
                if len(successful_pairs):
                    all_successful_pairs[f'{upstream_package}@{upstream_version}'] = [item[1] for item in successful_pairs]
            
            with pairs_file.open('w') as f:
                json.dump(all_successful_pairs, f, indent=2)
    except Exception as e:
        error_info = {
            'error_type': type(e).__name__,
            'error_message': str(e),
            'stack_trace': traceback.format_exc(),
            'location': f"{__file__}:{traceback.extract_tb(e.__traceback__)[-1].lineno}"
        }
        logger.error(f"执行过程中发生错误:\n"
                    f"错误类型: {error_info['error_type']}\n"
                    f"错误信息: {error_info['error_message']}\n"
                    f"发生位置: {error_info['location']}\n"
                    f"堆栈跟踪:\n{error_info['stack_trace']}")
        print(error_info)
if __name__ == '__main__':
    
    main()