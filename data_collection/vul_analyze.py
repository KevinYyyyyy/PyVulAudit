import os
import re
import pickle
from pathlib import Path
import sys
sys.path.append(Path(__file__).parent.parent.as_posix())

from pydriller import Commit
from pydriller.domain.commit import ModificationType
from src.constant import *

from data_collection.logger import logger
import json
from typing import List, Optional
from data_collection.data_classes import VulnerablePackage
from collections import Counter

def get_dependents(cve_id,advisory,real_time=False):
    dependents_file = DEPENDENTS_DIR / f'{cve_id}.json'
    if not dependents_file.exists():
        assert False
        return 0, {}
    else:
        with open(dependents_file, 'r') as f:
            all_dependents = json.load(f)
        
    
        total_dependents = 0  # 新增：统计当前CVE的总依赖项
        # 统计依赖关系
        for affected_item in advisory['affected']:
            package = affected_item['package']['name']
            if package in all_dependents:
                for version, deps in all_dependents[package].items():
                    
                    direct_dependents = deps.get('direct', [])
                    indirect_dependents = deps.get('indirect', [])
                    total_dependents += len(direct_dependents) + len(indirect_dependents)
                break
        return total_dependents,all_dependents
                            
                
def get_vul_description():
    # from snyk
    # fron nvd
    # from osv
    pass
def read_cves_filter_by_available_versions():
    with open('./filtered_cves_by_available_versions.pickle', 'rb') as f:
        filtered_cves_by_available_versions = pickle.load(f)
    return filtered_cves_by_available_versions

def read_fixing_commits(cve_id):
    fixing_commit_file = COMMITS_DIR/f'{cve_id}.pkl'
    if not fixing_commit_file.exists():
        return {}
    with fixing_commit_file.open('rb') as f:
        fixing_commits = pickle.load(f)
        return fixing_commits

def read_commit2methods(cve_id,repo_name,use_ast=False):    
    if use_ast:
        commit2methods_file = Path(str(CODE_CHANGES_DIR).replace('code_changes','code_changes_ast'))/f'{cve_id}_{repo_name}.json'
    else:
        commit2methods_file = CODE_CHANGES_DIR/f'{cve_id}_{repo_name}.json'
    # print(commit2methods_file)
    if not commit2methods_file.exists():
        return {}
    with commit2methods_file.open('rb') as f:
        commit2methods = json.load(f)
        return commit2methods
        
def read_snyk_fixing_commits(cve_id):
    fixing_commit_file = SNYK_URLS_DIR/f'{cve_id}.json'
    if not fixing_commit_file.exists():
        return {}
    with fixing_commit_file.open('rb') as f:
        fixing_commits = json.load(f)
        return fixing_commits
def read_possible_urls(cve_id):
    possible_urls_file = POSSIBLE_COMMITS_DIR/f'{cve_id}.pkl'
    if not possible_urls_file.exists():
        return {}
    with possible_urls_file.open('rb') as f:
        possible_urls = pickle.load(f)
        return possible_urls
def read_cve2advisory(small=False, medium=False,valid_py_cve=True,specific_date=True, cve_has_vfc=False, cve_has_vf=False, only_one_vf=False):
    if specific_date:
        if only_one_vf:
            with open(DATA_DIR/SUFFIX/'cve2advisory_only_one_VF.pkl', 'rb') as f:
                cve2advisory = pickle.load(f)
        elif cve_has_vf:
            with open(CVE2ADVISORY_VF_FILE_DATE, 'rb') as f:
                cve2advisory = pickle.load(f)
        elif cve_has_vfc:
            with open(CVE2ADVISORY_VFC_FILE_DATE, "rb") as f:
                cve2advisory = pickle.load(f)
        else:
            with open(CVE2ADVISORY_FILE_DATE, "rb") as f:
                cve2advisory = pickle.load(f)
    return cve2advisory
    if valid_py_cve:
        with open('../tests/generated_samples/valid_py_cve_ids_20250619.txt', 'r') as f:
            valid_cve_ids = f.read().splitlines()
    
    else:
        if small:
            one_method_file = '../tests/generated_samples/one_method_samples_20250504' + '.json'
            more_than_one_method_file = '../tests/generated_samples/more_than_one_samples_20250504' + '.json'
            with open(one_method_file, 'r') as f:
                cve2advisory_1 = json.load(f)
            with open(more_than_one_method_file, 'r') as f:
                cve2advisory_2 = json.load(f)
            
            cve2advisory = {**cve2advisory_1, **cve2advisory_2}

        elif medium:
            # file_ = '../tests/generated_samples/100_samples_20250609' + '.json'
            file_ = '../tests/generated_samples/100_samples_20250615' + '.json'
            one_method_file = '../tests/generated_samples/one_method_samples_20250504' + '.json'
            more_than_one_method_file = '../tests/generated_samples/more_than_one_samples_20250504' + '.json'
            with open(one_method_file, 'r') as f:
                cve2advisory_1 = json.load(f)
            with open(more_than_one_method_file, 'r') as f:
                cve2advisory_2 = json.load(f)
            
            cve2advisory = {**cve2advisory_1, **cve2advisory_2}
            with open(file_, 'r') as f:
                cve2advisory_1 = json.load(f)
            cve2advisory = {**cve2advisory, **cve2advisory_1}
        # skip_project = []
        # skip_project=['azure-sdk-for-python']
        else:
            with open(CVE2ADVISORY_FILE, "rb") as f:
                cve2advisory = pickle.load(f)
    if valid_py_cve:
        cve2advisory = {cve_id: advisory for cve_id, advisory in cve2advisory.items() if cve_id in valid_cve_ids}
    return cve2advisory




def is_source_code_file(file):
    if file.change_type == ModificationType.ADD or not file.old_path or file.change_type == ModificationType.RENAME:
        return False
    elif  any(f"{dir_}" in file.old_path.lower().split('/')[:-1]  for dir_ in exclude_dirs):
        # for dir_ in exclude_dirs:
        #     print(dir_, dir_ in self.old_path.lower().split('/')[:-1] )
        # assert False
        return False
    # elif any(self.old_path.lower().startswith(f"{dir_}/") for dir_ in exclude_dirs):
    #     assert False

    #     return False
    elif 'test'  in file.filename.lower():
        return False
    elif 'setup.py'  in file.filename.lower() or 'setup.cfg'  in file.filename.lower():
        return False
    
    elif file.filename.lower().endswith(tuple(exclude_suffixes)):
        return False
    return True
    
def filter_files(file_changes):
    """过滤文件列表，只保留源代码文件且不包含测试/示例/文档目录的文件"""
    # 过滤掉新添加的文件 
    # file_changes = [file for file in file_changes if file.change_type != ModificationType.ADD and file.old_path]
    
    # # 过滤掉测试/示例/文档相关目录的文件
    # # 不能简单的根据字符串匹配https://github.com/mapproxy/mapproxy/commit/420412aad45171e05752007a0a2350c03c28dfd8
    # # 移除了文件名称，避免匹配demo.py
    # filtered = [file for file in file_changes 
    #            if not any(f"{dir_}" in file.old_path.lower().split('/')[:-1]  for dir_ in exclude_dirs)]
    
    
    # # filtered = [file for file in file_changes if not any(file.filename.lower().startswith(f"{dir_}/") for dir_ in exclude_dirs)]
    # # print([file.new_path for file in filtered if file.new_path])
    # # old_path = 'tensorflow/python/ops/bincount_ops_test.py'
    # # 过滤掉仍然可能存在的test文件
    # filtered = [file for file in filtered if 'test' not in file.filename.lower()]
    # # print([file.new_path for file in filtered if file.new_path])

    # # https://github.com/bwoodsend/rockhopper/commit/1a15fad5e06ae693eb9b8908363d2c8ef455104e#diff-60f61ab7a8d1910d86d9fda2261620314edcae5894d5aaa236b821c7256badd7
    # filtered = [file for file in filtered if 'setup.py' not in file.filename.lower()]
    # # print([file.new_path for file in filtered if file.new_path])

    # # logger.debug([file.old_path for file in filtered])     
    # exclude_suffixes = {'.md', '.rst', '.txt','.feature'}
    # filtered = [file for file in filtered if not file.filename.lower().endswith(tuple(exclude_suffixes))]
    # print([file.new_path for file in filtered if file.new_path])
    filtered_files = [file for file in file_changes if is_source_code_file(file)]
    # 在过滤掉一些非功能性文件后，再考虑.py和其他修改
    # 过滤掉非.py文件，并且非test.py文件
    # print([file.old_path for file in filtered])
    filtered_py = [file for file in filtered_files if file.filename.endswith('.py')]
    # print([file.new_path for file in filtered_py if file.new_path])

    filtered_non_py = [file for file in filtered_files if not file.filename.endswith('.py')]
    
    logger.debug([file.filename for file in filtered_py])
    return filtered_non_py,filtered_py


def get_modified_files(commit:Commit):
    commit_hash = commit.hash
    try:
        modified_files = commit.modified_files
        if len(modified_files) == 0:
            logger.debug(f'No files modified in commit {commit_hash}')

            return [],[]

        # logger.debug([file.old_paath for file in modified_files])

        return modified_non_py_files,modified_py_files
    except Exception as e:
        logger.warning(f'Error processing commit {commit_hash}: {e}')
        assert False
def get_pkg2url():
    # with open(DATA_DIR / 'pkg2url_additional.json', 'r') as f:
    #     pkg2url_additional = json.load(f)
    #     pkg2url_additional = {k.lower(): v for k, v in pkg2url_additional.items()}

    # with open(DATA_DIR / 'pkg2url.json', 'r') as f:
    #     pkg2url = json.load(f)
    #     pkg2url = {k.lower(): v for k, v in pkg2url.items()}
    # pkg2url.update(pkg2url_additional)
    
    with open(DATA_DIR / 'pkg2url_new.json', 'r') as f:
        pkg2url = json.load(f)
        pkg2url = {k.lower(): v for k, v in pkg2url.items()}
    return pkg2url
def adjust_message(message):
    # 去除回车符和多余的换行符，替换制表符和逗号为空格，去除前后空格
    message_no_carriage = message.replace("\r", "\n")
    one_newline_message = re.sub(r"\n+", "\n", message_no_carriage)
    clear_message = one_newline_message.replace("\n", ". ").replace("\t", " ").replace(",", " ").replace("\"", "'")
    stripped_message = clear_message.strip()
    return re.sub(r" +", " ", stripped_message)
def find_vulnerable_calls(directory, function_name):
    vulnerable_files = []

    # 遍历目录中的所有文件
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)
                if 'test' in file_path:
                    continue
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        for line_num, line in enumerate(f, start=1):
                            if line.lstrip().startswith('>>>') or line.lstrip().startswith('#'):
                                continue
                            if function_name+'(' in line and 'def' not in line:
                                vulnerable_files.append(
                                    (file_path, line_num, line.strip()))
                except Exception as e:
                    print(f"Error reading {file_path}: {e}")
                

    return vulnerable_files


def find_unzipable_files(directory):
    # TODO: add tar.gz
    # 确保目录存在
    if not os.path.isdir(directory):
        print(f"Directory '{directory}' does not exist.")
        return []

    # 获取目录下的所有文件
    files = os.listdir(directory)

    # 过滤出以 .whl 结尾的文件
    zip_files = [file for file in files if file.endswith(".whl") or file.endswith(".zip")]

    # 返回完整路径
    return [os.path.join(directory, file) for file in zip_files]


def extract_pypi_archives(directory):
    """
    解压目录下所有PyPI可能使用的压缩包格式文件

    参数:
        directory (str): 要扫描的目录路径

    支持的格式:
        - .tar.gz
        - .tar.bz2
        - .zip
        - .whl (实际上是zip格式)
        - .egg (实际上是zip格式)
    """
    # 支持的压缩包扩展名
    archive_extensions = ('.tar.gz', '.tar.bz2', '.zip', '.whl', '.egg')

    # 转换为Path对象
    dir_path = Path(directory)

    # 遍历目录下所有文件
    for file_path in dir_path.glob('*'):
        if file_path.is_file():
            # 检查文件扩展名是否匹配
            if str(file_path).lower().endswith(archive_extensions):
                print(f"发现压缩包: {file_path.name}")

                # 创建解压目录(使用文件名作为目录名)
                extract_dir = dir_path / file_path.stem
                if file_path.suffix == '.gz' and file_path.name.endswith('.tar.gz'):
                    extract_dir = dir_path / file_path.name.replace('.tar.gz', '')
                elif file_path.suffix == '.bz2' and file_path.name.endswith('.tar.bz2'):
                    extract_dir = dir_path / file_path.name.replace('.tar.bz2', '')

                extract_dir.mkdir(exist_ok=True)

                try:
                    # 根据不同类型解压
                    if file_path.suffix == '.gz' and file_path.name.endswith('.tar.gz'):
                        # .tar.gz 文件
                        with tarfile.open(file_path, 'r:gz') as tar:
                            tar.extractall(path=extract_dir)
                            print(f"已解压 {file_path.name} 到 {extract_dir}")

                    elif file_path.suffix == '.bz2' and file_path.name.endswith('.tar.bz2'):
                        # .tar.bz2 文件
                        with tarfile.open(file_path, 'r:bz2') as tar:
                            tar.extractall(path=extract_dir)
                            print(f"已解压 {file_path.name} 到 {extract_dir}")

                    elif file_path.suffix == '.zip' or file_path.suffix == '.whl' or file_path.suffix == '.egg':
                        # .zip, .whl 或 .egg 文件
                        with zipfile.ZipFile(file_path, 'r') as zip_ref:
                            zip_ref.extractall(extract_dir)
                            print(f"已解压 {file_path.name} 到 {extract_dir}")

                except Exception as e:
                    print(f"解压 {file_path.name} 时出错: {str(e)}")
                    continue


def get_vul_version(data):
    def get_version(affects):
        versions = list()
        for affect in affects:
            if "ranges" in affect:
                assert len(affect["ranges"]) == 1
                introduced = affect["ranges"][0]["events"][0]["introduced"] if "introduced" in affect["ranges"][0]["events"][0] else None
                fixed = affect["ranges"][0]["events"][1]["fixed"] if len(affect["ranges"][0]["events"])>1 and "fixed" in affect["ranges"][0]["events"][1] else None
                versions.append((introduced, fixed))
            else:
                assert False
        return str(versions)

    return data["affected"].apply(lambda x:get_version(x) )


def load_vulnerable_packages(vulnerable_packages_dir: str = None, 
                           filter_cve_ids: Optional[List[str]] = None,
                           filter_package_names: Optional[List[str]] = None,
                           max_vfs = None) -> List[VulnerablePackage]:
    """
    读取vulnerable packages目录下的所有pickle文件，返回VulnerablePackage实例列表
    
    Args:
        vulnerable_packages_dir: vulnerable packages目录路径，如果为None则使用默认路径
        dataset_size: 数据集大小 ('small', 'medium', 'large')
        filter_cve_ids: 可选的CVE ID过滤列表，如果提供则只加载这些CVE的包
        filter_package_names: 可选的包名过滤列表，如果提供则只加载这些包
    
    Returns:
        List[VulnerablePackage]: VulnerablePackage实例的列表
    
    Raises:
        FileNotFoundError: 如果目录不存在
        ValueError: 如果没有找到任何有效的包文件
    """
    # 设置默认目录路径
    if vulnerable_packages_dir is None:
        packages_dir = VUL_PACKAGES_DIR_DATE
    else:
        packages_dir = Path(vulnerable_packages_dir)
    
    # 检查目录是否存在
    if not packages_dir.exists():
        raise FileNotFoundError(f"Vulnerable packages directory not found: {packages_dir}")
    
    if not packages_dir.is_dir():
        raise ValueError(f"Path is not a directory: {packages_dir}")
    
    vulnerable_packages = []
    failed_files = []
    skipped_files = []
    
    # 获取所有pickle文件
    pkl_files = list(packages_dir.glob("*.pkl"))
    
    if not pkl_files:
        logger.warning(f"No pickle files found in directory: {packages_dir}")
        return []
    
    logger.info(f"Found {len(pkl_files)} pickle files in {packages_dir}")
    
    # 遍历所有pickle文件
    for pkl_file in pkl_files:
        try:
            # 加载pickle文件
            with open(pkl_file, 'rb') as f:
                vulnerable_package = pickle.load(f)
            
            # 验证是否为VulnerablePackage实例
            if not isinstance(vulnerable_package, VulnerablePackage):
                logger.warning(f"File {pkl_file.name} does not contain a VulnerablePackage instance")
                failed_files.append(pkl_file.name)
                continue
            
            # 应用CVE ID过滤
            if filter_cve_ids and vulnerable_package.cve_id not in filter_cve_ids:
                skipped_files.append(f"{pkl_file.name} (CVE filter)")
                continue
            
            # 应用包名过滤
            if filter_package_names and vulnerable_package.package_name not in filter_package_names:
                skipped_files.append(f"{pkl_file.name} (Package filter)")
                continue

            # 应用VF数量过滤
            if max_vfs and len(vulnerable_package.vulnerable_functions)>max_vfs:
                skipped_files.append(f"{pkl_file.name} (Package filter)")
                continue

            
            # 验证关键字段不为空
            if not vulnerable_package.cve_id:
                logger.warning(f"File {pkl_file.name} has empty CVE ID")
                failed_files.append(pkl_file.name)
                continue
            
            if not vulnerable_package.package_name:
                logger.warning(f"File {pkl_file.name} has empty package name")
                failed_files.append(pkl_file.name)
                continue
            
            if not vulnerable_package.package_version:
                logger.warning(f"File {pkl_file.name} has empty package version")
                failed_files.append(pkl_file.name)
                continue
            
            vulnerable_packages.append(vulnerable_package)
            
        except (pickle.PickleError, EOFError) as e:
            logger.error(f"Failed to load pickle file {pkl_file.name}: {e}")
            failed_files.append(pkl_file.name)
            continue
        except Exception as e:
            logger.error(f"Unexpected error loading {pkl_file.name}: {e}")
            failed_files.append(pkl_file.name)
            continue
    
    # 记录统计信息
    logger.info(f"Successfully loaded {len(vulnerable_packages)} vulnerable packages")
    
    if failed_files:
        logger.warning(f"Failed to load {len(failed_files)} files: {failed_files[:5]}{'...' if len(failed_files) > 5 else ''}")
    
    if skipped_files:
        logger.info(f"Skipped {len(skipped_files)} files due to filters: {skipped_files[:5]}{'...' if len(skipped_files) > 5 else ''}")
    
    if not vulnerable_packages:
        raise ValueError("No valid VulnerablePackage instances found")
    
    return vulnerable_packages


def load_vulnerable_packages_by_cve(vulnerable_packages_dir: str,
                                   cve_ids: Optional[List[str]],
                                   dataset_size: str = 'small') -> List[VulnerablePackage]:
    """
    根据特定CVE ID加载vulnerable packages
    
    Args:
        vulnerable_packages_dir: vulnerable packages目录路径
        cve_id: 要加载的CVE ID
        dataset_size: 数据集大小
    
    Returns:
        List[VulnerablePackage]: 指定CVE的VulnerablePackage实例列表
    """
    return load_vulnerable_packages(
        vulnerable_packages_dir=vulnerable_packages_dir,
        dataset_size=dataset_size,
        filter_cve_ids=cve_ids
    )


def load_vulnerable_packages_by_package(vulnerable_packages_dir: str,
                                       package_names: Optional[List[str]],
                                       dataset_size: str = 'small') -> List[VulnerablePackage]:
    """
    根据特定包名加载vulnerable packages
    
    Args:
        vulnerable_packages_dir: vulnerable packages目录路径
        package_name: 要加载的包名
        dataset_size: 数据集大小
    
    Returns:
        List[VulnerablePackage]: 指定包的VulnerablePackage实例列表
    """
    return load_vulnerable_packages(
        vulnerable_packages_dir=vulnerable_packages_dir,
        dataset_size=dataset_size,
        filter_package_names=package_names
    )


def get_vulnerable_packages_summary(vulnerable_packages: List[VulnerablePackage]) -> dict:
    """
    获取vulnerable packages的统计摘要
    
    Args:
        vulnerable_packages: VulnerablePackage实例列表
    
    Returns:
        dict: 包含统计信息的字典
    """
    if not vulnerable_packages:
        return {"total_packages": 0}
    
    from collections import defaultdict
    import numpy as np
    
    # 统计计数器
    cve_counts = defaultdict(int)
    package_counts = defaultdict(int)
    function_counts = []
    module_counts = []
    
    for vp in vulnerable_packages:
        cve_counts[vp.cve_id] += 1
        package_counts[f"{vp.package_name}@{vp.package_version}"] += 1
        function_counts.append(len(vp.vulnerable_functions))
        module_counts.append(len(vp.upstream_modules) if vp.upstream_modules else 0)
    
    summary = {
        "total_packages": len(vulnerable_packages),
        "unique_cves": len(cve_counts),
        "unique_package_versions": len(package_counts),
        "function_stats": {
            "total_functions": sum(function_counts),
            "avg_functions_per_package": np.mean(function_counts) if function_counts else 0,
            "max_functions_per_package": max(function_counts) if function_counts else 0,
            "min_functions_per_package": min(function_counts) if function_counts else 0,
            "median_functions_per_package": np.median(function_counts) if function_counts else 0
        },
        "module_stats": {
            "total_modules": sum(module_counts),
            "avg_modules_per_package": np.mean(module_counts) if module_counts else 0,
            "max_modules_per_package": max(module_counts) if module_counts else 0,
            "min_modules_per_package": min(module_counts) if module_counts else 0,
            "median_modules_per_package": np.median(module_counts) if module_counts else 0
        },
        "top_cves_by_package_count": dict(sorted(cve_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
        "top_packages_by_occurrence": dict(sorted(package_counts.items(), key=lambda x: x[1], reverse=True)[:10])
    }
    
    return summary
if __name__ == "__main__":
    vulnerable_packages = load_vulnerable_packages()
    cve_ids = {vp.cve_id for vp in vulnerable_packages}
    print(f"Loaded {len(vulnerable_packages)} vulnerable packages")
    print(f"Loaded {len(cve_ids)} CVEs")

    cnt_dict = {}
    for vp in vulnerable_packages:
        cve_id = vp.cve_id
        vf_cnt = len(vp.vulnerable_functions)
        if cnt_dict.get(cve_id, -1) < vf_cnt:
            cnt_dict[cve_id] = vf_cnt
    print(Counter(cnt_dict.values()))
    


    
    # 打印前几个包的信息
    # for i, vp in enumerate(vulnerable_packages[:3]):
    #     print(f"\nPackage {i+1}:")
    #     print(f"  CVE ID: {vp.cve_id}")
    #     print(f"  Package: {vp.package_name}@{vp.package_version}")
    #     print(f"  Vulnerable Functions: {len(vp.vulnerable_functions)}")
    #     if len(vp.vulnerable_functions)<4:
    #         print(f"{(vp.vulnerable_functions)}")
    #     print(f"  Upstream Modules: {len(vp.upstream_modules) if vp.upstream_modules else 0}")
    
    # 获取统计摘要
    # summary = get_vulnerable_packages_summary(vulnerable_packages)
    # print(f"\nSummary: ")
    # for key, value in summary.items():
    #     print(key+':')
    #     print(value)
        