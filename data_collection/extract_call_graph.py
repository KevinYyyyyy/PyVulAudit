# import
import os
import sys
from pathlib import Path
import re
sys.path.append(str(Path(__file__).parent.parent / 'data_collection'))
import json
import subprocess
from pathlib import Path
from logger import logger
from tqdm import tqdm
from constant import *
from itertools import chain
import pickle
from collect_changes import get_vulnerable_funcs_for_cve
from vul_analyze import find_vulnerable_calls,get_pkg2url,read_commit2methods
from packaging import version as pkg_version
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
import time
from my_utils import get_repo_name
from joblib import Parallel, delayed
from collect_dependency import download_packages_parallel, get_external_pkgs,get_direct_and_indirect_dependents, process_package
from InstSimulator.get_modules_information import get_modules_information_from_name_version
from multiprocessing import Pool
# 全局driver变量
driver = None

def init_driver():
    """初始化Selenium WebDriver"""
    global driver
    if driver is None:
        try:
            options = webdriver.ChromeOptions()
            options.add_argument('--disable-gpu')
            options.add_argument('--no-sandbox')
            options.add_argument('--headless')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--start-maximized')
            options.add_argument('--log-level=3')
            logger.info("初始化ChromeDriver")
            
            driver = webdriver.Chrome(options=options)
            logger.info("ChromeDriver初始化成功")
            return driver
        except Exception as e:
            logger.error(f"ChromeDriver初始化失败: {str(e)}")
            try:
                from webdriver_manager.chrome import ChromeDriverManager
                driver = webdriver.Chrome(
                    ChromeDriverManager().install(),
                    options=options
                )
                logger.info("使用webdriver-manager初始化成功")
                return driver
            except Exception as e:
                logger.error(f"webdriver-manager初始化也失败: {str(e)}")
                raise
    return driver

def close_driver():
    """关闭WebDriver"""
    global driver
    if driver is not None:
        driver.quit()
        driver = None



def get_local_module_path(downstream_path,modules, package, version):
    """处理包含python2/python3目录的特殊包结构"""
    base_path = downstream_path
    module_paths = []
    base_path = Path(base_path)
    logger.debug(f"base_path: {base_path}")
    modules = [m.strip().strip("'\"") for m in modules if len(m.strip().strip("'\""))]
    # 检查是否存在python2/python3子目录
    py_dirs = []
    for d in ['python3', 'python2']: # e.g.,httolib2-0.9.1
        py_dir = base_path / d
        if py_dir.exists():
            py_dirs.append(py_dir)
            break  # 只处理第一个找到的子目录, 因为py2会有ast解析时候的语法错误
    
    # 如果没有特殊子目录，直接搜索base_path
    if not py_dirs:
        py_dirs = [base_path]
    
    # 搜索所有可能的目录
    found_modules = set()
    for search_dir in py_dirs:
        for module in modules:
            # 拼接完整路径
            module_path = search_dir / module
            # logger.info(f'module_path:{module_path}')
            if module_path.exists():
                module_paths.append(str(module_path))
                found_modules.add(module)
    # 处理有哪些module没在module_paths中
    not_found_modules = set(modules) - found_modules
    if len(not_found_modules) > 0:
        logger.warning(f"Module not found: {not_found_modules}")
    # logger.debug(f"modules: {modules}, module_paths: {module_paths}")

    return module_paths
def find_modules(package, version):
    # module_guard = os.path.expanduser("~/Gitclone/ModuleGuard")
    # cmd = f"conda run -n module_guard python {module_guard}/instsimulator_main.py -r {package}=={version}"
    # result = subprocess.run(cmd, shell=True,
    #                         capture_output=True, text=True)
    # if result.returncode != 0:
    #     logger.error(f"Failed to run instsimulator_main.py: {result.stderr}, when executing {cmd}")
    #     return None
    # output = result.stdout
    module_list = get_modules_information_from_name_version(package, version)
    if module_list is None:
        return []
    # print(output)
    # # 解析输出，提取模块路径
    # try:
    #     # 去除首尾空白字符和方括号
    #     output = output.strip().strip("[]")
    #     # 分割字符串并去除引号和空白
    #     module_list = [m.strip().strip("'\"") for m in output.split(',')]
    # except Exception as e:
    #     logger.error(f"Failed to parse module paths: {str(e)}")
    #     return module_list
    #     return None
    # 过滤掉测试/示例/文档相关目录的文件
    # logger.info(f"module_list: {module_list}")
    module_list = [m.strip().strip("'\"") for m in module_list if len(m.strip().strip("'\""))]
    filtered_modules = [module for module in module_list if not any(dir_ in module.split('/') for dir_ in exclude_dirs)]
    # logger.debug(f"filtered_modules: {filtered_modules}")
    return filtered_modules

def find_local_path_for_external_pkg(package, version):
    # 尝试多种可能的路径格式
    package_variants = [
        package,  # 原始包名
        package.replace('-', '.'),  # 将'-'替换为'.'
        package.replace('-', '_'),  # 将'-'替换为'_'
    ]
    
    # 尝试所有可能的路径格式
    for package_name in package_variants:
        external_dir = EXTRACT_DIR / package_name / version
        if external_dir.exists():
            break
    else:
        logger.warning(f"无法找到任何匹配的包目录格式: {package_variants}")
        return None
        
    # 查找目录下是否有package-version子目录
    search_dir = external_dir / f"{package}-{version}"
    # logger.debug(f"find_local_path_for_external_pkg, external dir: {external_dir}")
    if search_dir.exists():
        external_dir = search_dir

        logger.info(f'search_dir:{search_dir}',)

    # print(ext_dir)
    #通过glob查找ext_dir下是否包含python2和python3目录
    py3_dir = external_dir / 'python3'
    if py3_dir.exists():
         external_dir = py3_dir
    # print(ext_dir)
    
    # 检查目录是否只包含元数据文件
    py_files = list(external_dir.rglob("*.py"))
    if not py_files:
        logger.warning(f"{package}=={version} 目录 {external_dir} 可能只包含元数据文件，没有找到Python源代码 {[d for d in external_dir.iterdir() if d.is_dir()]}")
        # 保存失败案例到本地
        failed_cases_file = Path('./failed_cases/failed_cases_local_path_for_external_pkg.json')
        try:
            if failed_cases_file.exists():
                with failed_cases_file.open('r') as f:
                    failed_cases = json.load(f)
            else:
                failed_cases = {}
            key = f"{package}=={version}"
            failed_cases[key]={
                'path': str(external_dir),
                'reason': 'no_python_files',
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
            }
            
            with failed_cases_file.open('w') as f:
                json.dump(failed_cases, f, indent=2)
        except Exception as e:
            logger.error(f"保存失败案例时出错: {str(e)}")
        return None
    return str(external_dir)


def get_local_external_pkgs_path(upstream_package, upstream_version,downstream_package, downstream_version,external_pkgs):
    '''
    找到downstream_package和downstream_version对应的external_dep的路径
    '''
    all_ext_paths = []

    # external_pkgs = external_pkgs + [{'package': upstream_package,'version': upstream_version}]
    logger.debug(f"external_pkgs: {external_pkgs}")
    find_upstream_package = False
    for item in external_pkgs:
        package, version = item['package'], item['version']
        if package == upstream_package and version== upstream_version:
            find_upstream_package = True
        if package == downstream_package and version== downstream_version:
            continue
        local_path = find_local_path_for_external_pkg(package, version)
        if local_path is None:
            logger.warning(f"Failed to find local path for {package}=={version}")
            continue
        all_ext_paths.append(local_path)   
    if not find_upstream_package:
        pass
        # assert False
    all_ext_paths = list(set(all_ext_paths))
    return all_ext_paths    

def get_remote_modules(package,version):
    """获取远程模块"""
    module_file = MODULE_DIR / package / f'{package}-{version}_modules.json'
    if not module_file.parent.exists():
        module_file.parent.mkdir(parents=True, exist_ok=True)
    if module_file.exists() and False:
        try:
            with module_file.open('r') as f:
                modules = json.load(f)
            
            return modules
        except Exception as e:
            pass
    else:
        modules = find_modules(package, version)
        if len(modules) == 0:
            return []
        # logger.debug(f"Found modules: {modules}")
        with module_file.open('w') as f:
            json.dump(modules, f)
    modules = [i for i in modules if len(i.strip())]
    return modules
def execute_jarvis(jarvis_output_file,down_module_paths, down_path, all_ext_pkg_paths,cve_id, downstream_package,downstream_version, up_package, up_version):
    """执行Jarvis"""
    logger.info(f"Extracting call graph for {cve_id}, downstream package: {downstream_package}, downstream version: {downstream_version}, upstream package: {up_package}, upstream version: {up_version}")
    jarvis = os.path.expanduser("~/Gitclone/Jarvis")
    
    
    down_module_paths = down_module_paths


    # jarvis_cmd = f"conda run -n jarvis python3 {jarvis}/tool/Jarvis/jarvis_cli.py {' '.join(down_module_paths)} --package {down_path} --decy -o {jarvis_output_file} -ext {' '.join(quoted_ext_pkgs)} --skip_builtin --precision"
    # execute cmd
    cmd = [
    "conda", "run", "-n", "jarvis",
    "python3", f"{jarvis}/tool/Jarvis/jarvis_cli.py",
    *down_module_paths,
    "--package", down_path,
    "--decy",
    "-o", jarvis_output_file,
    "-ext", *all_ext_pkg_paths,
    "--skip_builtin", "--precision"
    ]

    # 转换为命令字符串（用于打印调试）
    jarvis_cmd = subprocess.list2cmdline(cmd)
    result = subprocess.run(jarvis_cmd, shell=True,
                            capture_output=True, text=True)
    print(jarvis_cmd)
    if result.returncode!= 0:
        logger.error(f"Failed to run jarvis_cli.py: {result.stderr}")
        resuts_file = Path(f'./failed_cg.txt')
        with open(resuts_file, 'a') as f:
            f.write(f"{result.stderr}\n")
        # assert False
        return False

    # cg = CallGraphGenerator(down_module_paths, down_path, decy=True,precision=False,moduleEntry=None,skip_builtin=True)
    # all_external_paths = all_ext_pkg_paths
    # cg.import_manager.add_external_path(all_external_paths)
    # logger.debug(f"jarvis_cmd: {jarvis_cmd}")
    # try:
    #     cg.analyze()
    # except Exception as e:
    #     logger.error(f"Failed to analyze {cve_id}: {str(e)}")
    #     logger.debug(f"all_external_paths: {all_external_paths}")
    #     logger.debug(f"down_module_paths: {down_module_paths}")
        

    #     # assert False
    #     return False

    # formatter = formats.Simple(cg)
    # output = formatter.generate()
    # as_formatter = formats.AsGraph(cg)
    # print(output)
    # assert False

    # with open(jarvis_output_file, "w+") as f: 
    #     f.write(json.dumps(output))
    return True

def process_one_dependent(cve_id, advisory, package_name, repo_url, upstream_package, upstream_version, item, code_changes, vulnerable_funcs,rewrite_call_graph=False):
    down_package, down_version = item['package'], item['version']
    pair_id = f"{upstream_package}@{upstream_version}_{down_package}@{down_version}"
    result_dir = Path(f'./func_results_records/{cve_id}/{pair_id}')
    if result_dir.exists() and False:
        logger.warning(f"{pair_id} has already been processed, skipping")

        return True
    
    # if not(package == "topsail" and version == "0.0.1"):
    #     continue


    #首先借助pyref获取所有的modules
    downstream_modules = get_remote_modules(down_package,down_version)
    if len(downstream_modules) == 0:
        logger.warning(f"Failed to find modules for {down_package}=={down_version} 可能只包含元数据文件，没有找到Python源代码") 
        return
    logger.info(f'Downstream {down_package} {down_version} has {len(downstream_modules)} {downstream_modules} downstream modules')

    downstream_path = find_local_path_for_external_pkg(down_package, down_version)  
    if downstream_path is None:
        logger.warning(f"Failed to find local path for {down_package}=={down_version}")
        return
    # 解析downstream的modules local path
    module_paths = get_local_module_path(downstream_path, downstream_modules, down_package, down_version)
    if len(module_paths) == 0:
        logger.warning(f"Failed to find local path for {down_package}=={down_version}")
        return
    # logger.info(f'downstream module_paths:{module_paths}')


    #解析potential external deps local path
    external_pkgs = get_external_pkgs(upstream_package,upstream_version,down_package, down_version)
    if len(external_pkgs) > 100:
        all_ext_pkg_paths = []
    else:
    # 下载external pkgs
        download_packages_parallel(external_pkgs)
        # 解析external deps local path
        all_ext_pkg_paths = get_local_external_pkgs_path(upstream_package, upstream_version,down_package, down_version,external_pkgs)


        
    jarvis_output_file = CALL_GRAPH_DIR / down_package / f'{down_package}-{down_version}_call_graph.json'
    if not jarvis_output_file.parent.exists():
            jarvis_output_file.parent.mkdir(parents=True,  exist_ok=True)
    if jarvis_output_file.exists() and not rewrite_call_graph:
        logger.info(f"{jarvis_output_file} already exists, skipping")
    else:           
        # jarvis构建call graph
        success = execute_jarvis(jarvis_output_file=jarvis_output_file, down_module_paths=module_paths, down_path=downstream_path, all_ext_pkg_paths=all_ext_pkg_paths,cve_id=cve_id, downstream_package=down_package,downstream_version=down_version, up_package=upstream_package,up_version=upstream_version)
        if not success:
            logger.warning(f"Failed to extract call graph for {cve_id}")
            
            return False

    
    # 由于jarvis构建call graph的过程中，可能会出现一些错误，导致call graph构建失败
    # 正则表达式先判断
    all_vulnerable_files = []
    for one_dir in all_ext_pkg_paths +[downstream_path]:
        if f"{upstream_package}/{upstream_version}" in one_dir:
            continue
        for vulnerable_func, full_func_name  in vulnerable_funcs:
            vulnerable_files = find_vulnerable_calls(one_dir,
                                                function_name=vulnerable_func)
            all_vulnerable_files.extend(vulnerable_files)
    logger.warning(vulnerable_funcs)
    if len(all_vulnerable_files) == 0:
        logger.debug(f"正则匹配的方式没有找到调用 :{cve_id} 的downstream {down_package}调用 的 {down_version} {[item[0] for item in vulnerable_funcs]} 的文件 ")
        find_by_ref = False
    else:
        logger.warning(f"正则匹配的方式找到调用: {cve_id} 的downstream {down_package} 调用的 {down_version}  {[item[0] for item in vulnerable_funcs]}的文件 !!!!")
        logger.debug("Potential vulnerable calls found:")
        for file_path, line_num, line_content in all_vulnerable_files:
            logger.debug(f"File: {file_path}, Line: {line_num}, Content: {line_content}")
        find_by_ref = True
    if not jarvis_output_file.exists():
        logger.error(f"Failed to extract call graph for {cve_id}, output file: {jarvis_output_file}")
        assert False
    else:
        logger.info(f"Loading extracted call graph from {jarvis_output_file}")
        with open(jarvis_output_file,'r') as f:
            call_graph = json.load(f)
    
        # 判断vulnerable func是否出现在call graph中
        found_funcs = []
        callers = call_graph.keys()
        for func, full_name in vulnerable_funcs:
            # 检查call graph中是否包含该函数（宽松匹配）
            if full_name in callers:  # 如果caller字符串包含函数名
                found_funcs.append(full_name)
                # parts = caller.split('.')
                # if func in parts :  # 如果caller字符串包含函数名
                #     found_funcs.append(caller)
        
        if found_funcs:
            # 保存结果到本地
            result_data = {
                'cve_id': cve_id,
                'upstream_package': upstream_package,
                'upstream_version': upstream_version,
                'downstream_package': down_package,
                'downstream_version': down_version,
                'vulnerable_functions': [item[1] for item in vulnerable_funcs],
                'found_functions': found_funcs,
                'code_changes': code_changes
            }
            
            
            logger.warning(f"在call graph中找到易受攻击的函数: {found_funcs}")
            # 使用BFS查找从任意调用者到目标函数的所有调用路径
            def find_call_paths(call_graph, target_func):
                """
                使用BFS查找从任意调用者到目标函数的所有调用路径
                Args:
                    call_graph: 原始调用图字典
                    target_func: 目标函数名
                Returns:
                    所有调用路径的列表,每个路径是一个函数调用序列
                """
                # 构建反向图
                reverse_graph = {}
                for caller, callees in call_graph.items():
                    for callee in callees:
                        if callee not in reverse_graph:
                            reverse_graph[callee] = []
                        reverse_graph[callee].append(caller)
                    
                # 如果目标函数不在反向图中,说明没有函数调用它
                if target_func not in reverse_graph:
                    return []
                
                # 使用BFS查找所有路径
                all_paths = []
                queue = [(target_func, [target_func])]  # (当前节点, 当前路径)
                
                while queue:
                    current, path = queue.pop(0)
                    
                    # 如果当前函数没有调用者,说明找到了一条完整路径
                    if current not in reverse_graph:
                        all_paths.append(path)
                        continue
                        
                    # 将所有调用者加入队列
                    for caller in reverse_graph[current]:
                        if caller not in path:  # 避免循环调用
                            queue.append((caller, [caller] + path))
                    
                return all_paths

            # 检查调用关系
            # for func in found_funcs:
            #     # 获取所有调用路径
            #     call_paths = find_call_paths(call_graph, func)
                
            #     if call_paths:
            #         logger.warning(f"函数 {func} 的所有调用路径:")
            #         for path in call_paths:
            #             logger.warning(f"调用路径: {' -> '.join(path)}")
            #     else:
            #         logger.warning(f"函数 {func} 存在于call graph中但未被调用")

            result_file = Path(f'./func_results/{cve_id}/{down_package}-{down_version}_results.json')
            if not result_file.parent.exists():
                result_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(result_file, 'w') as f:
                json.dump(result_data, f, indent=2)
        else:
            if find_by_ref:
                resuts_file = Path(f'./find_by_ref.txt')
                with open(resuts_file, 'a') as f:
                    line1 = f'{cve_id} {upstream_package} {upstream_version} {down_package} {down_version}\n'
                    line2 = f'{[item[1] for item in vulnerable_funcs]}\n'
                    f.write(line1)
                    f.write(line2)
                pass
            logger.warning(f"未在call graph中找到任何易受攻击的函数: {[f[1] for f in vulnerable_funcs]}")
        if not result_dir.exists():
            result_dir.mkdir(parents=True, exist_ok=True)
        return True
                

def process_dependents_parallel(items, n_jobs=10):
    """Process multiple packages in parallel using joblib"""
    # results = Parallel(n_jobs=n_jobs, verbose=0)(
    #     delayed(process_one_dependent)(
    #         item
    #     ) for item in items
    # )
    with Pool(n_jobs) as pool:
        results = pool.map(process_one_dependent, items)
    return results
    return results                
if __name__ == '__main__':

    
    with open('../tests/small_dataset.pkl', 'rb') as f:
        cve2advisory = pickle.load(f)
    pkg2url = get_pkg2url()
    with open('../tests/one_method_dataset.pkl', 'rb') as f:
        cve2advisory_1 = pickle.load(f)
    with open('../tests/more_than_one_dataset.pkl', 'rb') as f:
        cve2advisory_2 = pickle.load(f)
    cve2advisory = {**cve2advisory_1, **cve2advisory_2}
    # only_download(filtered_cve2advisory)
    # driver = init_driver()
    rewrite_call_graph = True
    for idxx, (cve_id, advisory) in enumerate(cve2advisory.items()):
        
        # if cve_id != "CVE-2024-3772":
        #     continue
        # else:
        #     rewrite_call_graph = True
        # if cve_id != "CVE-2024-9902":
        #     continue
        # else:
        #     rewrite_call_graph = True
        # if idxx <3:
        #     continue
        # if idxx > 10:
        #     continue
        cve_dependents,all_dependents =  advisory['cve_dependents']
        if cve_dependents ==0:
            logger.warning(f"{cve_id} {advisory['id']} has no dependents, skipping")
            continue
        if cve_dependents > 1000:
            logger.warning(f"{cve_id} has too many ({cve_dependents}) dependents, skipping")
            continue
        logger.info(f"Processing {cve_id} ({idxx}/{len(cve2advisory)}), advisory: {advisory['id']}")

        logger.info(f"{cve_id} has {cve_dependents} dependents")
        
        all_unique_affected_projects = set()
        for affected_version in advisory['affected']:
            package_name = affected_version['package']['name'].lower()
            all_unique_affected_projects.add((package_name,pkg2url[package_name]))
        all_unique_affected_projects = list(all_unique_affected_projects)


        for package_name,repo_url in all_unique_affected_projects:

            
            vulnerable_funcs = get_vulnerable_funcs_for_cve(cve_id, get_repo_name(repo_url))

            all_code_changes = set(chain.from_iterable(code_changes.values()))
            if len(code_changes) ==0:
                logger.warning(f"{cve_id} {advisory['id']} has no code changes, skipping")
                continue
            logger.info(f"Found code changes for {cve_id}: {all_code_changes}, repo:{repo_name}")
            # print(all_dependents)
            # 找到affected_version对应的package和version
            affected_versions = [item for item in advisory['affected'] if item['package']['name'].lower() == package_name.lower()]
            # assert len(affected_versions) == 1
            # print(affected_version)

            upstream_package = package_name
            
            versions = chain.from_iterable([affected_version['versions'] for affected_version in affected_versions])
            try:
                versions_sorted = sorted(versions, key=pkg_version.parse, reverse=True)
            except Exception as e:
                logger.error(f"Failed to parse versions: {str(e)}")
                # assert False
                versions_sorted = sorted(versions, reverse=True)
            items_to_process = []
            
            for upstream_version in versions_sorted:
                # if  upstream_version !='2.11.12':
                #     continue
                direct, indirect = get_direct_and_indirect_dependents(all_dependents, upstream_package, upstream_version)
                total_dependents_for_version = len(direct) + len(indirect)
                
                if total_dependents_for_version == 0:
                    continue
                    
                logger.debug(f"{cve_id} {upstream_package} {upstream_version} has {total_dependents_for_version}/{cve_dependents} dependents")
                
                # 下载上游包
                package_dir = EXTRACT_DIR / upstream_package / upstream_version
                if not package_dir.exists():
                    logger.debug(f"{upstream_package}=={upstream_version} not exists")
                    continue

                process_package(upstream_package, upstream_version)
                upstream_local_source_path = find_local_path_for_external_pkg(upstream_package, upstream_version)
                if upstream_local_source_path is None:
                    logger.warning(f"Failed to find local path for upstream package {upstream_package}=={upstream_version}")
                    continue
                
                # 准备并行处理的参数
                for item in direct + indirect:
                    items_to_process.append({
                        'cve_id': cve_id,
                        'advisory': advisory,
                        'package_name': package_name,
                        'repo_url': repo_url,
                        'upstream_package': upstream_package,
                        'upstream_version': upstream_version,
                        'item': item,
                        'code_changes': code_changes,
                        'vulnerable_funcs': vulnerable_funcs
                    })
                
                
                # for item in direct+indirect:
                #     process_one_dependent(cve_id, advisory, package_name, repo_url, upstream_package, upstream_version, item)
                #     assert False
                # break
            # 并行处理所有dependents
            logger.info(f"开始并行处理 {len(items_to_process)} 个 upstream-downstream pairs")
            results = Parallel(n_jobs=1)(
                delayed(process_one_dependent)(
                    item['cve_id'],
                    item['advisory'],
                    item['package_name'],
                    item['repo_url'],
                    item['upstream_package'],
                    item['upstream_version'],
                    item['item'],
                    item['code_changes'],
                    item['vulnerable_funcs']
                ) for item in items_to_process
            )
            
            # 处理结果
            successful = [r for r in results if r is True]
            logger.info(f"完成并行处理，成功处理 {len(successful)}/{len(items_to_process)} 个dependents")
        

    # close_driver()
