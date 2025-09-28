import os
from pathlib import Path
import json
import time
import requests
import sys

from data_collection.vul_analyze import read_cve2advisory
from logger import logger
from constant import *
from data_collection.get_compatable_python_version import filter_versions
from packaging import version as pkg_version
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.service import Service
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import traceback


# 全局session配置
session = requests.Session()
retries = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[500, 502, 503, 504],
    allowed_methods=['GET']
)
session.mount('https://', HTTPAdapter(max_retries=retries))

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
            service = Service(executable_path=ChromeDriverManager().install())
            driver = webdriver.Chrome(
                service=service,
                options=options
            )
            logger.info("使用webdriver-manager初始化成功")
        except Exception as e:
            logger.error(f"webdriver-manager初始化也失败: {str(e)}")
            raise
    return driver


def close_driver():
    """关闭driver"""
    global driver
    if driver is not None:
        driver.quit()
        driver = None


def get_dependents_num_from_osi(package, version):
    """从deps.dev API获取dependents数量"""
    url = f"https://api.deps.dev/v3alpha/systems/pypi/packages/{package}/versions/{version}:dependents"
    try:
        response = session.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        return data['dependentCount']
    except requests.exceptions.SSLError:
        logger.warning("SSL验证失败，尝试不验证SSL证书...")
        response = session.get(url, verify=False, timeout=10)
        data = response.json()
        return data['dependentCount']
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            logger.warning(f"deps.dev上没有找到{package}@{version}的依赖项")
            return 0
        else:
            logger.error(f"获取dependents数量失败: {str(e)}")
            return -1
    except Exception as e:
        logger.error(f"获取dependents数量失败: {str(e)}")
        return -1


def get_dependents_from_osi(package, version):
    """使用Selenium从deps.dev获取依赖信息"""
    global driver
    
    url = f"https://deps.dev/pypi/{package}/{version}/dependents"
    max_retries = 3
    retry_count = 0
    
    # 首先检查是否有dependents
    ret = get_dependents_num_from_osi(package, version)
    if ret == 0:
        logger.debug(f"deps.dev上没有找到{package}@{version}的依赖项")
        return {'direct': [], 'indirect': []}
    elif ret == -1:
        return {'direct': ['ERROR'], 'indirect': ['ERROR']}
    
    while retry_count < max_retries:
        try:
            logger.info(f"正在访问: {url} (尝试 {retry_count + 1}/{max_retries})")
            driver.get(url)
            
            # 等待页面加载
            WebDriverWait(driver, 20).until(
                EC.presence_of_element_located((By.XPATH, '//*[@id="root"]/div[1]/div/div/div/div'))
            )
            
            dependents = {'direct': [], 'indirect': []}
            rows = driver.find_elements(By.XPATH, '//*[@id="root"]/div[1]/div/div/div/div/table/tbody/tr')
            logger.info(f"找到 {len(rows)} 个依赖项")
            
            for row in rows:
                try:
                    package_name, version_num, relation = row.text.split(' ')
                    if relation.lower() == 'direct':
                        dependents['direct'].append({
                            'package': package_name,
                            'version': version_num
                        })
                    else:
                        dependents['indirect'].append({
                            'package': package_name,
                            'version': version_num
                        })
                except Exception as e:
                    logger.warning(f"解析依赖项失败: {e}")
                    continue
            
            return dependents
            
        except (TimeoutException, WebDriverException) as e:
            retry_count += 1
            logger.warning(f"页面加载失败: {str(e)}, 正在重试 ({retry_count}/{max_retries})")
            time.sleep(2)
            continue
        except Exception as e:
            logger.error(f"发生错误: {str(e)}")
            
    return {'direct': ['ERROR'], 'indirect': ['ERROR']}


def get_dependents_for_version(package, version, rewrite=False):
    """获取指定包版本的dependents"""
    if len(version.split('.')) == 2:
        version = version + '.0'
        
    dependents_file = DEPENDENTS_DIR_DATE / package / f'{package}_{version}.json'
    dependents_file.parent.mkdir(parents=True, exist_ok=True)
    
    # 检查缓存文件
    if dependents_file.exists() and not rewrite:
        with open(dependents_file, 'r') as f:
            dependents = json.load(f)
        if 'ERROR' not in dependents['direct'] and 'ERROR' not in dependents['indirect'] and dependents:
            return dependents
    elif sys.platform !='darwin':
        return {}
        assert False,dependents_file
    
    # 获取dependents
    dependents = get_dependents_from_osi(package, version)

    # if sys.platform == 'darwin':
    #     dependents = get_dependents_from_osi(package, version)
    # else:
    #     logger.error("暂时只支持macOS系统")
    #     return {'direct': ['ERROR'], 'indirect': ['ERROR']}
    
    # 保存到缓存
    with open(dependents_file, 'w') as f:
        json.dump(dependents, f)
    
    return dependents


def get_dependents_for_cve(cve_id, advisory, no_dependents_count_skip=-1, rewrite=False):
    """获取CVE的所有dependents"""
    
    logger.info(f"Processing CVE: {cve_id}, advisory: {advisory['id']}")
    # rewrite = cve_id == 'CVE-2025-32962'
    dependents_file = DEPENDENTS_DIR_DATE / f'{cve_id}.json'
    logger.info(f"dependents_file: {dependents_file}")
    if dependents_file.exists() and not rewrite:
        with open(dependents_file, 'r') as f:
            all_dependents = json.load(f)
    elif sys.platform != 'darwin':
            return {}
    else:


        all_dependents = {}
        for upstream_package,infos in advisory['available_affected'].items():
            versions = infos['versions']
            
            logger.debug(f"package: {upstream_package}, total {len(versions)} versions")
            # 按版本排序
            try:
                versions_sorted = sorted(versions, key=pkg_version.parse, reverse=True)
            except:
                versions_sorted = sorted(versions, reverse=True)
            
            logger.debug(f"package: {upstream_package}, total {len(versions)} available versions: {versions_sorted}")
            
            for version in versions_sorted:
                dependents = get_dependents_for_version(upstream_package, version)
                
                # 检查是否连续无依赖
                if no_dependents_count_skip > 0:
                    if len(dependents.get('direct', [])) == 0 and len(dependents.get('indirect', [])) == 0:
                        no_dependents_count += 1
                        if no_dependents_count >= no_dependents_count_skip:
                            logger.debug(f"连续{no_dependents_count}个版本无依赖项，跳过剩余版本")
                            break
                        else:
                            logger.debug(f"连续{no_dependents_count}/{no_dependents_count_skip}个版本无依赖项")
                        continue
                    else:
                        no_dependents_count = 0
                
                if upstream_package not in all_dependents:
                    all_dependents[upstream_package] = {}
                all_dependents[upstream_package][version] = dependents
        
        # 保存结果
        with open(dependents_file, 'w') as f:
            json.dump(all_dependents, f)
    
    # 统计dependents数量
    total_direct = 0
    total_indirect = 0
    for package in all_dependents:
        for version in all_dependents[package]:
            total_direct += len(all_dependents[package][version].get('direct', []))
            total_indirect += len(all_dependents[package][version].get('indirect', []))
    
    logger.info(f"Total direct dependents: {total_direct}, Total indirect dependents: {total_indirect}")
    return all_dependents, total_direct, total_indirect


def parse_dependency_graph(package_name, version, rewrite=False):
    """解析依赖图数据(通过API方式)"""
    graph_data = {
        'nodes': {},
        'edges': []
    }
    file_path = DEP_DIR_DATE / f"{package_name}_{version}.json"
    
    if file_path.exists() and not rewrite:
        with open(file_path, 'r') as f:
            graph_data = json.load(f)
        logger.info(f"依赖图数据加载: {file_path}")
        return graph_data
    
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
            logger.error(f"获取dependency graph失败: {str(e)}")
            return []
    except Exception as e:
        logger.error(f"获取dependency graph失败: {str(e)}")
        return []
        
    # 解析节点
    nodes_map = {}
    for idx, node in enumerate(data['nodes']):
        pkg_name = node['versionKey']['name']
        pkg_version = node['versionKey']['version']
        pkg_system = node['versionKey']['system']
        node_name = f"{pkg_name} {pkg_version}"
        
        node_data = {
            'name': pkg_name,
            'version': pkg_version,
            'system': pkg_system,
        }
        graph_data['nodes'][node_name] = node_data
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


def get_direct_and_indirect_dependents(all_dependents, package, version):
    """获取直接和间接依赖"""
    direct = all_dependents.get(package, {}).get(version, {}).get('direct', [])
    indirect = all_dependents.get(package, {}).get(version, {}).get('indirect', [])
    return direct, indirect


def collect_dependency_graphs_for_dependents(upstream_package, upstream_version, dependents, cve_id=None):
    """为dependents收集dependency graphs"""
    dependency_graphs = {}
    
    for dependent in dependents:
        dependent_package = dependent['package']
        dependent_version = dependent['version']
        
        logger.info(f"正在获取 {dependent_package}=={dependent_version} 的依赖图...")
        
        try:
            # 获取dependent的dependency graph
            dep_graph = parse_dependency_graph(dependent_package, dependent_version)
            
            if dep_graph and len(dep_graph.get('nodes', {})) > 0:
                dependency_graphs[f"{dependent_package}@{dependent_version}"] = dep_graph
                logger.info(f"成功获取 {dependent_package}=={dependent_version} 的依赖图: "
                          f"节点数={len(dep_graph['nodes'])}, 边数={len(dep_graph['edges'])}")
            else:
                logger.warning(f"未能获取 {dependent_package}=={dependent_version} 的依赖图")
                
        except Exception as e:
            logger.error(f"获取 {dependent_package}=={dependent_version} 依赖图时发生错误: {str(e)}")
            continue
            
    return dependency_graphs


def process_upstream_version(upstream_package, upstream_version, all_dependents, cve_id=None):
    """处理单个upstream version，获取其dependents并收集dependency graphs"""
    logger.info(f"处理 {upstream_package}=={upstream_version}")
    
    # 获取直接和间接依赖
    direct, indirect = get_direct_and_indirect_dependents(all_dependents, upstream_package, upstream_version)
    print(direct, indirect )
    logger.info(f"{upstream_package}=={upstream_version} 有 {len(direct)} 个直接依赖和 {len(indirect)} 个间接依赖")
    
    if not direct and not indirect:
        logger.info(f"{upstream_package}=={upstream_version} 没有依赖，跳过")
        return {}
    
    # 合并直接和间接依赖
    all_dependents_list = direct + indirect
    
    # 去重（基于package和version的组合）
    unique_dependents = {}
    for dep in all_dependents_list:
        logger.debug(f"dep:{dep}")
        key = f"{dep['package']}@{dep['version']}"
        if key not in unique_dependents:
            unique_dependents[key] = dep
    
    unique_dependents_list = list(unique_dependents.values())
    logger.info(f"去重后共有 {len(unique_dependents_list)} 个依赖")
    
    # 收集这些dependents的dependency graphs
    # assert False
    dependency_graphs = collect_dependency_graphs_for_dependents(
        upstream_package, upstream_version, unique_dependents_list, cve_id
        )
    
    return {
        'upstream': {
            'package': upstream_package,
            'version': upstream_version
        },
        'dependents': {
            'direct_count': len(direct),
            'indirect_count': len(indirect),
            'total_unique_count': len(unique_dependents_list)
        },
        'dependency_graphs': dependency_graphs
    }


def main():
    """主函数"""
    global driver
    
    try:
        # 初始化driver
        # driver = init_driver()

        if sys.platform == 'darwin':
            driver = init_driver()
        else:
            logger.error("当前只支持macOS系统")
            # return
            
        cve2advisory = read_cve2advisory(cve_has_vf=True)
        
        for idx, (cve_id, advisory) in enumerate(cve2advisory.items()):
            # if cve_id not in ['CVE-2023-52323']:
            #     continue
            logger.info(f"处理 CVE:{cve_id} ({idx+1}/{len(cve2advisory)})")
            
            
            
            # 首先获取所有dependents
            all_dependents, total_direct, total_indirect = get_dependents_for_cve(cve_id, advisory)
            
            if total_direct == 0 and total_indirect == 0:
                logger.warning(f"{cve_id} has no dependents, skipping")
                continue
            
            logger.info(f"CVE {cve_id} 共有 {total_direct + total_indirect} 个dependents")
            
            cve_results = {}
            
            # 遍历所有受影响的版本
            for upstream_package,infos in advisory['available_affected'].items():
                versions = infos['versions']
                
                
                for upstream_version in versions:
                    
                    
                    # 处理这个upstream version
                    result = process_upstream_version(
                        upstream_package, upstream_version, all_dependents, cve_id
                    )
                    
                    if result:
                        key = f"{upstream_package}@{upstream_version}"
                        cve_results[key] = result
            
            # 保存结果
            # if cve_results:
            #     with output_file.open('w') as f:
            #         json.dump(cve_results, f, indent=2)
            #     logger.info(f"CVE {cve_id} 的依赖图metadata_info已保存到: {output_file}")
            # else:
            #     logger.warning(f"CVE {cve_id} 没有找到有效的依赖图metadata_info")

                
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
    finally:
        close_driver()


if __name__ == '__main__':
    main()