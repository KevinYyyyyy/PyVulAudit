import json
import pickle
from pathlib import Path
from data_collection.logger import logger
from data_collection.constant import *

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
import time
from packaging import version as pkg_version
from tqdm import tqdm
from data_collection.get_compatable_python_version import  filter_versions
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from data_collection.vul_analyze import read_cve2advisory
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.service import Service
import sys
from joblib import Parallel, delayed  # 添加joblib导入

# 在文件顶部添加重试策略
session = requests.Session()
retries = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[500, 502, 503, 504],
    allowed_methods=['GET']
)
session.mount('https://', HTTPAdapter(max_retries=retries))

def get_dependents_for_cve(cve_id, advisory, no_dependents_count_skip = -1,rewrite=False):
    logger.info(f"Processing CVE: {cve_id}, adivisory: {advisory['id']}")
    dependents_file = DEPENDENTS_DIR / f'{cve_id}.json'
    if dependents_file.exists() and not rewrite:
        with open(dependents_file, 'r') as f:
            all_dependents = json.load(f)
        
    else:
        all_dependents = {}
        for affected_version in advisory['affected']:
            no_dependents_count = 0

            package = affected_version['package']['name']
            versions = affected_version['versions']
            # 只保留在pypi中还可用的版本
            logger.debug(f"package: {package}, total {len(versions)} versions")
            a = len(versions)

            versions = filter_versions(package,versions) # TODO：https://deps.dev/advisory/osv/GHSA-g57v-2687-jx33
            # 按版本从新到旧排序
            # print()
            # if len(versions)<a:
            #     assert False
            # continue
            try:
                versions_sorted = sorted(versions, key=pkg_version.parse, reverse=True)
            except:
                versions_sorted = sorted(versions, reverse=True)
            
            logger.debug(f"package: {package}, total {len(versions)} available versions: {versions_sorted}")
            
            for version in versions_sorted:
                dependents = get_dependents_for_version(package, version)
                if no_dependents_count_skip > 0:
                    if  len(dependents.get('direct', []))==0 and len(dependents.get('indirect', [])) == 0:
                        no_dependents_count += 1
                        if no_dependents_count >= no_dependents_count_skip:
                            logger.debug(f"连续{no_dependents_count}个版本无依赖项，跳过剩余版本")
                            break
                        else:
                            logger.debug(f"连续{no_dependents_count}/{no_dependents_count_skip}个版本无依赖项")
                        continue
                    else:
                        no_dependents_count = 0
                
                if package not in all_dependents:
                    all_dependents[package] = {}
                all_dependents[package][version] = dependents
                # time.sleep(1)
        
        with open(dependents_file, 'w') as f:
            json.dump(all_dependents, f)
    
    # 统计所有direct和indirect的数量
    total_direct = 0
    total_indirect = 0
    for package in all_dependents:
        for version in all_dependents[package]:
            total_direct += len(all_dependents[package][version].get('direct', []))
            total_indirect += len(all_dependents[package][version].get('indirect', []))
    
    logger.info(f"Total direct dependents: {total_direct}, Total indirect dependents: {total_indirect}")
    pass
    return all_dependents, total_direct, total_indirect

# def get_dependents_from_osi(cve_id):
#     # 从OSI获取dependents
#     pass
def get_dependents_for_version(package, version,rewrite=False):
    # 从OSI获取dependents
    if len(version.split('.')) == 2:
        version = version + '.0'
    dependents_file = DEPENDENTS_DIR / package /f'{package}_{version}.json'
    if not dependents_file.parent.exists():
        dependents_file.parent.mkdir(parents=True, exist_ok=True)
    if dependents_file.exists() and not rewrite:
        with open(dependents_file, 'r') as f:
            dependents = json.load(f)
        if 'ERROR'  not in dependents['direct'] and 'ERROR' not in dependents['indirect'] and dependents:
            # logger.debug(f"Loaded cached dependents from {dependents_file}")
            return dependents
    if sys.platform == 'darwin':
        dependents = get_dependents_from_osi(package, version)
    else:
        assert False, "暂时不支持非macOS系统"
    with open(dependents_file, 'w') as f:
        json.dump(dependents, f)
    # logger.debug(dependents_file)
    return dependents

# 在文件顶部添加全局变量
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

# if sys.platform == 'darwin':
#     driver = init_driver()

def close_driver():
    global driver
    if driver is not None:
        driver.quit()
        driver = None
    
def get_dependents_num_from_osi(package, version):

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
    #404
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
    url = f"https://deps.dev/pypi/{package}/{version}/dependents"

    """使用Selenium从deps.dev获取依赖信息"""
    global driver
    max_retries = 3
    retry_count = 0
    ret = get_dependents_num_from_osi(package, version)
    if  ret == 0:
        logger.debug(f"deps.dev上没有找到{package}@{version}的依赖项")
        return {'direct': [], 'indirect': []}
    elif ret == -1:
        return {'direct': ['ERROR'], 'indirect': ['ERROR']}
    while retry_count < max_retries:
        try:
            # 检查driver是否有效
            # if driver is None or driver.session_id is None:
            #     logger.warning("Driver会话无效，重新初始化...")
            #     close_driver()
            #     driver = init_driver()
                
            logger.info(f"正在访问: {url} (尝试 {retry_count + 1}/{max_retries})")
            driver.get(url)
            
            # 使用更健壮的XPath定位方式
            WebDriverWait(driver, 20).until(
                EC.presence_of_element_located((By.XPATH, '//*[@id="root"]/div[1]/div/div/div/div'))
            )
            
            dependents = {}
            dependents['direct'] = []
            dependents['indirect'] = []
            rows = driver.find_elements(By.XPATH, '//*[@id="root"]/div[1]/div/div/div/div/table/tbody/tr')
            logger.info(f"找到 {len(rows)} 个依赖项")
            
            for row in rows[:]:
                try:
                    package, version, relation = row.text.split(' ')
                    if relation.lower() == 'direct':
                        dependents['direct'].append({
                            'package': package,
                            'version': version
                        })
                    else:
                        dependents['indirect'].append({
                            'package': package,
                           'version': version
                        })
                except Exception as e:
                    assert False
                    logger.warning(f"解析依赖项失败: {e}")
            
            return dependents
            
        except (TimeoutException, WebDriverException) as e:
            retry_count += 1
            logger.warning(f"页面加载失败: {str(e)}, 正在重试 ({retry_count}/{max_retries})")
            # if "invalid session id" in str(e):
            #     close_driver()
            #     driver = init_driver()
            time.sleep(2)
            continue
        except Exception as e:
            logger.error(f"发生错误: {str(e)}, ")
    return {'direct': ['ERROR'], 'indirect': ['ERROR']}





def process_single_cve(cve_id, advisory):
    """处理单个CVE的函数，用于并行执行"""
    try:
        # 得到所有的osi urls
        url_temp = f"https://deps.dev/advisory/osv/{advisory['id']}"
        # print(advisory)
        # get_dependents_num_from_osi(url_temp)
        # assert False
        #TODO： GHSA-x7q2-wr7g-xqmf GHSA-fp6p-5xvw-m74f
        #TODO： 和osi的统计相比多了好多好多
        # if cve_id != 'CVE-2023-52307':
        #     continue
        # if cve_id in filtered_cves:
        #     logger.warning(f"{cve_id} is filtered, skip")
        #     continue

        # if cve_id == 'CVE-2024-42474':
        #     skip=False
        # if skip:
        #     continue
        
        get_dependents_for_cve(cve_id, advisory, rewrite=True)
        return f"Successfully processed {cve_id}"
    except Exception as e:
        logger.error(f"Error processing {cve_id}: {str(e)}")
        # assert False
        return f"Failed to process {cve_id}: {str(e)}"

if __name__ == '__main__':
    driver = init_driver()
    cve2advisory = read_cve2advisory(valid_py_cve=False)
    
    # store available versions

    try:
        # 使用joblib并行处理
        # n_jobs=-1 表示使用所有可用的CPU核心，可以根据需要调整
        # backend='threading' 适合I/O密集型任务，如果是CPU密集型可以使用'multiprocessing'
        results = Parallel(n_jobs=4, backend='multiprocessing', verbose=1)(
            delayed(process_single_cve)(cve_id, advisory) 
            for cve_id, advisory in tqdm(cve2advisory.items(), desc="Processing CVEs")
        )
        
        # 打印处理结果
        for result in results:
            logger.info(result)
            
    finally:
        close_driver()  # 程序结束时关闭driver