import json
import pickle
from pathlib import Path
from logger import logger
from constant import SNYK_URLS_DIR
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
import time
from tqdm import tqdm
from collections import defaultdict
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib.parse import urlparse
from vul_analyze import read_cve2advisory,read_fixing_commits
from github_utils import find_potential_commits_from_github, is_commit_url
from my_utils import get_url_priority
from constant import SNYK_COMMITS_DIR
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.service import Service

service = Service(ChromeDriverManager().install())
# 添加重试策略
session = requests.Session()
retries = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[500, 502, 503, 504],
    allowed_methods=['GET']
)
session.mount('https://', HTTPAdapter(max_retries=retries))

def get_snyk_urls_for_cve(cve_id):
    """获取指定CVE的Snyk URLs"""
    logger.info(f"Processing CVE: {cve_id}")
    urls_file = SNYK_URLS_DIR / f'{cve_id}.json'
    
    if urls_file.exists() and False:
        with open(urls_file, 'r') as f:
            urls_data = json.load(f)
            logger.debug(f"Loaded cached URLs from {urls_file}")
            return urls_data
    
    urls_data = get_urls_from_snyk(cve_id)

    
    if len(urls_data['related_urls']) == 0:
        logger.warning(f"No related URLs found for CVE: {cve_id}")
        return urls_data
    # 确保目录存在
    if not urls_file.parent.exists():
        urls_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(urls_file, 'w') as f:
        json.dump(urls_data, f)
    
    return urls_data

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
            assert False
            driver = webdriver.Chrome(
                options=options
            )
            logger.info("ChromeDriver初始化成功")

            return driver
        except Exception as e:
            logger.error(f"ChromeDriver初始化失败: {str(e)}")
            try:
                
                from webdriver_manager.chrome import ChromeDriverManager
                service = Service(executable_path=ChromeDriverManager().install())
                driver = webdriver.Chrome(
                    service=service,
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

def get_urls_from_snyk(cve_id):
    """从Snyk获取URLs信息"""
    search_url = f"https://security.snyk.io/vuln/pip?search={cve_id}"
    urls_data = {
        'advisory_url': '',
        'related_urls': [],
        'not found':False
    }
    
    global driver
    max_retries = 3
    retry_count = 0
    
    while retry_count < max_retries and len(urls_data['related_urls'])==0:
        try:
            if driver is None or driver.session_id is None:
                logger.warning("Driver会话无效，重新初始化...")
                close_driver()
                driver = init_driver()
            
            # 首先访问搜索页面
            logger.info(f"正在访问搜索页面: {search_url} (尝试 {retry_count + 1}/{max_retries})")
            driver.get(search_url)
            
            # 检查是否有搜索结果
                    
            
            # 等待搜索结果加载
            WebDriverWait(driver, 10).until(
                EC.any_of(EC.presence_of_element_located((By.XPATH, "/html/body/div[1]/div[1]/div/div/div[2]/div[2]/div[2]/div/div/div/div/div/table/tbody")),
                EC.presence_of_element_located((By.XPATH, "/html/body/div[1]/div[1]/div/div/div[2]/div[2]/div[2]/div/div/section/header")))
            )
            # 检查是否是无结果页面
            no_results = driver.find_elements(By.XPATH, "/html/body/div[1]/div[1]/div/div/div[2]/div[2]/div[2]/div/div/section/header")
            if no_results and 'no results found' in no_results[0].text.lower():
                logger.warning(f"未找到CVE {cve_id}的搜索结果，可能不是pip的cve")
                
                urls_data['not found'] = True
                
                return urls_data
            # 获取第一个搜索结果并点击
            results = driver.find_elements(By.CSS_SELECTOR, "table tbody tr td a")
            results = [result for result in results if 'SNYK-PYTHON' in result.get_attribute('href')]
            # print('results:',results)

            results = list(results)
            for result in results[::-1]:
                url = result.get_attribute('href')
                advisory_url = url
                # print('url:',url)
                urls_data['advisory_url'] = advisory_url
                result.click()
            
            
                content_element = None
                # 遍历所有可能的位置查找References部分
                potential_locations = [
                    "/html/body/div[1]/div[1]/div/div/div[2]/div[2]/div[0]/div",
                    "/html/body/div[1]/div[1]/div/div/div[2]/div[2]/div[1]/div",
                    "/html/body/div[1]/div[1]/div/div/div[2]/div[2]/div[2]/div",
                    "/html/body/div[1]/div[1]/div/div/div[2]/div[2]/div[3]/div",
                    "/html/body/div[1]/div[1]/div/div/div[2]/div[2]/div[4]/div",
                    "/html/body/div[1]/div[1]/div/div/div[2]/div[2]/div[5]/div",
                    "/html/body/div[1]/div[1]/div/div/div[2]/div[2]/div[6]/div",
                    "/html/body/div[1]/div[1]/div/div/div[2]/div[2]/div[7]/div",
                    
                ]
                elements = driver.find_elements(By.XPATH, "/html/body/div[1]/div[1]/div/div/div[2]/div[2]/div")
                print(len(elements))
                for element in elements:
                    try:
                      
                        print('element:',element.text)
                        if "References" in element.text:
                            content_element = element
                            break
                    except:
                        continue
                print(content_element)
                for xpath in potential_locations:
                    try:
                        element = driver.find_element(By.XPATH, xpath)
                        # print('element:',element.text)
                        if "References" in element.text:
                            content_element = element
                            break
                    except:
                        continue
                
                if content_element is None:
                    logger.warning("未找到References部分")
                    assert False
                    return urls_data
                    
                # 获取链接
                links = content_element.find_elements(By.TAG_NAME, "a")
                    
                for link in links:
                    href = link.get_attribute('href')
                    if href:
                        urls_data['related_urls'].append(href)
                
                # 去重
                urls_data['related_urls'] = list(set(urls_data['related_urls']))
                    
                # 成功获取数据，跳出重试循环
                break
            
        except (TimeoutException, WebDriverException) as e:
            retry_count += 1
            logger.warning(f"页面加载失败: {str(e)}, 正在重试 ({retry_count}/{max_retries})")
            if "invalid session id" in str(e):
                close_driver()
                driver = init_driver()
            time.sleep(2)
            continue
        except Exception as e:
            logger.error(f"发生错误: {str(e)}")
            break
    print(urls_data)
    assert False
    return urls_data

def extract_all_possible_urls(snyk_refs):

    """
    从安全公告中提取所有可能的URL
    如果 commit_priority=True，则代表如果搜索到commit则不会继续搜索pull和issue，但会导致merge commit的问题
    """
    url_result = defaultdict(list)
    # 按URL内容关键词排序
    sorted_refs = sorted(snyk_refs, key=lambda x: get_url_priority(x))
    visited_pull_ids = []
    find_commit_url = False
    for ref in sorted_refs:
        # GHSA-cqhg-xjhh-p8hf 包含了snyk。会有很多commit，原因是这个pull是比较atomic commit的格式
        # 对于同时出现commit和pull的情况，认为commit为fixing commit，GHSA-hhpg-v63p-wp7w
        # 也不能简单的通过release后的版本进行，因为并不是所有的commit都是和该CVE有关

        # solution:
        # 1. 如果有commit直接出现在refs中，则认为这些即是fixing commit

        # 1. find commit URL
        url =ref

        logger.info(f'url: {ref}')
        parsed_url = urlparse(ref)
        nloc = parsed_url.netloc
        if nloc == 'github.com':
            source, commit_urls =  find_potential_commits_from_github(logger, url, visited_pull_ids)
            if source:
                url_result[source].extend(commit_urls)
        else:
            # if 'gitlab' in url or 'bitbucket' in url:
            #     # fixing_urls.append(url)
            #     # TODO: handle gitlab and bitbucket
            #     raise NotImplementedError("GitLab and Bitbucket URLs are not supported yet.")
            pass
            # logger.warning("url {} not supported".format(url))

    
    # 从snyk收集可能的urls
    # snyk_urls = get_snyk_urls(advisory)
    return url_result
if __name__ == '__main__':
    # urls = get_urls_from_snyk('CVE-2015-2687')
    # assert False
    # print(urls)

    # assert False
    # 读取CVE数据
    cve2advisory = read_cve2advisory()
    # 读取commits数据
    
    # 初始化driver
    driver = init_driver()
    rewrite_all_fixing_commits = True
    try:
        for cve_id in tqdm(cve2advisory.keys()):
            if cve_id !='CVE-2024-6961':
                continue
            fixing_commits = read_fixing_commits(cve_id)

            urls_data = get_snyk_urls_for_cve(cve_id)
            fixing_commits = extract_all_possible_urls(urls_data['related_urls'])
            print(fixing_commits)
            fixing_commit_file = SNYK_COMMITS_DIR/f'{cve_id}.pkl'
            if not fixing_commit_file.parent.exists():
                fixing_commit_file.parent.mkdir(parents=True, exist_ok=True)
            if not rewrite_all_fixing_commits and fixing_commit_file.exists():
                print(f"Loading {fixing_commit_file}")
                with fixing_commit_file.open('r') as f:
                    all_fixing_commits = json.load(f)
            else:
                all_fixing_commits = extract_all_possible_urls(urls_data['related_urls'])
                with fixing_commit_file.open('w') as f:
                    json.dump(all_fixing_commits, f)
            print(all_fixing_commits)
            # assert False
            logger.info(f"收集到的URLs for {cve_id}: "
                       f"Related: {len(urls_data['related_urls'])}")
    finally:
        close_driver()

