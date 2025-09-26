import pandas as pd
import sys

from pandas.core.arrays.categorical import factorize_from_iterables
from logger import logger
sys.path.append('../')
from collections import defaultdict, Counter
from urllib.parse import urlparse

import os
import glob
import json
from cvss import CVSS3
import matplotlib.pyplot as plt
import pickle
from tqdm import tqdm
from  data_collection.constant import *
from datetime import datetime
from data_collection.get_compatable_python_version import filter_versions
from my_utils import request_metadata_json_from_pypi

def data_transform(in_path, out_path):
    # transform all vulnerabilities into a single json file
    files = glob.iglob(in_path + "/*")
    result = list()
    for file in files:
        with open(file, 'r') as infile:
            result.append(json.load(infile))
    with open(out_path, 'w') as output_file:
        json.dump(result, output_file, indent=4)


def download_osv_database(output_file):
    # 从OSV获取所有漏洞
    os.system("curl https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip -o pypi.zip")  # 修改为PyPI的漏洞链接
    os.system("unzip pypi.zip -d pypi_vuls")  # 修改为PyPI的文件夹名称
    data_transform("./pypi_vuls", output_file)
    os.system("rm pypi.zip")
    # os.system("rm -r pypi_vuls")


def filter_unrelated_items(df):
    print('before filtering:', df.shape)
    # 按照时间过滤
    cutoff_date = datetime.strptime('2025-06-19', '%Y-%m-%d')
    df['published_date'] = df['published'].apply(lambda x: datetime.strptime(x.split('T')[0], '%Y-%m-%d'))
    df = df[df['published_date'] <= cutoff_date]
    print(f'after date filtering (before 2025-06-19):', df.shape)
    # 过滤掉malicious package
    print(f"mal-related records:{df[df['id'].str.startswith('MAL')].shape}")

    df = df[~df['id'].str.startswith('MAL')]
    print('after mal filtering:', df.shape)
    # 过滤掉不和CVE相关的item
    # 过滤掉来自pypa的，因为会出现在ga中
    df = df[df['id'].str.startswith('GHSA')]
    df = df[~((~df['id'].str.startswith('CVE')) & (df['aliases'].isna()))]
    print('only keep github advisory:', df.shape)
     # 过滤掉github_reviewed == True
    df = df[df['database_specific'].apply(lambda x: x.get('github_reviewed', False) == True)]
    print('only keep github_reviewed == True:', df.shape)

    # 过滤掉 withdrawn
    print("withdrawn_cnt:", df[df['withdrawn'].notna()].shape)
    df = df[df['withdrawn'].isna()]
    print('only keep no withdrawn advisory:', df.shape)

    

   


    print('after  filtering:', df.shape)

    return df

def select_by_package_name(df, package_name):
    ret_df = df[
        df.apply(lambda x: any(p['package']['name'].lower() == package_name.lower() for p in x['affected']), axis=1)]
    return ret_df

def get_available_affected_pkgs(affected_pkgs, filter=False):
    available_pkgs = {}
    for affected_pkg in affected_pkgs:
        pkg = affected_pkg['package']['name']
        versions = affected_pkg['versions']
        if filter:
            filtered_versions = filter_versions(pkg,versions, rewrite=False)

            if len(filtered_versions):
                available_pkgs[pkg] = filtered_versions
        else:
            available_pkgs[pkg] = versions

    return available_pkgs
def get_cve2advisory(df):

    # transform df to json
    json_data = df.to_json(orient='records')
    json_data = json.loads(json_data)
    with open('pkg2url.json', 'r') as f:
        pkg2url = json.load(f)
        pkg2url = {k.lower(): v for k, v in pkg2url.items()}
    PKG_URL_MAPPING = {
            'trytond': 'https://github.com/tryton/trytond',
            'tryton': 'https://github.com/tryton/trytond',
            'apache-superset': 'https://github.com/apache/superset',
            'web2py': 'https://github.com/web2py/web2py',
            'refuel-autolabel': 'https://github.com/refuel-ai/autolabel',
            'langflow': 'https://github.com/langflow-ai/langflow',
            'moin': 'https://github.com/moinwiki/moin',
            'swift': 'https://github.com/openstack/swift',
            'keystone': 'https://github.com/openstack/keystone',
            'glance': 'https://github.com/openstack/glance',
            'plone-app-event':'https://github.com/plone/plone.app.event',
            'plone-app-theming':'https://github.com/plone/plone.app.theming',
            'plone-app-dexterity':'https://github.com/plone/plone.app.dexterity',
            'plone-supermodel':'https://github.com/plone/plone.supermodel',
            'composio-claude':'https://github.com/ComposioHQ/composio',
            'composio-openai':'https://github.com/ComposioHQ/composio',
            'composio-julep':'https://github.com/ComposioHQ/composio',
            'mat2':'https://github.com/jvoisin/mat2',
            'products-cmfplone':'https://github.com/plone/plone.org/Products.CMFPlone',
            'proxy-py': 'https://github.com/abhinavsingh/proxy.py',
            'apache-libcloud': 'https://github.com/apache/libcloud',
            'llama-index-core': 'https://github.com/run-llama/llama_index',
            'leo': 'https://github.com/leo-editor/leo-editor',
            'puncia': 'https://github.com/ARPSyndicate/puncia',
            'llamafactory': 'https://github.com/hiyouga/LLaMA-Factory',
            'ironic': 'https://github.com/openstack/ironic',
            'mailman': 'https://github.com/terencehonles/mailman',
            'toui': 'https://github.com/mubarakalmehairbi/ToUI',
            'storlets': 'https://github.com/openstack/storlets',
            'langchain-experimental': 'https://github.com/langchain-ai/langchain-experimental',
            'trac':'https://github.com/edgewall/trac',
            'keystonemiddleware':'https://github.com/openstack/keystonemiddleware',
            'django-piston':'https://github.com/django-piston/django-piston',
            'blazar-dashboard':'https://github.com/openstack/blazar-dashboard',
            'm2crypto':'https://github.com/mcepl/M2Crypto',
            'duplicity':'https://github.com/henrysher/duplicity',
            'instack-undercloud':'https://github.com/openstack-archive/instack-undercloud',
            'elixir':'https://github.com/elixir-lang/elixir',
            'mayan-edms-ng':'https://github.com/mayan-edms/Mayan-EDMS',
            'plone-app-users':'https://github.com/plone/plone.app.users',
            'os-brick':'https://github.com/openstack/os-brick',
            'openpyxl':'https://github.com/soxhub/openpyxl',
            'products-atcontenttypes':'https://github.com/plone/Products.ATContentTypes',
            'manila-ui':'https://github.com/openstack/manila-ui',
            'vtk':'https://github.com/Kitware/VTK',
            'proteus':'https://github.com/erdc/proteus',
            'yaql':'https://github.com/openstack/yaql',
            'kolla':'https://github.com/openstack/kolla',
               
        }
    with open('pkg2url_additional.json', 'r') as f:
        pkg2url_additional = json.load(f)
        pkg2url_additional = {k.lower(): v for k, v in pkg2url_additional.items()}
        PKG_URL_MAPPING.update(pkg2url_additional)
        tmp = {'composio-claude':'https://github.com/ComposioHQ/composio',
            'composio-openai':'https://github.com/ComposioHQ/composio',
            'composio-julep':'https://github.com/ComposioHQ/composio',
            'pytorch-lightning':'https://github.com/Lightning-AI/pytorch-lightning'}
        PKG_URL_MAPPING.update(tmp)
        PKG_URL_MAPPING.update(pkg2url)
    all_cve_ids = set()
    # for item in tqdm(json_data):
    #     cve_ids_in_ad = item['cve_id']

    #     if len(cve_ids_in_ad) > 1:
    #         print(item['cve_id'], item['id'])

    #         # CVE-2021-32811
    #         # osv和nvd是保持一致的，但是snyk只保留了root？
    #         # github advisory是唯一的，例如GHSA-g4gq-j4p2-j8fr只对应CVE-2021-32811,GHSA-qcx9-j53g-ccgf只对应CVE-2021-32807
    #         # 从references里找信息 NVD的信息，以NVD为evidence
    #         nvd_urls = [ref['url'] for ref in item['references'] if
    #                     ref['url'].startswith('https://nvd.nist.gov')]
    #         cve_id_in_refs = [nvd_url.split('/')[-1] for nvd_url in nvd_urls]  
    #         cve_ids = list(set(cve_ids_in_ad) & set(cve_id_in_refs))
    #         if len(cve_ids) != 1:
    #             assert False, item['id']
    #         # print(cve_id_in_refs, cve_ids_in_ad)
    #         item['cve_id'] = cve_ids[0]

    #         continue
    #     else:
    #         item['cve_id'] = cve_ids_in_ad[0]
    #     cve_id = item['cve_id']
    
    no_cve_id_cnt = 0
    no_available_pkg_cnt = 0
    valid_cve_id_data = defaultdict(list)
    for item in tqdm(json_data):
        # ! 1.assign unique CVE ID for each advisory per NVD URl in refs
        cve_ids_in_ad = [alias for alias in item['aliases'] if alias.startswith('CVE')]

        if len(cve_ids_in_ad) == 1:
            item['cve_id'] = cve_ids_in_ad[0]
            valid_cve_id_data[cve_ids_in_ad[0]].append(item)
        elif len(cve_ids_in_ad) > 1:
            # CVE-2021-32811
            # osv和nvd是保持一致的，但是snyk只保留了root？
            # github advisory是唯一的，例如GHSA-g4gq-j4p2-j8fr只对应CVE-2021-32811,GHSA-qcx9-j53g-ccgf只对应CVE-2021-32807
            # 从references里找信息 NVD的信息，以NVD为evidence
            nvd_urls = [ref['url'] for ref in item['references'] if
                        ref['url'].startswith('https://nvd.nist.gov')]
            cve_id_in_refs = [nvd_url.split('/')[-1] for nvd_url in nvd_urls]  
            cve_ids = list(set(cve_ids_in_ad) & set(cve_id_in_refs))
            if len(cve_ids) > 1:
                assert False
            # print(cve_id_in_refs, cve_ids_in_ad)
            


        else:
            no_cve_id_cnt += 1
    more_than_one_cve = sum(len(ids)>1 for ids in valid_cve_id_data.values())
    logger.info(f"no_cve_id_cnt:{no_cve_id_cnt}, valid_cve_id_data:{len(valid_cve_id_data)}, original:{len(json_data)}, more_than_one_cve:{more_than_one_cve}")



    valid_pkg_cve_data = {}
    # !2. check the available packages
    for cve_id, items in tqdm(valid_cve_id_data.items()):
        # 和重复的advisory受影响的是一样的, keep the lasted
        item = [item for item in items if item['id'] not in ['GHSA-4ppp-gpcr-7qf6', 'GHSA-j8fq-86c5-5v2r']][0]
        item = item.copy()
        affected = item['affected']
        all_affected_pypi_packages = []
        # 一个cve和一个project相关，但是一个project可能有多个release，名称可能不同. e.g., tensorflow
        # 1. only kept the PyPI-related packages
        for affected_item in affected:
            package = affected_item['package']
            if package['ecosystem'] != 'PyPI':
                continue
            
            package_name = package['name'].lower()
            if package_name == 'fastbots':
                # assert False
                continue # Package 'fastbots' not found on PyPI.
            # 在文件顶部添加这个字典常量




            all_affected_pypi_packages.append(affected_item)
            
                # assert False
        def check_same_package(cve_id, all_affected_pypi_packages):
            all_packages = set()
            for package in all_affected_pypi_packages:
                # print(package)
                # print('-' * 100)

                all_packages.add(package['package']['purl'])
            all_packages = list(all_packages)

            def check_from_same_project(all_packages):
                keys = ['tensorflow', 'opencv', 'composio', 'kerberos', 'plone', 'dm-reverb', 'tryton']
                for key in keys:
                    if all([key in i for i in all_packages]):
                        return True
                return False

            if len(all_packages) > 1 and not check_from_same_project(all_packages):
                print('more than one affected packages', cve_id)

                if cve_id in ['CVE-2023-39631', 'CVE-2015-6938', 'CVE-2012-0878']:
                    return True
                # assert False, all_packages
            return False

        # print('='*100)
        project_urls, download_url = None, None
        # check_same_package(cve_id, all_affected_pypi_packages)
        # 一个漏洞在某一包中可能被重复引入，分支管理，major不同
        all_available_affected_pypi_packages = get_available_affected_pkgs(affected_pkgs = all_affected_pypi_packages, filter=True)
        item['available_affected'] = all_available_affected_pypi_packages

        if sum([len(versions) for versions in all_available_affected_pypi_packages.values()]) == 0:
            # print(items)
            # assert False
            no_available_pkg_cnt += 1
        else:
            valid_pkg_cve_data[cve_id]=item
    logger.info(f"no_available_pkg_cnt CVE:{no_available_pkg_cnt}, len(valid_pkg_cve_data):{len(valid_pkg_cve_data)} ")
    
    
    def count_pkgs(cve2advisory, step=1):
        all_pkgs = set()
        if step == 1:
            for cve_id, advisory in cve2advisory.items():
                for item in advisory[0]['affected']:
                    if item['package']['ecosystem'] != 'PyPI':
                        continue
                    pkg = item['package']['name']
                    versions = item['versions']
                    all_pkgs.update({f'{pkg}@{version}' for version in versions})

        elif step == 2:
            for cve_id, advisory in cve2advisory.items():
                for pkg,versions in advisory['available_affected'].items():
                    all_pkgs.update({f'{pkg}@{version}' for version in versions})
        elif step ==3:
            repo_count = set()
            for cve_id, advisory in cve2advisory.items():
                for pkg,infos in advisory['available_affected'].items():
                    versions = infos['versions']
                    all_pkgs.update({f'{pkg}@{version}' for version in versions})
                    repo_count.add(infos['repo_url'])

            logger.info(f"{len(all_pkgs)} pkgs, 总共来自{len(repo_count)}个repos")
        return len(all_pkgs)
    # ! 3. check the repository availability 
    more_than_one_repo=[]
    no_urls_from_metadata = []
    all_other_platform = {}
    if os.path.exists('./pkg2url_new.json'):
        with open('pkg2url_new.json', 'r') as f:
            PKG_URL_MAPPING.update(json.load(f))
    
    cve2advisory = {}
    valid_pkg_repo_data = set()

    for idxx, (cve_id, advisory) in tqdm(enumerate(valid_pkg_cve_data.items()), total=len(valid_pkg_cve_data)):
        advisory = advisory.copy()
        refs = advisory.get('references', [])
        assert refs != []
        github_urls = set()
        nlocs = []
        all_available_pkgs = defaultdict(dict)
        refs = [ ref['url'] for ref in refs]

        # logger.info(refs)
        if len(advisory['available_affected'])<2:
            continue
        if 'tensorflow' in advisory['available_affected'].keys():
            continue
        if 'langchain' not in advisory['available_affected'].keys():
            continue
        logger.debug(f"advisory['available_affected']:{advisory['available_affected'].keys()}")
        for package_name,versions in advisory['available_affected'].items():
            repo_url=None
            if package_name in PKG_URL_MAPPING and False:
                repo_url = PKG_URL_MAPPING[package_name]
            else:
                # mining repo_url with metadata
                response = request_metadata_json_from_pypi(package_name).json()
                logger.info(f'package:{package_name}')
                if 'info' in response:
                    info = response['info']
                    project_urls = info.get('project_urls', {})
                    homepage = info.get('home_page', '')
                    logger.debug(f'advisory: {advisory["id"]}')
                    all_possible_urls = [homepage] 
                    if project_urls:
                        if project_urls.get('Source'):
                            all_possible_urls.append(project_urls.get('Source'))
                        else:
                            all_possible_urls += list(project_urls.values())
                    # if refs:
                        # all_possible_urls += refs
                    # logger.info(f"{all_possible_urls}")
                    all_possible_urls = refs
                    # 查找所有github.com
                    all_other_urls = set([url for url in all_possible_urls if url and urlparse(url).netloc in ['bitbucket.com', 'gitlab.com']])
                    if len(all_other_urls):
                        all_other_platform[package_name] = all_other_urls

                    all_possible_urls = set([url for url in all_possible_urls if url and 'github.com' == urlparse(url).netloc])
                logger.debug(f'package: {package_name}')
                # all_possible_urls = refs
                if len(all_possible_urls):

                    def get_repository_from_url(url):
                        parsed_url = urlparse(url)
                        # 提取 path 部分，去掉开头的 '/'，然后按 '/' 分割
                        path_parts = parsed_url.path.strip('/').split('/')
                        
                        # 通常 GitHub URL 是这种格式 /username/repository
                        if path_parts[0] == 'sponsors':
                            return None
                        if len(path_parts) >= 2:
                            return ('https://github.com/'+ '/'.join(path_parts[0:2]) ).removesuffix('.git') # 返回 repository 部分
                        return None  # 如果格式不对，返回 None
                    repo_urls = set([i.lower() for i in [get_repository_from_url(url) for url in all_possible_urls] if i])
                    # logger.debug(f'all_possible_urls from pypi:{all_possible_urls}')
                    # logger.debug(f"get_repository_from_url  from pypi: {repo_urls}")
                    # logger.info(f"from advisory:{refs}")
                    assert len(repo_urls) <= 1, repo_urls
                    # assert len(repo_urls), repo_urls
                    if len(repo_urls):
                        repo_url = repo_urls.pop()
                        PKG_URL_MAPPING[package_name] = repo_url
                        print(f"add {package_name} to PKG_URL_MAPPING {PKG_URL_MAPPING[package_name]}")
                    else:
                        no_urls_from_metadata.append(package_name)
            if repo_url:    
                valid_pkg_repo_data.add(cve_id)
                all_available_pkgs[package_name]['repo_url'] = repo_url
                all_available_pkgs[package_name]['versions'] = versions
                advisory['available_affected'] = all_available_pkgs
                cve2advisory[cve_id] = advisory
            else:
                print(f"no possible url for {package_name}")
                no_urls_from_metadata.append(package_name)
    assert False
    with open('pkg2url_new.json', 'w') as f:
        json.dump(PKG_URL_MAPPING, f)
    
    logger.info(f'no_urls_from_metadata:{len(no_urls_from_metadata)}')
    # logger.info(f'no_urls_from_metadata:{no_urls_from_metadata}')
    logger.info(f'all_other_platform:{all_other_platform}')
    # 2025-08-20 20:28:12,961 - INFO - collect_vuls.py:401 - no_urls_from_metadata:['logilab-common', 'mltable', 'llama-index-cli', 'jw-util', 'upsonic', 'rhodecode', 'langroid', 'aodh', 'hyperkitty', 'products-passwordresettool', 'upsonic', 'langroid', 'pytorch', 'llama-index-retrievers-duckdb-retriever', 'langroid', 'skyvern', 'ladon', 'logilab-common', 'cloudtoken', 'postorius', 'aleksis-core', 'astrbot']

    # 打印各步骤过滤掉的信息
    # 1. pkg availability
    logger.info(f'before removing no available  pkgs: {count_pkgs(valid_cve_id_data)} {len(valid_cve_id_data)}')
    logger.info(f'after removing no available pkgs: {count_pkgs(valid_pkg_cve_data, step=2)} {len(valid_pkg_cve_data)}')
    # 2. repo availability
    logger.info(f'after removing no available pkg&repo pkgs: {count_pkgs(cve2advisory, step=3)}, {len(valid_pkg_repo_data)}')
    #     for ref in refs:
    #         url = ref
    #         parsed_url = urlparse(url)
    #         nloc = parsed_url.netloc
    #         if nloc == 'github.com':
    #             github_urls.add(url)

    #         else:
    #             # TODO: handle gitlab and bitbucket
    #             pass
    #         nlocs.append(nloc)
    #     logger.info(github_urls)
    #     logger.info(Counter(nlocs))
    #     assert False
    #     all_urls = [i for urls in extracted_urls.values() for i in urls]
    #     all_repos = set([i.split('/')[4] for i in all_urls])
    #     affected_pkgs = advisory['available_affected']
    #     if len(all_repos) > 1:
    #         other_repos = [repo for repo in all_repos if repo not in affected_pkgs]
    #         if len(other_repos):
    #             print(all_repos)
    #             print(affected_pkgs)
    #             print(cve_id, advisory['id'])
    #             more_than_one_repo.append((cve_id, all_repos))

    #     continue
    # print(more_than_one_repo)
    # print(len(more_than_one_repo))
    # assert False
    # for i in a[10:]:
    #     fixing_commit_file = COMMITS_DIR_DATE/f'{cve_id}.pkl'
    #     if not fixing_commit_file.parent.exists():
    #         fixing_commit_file.parent.mkdir(parents=True, exist_ok=True)
    #     if  fixing_commit_file.exists():
    #         print(f"Loading {fixing_commit_file}")
    #         with fixing_commit_file.open('rb') as f:
    #             all_fixing_commits = pickle.load(f)
    #         print(all_fixing_commits)
    #     else:
            
    #         all_unique_affected_packages = get_all_unique_affected_projects(advisory)
    #         all_fixing_commits = {}
    #         for package_name in all_unique_affected_packages:
    #             extracted_urls_for_repo = []
    #             repo_url = pkg2url.get(package_name.lower())
    #             if repo_url is None:
    #                 logger.warning(f'No repo url found for {package_name}')
    #                 continue
    #             repo_path = REPO_DIR / get_repo_name(repo_url)
    #             # 1. 从extracted_urls_for_package中找到所有的repo commit urls
                
    #             extracted_urls_for_repo = get_extracted_urls_for_repo(extracted_urls,repo_url)
                
    #             if sum( len(urls) for urls in extracted_urls_for_repo.values())==0:
    #                 logger.warning(f'No fixing commits found for {package_name}')
    #                 continue
    #             # 2. 分别进行fixing commit解析
                
    #             logger.info(f"Processing repo_url: {repo_url}")
    #             all_possible_urls = set(chain.from_iterable(extracted_urls_for_repo.values()))
    #             fixing_commits = extract_fixing_commits(all_possible_urls, repo_path, repo_url,advisory)
    #             # 3. 合并所有的fixing commits
    #             all_fixing_commits.update(fixing_commits)
    #         try:
    #             with fixing_commit_file.open('wb') as f:
    #                 pickle.dump(all_fixing_commits, f)
    #         except Exception as e:
    #             logger.error(f"Failed to save fixing commits for {cve} - {aid}")
    #             logger.error(e)
    #             print(all_fixing_commits)
    #             assert False

    # with open(merge_commit_file, 'w') as f:
    #     json.dump(merge_commits, f, indent=2)


           
    # # with open('pkg2url_additional.json', 'w') as f:
    # #             json.dump(PKG_URL_MAPPING, f)    
    # return valid_pkg_cve_data
    return cve2advisory


def fetch_vul_records_from_osv(vul_file):
    # File to store raw vulnerabilities
    if not os.path.exists(vul_file):
        download_osv_database(output_file = vul_file)
    df = pd.read_json(vul_file)
    df = filter_unrelated_items(df)

    if not CVE2ADVISORY_FILE_DATE.exists() or True:
        if not CVE2ADVISORY_FILE_DATE.parent.exists():
            CVE2ADVISORY_FILE_DATE.parent.mkdir(parents=True, exist_ok=True)
        cve2advisory = get_cve2advisory(df)
        
        with open(CVE2ADVISORY_FILE_DATE, "wb") as f:
            pickle.dump(cve2advisory, f)
    
    else:
        with CVE2ADVISORY_FILE_DATE.open("rb") as f:
            cve2advisory = pickle.load(f)


    logger.info(f'len(cve2advisory):{len(cve2advisory)}')
    assert len(cve2advisory) == len(set(cve2advisory.keys()))
    return cve2advisory

def evaluate_dataset_quality(cve2advisory):
    # !. 统计top N
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
    # df = pd.read_csv('/Users/keviny/Downloads/OWASP_TOP10_CWEs.csv',index_col=False)
    # cwes_set = set(['CWE-'+str(i) for i in df.iloc[:,0].tolist()])

    
    
    # 只保留value
    owasp_top_10_2021 = set([item for sublist in owasp_top_10_2021.values() for item in sublist])
    # 2.https://cwe.mitre.org/top25/
    cwe_top_25_ids = set(
        ["CWE-79", "CWE-787", "CWE-89", "CWE-352", "CWE-22", "CWE-125", "CWE-78", 
        "CWE-416", "CWE-862", "CWE-434", "CWE-94", "CWE-20", "CWE-77", "CWE-287", 
        "CWE-269", "CWE-502", "CWE-200", "CWE-863", "CWE-918", "CWE-119", "CWE-476", 
        "CWE-798", "CWE-190", "CWE-400", "CWE-306"]
    )
    # print("第一列数据：")
    # print(len(cwe_top_25_ids), len(owasp_top_10_2021))
    # print(owasp_top_10_2021-cwes_set)
    # assert False

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
    logger.info(f'cwe top25 advisories count:{len(cwe_top25_advisories)}')
    logger.info(f'owsap top10 advisories count:{len(owsap_top10_advisories)}')
    # 2. 统计severity
    #统计保留和被过滤掉的serverity分布
   
    cve_severity = [s['database_specific']['severity'] for cve_id, s in cve2advisory.items()]
    owsap_cve_severity = [s['database_specific']['severity'] for cve_id, s in cve2advisory.items() if cve_id in owsap_top10_advisories]
    cwe_cve_severity = [s['database_specific']['severity'] for cve_id, s in cve2advisory.items() if cve_id in cwe_top25_advisories]
    def cal_percentage(data):
        categories = set(data)
        percentage = {}
        for category in categories:
            percentage[category] = round(data.count(category)*100 / len(data), 2)
        return percentage
    logger.info(f'valid_cves_severity: {cal_percentage(cve_severity)}')
    categories = set(cve_severity)
    percentage = {}
    for category in categories:
        percentage[category] = round(cve_severity.count(category))
    print(percentage)
    logger.info(f'valid_owsap_cve_severity: {cal_percentage(owsap_cve_severity)}')
    logger.info(f'valid_cwe_cve_severity: {cal_percentage(cwe_cve_severity)}')

if __name__ == '__main__':

    # 从OSV获取所有漏洞
    vul_file = f"./pypi_vuls_{datetime.now().strftime('%Y%m')}.json"

    cve2advisory = fetch_vul_records_from_osv(vul_file=vul_file)

    evaluate_dataset_quality(cve2advisory=cve2advisory)
    assert False
    vul_path = "pypi_vuls.json"  # 修改为PyPI漏洞的JSON文件路径
    if not os.path.exists(vul_path):
        get_osv_database(vul_path)
    df = pd.read_json(vul_path)
    df = filter_unrelated_items(df)


    assert False
    if not CVE2ADVISORY_FILE.exists() or True:
        cve2advisory = get_cve2advisory(df)
        # assert False
        with open(CVE2ADVISORY_FILE, "wb") as f:
            pickle.dump(cve2advisory, f)

    else:
        with CVE2ADVISORY_FILE.open("rb") as f:
            cve2advisory = pickle.load(f)

    print(len(cve2advisory))
    assert len(cve2advisory) == len(set(cve2advisory.keys()))


    def get_affected_packages(advisory):
        all_packages = set()
        all_urls = set()
        for package in advisory['affected']:
            # print(package)
            # print('-' * 100)
            # print(package)

            all_packages.add(package['package']['purl'])
            all_urls.add(package['repo_url'])
        all_packages = list(all_packages)
        all_urls = list(all_urls)
        return all_packages, all_urls


    counts = []
    package2cves =defaultdict(list)

    for cve, advisory in p.items():
        # print(advisory)
        affected_packages_purls,affected_packages_urls = get_affected_packages(advisory)
        # print(affected_packages_purls)
        for purl in affected_packages_urls:
            package2cves[purl].append(cve)
        counts.append(len(affected_packages_purls))
    counts = {package: len(cves)  for package, cves in package2cves.items()}
    # print(counts['pkg:pypi/torch']) #和synk比是对的，但是有的是没有CVE的哦

    print(counts)
    # visualize_package_cves(counts, top_n=100, chart_type='barh')
    # visualize_package_cves(counts, top_n=50, chart_type='bar', color='salmon')
    # visualize_package_cves(counts, top_n=15, chart_type='pie', title='Top 5 Packages by CVE Count')
    # assert False
    # plt.show()

    # TODO: 实现查找vulnerable functions的功能
    # 从github advisory中提取修复提交
    # 分析修复提交中的漏洞函数
    # 输出每个CVE的root vulnerable functions
    



