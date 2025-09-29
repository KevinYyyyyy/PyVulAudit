import os
from pathlib import Path
import json
import time
import requests
import sys
import pickle
import argparse
from datetime import datetime
# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent.absolute()
sys.path.append(str(PROJECT_ROOT))
from data_collection.logger import logger
from src.constant import *
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


# Global session configuration
session = requests.Session()
retries = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[500, 502, 503, 504],
    allowed_methods=['GET']
)
session.mount('https://', HTTPAdapter(max_retries=retries))

# Global driver variable
driver = None

def init_driver():
    """初始化全局Selenium WebDriver"""
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
            
            service = Service(ChromeDriverManager().install())
            driver = webdriver.Chrome(service=service, options=options)
            return driver
            
        except Exception as e:
            raise
    return driver
def close_driver():
    """Close driver"""
    global driver
    if driver is not None:
        driver.quit()
        driver = None
        print("🔧 ChromeDriver closed")


def get_dependents_num_from_osi(package, version):
    """Get dependents count from deps.dev API"""
    url = f"https://api.deps.dev/v3alpha/systems/pypi/packages/{package}/versions/{version}:dependents"
    print(f"📊 Fetching dependents count for {package}@{version}")
    try:
        response = session.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        count = data['dependentCount']
        print(f"✅ Found {count} dependents for {package}@{version}")
        return count
    except requests.exceptions.SSLError:
        logger.warning("SSL verification failed, trying without SSL certificate verification...")
        print("⚠️ SSL verification failed, retrying without SSL verification...")
        response = session.get(url, verify=False, timeout=10)
        data = response.json()
        count = data['dependentCount']
        print(f"✅ Found {count} dependents for {package}@{version} (no SSL)")
        return count
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            logger.warning(f"No dependents found for {package}@{version} on deps.dev")
            print(f"⚠️ No dependents found for {package}@{version} on deps.dev")
            return 0
        else:
            logger.error(f"Failed to get dependents count: {str(e)}")
            print(f"❌ Failed to get dependents count: {str(e)}")
            return -1
    except Exception as e:
        logger.error(f"Failed to get dependents count: {str(e)}")
        print(f"❌ Failed to get dependents count: {str(e)}")
        return -1


def get_dependents_from_osi(package, version):
    """Use Selenium to get dependency information from deps.dev"""
    global driver
    
    url = f"https://deps.dev/pypi/{package}/{version}/dependents"
    max_retries = 3
    retry_count = 0
    
    print(f"🔍 Scraping dependents for {package}@{version} from deps.dev")
    
    # First check if there are dependents
    ret = get_dependents_num_from_osi(package, version)
    if ret == 0:
        logger.debug(f"No dependents found for {package}@{version} on deps.dev")
        print(f"ℹ️ No dependents found for {package}@{version}")
        return {'direct': [], 'indirect': []}
    elif ret == -1:
        print(f"❌ Error checking dependents count for {package}@{version}")
        return {'direct': ['ERROR'], 'indirect': ['ERROR']}
    
    while retry_count < max_retries:
        try:
            logger.info(f"Accessing: {url} (attempt {retry_count + 1}/{max_retries})")
            print(f"🌐 Accessing: {url} (attempt {retry_count + 1}/{max_retries})")
            if not driver:
                driver = init_driver()
            driver.get(url)
            
            # Wait for page to load
            WebDriverWait(driver, 20).until(
                EC.presence_of_element_located((By.XPATH, '//*[@id="root"]/div[1]/div/div/div/div'))
            )
            
            dependents = {'direct': [], 'indirect': []}
            rows = driver.find_elements(By.XPATH, '//*[@id="root"]/div[1]/div/div/div/div/table/tbody/tr')
            logger.info(f"Found {len(rows)} dependents")
            print(f"📋 Found {len(rows)} dependents on the page")
            
            for row in rows:
                try:
                    # 直接从各个td元素中提取数据
                    tds = row.find_elements(By.TAG_NAME, 'td')
                    
                    if len(tds) < 3:
                        print(f"⚠️ Skipping row with insufficient columns: {len(tds)} (expected 3)")
                        logger.warning(f"Skipping row with insufficient columns: {len(tds)}")
                        continue
                    
                    # 提取包名 - 从第一个td中的链接或直接文本
                    package_td = tds[0]
                    package_link = package_td.find_elements(By.TAG_NAME, 'a')
                    if package_link:
                        package_name = package_link[0].text.strip()
                    else:
                        package_name = package_td.text.strip()
                    
                    # 提取版本号 - 从第二个td
                    version_num = tds[1].text.strip()
                    
                    # 提取关系类型 - 从第三个td
                    relation = tds[2].text.strip()
                    
                    print(f"📦 Parsed: {package_name} {version_num} {relation}")
                    
                    # 验证提取的数据
                    if not package_name or not version_num or not relation:
                        print(f"⚠️ Skipping row with empty data: package='{package_name}', version='{version_num}', relation='{relation}'")
                        continue
                    
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
                    logger.warning(f"Failed to parse dependent row: {e}")
                    print(f"⚠️ Failed to parse dependent row: {e}")
                    # 打印行的HTML以便调试
                    try:
                        print(f"Row HTML: {row.get_attribute('outerHTML')}")
                    except:
                        print(f"Row text: {row.text}")
                    continue
            
            print(f"✅ Successfully scraped {len(dependents['direct'])} direct and {len(dependents['indirect'])} indirect dependents")
            return dependents
            
        except (TimeoutException, WebDriverException) as e:
            retry_count += 1
            logger.warning(f"Page loading failed: {str(e)}, retrying ({retry_count}/{max_retries})")
            print(f"⚠️ Page loading failed: {str(e)}, retrying ({retry_count}/{max_retries})")
            time.sleep(2)
            continue
        # except Exception as e:
        #     logger.error(f"Error occurred: {str(e)}")
            
    print(f"❌ Failed to scrape dependents after {max_retries} attempts")
    return {'direct': ['ERROR'], 'indirect': ['ERROR']}


def get_dependents_for_version(package, version, force_update=False):
    """Get dependents for specified package version"""
    if len(version.split('.')) == 2:
        version = version + '.0'
        
    dependents_file = DEPENDENTS_DIR_DATE / package / f'{package}_{version}.json'
    dependents_file.parent.mkdir(parents=True, exist_ok=True)
    
    print(f"📦 Processing dependents for {package}@{version}")
    
    # Check cache file
    if dependents_file.exists() and not force_update:
        print(f"📂 Loading cached dependents from {dependents_file}")
        with open(dependents_file, 'r') as f:
            dependents = json.load(f)
        if 'ERROR' not in dependents['direct'] and 'ERROR' not in dependents['indirect'] and dependents:
            print(f"✅ Loaded {len(dependents['direct'])} direct and {len(dependents['indirect'])} indirect dependents from cache")
            return dependents
    # Get dependents
    print(f"🔍 Fetching fresh dependents data for {package}@{version}")
    dependents = get_dependents_from_osi(package, version)

    # if sys.platform == 'darwin':
    #     dependents = get_dependents_from_osi(package, version)
    # else:
    #     logger.error("Currently only supports macOS system")
    #     return {'direct': ['ERROR'], 'indirect': ['ERROR']}
    
    # Save to cache
    print(f"💾 Saving dependents to cache: {dependents_file}")
    with open(dependents_file, 'w') as f:
        json.dump(dependents, f)
    
    return dependents


def get_dependents_for_cve(cve_id, advisory, no_dependents_count_skip=-1, force_update=False):
    """Get all dependents for CVE"""
    
    logger.info(f"Processing CVE: {cve_id}, advisory: {advisory['id']}")
    # print(f"🔍 Processing CVE: {cve_id}")
    
    # rewrite = cve_id == 'CVE-2025-32962'
    dependents_file = DEPENDENTS_DIR_DATE / f'{cve_id}.json'
    logger.info(f"dependents_file: {dependents_file}")
    # print(f"📁 Dependents file: {dependents_file}")
    
    if dependents_file.exists() and not force_update:
        # print(f"📂 Loading cached CVE dependents from {dependents_file}")
        with open(dependents_file, 'r') as f:
            all_dependents = json.load(f)
    else:
        dependents_file.parent.mkdir(parents=True,exist_ok=True)
        all_dependents = {}
        print(f"🔄 Collecting fresh dependents data for CVE {cve_id}")
        
        for upstream_package,infos in advisory['available_affected'].items():
            no_dependents_count = 0  # Initialize counter for each package
            versions = infos['versions']
            logger.debug(f"package: {upstream_package}, total {len(versions)} versions")
            print(f"📦 Processing package: {upstream_package} with {len(versions)} versions")
            
            # Sort by version
            try:
                versions_sorted = sorted(versions, key=pkg_version.parse, reverse=True)
            except:
                versions_sorted = sorted(versions, reverse=True)
            
            logger.debug(f"package: {upstream_package}, total {len(versions)} available versions: {versions_sorted}")
            print(f"📋 Sorted versions for {upstream_package}: {versions_sorted[:5]}{'...' if len(versions_sorted) > 5 else ''}")
            
            for version in versions_sorted:
                print(f"🔍 Processing {upstream_package}@{version}")
                dependents = get_dependents_for_version(upstream_package, version, force_update=force_update)
                
                # Check for consecutive no dependents
                if no_dependents_count_skip > 0:
                    if len(dependents.get('direct', [])) == 0 and len(dependents.get('indirect', [])) == 0:
                        no_dependents_count += 1
                        if no_dependents_count >= no_dependents_count_skip:
                            logger.debug(f"Consecutive {no_dependents_count} versions with no dependents, skipping remaining versions")
                            print(f"⏭️ Skipping remaining versions after {no_dependents_count} consecutive versions with no dependents")
                            break
                        else:
                            logger.debug(f"Consecutive {no_dependents_count}/{no_dependents_count_skip} versions with no dependents")
                            print(f"⚠️ {no_dependents_count}/{no_dependents_count_skip} consecutive versions with no dependents")
                        continue
                    else:
                        no_dependents_count = 0
                
                if upstream_package not in all_dependents:
                    all_dependents[upstream_package] = {}
                all_dependents[upstream_package][version] = dependents
                print(f"✅ Added {len(dependents.get('direct', []))} direct + {len(dependents.get('indirect', []))} indirect dependents for {upstream_package}@{version}")
        
        # Save results
        print(f"💾 Saving CVE dependents to {dependents_file}")
        with open(dependents_file, 'w') as f:
            json.dump(all_dependents, f)
    
    # Count dependents
    total_direct = 0
    total_indirect = 0
    for package in all_dependents:
        for version in all_dependents[package]:
            total_direct += len(all_dependents[package][version].get('direct', []))
            total_indirect += len(all_dependents[package][version].get('indirect', []))
    
    logger.info(f"Total direct dependents: {total_direct}, Total indirect dependents: {total_indirect}")
    return all_dependents, total_direct, total_indirect


def parse_dependency_graph(package_name, version, force_update=False):
    """Parse dependency graph data (via API method)"""
    graph_data = {
        'nodes': {},
        'edges': []
    }
    file_path = DEP_DIR_DATE / f"{package_name}_{version}.json"
    
    print(f"🔗 Parsing dependency graph for {package_name}@{version}")
    
    if file_path.exists() and not force_update:
        with open(file_path, 'r') as f:
            graph_data = json.load(f)
        logger.info(f"Dependency graph data loaded: {file_path}")
        print(f"📂 Loaded dependency graph from cache: {file_path}")
        return graph_data
    file_path.parent.mkdir(parents=True, exist_ok=True)
    
    url = f"https://api.deps.dev/v3alpha/systems/pypi/packages/{package_name}/versions/{version}:dependencies"
    
    try:
        logger.info(f"Fetching dependency data via API: {url}")
        print(f"🌐 Fetching dependency data from API: {url}")
        response = session.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.SSLError:
        logger.warning("SSL verification failed, trying without SSL certificate verification...")
        print("⚠️ SSL verification failed, retrying without SSL verification...")
        try:
            response = session.get(url, verify=False, timeout=10)
            response.raise_for_status()
            data = response.json()
        except Exception as e:
            logger.error(f"Failed to get dependency graph: {str(e)}")
            print(f"❌ Failed to get dependency graph: {str(e)}")
            return []
    except Exception as e:
        logger.error(f"Failed to get dependency graph: {str(e)}")
        print(f"❌ Failed to get dependency graph: {str(e)}")
        return []
        
    # Parse nodes
    print(f"📊 Parsing {len(data.get('nodes', []))} nodes and {len(data.get('edges', []))} edges")
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
        
    # Parse edge relationships
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
        
    # Save data
    with open(file_path, 'w') as f:
        json.dump(graph_data, f, indent=2)
    logger.info(f"Dependency graph data saved to: {file_path}")
    print(f"💾 Dependency graph saved to: {file_path}")
    
    return graph_data


def get_direct_and_indirect_dependents(all_dependents, package, version):
    """Get direct and indirect dependents"""
    direct = all_dependents.get(package, {}).get(version, {}).get('direct', [])
    indirect = all_dependents.get(package, {}).get(version, {}).get('indirect', [])
    return direct, indirect


def collect_dependency_graphs_for_dependents(upstream_package, upstream_version, dependents, cve_id=None):
    """Collect dependency graphs for dependents"""
    dependency_graphs = {}
    
    print(f"🔗 Collecting dependency graphs for {len(dependents)} dependents of {upstream_package}@{upstream_version}")
    
    for dependent in dependents:
        dependent_package = dependent['package']
        dependent_version = dependent['version']
        
        logger.info(f"Getting dependency graph for {dependent_package}=={dependent_version}...")
        print(f"📊 Getting dependency graph for {dependent_package}@{dependent_version}")
        
        try:
            # Get dependent's dependency graph
            dep_graph = parse_dependency_graph(dependent_package, dependent_version)
            
            if dep_graph and len(dep_graph.get('nodes', {})) > 0:
                dependency_graphs[f"{dependent_package}@{dependent_version}"] = dep_graph
                logger.info(f"Successfully got dependency graph for {dependent_package}=={dependent_version}: "
                          f"nodes={len(dep_graph['nodes'])}, edges={len(dep_graph['edges'])}")
                print(f"✅ Got dependency graph: {len(dep_graph['nodes'])} nodes, {len(dep_graph['edges'])} edges")
            else:
                logger.warning(f"Failed to get dependency graph for {dependent_package}=={dependent_version}")
                print(f"⚠️ Failed to get dependency graph for {dependent_package}@{dependent_version}")
                
        except Exception as e:
            logger.error(f"Error getting dependency graph for {dependent_package}=={dependent_version}: {str(e)}")
            print(f"❌ Error getting dependency graph for {dependent_package}@{dependent_version}: {str(e)}")
            continue
            
    print(f"✅ Collected {len(dependency_graphs)} dependency graphs")
    return dependency_graphs


def process_upstream_version(upstream_package, upstream_version, all_dependents, cve_id=None, collect_dependency_graph=False):
    """Process single upstream version, get its dependents and optionally collect dependency graphs"""
    logger.info(f"Processing {upstream_package}=={upstream_version}")
    # print(f"🔄 Processing upstream version {upstream_package}@{upstream_version}")
    
    # Get direct and indirect dependents
    direct, indirect = get_direct_and_indirect_dependents(all_dependents, upstream_package, upstream_version)
    logger.info(f"{upstream_package}=={upstream_version} has {len(direct)} direct dependents and {len(indirect)} indirect dependents")
    # print(f"📊 Found {len(direct)} direct + {len(indirect)} indirect dependents")
    
    if not direct and not indirect:
        logger.info(f"{upstream_package}=={upstream_version} has no dependents, skipping")
        # print(f"ℹ️ No dependents found, skipping {upstream_package}@{upstream_version}")
        return {}
    
    # Merge direct and indirect dependents
    all_dependents_list = direct + indirect
    
    # Deduplicate (based on package and version combination)
    unique_dependents = {}
    for dep in all_dependents_list:
        logger.debug(f"dep:{dep}")
        key = f"{dep['package']}@{dep['version']}"
        if key not in unique_dependents:
            unique_dependents[key] = dep
    
    unique_dependents_list = list(unique_dependents.values())
    logger.info(f"After deduplication: {len(unique_dependents_list)} dependents")
    # print(f"🔄 After deduplication: {len(unique_dependents_list)} unique dependents")
    
    # Collect dependency graphs for these dependents (only if enabled)
    dependency_graphs = {}
    if collect_dependency_graph:
        logger.info("Collecting dependency graphs for dependents...")
        print("📊 Collecting dependency graphs...")
        dependency_graphs = collect_dependency_graphs_for_dependents(
            upstream_package, upstream_version, unique_dependents_list, cve_id
        )
    else:
        logger.info("Dependency graph collection is disabled")
        # print("ℹ️ Dependency graph collection is disabled")
    
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

def create_snapshot(snapshot_dir,cve2advisory,snapshot_date=None,collect_dependency_graph=False):
    from src.create_snapshot import SnapshotCreator
    
    # 如果没有传递snapshot_date参数，使用当前日期
    if snapshot_date is None:
        snapshot_date = datetime.now().strftime('%m%d')
    
    creator = SnapshotCreator(snapshot_dir=snapshot_dir,snapshot_date='0927')
    vulnerable_packages = set()
    for cve_id,advisory in cve2advisory.items():
        available_affected = advisory.get('available_affected', {})
        for package_name, infos in available_affected.items():
            versions = infos['versions']
            for version in versions:
                vulnerable_packages.add((package_name, version))

    # 2. 对每个package获取版本信息
    for vulnerable_package in vulnerable_packages:
        success = creator.create_snapshot_for_pkg(
        vulnerable_package,collect_dependency_graph
        )
        print(f"Single snapshot creation: {success}")

    # 列出所有snapshots
    snapshots = creator.list_snapshots()
    print(f"Available snapshots: {len(snapshots)}")
def create_parser():
    """
    Create command line argument parser for dependents and dependency collection.
    """
    parser = argparse.ArgumentParser(
        description='Collect Dependents and Dependencies - Analyze package dependencies and dependents for vulnerability analysis',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python collect_dependents_and_dependency.py
  python collect_dependents_and_dependency.py --cve CVE-2023-24580 CVE-2020-13757
  python collect_dependents_and_dependency.py --package Django Flask
  python collect_dependents_and_dependency.py --cve CVE-2023-24580 --force-update
  python collect_dependents_and_dependency.py --no-dependents-count-skip 5
  python collect_dependents_and_dependency.py --cve CVE-2023-24580 --collect-dependency-graph
        """
    )
    
    parser.add_argument(
        '--cve',
        type=str,
        nargs='*',
        help='Specific CVE IDs to analyze (supports multiple CVEs)'
    )
    
    parser.add_argument(
        '--package',
        type=str,
        nargs='*',
        help='Specific package names to analyze (supports multiple packages)'
    )
    
    parser.add_argument(
        '--force-update',
        action='store_true',
        help='Force update of existing cached data'
    )
    
    parser.add_argument(
        '--no-dependents-count-skip',
        type=int,
        default=-1,
        help='Skip processing after N consecutive versions with no dependents (default: -1, no skip)'
    )
    
    parser.add_argument(
        '--output',
        type=str,
        help='Output directory for results (default: uses DATA_DIR/SUFFIX)'
    )
    
    parser.add_argument(
        '--collect-dependency-graph',
        action='store_true',
        help='Enable collection of dependency graphs for each dependent package'
    )
    
    return parser


def main():
    """Main function to collect dependents and dependencies"""
    parser = create_parser()
    args = parser.parse_args()
    
    print("🚀 Starting dependents and dependency collection")


    # Initialize WebDriver
    init_driver()
    
    # Initialize variables for finally block
    filtered_cve2advisory = {}
    output_dir = DATA_DIR / SUFFIX
    
    try:
        # Load CVE data
        print("📊 Loading CVE advisory data...")
        logger.info("Loading CVE advisory data")
        
        # Load cve2advisory from pickle file (same as install_pkg.py)
        cvf_output_file = output_dir / "cve2advisory_enhanced.pkl"
        with cvf_output_file.open('rb') as f:
            cve2advisory = pickle.load(f)
        
        if not cve2advisory:
            print("❌ Failed to load CVE advisory data")
            logger.error("Failed to load CVE advisory data")
            return
            
        print(f"✅ Successfully loaded {len(cve2advisory)} CVE records")
        logger.info(f"Loaded {len(cve2advisory)} CVE advisories")
        
        # Filter CVE data based on command line parameters
        filtered_cve2advisory = cve2advisory
        
        # Filter by specific CVEs if requested
        if args.cve:
            print(f"🔍 Filtering by specified CVEs: {args.cve}")
            logger.info(f"Filtering by specific CVEs: {args.cve}")
            filtered_cve2advisory = {
                cve: advisory for cve, advisory in cve2advisory.items()
                if cve in args.cve
            }
            if not filtered_cve2advisory:
                print(f"⚠️ Specified CVEs not found in {cvf_output_file} (need to first execute patch_parser.py for them): {args.cve}")
                logger.warning(f"None of the specified CVEs {args.cve} were found in the dataset")
                return
            print(f"✅ {len(filtered_cve2advisory)} CVEs remaining after filtering")
            logger.info(f"Filtered to {len(filtered_cve2advisory)} CVEs")
        
        # Filter by specific packages if requested
        if args.package:
            print(f"📦 Filtering by package names: {args.package}")
            logger.info(f"Filtering by packages: {args.package}")
            package_filtered_cves = {}
            for cve, advisory in filtered_cve2advisory.items():
                # Check if any affected package matches the requested packages
                affected_packages = advisory.get('affected', [])
                for affected in affected_packages:
                    package_name = affected.get('package', {}).get('name', '')
                    if any(pkg.lower() in package_name.lower() for pkg in args.package):
                        package_filtered_cves[cve] = advisory
                        break
            
            filtered_cve2advisory = package_filtered_cves
            if not filtered_cve2advisory:
                print(f"⚠️ No CVEs found for specified packages: {args.package}")
                logger.warning(f"No CVEs found for packages: {args.package}")
                return
            print(f"✅ {len(filtered_cve2advisory)} CVEs remaining after filtering")
            logger.info(f"Filtered to {len(filtered_cve2advisory)} CVEs for specified packages")
        
        # Process each CVE to collect dependents
        all_results = {}
        for idx, (cve_id, advisory) in enumerate(filtered_cve2advisory.items()):
            print(f"🔄 Processing CVE {cve_id} ({idx + 1}/{len(filtered_cve2advisory)})")
            logger.info(f"Processing CVE {cve_id} ({idx + 1}/{len(filtered_cve2advisory)})")
            
            # try:
                # Get dependents for this CVE
            ret = get_dependents_for_cve(
                cve_id=cve_id,
                advisory=advisory,
                no_dependents_count_skip=args.no_dependents_count_skip,
                force_update=getattr(args, 'force_update', False)
            )
            all_dependents, total_direct, total_indirect = ret
            
            if total_direct == 0 and total_indirect == 0:
                print(f"⚠️ CVE {cve_id} has no dependents, skipping")
                assert False
                logger.warning(f"{cve_id} has no dependents, skipping")
                continue
            
            all_results[cve_id] = {
                'dependents': all_dependents,
                'total_direct': total_direct,
                'total_indirect': total_indirect,
                'total': total_direct + total_indirect
            }
            print(f"📊 CVE {cve_id}: {total_direct} direct + {total_indirect} indirect = {total_direct + total_indirect} total dependents")

            # 遍历所有受影响的版本
            for upstream_package, infos in advisory['available_affected'].items():
                versions = infos['versions']
                for upstream_version in versions:
                    
      
                    # 处理这个upstream version
                    result = process_upstream_version(
                        upstream_package, upstream_version, all_dependents, cve_id, 
                        collect_dependency_graph=args.collect_dependency_graph
                    )
                    
                    if result:
                        key = f"{upstream_package}@{upstream_version}"
            
            # except Exception as e:
            #     print(f"❌ Error processing CVE {cve_id}: {str(e)}")
            #     logger.error(f"Error processing CVE {cve_id}: {str(e)}")
            #     continue
        if not all_results:
            print("⚠️ No dependents data found for any CVEs")
            return
            
        print(f"✅ Successfully processed {len(all_results)} CVEs with dependents")
        
        # Save results to output directory
        if args.output:
            output_dir = args.output
        else:
            output_dir = str(DATA_DIR / SUFFIX)
        
        os.makedirs(output_dir, exist_ok=True)
        
        output_file = os.path.join(output_dir, "cve_dependents_results.json")
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(all_results, f, indent=2, ensure_ascii=False)
        
        print(f"💾 Results saved to {output_file}")
        logger.info(f"Results saved to {output_file}")
        
    except Exception as e:
        print(f"❌ Error in main execution: {str(e)}")
        logger.error(f"Error in main execution: {str(e)}")
        raise
    finally:
        # Close WebDriver
        close_driver()
        
        # Create snapshots for processed CVEs
        if filtered_cve2advisory:
            if args.force_update:
                print("📸 Creating snapshots for processed CVEs...")
                snapshot_dir = Path(output_dir) / "snapshots"
                create_snapshot(snapshot_dir, filtered_cve2advisory, args.collect_dependency_graph)
                print("✅ Snapshots creation completed")
        
        print("🔚 WebDriver closed, execution completed")


if __name__ == '__main__':
    main()