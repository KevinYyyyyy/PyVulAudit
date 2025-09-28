import requests
from collections import defaultdict
from packaging import version as pversion
# from bs4 import BeautifulSoup
from data_collection.my_utils import request_metadata_from_pypi
from data_collection.logger import logger
import json
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from data_collection.constant import DATA_DIR
import pickle
# 在文件顶部添加重试策略
session = requests.Session()
retries = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[500, 502, 503, 504],
    allowed_methods=['GET']
)
session.mount('https://', HTTPAdapter(max_retries=retries))

def get_available_versions_from_osi(package_name):
    """
    获取指定包的所有可用版本。
    参数:
        package_name (str): 包名。
    返回:
        list: 所有可用版本的列表。
    """
    url = f"https://api.deps.dev/v3/systems/pypi/packages/{package_name}"
    try:
        response = session.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        versions = [version["versionKey"]['version'] for version in data["versions"]]
        return versions
    except requests.exceptions.SSLError:
        logger.warning("SSL验证失败，尝试不验证SSL证书...")
        response = session.get(url, verify=False, timeout=10)
        data = response.json()
        return [version["versionKey"]['version'] for version in data["versions"]]
    except Exception as e:
        logger.error(f"获取包版本失败: {str(e)}")
        return []
def filter_versions(package_name, versions,filter_file, rewrite=True):
    # 只保留在pypi中还可用的版本
    # 获取pypi还可获取的version
    if not isinstance(versions, list) and isinstance(versions, str):
        versions = [versions]
    if not filter_file.parent.exists():
        filter_file.parent.mkdir(parents=True, exist_ok=True)
    if filter_file.exists() and not rewrite:
        with open(filter_file, 'rb') as f:
            available_versions = pickle.load(f)
    else:
        try:
            available_versions = get_available_versions_from_osi(package_name)
            with open(filter_file, 'wb') as f:
                pickle.dump(available_versions, f)
        except:
            if filter_file.exists():
                with open(filter_file, 'rb') as f:
                    available_versions = pickle.load(f)
            pass

    filtered_affected_versions = [version for version in versions if version  in available_versions]
    return filtered_affected_versions
    
def get_python_versions(package_name):
    # 访问 PyPI JSON API
    url = f"https://pypi.org/pypi/{package_name}/json"
    response = requests.get(url)
    if response.status_code != 200:
        print(f"Package '{package_name}' not found on PyPI.")
        return {}

    data = response.json()

    # 提取所有 .whl 文件链接
    version_to_python_versions = defaultdict(set)  # 用 set 去重 Python 版本

    for version, release in data["releases"].items(): # releases: projects should shift to using the Index API to get this information, where possible.
        for file_info in release:
            if file_info["filename"].endswith(".whl"):
                python_version = file_info["python_version"]
                version_to_python_versions[version].add(python_version)

    # 将 set 转换为 list
    for version, python_versions in version_to_python_versions.items():
        version_to_python_versions[version] = sorted(list(python_versions))

    return version_to_python_versions


# def get_python_versions_from_index(package_name):
#     """
#     使用 PyPI Index API 获取包的所有 Python 版本信息。

#     参数:
#         package_name (str): 包名。

#     返回:
#         dict: {version: [python_versions]}，按版本号排序。
#     """
#     # 访问 Index API
#     response = request_metadata_from_pypi(package_name = package_name)

#     # 解析 HTML
#     soup = BeautifulSoup(response.text, "html.parser")
#     version_to_python_versions = {}

#     for link in soup.find_all("a"):
#         href = link.get("href", "")
#         filename = href.split("/")[-1].split('#')[0]  # 提取文件名


#         # 检查是否是 .whl 文件
#         if filename.endswith(".whl"):
#             # 解析文件名
#             parts = filename.split("-")
#             if len(parts) < 3:
#                 continue  # 跳过格式不正确的文件

#             package_version = "-".join(parts[:-3])  # 包名+版本号
#             python_version = parts[-3]  # Python 版本标签

#             # 添加到字典
#             if package_version not in version_to_python_versions:
#                 version_to_python_versions[package_version] = set()
#             version_to_python_versions[package_version].add(python_version)

#     # 将 set 转换为 list 并排序
#     for key in version_to_python_versions:
#         version_to_python_versions[key] = sorted(list(version_to_python_versions[key]))

#     # 按版本号排序
#     sorted_results = dict(sorted(
#         version_to_python_versions.items(),
#         key=lambda item: pversion.parse(item[0].split('-')[-1])  # 提取版本号并解析
#     ))

#     return sorted_results



# def filter_by_pythonversions(results, support_versions=['cp37', 'cp38', 'cp39', 'cp310', 'cp311', 'cp312', 'py3']):
#     """
#     过滤 results 中的 Python 版本，只保留包含任意 support_versions 的条目，并且只保留 cp 开头的版本。

#     参数:
#         results (dict): 包版本及其支持的 Python 版本，格式为 {version: [python_versions]}。
#         support_versions (list): 需要支持的 Python 版本列表，默认为 ['cp37', 'cp38', 'cp39', 'cp310', 'cp311', 'cp312']。

#     返回:
#         dict: 过滤后的结果，格式为 {version: [filtered_python_versions]}。
#     """
#     filtered_results = {}

#     for version, python_versions in results.items():
#         # 筛选出以 cp 开头的版本
#         cp_versions = [pv for pv in python_versions if pv.startswith("cp") or pv.startswith("py")]
#         logger.debug(f"cp_versions: {cp_versions}")

#         # 检查是否有任意 support_versions 出现在 cp_versions 中
#         if any(support_version in cp_versions for support_version in support_versions):
#             # 保留符合条件的版本
#             filtered_results[version] = list(set(cp_versions) & set(support_versions))
#         else:
#             filtered_results[version] = []

#     return filtered_results

if __name__ == '__main__':
    # 示例：获取并合并 numpy 的 Python 版本信息
    package_name = "numpy"
    result = get_python_versions_from_index(package_name)
    result = filter_pythonversions(result)
    # # 按版本号排序
    # sorted_filtered_results = dict(sorted(
    #     result.items(),
    #     key=lambda item: pversion.parse(item[0].split('-')[-1])  # 提取版本号并解析
    # ))
    print(f"Python versions supported by {package_name}:")
    for version, python_versions in result.items():
        print(f"{package_name}-{version}: {python_versions}")