import requests
from collections import defaultdict
from packaging import version as py_version
# from bs4 import BeautifulSoup
from pathlib import Path
import json
import re


from data_collection.entities import Vulnerability


def get_modules_from_py_files(package, version,py_files_list):
    all_modules = set()
    modules = set([file.removesuffix('.py').replace('/','.') for file in py_files_list])
    all_modules.update(modules)
    for module in modules:
        if module.endswith('.__init__'):
            all_modules.add(module.removesuffix('.__init__'))
    return all_modules
# 按照key排序
def version_key(v_str):
    # 处理Pre-releases
    try:
        version_obj = py_version.Version(v_str)
        if 'a' in v_str or 'b' in v_str or 'rc' in v_str:
            return (0, version_obj)
        # elif len(version_obj.release) >= 2:
        #     major, minor = version_obj.release[0], version_obj.release[1]
        #     # 如果是Python 3.x版本
        #     if major == 3:
        #         # 3.10及以下版本：优先级高（数值小）
        #         if minor <= 10:
        #             return (1, -minor)  # 3.10=-10, 3.9=-9, 3.8=-8, 3.7=-7...
        #         # 3.11及以上版本：优先级低（数值大）
        #         else:
        #             return (2, minor)   # 3.13=13, 3.12=12, 3.11=11...
        else:
            return (1, version_obj)
    except py_version.InvalidVersion:
        # 无法解析的版本放在前面，按原顺序排序（用字符串本身作为辅助键）
        return (-1, v_str)
def extract_memory_size(error_log):
        # 使用正则表达式匹配"MemoryError detected"后面的内存大小
        pattern = r"MemoryError detected ([\d.]+(GMK)?)"
        match = re.search(pattern, error_log)
        if match:
            try:
                mem_size = int(match.group(1))
                return mem_size
            except ValueError:
                return None
        return None
def request_metadata_from_pypi(package_name):
    url = f"https://pypi.org/simple/{package_name}/"
    headers = {
    "Host": "pypi.org",
    "Accept": "application/vnd.pypi.simple.v1+json"
    }
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        print(f"Package '{package_name}' not found on PyPI. {url}")
        return {}
    return response


def request_metadata_json_from_pypi(package_name,package_version=None):
    if package_version is None:
        url = f"https://pypi.org/pypi/{package_name}/json"
    else:
        url = f"https://pypi.org/pypi/{package_name}/{package_version}/json"

    response = requests.get(url)

    return response

def request_dep_from_libio(package_name, package_version):
    url = f"https://libraries.io/api/PyPI/{package_name}/{package_version}/dependencies?api_key=4a8918e45095d8b39244c8aeb984c253"
    response = requests.get(url)
    if response.status_code != 200:
        print(f"Package '{package_name}' not found on libraries.io.")
        return {}
    return response


def request_dep_from_osi(package_name, package_version):
    url = f"https://api.deps.dev/v3/systems/pypi/packages/{package_name}/versions/{package_version}:dependencies"
    response = requests.get(url)
    if response.status_code != 200:
        print(f"Package '{package_name}' not found on OSI.")
        return {}
    return response

def get_repo_url(commit_url):
    # commit_url = "https://github.com/toastdriven/django-tastypie/commit/e8af315211b07c8f48f32a063233cc3f76dd5bc2"
    repo_url = commit_url.split('/commit')[0]
    return repo_url


def get_repo_name(repo_url):
    repo_name = '_'.join(repo_url.split('/')[-2:])
    return repo_name
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

#             package_version = "-".join(parts[1:-3])  # 包名+版本号
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

def filter_by_pythonversions(results, support_versions=['cp37', 'cp38', 'cp39', 'cp310', 'cp311', 'cp312']):
    """
    过滤 results 中的 Python 版本，只保留包含任意 support_versions 的条目，并且只保留 cp 开头的版本。

    参数:
        results (dict): 包版本及其支持的 Python 版本，格式为 {version: [python_versions]}。
        support_versions (list): 需要支持的 Python 版本列表，默认为 ['cp37', 'cp38', 'cp39', 'cp310', 'cp311', 'cp312']。

    返回:
        dict: 过滤后的结果，格式为 {version: [filtered_python_versions]}。
    """
    filtered_results = {}

    for version, python_versions in results.items():
        # 筛选出以 cp 开头的版本
        cp_versions = [pv for pv in python_versions if pv.startswith("cp")]

        # 检查是否有任意 support_versions 出现在 cp_versions 中
        if any(support_version in cp_versions for support_version in support_versions):
            # 保留符合条件的版本
            filtered_results[version] = list(set(cp_versions) & set(support_versions))
        # else:
        #     filtered_results[version] = []

    return filtered_results

# def get_affected_downstreams(vul:Vulnerability, filter=False, rewrite=False):
#     affected_versions = vul.affected_versions
#     package_name = vul.package_name
#     cve = vul.cve


#     osi_url_tmp = "https://deps.dev/pypi/{package_name}/{version}"
#     print('affected version:', len(affected_versions))

#     # 获取pypi还可获取的version
#     available_versions = get_python_versions_from_index(package_name)
#     # print("available_versions:", available_versions)
#     #
#     # 过滤较老的版本
#     if filter:
#         filtered_versions = filter_by_pythonversions(available_versions)
#         # print("available_versions (after filter):", filtered_versions)
#         filtered_affected_versions = [version for version in affected_versions if version in filtered_versions]
#     else:
#         filtered_affected_versions = affected_versions

#     # 生成osi的url，用八爪鱼去抓
#     # TODO：脚本的方式
#     # 从八爪鱼抓去的dependency数据
#     dep_data = Path(f'../data/case_study/{cve}.json')
#     if not dep_data.exists():
#         all_downstream_urls = []
#         for affected_version in filtered_affected_versions:
#             osi_url = osi_url_tmp.format(package_name=package_name, version=affected_version)
#             dependents_url = osi_url + '/dependents'
#             all_downstream_urls.append(dependents_url)
#         with dep_data.open('w') as f:
#             json.dump(all_downstream_urls, f)
#     else:
#         with dep_data.open('r') as f:
#             dep_data = json.load(f)

#     # 构建上下游关系
#     up2down = defaultdict(list)
#     edges = []
#     for item in dep_data:
#         up = item['UpStream'] + '@' + item['UpVersion']
#         down = (item['Package'] + '@' + item['Version'], item['Relation'])
#         up2down[up].append(down)
#         if item['Relation'] == 'Direct':
#             edges.append([item['UpStream'] + '@' + item['UpVersion'], item['Package'] + '@' + item['Version']])

#     for i in filtered_affected_versions:
#         tmp = package_name + '@' + i
#         if tmp not in up2down:
#             up2down[tmp] = []
#     return up2down

def normalize_package_name(package):
    return package.replace("-", ".").replace("_", ".")

def is_source_code_file(file_path, exclude_dirs):
    """判断是否为源码文件"""
    if not isinstance(file_path, Path):
        file_path = Path(file_path)
    path_parts = file_path.parts
    # 检查路径中的每个目录部分是否在排除列表中
    # /root/pyvul/neofs_testlib/shell/ssh_shell.py
    return not any(part.lower() in [d.lower() for d in exclude_dirs] for part in path_parts)

def get_url_priority(url):
    url = url.lower()
    if '/commit/' in url:
        return 0  # commit URL最高优先级
    elif '/pull/' in url or '/merge/' in url:
        return 1  # pull request次之
    elif '/issues/' in url:
        return 2  # issue最低优先级
    return 3  # 其他类型


if __name__ == '__main__':
    ret = is_source_code_file('/root/pyvul/neofs_testlib/reporter/interfaces.py', ['doc', 'docs', 'test', 'tests', 
                'testcase', 'testcases', 'testing', 'unittest',
                'build', 'dist',
                'example', 'examples','demo','demos','python2'])
    print(ret)



