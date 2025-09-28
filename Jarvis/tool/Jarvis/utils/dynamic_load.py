import sys
import importlib
import os
from collections import defaultdict
from pathlib import Path
def import_from_local_path(module_name, local_path):
    """
    从本地路径导入模块
    :param module_name: 模块名称
    :param local_path: 模块的本地路径
    :return: 导入的模块对象
    """
    # 将本地路径添加到 sys.path
    print(local_path)
    if local_path not in sys.path:
        sys.path.insert(0, local_path)

    # 导入模块
    print(sys.path)
    module = importlib.import_module(module_name)
    print(module)
    assert False

    # 从 sys.path 中移除本地路径（可选）
    # sys.path.remove(local_path)

    return module


def find_all_modules(directory,package):
    """
    查找指定目录下的所有 Python 模块和包，并返回模块名与文件路径的映射。

    :param directory: 要扫描的目录路径
    :return: 包含模块名和文件路径的字典
    """
    modules = {}
    directory = str(directory)

    for root, dirs, files in os.walk(directory +'/'+package):
        # 检查当前目录是否为包（包含 __init__.py）
        if "__init__.py" in files:
            package_name = root.replace(directory, "").strip("/").replace("/", ".")
            package_path = os.path.join(root, "__init__.py")
            modules[package_name] = package_path

        # 检查当前目录下的 .py 文件
        for file in files:
            if file.endswith(".py") and file != "__init__.py":
                module_name = file[:-3]  # 去掉 .py 后缀
                full_module_name = (
                    f"{root.replace(directory, '').strip('/').replace('/', '.')}.{module_name}"
                )
                module_path = os.path.join(root, file)
                modules[full_module_name] = module_path

    return modules

def load_all_modules():
    download_dir = Path(
        "/Users/keviny/Desktop/Research/ANU/Projects/PyVul/data_collection/downloads/numpy@1.8.1/sparselsh@1.1.3/sparselsh@1.1.3/")
    deps = ['numpy-1.8.1', 'scipy-0.14.0']
    all_dep_modules = {}
    for dep in deps:
        dep_dir = download_dir / dep
        package = dep.split("-")[0]
        modules = find_all_modules(dep_dir, package)
        all_dep_modules[package] = modules
    return all_dep_modules
def load_all_deps():
    download_dir = Path(
        "/Users/keviny/Desktop/Research/ANU/Projects/PyVul/data_collection/downloads/numpy@1.8.1/sparselsh@1.1.3/sparselsh@1.1.3/")
    deps = ['numpy-1.8.1', 'scipy-0.14.0']
    all_dep_dirs = {}
    for dep in deps:
        dep_dir = download_dir / dep

        all_dep_dirs[dep] = str(dep_dir)
    return all_dep_dirs
if __name__ == '__main__':
    download_dir = Path("/Users/keviny/Desktop/Research/ANU/Projects/PyVul/data_collection/downloads/numpy@1.8.1/sparselsh@1.1.3/sparselsh@1.1.3/")
    deps = ['numpy-1.8.1', 'scipy-0.14.0']
    all_dep_modules = {}
    for dep in deps[:1]:
        dep_dir = download_dir / dep
        package = dep.split("-")[0]
        modules = find_all_modules(dep_dir,package)
        print(modules)
        all_dep_modules[package] = modules
    print(all_dep_modules['scipy']['sparse'])
# 示例：从本地路径导入 numpy
# numpy_module = import_from_local_path("numpy", "/Users/keviny/Desktop/Research/ANU/Projects/PyVul/data_collection/downloads/numpy@1.8.1/sparselsh@1.1.3/sparselsh@1.1.3/numpy-1.8.1")
# print(numpy_module)
# print(numpy_module.__version__)  # 输出