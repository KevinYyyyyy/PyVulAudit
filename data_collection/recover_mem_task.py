import re
import os

# === 配置部分 ===
base_dir = "/home/kevin/PyVul/docker_workdir/pypi_packages"
log_file = "logs/collect_pkg_metadata.log"

# === 正则表达式匹配 package(name, version) 和 tried_py_versions ===
pattern = r"package \('(.*?)', '(.*?)'\) tried_py_versions:\[(.*?)\]"

# === 创建 base_dir（如果不存在） ===
# if not os.path.exists(base_dir):
#     os.makedirs(base_dir, exist_ok=True)

with open('./recover_mem.txt') as f:
    logs = f.readlines()
for line in logs:
    line=line.strip()
    # 过滤非目标日期的日志
    line = line.removeprefix('\x1b[94m').removesuffix('\x1b[0m')
    # print( line.startswith('2025-07-07') ,  line.startswith('2025-07-08'), line[:9])
    if not line.startswith('2025-07-07') and not line.startswith('2025-07-08'):
        continue


    # 确保是 collect_pkg_metadata.py:284 的日志
    if "collect_pkg_metadata.py:284" not in line:
        continue

    # 匹配包名、版本和 tried_py_versions
    # print(line)
    match = re.search(pattern, line)
    if not match:
        continue

    name = match.group(1)
    version = match.group(2)
    pyvers_str = match.group(3)

    # 处理 tried_py_versions（去除空格、引号，转为列表）
    try:
        pyvers_list = [v.strip().strip("'\"") for v in pyvers_str.split(",")]
    except Exception as e:
        print(f"Error parsing versions for {name}:{version}: {e}")
        continue
    print(name, version, pyvers_list)
    # 去重并排序
    unique_pyvers = sorted(set(pyvers_list))

    # 构造目标目录
    target_dir = os.path.join(base_dir, name, version)
    os.makedirs(target_dir, exist_ok=True)

    # 写入 TRIED_PY_VERSION 文件
    with open(os.path.join(target_dir, "TRIED_PY_VERSION"), "w", encoding="utf-8") as f_tried:
        f_tried.write("\n".join(unique_pyvers))

    # 获取最新版本（最后一个排序结果）
    latest_version = unique_pyvers[-1]

    # 写入 INSTALLED_PY_VERSION 文件
    with open(os.path.join(target_dir, "INSTALLED_PY_VERSION"), "w", encoding="utf-8") as f_installed:
        f_installed.write(latest_version)

    print(f"Generated files for {name}:{version} in {target_dir}")

print("✅ All package directories have been processed.")