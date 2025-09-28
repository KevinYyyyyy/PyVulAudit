#!/bin/bash

# 定义基础目录
base_dir="/home/kevin/PyVul/docker_workdir/pypi_packages"

# 定义所有 packages 及其版本
packages=(
    "azureml-designer-core:0.0.68"
    "azureml-opendatasets:1.38.0"
    "azureml-opendatasets:1.34.0"
    "merlintf-mri:0.4.2"
    "ms2query:0.6.0"
    "osl-dynamics:1.0.0"
    "crystal4d:0.0.1"
    "monopolion-evaluator:0.1.0"
    "scrnatools:1.0.0"
    "phl-budget-data:0.1.0"
    "uquake:0.1.1"
    "evadb:0.1.0"
    "nvidia-modulus-sym:1.3.0"
    "pyjamas-rfglab:2023.3.1"
    "raiwidgets:0.9.4"
)

# 定义每个包支持的 Python 版本
declare -A package_pyversions=(
    ["azureml-designer-core"]="['3.10', '3.9', '3.8']"
    ["azureml-opendatasets"]="['3.8']"
    ["merlintf-mri"]="['3.8']"
    ["ms2query"]="['3.10', '3.9', '3.8']"
    ["osl-dynamics"]="['3.8']"
    ["crystal4d"]="['3.8']"
    ["monopolion-evaluator"]="['3.8']"
    ["scrnatools"]="['3.10', '3.9', '3.8']"
    ["phl-budget-data"]="['3.9', '3.8']"
    ["uquake"]="['3.8']"
    ["evadb"]="['3.8']"
    ["nvidia-modulus-sym"]="['3.11', '3.10', '3.9', '3.8']"
    ["pyjamas-rfglab"]="['3.8']"
    ["raiwidgets"]="['3.8']"
)

# 遍历所有 package
for pkg_version in "${packages[@]}"; do
    # 提取包名和版本
    pkg=$(echo "$pkg_version" | cut -d':' -f1)
    version=$(echo "$pkg_version" | cut -d':' -f2)

    # 构建目标目录
    target_dir="$base_dir/$pkg/$version"
    mkdir -p "$target_dir"

    # 获取当前包的 tried_py_versions
    versions="${package_pyversions[$pkg]}"
    if [ -z "$versions" ]; then
        echo "Warning: No tried_py_versions found for package '$pkg'. Skipping."
        continue
    fi

    # 去掉方括号和引号，转换为数组
    clean_versions=$(echo "$versions" | tr -d "[]" | tr -d "'")
    read -r -a pyvers <<< "$clean_versions"

    # 去重并排序
    unique_pyvers=($(printf "%s\n" "${pyvers[@]}" | sort -u))

    # 写入 TRIED_PY_VERSIONS 文件
    printf "%s\n" "${unique_pyvers[@]}" > "$target_dir/TRIED_PY_VERSION"

    # 获取最后一个版本（最新）
    last_version=$(printf "%s\n" "${unique_pyvers[@]}" | tail -n1)

    # 写入 INSTALLED_PY_VERSION 文件
    echo "$last_version" > "$target_dir/INSTALLED_PY_VERSION"
    

    echo "Generated files for $pkg:$version in $target_dir"
done

echo "✅ All package directories have been processed."
