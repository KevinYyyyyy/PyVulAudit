import requests
from pathlib import Path
import sys
sys.path.append(Path(__file__).parent.parent.as_posix())
from data_collection.vul_analyze import get_modified_files
from github_utils import get_commit_detail
from constant import exclude_dirs
from logger import logger
import re
def getModifiedLinesWithNumbers(Diff):
    lines = Diff.split('\n')
    print(lines)
    modifiedLinesAdd = {}
    modifiedLinesDel = {}

    startLocation = 0
    endLocation = 0
    lineOffset = 0
    for line in lines:
        if line.startswith('+++') or line.startswith('---'):
            continue
        # extract the modified item location
        if line.startswith('+'):
            continue
        if line.startswith('@@'):
            startLocation = int(re.findall(r'\@\@ -(\d+),\d+ \+\d+,+\d+ \@\@', line)[0])
            endLocation = startLocation + int(re.findall(r'\@\@ -\d+,(\d+) \+\d+,+\d+ \@\@', line)[0])
            lineOffset = 0
            continue

        # extract the modified code items
        if line.startswith('-'):
            currentLocation = startLocation + lineOffset
            # print(currentLocation)
            modifiedLinesDel[currentLocation] = line

        lineOffset += 1

    startLocation = 0
    endLocation = 0
    lineOffset = 0
    for line in lines:
        # extract the modified item location
        if line.startswith('+++') or line.startswith('---'):
            continue
        if line.startswith('-'):
            continue
        if line.startswith('@@'):
            startLocation = int(re.findall(r'\@\@ -\d+,\d+ \+(\d+),\d+ \@\@', line)[0])
            endLocation = startLocation + int(re.findall(r'\@\@ -\d+,\d+ \+\d+,(\d+) \@\@', line)[0])
            lineOffset = 0
            continue

        # extract the modified code items
        if line.startswith('+'):
            currentLocation = startLocation + lineOffset
            # print(currentLocation, line)
            modifiedLinesAdd[currentLocation] = line

        lineOffset += 1

    return modifiedLinesAdd, modifiedLinesDel

def filter_files(file_changes):
    """过滤文件列表，只保留.py文件且不包含测试/示例/文档目录的文件"""
    # 过滤掉新添加的文件 
    file_changes = [file for file in file_changes if file.status != 'added']
    
    # 过滤掉测试/示例/文档相关目录的文件
    # 不能简单的根据字符串匹配https://github.com/mapproxy/mapproxy/commit/420412aad45171e05752007a0a2350c03c28dfd8
    # 移除了文件名称，避免匹配demo.py
    filtered = [file for file in file_changes 
               if not any(f"{dir_}" in '/'.join(file.filename.split('/')[:-1]) or file.filename.startswith(f"{dir_}/") for dir_ in exclude_dirs)]
    # old_path = 'tensorflow/python/ops/bincount_ops_test.py'
    # 过滤掉仍然可能存在的test文件
    filtered = [file for file in filtered if 'test' not in file.filename]
    # https://github.com/bwoodsend/rockhopper/commit/1a15fad5e06ae693eb9b8908363d2c8ef455104e#diff-60f61ab7a8d1910d86d9fda2261620314edcae5894d5aaa236b821c7256badd7
    filtered = [file for file in filtered if 'setup.py' not in file.filename]
    logger.debug([file.filename for file in filtered])     

    # 在过滤掉一些非功能性文件后，再考虑.py和其他修改
    # 过滤掉非.py文件，并且非test.py文件
    filtered_py = [file for file in file_changes if file.filename.endswith('.py')]
    filtered = [file for file in file_changes if not file.filename.endswith('.py')]
    return filtered,filtered_py
def extract_modified_files(logger, repo_name,commit_hash):
    commit_detail = get_commit_detail(logger, repo_name,commit_hash)
    print(commit_detail.__dict__.keys())
    modified_files = commit_detail.files
    print(modified_files)
    modified_non_py_files, modified_py_files = filter_files(modified_files)
    return modified_non_py_files, modified_py_files
    

def extract_methods_changed(modified_non_py_files, modified_py_files):
    for file in modified_py_files:
        patch = file.patch
        status = file.status
        if status == 'added':
            continue
        print(file.__dict__)
        print('-----------------')
        modifiedLinesAdd, modifiedLinesDel = getModifiedLinesWithNumbers(patch)
        print(modifiedLinesAdd)
        print(modifiedLinesDel)
        print('-----------------')
        print()
        assert False
        

    return modified_files
    # ethods_changed_new = {
    #         y
    #         for x in added
    #         for y in new_methods
    #         if y.start_line <= x[0] <= y.end_line
    #     }
    #     methods_changed_old = {
    #         y
    #         for x in deleted
    #         for y in old_methods
    #         if y.start_line <= x[0] <= y.end_line
    #     }

    #     return list(methods_changed_new.union(methods_changed_old))
if __name__ == '__main__':
    repo_name = 'jaraco/zipp'
    commit_hash = 'fd604bd34f0343472521a36da1fbd22e793e14fd'
    modified_non_py_files, modified_py_files = extract_modified_files(None,repo_name,commit_hash)

    ret = extract_methods_changed(modified_non_py_files, modified_py_files)
