import re
from logger import logger
from constant import REF_DIR
import json
import subprocess
import os
import re
from pathlib import Path

def is_private_method(method):
    """判断方法是否为私有方法
    
    参数:
        method (str): 方法名称或签名
        
    返回:
        bool: 如果是私有方法返回True，否则返回False
    """
    if not isinstance(method, str):
        return False
        
    if not method:
        return False
        
    # 判断标准:
    # 1. 以单个下划线开头 (_method)
    # 2. 以双下划线开头 (__method)
    # 3. 不以双下划线结尾 (避免误判魔术方法)
    return (method.startswith('_') and 
            not method.startswith('__') or 
            (method.startswith('__') and method.endswith('__')))
def is_space_change(method_before, method_after):
    """判断两个方法是否有空格变化"""
    # 移除单行和多行注释
    def remove_comments(code):
        # 移除单行注释
        code = re.sub(r'#.*$', '', code, flags=re.MULTILINE)
        # 移除多行注释
        code = re.sub(r'""".*?"""', '', code, flags=re.DOTALL)
        code = re.sub(r"'''.*?'''", '', code, flags=re.DOTALL)
        return code
    
    # 移除注释和所有空白字符
    method_before = remove_comments(method_before)
    method_before = ''.join(method_before.split())
    
    method_after = remove_comments(method_after)
    method_after = ''.join(method_after.split())
    
    return method_before == method_after

def get_ref_methods(repo_path, commit_hash):
    """获取指定commit的重构方法"""
    # 展开~符号为绝对路径
    repo_path = os.path.expanduser(repo_path)
    pyref = os.path.expanduser("~/Gitclone/PyRef")
    
    # 确保输出目录存在
    output_dir = Path(repo_path) / "changes"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    output_file = output_dir / f"{commit_hash}_data.json"

    
    try:
        if not output_file.exists():
            cmd = f"conda run -n test_module python {pyref}/main.py getrefs -r {repo_path} -c {commit_hash}"
            logger.info(f"获取重构方法: {cmd}")
            try:
                subprocess.run(cmd, shell=True, check=True, capture_output=True, timeout=30)  # 1分钟超时
            except subprocess.TimeoutExpired:
                logger.warning(f"命令执行超时(>0.5min): {cmd}")
                with open(output_file, 'w') as f:
                    json.dump([], f)
                return []
        # logger.debug(f"读取重构方法: {output_file}")
        with open(output_file, 'r') as f:
            ref_methods =  json.load(f)
        ref_method_ids = {}
        for ref_method in ref_methods:
            # ref_type = ref_method["Refactoring Type"]
            # print(ref_type)
            # if ref_type == 'Extract Method':
            #     # 不一定完全一样
            #     # 例如https://github.com/celery/django-celery-results/pull/316/files 增加了if condition
            #     line_no = ref_method['Original Method Line'].split(',')[0].lstrip('(')

            #     assert False
            # elif ref_type == 'Move Method':
            #     line_no = ref_method['Old Method Line']
            # else:
            #     line_no = ref_method['Original Line']
            # ref_method_id = ref_method['Location'].replace('.py','').replace('/','.')
            ref_method_id = ref_method['Original']
            ref_method_ids[ref_method_id] = ''
        return ref_method_ids
            
    except Exception as e:
        logger.error(f"获取重构方法时出错: {str(e)}, cmd:{cmd}")
        assert False
    return []


def get_ref_methods_for_all_fixing_commits(repo_path):
    """获取指定commit的重构方法"""
    # 展开~符号为绝对路径
    repo_path = os.path.expanduser(repo_path)
    pyref = os.path.expanduser("~/Gitclone/PyRef")
    
    # 确保输出目录存在
    output_dir = Path(repo_path) / "changes"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # output_file = output_dir / f"{commit_hash}_data.json"
    output_file = output_dir / f"all_specific_commits_data.json"
    
    
    try:
        if not output_file.exists():
            logger.error(f"不存在{output_file}，需要获取重构方法")
            # cmd = f"conda run -n test_module python {pyref}/main.py getrefs -r {repo_path} -c {commit_hash}"
            # subprocess.run(cmd, shell=True, check=True)
        logger.info(f"读取重构方法: {output_file}")
        with open(output_file, 'r') as f:
            return json.load(f)
            
    except Exception as e:
        logger.error(f"获取重构方法时出错: {str(e)}")
        assert False
    return []


# TODO：通过PyREF获取重构
def extract_ref_methods(repo_path, commits):
    """提取指定commit的重构方法"""
    # 展开~符号为绝对路径
    repo_path = os.path.expanduser(repo_path)
    pyref = os.path.expanduser("~/Gitclone/PyRef")
    
    # 确保输出目录存在
    output_dir = Path(repo_path) / "changes"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # 寻找未存在的output_file
    all_candidates = []
    for commit in commits:
        if isinstance(commit, str):
            commit_hash = commit.split('/')[-1]
        else:
            assert False
        output_file = output_dir / f"{commit_hash}.csv"
        if True or not output_file.exists():
            all_candidates.append(commit_hash)
            print(all_candidates)
    if len(all_candidates):
        try:
            cmd = f"conda run -n test_module python {pyref}/main.py getrefs -r {repo_path} -c {' '.join(all_candidates)}"
            subprocess.run(cmd, shell=True, check=True,capture_output=False)
            logger.info(f"成功获取重构方法: {output_file}")
        except Exception as e:
            logger.error(f"获取重构方法时出错: {str(e)}")

def is_ref_method(method, ref_methods_ids):
    """判断方法是否为重构方法

    参数:
        method (str): 方法名称或签名

    返回:
        bool: 如果是重构方法返回True，否则返回False
    """
    # 通过PyREF获取重构
    # logger.debug(commit_hash)
    # ref_methods = get_ref_methods(repo_path, commit_hash)
    method_id = method['name']
    return method_id in ref_methods_ids

    # return False
if __name__ == '__main__':
    ref_methods = get_ref_methods(repo_path="~/Desktop/Research/ANU/Projects/PyVul/data_collection/repos/toastdriven_django-tastypie", commit_hash="011e5577403740b6f6ee1c18d97e9dca251a9e58")
    print(ref_methods)
    