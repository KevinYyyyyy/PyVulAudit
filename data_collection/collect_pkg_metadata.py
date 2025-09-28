import os
from pathlib import Path
import json
import time
import tempfile
import requests
import glob
import shutil
import re
import threading
import signal
import random
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
from logger import logger
from constant import *
from itertools import chain
from joblib import Parallel, delayed
import subprocess
from collect_dependents import get_dependents_from_osi
from get_compatable_python_version import filter_versions
from pip._internal.models.wheel import Wheel
import fcntl
import contextlib
from functools import partial

import pickle
import traceback
from my_utils import request_metadata_json_from_pypi,request_metadata_from_pypi, version_key,normalize_package_name,is_source_code_file
from collections import defaultdict
import docker
from packaging.version import parse
from packaging.specifiers import SpecifierSet
import gc
import sys
from vul_analyze import read_cve2advisory,get_dependents
from my_utils import get_repo_name,extract_memory_size
from collect_changes import get_all_unique_affected_projects
# from optimized_env_analyzer import OptimizedEnvAnalyzer


candidate_py_versions = ['3.10','3.9','3.8','3.7']

class  EnvAnalyzer(object):
    def __init__(self, workdir, py_version = '3.7', store_files = False,n_threads=10,max_mem_gb=16,only_py_list=False):
        self.workdir = workdir
        self.py_version = py_version
        self.store_files = store_files
        self.init_dockerfile()
        self.n_threads=n_threads
        # 动态分配内存
        if not max_mem_gb:
            total_mem_gb = 188 if sys.platform != "darwin" else 32
            mem_per_thread_gb = max(1, int(total_mem_gb / (self.n_threads+1)))
            # print(f"Total memory: {total_mem_gb} GB, memory per thread: {mem_per_thread_gb} GB")
        else:
            mem_per_thread_gb = int(max_mem_gb)
        self.mem_per_thread_gb = mem_per_thread_gb
            
        self.mem_per_thread_kb = mem_per_thread_gb * 1024 * 1024
        

        self.only_py_list=only_py_list


        self.image_tag = f"pyvul:py{self.py_version}"
        
        self.client = docker.from_env()
        
        logger.debug(f"Init EnvAnalyzer with py={self.py_version}.")
        self.client.images.build(path=os.path.join(self.workdir, 'metadata'), tag=self.image_tag, dockerfile="Dockerfile", forcerm=True,network_mode="host")
        logger.debug("Docker image built.")
        # # 初始化容器池
        # self.container_pool = ContainerPool(self.client, self.image_tag, pool_size=min(5, n_threads))


    def init_dockerfile(self):
        dockerfile_dir = os.path.join(self.workdir, "metadata")
        if not os.path.exists(dockerfile_dir):
            os.makedirs(dockerfile_dir)
        # jarvis_source = os.path.expanduser("~/Gitclone/Jarvis/tool/Jarvis_M")
        # jarvis_dest = os.path.join(dockerfile_dir, "Jarvis_M")
        # if os.path.exists(jarvis_source):
        #     if os.path.exists(jarvis_dest):
        #         shutil.rmtree(jarvis_dest)
        #     shutil.copytree(jarvis_source, jarvis_dest)
        with open(os.path.join(dockerfile_dir, "Dockerfile"), "w", encoding = "utf-8") as df:
            df.write('FROM python:{}\n'.format(self.py_version))
            # df.write('RUN pip install --no-cache-dir pipdeptree\n')
            # df.write('RUN pip install --no-cache-dir graphviz\n')
            # df.write('RUN pip install --no-cache-dir fawltydeps\n')
            # df.write('COPY Jarvis_M /jarvis\n') 
            # df.write('RUN cd /jarvis && python3.8 -m pip install -e .\n')
            # df.write('RUN sed -i \'s/jessie/buster/g\' /etc/apt/sources.list\n')
            # df.write('RUN apt update\n')
            # df.write('RUN apt install --force-yes -y jq\n')
    
    def close(self):
        try:
            self.client.containers.prune()
        except Exception as e:
            logger.error(f"Failed to prune containers: {str(e)}")
            # assert False
            # continue
        # self.client.images.remove(image=self.image_tag)
        self.client.close()

   


    def get_pkg_structure(self, args, rewrite=False):

        package, version = args
        package = package.strip()
        version = version.strip()
        package_dir = os.path.abspath(os.path.join(self.workdir, "pypi_packages_only_py_files", package, version))
        if not os.path.exists(package_dir):
            os.makedirs(package_dir,exist_ok=True)
        py_files_list_file = os.path.join(package_dir,'PY_FILES_LIST')
        if os.path.exists(py_files_list_file) and not rewrite:
            with open(py_files_list_file,'r') as f:
                py_files = [l.strip() for l in f.readlines()]
            if len(py_files):
                return

        # 如果之前尝试安装过，则检查是否需要重新安装
        tried_py_versions = []            
        tried_py_versions_file = os.path.join(package_dir, 'TRIED_PY_VERSION')
        if os.path.exists(tried_py_versions_file):
            with open(tried_py_versions_file,'r') as f:
                tried_py_versions = [l.strip() for l in f.readlines()]
            logger.debug(f"package {args} tried_py_versions:{tried_py_versions}")
            if self.py_version in tried_py_versions:
                logger.debug(f"Package {package} {version} has been attempted to be installed with a py version greater than {self.py_version}, but failed, skip")
                return
        logger.info(f'Getting package structure for {args}')
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_dir_path = Path(tmp_dir)
            tmp_package_dir = tmp_dir_path / "pypi_packages" / package / version

            self._get_pkg_structure(args,workdir=tmp_dir_path,ret_py_list=False,rewrite=rewrite)

            with open(os.path.join(tmp_package_dir, 'PY_FILES_LIST'), 'r') as f:
                py_files = [l.strip() for l in f.readlines()]
            if len(py_files):
                logger.info(f"Package {package} {version} has been installed successfully, py version:{self.py_version}")
                with open(py_files_list_file,'w') as f:
                    f.write('\n'.join(py_files))

                with open(os.path.join(package_dir,'INSTALLED_PY_VERSION'),'w') as f:
                    f.write(self.py_version)
                for file in ['ERROR', 'CHECK_LOG']:
                    if os.path.exists(os.path.join(package_dir,file)):
                        #remove the file
                        os.remove(os.path.join(package_dir,file))
            else:
                logger.warning(f"Package {package} {version} has been installed failed, skip")    
                for file in ['ERROR', 'CHECK_LOG']:
                    if os.path.exists(os.path.join(tmp_package_dir,file)):
                        shutil.copy(os.path.join(tmp_package_dir,file),package_dir)

                
            # 保存已经尝试过安装的py_version
            tried_py_versions_file = os.path.join(package_dir, 'TRIED_PY_VERSION')
            if self.py_version not in tried_py_versions:
                tried_py_versions.append(self.py_version)
                
            with open(tried_py_versions_file,'w') as f:
                f.write('\n'.join(tried_py_versions))

        return
            
                    
    def _get_pkg_structure(self, args, workdir=None, ret_py_list=False, rewrite=True):
        package, version = args
        package = package.strip()
        version = version.strip()
        if not workdir:
            workdir = self.workdir
        package_dir = os.path.abspath(os.path.join(workdir, "pypi_packages", package, version))

        package_name = normalize_package_name(package)
        container_workdir = "/root/pyvul"
        uid = os.getuid()
        gid = os.getgid()
        if not os.path.exists(os.path.join(workdir, "pypi_packages")):
            os.makedirs(os.path.join(workdir, "pypi_packages"),exist_ok=True)

        if not os.path.exists(package_dir):
            os.makedirs(package_dir,exist_ok=True)
        logger.info("Installing package with py {}: {} in {}".format(self.py_version,args,package_dir))
        mount = docker.types.Mount(
            target=container_workdir,
            source=package_dir,
            type="bind",
            read_only=False
        )
        # return
        timeout = 60*10
        buf_prefix = "stdbuf -i0 -o0 -e0"
        timeout_prefix = f"timeout {timeout}"
        pip_command0 = f"python -W ignore:DEPRECATION -m pip install  --target={container_workdir} --no-compile {package_name}=={version} --no-deps  --no-cache-dir --disable-pip-version-check" +( " -i https://pypi.tuna.tsinghua.edu.cn/simple" if sys.platform == "darwin" else ""
       )
        list_py_command = f"find {container_workdir} -mindepth 1 -type f -name '*.py' > {container_workdir}/PY_FILES_LIST"
        path_command = 'export PYTHONPATH=/root/envdep:$PYTHONPATH'
        commands = [
            f"{buf_prefix} {timeout_prefix} {pip_command0} || touch {container_workdir}/ERROR",
            f"{list_py_command}",
            f"chown -R {uid}:{gid} {container_workdir}"
        ]


        command = " && ".join(commands)
        # print(command.replace(container_workdir, package_dir))

        try:
            container = self.client.containers.run(
                image=self.image_tag,
                command=["/bin/bash", "-c", command],
                detach=True,
                network_mode="host",
                mounts=[mount],
            )
        except Exception as e:
            logger.error("Container running failed, reason1: {}".format(e))
            os.system('echo runningerror > {}/ERROR'.format(package_dir))
            exit_code = -1
            return package_dir, exit_code
        try:
            exit_code = container.wait(timeout = timeout + 100, condition = 'not-running')['StatusCode']
        except Exception as e:
            logger.warning('Container time out, killed.')
            try:
                if container.status == 'running':
                    container.kill()
            except Exception as e:
                os.system('echo timeout > {}/ERROR'.format(package_dir))
            exit_code = -1
        finally:
            try:
                log = container.logs(stdout = True, stderr = True).decode(encoding = 'utf-8', errors = 'ignore').strip()
                with open(os.path.join(package_dir, 'CHECK_LOG'), 'w', encoding = 'utf-8') as lf:
                    lf.write(log)
            except Exception as e:
                os.system('echo logerror > {}/ERROR'.format(package_dir))
                exit_code = -2
            try:
                container.remove(v=True, force = True)
            except Exception as e:
                os.system('echo rmerror > {}/ERROR'.format(package_dir))
                exit_code = -2

        gc.collect()
        
        return package_dir, exit_code


    
    def install_package(self, args, rewrite=False):
        package, version = args
        package = package.strip()
        version = version.strip()
        package_dir = os.path.abspath(os.path.join(self.workdir, "pypi_packages", package, version))
        jarvis_output_file = os.path.abspath(str(CALL_GRAPH_DIR /package/version/ f'jarvis_cg.json'))
        jarvis_output_dir = Path(jarvis_output_file).parent
        if not os.path.exists(package_dir):
            os.makedirs(package_dir,exist_ok=True)
        if check_installed(args, workdir=self.workdir) and not rewrite:
            logger.info(f"Package {package} {version} has been installed  successfully, skip")
            return

        tried_py_versions = []            
        tried_py_versions_file = os.path.join(package_dir, 'TRIED_PY_VERSION')
        if os.path.exists(tried_py_versions_file):
            with open(tried_py_versions_file,'r') as f:
                tried_py_versions = [l.strip() for l in f.readlines()]
            #过滤掉不是3.xx的lines
            tried_py_versions = [v for v in tried_py_versions if v.startswith('3.')]
            logger.debug(f"package {args} tried_py_versions:{tried_py_versions}")
        else:
            tried_py_versions_file_tmp = os.path.abspath(os.path.join(self.workdir, "pypi_packages_only_py_files", package, version, 'TRIED_PY_VERSION'))
            with open(tried_py_versions_file_tmp,'r') as f:
                tried_py_versions = [l.strip() for l in f.readlines()][:-1]

        success_install = self._install_package(args, workdir=self.workdir,rewrite=rewrite)
        if success_install:
            # get_cg(args, workdir=self.workdir,max_mem_gb=self.mem_per_thread_gb)
            pass
            # self._execute_jarvis(args, workdir=self.workdir,max_mem_gb=self.mem_per_thread_gb,rewrite=rewrite)
            # self._clean_up_package(args, workdir=self.workdir)
            

        # 保存已经尝试过安装的py_version
        tried_py_versions_file = os.path.join(package_dir, 'TRIED_PY_VERSION')
        if self.py_version not in tried_py_versions:
            tried_py_versions.append(self.py_version)
            
        with open(tried_py_versions_file,'w') as f:
            f.write('\n'.join(tried_py_versions))

        return

    def _install_package(self, args,workdir=None,rewrite=False):
        package, version = args
        package = package.strip()
        version = version.strip()
        args = (package, version)
        package_dir = os.path.abspath(os.path.join(workdir, "pypi_packages", package, version))

        package_name = normalize_package_name(package)
        container_workdir = "/root/pyvul"
        uid = os.getuid()
        gid = os.getgid()
        if not os.path.exists(os.path.join(workdir, "pypi_packages")):
            os.makedirs(os.path.join(workdir, "pypi_packages"),exist_ok=True)
        if not os.path.exists(package_dir):
            os.makedirs(package_dir,exist_ok=True)

        logger.info("Installing package with py {}: {} in {}".format(self.py_version,args,package_dir))
        mount = docker.types.Mount(
            target=container_workdir,
            source=package_dir,
            type="bind",
            read_only=False
        )

        timeout = 60*5
        buf_prefix = "stdbuf -i0 -o0 -e0"
        timeout_prefix = f"timeout {timeout}"

        # pip_command1 = f"python -W ignore:DEPRECATION -m pip install --no-compile {package_name}=={version} --disable-pip-version-check"
        pip_command2 = f"python -W ignore:DEPRECATION -m pip install --target={container_workdir} --no-compile {package_name}=={version} --no-cache-dir --disable-pip-version-check"  + ( " -i https://pypi.tuna.tsinghua.edu.cn/simple" if sys.platform == "darwin" else ""
       )

        commands = [
            f"rm -rf {container_workdir}/*",
            f"{buf_prefix} {timeout_prefix} {pip_command2}|| touch {container_workdir}/HAVEERROR",
            f"chown -R {uid}:{gid} {container_workdir}"
        ]

        command = " && ".join(commands)

        try:
            container = self.client.containers.run(
                image=self.image_tag,
                command=["/bin/bash", "-c", command],
                detach=True,
                network_mode="host",
                mounts=[mount]
            )
        except Exception as e:
            logger.error("Container running failed, reason1: {}".format(e))
            os.system('echo runningerror > {}/ERROR'.format(package_dir))
            exit_code = -1
            return 
    

        try:
            exit_code = container.wait(timeout = timeout + 100, condition = 'not-running')['StatusCode']
        except Exception as e:
            logger.warning('Container time out, killed.')
            try:
                if container.status == 'running':
                    container.kill()
            except Exception as e:
                os.system('echo timeout > {}/ERROR'.format(package_dir))
        finally:
            try:
                log = container.logs(stdout = True, stderr = True).decode(encoding = 'utf-8', errors = 'ignore').strip()
                with open(os.path.join(package_dir, 'CHECK_LOG'), 'w', encoding = 'utf-8') as lf:
                    lf.write(log)
            except Exception as e:
                os.system('echo logerror > {}/ERROR'.format(package_dir))

            try:
                container.remove(v=True, force = True)
            except Exception as e:
                os.system('echo rmerror > {}/ERROR'.format(package_dir))

        if len(os.listdir(package_dir)) <= 3:
            os.system(f"touch {package_dir}/HAVEERROR")
        gc.collect()
        if not os.path.exists(os.path.join(package_dir,'ERROR')) and not os.path.exists(os.path.join(package_dir,'HAVEERROR')):
            with open(os.path.join(package_dir,'INSTALLED_PY_VERSION'), 'w') as f:
                f.write(self.py_version)
            logger.debug(f'Package {package_dir} has been installed successfully')
            return True
        else:
            logger.debug(f'Package {package_dir} has been installed with errors')
            return False
      
        # logger.info('Excution finished. Exit Code: {},{}-{}'.format(exit_code,package,version))
    
    @staticmethod
    def find_project_py_files(package,version, workdir,container_workdir="/root/pyvul/", verbose=0):   
        package_dir = os.path.abspath(os.path.join(workdir, "pypi_packages_only_py_files", package, version))
        py_files_list_file = os.path.join(package_dir,'PY_FILES_LIST')
        # 递归获取所有Python文件
        if os.path.exists(py_files_list_file):
            with open(py_files_list_file,'r') as f:
                py_files_list = [f.strip() for f in f.readlines()]
        else:
            if verbose:
                logger.warning(f"Not found {py_files_list_file}")
            return []
        filtered_python_files = [file for file in py_files_list if file.endswith('.py') and is_source_code_file(file, exclude_dirs)]

        filtered_python_files = [file.replace(container_workdir, '') for file in filtered_python_files]
      
        # logger.debug(f"Found {len(filtered_python_files)} Python files in {package_dir}")
        
        return filtered_python_files

    def _execute_jarvis(self,args, workdir,max_mem_gb,rewrite=False):
        """执行Jarvis
        
        Args:
            batch_mode: 是否使用分批处理模式
            batch_n: 批数量
        """
        package, version = args
        package = package.strip()
        version = version.strip()
        jarvis_output_file = os.path.abspath(str(CALL_GRAPH_DIR /package/version/ f'jarvis_cg.json'))
        jarvis_output_dir = Path(jarvis_output_file).parent
        if not jarvis_output_dir.exists():
            jarvis_output_dir.mkdir(parents=True)

        if os.path.exists(os.path.join(str(jarvis_output_dir),'ERROR')) and not rewrite:
            logger.debug(f"{args} has ERROR file and not rewrite, skip")
            return

        if os.path.exists(jarvis_output_file) and not rewrite:
            return


        package_dir = os.path.join(workdir, "pypi_packages", package, version)
        py_files_list = self.find_project_py_files(package, version, workdir=workdir,verbose=1)
        
        if len(py_files_list) == 0:
            logger.warning(f"Not found any python files in {package_dir}/PY_FILES_LIST")
            logger.debug(f'jarvis_output_dir: {jarvis_output_dir}')
            os.system(f'echo Not found any python files > {jarvis_output_dir}/ERROR')
            return False
        elif len(py_files_list) > 500:
            os.system(f'echo Too Many python files {len(py_files_list)}> {jarvis_output_dir}/ERROR')
            return False 
        entry_files = ' '.join(py_files_list)
        logger.info(f"Executing jarvis for {args} with {len(py_files_list)} files")
        
        external_abs_path = os.path.abspath(package_dir)
        if sys.platform == 'darwin':
            jarvis_timeout = 60*5
            if not max_mem_gb:
                max_mem_gb = 8
            cmd = (
            f"timeout {jarvis_timeout} conda run -n jarvis jarvis-cli {entry_files} "
            f"--decy -o {jarvis_output_file} -ext {external_abs_path}"
            )
        else:
            jarvis_timeout = 60*20
            if not max_mem_gb:
                max_mem_gb = 32
            cmd = (
                f"ulimit -v {max_mem_gb*1024*1024} && "
                f"timeout {jarvis_timeout} conda run -n jarvis jarvis-cli {entry_files} "
                f"--decy -o {jarvis_output_file} -ext {external_abs_path}"
            )

        try:
            # os.chdir(package_dir)
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True, cwd=external_abs_path)
            
            if result.returncode != 0:
                if "memoryerror" in result.stderr.lower():
                    logger.error(f"MemoryError detected in jarvis_cli.py for {package} {version} with {self.mem_per_thread_gb}G: {result.stderr}")
                    with open(f'{jarvis_output_dir}/ERROR','w') as f:
                        f.write(f'MemoryError detected {self.mem_per_thread_gb}G: {result.stderr}')
                logger.error(f"Failed to run jarvis_cli.py for {package} {version}: {result.stderr}")
                with open(f'{jarvis_output_dir}/ERROR','w') as f:
                    f.write(f'Failed to run jarvis_cli.py {result.stderr}')
        except subprocess.TimeoutExpired as e:
            logger.error(f"Jarvis execution timed out after {e.timeout} seconds")
            with open(f'{jarvis_output_dir}/ERROR','w') as f:
                f.write(f'{package} {version} Timeout after {e.timeout}s: {str(e)}')
        except OSError as e:
            if 'Argument list too long' in str(e):
                logger.error(f"Argument list too long for {package} {version}")
            with open(f'{jarvis_output_dir}/ERROR','w') as f:
                f.write(f'{package} {version} OSError: {str(e)}')
  
        if not os.path.exists(jarvis_output_file):
            logger.info(f"Jarvis execution failed for {package} {version}")
            return False
        logger.info(f"Jarvis execution successfully finished for {package} {version}, stored in {jarvis_output_file}")
        return True



    def _merge_call_graphs(self, temp_outputs, final_output):
        """合并多个调用图文件"""
        merged_graph = {}
        
        for temp_file in temp_outputs:
            try:
                with open(temp_file, 'r') as f:
                    batch_graph = json.load(f)
                
                # 合并调用图
                for caller, callees in batch_graph.items():
                    if caller in merged_graph:
                        # 合并callees列表，去重
                        existing_callees = set(merged_graph[caller])
                        new_callees = set(callees)
                        merged_graph[caller] = list(existing_callees.union(new_callees))
                    else:
                        merged_graph[caller] = callees
                        
            except (json.JSONDecodeError, FileNotFoundError) as e:
                logger.warning(f"Failed to load call graph from {temp_file}: {e}")
                continue
        
        # 写入最终合并的调用图
        with open(final_output, 'w') as f:
            json.dump(merged_graph, f, indent=2)
        
        logger.info(f"Merged {len(temp_outputs)} call graphs into {final_output}")
        return len(merged_graph) > 0

    def _clean_up_package(self, args, workdir):
        package, version = args
        package = package.strip()
        version = version.strip()
        package_dir = os.path.abspath(os.path.join(workdir, "pypi_packages", package, version))
        logger.debug(f"Cleaning up package {args} {package_dir}")
        jarvis_output_file = os.path.abspath(str(CALL_GRAPH_DIR /package/version/ f'jarvis_cg.json'))
        jarvis_output_dir = Path(jarvis_output_file).parent
        # if os.path.exists(jarvis_output_dir/'ERROR'):
        #     with open(os.path.join(jarvis_output_dir,'ERROR')) as f:
        #                     jarvis_failed_reason = f.read().strip().lower()
        #     if 'memoryerror' in jarvis_failed_reason:
        #         return
        for f in os.listdir(package_dir):
            if f not in KEEP_FILES:
                os.system('rm -rf {}/{}'.format(package_dir,f))

        
    def stop(self):
        """设置停止标志"""
        self._stop_event.set()

def execute_jarvis(args, workdir,rewrite=False,max_mem_gb=None):
    package, version = args
    package = package.strip()
    version = version.strip()
    jarvis_output_file = os.path.abspath(str(CALL_GRAPH_DIR /package/version/ f'jarvis_cg.json'))
    jarvis_output_dir = Path(jarvis_output_file).parent
    if not jarvis_output_dir.exists():
        jarvis_output_dir.mkdir(parents=True)

    # if os.path.exists(os.path.join(str(jarvis_output_dir),'ERROR')) and not rewrite:
    #     logger.debug(f"{args} has ERROR file and not rewrite, skip")
    #     return

    # if os.path.exists(jarvis_output_file) and not rewrite:
    #     return

    package_dir = os.path.join(workdir, "pypi_packages", package, version)
    py_files_list = EnvAnalyzer.find_project_py_files(package, version, workdir=workdir,verbose=1)
    
    if len(py_files_list) == 0:
        logger.warning(f"Not found any python files in {package_dir}/PY_FILES_LIST")
        logger.debug(f'jarvis_output_dir: {jarvis_output_dir}')
        os.system(f'echo Not found any python files > {jarvis_output_dir}/ERROR')
        return False
    elif len(py_files_list) > 500:
        os.system(f'echo Too Many python files {len(py_files_list)}> {jarvis_output_dir}/ERROR')
        return False 
    entry_files = ' '.join(py_files_list)
    logger.info(f"Executing jarvis for {args} with {len(py_files_list)} files")
    
    external_abs_path = os.path.abspath(package_dir)
    if sys.platform == 'darwin':
        jarvis_timeout = 60*5
        if not max_mem_gb:
            max_mem_gb = 8
        cmd = (
        f"timeout {jarvis_timeout} conda run -n jarvis jarvis-cli {entry_files} "
        f"--decy -o {jarvis_output_file} -ext {external_abs_path}"
        )
    else:
        jarvis_timeout = 60*20
        if not max_mem_gb:
            max_mem_gb = 32
        cmd = (
            f"ulimit -v {max_mem_gb*1024*1024} && "
            f"timeout {jarvis_timeout} conda run -n jarvis jarvis-cli {entry_files} "
            f"--decy -o {jarvis_output_file} -ext {external_abs_path}"
        )

    try:
        # os.chdir(package_dir)
        result = subprocess.run(cmd, capture_output=True, text=True, shell=True, cwd=external_abs_path)
        
        if result.returncode != 0:
            if "memoryerror" in result.stderr.lower():
                logger.error(f"MemoryError detected in jarvis_cli.py for {package} {version} with {max_mem_gb}G: {result.stderr}")
                with open(f'{jarvis_output_dir}/ERROR','w') as f:
                    f.write(f'MemoryError detected {max_mem_gb}G: {result.stderr}')
            else:
                logger.error(f"Failed to run jarvis_cli.py for {package} {version}: {result.stderr}")
                with open(f'{jarvis_output_dir}/ERROR','w') as f:
                    f.write(f'Failed to run jarvis_cli.py {result.stderr}')
    except subprocess.TimeoutExpired as e:
        logger.error(f"Jarvis execution timed out after {e.timeout} seconds")
        with open(f'{jarvis_output_dir}/ERROR','w') as f:
            f.write(f'{package} {version} Timeout after {e.timeout}s: {str(e)}')
    except OSError as e:
        if 'Argument list too long' in str(e):
            logger.error(f"Argument list too long for {package} {version}")
        with open(f'{jarvis_output_dir}/ERROR','w') as f:
            f.write(f'{package} {version} OSError: {str(e)}')

    if not os.path.exists(jarvis_output_file):
        logger.warning(f"Jarvis execution failed for {package} {version}")
        return False
    logger.info(f"Jarvis execution successfully finished for {package} {version}, stored in {jarvis_output_file}")
    return True




def get_cg(args, workdir, max_mem_gb,rewrite=False):
    package, version = args
    package = package.strip()
    version = version.strip()
    args = (package, version)
    package_dir = os.path.abspath(os.path.join(workdir, "pypi_packages", package, version))
    jarvis_output_file = os.path.abspath(str(CALL_GRAPH_DIR /package/version/ f'jarvis_cg.json'))
    jarvis_output_dir = Path(jarvis_output_file).parent

    if not check_installed((package, version), workdir):
        logger.warning(f"When get cg, Package {args} has not been installed, skip")
        return
    elif os.path.exists(jarvis_output_file) and not rewrite:
        logger.info(f"CG for {args} exists, skip")
        return
        

    success = execute_jarvis(args,workdir=workdir,max_mem_gb=max_mem_gb, rewrite=rewrite)

    # if success:
    # clean_up_package(args,workdir)
    # self._clean_up_package(args,self.workdir)


def filter_packages(packages,py_version, workdir, memout=False):
    filtered_packages = []
    for package, version in packages:
        package_dir = os.path.abspath(os.path.join(workdir, "pypi_packages", package, version))
        tried_py_versions_file = os.path.join(package_dir, 'TRIED_PY_VERSION')

        # 1. 存在cg file, 包括cg file和memery out的情况
        jarvis_output_file = os.path.abspath(str(CALL_GRAPH_DIR /package/version/ f'jarvis_cg.json'))
        jarvis_error_file = os.path.abspath(str(CALL_GRAPH_DIR /package/version/ f'ERROR'))
        py_files_list = EnvAnalyzer.find_project_py_files(package, version, workdir=workdir,verbose=1)

        # if len(py_files_list) == 0:
        #     logger.warning(f"Not found any python files in {package_dir}/PY_FILES_LIST")
        #     logger.debug(f'jarvis_output_dir: {jarvis_output_dir}')
        #     os.system(f'echo Not found any python files > {jarvis_error_file}')
        #     continue
        # elif len(py_files_list) > 500:
        #     os.system(f'echo Too Many python files {len(py_files_list)}> {jarvis_error_file}')
        #     continue

        if os.path.exists(tried_py_versions_file):
            with open(tried_py_versions_file, 'r') as f:
                tried_py_versions = f.read().strip().split('\n')
                tried_py_versions = [v.strip() for v in tried_py_versions if v]
        else:
            tried_py_versions = []
        if os.path.exists(jarvis_output_file):
            continue
        elif os.path.exists(jarvis_error_file):
            continue
            with open(jarvis_error_file, 'r') as f:
                error = f.read().strip()
            if 'memoryerror' in error.lower() and len(tried_py_versions) and memout:
                # 检查当前版本是不是上最近一个尝试安装的py_version
                if py_version != tried_py_versions [-1]:
                    continue
            else:
                continue
        # 2. 不存在cg file, 则证明没有安装成功过/或者安装了但是没执行jarvis

        if len(tried_py_versions) == 0 or py_version not in tried_py_versions:
            filtered_packages.append((package, version))
        
        elif (os.path.exists(os.path.join(package_dir,'HAVEERROR')) or os.path.exists(os.path.join(package_dir,'ERROR'))) and py_version in tried_py_versions:
            continue
        elif not (CALL_GRAPH_DIR /package/version).exists() and py_version == tried_py_versions[-1]:
            # if py_version == '3.12':
            #     assert False,f"{tried_py_versions} {(os.path.exists(os.path.join(package_dir,'HAVEERROR')) or os.path.exists(os.path.join(package_dir,'ERROR')))}"     
            filtered_packages.append((package, version))
    return filtered_packages   
def get_direct_and_indirect_dependents(all_dependents, package, version):
    direct = all_dependents.get(package, {}).get(version, {}).get('direct', [])
    indirect = all_dependents.get(package, {}).get(version, {}).get('indirect', [])
    return direct, indirect
    
def get_python_version(package_name, package_version):
    response = request_metadata_json_from_pypi(package_name, package_version)
    if response.status_code == 200:
        metadata = response.json()

    elif response.status_code == 404:
        logger.warning(f"Package '{package_name}' version={package_version} not found on PyPI.{response.status_code}")
        return False, None
    else:
        print(f"Package '{package_name}' version={package_version} error.{response.status_code}")
        assert False

    # 1. classifiers 收集py versions and topics
    py_versions = []
    topics = []
    for classifier in metadata['info']['classifiers']:
        if classifier.startswith('Programming Language :: Python ::') and not classifier.startswith('Programming Language :: Python :: Implementation'):
            py_versions.append(classifier)
        elif classifier.startswith('Topic ::'):
            topics.append(classifier)

    py_versions = [f.replace(':: Only','').split(' :: ')[-1] for f in py_versions]
    # logger.debug(f"py_versions: {py_versions} for {package_name} {package_version}")
    #sort python versions by major version and minor version
    py_versions = sorted(py_versions, key=lambda x: list(map(int, x.split('.'))))

    # 2. requires_python 收集py versions
    requires_python = metadata['info'].get('requires_python', '')
    name = metadata['info']['name']


    return True, (py_versions,requires_python,name, topics)

def get_all_upstream_versions(cve_id, advisory, all_dependents):
    """获取所有需要下载的upstream version"""

    # all_upstream_versions_with_dependents = []
    pkg2versions = defaultdict(list)

    for affected_version in advisory['affected']:
        upstream_package = affected_version['package']['name']
        versions = affected_version['versions']
        filtered_versions = filter_versions(upstream_package,versions)
        
        for upstream_version in versions:
            # ret =  get_dependents_from_osi(upstream_package, upstream_version)
            # direct, indirect = ret['direct'], ret['indirect']

            
            direct, indirect = get_direct_and_indirect_dependents(all_dependents, upstream_package, upstream_version)
            total_dependents_for_version = len(direct) + len(indirect)
        
            if len(direct) or len(indirect):
                # all_upstream_versions_with_dependents.append({
                #     'package': upstream_package,
                #     'version': upstream_version,
                # })
                pkg2versions[normalize_package_name(upstream_package)].append(upstream_version)
        return pkg2versions



def get_all_downstream_and_pairs(cve2advisory,only_one_downstream_version=False):
    all_downstream_install =set()
    all_upstream_install = set()

    all_pairs = defaultdict(dict)
    logger.info(f"Getting all downstream and upstream versions for {len(cve2advisory)} CVEs with only_one_downstream_version={only_one_downstream_version}")
    for idxx,(cve_id, advisory) in enumerate(cve2advisory.items()):
        # if cve_id !='CVE-2024-0243':
        #     continue
        # 获取依赖信息

        cve_dependents, all_dependents = get_dependents(cve_id,advisory)
        
        if cve_dependents == 0:
            # logger.warning(f"{cve_id} has no dependents, skipping")
            continue        

        all_upstream_versions_with_dependents = get_all_upstream_versions(cve_id, advisory, all_dependents)
        all_unique_affected_projects = get_all_unique_affected_projects(advisory)
        all_unique_affected_projects = [item[0] for item in all_unique_affected_projects]
        
        for upstream_package,upstream_versions in all_upstream_versions_with_dependents.items():
            for upstream_version in upstream_versions:
                direct, indirect = get_direct_and_indirect_dependents(all_dependents, upstream_package, upstream_version)
                # indirect = []
                # get the metadata info for each downstream
                all_downstream = [(down['package'], down['version'] ) for down in direct + indirect]
                if len(all_downstream) == 0:
                    continue
                all_pairs[cve_id][(upstream_package, upstream_version)] = None
                
                if only_one_downstream_version:
                    new_all_downstream = []
                    downstream2versions = dict()
                    # group by package
                    for pkg, version in all_downstream:
                        if pkg not in downstream2versions:
                            downstream2versions[pkg] = []
                        if version not in downstream2versions[pkg]:
                            downstream2versions[pkg].append(version)
                    
                    pkg2versions = defaultdict(set)
                    for pkg, versions in downstream2versions.items():
                        # order versions from latest to oldest
                        versions = sorted(versions, key=lambda x: version_key(x), reverse=False)
                        new_all_downstream.append((pkg, versions[-1]))
                    all_downstream = new_all_downstream
                
                all_downstream_install.update(all_downstream)
                all_pairs[cve_id][(upstream_package, upstream_version)]= all_downstream
    
    # all_pairs_file = PAIRS_DIR / 'all_pairs.json'
    # with open(all_pairs_file, 'w') as f:
    #     json.dump(all_pairs, f, indent=2)
    # all_downstream_install = [list(item) for item in all_downstream_install]
    return all_downstream_install,all_pairs

def collect_metadata_info(packages, output_file):

    def process_one_package(down_package, down_version,cve_id=None, advisory=None):
        success, item = get_python_version(down_package, down_version)
        # logger.debug(f"Python versions for {down_package} {down_version}: {py_versions}")
        
        if item is None:
            return (success, (down_package, down_version,'','','',''))
        else:
            return (success, (down_package, down_version)+item)
    
    def process_packages_parallel(dependents, n_jobs=10, cve_id=None, advisory=None):
        """并行处理多个依赖包"""
        # items = [(item['package'], item['version']) 
        #             for item in dependents]
        results = Parallel(n_jobs=n_jobs)(
            delayed(process_one_package)(*item) for item in dependents
        )
        return results
        
    
    # 初始化WebDriver
    if output_file.exists() and True:
        with open(output_file, 'r') as f:
            all_metadata = json.load(f)
    else:
        all_metadata = defaultdict(dict)
    
    # filter packages
    filtered_packages = []
    for item in packages:
        pkg, version = item
        if pkg not in all_metadata or version not in all_metadata[pkg]:
            filtered_packages.append((pkg, version))
    results = process_packages_parallel(filtered_packages, n_jobs=50)

    failed_pkg = []
    for success, item in results:
        down_package, down_version, py_versions, requires_python,pkg_name,topics = item
        if not success:
            failed_pkg.append((down_package, down_version))
            continue
        
        if down_package not in all_metadata:
            all_metadata[down_package] = {}
        all_metadata[down_package][down_version] = {
            'py_versions': py_versions,
            'requires_python': requires_python,
            'name':pkg_name,
            'topics':topics,
        }
    with open(output_file, 'w') as f:
        json.dump(all_metadata, f)
    return failed_pkg


def extract_py_versions_from_metadata(info, up_py_versions=None):
    # 1. from_classifiers
    py_versions_class = info['py_versions']

    # 2. from_requires_python
    py_versions_req = []
    # 如果没有指定python版本号,则使用candidate py_versions+
    #! 有的requires_python会要求非常严格例如==3.10.8
    
    requires_python = info['requires_python']
    if requires_python:
        cleaned_requires_python = requires_python.replace('.*','')
        try:
            spec = SpecifierSet(cleaned_requires_python)
            if len(spec)==1 and list(spec)[0].operator == '==':
                py_version = list(spec)[0].version
                py_versions_req.append(py_version)
            
            elif len(py_versions_class):
                for py_version in py_versions_class:
                    if spec.contains(py_version):
                        py_versions_req.append(py_version)
            elif up_py_versions:
                for py_version in up_py_versions:
                    if spec.contains(py_version):
                        py_versions_req.append(py_version)
            else:
                for py_version in candidate_py_versions:
                    if spec.contains(py_version):
                        py_versions_req.append(py_version)
        except:
            py_versions_req = py_versions_class
    else:
        py_versions_req = py_versions_class
    py_versions = py_versions_req

    exclude_py_versions = ['3.3','3.2','3.1','3.0','3','empty']
    py_versions = [py_version.strip() for py_version in py_versions if py_version.strip() not in exclude_py_versions and not py_version.startswith('2')]
    if len(py_versions) == 0 and up_py_versions:
        py_versions = up_py_versions

    if len(py_versions) == 0:
        for py_version in candidate_py_versions:
                py_versions.append(py_version)
    
    return py_versions

def generate_install_tasks(all_pairs, workdir, metadata_file,metadata_file_for_upstream,install_tasks_file,install_tasks_file_for_upstream,rewrite=False):

    if not workdir.exists():
        workdir.mkdir(parents=True, exist_ok=True)
    

    if not rewrite and install_tasks_file.exists() and install_tasks_file_for_upstream.exists():
        return
    if metadata_file.exists() and True:
        with open(metadata_file, 'r') as f:
            all_metadata = json.load(f)
    else:
        assert False
        all_metadata = defaultdict(dict)
    if metadata_file_for_upstream.exists() and True:
        with open(metadata_file_for_upstream, 'r') as f:
            all_metadata_for_upstream = json.load(f)
    else:
        assert False
        all_metadata_for_upstream = defaultdict(dict)
    install_tasks_for_upstream = defaultdict(list)
    install_tasks_for_downstream = defaultdict(list)
    for cve_id in all_pairs:
        for upstream, downstreams in all_pairs[cve_id].items():
            up_package, up_version = upstream
            up_metadata = all_metadata_for_upstream.get(up_package, {}).get(up_version, None)

            if up_metadata is None:
                logger.warning(f"{up_package} {up_version} not in metadata")
                continue
            up_py_versions = extract_py_versions_from_metadata(up_metadata)
            for py_version in up_py_versions:
                py_version = py_version.strip()
                install_tasks_for_upstream[py_version].append(upstream)
                
            for downstream in downstreams:
                down_package, down_version = downstream
                
                down_metadata = all_metadata.get(down_package, {}).get(down_version, None)
                if down_metadata is None:
                    # logger.warning(f"{down_package} {down_version} not in metadata")
                    continue
                down_py_versions = extract_py_versions_from_metadata(down_metadata, up_py_versions)

                for py_version in down_py_versions:
                    py_version = py_version.strip()
                    if downstream not in install_tasks_for_downstream[py_version]:
                        install_tasks_for_downstream[py_version].append(downstream)
                
    install_tasks_for_upstream = dict(sorted(install_tasks_for_upstream.items(), key= lambda x:version_key(x[0]), reverse=True))
    install_tasks_for_downstream = dict(sorted(install_tasks_for_downstream.items(), key= lambda x:version_key(x[0]), reverse=True))
    
    with open(install_tasks_file, 'w') as f:
        json.dump(install_tasks_for_downstream, f)
    with open(install_tasks_file_for_upstream, 'w') as f:
        json.dump(install_tasks_for_upstream, f)
  

def install_packages_with_version_control(install_tasks_file,workdir, metadata_file, install_tasks_list=None,only_py_list=False, save_installed=False, n_threads_cg_=None, max_mem_gb_=None,mem_out_task=False):
    from multiprocessing.dummy import Pool as ThreadPool

    metadata_installed_file = metadata_file.parent / metadata_file.name.replace('.json','_installed.json')
    

    if isinstance(install_tasks_file, str) or isinstance(install_tasks_file, Path):
        with open(install_tasks_file, 'r') as f:
            install_tasks = json.load(f)
        
    else:

        install_tasks = install_tasks_file
       
    install_tasks_cnt = 0
    
    if metadata_installed_file and os.path.exists(metadata_installed_file):
        with open(metadata_installed_file, 'r') as f:
            metadata_with_install = json.load(f)
    else:
        metadata_with_install = defaultdict(dict)

    installed_packages = []
    for package, versions in metadata_with_install.items():
        for version, info in versions.items():
            if info.get('installed_py_version',None):
                installed_packages.append([package, version])

    # logger.info(f"Already installed {len(installed_packages)} packages")
    if sys.platform == 'darwin':
        n_threads_cg = 2
        max_mem_gb = 8
        n_threads_install = 2
    else:
        n_threads_cg = 8 if n_threads_cg_ is None else n_threads_cg_
        n_threads_install = 15
        max_mem_gb = 24 if max_mem_gb_ is None else max_mem_gb_
        
    # assert False
    for py_version,packages in install_tasks.items():

        py_version = py_version.strip()
        # if py_version in[ '3.13']:
        #     continue
        if py_version == '3.14':
            logger.warning(f"Docker fails because there's no official Python 3.14 image available")
            continue

        if py_version.startswith('2'):
            continue

        if py_version == 'empty':
            continue

        if install_tasks_list:
            packages_install = []
            for item in packages:
                if tuple(item) in install_tasks_list:
                    packages_install.append(item)
            packages = packages_install
        analyzer_install = None

        try:
            if not only_py_list:
                batch_n = 500
                if not mem_out_task:
                    filtered_packages = filter_packages(packages=packages,py_version=py_version, workdir=workdir)
                else:
                    filtered_packages = packages
                logger.info(f'Totally {len(packages)} packages under python version {py_version}, {len(packages) - len(filtered_packages)} have been filtered, {len(filtered_packages)} will be addressed')
                if len(filtered_packages) == 0:
                    continue
                analyzer_install = EnvAnalyzer(workdir, py_version = py_version,  n_threads=n_threads_install, max_mem_gb=None,only_py_list=only_py_list)
                for i in range(0, len(filtered_packages), batch_n):
                    batch_packages = filtered_packages[i:i+batch_n]
                    
                    pool_install = ThreadPool(n_threads_install)
                    pool_install.map(partial(analyzer_install.install_package, rewrite=mem_out_task), batch_packages)
                    pool_install.close()
                    pool_install.join()

                    pool_cg = ThreadPool(n_threads_cg)
                    pool_cg.map(partial(get_cg, workdir=workdir, max_mem_gb=max_mem_gb), batch_packages)
                    pool_cg.close()
                    pool_cg.join()

                    delete(workdir,batch_packages)
                        # analyzer.close()
                        # analyzer = None
                        # time.sleep(3)
            else:
                pool_install = ThreadPool(n_threads_install)
                filtered_packages = [pkg for pkg in packages if not len(EnvAnalyzer.find_project_py_files(*pkg,workdir=workdir))]
                if len(filtered_packages) == 0:
                    continue
                analyzer_install = EnvAnalyzer(workdir, py_version = py_version,  n_threads=n_threads_install, max_mem_gb=None,only_py_list=only_py_list)
                pool_install.map(analyzer_install.get_pkg_structure, filtered_packages)
        except docker.errors.BuildError:
            logger.warning(f"Failed to create analyzer for python version {py_version}")
            continue
        except:
            raise       
        finally:
            if analyzer_install:
                analyzer_install.close()
        # TODO 处理memout

    if save_installed:
        store_installed_packages(metadata_file=metadata_file,metadata_installed_file=metadata_installed_file)

KEEP_FILES = ['HAVEERROR','INSTALLED_PY_VERSION','CHECK_LOG','PY_FILES_LIST','ERROR', 'TRIED_PY_VERSION']


def clean_up_package(args, workdir):
    package, version = args
    package = package.strip()
    version = version.strip()
    package_dir = os.path.abspath(os.path.join(workdir, "pypi_packages", package, version))
    jarvis_output_file = os.path.abspath(str(CALL_GRAPH_DIR /package/version/ f'jarvis_cg.json'))
    jarvis_output_dir = Path(jarvis_output_file).parent
    dirs = os.listdir(package_dir)
    if len(dirs) == 0:
        return
    logger.debug(f"Cleaning up package {args} {package_dir}")
    
    for f in os.listdir(package_dir):

        if f not in KEEP_FILES:
            os.system('rm -rf {}/{}'.format(package_dir,f))  

def delete(workdir,packages):

    # cnt = 0
    sum_size = 0
    for package, version in packages:
        package_dir = os.path.join(workdir, "pypi_packages", package, version)  
        if os.path.exists(package_dir):
            # 检查package_dir是否是dir
            if not os.path.isdir(package_dir):
                # os.system('rm {}'.format(package_dir))
                print(package_dir, os.path.exists(jarvis_output_file))
                continue
            # 计算目录大小（单位：GB）
            dir_size = sum(os.path.getsize(os.path.join(dirpath, filename)) 
                          for dirpath, dirnames, filenames in os.walk(package_dir) 
                          for filename in filenames)
            sum_size += dir_size / (1024 * 1024 * 1024)  # 转换为GB
        clean_up_package((package, version), workdir)
    # logger.info(f'{cnt} packages mem out')
    logger.info(f'{round(sum_size,2)}GB')

def check_installed(args, workdir=None):
    package, version = args
    package = package.strip()
    version = version.strip()
    package_dir = os.path.join(workdir, "pypi_packages", package, version)

    # 1. 没有安装过
    if not os.path.exists(package_dir):
        # print(package_dir)
        # print('1')
        return False
    # 2. 存在ERROR File
    if os.path.exists(os.path.join(package_dir,'HAVEERROR')) or os.path.exists(os.path.join(package_dir,'ERROR')):

        return False
    # 3. 没有INSTALLED_PY_VERSION/TRIED_PY_VERSION/CHECK_LOG
    # 移除掉deps后只剩下三个文件
    if not os.path.exists(os.path.join(package_dir,'INSTALLED_PY_VERSION')) or not os.path.exists(os.path.join(package_dir,'CHECK_LOG')): 
        
        return False
    # 4. 满足以上条件，获取安装的python版本号
    with open(os.path.join(package_dir,'INSTALLED_PY_VERSION'), 'r') as f:
        py_version = f.read().strip()

    
    return py_version

def store_installed_packages(metadata_file, metadata_installed_file):
    with open(metadata_file, 'r') as f:
        all_metadata = json.load(f)
    installed_cnt = 0
    for package, versions in all_metadata.items():
        for version in versions:
            if all_metadata[package][version].get('installed_py_version', None):
                installed_cnt += 1
                continue
            py_version = check_installed((package, version), workdir)
            if py_version:
                all_metadata[package][version]['installed_py_version'] = py_version
                installed_cnt += 1
            else:
                all_metadata[package][version]['installed_py_version'] = None


    
    with open(metadata_installed_file, 'w') as f:
        json.dump(all_metadata, f, indent=2)
    logger.info(f"Installed {installed_cnt} packages")

if __name__ == '__main__': 
    import argparse
    parser = argparse.ArgumentParser(description='Process CVE data.')
    parser.add_argument('--size', type=str, choices=['small','large','medium'], default='small', help='Size of the dataset')
    args = parser.parse_args()
    workdir = Path('../docker_workdir')
    if not workdir.exists():
        workdir.mkdir(parents=True, exist_ok=True)
    

    install_tasks_file_for_upstream = workdir / 'install_tasks_for_upstream.json'


    cve2advisory_small = read_cve2advisory(small=True,valid_py_cve=True) # 40
    cve2advisory_medium = read_cve2advisory(medium=True,valid_py_cve=True) # 131
    cve2advisory_large = read_cve2advisory(valid_py_cve=True) # 698 valid CVEs

    install_tasks_file = workdir / 'install_tasks_small.json'

    metadata_file = Path('./all_metadata.json')
    if args.size == 'small':
        install_tasks_file = workdir / 'install_tasks_small.json'
        install_tasks_file_for_upstream = workdir / 'install_tasks_for_upstream_small.json'

        cve2advisory  = cve2advisory_small

        pairs_cache_file = workdir / 'get_all_downstream_and_pairs_results_small.pkl'

        metadata_file_for_upstream = Path('./all_metadata_file_for_upstream_small.json')
        metadata_file = Path('./all_metadata_small.json')
        failed_pkgs_cache_file = workdir / 'failed_pkgs_small.pkl'
        pkg_with_py_file_cache_file = workdir / 'all_pkgs_with_py_file_small.pkl'
        
    elif args.size == 'medium':
        install_tasks_file = workdir / 'install_tasks_medium.json'
        install_tasks_file_for_upstream = workdir / 'install_tasks_for_upstream_medium.json'
        cve2advisory  = cve2advisory_medium

        pairs_cache_file = workdir /'get_all_downstream_and_pairs_results_medium.pkl'

        metadata_file_for_upstream = Path('./all_metadata_file_for_upstream_medium.json')
        metadata_file = Path('./all_metadata_medium.json')
        failed_pkgs_cache_file = workdir / 'failed_pkgs_medium.pkl'
        pkg_with_py_file_cache_file = workdir /'all_pkgs_with_py_file_medium.pkl'

    else:
        install_tasks_file = workdir / 'install_tasks.json'
        install_tasks_file_for_upstream = workdir / 'install_tasks_for_upstream.json'
        cve2advisory  = cve2advisory_large

        pairs_cache_file = workdir / 'get_all_downstream_and_pairs_results_large.pkl'

        metadata_file_for_upstream = Path('./all_metadata_file_for_upstream_large.json')
        metadata_file = Path('./all_metadata_large.json')
        failed_pkgs_cache_file = workdir / 'failed_pkgs_large.pkl'
        pkg_with_py_file_cache_file = workdir / 'all_pkgs_with_py_file_large.pkl'
    
    all_downstream, all_pairs = get_all_downstream_and_pairs(cve2advisory,only_one_downstream_version=True)
    # print(len(all_downstream))
    all_downstream, all_pairs = get_all_downstream_and_pairs(cve2advisory,only_one_downstream_version=False)
    # print(len(all_downstream))

    assert False
    use_cache = True
    # 1. 获取所有的downstream和upstream
    if pairs_cache_file.exists() and use_cache:
        with open(pairs_cache_file, 'rb') as f:
            all_downstream, all_pairs = pickle.load(f)
    else:
        all_downstream, all_pairs = get_all_downstream_and_pairs(cve2advisory,only_one_downstream_version=True)
        with open(pairs_cache_file, 'wb') as f:
            pickle.dump((all_downstream, all_pairs), f)
    all_upstream = list(set(chain.from_iterable(all_pairs.values())))

    # 2. 收集metadata
    logger.info(f'Collecting metadata for {len(all_upstream)} upstream packages with {len(all_downstream)} downstream packages')
    if failed_pkgs_cache_file.exists() and metadata_file.exists() and use_cache:
        with open(failed_pkgs_cache_file, 'rb') as f:
            failed_downstream, failed_upstream = pickle.load(f)
    else:   
        failed_downstream = collect_metadata_info(packages = all_downstream, output_file=metadata_file)
        failed_upstream =collect_metadata_info(packages = all_upstream, output_file=metadata_file_for_upstream)
        with open(failed_pkgs_cache_file, 'wb') as f:
            pickle.dump((failed_downstream, failed_upstream), f)
    all_downstream = [pkg for pkg in all_downstream if pkg not in failed_downstream]
    all_upstream = [pkg for pkg in all_upstream if pkg not in failed_upstream]
    logger.info(f'Finished metadata for {len(all_upstream)} upstream packages with {len(all_downstream)} downstream packages')


    


    # 3. 生成install_tasks
    if install_tasks_file.exists() and install_tasks_file_for_upstream.exists() and use_cache:
        pass
    else:
        generate_install_tasks(all_pairs= all_pairs, workdir=workdir, metadata_file= metadata_file, install_tasks_file=install_tasks_file, 
        metadata_file_for_upstream= metadata_file_for_upstream,install_tasks_file_for_upstream=install_tasks_file_for_upstream,
        rewrite=True)
    with open(install_tasks_file, 'r') as f:
        install_tasks_for_downstream = json.load(f)
    with open(install_tasks_file_for_upstream, 'r') as f:
        install_tasks_for_upstream = json.load(f)
    logger.debug(f"install_tasks_for_downstream:")
    logger.info({key:len(v) for key, v in install_tasks_for_downstream.items()})
    logger.debug(f"install_tasks_for_upstream:")
    logger.info({key:len(v) for key, v in install_tasks_for_upstream.items()})
    logger.info(f"Total {sum([len(tasks) for tasks in install_tasks_for_upstream.values()])} tasks for upstream to install")
    logger.info(f"Total {sum([len(tasks) for tasks in install_tasks_for_downstream.values()])} tasks for downstream to install")
    # 4. 执行install_tasks,只尝试获取安装后的structure
    # ! 只尝试获取安装后的structure

    # install_packages_with_version_control(install_tasks_file_for_upstream,workdir,metadata_file=metadata_file,install_tasks_list=all_upstream, only_py_list=True, n_threads = 30)

    # install_packages_with_version_control(install_tasks_file,workdir,metadata_file=metadata_file,install_tasks_list=all_downstream, only_py_list=True, n_threads=30)



        
    
    if pkg_with_py_file_cache_file.exists() and use_cache:
        with open(pkg_with_py_file_cache_file, 'rb') as f:
            all_downstream_with_py_file, all_upstream_with_py_file = pickle.load(f)
    else:
        is_any_py_files = EnvAnalyzer.find_project_py_files
        all_downstream_with_py_file = [(pkg, version) for pkg, version in all_downstream if is_any_py_files(pkg, version,workdir=workdir)]
        all_upstream_with_py_file = [(pkg, version) for pkg, version in all_upstream if is_any_py_files(pkg, version,workdir=workdir)]
        with open(pkg_with_py_file_cache_file, 'wb') as f:
            pickle.dump((all_downstream_with_py_file, all_upstream_with_py_file), f)
    
    logger.info(f"all_upstream: {len(all_upstream)}, all_upstream_with_py_file: {len(all_upstream_with_py_file)}, {len(all_upstream)-len(all_upstream_with_py_file)} don't have py files")
    # for item in all_upstream:
    #     if item not in all_upstream_with_py_file:
    #         package, version = item
    #         package_dir = os.path.abspath(os.path.join(workdir, "pypi_packages_only_py_files", package, version))
    #         py_files_list_file = os.path.join(package_dir,'PY_FILES_LIST')
    #         print(py_files_list_file)
    # assert False
    # for upstream in all_upstream:
    #     if upstream not in all_upstream_with_py_file:
    #         print(os.path.join(workdir, "pypi_packages_only_py_files", upstream[0], upstream[1]))
    logger.info(f"all_downstream: {len(all_downstream)}, all_downstream_with_py_file: {len(all_downstream_with_py_file)}, {len(all_downstream)-len(all_downstream_with_py_file)} don't have py files")

    # 5. 安装完整的pkg for each downstream, 即包括deps

    # install_packages_with_version_control(install_tasks_file,workdir,metadata_file=metadata_file, install_tasks_list=all_downstream_with_py_file, only_py_list=False, save_installed=True)

    #TODO get MemOut cases
    def get_memout_tasks(all_downstream_with_py_file, workdir,max_mem = 32):
        meme_out_tasks = defaultdict(list)
        
        for pkg, version in all_downstream_with_py_file:
            
            jarvis_error_file = CALL_GRAPH_DIR /pkg/version/ 'ERROR'
            if jarvis_error_file.exists():
                with open(jarvis_error_file, 'r') as f:
                    error = f.read()
                # print(error)
                if 'MemoryError' in error:
                    pre_max_mem = extract_memory_size(error)
                    if not pre_max_mem or  pre_max_mem<max_mem:
                        py_version_file = Path(os.path.join(workdir, "pypi_packages",  pkg, version)) / 'INSTALLED_PY_VERSION'
                        with open(py_version_file, 'r') as f:
                            py_version = f.read().strip()
                        meme_out_tasks[py_version].append((pkg, version))
        return meme_out_tasks
    memout_tasks_cache_file = Path('./memout_tasks.pkl')
    
    if memout_tasks_cache_file.exists():
        with open(memout_tasks_cache_file, 'rb') as f:
            memout_tasks = pickle.load(f)
    else:
        memout_tasks = get_memout_tasks(all_downstream_with_py_file, workdir,max_mem=32)
        logger.info(f"Totally {sum([len(v) for v in memout_tasks.values()])} memery out  re-install tasks")
        logger.info({key:len(v) for key, v in memout_tasks.items()})
        logger.info(f"Total {sum([len(tasks) for tasks in memout_tasks.values()])} tasks for upstream to install")
        with open(memout_tasks_cache_file, 'wb') as f:
            pickle.dump(memout_tasks, f)
    
    install_packages_with_version_control(memout_tasks,workdir,metadata_file=metadata_file,  only_py_list=False, save_installed=True, max_mem_gb_=32, n_threads_cg_=5, mem_out_task = True)


            




 