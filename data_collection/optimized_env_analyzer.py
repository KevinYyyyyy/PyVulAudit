# optimized_env_analyzer.py
from docker_container_pool import ContainerPool
import os
import logging
from typing import Tuple, List, Optional
import sys
from logger import logger
class OptimizedEnvAnalyzer:
    def __init__(self, workdir: str, py_version: str = '3.7', 
                 pool_size: int = 5, store_files: bool = False):
        self.workdir = workdir
        self.py_version = py_version
        self.store_files = store_files
        self.image_tag = f"pyvul:py{self.py_version}"
        
        # 初始化容器池
        self.container_pool = ContainerPool(
            image_tag=self.image_tag,
            pool_size=pool_size
        )
        
        self.container_workdir = "/root/pyvul"
    
    def process_package(self, package: str, version: str) -> Tuple[str, int]:
        """处理单个包"""
        package_dir = os.path.abspath(os.path.join(
            self.workdir, "pypi_packages", package, version
        ))
        if not os.path.exists(package_dir):
            os.makedirs(package_dir, exist_ok=True)
        
        container = self.container_pool.get_container()
        if not container:
            logger.error("Failed to get container from pool")
            return package_dir, -1
        
        try:
            # 挂载目录
            mount_cmd = f"mkdir -p /root/pyvul && mount -o rw --bind {package_dir} /root/pyvul"
            self.container_pool.execute_command(container, mount_cmd)
            
            # 安装包
            timeout = 60*5
            buf_prefix = "stdbuf -i0 -o0 -e0"
            timeout_prefix = f"timeout {timeout}"

            pip_command = f"python -W ignore:DEPRECATION -m pip install --target={self.container_workdir} --no-compile {package}=={version} --no-cache-dir --disable-pip-version-check"  + ( " -i https://pypi.tuna.tsinghua.edu.cn/simple" if sys.platform == "darwin" else ""
            )
            uid = os.getuid()
            gid = os.getgid()
            commands = [
                f"rm -rf {self.container_workdir}/*",
                f"{buf_prefix} {timeout_prefix} {pip_command}|| touch {self.container_workdir}/HAVEERROR",
                f"chown -R {uid}:{gid} {self.container_workdir}"
            ]

            install_cmd = " && ".join(commands)

            exit_code, (stdout, stderr) = self.container_pool.execute_command(
                container, commands
            )
            
            # 记录日志
            with open(os.path.join(package_dir, 'CHECK_LOG'), 'wb') as f:
                if stdout:
                    f.write(stdout)
                if stderr:
                    print(stderr)
                    assert False
                    f.write(stderr)
            
            if exit_code != 0:
                with open(os.path.join(package_dir, 'ERROR'), 'w') as f:
                    f.write(f"Installation failed with exit code {exit_code}")
            
            return package_dir, exit_code
            
        finally:
            self.container_pool.release_container(container.id)
    
    def process_packages_batch(self, packages: List[Tuple[str, str]], 
                             batch_size: int = 10) -> None:
        """批量处理包"""
        for i in range(0, len(packages), batch_size):
            batch = packages[i:i + batch_size]
            for package, version in batch:
                self.process_package(package, version)
    
    def close(self) -> None:
        """清理资源"""
        self.container_pool.close()