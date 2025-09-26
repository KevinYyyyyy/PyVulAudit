import os
import json
import time
import tempfile
import docker
import shutil
from pathlib import Path
from joblib import Parallel, delayed
from functools import partial
from multiprocessing.dummy import Pool as ThreadPool
import sys
import subprocess
import gc
from collections import defaultdict
from logger import logger
from constant import DATA_DIR, SUFFIX


class SelectedPackageInstaller:
    """专门用于安装selected_packages的安装器"""
    
    def __init__(self, workdir, py_version='3.10', n_threads=8, max_mem_gb=16):
        self.workdir = Path(workdir)
        self.base_pypi_dir =  Path("../docker_workdir/pypi_packages" ) # 读取已安装版本的目录
        self.py_version = py_version
        self.n_threads = n_threads
        self.max_mem_gb = max_mem_gb
        
        # 为selected packages创建独立的目录结构
        self.selected_packages_dir = self.workdir / "selected_packages"
        self.selected_packages_dir.mkdir(parents=True, exist_ok=True)
        
        # Docker客户端和镜像缓存
        self.client = docker.from_env()
        self.docker_images = {}
        
        logger.info(f"SelectedPackageInstaller initialized with default py={self.py_version}")
    
    def get_installed_py_version(self, pkg_name, pkg_version):
        """读取包的已安装Python版本"""
        version_file = self.base_pypi_dir / pkg_name / pkg_version / "INSTALLED_PY_VERSION"
        if version_file.exists():
            try:
                with open(version_file, 'r') as f:
                    return f.read().strip()
            except:
                pass
        else:
            assert False, version_file
        return self.py_version  # 默认版本
    
    def group_packages_by_py_version(self, selected_packages):
        """按Python版本分组包"""
        grouped = defaultdict(list)
        
        for package_info in selected_packages:
            pkg_name, pkg_version = package_info['package'].split('@')
            py_ver = self.get_installed_py_version(pkg_name, pkg_version)
            grouped[py_ver].append(package_info)
        logger.info(f"Packages grouped by Python version: {dict((k, len(v)) for k, v in grouped.items())}")
        return dict(grouped)
    
    def ensure_docker_image(self, py_version):
        """确保Docker镜像存在"""
        image_tag = f"pyvul_selected:py{py_version}"
        
        if image_tag not in self.docker_images:
            dockerfile_dir = self.workdir / f"selected_metadata_py{py_version}"
            dockerfile_dir.mkdir(parents=True, exist_ok=True)
            
            dockerfile_path = dockerfile_dir / "Dockerfile"
            with open(dockerfile_path, "w", encoding="utf-8") as df:
                df.write(f'FROM python:{py_version}\n')
                df.write('RUN pip install --no-cache-dir pipdeptree\n')
            
            try:
                self.client.images.build(
                    path=str(dockerfile_dir), 
                    tag=image_tag, 
                    dockerfile="Dockerfile", 
                    forcerm=True,
                    network_mode="host"
                )
                self.docker_images[image_tag] = True
                logger.info(f"Docker image {image_tag} built successfully")
            except Exception as e:
                logger.error(f"Failed to build Docker image {image_tag}: {e}")
                raise
    
    def install_single_package(self, package_info, py_version, rewrite=False):
        """安装单个包"""
        package = package_info['package']
        pkg_name, pkg_version = package.split('@')
        
        package_dir = self.selected_packages_dir / pkg_name / pkg_version
        package_dir.mkdir(parents=True, exist_ok=True)
        
        if self._check_installed(package_dir) and not rewrite:
            logger.info(f"Package {package} already installed, skipping")
            return True
        
        logger.info(f"Installing selected package: {package} with py{py_version}")
        
        try:
            success = self._docker_install_package(pkg_name, pkg_version, package_dir, py_version)
            
            if success:
                self._save_package_info(package_dir, package_info, py_version)
                logger.info(f"Successfully installed {package}")
                return True
            else:
                logger.warning(f"Failed to install {package}")
                return False
                
        except Exception as e:
            logger.error(f"Error installing {package}: {e}")
            with open(package_dir / "ERROR", "w") as f:
                f.write(f"Installation error: {str(e)}")
            return False
    
    def _docker_install_package(self, pkg_name, pkg_version, package_dir, py_version):
        """使用指定Python版本的Docker安装包"""
        container_workdir = "/root/selected_pyvul"
        uid = os.getuid()
        gid = os.getgid()
        image_tag = f"pyvul_selected:py{py_version}"
        
        logger.info(f"Installing {pkg_name}=={pkg_version} with py{py_version} in {package_dir}")
        
        mount = docker.types.Mount(
            target=container_workdir,
            source=str(package_dir.absolute()),
            type="bind",
            read_only=False
        )
        
        timeout = 60 * 10
        buf_prefix = "stdbuf -i0 -o0 -e0"
        timeout_prefix = f"timeout {timeout}"
        
        pip_command = (
            f"python -W ignore:DEPRECATION -m pip install "
            f"--target={container_workdir} --no-compile {pkg_name}=={pkg_version} "
            f"--no-cache-dir --disable-pip-version-check"
        )
        
        if sys.platform == "darwin":
            pip_command += " -i https://pypi.tuna.tsinghua.edu.cn/simple"
        
        list_py_command = f"find {container_workdir} -mindepth 1 -type f -name '*.py' > {container_workdir}/PY_FILES_LIST"
        dep_tree_command = f"cd {container_workdir} && python -m pipdeptree --json > {container_workdir}/dependency_tree.json"
        pip_freeze_command = f"cd {container_workdir} && python -m pip freeze > {container_workdir}/requirements.txt"
        
        commands = [
            f"rm -rf {container_workdir}/*",
            f"{buf_prefix} {timeout_prefix} {pip_command} || touch {container_workdir}/INSTALL_ERROR",
            f"{list_py_command}",
            f"{dep_tree_command} || echo 'Failed to generate dependency tree'",
            f"{pip_freeze_command} || echo 'Failed to generate requirements.txt'",
            f"chown -R {uid}:{gid} {container_workdir}"
        ]
        
        command = " && ".join(commands)
        try:
            container = self.client.containers.run(
                image=image_tag,
                command=["/bin/bash", "-c", command],
                detach=True,
                network_mode="host",
                mounts=[mount]
            )
            
            exit_code = container.wait(timeout=timeout + 100, condition='not-running')['StatusCode']
            
            log = container.logs(stdout=True, stderr=True).decode(
                encoding='utf-8', errors='ignore'
            ).strip()
            
            with open(package_dir / 'INSTALL_LOG', 'w', encoding='utf-8') as lf:
                lf.write(log)
            
            container.remove(v=True, force=True)
            
            if exit_code == 0 and not (package_dir / "INSTALL_ERROR").exists():
                with open(package_dir / 'INSTALLED_PY_VERSION', 'w') as f:
                    f.write(py_version)
                return True
            else:
                return False
                
        except Exception as e:
            logger.error(f"Docker container execution failed: {e}")
            with open(package_dir / "ERROR", "w") as f:
                f.write(f"Container error: {str(e)}")
            return False
        finally:
            gc.collect()
    
    def _check_installed(self, package_dir):
        """检查包是否已经安装"""
        return (
            (package_dir / 'INSTALLED_PY_VERSION').exists() and
            (package_dir / 'PY_FILES_LIST').exists() and
            not (package_dir / 'ERROR').exists() and
            not (package_dir / 'INSTALL_ERROR').exists()
        )
    
    def _save_package_info(self, package_dir, package_info, py_version):
        """保存包的详细信息"""
        info_file = package_dir / "package_info.json"
        
        saved_info = {
            'package': package_info['package'],
            'pkg_name': package_info['pkg_name'],
            'pkg_version': package_info['pkg_version'],
            'monthly_downloads': package_info.get('monthly_downloads', 0),
            'composite_score': package_info.get('composite_score', 0),
            'maintenance_score': package_info.get('maintenance_score', 0),
            'popularity_score': package_info.get('popularity_score', 0),
            'complexity_score': package_info.get('complexity_score', 0),
            'depth': package_info.get('depth'),
            'dep_type': package_info.get('dep_type'),
            'upstream_dependencies': package_info.get('upstream_dependencies', []),
            'installed_py_version': py_version,
            'install_timestamp': time.time()
        }
        
        with open(info_file, 'w') as f:
            json.dump(saved_info, f, indent=2)
    
    def install_selected_packages(self, selected_packages, batch_size=10):
        """按Python版本分组并批量安装选中的包"""
        logger.info(f"Starting installation of {len(selected_packages)} selected packages")
        
        # 按Python版本分组
        grouped_packages = self.group_packages_by_py_version(selected_packages)
        
        all_successful = []
        all_failed = []
        
        # 为每个Python版本安装包
        for py_version, pkgs in grouped_packages.items():
            print(py_version, [pkg['package'] for pkg in pkgs])
        for py_version, packages in grouped_packages.items():
            logger.info(f"Installing {len(packages)} packages for Python {py_version}")
            
            # 确保Docker镜像存在
            self.ensure_docker_image(py_version)
            
            # 分批处理
            for i in range(0, len(packages), batch_size):
                batch = packages[i:i + batch_size]
                logger.info(f"Processing Python {py_version} batch {i//batch_size + 1}/{(len(packages) + batch_size - 1)//batch_size}")
                
                # 创建部分函数，固定py_version参数
                install_func = partial(self.install_single_package, py_version=py_version)
                
                # 并行安装
                with ThreadPool(min(self.n_threads, len(batch))) as pool:
                    results = pool.map(install_func, batch)
                
                # 收集结果
                for package_info, success in zip(batch, results):
                    if success:
                        all_successful.append(package_info['package'])
                    else:
                        all_failed.append(package_info['package'])
                
                time.sleep(1)
        
        # 生成安装报告
        self._generate_install_report(all_successful, all_failed)
        
        logger.info(f"Installation completed: {len(all_successful)} successful, {len(all_failed)} failed")
        return all_successful, all_failed
    
    def _generate_install_report(self, successful_installs, failed_installs):
        """生成安装报告"""
        report_file = self.selected_packages_dir / "install_report.json"
        
        report = {
            'installation_timestamp': time.time(),
            'total_packages': len(successful_installs) + len(failed_installs),
            'successful_installs': len(successful_installs),
            'failed_installs': len(failed_installs),
            'success_rate': len(successful_installs) / (len(successful_installs) + len(failed_installs)) if (len(successful_installs) + len(failed_installs)) > 0 else 0,
            'successful_packages': successful_installs,
            'failed_packages': failed_installs
        }
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Install report saved to {report_file}")
    
    def close(self):
        """清理资源"""
        try:
            self.client.containers.prune()
            logger.info("Cleaned up containers")
        except Exception as e:
            logger.error(f"Failed to cleanup containers: {e}")
        
        try:
            self.client.close()
        except Exception as e:
            logger.error(f"Failed to close Docker client: {e}")

def install_selected_packages_main(selected_packages_file, workdir, py_version='3.10', 
                                 n_threads=8, max_mem_gb=16, batch_size=10):
    """主安装函数"""
    
    with open(selected_packages_file, 'r') as f:
        selected_packages = json.load(f)
    
    logger.info(f"Loading {len(selected_packages)} selected packages for installation")
    
    installer = SelectedPackageInstaller(
        workdir=workdir,
        py_version=py_version,
        n_threads=n_threads,
        max_mem_gb=max_mem_gb
    )
    
    try:
        successful, failed = installer.install_selected_packages(
            selected_packages, 
            batch_size=batch_size
        )
        
        print(f"\n=== INSTALLATION SUMMARY ===")
        print(f"Total packages: {len(selected_packages)}")
        print(f"Successful: {len(successful)}")
        print(f"Failed: {len(failed)}")
        print(f"Success rate: {len(successful)/len(selected_packages)*100:.1f}%")
        
        if failed:
            print(f"\nFailed packages:")
            for pkg in failed[:10]:
                print(f"  - {pkg}")
            if len(failed) > 10:
                print(f"  ... and {len(failed)-10} more")
        
        return successful, failed
        
    finally:
        installer.close()

if __name__ == "__main__":
    from pathlib import Path
    
    WORKDIR = Path("../docker_workdir_selected")
    selected_packages_file = DATA_DIR / SUFFIX / 'selected_representative_packages_with_complexity.json'
    
    if selected_packages_file.exists():
        successful, failed = install_selected_packages_main(
            selected_packages_file=selected_packages_file,
            workdir=WORKDIR,
            n_threads=6,
            max_mem_gb=16,
            batch_size=8
        )
        
        print(f"\nInstallation results saved to {WORKDIR}/selected_packages/")
    else:
        print(f"Selected packages file not found: {selected_packages_file}")