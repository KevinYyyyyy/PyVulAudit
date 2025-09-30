"""
Enhanced Environment Analyzer for CVE vulnerability analysis.

This module provides functionality to install Python packages, analyze their dependencies,
and generate call graphs for vulnerability assessment.
"""

import os
import json
import time
import tempfile
import subprocess
import threading
import signal
import gc
import sys
import re
import pickle
import argparse
from pathlib import Path
from collections import defaultdict
from functools import partial
from typing import Dict, List, Tuple, Optional, Set, Any
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
import contextlib
from itertools import chain

import docker
from packaging.version import parse
from packaging.specifiers import SpecifierSet
from joblib import Parallel, delayed
from tqdm import tqdm

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent.absolute()
sys.path.append(str(PROJECT_ROOT))
from src.constant import *
from data_collection.my_utils import (
    request_metadata_json_from_pypi, 
    version_key, 
    normalize_package_name, 
    is_source_code_file,
    extract_memory_size,
    get_modules_from_py_files,
    get_repo_name
)
from data_collection.collect_changes import get_all_unique_affected_projects
from data_collection.get_compatable_python_version import filter_versions
from data_collection.data_classes import VulnerablePackage
from data_collection.logger import logger


@dataclass
class PackageInfo:
    """Data class for package information."""
    name: str
    version: str
    py_versions: List[str]
    requires_python: str
    topics: List[str]


@dataclass
class InstallResult:
    """Data class for installation results."""
    package: str
    version: str
    success: bool
    py_version: Optional[str] = None
    error_message: Optional[str] = None


class EnvAnalyzer:
    """
    Environment analyzer for installing Python packages and generating call graphs.
    
    This class manages Docker containers to safely install packages in isolated environments
    and analyze their structure for vulnerability research.
    """
    
    CANDIDATE_PY_VERSIONS = ['3.10', '3.9', '3.8', '3.7']
    KEEP_FILES = ['HAVEERROR', 'INSTALLED_PY_VERSION', 'CHECK_LOG', 'PY_FILES_LIST', 'ERROR', 'TRIED_PY_VERSION']
    EXCLUDE_DIRS = ['__pycache__', '.git', 'tests', 'test']
    
    def __init__(
        self, 
        workdir: Path, 
        py_version: str = '3.7', 
        store_files: bool = False,
        n_threads: int = 10,
        max_mem_gb: Optional[int] = None,
        only_py_list: bool = False
    ):
        """
        Initialize the environment analyzer.
        
        Args:
            workdir: Working directory for package installation
            py_version: Python version to use for installation
            store_files: Whether to store package files
            n_threads: Number of threads for parallel processing
            max_mem_gb: Maximum memory per thread in GB
            only_py_list: Only collect Python file lists
        """
        self.workdir = Path(workdir)
        self.py_version = py_version
        self.store_files = store_files
        self.n_threads = n_threads
        self.only_py_list = only_py_list
        
        # Calculate memory allocation
        self.mem_per_thread_gb = self._calculate_memory_allocation(max_mem_gb, n_threads)
        self.mem_per_thread_kb = self.mem_per_thread_gb * 1024 * 1024
        
        # Docker setup
        self.image_tag = f"pyvul:py{self.py_version}"
        self.client = docker.from_env()
        
        logger.debug(f"Initializing EnvAnalyzer with Python {self.py_version}")
        self._build_docker_image()
    
    def _calculate_memory_allocation(self, max_mem_gb: Optional[int], n_threads: int) -> int:
        """Calculate memory allocation per thread."""
        if max_mem_gb:
            return max_mem_gb
        
        total_mem_gb = 188 if sys.platform != "darwin" else 32
        return max(1, int(total_mem_gb / (n_threads + 1)))
    
    def _build_docker_image(self) -> None:
        """Build the Docker image for package installation."""
        dockerfile_dir = self.workdir / "metadata"
        dockerfile_dir.mkdir(parents=True, exist_ok=True)
        
        dockerfile_content = f'FROM python:{self.py_version}\n'
        
        dockerfile_path = dockerfile_dir / "Dockerfile"
        dockerfile_path.write_text(dockerfile_content)
        
        try:
            self.client.images.build(
                path=str(dockerfile_dir),
                tag=self.image_tag,
                dockerfile="Dockerfile",
                forcerm=True,
                network_mode="host"
            )
            logger.debug("Docker image built successfully")
        except docker.errors.BuildError as e:
            logger.error(f"Failed to build Docker image: {e}")
            raise
    
    def get_package_structure(self, package: str, version: str, rewrite: bool = False) -> Optional[List[str]]:
        """
        Get the Python file structure of a package.
        
        Args:
            package: Package name
            version: Package version
            rewrite: Whether to rewrite existing results
            
        Returns:
            List of Python files or None if failed
        """
        package = package.strip()
        version = version.strip()
        
        package_dir = self.workdir / "pypi_packages_only_py_files" / package / version
        package_dir.mkdir(parents=True, exist_ok=True)
        
        py_files_list_file = package_dir / 'PY_FILES_LIST'
        
        # Check if already processed
        if py_files_list_file.exists() and not rewrite:
            py_files = py_files_list_file.read_text().strip().split('\n')
            if py_files and py_files[0]:  # Check for non-empty list
                return py_files
        
        # Check if previously attempted with this Python version
        if self._check_previous_attempts(package_dir):
            logger.debug(f"Package {package} {version} previously failed with {self.py_version}")
            return None
        
        logger.info(f'Getting package structure for {package} {version}')
        
        try:
            with tempfile.TemporaryDirectory() as tmp_dir:
                tmp_dir_path = Path(tmp_dir)
                success = self._install_package_structure(
                    package, version, tmp_dir_path, rewrite
                )
                
                if success:
                    tmp_py_files_file = tmp_dir_path / "pypi_packages" / package / version / 'PY_FILES_LIST'
                    if tmp_py_files_file.exists():
                        py_files = tmp_py_files_file.read_text().strip().split('\n')
                        if py_files and py_files[0]:
                            logger.debug(f"Package Structure Extracted successfully, stored in:{py_files_list_file}")
                            py_files_list_file.write_text('\n'.join(py_files))
                            (package_dir / 'INSTALLED_PY_VERSION').write_text(self.py_version)
                            self._cleanup_error_files(package_dir)
                            return py_files
                            
                
                # Handle failure
                self._handle_installation_failure(package_dir, tmp_dir_path / "pypi_packages" / package / version)
                
        except Exception as e:
            logger.error(f"Error processing {package} {version}: {e}")
        
        # Update attempted versions
        self._update_attempted_versions(package_dir)
        return None
    
    def _install_package_structure(self, package: str, version: str, workdir: Path, rewrite: bool) -> bool:
        """Install package and extract Python file structure."""
        package_dir = workdir / "pypi_packages" / package / version
        package_dir.mkdir(parents=True, exist_ok=True)
        
        package_name = normalize_package_name(package)
        container_workdir = "/root/pyvul"
        uid = os.getuid()
        gid = os.getgid()
        
        mount = docker.types.Mount(
            target=container_workdir,
            source=str(package_dir.absolute()),
            type="bind",
            read_only=False
        )
        
        timeout = 600  # 10 minutes
        index_option = " -i https://pypi.tuna.tsinghua.edu.cn/simple" if sys.platform == "darwin" else ""
        
        pip_command = (
            f"python -W ignore:DEPRECATION -m pip install "
            f"--target={container_workdir} --no-compile {package_name}=={version} "
            f"--no-deps --no-cache-dir --disable-pip-version-check{index_option}"
        )
        
        list_py_command = f"find {container_workdir} -mindepth 1 -type f -name '*.py' > {container_workdir}/PY_FILES_LIST"
        
        commands = [
            f"timeout {timeout} {pip_command} || touch {container_workdir}/ERROR",
            list_py_command,
            f"chown -R {uid}:{gid} {container_workdir}"
        ]
        
        command = " && ".join(commands)
        
        try:
            return self._run_docker_command(command, mount, package_dir, timeout)
        except Exception as e:
            logger.error(f"Docker execution failed for {package} {version}: {e}")
            (package_dir / 'ERROR').write_text(f"Docker execution failed: {str(e)}")
            return False
    
    def _check_previous_attempts(self, package_dir: Path) -> bool:
        """Check if package was previously attempted with current Python version."""
        tried_versions_file = package_dir / 'TRIED_PY_VERSION'
        if tried_versions_file.exists():
            tried_versions = tried_versions_file.read_text().strip().split('\n')
            return self.py_version in tried_versions
        return False
    
    def _update_attempted_versions(self, package_dir: Path) -> None:
        """Update the list of attempted Python versions."""
        tried_versions_file = package_dir / 'TRIED_PY_VERSION'
        tried_versions = []
        
        if tried_versions_file.exists():
            tried_versions = tried_versions_file.read_text().strip().split('\n')
        
        if self.py_version not in tried_versions:
            tried_versions.append(self.py_version)
            tried_versions_file.write_text('\n'.join(tried_versions))
    
    def _cleanup_error_files(self, package_dir: Path) -> None:
        """Remove error files after successful installation."""
        for error_file in ['ERROR', 'CHECK_LOG']:
            error_path = package_dir / error_file
            if error_path.exists():
                error_path.unlink()
    
    def _handle_installation_failure(self, package_dir: Path, tmp_package_dir: Path) -> None:
        """Handle installation failure by copying error files."""
        for error_file in ['ERROR', 'CHECK_LOG']:
            tmp_error_path = tmp_package_dir / error_file
            if tmp_error_path.exists():
                (package_dir / error_file).write_text(tmp_error_path.read_text())
    
    def install_package(self, package: str, version: str, rewrite: bool = False) -> InstallResult:
        """
        Install a package with dependencies.
        
        Args:
            package: Package name
            version: Package version
            rewrite: Whether to reinstall if already exists
            
        Returns:
            InstallResult object with installation status
        """
        package = package.strip()
        version = version.strip()
        
        if self._is_package_installed(package, version) and not rewrite:
            logger.info(f"Package {package} {version} already installed")
            return InstallResult(package, version, True, self.py_version)
        
        try:
            success = self._perform_installation(package, version, rewrite)
            self._update_attempted_versions(self.workdir / "pypi_packages" / package / version)
            
            if success:
                return InstallResult(package, version, True, self.py_version)
            else:
                return InstallResult(package, version, False, error_message="Installation failed")
                
        except Exception as e:
            logger.error(f"Error installing {package} {version}: {e}")
            return InstallResult(package, version, False, error_message=str(e))
    
    def _is_package_installed(self, package: str, version: str) -> bool:
        """Check if package is already successfully installed."""
        package_dir = self.workdir / "pypi_packages" / package / version
        
        if not package_dir.exists():
            return False
            
        # Check for error files
        if any((package_dir / error_file).exists() for error_file in ['HAVEERROR', 'ERROR']):
            return False
            
        # Check for installation markers
        required_files = ['INSTALLED_PY_VERSION', 'CHECK_LOG']
        return all((package_dir / req_file).exists() for req_file in required_files)
    
    def _perform_installation(self, package: str, version: str, rewrite: bool) -> bool:
        """Perform the actual package installation using Docker."""
        package_dir = self.workdir / "pypi_packages" / package / version
        package_dir.mkdir(parents=True, exist_ok=True)
        
        container_workdir = "/root/pyvul"
        uid = os.getuid()
        gid = os.getgid()
        
        mount = docker.types.Mount(
            target=container_workdir,
            source=str(package_dir.absolute()),
            type="bind",
            read_only=False
        )
        
        # Prepare installation commands
        timeout = 300  # 5 minutes
        package_name = normalize_package_name(package)
        
        index_option = " -i https://pypi.tuna.tsinghua.edu.cn/simple" if sys.platform == "darwin" else ""
        pip_command = (
            f"python -W ignore:DEPRECATION -m pip install "
            f"--target={container_workdir} --no-compile {package_name}=={version} "
            f"--no-cache-dir --disable-pip-version-check{index_option}"
        )
        
        commands = [
            f"rm -rf {container_workdir}/*",
            f"timeout {timeout} {pip_command} || touch {container_workdir}/HAVEERROR",
            f"chown -R {uid}:{gid} {container_workdir}"
        ]
        
        command = " && ".join(commands)
        
        try:
            logger.info(f"Installing {package} { version}")
            return self._run_docker_command(command, mount, package_dir, timeout)
        except Exception as e:
            logger.error(f"Docker execution failed for {package} {version}: {e}")
            (package_dir / 'ERROR').write_text(f"Docker execution failed: {str(e)}")
            return False
    
    def _run_docker_command(self, command: str, mount: docker.types.Mount, 
                           package_dir: Path, timeout: int) -> bool:
        """Run a command in Docker container."""
        try:
            container = self.client.containers.run(
                image=self.image_tag,
                command=["/bin/bash", "-c", command],
                detach=True,
                network_mode="host",
                mounts=[mount]
            )
            
            try:
                exit_code = container.wait(timeout=timeout + 100, condition='not-running')['StatusCode']
                
                # Save logs
                log = container.logs(stdout=True, stderr=True).decode('utf-8', errors='ignore')
                (package_dir / 'CHECK_LOG').write_text(log)
                
                # Check installation success
                if len(list(package_dir.iterdir())) <= 3:
                    (package_dir / 'HAVEERROR').touch()
                    return False
                
                success = not any((package_dir / error_file).exists() 
                                for error_file in ['ERROR', 'HAVEERROR'])
                
                if success:
                    (package_dir / 'INSTALLED_PY_VERSION').write_text(self.py_version)
                    logger.debug(f'Package installed successfully: {package_dir}')
                
                return success
                
            except Exception as e:
                logger.warning(f'Container operation failed: {e}')
                if container.status == 'running':
                    container.kill()
                return False
                
        finally:
            try:
                container.remove(v=True, force=True)
            except:
                pass
            gc.collect()
    
    @staticmethod
    def find_project_py_files(package: str, version: str, workdir: Path, 
                             container_workdir: str = "/root/pyvul/", 
                             verbose: int = 0) -> List[str]:
        """
        Find Python files in a project.
        
        Args:
            package: Package name
            version: Package version
            workdir: Working directory
            container_workdir: Container working directory
            verbose: Verbosity level
            
        Returns:
            List of Python file paths
        """
        package_dir = workdir / "pypi_packages_only_py_files" / package / version
        py_files_list_file = package_dir / 'PY_FILES_LIST'
        
        if not py_files_list_file.exists():
            if verbose:
                logger.warning(f"Not found {py_files_list_file}")
            return []
        
        try:
            py_files_list = py_files_list_file.read_text().strip().split('\n')
            filtered_files = [
                file for file in py_files_list 
                if file.endswith('.py') and is_source_code_file(file, EnvAnalyzer.EXCLUDE_DIRS)
            ]
            
            # Remove container workdir prefix
            filtered_files = [
                file.replace(container_workdir, '') for file in filtered_files
            ]
            
            return filtered_files
            
        except Exception as e:
            logger.error(f"Error reading Python files for {package} {version}: {e}")
            return []
    
    def cleanup_package(self, package: str, version: str) -> None:
        """Clean up package directory, keeping only essential files."""
        package_dir = self.workdir / "pypi_packages" / package / version
        
        if not package_dir.exists():
            return
        
        logger.debug(f"Cleaning up package {package} {version}")
        
        for item in package_dir.iterdir():
            if item.name not in self.KEEP_FILES:
                if item.is_dir():
                    import shutil
                    shutil.rmtree(item)
                else:
                    item.unlink()
    
    def close(self) -> None:
        """Clean up resources."""
        try:
            self.client.containers.prune()
        except Exception as e:
            logger.error(f"Failed to prune containers: {e}")
        finally:
            self.client.close()


class PackageMetadataCollector:
    """Collects metadata for packages from PyPI."""
    
    @staticmethod
    def get_python_version_info(package_name: str, package_version: str) -> Tuple[bool, Optional[PackageInfo]]:
        """
        Get Python version information for a package.
        
        Args:
            package_name: Name of the package
            package_version: Version of the package
            
        Returns:
            Tuple of (success, PackageInfo or None)
        """
        try:
            response = request_metadata_json_from_pypi(package_name, package_version)
            
            if response.status_code == 404:
                # logger.warning(f"Package '{package_name}' version={package_version} not found on PyPI")
                return False, None
            elif response.status_code != 200:
                # logger.error(f"PyPI request failed for {package_name} {package_version}: {response.status_code}")
                return False, None
            
            metadata = response.json()
            
            # Extract Python versions from classifiers
            py_versions = []
            topics = []
            
            for classifier in metadata['info']['classifiers']:
                if (classifier.startswith('Programming Language :: Python ::') and 
                    not classifier.startswith('Programming Language :: Python :: Implementation')):
                    version = classifier.replace(':: Only', '').split(' :: ')[-1]
                    py_versions.append(version)
                elif classifier.startswith('Topic ::'):
                    topics.append(classifier)
            
            # Sort Python versions
            py_versions = sorted(py_versions, key=lambda x: tuple(map(int, x.split('.'))))
            
            requires_python = metadata['info'].get('requires_python', '')
            name = metadata['info']['name']
            
            package_info = PackageInfo(
                name=name,
                version=package_version,
                py_versions=py_versions,
                requires_python=requires_python,
                topics=topics
            )
            
            return True, package_info
            
        except Exception as e:
            logger.error(f"Error getting metadata for {package_name} {package_version}: {e}")
            return False, None
    
    @staticmethod
    def collect_metadata_batch(packages: List[Tuple[str, str]], 
                              output_file: Path, 
                              n_jobs: int = 10) -> List[Tuple[str, str]]:
        """
        Collect metadata for multiple packages in parallel.
        
        Args:
            packages: List of (package, version) tuples
            output_file: File to save metadata
            n_jobs: Number of parallel jobs
            
        Returns:
            List of failed packages
        """
        # Load existing metadata
        existing_metadata = {}
        if output_file.exists():
            with open(output_file, 'r') as f:
                existing_metadata = json.load(f)
        
        # Filter packages that need processing
        packages_to_process = []
        for pkg, version in packages:
            if pkg not in existing_metadata or version not in existing_metadata[pkg]:
                packages_to_process.append((pkg, version))
        
        if not packages_to_process:
            logger.info("All packages already have metadata")
            return []
        
        logger.info(f"Collecting metadata for {len(packages_to_process)} packages")
        
        # Process in parallel
        results = Parallel(n_jobs=n_jobs)(
            delayed(PackageMetadataCollector.get_python_version_info)(pkg, version)
            for pkg, version in packages_to_process
        )
        
        failed_packages = []
        updated_metadata = defaultdict(dict, existing_metadata)
        
        for (pkg, version), (success, package_info) in zip(packages_to_process, results):
            if success and package_info:
                if pkg not in updated_metadata:
                    updated_metadata[pkg] = {}
                updated_metadata[pkg][version] = {
                    'py_versions': package_info.py_versions,
                    'requires_python': package_info.requires_python,
                    'name': package_info.name,
                    'topics': package_info.topics,
                }
            else:
                failed_packages.append((pkg, version))
        
        # Save updated metadata
        with open(output_file, 'w') as f:
            json.dump(dict(updated_metadata), f, indent=2)
        
        logger.info(f"Metadata collection complete. {len(failed_packages)} packages failed")
        return failed_packages


class JarvisCallGraphGenerator:
    """Generates call graphs using Jarvis tool."""
    
    @staticmethod
    def execute_jarvis(package: str, version: str, workdir: Path, 
                      max_mem_gb: Optional[int] = None, rewrite: bool = False) -> bool:
        """
        Execute Jarvis to generate call graph for a package.
        
        Args:
            package: Package name
            version: Package version
            workdir: Working directory
            max_mem_gb: Maximum memory in GB
            rewrite: Whether to rewrite existing results
            
        Returns:
            True if successful, False otherwise
        """
        package = package.strip()
        version = version.strip()
        
        jarvis_output_file = CALL_GRAPH_DIR_DATE / package / version / 'jarvis_cg.json'
        jarvis_output_dir = jarvis_output_file.parent
        jarvis_output_dir.mkdir(parents=True, exist_ok=True)
        
        # if jarvis_output_file.exists() and not rewrite:
        #     return True
        py_version = _check_package_installed(package, version, workdir)
        if not py_version:
            return False
        
        if (jarvis_output_dir / 'ERROR').exists() and not rewrite:
            logger.debug(f"{package} {version} has ERROR file and not rewrite, skip")
            return False
        
        py_files_list = EnvAnalyzer.find_project_py_files(package, version, workdir=workdir, verbose=1)
        
        if len(py_files_list) == 0:
            logger.warning(f"Not found any python files for {package} {version}")
            (jarvis_output_dir / 'ERROR').write_text('Not found any python files')
            return False
        elif len(py_files_list) > 500:
            (jarvis_output_dir / 'ERROR').write_text(f'Too Many python files {len(py_files_list)}')
            return False
        
        entry_files = ' '.join(py_files_list)
        logger.info(f"Executing jarvis for {package} {version} with {len(py_files_list)} files")
        
        external_abs_path = (workdir / "pypi_packages" / package / version).absolute()
        
        # Configure based on platform
        if sys.platform == 'darwin':
            jarvis_timeout = 300  # 5 minutes
            max_mem_gb = max_mem_gb or 8
            cmd = (
                f"timeout {jarvis_timeout}  jarvis-cli {entry_files} "
                f"--decy -o {jarvis_output_file} -ext {external_abs_path}"
            )
        else:
            jarvis_timeout = 1200  # 20 minutes
            max_mem_gb = max_mem_gb or 32
            cmd = (
                f"ulimit -v {max_mem_gb * 1024 * 1024} && "
                f"timeout {jarvis_timeout} jarvis-cli {entry_files} "
                f"--decy -o {jarvis_output_file} -ext {external_abs_path}"
            )
        try:
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                shell=True, 
                cwd=str(external_abs_path)
            )
            
            if result.returncode != 0:
                error_msg = f'Failed to run jarvis_cli.py {result.stderr}'
                if "memoryerror" in result.stderr.lower():
                    error_msg = f'MemoryError detected {max_mem_gb}G: {result.stderr}'
                    logger.error(f"MemoryError detected in jarvis_cli.py for {package} {version}")
                    return False

                
                (jarvis_output_dir / 'ERROR').write_text(error_msg)
                logger.error(f"Failed to run jarvis_cli.py for {package} {version}: {result.stderr}")
                return False

                
        except subprocess.TimeoutExpired as e:
            error_msg = f'{package} {version} Timeout after {e.timeout}s: {str(e)}'
            (jarvis_output_dir / 'ERROR').write_text(error_msg)
            logger.error(f"Jarvis execution timed out after {e.timeout} seconds")
            return False

            
        except OSError as e:
            error_msg = f'{package} {version} OSError: {str(e)}'
            if 'Argument list too long' in str(e):
                logger.error(f"Argument list too long for {package} {version}")
            (jarvis_output_dir / 'ERROR').write_text(error_msg)
            return False
        
        if not jarvis_output_file.exists():
            logger.warning(f"Jarvis execution failed for {package} {version}")
            return False
        
        logger.info(f"Jarvis execution successfully finished for {package} {version}")
        return True


def extract_python_versions_from_metadata(metadata: Dict[str, Any], 
                                         upstream_versions: Optional[List[str]] = None) -> List[str]:
    """
    Extract compatible Python versions from package metadata.
    
    Args:
        metadata: Package metadata dictionary
        upstream_versions: Optional list of upstream Python versions
        
    Returns:
        List of compatible Python versions
    """
    py_versions_from_classifiers = metadata.get('py_versions', [])
    requires_python = metadata.get('requires_python', '')
    
    compatible_versions = []
    def clean_requires_python(requires_python):
        if not requires_python:
            return requires_python
        
        # Remove problematic patterns
        cleaned = requires_python.replace('.*', '').replace('.,', ',').replace('.x', '').replace('*', '')
        
        # Remove quotes around version numbers
        cleaned = re.sub(r"['\"]", "", cleaned)
        
        # Clean up any double spaces or trailing/leading whitespace
        cleaned = re.sub(r'\s+', ' ', cleaned).strip()
        
        return cleaned
    if requires_python:
        # Handle requires_python specification
        cleaned_requires_python = clean_requires_python(requires_python)
        try:
            spec = SpecifierSet(cleaned_requires_python)
            
            if len(spec) == 1 and list(spec)[0].operator == '==':
                # Exact version requirement
                compatible_versions.append(list(spec)[0].version)
            else:
                # Check against available versions
                candidate_versions = (py_versions_from_classifiers or 
                                    upstream_versions or 
                                    EnvAnalyzer.CANDIDATE_PY_VERSIONS)
                
                for version in candidate_versions:
                    if spec.contains(version):
                        compatible_versions.append(version)
        except Exception as e:
            # logger.warning(f"Error parsing requires_python: '{requires_python}': {e}")
            compatible_versions = py_versions_from_classifiers
    else:
        compatible_versions = py_versions_from_classifiers
    
    # Filter out old/unsupported versions
    excluded_versions = {'3.3', '3.2', '3.1', '3.0', '3', 'empty'}
    compatible_versions = [
        v.strip() for v in compatible_versions 
        if v.strip() not in excluded_versions and not v.startswith('2')
    ]
    
    # Fallback to default versions if none found
    if not compatible_versions:
        if upstream_versions:
            compatible_versions = upstream_versions
        else:
            compatible_versions = EnvAnalyzer.CANDIDATE_PY_VERSIONS.copy()
    
    return compatible_versions


def filter_packages_for_processing(packages: List[Tuple[str, str]], 
                                  py_version: str, 
                                  workdir: Path, 
                                  include_memory_errors: bool = False) -> List[Tuple[str, str]]:
    """
    Filter packages that need processing based on current state.
    
    Args:
        packages: List of (package, version) tuples
        py_version: Python version to check
        workdir: Working directory
        include_memory_errors: Whether to include packages that failed with memory errors
        
    Returns:
        Filtered list of packages
    """
    filtered_packages = []
    
    for package, version in packages:
        package_dir = workdir / "pypi_packages" / package / version
        jarvis_output_file = CALL_GRAPH_DIR_DATE / package / version / 'jarvis_cg.json'
        jarvis_error_file = CALL_GRAPH_DIR_DATE / package / version / 'ERROR'
        
        # Skip if call graph already exists
        # if jarvis_output_file.exists():
        #     continue
            
        # Handle existing errors
        if jarvis_error_file.exists():
            if include_memory_errors:
                error_content = jarvis_error_file.read_text().strip()
                if 'memoryerror' not in error_content.lower():
                    continue
            else:
                continue
        # install_error_file = package_dir / 'HAVEERROR'
        # if install_error_file.exists():
        #     continue
        
        # Check attempted versions
        tried_versions_file = package_dir / 'TRIED_PY_VERSION'
        tried_versions = []
        
        if tried_versions_file.exists():
            tried_versions = tried_versions_file.read_text().strip().split('\n')
            tried_versions = [v.strip() for v in tried_versions if v.strip()]
        
        # Add to filtered list if not attempted or needs retry
        if not tried_versions or py_version not in tried_versions:
            filtered_packages.append((package, version))
        elif (package_dir / 'HAVEERROR').exists() or (package_dir / 'ERROR').exists():
            if py_version in tried_versions:
                continue
        elif py_version == tried_versions[-1] and not (CALL_GRAPH_DIR_DATE / package / version).exists():
            filtered_packages.append((package, version))
    
    return filtered_packages


def get_direct_and_indirect_dependents(all_dependents: Dict, package: str, version: str) -> Tuple[List, List]:
    """Get direct and indirect dependents for a package version."""
    direct = all_dependents.get(package, {}).get(version, {}).get('direct', [])
    indirect = all_dependents.get(package, {}).get(version, {}).get('indirect', [])
    return direct, indirect


def get_all_upstream_versions(cve_id: str, advisory: Dict, all_dependents: Dict) -> Dict[str, List[str]]:
    """Get all upstream versions that need to be downloaded for a CVE."""
    pkg2versions = defaultdict(list)
    
    for affected_version in advisory['affected']:
        upstream_package = affected_version['package']['name']
        versions = affected_version['versions']
        filtered_versions = filter_versions(upstream_package, versions)
        
        for upstream_version in versions:
            direct, indirect = get_direct_and_indirect_dependents(all_dependents, upstream_package, upstream_version)
            total_dependents_for_version = len(direct) + len(indirect)
        
            if len(direct) or len(indirect):
                pkg2versions[normalize_package_name(upstream_package)].append(upstream_version)
    
    return pkg2versions


def get_all_downstream_and_pairs(cve2advisory: Dict,  snapshot_dir: str, only_one_downstream_version: bool = False,) -> Tuple[Set, Dict]:
    """
    Get all downstream packages and CVE-package pairs.
    
    Args:
        cve2advisory: Dictionary mapping CVE IDs to advisory data
        only_one_downstream_version: If True, only keep latest version per downstream package
        
    Returns:
        Tuple of (all_downstream_packages, all_pairs)
    """
    all_downstream_install = set()
    all_pairs = defaultdict(dict)
    
    logger.info(f"Getting all downstream and upstream versions for {len(cve2advisory)} CVEs "
               f"with only_one_downstream_version={only_one_downstream_version}")
    all_upstream_versions_with_dependents = defaultdict(dict)
    vulnerable_packages = set()
        
    for cve_id, advisory in cve2advisory.items():
        available_affected = advisory.get('available_affected', {})
        for package_name, infos in available_affected.items():
            versions = infos['versions']
            for version in versions:
                vulnerable_packages.add((package_name, version))
        
        for upstream_pkg, upstream_version in vulnerable_packages:

            snapshot_file = snapshot_dir/f'{"@".join([ upstream_pkg,upstream_version])}'/'dependents.json'
            with open(snapshot_file, 'r') as f:
                all_dependents = json.load(f)
            all_upstream_versions_with_dependents[upstream_pkg][upstream_version] = all_dependents
        for upstream_package, upstream_versions in all_upstream_versions_with_dependents.items():
            for upstream_version,dependents in upstream_versions.items():
                direct = dependents['direct']
                indirect = dependents['indirect']
                
                all_downstream = direct + indirect
                if len(all_downstream) ==0:
                    continue
                all_pairs[cve_id][(upstream_package, upstream_version)] = None
                
                if only_one_downstream_version:
                    # Group by package and keep only latest version
                    downstream2versions = defaultdict(list)
                    for pkg, version in all_downstream:
                        downstream2versions[pkg].append(version)
                    
                    new_all_downstream = []
                    for pkg, versions in downstream2versions.items():
                        # Sort versions and keep the latest
                        versions = sorted(versions, key=lambda x: version_key(x), reverse=False)
                        new_all_downstream.append((pkg, versions[-1]))
                    all_downstream = new_all_downstream
                
                all_downstream_install.update(all_downstream)
                all_pairs[cve_id][(upstream_package, upstream_version)] = all_downstream
    
    return all_downstream_install, all_pairs


def generate_install_tasks(all_pairs: Dict, workdir: Path, metadata_file: Path, 
                          metadata_file_for_upstream: Path, install_tasks_file: Path,
                          install_tasks_file_for_upstream: Path, rewrite: bool = False) -> None:
    """
    Generate installation tasks based on CVE pairs and metadata.
    
    Args:
        all_pairs: Dictionary of CVE to package pairs
        workdir: Working directory
        metadata_file: Downstream metadata file
        metadata_file_for_upstream: Upstream metadata file
        install_tasks_file: Output file for downstream tasks
        install_tasks_file_for_upstream: Output file for upstream tasks
        rewrite: Whether to rewrite existing files
    """
    workdir.mkdir(parents=True, exist_ok=True)
    
    if not rewrite and install_tasks_file.exists() and install_tasks_file_for_upstream.exists():
        return
    
    # Load metadata
    if not metadata_file.exists() or not metadata_file_for_upstream.exists():
        raise FileNotFoundError("Metadata files not found")
    
    with open(metadata_file, 'r') as f:
        all_metadata = json.load(f)
    
    with open(metadata_file_for_upstream, 'r') as f:
        all_metadata_for_upstream = json.load(f)
    
    install_tasks_for_upstream = defaultdict(list)
    install_tasks_for_downstream = defaultdict(list)
    
    for cve_id in tqdm(all_pairs):
        for upstream, downstreams in all_pairs[cve_id].items():
            up_package, up_version = upstream
            up_metadata = all_metadata_for_upstream.get(up_package, {}).get(up_version, None)
            
            if up_metadata is None:
                logger.warning(f"{up_package} {up_version} not in metadata")
                continue
            
            up_py_versions = extract_python_versions_from_metadata(up_metadata)
            for py_version in up_py_versions:
                py_version = py_version.strip()
                install_tasks_for_upstream[py_version].append(upstream)
            
            for downstream in downstreams:
                down_package, down_version = downstream
                down_metadata = all_metadata.get(down_package, {}).get(down_version, None)
                
                if down_metadata is None:
                    continue
                
                down_py_versions = extract_python_versions_from_metadata(down_metadata, up_py_versions)
                
                for py_version in down_py_versions:
                    py_version = py_version.strip()
                    if downstream not in install_tasks_for_downstream[py_version]:
                        install_tasks_for_downstream[py_version].append(downstream)
    
    # Sort by version
    install_tasks_for_upstream = dict(sorted(install_tasks_for_upstream.items(), 
                                           key=lambda x: version_key(x[0]), reverse=True))
    install_tasks_for_downstream = dict(sorted(install_tasks_for_downstream.items(), 
                                             key=lambda x: version_key(x[0]), reverse=True))
    
    with open(install_tasks_file, 'w') as f:
        json.dump(install_tasks_for_downstream, f, indent=2)
    
    with open(install_tasks_file_for_upstream, 'w') as f:
        json.dump(install_tasks_for_upstream, f, indent=2)


def install_packages_with_version_control(install_tasks: Dict, workdir: Path, 
                                        metadata_file: Path, install_tasks_list: Optional[List] = None,
                                        only_py_list: bool = False, save_installed: bool = False,
                                        n_threads_cg: Optional[int] = None, max_mem_gb: Optional[int] = None,
                                        mem_out_task: bool = False) -> None:
    """
    Install packages with version control and parallel processing.
    
    Args:
        install_tasks: Dictionary of Python version to package lists
        workdir: Working directory
        metadata_file: Metadata file path
        install_tasks_list: Optional list to filter tasks
        only_py_list: Only collect Python file lists
        save_installed: Save installation status
        n_threads_cg: Number of threads for call graph generation
        max_mem_gb: Maximum memory per thread
        mem_out_task: Whether this is a memory-out retry task
    """

    # Configure threading based on platform
    if sys.platform == 'darwin':
        n_threads_cg = 2
        max_mem_gb = 8
        n_threads_install = 2
    else:
        n_threads_cg = n_threads_cg or 8
        n_threads_install = 15
        max_mem_gb = max_mem_gb or 32
    for py_version, packages in install_tasks.items():
        py_version = py_version.strip()
        # Skip unsupported versions
        if py_version == '3.14':
            logger.warning("Docker fails because there's no official Python 3.14 image available")
            continue
        
        if py_version.startswith('2') or py_version == 'empty':
            continue
        
        # Filter packages if list provided
        if install_tasks_list:
            packages = [pkg for pkg in packages if tuple(pkg) in install_tasks_list or pkg in install_tasks_list]
        
        if not packages:
            continue
        
        analyzer_install = None

        
        try:
            if not only_py_list:
                batch_size = 2
                
                if not mem_out_task:
                    filtered_packages = filter_packages_for_processing(
                        packages=packages, py_version=py_version, workdir=workdir
                    )
                else:
                    filtered_packages = packages
                
                logger.info(f'Processing {len(packages)} packages under Python {py_version}, '
                           f'{len(packages) - len(filtered_packages)} filtered, '
                           f'{len(filtered_packages)} to process')
                
                if not filtered_packages:
                    continue
                
                analyzer_install = EnvAnalyzer(
                    workdir, py_version=py_version, n_threads=n_threads_install, 
                    max_mem_gb=None, only_py_list=only_py_list
                )
                
                # Process in batches
                for i in range(0, len(filtered_packages), batch_size):
                    batch_packages = filtered_packages[i:i+batch_size]
                    
                    # Install packages
                    with ThreadPoolExecutor(max_workers=n_threads_install) as executor:
                        install_futures = [
                            executor.submit(analyzer_install.install_package, pkg, version, mem_out_task)
                            for pkg, version in batch_packages
                        ]
                        
                        for future in as_completed(install_futures):
                            try:
                                result = future.result()
                                if not result.success:
                                    logger.warning(f"Installation failed: {result.package} {result.version}")
                                    # print(f"❌ Installation failed: {result.package} {result.version}")
                                else:
                                    logger.debug(f"Installation success: {result.package} {result.version}")
                                    # print(f"✅ Installation success: {result.package} {result.version}")

                                    
                                    
                            except Exception as e:
                                logger.error(f"Installation error: {e}")
                    
                    # Generate call graphs
                    with ThreadPoolExecutor(max_workers=n_threads_cg) as executor:
                        cg_futures = [
                            executor.submit(JarvisCallGraphGenerator.execute_jarvis, 
                                          pkg, version, workdir, max_mem_gb)
                            for pkg, version in batch_packages
                        ]
                        
                        for future in as_completed(cg_futures):
                            try:
                                result = future.result()
                            except Exception as e:
                                logger.error(f"Call graph generation error: {e}")
                    
                    # Cleanup
                    # _cleanup_batch_packages(workdir, batch_packages)
            
            else:
                # Only collect Python file structure
                filtered_packages = [
                    pkg for pkg in packages 
                    if not EnvAnalyzer.find_project_py_files(pkg[0], pkg[1], workdir=workdir)
                ]
                
                if not filtered_packages:
                    continue
                
                analyzer_install = EnvAnalyzer(
                    workdir, py_version=py_version, n_threads=n_threads_install, 
                    max_mem_gb=None, only_py_list=only_py_list
                )
                
                with ThreadPoolExecutor(max_workers=n_threads_install) as executor:
                    futures = [
                        executor.submit(analyzer_install.get_package_structure, pkg, version)
                        for pkg, version in filtered_packages
                    ]
                    
                    for future in as_completed(futures):
                        try:
                            result = future.result()
                        except Exception as e:
                            logger.error(f"Structure collection error: {e}")
        
        except docker.errors.BuildError:
            logger.warning(f"Failed to create analyzer for python version {py_version}")

            continue
        except Exception as e:
            logger.error(f"Unexpected error processing Python {py_version}: {e}")
            raise

        finally:
            if analyzer_install:
                analyzer_install.close()
    
    if save_installed:
        _store_installed_packages(metadata_file, workdir)


def _cleanup_batch_packages(workdir: Path, packages: List[Tuple[str, str]]) -> None:
    """Clean up a batch of packages after processing."""
    total_size = 0
    
    for package, version in packages:
        package_dir = workdir / "pypi_packages" / package / version
        
        if package_dir.exists() and package_dir.is_dir():
            # Calculate directory size
            dir_size = sum(
                os.path.getsize(os.path.join(dirpath, filename))
                for dirpath, dirnames, filenames in os.walk(package_dir)
                for filename in filenames
            )
            total_size += dir_size / (1024 * 1024 * 1024)  # Convert to GB
        _cleanup_single_package(package, version, workdir)
    
    logger.info(f'Cleaned up {round(total_size, 2)}GB')


def _cleanup_single_package(package: str, version: str, workdir: Path) -> None:
    """Clean up a single package directory."""
    package_dir = workdir / "pypi_packages" / package / version
    
    if not package_dir.exists():
        return
    
    logger.debug(f"Cleaning up package {package} {version}")
    
    for item in package_dir.iterdir():
        if item.name not in EnvAnalyzer.KEEP_FILES:
            if item.is_dir():
                import shutil
                shutil.rmtree(item)
            else:
                item.unlink()


def _store_installed_packages(metadata_file: Path, workdir: Path) -> None:
    """Store information about successfully installed packages."""
    metadata_installed_file = metadata_file.parent / metadata_file.name.replace('.json', '_installed.json')
    
    with open(metadata_file, 'r') as f:
        all_metadata = json.load(f)
    
    installed_cnt = 0
    
    for package, versions in all_metadata.items():
        for version in versions:
            if all_metadata[package][version].get('installed_py_version', None):
                installed_cnt += 1
                continue
            
            py_version = _check_package_installed(package, version, workdir)
            if py_version:
                all_metadata[package][version]['installed_py_version'] = py_version
                installed_cnt += 1
            else:
                all_metadata[package][version]['installed_py_version'] = None
    
    with open(metadata_installed_file, 'w') as f:
        json.dump(all_metadata, f, indent=2)
    
    logger.info(f"Installed {installed_cnt} packages")


def _check_package_installed(package: str, version: str, workdir: Path) -> Optional[str]:
    """Check if a package is successfully installed and return Python version."""
    package_dir = workdir / "pypi_packages" / package / version
    
    if not package_dir.exists():
        return None
    
    # Check for error files
    if any((package_dir / error_file).exists() for error_file in ['HAVEERROR', 'ERROR']):
        return None
    
    # Check for required files
    required_files = ['INSTALLED_PY_VERSION', 'CHECK_LOG']
    if not all((package_dir / req_file).exists() for req_file in required_files):
        return None
    
    # Return installed Python version
    try:
        return (package_dir / 'INSTALLED_PY_VERSION').read_text().strip()
    except:
        return None


def get_memory_out_tasks(packages_with_py_files: List[Tuple[str, str]], 
                        workdir: Path, max_mem: int = 32) -> Dict[str, List[Tuple[str, str]]]:
    """
    Get packages that failed due to memory errors for retry with more memory.
    
    Args:
        packages_with_py_files: List of packages with Python files
        workdir: Working directory
        max_mem: Maximum memory previously used
        
    Returns:
        Dictionary of Python version to packages that need memory retry
    """
    memory_out_tasks = defaultdict(list)
    
    for pkg, version in packages_with_py_files:
        jarvis_error_file = CALL_GRAPH_DIR_DATE / pkg / version / 'ERROR'
        
        if jarvis_error_file.exists():
            error_content = jarvis_error_file.read_text()
            
            if 'MemoryError' in error_content:
                pre_max_mem = extract_memory_size(error_content)
                
                if not pre_max_mem or pre_max_mem < max_mem:
                    py_version_file = workdir / "pypi_packages" / pkg / version / 'INSTALLED_PY_VERSION'
                    
                    if py_version_file.exists():
                        py_version = py_version_file.read_text().strip()
                        memory_out_tasks[py_version].append((pkg, version))
    
    return memory_out_tasks

def normalize_package_funcs(all_pairs,all_upstream_with_py_file,all_downstream_with_py_file,workdir,rewrite):
    def remove_first_prefix(name: str) -> str:
        for prefix in PREFIXES:
            if name.startswith(prefix):
                return name[len(prefix):]
        return name
    PREFIXES = ('src.', 'lib.', 'python.', 'pysrc.', 'Lib.', 'pylib.', 
            'python3.', 'master.', 'lib3.')
    all_upstream_filtered = []
    all_downstream_filtered = []
    all_pairs_filtered = defaultdict(dict)
    pkg2repo_file = PROJECT_ROOT / "src/pkg2repo.json"
    with pkg2repo_file.open('r') as f:
        pkg2repo_mapping = json.load(f)
    for cve_id, cve_data in all_pairs.items():
        
        for upstream, all_downstream in cve_data.items():
            pkg,version = upstream
            if upstream not in all_upstream_with_py_file:
                continue
            repo_url = pkg2repo_mapping[pkg]
            repo_name = get_repo_name(repo_url)
            code_changes_path = CODE_CHANGES_DIR_DATE / f'{cve_id}_{repo_name}.json'
            code_changes_dict_path = CODE_CHANGES_DIR_DATE / f'{cve_id}_{repo_name}_dict.pkl'
            
            if not code_changes_path.exists():
                continue
            
            normalized_vulnerable_funcs_file = CODE_CHANGES_DIR_DATE / f'{cve_id}_{repo_name}_{"_".join(upstream)}_normalized.json'
            
            
            if normalized_vulnerable_funcs_file.exists() and not rewrite:
                with normalized_vulnerable_funcs_file.open('r') as f:
                    normalized_vulnerable_funcs = json.load(f)
            else:
                with code_changes_path.open('r') as f:
                    code_changes = json.load(f)
                vulnerable_funcs = list()
                for _, file2methods in code_changes.items():
                    vulnerable_funcs.extend(list(set(chain.from_iterable(file2methods.values()))))
                if len(vulnerable_funcs)==0:
                    continue
                
                normalized_vulnerable_funcs = [
                            (full_name.split('.')[-1], remove_first_prefix(full_name))
                            for full_name in vulnerable_funcs
                        ]
                print(normalized_vulnerable_funcs_file)
                with normalized_vulnerable_funcs_file.open('w') as f:
                    json.dump(normalized_vulnerable_funcs, f)
            
            
            
            if (pkg,version) in all_upstream_with_py_file: 
                        
                # Find Python files in the package
                filtered_python_files = EnvAnalyzer.find_project_py_files(
                    pkg, version, workdir=workdir
                )
                if not filtered_python_files:
                    logger.warning(f"No Python files found for {upstream}")
                
                upstream_modules = get_modules_from_py_files(pkg, version, filtered_python_files)
                normalized_funcs = []
                
                # Match functions to modules
                for func, full_name in normalized_vulnerable_funcs:
                    find_match = None
                    func_ns = '.'.join(full_name.split('.')[:-1])
                    # 1. Exact match: function name starts with module.
                    for module in upstream_modules:
                        if full_name.startswith(f"{module}."):
                            find_match = module
                            break
                    # 3. Loose match: function name contains .module. or module.endswith(func_ns)
                    if not find_match:
                        for module in upstream_modules:
                            if f".{module}." in full_name or module.endswith(func_ns):
                                find_match = module
                                break
                        
                    if find_match:
                        normalized_funcs.append((func, full_name))
                
                if not normalized_funcs:
                    logger.warning(f"No vulnerable functions found in {upstream}")
                # logger.debug(f"normalized_funcs:{ normalized_funcs}")
                if normalized_funcs and upstream_modules:
                    all_upstream_filtered.append(upstream)
                    
                    all_downstream_filtered.extend([down for down in all_downstream if down in all_downstream_with_py_file])
                    all_pairs_filtered[cve_id][upstream]=all_downstream_filtered
                    logger.info(f"Kept upstream {upstream} with {len(normalized_funcs)} normalized functions")
                else:
                    logger.info(f"Filtered out upstream {upstream} - no valid normalized functions")
    return all_upstream_filtered, all_downstream_filtered, all_pairs_filtered
    
def create_parser():
    """
    Create command line argument parser for package installation and analysis.
    """
    parser = argparse.ArgumentParser(
        description='Package Installation and Vulnerability Analysis Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python install_pkg.py --cve CVE-2023-24580 CVE-2020-13757 
  python install_pkg.py --package Django Flask --force-update
        """
    )
    
    # CVE and package analysis options
    parser.add_argument(
        '--cve',
        type=str,
        nargs='*',
        help='Specific CVE IDs to analyze (supports multiple CVEs)'
    )
    
    parser.add_argument(
        '--package',
        type=str,
        nargs='*',
        help='Specific package names to analyze (supports multiple packages)'
    )
    
    parser.add_argument(
        '--analyze-all',
        action='store_true',
        help='Analyze all CVEs and packages in the dataset'
    )
    
    # Configuration options
    parser.add_argument(
        '--size', 
        type=int, 
        default=6,
        help='Dataset size to process (default: 6)'
    )
    parser.add_argument(
        '--workdir', 
        type=Path, 
        default=Path('../docker_workdir_new'),
        help='Working directory for package installation (default: ../docker_workdir_new)'
    )
    
    parser.add_argument(
        '--snapshot-dir', 
        type=Path, 
        default=DATA_DIR/SUFFIX/'snapshots/0927',
        help='Snapshot directory containing dependency graphs'
    )
    
    parser.add_argument(
        '--threads', 
        type=int, 
        default=10,
        help='Number of threads for parallel processing (default: 10)'
    )
    
    parser.add_argument(
        '--memory', 
        type=int, 
        help='Max memory per thread in GB'
    )

    
    parser.add_argument(
        '--force-update',
        action='store_true',
        help='Force update of existing analysis results, ignore cache'
    )
    
    parser.add_argument(
        '--save-installed',
        action='store_true',
        help='Save information about successfully installed packages'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose output for debugging'
    )
    
    return parser


def main():
    """Main processing function."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Handle legacy argument name
    args.use_cache = not args.force_update
    
    # Initialize rewrite parameters based on force_update
    if args.force_update:
        # When force_update is True, all rewrite parameters should be True
        args.rewrite_structure = True
        args.rewrite_metadata = True
        args.rewrite_installation_tasks = True
        args.rewrite_call_graphs = True
    else:
        args.rewrite_structure = False
        args.rewrite_metadata = False
        args.rewrite_installation_tasks = False
        args.rewrite_call_graphs = False
    # Setup working directory
    args.workdir.mkdir(parents=True, exist_ok=True)
    print(f"📁 Working directory: {args.workdir}")
    
    output_dir = DATA_DIR/SUFFIX
    cvf_output_file = output_dir / "cve2advisory_enhanced.pkl"
    print(f"📊 Loading CVE data from: {cvf_output_file}")
    with cvf_output_file.open('rb') as f:
        cve2advisory = pickle.load(f)
    
    print(f"✅ Loaded {len(cve2advisory)} CVEs from advisory file")
    
    # Filter CVEs if specific ones are requested
    if args.cve:
        print(f"🔍 Filtering for specific CVEs: {args.cve}")
        filtered_cve2advisory = {}
        for cve_id in args.cve:
            if cve_id in cve2advisory:
                filtered_cve2advisory[cve_id] = cve2advisory[cve_id]
                print(f"  ✅ Found CVE: {cve_id}")
            else:
                print(f"  ❌ CVE not found: {cve_id}")
        cve2advisory = filtered_cve2advisory
        print(f"📋 Filtered to {len(cve2advisory)} CVEs")
    
    # Configure file paths based on dataset size
    install_tasks_file = args.workdir / 'install_tasks.json'
    install_tasks_file_for_upstream = args.workdir / 'install_tasks_for_upstream.json'
    pairs_cache_file = args.workdir / 'get_all_downstream_and_pairs_results.pkl'
    metadata_file_for_upstream = Path('./all_metadata_file_for_upstream.json')
    metadata_file = Path('./all_metadata.json')
    failed_pkgs_cache_file = args.workdir / 'failed_pkgs.pkl'
    pkg_with_py_file_cache_file = args.workdir / 'all_pkgs_with_py_file.pkl'
    
    # Apply dataset size filtering if not analyzing specific CVEs
    if not args.cve and not args.analyze_all:
        samples = list(cve2advisory.keys())[:args.size]  # Use small sample for testing
        cve2advisory = {k: v for k, v in cve2advisory.items() if k in samples}
        print(f"📊 Using {args.size} dataset size - processing {len(cve2advisory)} CVEs")
    
    logger.info(f"Processing {len(cve2advisory)} CVEs with {args.size} dataset")
    
    # Step 1: Get all downstream and upstream packages
    print("\n🔄 Step 1: Analyzing downstream and upstream package relationships")
    if pairs_cache_file.exists() and not args.rewrite_metadata:
        print("📂 Loading cached downstream and pairs data")
        logger.info("Loading cached downstream and pairs data")
        with open(pairs_cache_file, 'rb') as f:
            all_downstream, all_pairs = pickle.load(f)
    else:
        print("🔍 Generating downstream and pairs data from dependency graphs")
        logger.info("Generating downstream and pairs data")
        all_downstream, all_pairs = get_all_downstream_and_pairs(cve2advisory, only_one_downstream_version=True,snapshot_dir=args.snapshot_dir)
        print(f"💾 Saving pairs data to cache: {pairs_cache_file}")
        with open(pairs_cache_file, 'wb') as f:
            pickle.dump((all_downstream, all_pairs), f)
    
    all_upstream = list(set(chain.from_iterable(all_pairs.values())))
    print(f"📊 Found {len(all_downstream)} downstream packages and {len(all_upstream)} upstream packages")
    print(f"🔗 Total CVE-package pairs: {sum(len(pairs) for pairs in all_pairs.values())}")
    
    # Filter packages if specific ones are requested
    if args.package:
        print(f"\n🔍 Filtering for specific packages: {args.package}")
        original_downstream_count = len(all_downstream)
        original_upstream_count = len(all_upstream)
        
        # Filter downstream packages
        all_downstream = [(pkg, ver) for pkg, ver in all_downstream if pkg in args.package]
        # Filter upstream packages  
        all_upstream = [(pkg, ver) for pkg, ver in all_upstream if pkg in args.package]
        # Filter pairs
        filtered_pairs = {}
        for cve_id, pairs in all_pairs.items():
            filtered_pairs[cve_id] = [(pkg, ver) for pkg, ver in pairs if pkg in args.package]
        all_pairs = {k: v for k, v in filtered_pairs.items() if v}  # Remove empty pairs
        
        print(f"📋 Package filtering results:")
        print(f"  Downstream: {original_downstream_count} → {len(all_downstream)}")
        print(f"  Upstream: {original_upstream_count} → {len(all_upstream)}")
        print(f"  CVE pairs: {len(filtered_pairs)} → {len(all_pairs)}")

    # Step 2: Collect metadata
    print(f'\n🔄 Step 2: Collecting metadata for packages')
    print(f'📦 Target packages: {len(all_upstream)} upstream, {len(all_downstream)} downstream')
    logger.info(f'Collecting metadata for {len(all_upstream)} upstream packages '
               f'with {len(all_downstream)} downstream packages')
    
    if failed_pkgs_cache_file.exists() and metadata_file.exists() and not args.rewrite_metadata:
        print("📂 Loading cached metadata results")
        logger.info("Loading cached metadata results")
        with open(failed_pkgs_cache_file, 'rb') as f:
            failed_downstream, failed_upstream = pickle.load(f)
    else:
        print("🔍 Collecting package metadata from PyPI")
        logger.info("Collecting package metadata")
        print(f"  📥 Processing {len(all_downstream)} downstream packages...")
        failed_downstream = PackageMetadataCollector.collect_metadata_batch(
            packages=list(all_downstream), output_file=metadata_file
        )
        print(f"  📥 Processing {len(all_upstream)} upstream packages...")
        failed_upstream = PackageMetadataCollector.collect_metadata_batch(
            packages=list(all_upstream), output_file=metadata_file_for_upstream
        )
        print(f"💾 Saving failed packages cache to: {failed_pkgs_cache_file}")
        with open(failed_pkgs_cache_file, 'wb') as f:
            pickle.dump((failed_downstream, failed_upstream), f)
    
    # Filter out failed packages
    print(f"🧹 Filtering out failed packages:")
    print(f"  ❌ Failed upstream: {len(failed_upstream)}")
    print(f"  ❌ Failed downstream: {len(failed_downstream)}")
    all_downstream = [pkg for pkg in all_downstream if pkg not in failed_downstream]
    all_upstream = [pkg for pkg in all_upstream if pkg not in failed_upstream]
    
    print(f'✅ Successfully collected metadata:')
    print(f'  📦 Upstream packages: {len(all_upstream)}')
    print(f'  📦 Downstream packages: {len(all_downstream)}')
    logger.info(f'Successfully collected metadata for {len(all_upstream)} upstream '
               f'and {len(all_downstream)} downstream packages')
    # Step 3: Generate installation tasks
    print(f'\n🔄 Step 3: Generating installation tasks')
    if not (install_tasks_file.exists() and install_tasks_file_for_upstream.exists()) or args.rewrite_installation_tasks:
        print("🔧 Generating new installation tasks")
        logger.info("Generating installation tasks")
        generate_install_tasks(
            all_pairs=all_pairs, 
            workdir=args.workdir, 
            metadata_file=metadata_file, 
            install_tasks_file=install_tasks_file,
            metadata_file_for_upstream=metadata_file_for_upstream,
            install_tasks_file_for_upstream=install_tasks_file_for_upstream,
            rewrite=not args.use_cache
        )
        print(f"💾 Installation tasks saved to:")
        print(f"  📄 Downstream: {install_tasks_file}")
        print(f"  📄 Upstream: {install_tasks_file_for_upstream}")
    else:
        print("📂 Loading cached installation tasks")
    
    print("📖 Reading installation task files")
    with open(install_tasks_file, 'r') as f:
        install_tasks_for_downstream = json.load(f)
    with open(install_tasks_file_for_upstream, 'r') as f:
        install_tasks_for_upstream = json.load(f)
    
    downstream_task_count = sum(len(tasks) for tasks in install_tasks_for_downstream.values())
    upstream_task_count = sum(len(tasks) for tasks in install_tasks_for_upstream.values())
    
    print("📊 Installation tasks summary:")
    print(f"  📦 Downstream: {downstream_task_count} total tasks")
    print(f"  📦 Upstream: {upstream_task_count} total tasks")
    logger.info("Installation tasks summary:")
    logger.info(f"Downstream: {downstream_task_count} total tasks")
    logger.info(f"Upstream: {upstream_task_count} total tasks")
    # Step 4: Collect Python file structures
    print(f'\n🔄 Step 4: Collecting Python file structures')
    if pkg_with_py_file_cache_file.exists() and not args.rewrite_structure:
        print("📂 Loading cached Python file data")
        logger.info("Loading cached Python file data")
        with open(pkg_with_py_file_cache_file, 'rb') as f:
            all_downstream_with_py_file, all_upstream_with_py_file = pickle.load(f)
    else:
        print("🐍 Collecting Python file structures for packages")
        print(f"  📦 Processing {len(all_upstream)} upstream packages...")
        logger.info("Collecting Python file structures for all_upstream")
        # Install structure-only for upstream packages
        install_packages_with_version_control(
            install_tasks_for_upstream, args.workdir, metadata_file_for_upstream,
            install_tasks_list=all_upstream, only_py_list=True
        )
        print(f"  📦 Processing {len(all_downstream)} downstream packages...")
        logger.info("Collecting Python file structures for all_downstream")
        
        # Install structure-only for downstream packages
        install_packages_with_version_control(
            install_tasks_for_downstream, args.workdir, metadata_file,
            install_tasks_list=all_downstream, only_py_list=True
        )
        
        # Filter packages with Python files
        print("🔍 Filtering packages that contain Python files...")
        all_downstream_with_py_file = [
            (pkg, version) for pkg, version in all_downstream 
            if EnvAnalyzer.find_project_py_files(pkg, version, workdir=args.workdir)
        ]
        all_upstream_with_py_file = [
            (pkg, version) for pkg, version in all_upstream 
            if EnvAnalyzer.find_project_py_files(pkg, version, workdir=args.workdir)
        ]
        
        print(f"💾 Saving Python file data to cache: {pkg_with_py_file_cache_file}")
        with open(pkg_with_py_file_cache_file, 'wb') as f:
            pickle.dump((all_downstream_with_py_file, all_upstream_with_py_file), f)
    
    print(f"🐍 Packages with Python files:")
    print(f"  📦 Upstream: {len(all_upstream_with_py_file)}/{len(all_upstream)}")
    print(f"  📦 Downstream: {len(all_downstream_with_py_file)}/{len(all_downstream)}")
    logger.info(f"Packages with Python files:")
    logger.info(f"Upstream: {len(all_upstream_with_py_file)}/{len(all_upstream)}")
    logger.info(f"Downstream: {len(all_downstream_with_py_file)}/{len(all_downstream)}")
    
    # Filter upstream packages based on normalization results
    print(f'\n🔄 Step 5: Normalizing package functions and filtering')
    all_upstream_filtered_with_py_file ,all_downstream_filtered_with_py_file, all_pairs_filtered= normalize_package_funcs(all_pairs,all_upstream_with_py_file,all_downstream_with_py_file,args.workdir, not args.use_cache)
    print(f"📊 Filtering results:")
    print(f"  📦 Upstream filtered: {len(all_upstream_filtered_with_py_file)}")
    print(f"  📦 Downstream filtered: {len(all_downstream_filtered_with_py_file)}")
    print(f"  🔗 Filtered CVE pairs: {len(all_pairs_filtered)}")
    
    print(f"💾 Saving filtered pairs to: {args.workdir / 'filtered_pairs.pkl'}")
    with (args.workdir / 'filtered_pairs.pkl').open('wb') as f:
        pickle.dump(all_pairs_filtered,f)
    
    # Step 5: Full installation with dependencies
    print(f'\n🔄 Step 6: Full package installation with dependencies')
    logger.info("Starting full package installation with dependencies")
    install_packages_with_version_control(
        install_tasks_for_downstream, args.workdir, metadata_file,
        install_tasks_list=all_downstream_filtered_with_py_file, only_py_list=False, 
        save_installed=True
    )
    
    print("✅ Processing complete!")
    logger.info("Processing complete!")


if __name__ == '__main__':
    main()