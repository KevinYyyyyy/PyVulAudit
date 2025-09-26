# docker_container_pool.py
import docker
import logging
from typing import Optional, Dict, List
from threading import Lock
import time

from logger import logger

class ContainerPool:
    def __init__(self, image_tag: str, pool_size: int = 5, max_retries: int = 3):
        self.image_tag = image_tag
        self.pool_size = pool_size
        self.max_retries = max_retries
        self.client = docker.from_env()
        
        # 容器池状态
        self.available_containers: List[str] = []
        self.in_use_containers: Dict[str, docker.models.containers.Container] = {}
        self.lock = Lock()
        

        
        # 初始化容器池
        self._init_pool()

    
    def _init_pool(self) -> None:
        """初始化容器池"""
        for i in range(self.pool_size):
            try:
                container = self._create_container()
                self.available_containers.append(container.id)
                logger.info(f"Created container {container.id[:12]}")
            except Exception as e:
                logger.error(f"Failed to create container: {e}")
    
    def _create_container(self) -> docker.models.containers.Container:
        """创建一个新的容器"""
        return self.client.containers.run(
            image=self.image_tag,
            command=["tail", "-f", "/dev/null"],  # 保持容器运行
            detach=True,
            network_mode="host",
            mounts=[
            ],
            mem_limit="34g",  # 限制内存使用
            privileged=True
            # cpu_count=    # 限制CPU使用
        )
    
    def get_container(self, timeout: int = 60*5) -> Optional[docker.models.containers.Container]:
        """获取一个可用的容器，如果没有可用容器则等待"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            with self.lock:
                if self.available_containers:
                    container_id = self.available_containers.pop(0)
                    try:
                        container = self.client.containers.get(container_id)
                        if container.status != "running":
                            container.start()
                        self.in_use_containers[container_id] = container
                        return container
                    except Exception as e:
                        logger.error(f"Failed to get container {container_id[:12]}: {e}")
                        continue
            time.sleep(1)
        return None
    
    def release_container(self, container_id: str) -> None:
        """释放容器回池"""
        with self.lock:
            if container_id in self.in_use_containers:
                container = self.in_use_containers.pop(container_id)
                try:
                    # 清理容器工作目录
                    # container.exec_run("rm -rf /root/pyvul/*")
                    self.available_containers.append(container_id)
                    logger.info(f"Released container {container_id[:12]} back to pool")
                except Exception as e:
                    logger.error(f"Failed to clean container {container_id[:12]}: {e}")
                    self._replace_container(container_id)
    
    def _replace_container(self, old_container_id: str) -> None:
        """替换故障容器"""
        try:
            old_container = self.client.containers.get(old_container_id)
            old_container.remove(force=True)
        except:
            pass
        
        try:
            new_container = self._create_container()
            self.available_containers.append(new_container.id)
            logger.info(f"Replaced container {old_container_id[:12]} with {new_container.id[:12]}")
        except Exception as e:
            logger.error(f"Failed to replace container: {e}")
    
    def execute_command(self, container: docker.models.containers.Container, 
                       commands: str) -> tuple:
        """在容器中执行命令"""
        for cmd in commands:

            try:
                exec_result = container.exec_run(
                    f"{cmd}",
                    demux=True
                )
            except Exception as e:
                logger.error(f"Command execution failed (attempt {attempt + 1}): {e}")
                return -1
        return exec_result.exit_code, exec_result.output
        
    
    def close(self) -> None:
        """关闭所有容器并清理资源"""
        all_containers = self.available_containers + list(self.in_use_containers.keys())
        for container_id in all_containers:
            try:
                container = self.client.containers.get(container_id)
                container.remove(force=True)
                logger.info(f"Removed container {container_id[:12]}")
            except Exception as e:
                logger.error(f"Failed to remove container {container_id[:12]}: {e}")
        
