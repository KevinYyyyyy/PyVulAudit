from pathlib import Path
import sys
sys.path.append(Path(__file__).parent.parent.as_posix())
from datetime import datetime, date
from collections import defaultdict
from data_collection.constant import VUL_PACKAGES_DIR_DATE
from vul_analyze import read_cve2advisory,load_vulnerable_packages
from data_classes import VulnerablePackage
from typing import List, Dict
import pickle
from logger import logger
from data_collection.collect_dependents_and_dependency import parse_dependency_graph,get_dependents_for_version
import json

class PyPISnapshotCollector:
    def __init__(self, snapshot_date):
        self.snapshot_date = snapshot_date
        
    def collect_complete_index(self):
        # 方案1: 直接从PyPI Simple API获取
        packages = self.scrape_simple_index()
        
        # 方案2: 使用现有的第三方dumps
        # 比如: https://github.com/pypa/linehaul-cloud-function
        
        return packages
    
    def scrape_simple_index(self):
        """从PyPI Simple API获取所有package名称"""
        response = requests.get("https://pypi.org/simple/")
        soup = BeautifulSoup(response.content, 'html.parser')
        packages = [a.text for a in soup.find_all('a')]
        print(len(packages))
        print(packages)
        return packages

class SnapshotCreator:
    """负责创建dependency snapshots"""
    
    def __init__(self, snapshot_date: str, base_dir: str = "./research_snapshots"):
        self.base_dir = Path(base_dir) / snapshot_date
        self.base_dir.mkdir(exist_ok=True, parents=True)
        
    def create_snapshot_for_pkg(self,  vulnerable_pkg: VulnerablePackage) -> bool:
        """为特定CVE创建snapshot"""
        
        print(f"Creating snapshot for {vulnerable_pkg.package_name, vulnerable_pkg.package_version}...")
        
        # 1. 获取affected package的所有dependents
        all_dependents, direct_dependents, indirect_dependents= self._get_package_dependents(
            vulnerable_pkg.package_name, 
            vulnerable_pkg.package_version
        )
        
        
        # 2. 为每个dependent构建dependency graph
        dependency_graphs = {}
        
        for package_name, package_version in all_dependents:
            snapshot_dir = self.base_dir/ 'dep_graphs'
            snapshot_dir.mkdir(exist_ok=True,parents=True)
            snapshot_file = snapshot_dir/f'{"@".join([ package_name,package_version])}.json'
            if snapshot_file.exists():
                try:
                    with open(snapshot_file, 'r') as f:
                        graph = json.load(f)
                except:
                    graph = {}
            else:
                graph = {}
                
            if len(graph) == 0:
                graph = self._get_dependency_graph( package_name, package_version)
                with open(snapshot_file, 'w') as f:
                    json.dump(graph, f)
                
            dependency_graphs['@'.join([ package_name, package_version])] = graph
            

            
        # 3. 保存snapshot
        snapshot_dir = self.base_dir/ '@'.join([ vulnerable_pkg.package_name, vulnerable_pkg.package_version])

        snapshot_dir.mkdir(exist_ok=True,parents=True)
        
        self._save_snapshot_data(snapshot_dir, {
            'vulnerable_package': vulnerable_pkg,
            'dependents': {'direct':direct_dependents, 'indirect':indirect_dependents},
            'dependency_graphs': dependency_graphs
        })
            
        print(f"Snapshot saved to {snapshot_dir}")
        return True
    
    def _get_package_dependents(self, package_name: str, package_version: str) -> List[str]:
        """通过OSV API获取package的dependents"""
        dependents = get_dependents_for_version(package_name, package_version)
        direct_dependents = dependents.get('direct',[])
        direct_dependents = list({(item['package'], item['version']) for item in direct_dependents})
        indirect_dependents = dependents.get('indirect',[])
        indirect_dependents = list({(item['package'], item['version']) for item in indirect_dependents})

        all_dependents = direct_dependents+indirect_dependents
        
        return all_dependents,direct_dependents,indirect_dependents
        
    
    def _get_dependency_graph(self, package_name: str, package_version: str) -> Dict:
        # logger.info(f"正在获取 {package_name}=={package_version} 的依赖图...")
        
        try:
            # 获取dependent的dependency graph
            dep_graph = parse_dependency_graph(package_name, package_version)
            
            if dep_graph and len(dep_graph.get('nodes', {})) > 0:
                logger.info(f"成功获取 {package_name}=={package_version} 的依赖图: "
                          f"节点数={len(dep_graph['nodes'])}, 边数={len(dep_graph['edges'])}")
            else:
                logger.warning(f"未能获取 {package_name}=={package_version} 的依赖图")
                
        except Exception as e:
            logger.error(f"获取 {package_name}=={package_version} 依赖图时发生错误: {str(e)}")
            dep_graph = {}
        
        return dep_graph
            
            
    def _save_snapshot_data(self, snapshot_dir: Path, data: Dict):
        """保存snapshot数据到文件"""
        
        # 保存vulnerable package信息
        with open(snapshot_dir / "vulnerable_package.json", 'w') as f:
            json.dump({
                'cve_id': data['vulnerable_package'].cve_id,
                'package_name': data['vulnerable_package'].package_name,
                'package_version': data['vulnerable_package'].package_version,
                'vulnerable_functions': data['vulnerable_package'].vulnerable_functions
            }, f, indent=2)
        
        # 保存dependents列表
        with open(snapshot_dir / "dependents.json", 'w') as f:
            json.dump(data['dependents'], f, indent=2)
        
        # 保存dependency graphs
        # with open(snapshot_dir / "dependency_graphs.json", 'w') as f:
        #     json.dump(data['dependency_graphs'], f, indent=2)

        
        # 保存metadata
        with open(snapshot_dir / "metadata.json", 'w') as f:
            json.dump({
                'created_at': datetime.now().isoformat(),
                'total_dependents': len(data['dependents']),
                'total_dependency_graphs': len(data['dependency_graphs'])
            }, f, indent=2)
    
    def create_batch_snapshots(self, vulnerable_packages: List[VulnerablePackage]) -> Dict[str, bool]:
        """批量创建snapshots"""
        results = {}
        
        for vuln_pkg in vulnerable_packages:
            try:
                success = self.create_snapshot_for_cve(vuln_pkg.cve_id, vuln_pkg)
                results[vuln_pkg.cve_id] = success
            except Exception as e:
                print(f"Failed to create snapshot for {vuln_pkg.cve_id}: {e}")
                results[vuln_pkg.cve_id] = False
        
        return results
    
    def load_snapshot(self, cve_id: str) -> Dict:
        """加载已存在的snapshot"""
        snapshot_dir = self.base_dir / cve_id
        
        if not snapshot_dir.exists():
            raise FileNotFoundError(f"Snapshot for {cve_id} not found")
        
        data = {}
        
        # 加载各个文件
        with open(snapshot_dir / "vulnerable_package.json", 'r') as f:
            data['vulnerable_package'] = json.load(f)
            
        with open(snapshot_dir / "dependents.json", 'r') as f:
            data['dependents'] = json.load(f)
            
        # with open(snapshot_dir / "dependency_graphs.json", 'r') as f:
        #     data['dependency_graphs'] = json.load(f)
            
        with open(snapshot_dir / "metadata.json", 'r') as f:
            data['metadata'] = json.load(f)
        
        return data
    
    def list_snapshots(self) -> List[str]:
        """列出所有snapshots"""
        snapshots = []
        for item in self.base_dir.iterdir():
            if item.is_dir() and (item / "metadata.json").exists():
                snapshots.append(item.name)
        return sorted(snapshots)
    
if __name__ =='__main__':
    # execute order:
    # VF Done -> dependents -> store Vulnerable Package -> create snapshot
    # 初始化snapshot creator
    snapshot_date = '20250831'
    creator = SnapshotCreator(snapshot_date=snapshot_date)
    
    # 1. 获取完整package列表
    # all_package_indexes = PyPISnapshotCollector(snapshot_date=snapshot_date).scrape_simple_index()


    # 2. 获取有VF的CVEs对应的packages
    vulnerable_packages = ...
    # 示例：你已经收集到的vulnerable packages
    cve2advisory = read_cve2advisory(cve_has_vf=True)

    vulnerable_packages = load_vulnerable_packages()

    # cve_packages = load_vulnerable_packages_by_cve(
    # vulnerable_packages_dir="./vulnerable_packages_small",
    # cve_id="CVE-2024-3772",
    # dataset_size="small"
    # )
    # # 按包名过滤
    # package_instances = load_vulnerable_packages_by_package(
    #     vulnerable_packages_dir="./vulnerable_packages_small",
    #     package_name="django",
    #     dataset_size="small"
    # )

    # 2. 对每个package获取版本信息
    for vulnerable_package in vulnerable_packages:
        success = creator.create_snapshot_for_pkg(
        vulnerable_package
        )
        print(f"Single snapshot creation: {success}")

    # 列出所有snapshots
    snapshots = creator.list_snapshots()
    print(f"Available snapshots: {len(snapshots)}")
    
    # 加载snapshot
    # if snapshots:
    #     snapshot_data = creator.load_snapshot(snapshots[0])
    #     print(f"Loaded snapshot has {len(snapshot_data['dependents'])} dependents")