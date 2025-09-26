from dataclasses import dataclass
from typing import List, Dict



@dataclass
class VulnerablePackage:
    """存储vulnerable package信息"""
    cve_id: str
    package_name: str
    package_version: str
    vulnerable_functions: List[str]
    upstream_modules: List[str] = None
    
    def __post_init__(self):
        if self.upstream_modules is None:
            self.upstream_modules = []
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        return {
            'cve_id': self.cve_id,
            'package_name': self.package_name,
            'package_version': self.package_version,
            'vulnerable_functions': self.vulnerable_functions,
            'upstream_modules': self.upstream_modules
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'VulnerablePackage':
        """Create instance from dictionary"""
        return cls(
            cve_id=data['cve_id'],
            package_name=data['package_name'],
            package_version=data['package_version'],
            vulnerable_functions=data['vulnerable_functions'],
            upstream_modules=data.get('upstream_modules', [])
        )


@dataclass 
class PackageInfo:
    """存储package基本信息"""
    name: str
    version: str
    dependencies: List[str]
    dependents: List[str] = None
    is_upstream: bool = False