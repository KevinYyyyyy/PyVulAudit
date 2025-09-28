class Vulnerability:
    def __init__(self, cve: str, cwe: str):
        self.cve = cve
        self.cwe = cwe

        self.package_name = None
        self.vulnerable_funcs = None
        self.affected_versions = None   # 受影响的 Version
        self.affected_libraries = None  # 受影响的 Library

    def add_affected_library(self, library):
        self.affected_libraries.append(library)

    def add_affected_version(self, version):
        self.affected_versions.append(version)

    def set_affected_versions(self, versions):
        self.affected_versions=versions

    def set_package_name(self, package_name):
        self.package_name = package_name

    def set_vulnerable_funcs(self, funcs):
        self.vulnerable_funcs = funcs

    def set_affected_libraries(self, libraries:dict):
        self.affected_libraries = libraries
