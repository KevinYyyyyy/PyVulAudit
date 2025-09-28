import requests
from resolvelib import AbstractProvider, Resolver, BaseReporter
from packaging.requirements import Requirement
from packaging.version import Version
from packaging.specifiers import SpecifierSet


# Step 1: 获取 PyPI 包信息
def get_package_info(package_name):
    url = f"https://pypi.org/pypi/{package_name}/json"
    response = requests.get(url)
    if response.status_code != 200:
        raise ValueError(f"Package {package_name} not found on PyPI.")
    data = response.json()

    # 提取版本和依赖信息
    releases = data["releases"]
    version_info = {}
    for version, release in releases.items():
        if release:  # 忽略没有文件的版本
            requires_dist = data["info"].get("requires_dist", [])
            version_info[version] = requires_dist
    return version_info


# Step 2: 实现 resolvelib.Provider
class PipProvider(_ProviderBase):
    """Pip's provider implementation for resolvelib.

    :params constraints: A mapping of constraints specified by the user. Keys
        are canonicalized project names.
    :params ignore_dependencies: Whether the user specified ``--no-deps``.
    :params upgrade_strategy: The user-specified upgrade strategy.
    :params user_requested: A set of canonicalized package names that the user
        supplied for pip to install/upgrade.
    """

    def __init__(
        self,
        factory: Factory,
        constraints: Dict[str, Constraint],
        ignore_dependencies: bool,
        upgrade_strategy: str,
        user_requested: Dict[str, int],
    ) -> None:
        self._factory = factory
        self._constraints = constraints
        self._ignore_dependencies = ignore_dependencies
        self._upgrade_strategy = upgrade_strategy
        self._user_requested = user_requested

    def identify(self, requirement_or_candidate: Union[Requirement, Candidate]) -> str:
        return requirement_or_candidate.name

    def narrow_requirement_selection(
        self,
        identifiers: Iterable[str],
        resolutions: Mapping[str, Candidate],
        candidates: Mapping[str, Iterator[Candidate]],
        information: Mapping[str, Iterator["PreferenceInformation"]],
        backtrack_causes: Sequence["PreferenceInformation"],
    ) -> Iterable[str]:
        """Produce a subset of identifiers that should be considered before others.

        Currently pip narrows the following selection:
            * Requires-Python, if present is always returned by itself
            * Backtrack causes are considered next because they can be identified
              in linear time here, whereas because get_preference() is called
              for each identifier, it would be quadratic to check for them there.
              Further, the current backtrack causes likely need to be resolved
              before other requirements as a resolution can't be found while
              there is a conflict.
        """
        backtrack_identifiers = set()
        for info in backtrack_causes:
            backtrack_identifiers.add(info.requirement.name)
            if info.parent is not None:
                backtrack_identifiers.add(info.parent.name)

        current_backtrack_causes = []
        for identifier in identifiers:
            # Requires-Python has only one candidate and the check is basically
            # free, so we always do it first to avoid needless work if it fails.
            # This skips calling get_preference() for all other identifiers.
            if identifier == REQUIRES_PYTHON_IDENTIFIER:
                return [identifier]

            # Check if this identifier is a backtrack cause
            if identifier in backtrack_identifiers:
                current_backtrack_causes.append(identifier)
                continue

        if current_backtrack_causes:
            return current_backtrack_causes

        return identifiers

    def get_preference(
        self,
        identifier: str,
        resolutions: Mapping[str, Candidate],
        candidates: Mapping[str, Iterator[Candidate]],
        information: Mapping[str, Iterable["PreferenceInformation"]],
        backtrack_causes: Sequence["PreferenceInformation"],
    ) -> "Preference":
        """Produce a sort key for given requirement based on preference.

        The lower the return value is, the more preferred this group of
        arguments is.

        Currently pip considers the following in order:

        * Any requirement that is "direct", e.g., points to an explicit URL.
        * Any requirement that is "pinned", i.e., contains the operator ``===``
          or ``==`` without a wildcard.
        * Any requirement that imposes an upper version limit, i.e., contains the
          operator ``<``, ``<=``, ``~=``, or ``==`` with a wildcard. Because
          pip prioritizes the latest version, preferring explicit upper bounds
          can rule out infeasible candidates sooner. This does not imply that
          upper bounds are good practice; they can make dependency management
          and resolution harder.
        * Order user-specified requirements as they are specified, placing
          other requirements afterward.
        * Any "non-free" requirement, i.e., one that contains at least one
          operator, such as ``>=`` or ``!=``.
        * Alphabetical order for consistency (aids debuggability).
        """
        try:
            next(iter(information[identifier]))
        except StopIteration:
            # There is no information for this identifier, so there's no known
            # candidates.
            has_information = False
        else:
            has_information = True

        if has_information:
            lookups = (r.get_candidate_lookup() for r, _ in information[identifier])
            candidate, ireqs = zip(*lookups)
        else:
            candidate, ireqs = None, ()

        operators: list[tuple[str, str]] = [
            (specifier.operator, specifier.version)
            for specifier_set in (ireq.specifier for ireq in ireqs if ireq)
            for specifier in specifier_set
        ]

        direct = candidate is not None
        pinned = any(((op[:2] == "==") and ("*" not in ver)) for op, ver in operators)
        upper_bounded = any(
            ((op in ("<", "<=", "~=")) or (op == "==" and "*" in ver))
            for op, ver in operators
        )
        unfree = bool(operators)
        requested_order = self._user_requested.get(identifier, math.inf)

        return (
            not direct,
            not pinned,
            not upper_bounded,
            requested_order,
            not unfree,
            identifier,
        )

    def find_matches(
        self,
        identifier: str,
        requirements: Mapping[str, Iterator[Requirement]],
        incompatibilities: Mapping[str, Iterator[Candidate]],
    ) -> Iterable[Candidate]:
        def _eligible_for_upgrade(identifier: str) -> bool:
            """Are upgrades allowed for this project?

            This checks the upgrade strategy, and whether the project was one
            that the user specified in the command line, in order to decide
            whether we should upgrade if there's a newer version available.

            (Note that we don't need access to the `--upgrade` flag, because
            an upgrade strategy of "to-satisfy-only" means that `--upgrade`
            was not specified).
            """
            if self._upgrade_strategy == "eager":
                return True
            elif self._upgrade_strategy == "only-if-needed":
                user_order = _get_with_identifier(
                    self._user_requested,
                    identifier,
                    default=None,
                )
                return user_order is not None
            return False

        constraint = _get_with_identifier(
            self._constraints,
            identifier,
            default=Constraint.empty(),
        )
        return self._factory.find_candidates(
            identifier=identifier,
            requirements=requirements,
            constraint=constraint,
            prefers_installed=(not _eligible_for_upgrade(identifier)),
            incompatibilities=incompatibilities,
            is_satisfied_by=self.is_satisfied_by,
        )

    @lru_cache(maxsize=None)
    def is_satisfied_by(self, requirement: Requirement, candidate: Candidate) -> bool:
        return requirement.is_satisfied_by(candidate)

    def get_dependencies(self, candidate: Candidate) -> Iterable[Requirement]:
        with_requires = not self._ignore_dependencies
        # iter_dependencies() can perform nontrivial work so delay until needed.
        return (r for r in candidate.iter_dependencies(with_requires) if r is not None)


# Step 3: 定义 Candidate 类
class Candidate:
    def __init__(self, name, version):
        self.name = name
        self.version = version

    def __repr__(self):
        return f"{self.name}=={self.version}"


# Step 4: 解析依赖关系
def resolve_dependencies(requirements):
    provider = PyPIProvider()
    reporter = BaseReporter()  # 添加 Reporter
    resolver = Resolver(provider, reporter)  # 传递 Reporter

    # 解析依赖关系
    result = resolver.resolve(requirements)

    # 构建依赖关系图
    dependency_graph = {}
    for candidate in result.mapping.values():
        dependency_graph[candidate] = provider.get_dependencies(candidate)

    return dependency_graph


# Step 5: 输出依赖关系图
def print_dependency_graph(graph, depth=0):
    for package, dependencies in graph.items():
        print("  " * depth + str(package))
        if dependencies:
            subgraph = {dep: graph[dep] for dep in dependencies if dep in graph}
            print_dependency_graph(subgraph, depth + 1)


# Step 6: 主程序入口
if __name__ == "__main__":
    from packaging.requirements import Requirement

    # 输入需求
    requirements = [Requirement("numpy>=1.25.4")]

    # 解析依赖
    dependency_graph = resolve_dependencies(requirements)

    # 输出依赖关系图
    print("Dependency Graph:")
    print_dependency_graph(dependency_graph)