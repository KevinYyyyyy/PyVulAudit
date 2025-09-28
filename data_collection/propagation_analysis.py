import argparse

from logger import logger
from get_compatable_python_version import filter_versions


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Process CVE data.')
    parser.add_argument('--cve_id', type=str, help='Input CVE ID')
    args = parser.parse_args()
    # input = cve_id
    # output = potential affected downstream
    #cve_id→available affected versions → get dependents → available dependents→install&cg
    cve_id = args.cve_id
    # For each CVEs, check if has any available dependents and VFs
    advisory = cve2advisory.get(cve_id, None)
    if advisory is None:
        logger.error(f"No advisory for {cve_id}")
        return
    logger.info(f"Processing {cve_id}")
    #1. get the available affected versions
    from data_collection.collect_vuls import get_available_affected_pkgs
    available_affected_pkgs = get_available_affected_pkgs(advisory)
    if len(available_affected_pkgs) == 0:
        logger.warning(f"No available vulnerable upstream for {cve_id}")
        affected_downstream = []
        return
    # 2. get the fixing commits & VFs
    from vul_analyze import read_fixing_commits,get_pkg2url
    from collect_commits import get_extracted_urls_for_repo,extract_all_possible_urls,extract_fixing_commits
    from collect_changes import get_vulnerable_funcs_for_cve

    pkg2url = get_pkg2url()
    def extract_fixing_commits_and_vfs(advisory):
        all_unique_affected_packages = get_all_unique_affected_projects(advisory)
        all_fixing_commits = {}
        extracted_urls = extract_all_possible_urls(advisory)
        pkg2vfs = {}
        for package_name in all_unique_affected_packages:
            extracted_urls_for_repo = []
            repo_url = pkg2url.get(package_name.lower())
            if repo_url is None:
                logger.warning(f'No repo url found for {package_name}')
                continue
            repo_path = REPO_DIR / get_repo_name(repo_url)
            # 1. 从extracted_urls_for_package中找到所有的repo commit urls   
            extracted_urls_for_repo = get_extracted_urls_for_repo(extracted_urls,repo_url)
            if sum( len(urls) for urls in extracted_urls_for_repo.values())==0:
                logger.warning(f'No fixing commits found for {package_name}')
                continue
            # 2. 分别进行fixing commit解析
            logger.info(f"Processing repo_url: {repo_url}")
            if not repo_path.exists():
                success = clone_repo(repo_url, repo_path)
                if not success:
                    logger.warning(f'Failed to clone repo {repo_url}')
                    continue
            all_possible_urls = set(chain.from_iterable(extracted_urls_for_repo.values()))
            fixing_commits = extract_fixing_commits(all_possible_urls, repo_path, repo_url,advisory)
            all_fixing_commits.update(fixing_commits)



            logger.debug(f'Extracting {repo_url} code changes...')
            filtered_fixing_commits = filtered_by_merge_commit_and_large_pull(fixing_commits,extracted_urls_for_repo,repo_path,cve_id)
            if len(filtered_fixing_commits) == 0:
                logger.warning(f'No fixing commits for {cve_id}, {len(filtered_fixing_commits)}/{len(fixing_commits)}')
                continue
            else:
                logger.info(f'Found {len(filtered_fixing_commits)} filtered fixing commits from {len(fixing_commits)} fixing commits for {cve_id}')
            
            commit2methods,modified_non_py_files,modified_py_files= extract_changed_methods(filtered_fixing_commits, repo_path,extracted_urls_for_repo,cve_id)
            pkg2vfs[package_name] = [commit2methods,modified_non_py_files,modified_py_files]
        return all_fixing_commits, pkg2vfs
    def get_fixing_commits_and_vfs(cve_id, advisory, use_cache=False):
        if not use_cache:
            all_fixing_commits, pkg2vfs = extract_fixing_commits_and_vfs(advisory)
        else:
            # code_changes_path = CODE_CHANGES_DIR / f'{cve_id}_{repo_name}.json'
            # modified_files_path = CODE_CHANGES_DIR / f'{cve_id}_{repo_name}_modified_files.pkl'
            all_fixing_commits = read_fixing_commits(cve_id)
            all_unique_affected_packages = get_all_unique_affected_projects(advisory)    
            pkg2vfs = {}
            for package_name in all_unique_affected_packages:
                vfs = get_vulnerable_funcs_for_cve(cve_id, package_name)
                pkg2vfs[package_name] = vfs
        return all_fixing_commits, pkg2vfs

        

    all_fixing_commits, pkg2vfs = get_fixing_commits_and_vfs(cve_id, advisory)
    if len(all_fixing_commits) == 0:
        logger.warning(f"Cannot find fixing commits for {cve_id}")
        affected_downstream = []
        return

    if sum(len(vfs) for vfs in pkg2vfs.values()) == 0:
        logger.warning(f"Cannot find vulnerable functions for {cve_id}")
        affected_downstream = []
        return 

    #3. get the dependents
    from collect_dependents import get_dependents_from_osi
    from vul_analyze import get_dependents
    def get_all_dependents(available_affected_pkgs, use_cache=False):
        pkg2down = {}
        for upstream_package,versions in available_affected_pkgs.items():
            total_dependents_for_version = []
            for upstream_version in versions:
                if not use_cache:
                    ret =  get_dependents_from_osi(upstream_package, upstream_version)
                    direct, indirect = ret['direct'], ret['indirect']
                else:
                    cve_dependents, all_dependents = get_dependents(cve_id,advisory)
                    direct, indirect = get_direct_and_indirect_dependents(all_dependents, upstream_package, upstream_version)
                total_dependents_for_version = [direct, indirect]
            
                if len(total_dependents_for_version):
                    pkg2down[(normalize_package_name(upstream_package), upstream_version)]=total_dependents_for_version
        return pkg2down
    upstream2downstream = get_all_dependents(available_affected_pkgs)
    if len(upstream2downstream) == 0:
        logger.warning(f"No dependents for {cve_id}")
        affected_downstream = []
        return 
    assert False
    #3. install and cg
    install_and_cg(upstream2downstream)
    #4. get the potential affected downstream
    affected_downstream = check_reachability(available_affected_versions, dependents, vulnerable_functions)
    