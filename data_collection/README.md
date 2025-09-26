1. Run `collect_vuls.py` to collect vulnerabilities from the OSV.
    - 过滤器
        1. 掉malicious packages
        2. 只保留GHSA
        3. 只保留和CVE相关的，筛选aliases，过滤掉withdrawn的GHSA
    - 生成cve2advisory字典
        1. 获取advisory的cve：如果aliases的cve多于一个，则从references里筛选，只保留那些出现在references里的作为GHSA的cve
        2. 获取affected python package。
            - 一个漏洞在某一包中可能被重复引入，由于分支管理导致major不同
            - 有4个GHSA是重复的。'GHSA-4ppp-gpcr-7qf6', 'GHSA-hwqr-f3v9-hwxr', 'GHSA-4ppp-gpcr-7qf6', 'GHSA-hwqr-f3v9-hwxr'
        3. 获取repo_url
            - 基于pgk2url
            - 如果找不到，尝试从pypi/json和advisory/refs里获取

2. Run `collect_commits.py` to mining possible commit urls from advisories and get the valid fixing commits for each CVE.
    - 
    - 


3. 