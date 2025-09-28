import pandas as pd
from matplotlib.style.core import available
from packaging import version as pversion
import json
from pathlib import Path
import requests
from collections import defaultdict
import seaborn as sns
import matplotlib.pyplot as plt
import os
from utils import get_python_versions_from_index, filter_by_pythonversions,get_affected_downstreams
import subprocess
from entities import Vulnerability
from vul_analyze import find_unzipable_files,find_vulnerable_calls

cols = ['package_name', 'cwe', 'cve', 'affected version', 'vulnerable func']
vuls = [
    # ('Django','SQL Injection','CVE-2021-35042','QuerySet.order_by()', 'test_order_by_escape_prevention'),
    ['numpy', 'Code Injection', 'CVE-2019-6446',
     ['0.9.6', '0.9.8', '1.0', '1.0.3', '1.0.4', '1.0b1', '1.0b4', '1.0b5', '1.0rc1', '1.0rc2', '1.0rc3', '1.1.1',
      '1.10.0', '1.10.1', '1.10.2', '1.10.3', '1.10.4', '1.11.0', '1.11.1', '1.11.2', '1.11.3', '1.12.0', '1.12.1',
      '1.13.0', '1.13.1', '1.13.3', '1.14.0', '1.14.1', '1.14.2', '1.14.3', '1.14.4', '1.14.5', '1.14.6', '1.15.0',
      '1.15.1', '1.15.2', '1.15.3', '1.15.4', '1.16.0', '1.2.0', '1.2.1', '1.3.0', '1.4.0', '1.4.1', '1.5.0', '1.5.1',
      '1.6.0', '1.6.1', '1.6.2', '1.7.0', '1.7.1', '1.7.2', '1.8.0', '1.8.1', '1.8.2', '1.9.0', '1.9.1', '1.9.2',
      '1.9.3'], ['np.load(']],
    ['urllib3', 'DoS', 'CVE-2021-33503',
     ['1.25.10', '1.25.11', '1.25.4', '1.25.5', '1.25.6', '1.25.7', '1.25.8', '1.25.9', '1.26.0', '1.26.1', '1.26.2',
      '1.26.3', '1.26.4'], ['parse_url(']]
    # ('torch', 'Command Injection', 'CVE-2022-45907', 'parse_type_line', '', '')
]

if __name__ == '__main__':
    # 获取CVE信息
    df = pd.DataFrame(data=vuls, columns=cols)
    print(df)
    cves = df['cve'].tolist()
    for cve in cves[:1]:
        print(cve)
        selected_row = df[df['cve'] == cve]
        vul = Vulnerability(cve=cve, cwe=selected_row['cwe'].iloc[0])

        package_name = selected_row['package_name'].iloc[0]
        vul.set_package_name(package_name)

        affected_versions = selected_row['affected version'].iloc[0]
        affected_versions = sorted(affected_versions, key=lambda x: pversion.parse(x))
        vul.set_affected_versions(affected_versions)
        print(vul.affected_versions)

        vulnerable_funcs = selected_row['vulnerable func'].iloc[0]
        vul.set_vulnerable_funcs(vulnerable_funcs)

        up2down = get_affected_downstreams(vul,filter=True)
        vul.set_affected_libraries(up2down)


        osi_url_tmp = "https://deps.dev/pypi/{package_name}/{version}"
        print('affected version:', len(affected_versions))

        # # 获取pypi还可获取的version
        available_versions = get_python_versions_from_index(package_name)
        print("available_versions:", available_versions)

        # # 过滤较老的版本
        filtered_versions = filter_by_pythonversions(available_versions)
        # print("available_versions (after filter):", filtered_versions)
        filtered_affected_versions = [version for version in affected_versions if version  in filtered_versions]
        counts = [len(up2down[f"{package_name}@{i}"]) for i in filtered_affected_versions]
        version2count = list(zip(filtered_affected_versions, counts))

        # dep-level可视化

        # function-level处理
        print(version2count)
        # assert False
        for version, count in version2count[::-1]:

            if count < 1:
                continue
            selected_version = f'{package_name}@{version}'
            affected_downstreams = up2down[selected_version]
            print('selected_version:',selected_version, count, available_versions[version])

            downstream_package_name = [affected_downstream[0].replace('@', '==') for affected_downstream in
                                       affected_downstreams]
            for downstream in downstream_package_name:
                # continue
                downstream = downstream.replace("-", "_").replace("==", "@")
                unzip_path = Path(f'./downloads/{selected_version}/{downstream}/{downstream}')
                download_path = unzip_path.parent

                if not download_path.exists():
                    pip_install_cmd = f"pip download --no-deps -d {str(download_path)} --index-url https://pypi.org/simple {downstream.replace('@','==') }"
                    # pip_install_cmd = f"pip download -d {download_path} --index-url https://pypi.org/simple {downstream.replace('@','==') }"
                    print('cmd:', pip_install_cmd)
                    # 执行命令
                    result = subprocess.run(pip_install_cmd, shell=True, capture_output=True, text=True)


                if not unzip_path.exists():
                    # TODO: add tar.gz
                    whl_files = find_unzipable_files(download_path)
                    print('all unzipable files:', whl_files)
                    for whl_file in whl_files:
                        unzip_cmd = f"unzip {whl_file} -d {download_path}/{downstream}"
                        print('unzip_cmd:', unzip_cmd)
                        result = subprocess.run(unzip_cmd, shell=True,
                                                capture_output=True, text=True)

                        # print("STDOUT:", result.stdout)
                else:
                    pass
            version2potential = defaultdict(list)
            print('=' * 100)

            print(f"Selected packages: {selected_version}")
            vulnerable_packages = []
            for downstream in downstream_package_name:
                downstream = downstream.replace("-", "_").replace("==", "@")

                # 定义解压目录
                extract_dir = Path(f'./downloads/{selected_version}/{downstream}/{downstream}')
                print('extract_dir:', extract_dir)
                # 查找调用
                vulnerable_calls = find_vulnerable_calls(extract_dir,
                                                         function_name=vulnerable_funcs[0])

                # 输出结果
                if vulnerable_calls:
                    print("Potential vulnerable calls found:")
                    for file_path, line_num, line_content in vulnerable_calls:
                        print(f"File: {file_path}, Line: {line_num}, Content: {line_content}")
                    vulnerable_package = [file_path.split('/')[3] for
                                          file_path, line_num, line_content in vulnerable_calls]
                    vulnerable_package = set(vulnerable_package)
                    for i in vulnerable_package:
                        vulnerable_packages.append(i)


                else:
                    print("No vulnerable calls found.")
            print(vulnerable_packages)
            assert False
            for downstream in downstream_package_name:
                downstream = downstream.replace("-", "_").replace("==", "@")

                # 定义解压目录
                extract_dir = Path(f'./downloads/{selected_version}/{downstream}/{downstream}')
                print('extract_dir:', extract_dir)
                # 查找调用
                vulnerable_calls = find_vulnerable_calls(extract_dir,
                                                         function_name=vulnerable_func)
                # 构建call graph
                modules = find_modules(extract_dir.absolute())
                # print('modules:',modules)

                output_dir = Path(f'./jarvis_outputs/{selected_version}')
                if not output_dir.exists():
                    output_dir.mkdir(parents=True)
                jarvis_output_file = Path(f"{output_dir}/{downstream}/jarvis.json")
                if not jarvis_output_file.parent.exists():
                    jarvis_output_file.parent.mkdir(parents=True)
                jarvis_cmd = f"python3 ~/Gitclone/Jarvis/tool/Jarvis/jarvis_cli.py {' '.join(modules)} --package {extract_dir.absolute()} --decy -o {jarvis_output_file}"
                print('jarvis_cmd:', jarvis_cmd)
                result = subprocess.run(jarvis_cmd, shell=True,
                                        capture_output=True, text=True)

                # print("STDOUT:", result.stdout)
                print("STDERR:", result.stderr)
                # for module in modules:
                #         output_file = output_dir/ '/'.join(str(module).split('/')[3:]).replace('.py','_PY') / f"jarvis.json"
                #         if output_file.exists():
                #                 continue
                #         if not output_file.parent.exists():
                #                 output_file.parent.mkdir(parents=True)
                #         jarvis_cmd = f"python3 ~/Gitclone/Jarvis/tool/Jarvis/jarvis_cli.py {module} --package {extract_dir} -o {output_file}"
                #         print(jarvis_cmd)

            print('-' * 100)
            print('Potential vulnerable packages found:', vulnerable_packages)
            print('-' * 100)
            version2potential[selected_version] = vulnerable_packages

            print('=' * 100)
            assert False

        # print(version2potential)
        # print(counts)
        # sumcnt = 0
        # for version,cnt in counts:
        #         tmp_cnt = len(version2potential[f"{package_name}@{version}"]) if f"{package_name}@{version}" in version2potential else 0
        #         print(version, cnt, tmp_cnt)
        #         sumcnt += tmp_cnt
        # print(sumcnt)

        # vis_by_plot(list(version2potential.keys()), [len(i) for i in version2potential.values()], f"{package_name} {cve} Potential Vulnerable Libs")

    # plt.show()
    # ————————————
