import os
import subprocess
from pathlib import Path
from clone_repos import clone_repo
def process_failed_repos():
    input_file = "/Users/keviny/Desktop/Research/ANU/Projects/PyVul/data_collection/failed_repos.txt"
    output_file = "/Users/keviny/Desktop/Research/ANU/Projects/PyVul/data_collection/failed_repos_git_logs.txt"
    
    def print_and_write(msg, file):
        print(msg)
        file.write(msg + '\n')
    addressed_repos = set()  # 用于跟踪已处理的rep
    skip_project = ['azure-sdk-for-python']
    addressed_repos.update(skip_project)
    with open(input_file, 'r') as f_in, open(output_file, 'w') as f_out:
        for line in f_in:
            line = line.strip()
            if not line:
                continue

            parts = line.split('\t')
            if len(parts) < 2:
                continue
                
            commit_url = parts[0]
            print('commit_url:',commit_url)
            repo_path = parts[1]
            repo_url = '/'.join(commit_url.split('/')[:5])  # 从commit URL提取仓库URL
            if any(skip in repo_url for skip in skip_project):
                print_and_write(f"Skipping project: {repo_url}", f_out)
                continue  
            if repo_path in addressed_repos:
                print_and_write(f"Skipping already processed repo: {repo_path}", f_out)
                continue  # 如果已经处理过该repo，则跳过
            addressed_repos.add(repo_path)  # 标记为已处理
            commit_hash = commit_url.split('/')[-1].split('.')[0]  # 处理可能的.patch后缀
            
            header = f"=== Processing: {commit_url} in {repo_path} ==="
            print_and_write(header, f_out)
            
            if not os.path.exists(repo_path):
                clone_repo(repo_url, repo_path)

                
            try:
                # 进入仓库目录执行git log

                os.chdir(repo_path)
                cmd = f"git log -1 {commit_hash} --"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                if result.returncode == 0:
                    print_and_write(result.stdout, f_out)
                else:
                    if "fatal: bad object" in result.stderr:
                        print_and_write("Bad object detected, attempting to re-clone repository...", f_out)
                        # 获取仓库URL
                        
                        try:
                            # 删除原有仓库目录
                            import shutil
                            # shutil.rmtree(repo_path)
                            print_and_write(f"Removed existing repository at {repo_path}", f_out)
                            
                            # 重新克隆仓库
                            success = clone_repo(repo_url, repo_path)
                            if success:
                                # 重新尝试git log
                                os.chdir(repo_path)  # 重新进入目录
                                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                                if result.returncode == 0:
                                    print_and_write("Re-clone successful, git log output:", f_out)
                                    print_and_write(result.stdout, f_out)
                                else:
                                    print_and_write(f"Still failed after re-clone: {result.stderr}", f_out)
                            else:
                                print_and_write("Failed to re-clone repository", f_out)
                        except Exception as e:
                            print_and_write(f"Error during re-clone process: {str(e)}", f_out)
                    else:
                        error_msg = f"Error executing git log: {result.stderr}"
                        print_and_write(error_msg, f_out)
                    
            except Exception as e:
                error_msg = f"Exception occurred: {str(e)}"
                print_and_write(error_msg, f_out)
                assert False

            
            print_and_write("", f_out)  # 添加空行分隔不同记录

if __name__ == '__main__':
    process_failed_repos()