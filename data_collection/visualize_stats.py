import matplotlib.pyplot as plt
import numpy as np
import json
import os
from pathlib import Path

# 假设统计数据已经运行并保存到文件中
# 如果没有，可以先运行check_reachability.py并将结果保存
def save_stats_to_file(stats_dict, filename="reachability_stats.json"):
    with open(filename, 'w') as f:
        json.dump(stats_dict, f, indent=4)

def load_stats_from_file(filename="reachability_stats.json"):
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            return json.load(f)
    return None

# 在check_reachability.py中添加以下代码来保存统计数据
def collect_stats(total_cves, affecting_cves, total_pairs, affecting_pairs, 
                 total_downstream, reason_counter, all_call_chains, 
                 all_call_chains_len, all_vulnerable_invocation):
    stats = {
        "cve_stats": {
            "total_cves": total_cves,
            "affecting_cves": len(affecting_cves),
            "cve_level_impact_rate": len(affecting_cves)/total_cves if total_cves > 0 else 0,
            "pair_level_impact_rate": len(affecting_pairs)/total_pairs if total_pairs > 0 else 0,
            "total_downstream": len(total_downstream),
            "affecting_pairs": len(affecting_pairs),
            "downstream_impact_rate": len(affecting_pairs)/total_pairs if total_pairs > 0 else 0
        },
        "reason_stats": reason_counter,
        "call_chain_stats": {
            "total": sum(all_call_chains),
            "average": sum(all_call_chains)/len(all_call_chains) if all_call_chains else 0,
            "percentiles": list(np.percentile(all_call_chains, [25, 50, 75, 99]).tolist()) if all_call_chains else [],
            "raw_data": all_call_chains
        },
        "call_chain_length_stats": {
            "total": sum([sum(chain) for chain in all_call_chains_len]) if all_call_chains_len else 0,
            "average": sum([sum(chain) for chain in all_call_chains_len])/sum(all_call_chains) if all_call_chains and sum(all_call_chains) > 0 else 0,
            "percentiles": list(np.percentile([sum(chain) for chain in all_call_chains_len], [25, 50, 75, 99]).tolist()) if all_call_chains_len else [],
            "raw_data": [sum(chain) for chain in all_call_chains_len]
        },
        "vulnerable_invocation_stats": {
            "total": sum(all_vulnerable_invocation) if all_vulnerable_invocation else 0,
            "average": sum(all_vulnerable_invocation)/len(all_vulnerable_invocation) if all_vulnerable_invocation else 0,
            "percentiles": list(np.percentile(all_vulnerable_invocation, [25, 50, 75, 99]).tolist()) if all_vulnerable_invocation else [],
            "raw_data": all_vulnerable_invocation
        }
    }
    save_stats_to_file(stats)
    return stats

# 可视化函数
def visualize_stats(stats=None, output_file='cve_impact_analysis.png',show=False):
    if stats is None:
        stats = load_stats_from_file()
        if stats is None:
            print("没有找到统计数据文件，请先运行check_reachability.py并保存统计数据")
            return
    
    # 设置中文字体支持
    plt.rcParams['font.sans-serif'] = ['Arial Unicode MS', 'SimHei', 'Microsoft YaHei']
    plt.rcParams['axes.unicode_minus'] = False
    
    # 创建一个包含多个子图的图表
    fig = plt.figure(figsize=(20, 15))
    fig.suptitle('CVE影响分析统计', fontsize=16)
    
    # 1. CVE影响统计 - 饼图
    ax1 = fig.add_subplot(231)
    cve_stats = stats["cve_stats"]
    ax1.pie([cve_stats["affecting_cves"], cve_stats["total_cves"] - cve_stats["affecting_cves"]], 
            labels=[f'影响其他项目 ({cve_stats["affecting_cves"]})', f'不影响其他项目 ({cve_stats["total_cves"] - cve_stats["affecting_cves"]})'],
            autopct='%1.1f%%', startangle=90)
    ax1.set_title('CVE影响比例')
    
    # 2. 各原因统计 - 条形图
    ax2 = fig.add_subplot(232)
    reason_stats = stats["reason_stats"]
    reasons = list(reason_stats.keys())
    counts = list(reason_stats.values())
    y_pos = np.arange(len(reasons))
    ax2.barh(y_pos, counts)
    ax2.set_yticks(y_pos)
    ax2.set_yticklabels(reasons)
    ax2.set_xlabel('数量')
    ax2.set_title('各原因统计')
    
    # 3. 箱线图比较 (移动到第3个位置)
    ax3 = fig.add_subplot(233)
    call_chain_stats = stats["call_chain_stats"]
    call_chain_length_stats = stats["call_chain_length_stats"]
    vulnerable_invocation_stats = stats["vulnerable_invocation_stats"]
    box_data = [
        call_chain_stats["raw_data"],
        call_chain_length_stats["raw_data"],
        vulnerable_invocation_stats["raw_data"]
    ]
    ax3.boxplot(box_data, labels=['Call Chain数量', 'Call Chain长度', 'Vulnerable Invocation'])
    ax3.set_title('数据分布比较')
    ax3.set_yscale('log')  # 使用对数刻度以便更好地显示
    
    # 4. Call chain统计 - 直方图 (从第3个位置移到第4个位置)
    ax4 = fig.add_subplot(234)
    ax4.hist(call_chain_stats["raw_data"], bins=30)
    ax4.set_xlabel('Call Chain数量')
    ax4.set_ylabel('频率')
    ax4.set_title(f'Call Chain分布 (平均: {call_chain_stats["average"]:.2f})')
    
    # 5. Call chain长度统计 - 直方图
    ax5 = fig.add_subplot(235)
    ax5.hist(call_chain_length_stats["raw_data"], bins=30)
    ax5.set_xlabel('Call Chain长度')
    ax5.set_ylabel('频率')
    ax5.set_title(f'Call Chain长度分布 (平均: {call_chain_length_stats["average"]:.2f})')
    
    # 6. Vulnerable invocation统计 - 直方图 (从第5个位置移到第6个位置)
    ax6 = fig.add_subplot(236)
    ax6.hist(vulnerable_invocation_stats["raw_data"], bins=30)
    ax6.set_xlabel('Vulnerable Invocation数量')
    ax6.set_ylabel('频率')
    ax6.set_title(f'Vulnerable Invocation分布 (平均: {vulnerable_invocation_stats["average"]:.2f})')
    
    plt.tight_layout(rect=[0, 0, 1, 0.95])
    plt.savefig(output_file, dpi=300)
    if show:
        plt.show()

# 如果直接运行此脚本
if __name__ == "__main__":
    visualize_stats()