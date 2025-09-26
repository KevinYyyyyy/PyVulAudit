from math import ceil
import matplotlib.pyplot as plt
import numpy as np
from pandas.tseries.frequencies import build_field_sarray

# 终端中显示的数据
valid_cves_severity = {'LOW': 5.05, 'MODERATE': 38.5, 'HIGH': 40.16, 'CRITICAL': 16.29}
valid_owsap_cve_severity = {'LOW': 5.36, 'MODERATE': 38.93, 'HIGH': 36.95, 'CRITICAL': 18.76}
valid_cwe_cve_severity = {'MODERATE': 33.73, 'CRITICAL': 18.89, 'HIGH': 42.58, 'LOW': 4.8}

# 设置颜色映射
colors = {
    'LOW': '#4CAF50',       # Green
    'MODERATE': '#FFC107',   # Yellow
    'HIGH': '#FF9800',       # Orange
    'CRITICAL': '#F44336'    # Red
}

# 创建图形和子图
fig, axes = plt.subplots(1, 3, figsize=(18, 6))

# 绘制三个饼图
datasets = [
    (valid_cves_severity, "Severity Distribution of All CVEs"),
    (valid_owsap_cve_severity, "Severity Distribution of OWSAP TOP10"),
    (valid_cwe_cve_severity, "Severity Distribution of CWE TOP25")
]

for i, (data, title) in enumerate(datasets):
    # 确保所有图表使用相同的顺序
    labels = ['LOW', 'MODERATE', 'HIGH', 'CRITICAL']
    sizes = [data.get(label, 0) for label in labels]
    color_list = [colors[label] for label in labels]
    
    # 绘制饼图
    wedges, texts, autotexts = axes[i].pie(
        sizes, 
        labels=labels,
        colors=color_list,
        autopct='%1.1f%%',
        startangle=90,
        wedgeprops={'edgecolor': 'w', 'linewidth': 1}
    )
    
    # 设置标题和属性
    axes[i].set_title(title, fontsize=14)
    
    # 设置文本属性
    for text in texts:
        text.set_fontsize(10)
    for autotext in autotexts:
        autotext.set_fontsize(10)
        autotext.set_color('white')

# 调整布局
plt.tight_layout()

# 保存图像
# plt.savefig('severity_distribution_pie_charts.png', dpi=300, bbox_inches='tight')

# 显示图像
# plt.show()
import matplotlib.pyplot as plt
import numpy as np

# 表格中的数据
data = {
    'Category': ['ALL', 'OWSAP TOP10 (196)', 'CWE TOP25'],
    'Original_CVEs': [3450, 2254, 2058],
    'Valid_CVEs': [1143, 854, 664],
    'Coarse_grained': [698, 479, 390],
    'Fine_grained': [148, 87, 79]
}

# 计算基于原始CVE的百分比
percentages = {}
for key in ['Valid_CVEs', 'Coarse_grained', 'Fine_grained']:
    percentages[key] = [round(value / data['Original_CVEs'][i] * 100, 2) for i, value in enumerate(data[key])]
print(percentages)

# 设置图表
fig, ax = plt.subplots(figsize=(12, 8))

# 设置条形图的宽度和位置
x = np.arange(len(data['Category']))
width = 0.6

# 创建堆叠条形图
bars1 = ax.bar(x, percentages['Fine_grained'], width, label='Fine-grained', color='#4CAF50')
bars2 = ax.bar(x, [p1-p2 for p1, p2 in zip(percentages['Coarse_grained'],percentages['Fine_grained'])], width, bottom=percentages['Fine_grained'], label='Coarse-grained', color='#FFC107')
bars3 = ax.bar(x, [p2-p1 for p1, p2 in zip(percentages['Coarse_grained'], percentages['Valid_CVEs'])],
              width, bottom=percentages['Coarse_grained'], 
              label='Valid (Other)', color='#2196F3')

# 添加未被包含在Valid CVEs中的部分
bars4 = ax.bar(x, [100 - p for p in percentages['Valid_CVEs']], width, 
              bottom=percentages['Valid_CVEs'], label='Not Valid', color='#E0E0E0')
# 添加数据标签
def add_labels(bars, values, offsets=None):
    if offsets is None:
        offsets = [0] * len(bars)
    for i, (bar, value, offset) in enumerate(zip(bars, values, offsets)):
        height = bar.get_height()
        if height > 3:  # 只在高度足够的情况下显示标签
            print(list(data.keys())[bars.index(bar)+1])
            print(data, bars.index(bar))
            ax.text(bar.get_x() + bar.get_width()/2., bar.get_y() + height/2 + offset,
                    f'{value}%\n({ceil(value*data["Original_CVEs"][i]/100)})',
                    ha='center', va='center', color='black', fontweight='bold')

# 为每组条形添加标签
add_labels(bars1, percentages['Fine_grained'])
add_labels(bars2, percentages['Coarse_grained'])
add_labels(bars3, percentages['Valid_CVEs'])
add_labels(bars4, [round(i,2) for i in [100 - p for p in percentages['Valid_CVEs']]])

# 添加总数标签
for i, total in enumerate(data['Original_CVEs']):
    ax.text(i, 105, f'Total: {total}', ha='center', va='bottom', fontweight='bold')

# 设置图表标题和标签
ax.set_title('CVE Distribution by Category', fontsize=16)
ax.set_ylabel('Percentage of Original CVEs (%)', fontsize=14)
ax.set_xticks(x)
ax.set_xticklabels(data['Category'], fontsize=12)
ax.set_ylim(0, 110)  # 设置y轴范围，留出空间显示总数

# 添加图例
ax.legend(bbox_to_anchor=(1.0, 0.5), loc='upper right', fontsize=12)

# 添加网格线
ax.grid(axis='y', linestyle='--', alpha=0.7)

# 为每个条形图添加边框
for bars in [bars1, bars2, bars3, bars4]:
    for bar in bars:
        bar.set_edgecolor('black')
        bar.set_linewidth(0.5)

# 调整布局
plt.tight_layout()

# 保存图表
# plt.savefig('cve_distribution_stacked_bar.png', dpi=300, bbox_inches='tight')

# 显示图表
plt.show()