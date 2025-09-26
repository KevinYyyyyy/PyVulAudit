import matplotlib.pyplot as plt
from matplotlib_venn import venn3

# VFC data from your table
vfc_subsets = (
    663,     # Function only (100) 
    68,     # Module only (010)
    795,    # Module+Function only  (110) 
    22,    # Class only (001)
    121,    # Class+Function only (101)
    18,     # Module+Class only (011)
    412     # All three (111)
)

plt.figure(figsize=(12, 10))

# 创建 Venn 图
venn = venn3(subsets=vfc_subsets, set_labels=('Function', 'Module', 'Class'))

# 增大集合标签（Function, Module, Class）字体
for text in venn.set_labels:
    text.set_fontsize(20)

# 增大内部区域的数值和百分比标签
total_vfcs = sum(vfc_subsets)
for label_id in ['100', '010', '001', '110', '101', '011', '111']:
    label = venn.get_label_by_id(label_id)
    if label and label.get_text():
        count = int(label.get_text())
        percentage = f"{count}\n({count/total_vfcs*100:.1f}%)"
        label.set_text(percentage)
        label.set_fontsize(18)  # 内部文字字号

# 保存图像（不显示标题）
plt.savefig('./scope_analysis.png', dpi=300, bbox_inches='tight')
plt.tight_layout()
plt.show()