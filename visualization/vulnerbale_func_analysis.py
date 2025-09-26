import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
import numpy as np

# Set style with Morandi colors
plt.style.use('default')
plt.rcParams['font.family'] = 'serif'

# Morandi color palette - muted, elegant colors
morandi_colors = [
    "#f19e9c",
    "#a4cb9e",
    "#beaec0",
    # '#d69cdc',
    # '#9999f8',
    '#dabd9e',
    # '#D4A574',  # Warm beige
    # '#A8B5A0',  # Sage green
    '#C4A484',  # Dusty rose
    # '#8B9D8A',  # Muted olive
    # '#B5A394',  # Taupe
    '#9BA8B5',  # Dusty blue
    '#A39D94'   # Warm gray
]

# Data
data = {
    'Category': [
        'Method Modified by Deleted Lines',
        'Method Modified by Added Lines', 
        'Special Methods in New File',
        'Module Variable Dependencies',
        'Module-level Function Calls',
        'Same-name Function Replacement',
        'Class Variable Dependencies'
    ],
    'Success_CVE': [519, 960, 1132, 1123, 1133, 1133, 1133],
    'Functions': [1508, 4333, 4905, 5151, 5287, 5291, 5289],
    'Total_CVE': [928, 413, 179, 63, 6, 2, 5],
    'Impact_CVE': [614, 173, 1, 10, 0, 0, 0],
    'Impact_Functions': [3786, 961, 389, 143, 7, 3, 5],
    'Impact_Rate': [71.5, 18.2, 7.3, 2.7, 0.1, 0.1, 0.1]
}

df = pd.DataFrame(data)

# Create figure with subplots
fig = plt.figure(figsize=(16, 12))
gs = fig.add_gridspec(3, 2, height_ratios=[1, 1, 1], hspace=0.3, wspace=0.3)
fig.patch.set_facecolor('#FAFAFA')

# 1. Impact Rate Bar Chart
ax1 = fig.add_subplot(gs[0, :])
ax1.set_facecolor('#FAFAFA')
bars = ax1.barh(df['Category'], df['Impact_Rate'], color=morandi_colors, alpha=0.85, edgecolor='white', linewidth=1)

# Add value labels on bars
for i, (bar, rate) in enumerate(zip(bars, df['Impact_Rate'])):
    ax1.text(bar.get_width() + 1, bar.get_y() + bar.get_height()/2, 
             f'{rate}%', va='center', fontweight='bold', fontsize=10, color='#5A5A5A')

ax1.set_xlabel('Impact Rate (%)', fontsize=12, fontweight='bold', color='#5A5A5A')
ax1.set_title('Function Impact Distribution by Category', fontsize=14, fontweight='bold', pad=20, color='#5A5A5A')
ax1.set_xlim(0, 80)
ax1.spines['top'].set_visible(False)
ax1.spines['right'].set_visible(False)
ax1.spines['left'].set_color('#D3D3D3')
ax1.spines['bottom'].set_color('#D3D3D3')
ax1.tick_params(colors='#5A5A5A')

# Wrap long labels
labels = [label.replace(' ', '\n', 1) if len(label) > 20 else label for label in df['Category']]
ax1.set_yticklabels(labels, fontsize=10, color='#5A5A5A')

# 2. Traditional vs Novel Coverage
ax2 = fig.add_subplot(gs[1, 0])
ax2.set_facecolor('#FAFAFA')
traditional_coverage = 71.5 + 18.2  # 89.7%
novel_coverage = 7.3 + 2.7 + 0.1 + 0.1 + 0.1  # 10.3%

coverage_data = [traditional_coverage, novel_coverage]
coverage_labels = ['Traditional\nMethods', 'Novel\nApproaches']
colors_coverage = [morandi_colors[0], morandi_colors[1]]

wedges, texts, autotexts = ax2.pie(coverage_data, labels=coverage_labels, colors=colors_coverage, 
                                  autopct='%1.1f%%', startangle=90, 
                                  textprops={'fontsize': 11, 'color': '#5A5A5A'},
                                  wedgeprops={'edgecolor': 'white', 'linewidth': 2})
ax2.set_title('Coverage Comparison:\nTraditional vs Novel', fontsize=12, fontweight='bold', color='#5A5A5A')

# 3. Impact Functions vs CVEs Scatter Plot
ax3 = fig.add_subplot(gs[1, 1])
ax3.set_facecolor('#FAFAFA')
scatter = ax3.scatter(df['Impact_CVE'], df['Impact_Functions'], 
                     s=df['Impact_Rate']*15, c=morandi_colors, alpha=0.8, 
                     edgecolors='white', linewidths=2)

# Add labels for points
for i, txt in enumerate(['Deleted', 'Added', 'Special', 'Module', 'ModCall', 'Replace', 'Class']):
    ax3.annotate(txt, (df['Impact_CVE'][i], df['Impact_Functions'][i]), 
                xytext=(5, 5), textcoords='offset points', fontsize=9, color='#5A5A5A')

ax3.set_xlabel('Impact CVEs', fontsize=11, fontweight='bold', color='#5A5A5A')
ax3.set_ylabel('Impact Functions', fontsize=11, fontweight='bold', color='#5A5A5A')
ax3.set_title('CVE Impact vs Function Impact\n(Bubble size = Impact Rate)', fontsize=12, fontweight='bold', color='#5A5A5A')
ax3.grid(True, alpha=0.3, color='#D3D3D3')
ax3.spines['top'].set_visible(False)
ax3.spines['right'].set_visible(False)
ax3.spines['left'].set_color('#D3D3D3')
ax3.spines['bottom'].set_color('#D3D3D3')
ax3.tick_params(colors='#5A5A5A')

# 4. Novel Contributions Detail
ax4 = fig.add_subplot(gs[2, :])
ax4.set_facecolor('#FAFAFA')
novel_categories = df.iloc[2:].copy()  # Skip first two traditional categories
novel_bars = ax4.bar(range(len(novel_categories)), novel_categories['Impact_Functions'], 
                    color=morandi_colors[2:], alpha=0.85, edgecolor='white', linewidth=1)

# Add value labels on bars
for i, (bar, funcs, rate) in enumerate(zip(novel_bars, novel_categories['Impact_Functions'], 
                                          novel_categories['Impact_Rate'])):
    ax4.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 5, 
             f'{funcs}\n({rate}%)', ha='center', va='bottom', fontweight='bold', fontsize=10, color='#5A5A5A')

ax4.set_ylabel('Impact Functions', fontsize=12, fontweight='bold', color='#5A5A5A')
ax4.set_title('Novel Contribution Details: Functions Identified by Each Strategy', 
              fontsize=14, fontweight='bold', pad=20, color='#5A5A5A')
ax4.set_xticks(range(len(novel_categories)))
ax4.set_xticklabels([cat.replace(' ', '\n', 1) for cat in novel_categories['Category']], 
                   rotation=45, ha='right', fontsize=10, color='#5A5A5A')
ax4.spines['top'].set_visible(False)
ax4.spines['right'].set_visible(False)
ax4.spines['left'].set_color('#D3D3D3')
ax4.spines['bottom'].set_color('#D3D3D3')
ax4.tick_params(colors='#5A5A5A')

plt.tight_layout()
plt.show()

# Summary statistics
print("=== VULNERABILITY ANALYSIS SUMMARY ===")
print(f"Total CVEs analyzed: {df['Success_CVE'].max()}")
print(f"Total functions analyzed: {df['Functions'].max()}")
print(f"Traditional method coverage: {df.iloc[:2]['Impact_Rate'].sum():.1f}%")
print(f"Novel method coverage: {df.iloc[2:]['Impact_Rate'].sum():.1f}%")
print(f"Total functions identified by novel methods: {df.iloc[2:]['Impact_Functions'].sum()}")

print("\n=== CONTRIBUTION BREAKDOWN ===")
for i, row in df.iterrows():
    if row['Impact_Rate'] > 0.1:  # Only show meaningful contributions
        print(f"{row['Category']}: {row['Impact_Functions']} functions ({row['Impact_Rate']}%)")

# Create a summary table
print("\n=== DETAILED RESULTS TABLE ===")
print(df.to_string(index=False))

# Additional analysis: Create a CSV for paper
df_paper = df[['Category', 'Impact_CVE', 'Impact_Functions', 'Impact_Rate']].copy()
df_paper.columns = ['Strategy', 'CVEs', 'Functions', 'Coverage (%)']
print("\n=== PAPER-READY TABLE ===")
print(df_paper.to_string(index=False))

# Save the figure
plt.savefig('vulnerability_analysis.png', dpi=300, bbox_inches='tight')
print("\nFigure saved as 'vulnerability_analysis.png'")