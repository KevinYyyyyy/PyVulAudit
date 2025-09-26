import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
from matplotlib.patches import Rectangle
import pandas as pd

# Set up the plotting style
plt.style.use('default')
sns.set_palette("husl")

# Data
module_data = {
    'Global Variable Assignment': 276,
    'Expression': 62,
    'Import': 40,
    'Control Flow-Related': 14,
    'Decorated-Related': 10,
    'Exception/Assertion' : 1
}

class_data = {
    'Class Attribute Assignment': 244,
    'Expression': 56,
    'Class Definition ': 24,
    'Import': 10
}

def create_module_scope_chart():
    """Create module scope statement types chart"""
    fig, ax = plt.subplots(figsize=(12, 6))
    
    module_labels = list(module_data.keys())
    module_values = list(module_data.values())
    module_total = sum(module_values)
    module_percentages = [f'{v} ({v/module_total*100:.1f}%)' for v in module_values]
    
    bars = ax.barh(module_labels, module_values, color='steelblue', alpha=0.7)
    # ax.set_title(f'Module-scope Statement Types (Total: {module_total})', fontsize=14, fontweight='bold')
    ax.set_xlabel('Number of Changes')
    
    # 设置y轴类别标签字体样式
    ax.tick_params(axis='y', labelsize=16)
    # 设置y轴标签字体为粗体
    for label in ax.get_yticklabels():
        label.set_fontweight('normal')
        ...
    # Add value labels
    for i, (bar, pct) in enumerate(zip(bars, module_percentages)):
        width = bar.get_width()
        ax.text(width + 5, bar.get_y() + bar.get_height()/2, 
                pct, ha='left', va='center', fontweight='normal', fontsize=15)
    plt.tight_layout()
    plt.savefig('module_scope_statements.png', dpi=300, bbox_inches='tight')
    plt.show()


def create_class_scope_chart():
    """Create class scope statement types chart"""
    fig, ax = plt.subplots(figsize=(12, 5))
    
    class_labels = list(class_data.keys())
    class_values = list(class_data.values())
    class_total = sum(class_values)
    class_percentages = [f'{v} ({v/class_total*100:.1f}%)' for v in class_values]
    
    bars = ax.barh(class_labels, class_values, color='darkorange', alpha=0.7)
    # ax.set_title(f'Class-scope Statement Types (Total: {class_total})', fontsize=14, fontweight='bold')
    ax.set_xlabel('Number of Changes')
    
    # 设置y轴类别标签字体样式
    ax.tick_params(axis='y', labelsize=16)
    # 设置y轴标签字体为粗体
    for label in ax.get_yticklabels():
        label.set_fontweight('normal')
    
    # Add value labels
    for i, (bar, pct) in enumerate(zip(bars, class_percentages)):
        width = bar.get_width()
        ax.text(width + 5, bar.get_y() + bar.get_height()/2, 
                pct, ha='left', va='center', fontweight='normal', fontsize=15)
    
    plt.tight_layout()
    plt.savefig('class_scope_statements.png', dpi=300, bbox_inches='tight')
    plt.show()

def create_variable_emphasis_chart():
    """Create chart emphasizing variable assignments"""
    fig, ax = plt.subplots(figsize=(10, 6))
    
    # Calculate totals
    variable_assignments = 276 + 244  # Global + Class attribute
    other_statements = sum(module_data.values()) + sum(class_data.values()) - variable_assignments
    total = variable_assignments + other_statements
    
    categories = ['Variable Assignments', 'Other Statements']
    values = [variable_assignments, other_statements]
    percentages = [f'{v/total*100:.1f}%' for v in values]
    colors = ['#2E86AB', '#A23B72']
    
    bars = ax.bar(categories, values, color=colors, alpha=0.8)
    
    # Add value and percentage labels
    for bar, val, pct in zip(bars, values, percentages):
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2, height + 10, 
                f'{val}\n({pct})', ha='center', va='bottom', 
                fontweight='bold', fontsize=12)
    
    ax.set_title('Predominance of Variable-Related Changes in Non-Method Fixes', 
                 fontsize=14, fontweight='bold')
    ax.set_ylabel('Number of Changes')
    ax.set_ylim(0, max(values) * 1.15)
    
    # Add total annotation
    ax.text(0.5, 0.95, f'Total Non-method Changes: {total}', 
            transform=ax.transAxes, ha='center', va='top',
            bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
    
    plt.tight_layout()
    plt.savefig('variable_emphasis.png', dpi=300, bbox_inches='tight')
    plt.show()

def create_coverage_comparison_table():
    """Create coverage comparison table"""
    fig, ax = plt.subplots(figsize=(12, 8))
    ax.axis('tight')
    ax.axis('off')
    
    # Prepare data
    all_statements = {**module_data, **class_data}
    
    table_data = []
    for statement, count in all_statements.items():
        table_data.append([
            statement, 
            count, 
            '✗ Missed', 
            '✓ Captured'
        ])
    
    # Add totals
    total_count = sum(all_statements.values())
    table_data.append([
        'Total Non-method', 
        total_count, 
        '0% Coverage', 
        '100% Coverage'
    ])
    
    # Create table
    table = ax.table(cellText=table_data,
                    colLabels=['Statement Type', 'Count', 'Traditional Method', 'Our Multi-scope'],
                    cellLoc='center',
                    loc='center',
                    bbox=[0, 0, 1, 1])
    
    table.auto_set_font_size(True)
    table.set_fontsize(18)
    table.scale(1.2, 2)
    
    # Style the table
    for i in range(len(table_data) + 1):
        for j in range(4):
            cell = table[(i, j)]
            if i == 0:  # Header
                cell.set_facecolor('#4472C4')
                cell.set_text_props(weight='bold', color='white')
            elif i == len(table_data):  # Total row
                cell.set_facecolor('#D9E1F2')
                cell.set_text_props(weight='bold')
            else:
                if j == 2:  # Traditional method column
                    cell.set_facecolor('#FFE6E6')
                elif j == 3:  # Our approach column
                    cell.set_facecolor('#E6F3E6')
    
    plt.title('Statement Coverage Comparison', fontsize=16, fontweight='bold', pad=20)
    plt.savefig('coverage_comparison.png', dpi=300, bbox_inches='tight')
    plt.show()

def create_statement_breakdown_pie():
    """Create pie chart showing all statement types"""
    fig, ax = plt.subplots(figsize=(10, 8))
    
    # Combine all data
    all_data = {}
    for key, value in module_data.items():
        all_data[f"Module: {key}"] = value
    for key, value in class_data.items():
        all_data[f"Class: {key}"] = value
    
    labels = list(all_data.keys())
    values = list(all_data.values())
    
    # Create color map
    colors = []
    for label in labels:
        if 'Module:' in label:
            colors.append(plt.cm.Blues(0.7))
        else:
            colors.append(plt.cm.Oranges(0.7))
    
    wedges, texts, autotexts = ax.pie(values, labels=labels, autopct='%1.1f%%', 
                                      colors=colors, startangle=90)
    
    ax.set_title('Distribution of Non-Method Statement Types', fontsize=14, fontweight='bold')
    
    # Adjust text size
    for autotext in autotexts:
        autotext.set_fontsize(18)
        autotext.set_fontweight('bold')
    
    plt.tight_layout()
    plt.savefig('statement_breakdown_pie.png', dpi=300, bbox_inches='tight')
    plt.show()

def create_scope_comparison_chart():
    """Create comparison chart across scopes"""
    fig, ax = plt.subplots(figsize=(10, 6))
    
    # Data preparation
    scopes = ['Module Scope', 'Class Scope']
    variable_assignments = [276, 244]  # Global variable + Class attribute
    other_statements = [
        sum(module_data.values()) - 276,
        sum(class_data.values()) - 244
    ]
    
    x = np.arange(len(scopes))
    width = 0.35
    
    bars1 = ax.bar(x - width/2, variable_assignments, width, label='Variable Assignments', 
                   color='#1f77b4', alpha=0.7)
    bars2 = ax.bar(x + width/2, other_statements, width, label='Other Statements', 
                   color='#ff7f0e', alpha=0.7)
    
    # Add value labels
    for bars in [bars1, bars2]:
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2, height + 3,
                    f'{int(height)}', ha='center', va='bottom', 
                    fontweight='bold')
    
    ax.set_xlabel('Code Scope')
    ax.set_ylabel('Number of Changes')
    ax.set_title('Variable Assignments vs Other Statements by Scope', fontweight='bold')
    ax.set_xticklabels(scopes,fontsize=28)
    ax.set_
    ax.legend()
    
    # Add percentage annotations
    total_module = sum(module_data.values())
    total_class = sum(class_data.values())
    ax.text(0, total_module * 0.8, f'{276/total_module*100:.1f}%\nare variable\nassignments', 
            ha='center', va='center', bbox=dict(boxstyle='round', facecolor='lightblue', alpha=0.7))
    ax.text(1, total_class * 0.8, f'{244/total_class*100:.1f}%\nare variable\nassignments', 
            ha='center', va='center', bbox=dict(boxstyle='round', facecolor='lightsalmon', alpha=0.7))
    
    plt.tight_layout()
    plt.savefig('scope_comparison.png', dpi=300, bbox_inches='tight')
    plt.show()

# Generate all visualizations
if __name__ == "__main__":
    print("Generating module scope chart...")
    create_module_scope_chart()
    
    print("Generating class scope chart...")
    create_class_scope_chart()
    
    # print("Generating variable emphasis chart...")
    # create_variable_emphasis_chart()
    
    # print("Generating statement breakdown pie chart...")
    # create_statement_breakdown_pie()
    
    # print("Generating scope comparison chart...")
    # create_scope_comparison_chart()
    
    # print("Generating coverage comparison table...")
    # create_coverage_comparison_table()
    
    # print("All visualizations completed!")
    
    # Print summary statistics
    total_module = sum(module_data.values())
    total_class = sum(class_data.values())
    total_variable = module_data['Global Variable Assignment'] + class_data['Class Attribute Assignment']
    total_all = total_module + total_class
    
    print(f"\nSummary Statistics:")
    print(f"Total non-method changes: {total_all}")
    print(f"Variable assignments: {total_variable} ({total_variable/total_all*100:.1f}%)")
    print(f"Module-scope changes: {total_module} ({total_module/total_all*100:.1f}%)")
    print(f"Class-scope changes: {total_class} ({total_class/total_all*100:.1f}%)")