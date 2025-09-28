import matplotlib.pyplot as plt
import numpy as np


def visualize_package_cves(data, top_n=None, chart_type='barh', figsize=(12, 8), color='skyblue',
                           title='Number of CVEs Associated with Python Packages'):
    """
    可视化Python包及其关联的CVE数量

    参数:
        data (list): 包含元组的列表，格式为[('pkg:pypi/name', count), ...]
        top_n (int): 只显示前N个包，None表示显示全部
        chart_type (str): 图表类型，可选 'barh'(水平条形图，默认), 'bar'(垂直条形图), 'pie'(饼图)
        figsize (tuple): 图表尺寸，默认(12, 8)
        color (str): 图表颜色，默认'skyblue'
        title (str): 图表标题
    """
    # 处理数据
    sorted_data = sorted(data, key=lambda x: x[1], reverse=True)
    if top_n is not None:
        sorted_data = sorted_data[:top_n]

    packages = [x[0].replace('pkg:pypi/', '') for x in sorted_data]
    cve_counts = [x[1] for x in sorted_data]

    # 创建图表
    plt.figure(figsize=figsize)

    if chart_type == 'barh':
        # 水平条形图
        y_pos = np.arange(len(packages))
        bars = plt.barh(y_pos, cve_counts, color=color)
        plt.yticks(y_pos, packages)
        plt.xlabel('Number of CVEs')

        # 在条形上显示数字
        for bar in bars:
            width = bar.get_width()
            plt.text(width + max(cve_counts) * 0.02, bar.get_y() + bar.get_height() / 2,
                     f'{int(width)}', va='center')

    elif chart_type == 'bar':
        # 垂直条形图
        x_pos = np.arange(len(packages))
        bars = plt.bar(x_pos, cve_counts, color=color)
        plt.xticks(x_pos, packages, rotation=45, ha='right')
        plt.ylabel('Number of CVEs')

        # 在条形上显示数字
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width() / 2., height,
                     f'{int(height)}', ha='center', va='bottom')

    elif chart_type == 'pie':
        # 饼图
        def make_autopct(values):
            def my_autopct(pct):
                total = sum(values)
                val = int(round(pct * total / 100.0))
                return f'{pct:.1f}% ({val})'

            return my_autopct

        plt.pie(cve_counts, labels=packages, autopct=make_autopct(cve_counts),
                startangle=90, pctdistance=0.85)
        plt.axis('equal')  # 保持圆形

    else:
        raise ValueError("chart_type must be one of 'barh', 'bar', or 'pie'")

    plt.title(title)
    plt.tight_layout()
    # plt.show()


# 使用示例
if __name__ == "__main__":
    # 示例数据 - 实际使用时替换为你的完整数据
    sample_data = [
        ('pkg:pypi/tensorflow', 427),
        ('pkg:pypi/tensorflow-gpu', 421),
        ('pkg:pypi/tensorflow-cpu', 417),
        ('pkg:pypi/django', 126),
        ('pkg:pypi/plone', 100),
        ('pkg:pypi/apache-airflow', 85)
    ]

    # 显示前5个包的水平条形图
    visualize_package_cves(sample_data, top_n=5, chart_type='barh')

    # 显示前10个包的垂直条形图
    visualize_package_cves(sample_data, top_n=10, chart_type='bar', color='salmon')

    # 显示前5个包的饼图
    # visualize_package_cves(sample_data, top_n=5, chart_type='pie', title='Top 5 Packages by CVE Count')