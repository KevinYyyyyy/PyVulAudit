import logging
import sys
from pathlib import Path
class ColorFormatter(logging.Formatter):
    # ANSI 转义序列的颜色代码
    COLORS = {
        "DEBUG": "\033[94m",  # 蓝色
        "INFO": "\033[92m",   # 绿色
        "WARNING": "\033[93m",  # 黄色
        "ERROR": "\033[91m",  # 红色
        "CRITICAL": "\033[91m\033[1m"  # 红色加粗
    }
    RESET = "\033[0m"

    def format(self, record):
        # 获取原始日志消息
        log_message = super().format(record)
        # 根据日志级别添加颜色
        color = self.COLORS.get(record.levelname, self.RESET)
        return f"{color}{log_message}{self.RESET}"

def setup_logger(name: str, log_file: str = None, level: int = logging.INFO, 
                 console_output: bool = False, file_output: bool = True):
    """配置并返回一个logger实例
    
    Args:
        name: logger名称，通常使用__name__
        log_file: 日志文件路径，如果不提供则会根据运行的脚本名自动生成
        level: 日志级别，默认为INFO
        console_output: 是否输出到控制台，默认为True
        file_output: 是否输出到文件，默认为True
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # 清除已有的handler，避免重复添加
    logger.handlers.clear()
    
    # 日志格式
    formatter = ColorFormatter("%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s")
    
    # 控制台handler
    if console_output:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    
    # 文件handler
    if file_output:
        # 如果没有提供log_file，则根据运行的脚本名自动生成
        if log_file is None:
            script_name = Path(sys.argv[0]).stem
            log_file = f'./logs/{script_name}.log'
        
        # 确保日志目录存在
        log_path = Path(log_file).parent
        log_path.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_file, encoding='utf-8', mode='a')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger

logger = setup_logger(__name__, level=logging.DEBUG)
disable_logger = False
if disable_logger:
    logger.disabled = disable_logger
    logger.warning("After disabling, this will NOT be printed.")
