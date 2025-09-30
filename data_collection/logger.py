import logging
import sys
from pathlib import Path
class ColorFormatter(logging.Formatter):
    # ANSI escape sequence color codes
    COLORS = {
        "DEBUG": "\033[94m",  # Blue
        "INFO": "\033[92m",   # Green
        "WARNING": "\033[93m",  # Yellow
        "ERROR": "\033[91m",  # Red
        "CRITICAL": "\033[91m\033[1m"  # Red bold
    }
    RESET = "\033[0m"

    def format(self, record):
        # Get the original log message
        log_message = super().format(record)
        # Add color based on log level
        color = self.COLORS.get(record.levelname, self.RESET)
        return f"{color}{log_message}{self.RESET}"

def setup_logger(name: str, log_file: str = None, level: int = logging.INFO, 
                 console_output: bool = False, file_output: bool = True):
    """Configure and return a logger instance
    
    Args:
        name: Logger name, usually use __name__
        log_file: Log file path, if not provided, will be auto-generated based on the running script name
        level: Log level, default is INFO
        console_output: Whether to output to console, default is True
        file_output: Whether to output to file, default is True
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Clear existing handlers to avoid duplicate additions
    logger.handlers.clear()
    
    # Log format
    formatter = ColorFormatter("%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s")
    
    # Console handler
    if console_output:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    
    # File handler
    if file_output:
        # If log_file is not provided, auto-generate based on the running script name
        if log_file is None:
            script_name = Path(sys.argv[0]).stem
            log_file = f'./logs/{script_name}.log'
        
        # Ensure log directory exists
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
