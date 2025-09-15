import sys
import logging

INLINE_LEVEL = 25
logging.addLevelName(INLINE_LEVEL, "INFO")


class InlineStreamHandler(logging.StreamHandler):
    def emit(self, record):
        try:
            msg = self.format(record)
            stream = self.stream
            if record.levelno == INLINE_LEVEL:
                # For inline messages, use carriage return and don't add newline
                stream.write(f"\r{msg}")
            else:
                stream.write(msg + self.terminator)
            self.flush()
        except Exception:
            self.handleError(record)


class InlineFormatter(logging.Formatter):
    def __init__(self, fmt=None):
        super().__init__(fmt, datefmt="%Y-%m-%d %H:%M:%S")
    
    def format(self, record):
        if record.levelno == INLINE_LEVEL:
            # For inline level, use the full custom format and pad to clear previous text
            formatted_message = super().format(record)
            return f"{formatted_message:<80}"  # Left-align and pad to clear previous text
        else:
            # For normal levels, use standard formatting
            return super().format(record)


def inline(self, message, *args, **kwargs):
    """Custom logger method for inline logging"""
    if self.isEnabledFor(INLINE_LEVEL):
        self._log(INLINE_LEVEL, message, args, **kwargs)


def setup_logger(name, emulator_type, level):
    # Add the inline method to Logger class if not already added
    if not hasattr(logging.Logger, 'inline'):
        logging.Logger.inline = inline
    
    # Create logger
    logger = logging.getLogger(name)
    
    # Clear any existing handlers to avoid duplicates
    logger.handlers.clear()
    
    # Create custom handler and formatter
    handler = InlineStreamHandler(sys.stdout)
    custom_format = f"%(asctime)s.%(msecs)03d | %(levelname)-7s | {emulator_type:<4} -- %(message)s"
    handler.setFormatter(InlineFormatter(custom_format))
    handler.setLevel(level)  # Use the same level as the logger
    
    # Configure logger
    logger.addHandler(handler)
    logger.setLevel(level)
    
    # Disable the default root logger to avoid duplicate messages
    logging.getLogger().handlers = []
    
    return logger
