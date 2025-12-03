import logging
import os
import colorlog

def setup_logging():
    """
    Configures logging to output to the console with colors and to two
    separate files in a 'logs' directory: one for DEBUG and one for INFO.
    """

    DEBUG_GREEN_LEVEL = 9
    DEBUG_RED_LEVEL = 8
    DEBUG_PURPLE_LEVEL = 7
    DEBUG_YELLOW_LEVEL = 6
    logging.addLevelName(DEBUG_GREEN_LEVEL, "DBG_Green")
    logging.addLevelName(DEBUG_RED_LEVEL, "DBG_Red")
    logging.addLevelName(DEBUG_PURPLE_LEVEL, "DBG_Purple")
    logging.addLevelName(DEBUG_YELLOW_LEVEL, "DBG_Yellow")

    def debug_purple(self, message, *args, **kws):
        if self.isEnabledFor(DEBUG_PURPLE_LEVEL):
            self._log(DEBUG_PURPLE_LEVEL, message, args, **kws)

    def debug_green(self, message, *args, **kws):
        if self.isEnabledFor(DEBUG_GREEN_LEVEL):
            self._log(DEBUG_GREEN_LEVEL, message, args, **kws)

    def debug_red(self, message, *args, **kws):
        if self.isEnabledFor(DEBUG_RED_LEVEL):
            self._log(DEBUG_RED_LEVEL, message, args, **kws)

    def debug_yellow(self, message, *args, **kws):
        if self.isEnabledFor(DEBUG_YELLOW_LEVEL):
            self._log(DEBUG_YELLOW_LEVEL, message, args, **kws)

    logging.Logger.debug_green = debug_green
    logging.Logger.debug_red = debug_red
    logging.Logger.debug_purple = debug_purple
    logging.Logger.debug_yellow = debug_yellow

    LOG_DIR = "logs"
    os.makedirs(LOG_DIR, exist_ok=True) 


    logger = logging.getLogger()
    logger.setLevel(DEBUG_YELLOW_LEVEL)
    
    if logger.hasHandlers():
        logger.handlers.clear()

    file_formatter = logging.Formatter(
        fmt='%(asctime)s [%(levelname)-8s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_formatter = colorlog.ColoredFormatter(
        fmt='%(log_color)s%(asctime)s [%(levelname)-8s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        log_colors={
            'DEBUG':    'cyan',
            'INFO':     'white',
            'WARNING':  'yellow',
            'ERROR':    'red',
            'CRITICAL': 'bold_red,bg_white',
            'DBG_Green':   'green',
            'DBG_Red': 'red',
            'DBG_Purple': 'purple',
            'DBG_Yellow': 'yellow'
        }
    )


    debug_file_handler = logging.FileHandler(os.path.join(LOG_DIR, "debug.log"), mode ='w')
    debug_file_handler.setLevel(DEBUG_YELLOW_LEVEL) # Capture everything from the lowest level up
    debug_file_handler.setFormatter(file_formatter)
    logger.addHandler(debug_file_handler)

    info_file_handler = logging.FileHandler(os.path.join(LOG_DIR, "info.log"), mode ='w')
    info_file_handler.setLevel(logging.INFO) 
    info_file_handler.setFormatter(file_formatter)
    logger.addHandler(info_file_handler)

    console_handler = colorlog.StreamHandler()
    console_handler.setLevel(logging.ERROR)
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

