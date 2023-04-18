# -*- coding: UTF-8 -*-
"""
# @Author:  Zirui Zhou
# @Date:    2022/9/19 15:33:16
# @Contact: zirui.zhou19@student.xjtlu.edu.cn
"""

import logging
import sys
import time


class DebugTimer:
    """A simple class to record runtime of some codes.

    Attributes:
        start_time: A double of the timer's start time.
        end_time: A double of the timer's end time.
        desc: A string of the description of target process.
        print_format: A string of format of print().
        is_print: A boolean of whether time information is printed.
        logger: A logger to output the information.
    """
    start_time = 0
    end_time = 0
    desc = str()
    print_format = str()
    is_print = True
    logger = logging.Logger("DebugTimer", level=logging.INFO)

    def __init__(self, desc="unknown process", is_print=True, logger=None):
        self.desc = desc
        self.print_format = "The duration of {} is: {} s.\n"
        self.is_print = is_print
        self.logger.handlers = logger.handlers if logger else get_logger_handler()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.end()

    def start(self):
        """Start the timer.
        """
        self.start_time = time.perf_counter()

    def end(self):
        """End the timer.
        """
        self.end_time = time.perf_counter()
        if self.is_print:
            self.logger.info(self.print_format.format(self.desc, self.end_time - self.start_time))


def get_logger_handler(log_path=None, level=logging.DEBUG):
    handlers = list()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)
    handler.setFormatter(formatter)
    handlers.append(handler)

    if log_path:
        handler = logging.FileHandler(log_path)
        handler.setLevel(level)
        handler.setFormatter(formatter)
        handlers.append(handler)

    return handlers

