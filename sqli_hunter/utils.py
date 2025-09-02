# -*- coding: utf-8 -*-
"""
Utility Functions.

This module will contain various helper functions that are used across
the application, such as custom logging, user-agent generation,
and other common utilities to keep the main code clean.
"""
import logging
import sys

def get_logger(name: str) -> logging.Logger:
    """Creates and configures a logger instance."""
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)  # Set to DEBUG to capture all levels of messages

    # Create a handler to write messages to stderr
    handler = logging.StreamHandler(sys.stderr)

    # Create a formatter and set it for the handler
    # Example format: 2023-10-27 10:30:00,123 - exploiter - INFO - Log message here
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    handler.setFormatter(formatter)

    # Add the handler to the logger
    # Check if the logger already has handlers to avoid duplicate logs
    if not logger.handlers:
        logger.addHandler(handler)

    # Prevent log messages from propagating to the root logger
    logger.propagate = False

    return logger
