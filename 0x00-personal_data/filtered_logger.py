#!/usr/bin/env python3
"""Filtered logger"""


import re
from typing import List


def filter_datum(fields: List[str], redaction: str,
                 message: str, separator: str) -> str:
    """
     Returns a string with the specified fields obfuscated
    """

    for field in fields:
        message = re.sub(f'{field}=.*?{separator}',
                     f'{field}={redaction}{separator}', message)
    return message
