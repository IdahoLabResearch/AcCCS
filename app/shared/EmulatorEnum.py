"""
    Copyright 2023, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED
"""

from enum import Enum


class Protocol(Enum):
    DIN = "DIN"
    ISO_2 = "ISO-2"
    ISO_20 = "ISO-20"


class PEVState(Enum):
    A = "a"
    B = "b"
    C = "c"


class RunMode(Enum):
    FULL = 0
    STOP = 1
    SCAN = 2


class EmulatorType(Enum):
    PEV = "pev"
    EVSE = "evse"