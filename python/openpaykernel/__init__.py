"""OpenPayKernel: an open-source EMV Level 2 kernel (contact and contactless).

STUDY / RESEARCH USE ONLY. Not certified by EMVCo or any payment brand, not security-audited,
not guaranteed to be bug-free, and provided "AS IS" without warranty (Apache-2.0). Do not use it
to process real payments. See the Disclaimer in README.md.
"""
from .capk import CAPK, CAPKStore
from .config import AidConfig, Environment, TerminalConfig, Transaction
from .contact import AutoHost, ContactKernel, ContactResult, OnlineResponse
from .entry_point import EntryPoint
from .kernels.discover import DiscoverKernel
from .kernels.mastercard import MastercardKernel
from .kernels.unionpay import UnionPayKernel
from .kernels.visa import VisaKernel
from .outcome import CVM, Outcome, Status

__version__ = "0.1.0"

__all__ = [
    "CAPK", "CAPKStore", "AidConfig", "Environment", "TerminalConfig", "Transaction", "AutoHost",
    "ContactKernel", "ContactResult", "OnlineResponse", "EntryPoint", "MastercardKernel", "VisaKernel",
    "CVM", "Outcome", "Status", "UnionPayKernel", "DiscoverKernel",
]
