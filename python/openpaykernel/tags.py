"""EMV data element dictionary (EMV Book 3 Annex A, Book C-2/C-3 data dictionaries).

Only the attributes a kernel needs at run time are kept: name, format and
source. Format codes: 'n' numeric BCD, 'cn' compressed numeric, 'an', 'ans',
'b' binary.
"""
from __future__ import annotations

from typing import NamedTuple


class Tag(NamedTuple):
    name: str
    fmt: str
    source: str  # 'ICC', 'TERM', 'ISS'


T = {
    0x42: Tag("Issuer Identification Number", "n", "ICC"),
    0x4F: Tag("Application Identifier (ADF Name)", "b", "ICC"),
    0x50: Tag("Application Label", "ans", "ICC"),
    0x56: Tag("Track 1 Data", "ans", "ICC"),
    0x57: Tag("Track 2 Equivalent Data", "b", "ICC"),
    0x5A: Tag("Application PAN", "cn", "ICC"),
    0x5F20: Tag("Cardholder Name", "ans", "ICC"),
    0x5F24: Tag("Application Expiration Date", "n", "ICC"),
    0x5F25: Tag("Application Effective Date", "n", "ICC"),
    0x5F28: Tag("Issuer Country Code", "n", "ICC"),
    0x5F2A: Tag("Transaction Currency Code", "n", "TERM"),
    0x5F2D: Tag("Language Preference", "an", "ICC"),
    0x5F30: Tag("Service Code", "n", "ICC"),
    0x5F34: Tag("PAN Sequence Number", "n", "ICC"),
    0x5F36: Tag("Transaction Currency Exponent", "n", "TERM"),
    0x5F50: Tag("Issuer URL", "ans", "ICC"),
    0x61: Tag("Application Template", "b", "ICC"),
    0x6F: Tag("FCI Template", "b", "ICC"),
    0x70: Tag("READ RECORD Response Template", "b", "ICC"),
    0x71: Tag("Issuer Script Template 1", "b", "ISS"),
    0x72: Tag("Issuer Script Template 2", "b", "ISS"),
    0x77: Tag("Response Message Template Format 2", "b", "ICC"),
    0x80: Tag("Response Message Template Format 1", "b", "ICC"),
    0x82: Tag("Application Interchange Profile", "b", "ICC"),
    0x84: Tag("Dedicated File Name", "b", "ICC"),
    0x87: Tag("Application Priority Indicator", "b", "ICC"),
    0x88: Tag("Short File Identifier", "b", "ICC"),
    0x89: Tag("Authorisation Code", "ans", "ISS"),
    0x8A: Tag("Authorisation Response Code", "an", "ISS"),
    0x8C: Tag("CDOL1", "b", "ICC"),
    0x8D: Tag("CDOL2", "b", "ICC"),
    0x8E: Tag("CVM List", "b", "ICC"),
    0x8F: Tag("CA Public Key Index", "b", "ICC"),
    0x90: Tag("Issuer Public Key Certificate", "b", "ICC"),
    0x91: Tag("Issuer Authentication Data", "b", "ISS"),
    0x92: Tag("Issuer Public Key Remainder", "b", "ICC"),
    0x93: Tag("Signed Static Application Data", "b", "ICC"),
    0x94: Tag("Application File Locator", "b", "ICC"),
    0x95: Tag("Terminal Verification Results", "b", "TERM"),
    0x97: Tag("TDOL", "b", "ICC"),
    0x98: Tag("TC Hash Value", "b", "TERM"),
    0x99: Tag("Transaction PIN Data", "b", "TERM"),
    0x9A: Tag("Transaction Date", "n", "TERM"),
    0x9B: Tag("Transaction Status Information", "b", "TERM"),
    0x9C: Tag("Transaction Type", "n", "TERM"),
    0x9D: Tag("DDF Name", "b", "ICC"),
    0x9F01: Tag("Acquirer Identifier", "n", "TERM"),
    0x9F02: Tag("Amount, Authorised (Numeric)", "n", "TERM"),
    0x9F03: Tag("Amount, Other (Numeric)", "n", "TERM"),
    0x9F06: Tag("Application Identifier (Terminal)", "b", "TERM"),
    0x9F07: Tag("Application Usage Control", "b", "ICC"),
    0x9F08: Tag("Application Version Number (Card)", "b", "ICC"),
    0x9F09: Tag("Application Version Number (Terminal)", "b", "TERM"),
    0x9F0D: Tag("IAC - Default", "b", "ICC"),
    0x9F0E: Tag("IAC - Denial", "b", "ICC"),
    0x9F0F: Tag("IAC - Online", "b", "ICC"),
    0x9F10: Tag("Issuer Application Data", "b", "ICC"),
    0x9F11: Tag("Issuer Code Table Index", "n", "ICC"),
    0x9F12: Tag("Application Preferred Name", "ans", "ICC"),
    0x9F13: Tag("Last Online ATC Register", "b", "ICC"),
    0x9F14: Tag("Lower Consecutive Offline Limit", "b", "ICC"),
    0x9F15: Tag("Merchant Category Code", "n", "TERM"),
    0x9F16: Tag("Merchant Identifier", "ans", "TERM"),
    0x9F17: Tag("PIN Try Counter", "b", "ICC"),
    0x9F1A: Tag("Terminal Country Code", "n", "TERM"),
    0x9F1B: Tag("Terminal Floor Limit", "b", "TERM"),
    0x9F1C: Tag("Terminal Identification", "an", "TERM"),
    0x9F1D: Tag("Terminal Risk Management Data", "b", "TERM"),
    0x9F1E: Tag("IFD Serial Number", "an", "TERM"),
    0x9F1F: Tag("Track 1 Discretionary Data", "ans", "ICC"),
    0x9F20: Tag("Track 2 Discretionary Data", "cn", "ICC"),
    0x9F21: Tag("Transaction Time", "n", "TERM"),
    0x9F23: Tag("Upper Consecutive Offline Limit", "b", "ICC"),
    0x9F26: Tag("Application Cryptogram", "b", "ICC"),
    0x9F27: Tag("Cryptogram Information Data", "b", "ICC"),
    0x9F2D: Tag("ICC PIN Encipherment PK Certificate", "b", "ICC"),
    0x9F2E: Tag("ICC PIN Encipherment PK Exponent", "b", "ICC"),
    0x9F2F: Tag("ICC PIN Encipherment PK Remainder", "b", "ICC"),
    0x9F32: Tag("Issuer Public Key Exponent", "b", "ICC"),
    0x9F33: Tag("Terminal Capabilities", "b", "TERM"),
    0x9F34: Tag("CVM Results", "b", "TERM"),
    0x9F35: Tag("Terminal Type", "n", "TERM"),
    0x9F36: Tag("Application Transaction Counter", "b", "ICC"),
    0x9F37: Tag("Unpredictable Number", "b", "TERM"),
    0x9F38: Tag("PDOL", "b", "ICC"),
    0x9F39: Tag("POS Entry Mode", "n", "TERM"),
    0x9F40: Tag("Additional Terminal Capabilities", "b", "TERM"),
    0x9F41: Tag("Transaction Sequence Counter", "n", "TERM"),
    0x9F42: Tag("Application Currency Code", "n", "ICC"),
    0x9F44: Tag("Application Currency Exponent", "n", "ICC"),
    0x9F45: Tag("Data Authentication Code", "b", "ICC"),
    0x9F46: Tag("ICC Public Key Certificate", "b", "ICC"),
    0x9F47: Tag("ICC Public Key Exponent", "b", "ICC"),
    0x9F48: Tag("ICC Public Key Remainder", "b", "ICC"),
    0x9F49: Tag("DDOL", "b", "ICC"),
    0x9F4A: Tag("SDA Tag List", "b", "ICC"),
    0x9F4B: Tag("Signed Dynamic Application Data", "b", "ICC"),
    0x9F4C: Tag("ICC Dynamic Number", "b", "ICC"),
    0x9F4D: Tag("Log Entry", "b", "ICC"),
    0x9F4E: Tag("Merchant Name and Location", "ans", "TERM"),
    0x9F53: Tag("Transaction Category Code", "an", "TERM"),
    0x9F5D: Tag("Application Capabilities Information", "b", "ICC"),
    0x9F66: Tag("Terminal Transaction Qualifiers", "b", "TERM"),
    0x9F69: Tag("Card Authentication Related Data", "b", "ICC"),
    0x9F6B: Tag("Track 2 Data (MSD)", "b", "ICC"),
    0x9F6C: Tag("Card Transaction Qualifiers", "b", "ICC"),
    0x9F6D: Tag("Mag-stripe Application Version Number (Reader)", "b", "TERM"),
    0x9F6E: Tag("Form Factor Indicator / Third Party Data", "b", "ICC"),
    0x9F7C: Tag("Customer Exclusive Data", "b", "ICC"),
    0xA5: Tag("FCI Proprietary Template", "b", "ICC"),
    0xBF0C: Tag("FCI Issuer Discretionary Data", "b", "ICC"),
    # Mastercard C-2 terminal-side data objects
    0x9F7E: Tag("Mobile Support Indicator", "b", "TERM"),
    0xDF8117: Tag("Card Data Input Capability", "b", "TERM"),
    0xDF8118: Tag("CVM Capability - CVM Required", "b", "TERM"),
    0xDF8119: Tag("CVM Capability - No CVM Required", "b", "TERM"),
    0xDF811B: Tag("Kernel Configuration", "b", "TERM"),
    0xDF811E: Tag("Mag-stripe CVM Capability - CVM Required", "b", "TERM"),
    0xDF811F: Tag("Security Capability", "b", "TERM"),
    0xDF8120: Tag("TAC - Default", "b", "TERM"),
    0xDF8121: Tag("TAC - Denial", "b", "TERM"),
    0xDF8122: Tag("TAC - Online", "b", "TERM"),
    0xDF8123: Tag("Reader Contactless Floor Limit", "n", "TERM"),
    0xDF8124: Tag("Reader CL Transaction Limit (No On-device CVM)", "n", "TERM"),
    0xDF8125: Tag("Reader CL Transaction Limit (On-device CVM)", "n", "TERM"),
    0xDF8126: Tag("Reader CVM Required Limit", "n", "TERM"),
    0xDF8129: Tag("Outcome Parameter Set", "b", "TERM"),
    0xDF812C: Tag("Mag-stripe CVM Capability - No CVM Required", "b", "TERM"),
    0xDF8115: Tag("Error Indication", "b", "TERM"),
    0xDF8116: Tag("User Interface Request Data", "b", "TERM"),
}


def fmt(tag: int) -> str:
    t = T.get(tag)
    return t.fmt if t else "b"


def name(tag: int) -> str:
    t = T.get(tag)
    return t.name if t else f"Unknown {tag:X}"


def is_terminal_source(tag: int) -> bool:
    if 0xDF8100 <= tag <= 0xDF81FF:
        return True
    t = T.get(tag)
    return bool(t and t.source == "TERM")
