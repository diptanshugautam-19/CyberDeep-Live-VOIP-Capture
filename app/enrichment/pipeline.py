from collections import Counter, defaultdict
from datetime import datetime, timezone
from ipaddress import IPv4Address, ip_address

from dateutil import parser as date_parser

from app.enrichment.ports import port_intelligence
from app.enrichment.services import identify_service
from app.enrichment.telecom import enrich_telecom
from app.analysis.traffic import build_network_intelligence
from app.parsers.base import ConnectionRecord
from app.threat_intel.manager import ThreatIntelManager


STUN_TURN_PORTS = {3478, 3479, 3480, 3481, 5349, 19302, 19305}

IGNORE_PROTOCOLS = {
    "HTTP",
    "FTP",
    "SMTP",
    "POP3",
    "IMAP",
    "SMB",
    "NFS",
    "RDP",
    "TELNET",
    "MYSQL",
    "POSTGRESQL",
    "BITTORRENT"
}

OUI_DATABASE = {
    # 24-bit (6 hex chars) - MA-L
    # Apple Inc.
    "000393": ("Apple Inc.", "Mobile / Laptop"),
    "000502": ("Apple Inc.", "Mobile / Laptop"),
    "000A27": ("Apple Inc.", "Mobile / Laptop"),
    "000A95": ("Apple Inc.", "Mobile / Laptop"),
    "000D93": ("Apple Inc.", "Mobile / Laptop"),
    "0010FA": ("Apple Inc.", "Mobile / Laptop"),
    "001451": ("Apple Inc.", "Mobile / Laptop"),
    "0016CB": ("Apple Inc.", "Mobile / Laptop"),
    "0017F2": ("Apple Inc.", "Mobile / Laptop"),
    "0019E3": ("Apple Inc.", "Mobile / Laptop"),
    "001A2B": ("Apple Inc.", "Mobile / Laptop"),
    "001B63": ("Apple Inc.", "Mobile / Laptop"),
    "001CB3": ("Apple Inc.", "Mobile / Laptop"),
    "001D4F": ("Apple Inc.", "Mobile / Laptop"),
    "001E52": ("Apple Inc.", "Mobile / Laptop"),
    "001EC2": ("Apple Inc.", "Mobile / Laptop"),
    "001F5B": ("Apple Inc.", "Mobile / Laptop"),
    "001FF3": ("Apple Inc.", "Mobile / Laptop"),
    "0021E9": ("Apple Inc.", "Mobile / Laptop"),
    "002241": ("Apple Inc.", "Mobile / Laptop"),
    "002312": ("Apple Inc.", "Mobile / Laptop"),
    "002332": ("Apple Inc.", "Mobile / Laptop"),
    "00236C": ("Apple Inc.", "Mobile / Laptop"),
    "002436": ("Apple Inc.", "Mobile / Laptop"),
    "002500": ("Apple Inc.", "Mobile / Laptop"),
    "00254B": ("Apple Inc.", "Mobile / Laptop"),
    "002608": ("Apple Inc.", "Mobile / Laptop"),
    "00264A": ("Apple Inc.", "Mobile / Laptop"),
    "0026B0": ("Apple Inc.", "Mobile / Laptop"),
    "0026BB": ("Apple Inc.", "Mobile / Laptop"),
    "040CCE": ("Apple Inc.", "Mobile / Laptop"),
    "041E64": ("Apple Inc.", "Mobile / Laptop"),
    "042665": ("Apple Inc.", "Mobile / Laptop"),
    "045E60": ("Apple Inc.", "Mobile / Laptop"),
    "045453": ("Apple Inc.", "Mobile / Laptop"),
    "10DDB1": ("Apple Inc.", "Mobile / Laptop"),
    "14109F": ("Apple Inc.", "Mobile / Laptop"),
    "1499E2": ("Apple Inc.", "Mobile / Laptop"),
    "14AC60": ("Apple Inc.", "Mobile / Laptop"),
    "18AF61": ("Apple Inc.", "Mobile / Laptop"),
    "28CFE9": ("Apple Inc.", "Mobile / Laptop"),
    "305714": ("Apple Inc.", "Mobile / Laptop"),
    "34159E": ("Apple Inc.", "Mobile / Laptop"),
    "38CADA": ("Apple Inc.", "Mobile / Laptop"),
    "3C0754": ("Apple Inc.", "Mobile / Laptop"),
    "403CFC": ("Apple Inc.", "Mobile / Laptop"),
    "40A3CC": ("Apple Inc.", "Mobile / Laptop"),
    "442A60": ("Apple Inc.", "Mobile / Laptop"),
    "44D884": ("Apple Inc.", "Mobile / Laptop"),
    "482C6A": ("Apple Inc.", "Mobile / Laptop"),
    "48A98A": ("Apple Inc.", "Mobile / Laptop"),
    "48D705": ("Apple Inc.", "Mobile / Laptop"),
    "503EAA": ("Apple Inc.", "Mobile / Laptop"),
    "508492": ("Apple Inc.", "Mobile / Laptop"),
    "5425EA": ("Apple Inc.", "Mobile / Laptop"),
    "542A1B": ("Apple Inc.", "Mobile / Laptop"),
    "5855CA": ("Apple Inc.", "Mobile / Laptop"),
    "600308": ("Apple Inc.", "Mobile / Laptop"),
    "603074": ("Apple Inc.", "Mobile / Laptop"),
    "60C547": ("Apple Inc.", "Mobile / Laptop"),
    "64006A": ("Apple Inc.", "Mobile / Laptop"),
    "64200C": ("Apple Inc.", "Mobile / Laptop"),
    "685B35": ("Apple Inc.", "Mobile / Laptop"),
    "68A86D": ("Apple Inc.", "Mobile / Laptop"),
    "6C4008": ("Apple Inc.", "Mobile / Laptop"),
    "6C709F": ("Apple Inc.", "Mobile / Laptop"),
    "701124": ("Apple Inc.", "Mobile / Laptop"),
    "703EAC": ("Apple Inc.", "Mobile / Laptop"),
    "70A2B3": ("Apple Inc.", "Mobile / Laptop"),
    "748114": ("Apple Inc.", "Mobile / Laptop"),
    "7831C1": ("Apple Inc.", "Mobile / Laptop"),
    "78CA39": ("Apple Inc.", "Mobile / Laptop"),
    "7C04D0": ("Apple Inc.", "Mobile / Laptop"),
    "7CC3A1": ("Apple Inc.", "Mobile / Laptop"),
    "7CC537": ("Apple Inc.", "Mobile / Laptop"),
    "7CD1C3": ("Apple Inc.", "Mobile / Laptop"),
    "800184": ("Apple Inc.", "Mobile / Laptop"),
    "804971": ("Apple Inc.", "Mobile / Laptop"),
    "80929F": ("Apple Inc.", "Mobile / Laptop"),
    "842999": ("Apple Inc.", "Mobile / Laptop"),
    "843835": ("Apple Inc.", "Mobile / Laptop"),
    "8489AD": ("Apple Inc.", "Mobile / Laptop"),
    "84FCAC": ("Apple Inc.", "Mobile / Laptop"),
    "88665A": ("Apple Inc.", "Mobile / Laptop"),
    "8863DF": ("Apple Inc.", "Mobile / Laptop"),
    "88AE07": ("Apple Inc.", "Mobile / Laptop"),
    "8C8590": ("Apple Inc.", "Mobile / Laptop"),
    "8C8E2F": ("Apple Inc.", "Mobile / Laptop"),
    "907240": ("Apple Inc.", "Mobile / Laptop"),
    "9801A7": ("Apple Inc.", "Mobile / Laptop"),
    "985F41": ("Apple Inc.", "Mobile / Laptop"),
    "98B6E9": ("Apple Inc.", "Mobile / Laptop"),
    "A45E60": ("Apple Inc.", "Mobile / Laptop"),
    "A4B197": ("Apple Inc.", "Mobile / Laptop"),
    "A82066": ("Apple Inc.", "Mobile / Laptop"),
    "A85B78": ("Apple Inc.", "Mobile / Laptop"),
    "A8667F": ("Apple Inc.", "Mobile / Laptop"),
    "A88E24": ("Apple Inc.", "Mobile / Laptop"),
    "AC1F74": ("Apple Inc.", "Mobile / Laptop"),
    "ACBC32": ("Apple Inc.", "Mobile / Laptop"),
    "ACCF85": ("Apple Inc.", "Mobile / Laptop"),
    "B03495": ("Apple Inc.", "Mobile / Laptop"),
    "B0702D": ("Apple Inc.", "Mobile / Laptop"),
    "B0C559": ("Apple Inc.", "Mobile / Laptop"),
    "B418D1": ("Apple Inc.", "Mobile / Laptop"),
    "B48B19": ("Apple Inc.", "Mobile / Laptop"),
    "B8098A": ("Apple Inc.", "Mobile / Laptop"),
    "B8C75D": ("Apple Inc.", "Mobile / Laptop"),
    "B8E937": ("Apple Inc.", "Mobile / Laptop"),
    "B8F6B1": ("Apple Inc.", "Mobile / Laptop"),
    "C03896": ("Apple Inc.", "Mobile / Laptop"),
    "C01ADA": ("Apple Inc.", "Mobile / Laptop"),
    "C0847A": ("Apple Inc.", "Mobile / Laptop"),
    "C0CCF8": ("Apple Inc.", "Mobile / Laptop"),
    "C42C03": ("Apple Inc.", "Mobile / Laptop"),
    "C4B301": ("Apple Inc.", "Mobile / Laptop"),
    "C81EE7": ("Apple Inc.", "Mobile / Laptop"),
    "C86F1D": ("Apple Inc.", "Mobile / Laptop"),
    "C8BCC8": ("Apple Inc.", "Mobile / Laptop"),
    "D023DB": ("Apple Inc.", "Mobile / Laptop"),
    "D0817A": ("Apple Inc.", "Mobile / Laptop"),
    "D0C637": ("Apple Inc.", "Mobile / Laptop"),
    "D4909C": ("Apple Inc.", "Mobile / Laptop"),
    "D81D72": ("Apple Inc.", "Mobile / Laptop"),
    "D83062": ("Apple Inc.", "Mobile / Laptop"),
    "D89695": ("Apple Inc.", "Mobile / Laptop"),
    "D8A25E": ("Apple Inc.", "Mobile / Laptop"),
    "E0C97A": ("Apple Inc.", "Mobile / Laptop"),
    "E0DB55": ("Apple Inc.", "Mobile / Laptop"),
    "E0F5C6": ("Apple Inc.", "Mobile / Laptop"),
    "E425E9": ("Apple Inc.", "Mobile / Laptop"),
    "E4E4AB": ("Apple Inc.", "Mobile / Laptop"),
    "E8802E": ("Apple Inc.", "Mobile / Laptop"),
    "E8B2AC": ("Apple Inc.", "Mobile / Laptop"),
    "F01898": ("Apple Inc.", "Mobile / Laptop"),
    "F099BF": ("Apple Inc.", "Mobile / Laptop"),
    "F0DBF8": ("Apple Inc.", "Mobile / Laptop"),
    "F40F24": ("Apple Inc.", "Mobile / Laptop"),
    "F437B7": ("Apple Inc.", "Mobile / Laptop"),
    "F45C89": ("Apple Inc.", "Mobile / Laptop"),
    "F4F15A": ("Apple Inc.", "Mobile / Laptop"),
    "F4F951": ("Apple Inc.", "Mobile / Laptop"),
    "F81EDF": ("Apple Inc.", "Mobile / Laptop"),
    "F82793": ("Apple Inc.", "Mobile / Laptop"),
    "F86214": ("Apple Inc.", "Mobile / Laptop"),
    "FCE998": ("Apple Inc.", "Mobile / Laptop"),

    # Samsung Electronics
    "0000F0": ("Samsung Electronics", "Mobile / Laptop"),
    "0007AB": ("Samsung Electronics", "Mobile / Laptop"),
    "001247": ("Samsung Electronics", "Mobile / Laptop"),
    "0015B9": ("Samsung Electronics", "Mobile / Laptop"),
    "0016DB": ("Samsung Electronics", "Mobile / Laptop"),
    "0017C9": ("Samsung Electronics", "Mobile / Laptop"),
    "001A8A": ("Samsung Electronics", "Mobile / Laptop"),
    "001E7D": ("Samsung Electronics", "Mobile / Laptop"),
    "0021D2": ("Samsung Electronics", "Mobile / Laptop"),
    "00233D": ("Samsung Electronics", "Mobile / Laptop"),
    "002518": ("Samsung Electronics", "Mobile / Laptop"),
    "04180F": ("Samsung Electronics", "Mobile / Laptop"),
    "04FE8D": ("Samsung Electronics", "Mobile / Laptop"),
    "0808C2": ("Samsung Electronics", "Mobile / Laptop"),
    "0C1420": ("Samsung Electronics", "Mobile / Laptop"),
    "0C715D": ("Samsung Electronics", "Mobile / Laptop"),
    "103047": ("Samsung Electronics", "Mobile / Laptop"),
    "1436C6": ("Samsung Electronics", "Mobile / Laptop"),
    "14F435": ("Samsung Electronics", "Mobile / Laptop"),
    "1C5A3E": ("Samsung Electronics", "Mobile / Laptop"),
    "24E6FD": ("Samsung Electronics", "Mobile / Laptop"),
    "28C5D2": ("Intel Corporation", "Network Adapter"),
    "30078D": ("Samsung Electronics", "Mobile / Laptop"),
    "300C23": ("Samsung Electronics", "Mobile / Laptop"),
    "34C3AC": ("Samsung Electronics", "Mobile / Laptop"),
    "382DC7": ("Samsung Electronics", "Mobile / Laptop"),
    "38AA3C": ("Samsung Electronics", "Mobile / Laptop"),
    "3C5A37": ("Samsung Electronics", "Mobile / Laptop"),
    "3CA581": ("Samsung Electronics", "Mobile / Laptop"),
    "3CF72C": ("Samsung Electronics", "Mobile / Laptop"),
    "40163B": ("Samsung Electronics", "Mobile / Laptop"),
    "4083DE": ("Samsung Electronics", "Mobile / Laptop"),
    "40D32D": ("Samsung Electronics", "Mobile / Laptop"),
    "444E1A": ("Samsung Electronics", "Mobile / Laptop"),
    "44F459": ("Samsung Electronics", "Mobile / Laptop"),
    "4827EA": ("Samsung Electronics", "Mobile / Laptop"),
    "485AB6": ("Samsung Electronics", "Mobile / Laptop"),
    "4CBCA5": ("Samsung Electronics", "Mobile / Laptop"),
    "5001D9": ("Samsung Electronics", "Mobile / Laptop"),
    "503275": ("Samsung Electronics", "Mobile / Laptop"),
    "508569": ("Samsung Electronics", "Mobile / Laptop"),
    "50FE0C": ("Samsung Electronics", "Mobile / Laptop"),
    "5440AD": ("Samsung Electronics", "Mobile / Laptop"),
    "5C3C27": ("Samsung Electronics", "Mobile / Laptop"),
    "5CE8EB": ("Samsung Electronics", "Mobile / Laptop"),
    "6021C0": ("Samsung Electronics", "Mobile / Laptop"),
    "60AF6D": ("Samsung Electronics", "Mobile / Laptop"),
    "64B310": ("Samsung Electronics", "Mobile / Laptop"),
    "6C4F89": ("Samsung Electronics", "Mobile / Laptop"),
    "6C8DC1": ("Samsung Electronics", "Mobile / Laptop"),
    "703EB5": ("Samsung Electronics", "Mobile / Laptop"),
    "745F00": ("Samsung Electronics", "Mobile / Laptop"),
    "781A9A": ("Samsung Electronics", "Mobile / Laptop"),
    "7825AD": ("Samsung Electronics", "Mobile / Laptop"),
    "783A84": ("Samsung Electronics", "Mobile / Laptop"),
    "784B87": ("Samsung Electronics", "Mobile / Laptop"),
    "78E8B6": ("Samsung Electronics", "Mobile / Laptop"),
    "7C03D8": ("Samsung Electronics", "Mobile / Laptop"),
    "804C85": ("Samsung Electronics", "Mobile / Laptop"),
    "84253F": ("Samsung Electronics", "Mobile / Laptop"),
    "843838": ("Samsung Electronics", "Mobile / Laptop"),
    "8455A5": ("Samsung Electronics", "Mobile / Laptop"),
    "847AA8": ("Samsung Electronics", "Mobile / Laptop"),
    "88308A": ("Samsung Electronics", "Mobile / Laptop"),
    "8CC8CD": ("Samsung Electronics", "Mobile / Laptop"),
    "90187C": ("Samsung Electronics", "Mobile / Laptop"),
    "9405BB": ("Samsung Electronics", "Mobile / Laptop"),
    "94652D": ("Samsung Electronics", "Mobile / Laptop"),
    "9476B7": ("Samsung Electronics", "Mobile / Laptop"),
    "948C10": ("Samsung Electronics", "Mobile / Laptop"),
    "94B10A": ("Samsung Electronics", "Mobile / Laptop"),
    "94E979": ("Samsung Electronics", "Mobile / Laptop"),
    "980D2E": ("Samsung Electronics", "Mobile / Laptop"),
    "983B8F": ("Samsung Electronics", "Mobile / Laptop"),
    "98BD80": ("Samsung Electronics", "Mobile / Laptop"),
    "98DAC4": ("TP-Link Technologies", "Router / Switch"),
    "98F170": ("Samsung Electronics", "Mobile / Laptop"),
    "9C0298": ("Samsung Electronics", "Mobile / Laptop"),
    "9C3AAF": ("Samsung Electronics", "Mobile / Laptop"),
    "A00798": ("Samsung Electronics", "Mobile / Laptop"),
    "A0793A": ("Samsung Electronics", "Mobile / Laptop"),
    "A0B43F": ("Samsung Electronics", "Mobile / Laptop"),
    "A4307A": ("Samsung Electronics", "Mobile / Laptop"),
    "A470D6": ("Samsung Electronics", "Mobile / Laptop"),
    "A80600": ("Samsung Electronics", "Mobile / Laptop"),
    "A87B39": ("Samsung Electronics", "Mobile / Laptop"),
    "A89FBA": ("Samsung Electronics", "Mobile / Laptop"),
    "AC3613": ("Samsung Electronics", "Mobile / Laptop"),
    "AC5AF0": ("Samsung Electronics", "Mobile / Laptop"),
    "B0C4E7": ("Samsung Electronics", "Mobile / Laptop"),
    "B0D59D": ("Samsung Electronics", "Mobile / Laptop"),
    "B44BD2": ("Apple Inc.", "Mobile / Laptop"),
    "B479A7": ("Samsung Electronics", "Mobile / Laptop"),
    "B85510": ("Samsung Electronics", "Mobile / Laptop"),
    "B8C5C1": ("Samsung Electronics", "Mobile / Laptop"),
    "C0BDC8": ("Samsung Electronics", "Mobile / Laptop"),
    "C44202": ("Samsung Electronics", "Mobile / Laptop"),
    "C4731E": ("Samsung Electronics", "Mobile / Laptop"),
    "CC07AB": ("Samsung Electronics", "Mobile / Laptop"),
    "CC3A61": ("Samsung Electronics", "Mobile / Laptop"),
    "D059E4": ("Samsung Electronics", "Mobile / Laptop"),
    "D4E1C8": ("Samsung Electronics", "Mobile / Laptop"),
    "D807B6": ("TP-Link Technologies", "Router / Switch"),
    "D8492F": ("Canon Inc.", "Printer / Camera"),
    "D857EF": ("Samsung Electronics", "Mobile / Laptop"),
    # "E0D53E" is unknown,
    "E0AA96": ("Samsung Electronics", "Mobile / Laptop"),
    "E47CF5": ("Samsung Electronics", "Mobile / Laptop"),
    "E4B021": ("Samsung Electronics", "Mobile / Laptop"),
    "E807BF": ("Samsung Electronics", "Mobile / Laptop"),
    "E8508B": ("Samsung Electronics", "Mobile / Laptop"),
    "E8E5D6": ("Samsung Electronics", "Mobile / Laptop"),
    "F0E77E": ("Samsung Electronics", "Mobile / Laptop"),
    "F409D8": ("Samsung Electronics", "Mobile / Laptop"),
    "F4428F": ("Samsung Electronics", "Mobile / Laptop"),
    "F47B5E": ("Samsung Electronics", "Mobile / Laptop"),
    "F4D488": ("Samsung Electronics", "Mobile / Laptop"),
    "F8042E": ("Samsung Electronics", "Mobile / Laptop"),
    "F8CFC5": ("Samsung Electronics", "Mobile / Laptop"),
    "FC0012": ("Samsung Electronics", "Mobile / Laptop"),
    "FC3CC8": ("Samsung Electronics", "Mobile / Laptop"),
    "FCA13E": ("Samsung Electronics", "Mobile / Laptop"),

    # Intel Corporation
    "000347": ("Intel Corporation", "Network Adapter"),
    "000423": ("Intel Corporation", "Network Adapter"),
    "0008A1": ("Intel Corporation", "Network Adapter"),
    "000E0C": ("Intel Corporation", "Network Adapter"),
    "001302": ("Intel Corporation", "Network Adapter"),
    "001320": ("Intel Corporation", "Network Adapter"),
    "001500": ("Intel Corporation", "Network Adapter"),
    "0016EA": ("Intel Corporation", "Network Adapter"),
    "0018DE": ("Intel Corporation", "Network Adapter"),
    "001B21": ("Intel Corporation", "Network Adapter"),
    "001CC0": ("Intel Corporation", "Network Adapter"),
    "001DE0": ("Intel Corporation", "Network Adapter"),
    "001F3C": ("Intel Corporation", "Network Adapter"),
    "00215C": ("Intel Corporation", "Network Adapter"),
    "00216A": ("Intel Corporation", "Network Adapter"),
    "00216B": ("Intel Corporation", "Network Adapter"),
    "002314": ("Intel Corporation", "Network Adapter"),
    "0024D7": ("Intel Corporation", "Network Adapter"),
    "00270E": ("Intel Corporation", "Network Adapter"),
    "002710": ("Intel Corporation", "Network Adapter"),
    "00DBDF": ("Intel Corporation", "Network Adapter"),
    "047D7B": ("Intel Corporation", "Network Adapter"),
    "04EA56": ("Intel Corporation", "Network Adapter"),
    "081196": ("Intel Corporation", "Network Adapter"),
    "083E8E": ("Intel Corporation", "Network Adapter"),
    "089E01": ("Intel Corporation", "Network Adapter"),
    "1002B5": ("Intel Corporation", "Network Adapter"),
    "103D1C": ("Intel Corporation", "Network Adapter"),
    "10F311": ("Intel Corporation", "Network Adapter"),
    "142D27": ("Intel Corporation", "Network Adapter"),
    "185E0F": ("Intel Corporation", "Network Adapter"),
    "2016D8": ("Intel Corporation", "Network Adapter"),
    "244BFE": ("Intel Corporation", "Network Adapter"),
    "281878": ("Intel Corporation", "Network Adapter"),
    "2C5339": ("Intel Corporation", "Network Adapter"),
    "3010B3": ("Intel Corporation", "Network Adapter"),
    "3035AD": ("Intel Corporation", "Network Adapter"),
    "3052CB": ("Intel Corporation", "Network Adapter"),
    "3413E8": ("Intel Corporation", "Network Adapter"),
    "343111": ("Intel Corporation", "Network Adapter"),
    "346F24": ("Intel Corporation", "Network Adapter"),
    "34E6AD": ("Intel Corporation", "Network Adapter"),
    "3C52A1": ("Intel Corporation", "Network Adapter"),
    "3C6A97": ("Intel Corporation", "Network Adapter"),
    "40169F": ("Intel Corporation", "Network Adapter"),
    "40E230": ("Intel Corporation", "Network Adapter"),
    "448500": ("Intel Corporation", "Network Adapter"),
    "4851B5": ("Intel Corporation", "Network Adapter"),
    "4C3488": ("Intel Corporation", "Network Adapter"),
    "4C796E": ("Intel Corporation", "Network Adapter"),
    "4CEDDE": ("Intel Corporation", "Network Adapter"),
    "507B9D": ("Intel Corporation", "Network Adapter"),
    "50BBB5": ("Intel Corporation", "Network Adapter"),
    "5414F3": ("Intel Corporation", "Network Adapter"),
    "54833A": ("Intel Corporation", "Network Adapter"),
    "54A050": ("Intel Corporation", "Network Adapter"),
    "54E1AD": ("Intel Corporation", "Network Adapter"),
    "58946B": ("Intel Corporation", "Network Adapter"),
    "5C879C": ("Intel Corporation", "Network Adapter"),
    "5CBA37": ("Intel Corporation", "Network Adapter"),
    "600292": ("Intel Corporation", "Network Adapter"),
    "605718": ("Intel Corporation", "Network Adapter"),
    "606720": ("Intel Corporation", "Network Adapter"),
    "60F262": ("Intel Corporation", "Network Adapter"),
    "641CAE": ("Intel Corporation", "Network Adapter"),
    "645D86": ("Intel Corporation", "Network Adapter"),
    "680715": ("Intel Corporation", "Network Adapter"),
    "68ECC5": ("Intel Corporation", "Network Adapter"),
    "70188B": ("Intel Corporation", "Network Adapter"),
    "704D7B": ("Intel Corporation", "Network Adapter"),
    "705A0F": ("Intel Corporation", "Network Adapter"),
    "705AB6": ("Intel Corporation", "Network Adapter"),
    "70C94E": ("Intel Corporation", "Network Adapter"),
    "7440BB": ("Intel Corporation", "Network Adapter"),
    "74D02B": ("Intel Corporation", "Network Adapter"),
    "74E543": ("Intel Corporation", "Network Adapter"),
    "784F43": ("Intel Corporation", "Network Adapter"),
    "7C5079": ("Intel Corporation", "Network Adapter"),
    "7CB0C2": ("Intel Corporation", "Network Adapter"),
    "8086F2": ("Intel Corporation", "Network Adapter"),
    "80C5F2": ("Intel Corporation", "Network Adapter"),
    "80FA5B": ("Intel Corporation", "Network Adapter"),
    "844BF5": ("Intel Corporation", "Network Adapter"),
    "84FDD1": ("Intel Corporation", "Network Adapter"),
    "88532E": ("Intel Corporation", "Network Adapter"),
    "88b111": ("Intel Corporation", "Network Adapter"),
    "88D7F6": ("Intel Corporation", "Network Adapter"),
    "8C1645": ("Intel Corporation", "Network Adapter"),
    "8C3BAD": ("Intel Corporation", "Network Adapter"),
    "902E1C": ("Intel Corporation", "Network Adapter"),
    "90CDB6": ("Intel Corporation", "Network Adapter"),
    "90E2BA": ("Intel Corporation", "Network Adapter"),
    "940853": ("Intel Corporation", "Network Adapter"),
    "94B86D": ("Intel Corporation", "Network Adapter"),
    "94DE80": ("Intel Corporation", "Network Adapter"),
    "98AF65": ("Intel Corporation", "Network Adapter"),
    "98E7F5": ("Intel Corporation", "Network Adapter"),
    "9C2A70": ("Intel Corporation", "Network Adapter"),
    "9C4E36": ("Intel Corporation", "Network Adapter"),
    "9CB6D0": ("Intel Corporation", "Network Adapter"),
    "A002A9": ("Intel Corporation", "Network Adapter"),
    "A01290": ("Intel Corporation", "Network Adapter"),
    "A03299": ("Intel Corporation", "Network Adapter"),
    "A0510B": ("Intel Corporation", "Network Adapter"),
    "A088B4": ("Intel Corporation", "Network Adapter"),
    "A0C589": ("Intel Corporation", "Network Adapter"),
    "A402B9": ("Intel Corporation", "Network Adapter"),
    "A438CC": ("Intel Corporation", "Network Adapter"),
    "A44E31": ("Intel Corporation", "Network Adapter"),
    "A4B1C1": ("Intel Corporation", "Network Adapter"),
    "A81E84": ("Intel Corporation", "Network Adapter"),
    "A864F1": ("Intel Corporation", "Network Adapter"),
    "A8A159": ("Intel Corporation", "Network Adapter"),
    "ACD1B8": ("Intel Corporation", "Network Adapter"),
    "B01041": ("Intel Corporation", "Network Adapter"),
    "B025AA": ("Intel Corporation", "Network Adapter"),
    "B0359F": ("Intel Corporation", "Network Adapter"),
    "B0C090": ("Intel Corporation", "Network Adapter"),
    "B42E99": ("Intel Corporation", "Network Adapter"),
    "B48BC9": ("Intel Corporation", "Network Adapter"),
    "B8AEED": ("Intel Corporation", "Network Adapter"),
    "B8CA3A": ("Intel Corporation", "Network Adapter"),
    "C01885": ("Intel Corporation", "Network Adapter"),
    "C03C59": ("Intel Corporation", "Network Adapter"),
    "C48E8F": ("Intel Corporation", "Network Adapter"),
    "C82158": ("Intel Corporation", "Network Adapter"),
    "C858C0": ("Intel Corporation", "Network Adapter"),
    "C8D3FF": ("Intel Corporation", "Network Adapter"),
    "CC3D82": ("Intel Corporation", "Network Adapter"),
    "D0577B": ("Intel Corporation", "Network Adapter"),
    "D07E28": ("Intel Corporation", "Network Adapter"),
    "D0C5F3": ("Intel Corporation", "Network Adapter"),
    "D4258B": ("Intel Corporation", "Network Adapter"),
    "D43B04": ("Intel Corporation", "Network Adapter"),
    "D46D6D": ("Intel Corporation", "Network Adapter"),
    "D48564": ("Intel Corporation", "Network Adapter"),
    "D81265": ("Intel Corporation", "Network Adapter"),
    "D85DE2": ("Intel Corporation", "Network Adapter"),
    "D8C497": ("Intel Corporation", "Network Adapter"),
    "D8F2CA": ("Intel Corporation", "Network Adapter"),
    "DC4546": ("Intel Corporation", "Network Adapter"),
    "E02A82": ("Intel Corporation", "Network Adapter"),
    "E0D55E": ("Intel Corporation", "Network Adapter"),
    "E0D9E3": ("Intel Corporation", "Network Adapter"),
    "E4A8DF": ("Intel Corporation", "Network Adapter"),
    "E4B318": ("Intel Corporation", "Network Adapter"),
    "E4F89C": ("Intel Corporation", "Network Adapter"),
    "E82A44": ("Intel Corporation", "Network Adapter"),
    "E8B1FC": ("Intel Corporation", "Network Adapter"),
    "EC2E98": ("Intel Corporation", "Network Adapter"),
    "ECAAA0": ("Intel Corporation", "Network Adapter"),
    "F09FC2": ("Intel Corporation", "Network Adapter"),
    "F0D5BF": ("Intel Corporation", "Network Adapter"),
    "F46D3F": ("Intel Corporation", "Network Adapter"),
    "F48C50": ("Intel Corporation", "Network Adapter"),
    "F4A83B": ("Intel Corporation", "Network Adapter"),
    "F81654": ("Intel Corporation", "Network Adapter"),
    "F83441": ("Intel Corporation", "Network Adapter"),
    "FCAA14": ("Intel Corporation", "Network Adapter"),
    "FCDBB3": ("Intel Corporation", "Network Adapter"),

    # Dell Technologies
    "001422": ("Dell Technologies", "Computer"),
    "0026B9": ("Dell Technologies", "Computer"),

    # Cisco Systems
    "00000C": ("Cisco Systems", "Networking Equipment"),
    "0C8525": ("Cisco Systems", "Networking Equipment"),

    # TP-Link Technologies
    "1C1AC0": ("TP-Link Technologies", "Router / Switch"),
    "58EF68": ("TP-Link Technologies", "Router / Switch"),
    "74E1B6": ("TP-Link Technologies", "Router / Switch"),

    # VMware Inc.
    "005056": ("VMware", "Virtual Machine"),
    "000C29": ("VMware", "Virtual Machine"),
    "000569": ("VMware", "Virtual Machine"),

    # Lite-On Technology
    "3CF75D": ("Lite-On Technology", "Network Adapter"),

    # Siemens
    "0001E3": ("Siemens", "Industrial / Telecom"),

    # D-Link Systems
    "00055D": ("D-Link Systems", "Networking Equipment"),

    # Panasonic
    "00112F": ("Panasonic", "Electronics"),

    # Synology Inc.
    "001132": ("Synology Inc.", "Network Storage"),

    # Huawei Technologies
    "001565": ("Huawei Technologies", "Mobile / Laptop"),
    "E4E0A6": ("Huawei Technologies", "Mobile / Laptop"),

    # Skype
    "0016D3": ("Skype", "Software"),

    # Philips
    "001788": ("Philips", "Electronics"),

    # Google LLC
    "001A11": ("Google LLC", "Cloud Server"),
    "20DFB9": ("Google LLC", "Cloud Server"),

    # Asustek Computer
    "001D60": ("Asustek Computer", "Computer"),
    "001E8C": ("Asustek Computer", "Computer"),
    "3085A9": ("Asustek Computer", "Computer"),

    # Microsoft Corporation
    "002248": ("Microsoft Corporation", "Virtual Machine"),
    "00155D": ("Microsoft Corporation", "Virtual Machine"),

    # Super Micro Computer
    "002590": ("Super Micro Computer", "Computer"),

    # WatchGuard Technologies
    "00907F": ("WatchGuard Technologies", "Networking Equipment"),

    # Realtek Semiconductor
    "00E04C": ("Realtek Semiconductor", "Network Adapter"),

    # Ubiquiti Inc.
    "0418D6": ("Ubiquiti Inc.", "Networking Equipment"),
    "44D9E7": ("Ubiquiti Inc.", "Networking Equipment"),
    "802AA8": ("Ubiquiti Inc.", "Networking Equipment"),

    # Xiaomi Communications
    "24F5A2": ("Xiaomi Communications", "Mobile / Laptop"),

    # HP Inc.
    "3CD92B": ("HP Inc.", "Computer"),

    # Western Digital
    "5078B3": ("Western Digital", "Storage Device"),

    # Raspberry Pi Foundation
    "B827EB": ("Raspberry Pi Foundation", "Computer"),

    # Parallels International
    "001C42": ("Parallels International", "Virtual Machine"),

    # Oracle VirtualBox
    "080027": ("Oracle VirtualBox", "Virtual Machine"),

    # IANA Multicast
    "01005E": ("IANA Multicast", "Network Infrastructure"),
}
PROTOCOL_CATEGORIES = {
    # Network Discovery
    "ETHERNET": "Network Discovery", "ARP": "Network Discovery", "DHCP": "Network Discovery", 
    "DHCPV6": "Network Discovery", "ICMP": "Network Discovery", "ICMPV6": "Network Discovery", 
    "IPV4": "Network Discovery", "IPV6": "Network Discovery",
    
    # Name Resolution
    "DNS": "Name Resolution", "MDNS": "Name Resolution", "LLMNR": "Name Resolution", "NBNS": "Name Resolution",
    
    # Transport
    "TCP": "Transport", "UDP": "Transport", "QUIC": "Transport",
    
    # VoIP Signaling
    "SIP": "VoIP Signaling", "SDP": "VoIP Signaling", "H323": "VoIP Signaling", "H.323": "VoIP Signaling",
    "MGCP": "VoIP Signaling", "SCCP": "VoIP Signaling", "IAX": "VoIP Signaling", "IAX2": "VoIP Signaling",
    "H225": "VoIP Signaling", "H245": "VoIP Signaling", "MEGACO": "VoIP Signaling", "H.248": "VoIP Signaling",
    
    # NAT Traversal
    "STUN": "NAT Traversal", "TURN": "NAT Traversal", "ICE": "NAT Traversal",
    
    # Media
    "RTP": "Media", "SRTP": "Media", "RTCP": "Media", "SRTCP": "Media",
    
    # Security
    "TLS": "Security", "DTLS": "Security", "ZRTP": "Security", "MIKEY": "Security", "SDES": "Security",
    
    # Conferencing
    "MSRP": "Conferencing", "BFCP": "Conferencing", "T.38": "Conferencing", "T38": "Conferencing",
    
    # Carrier/Telecom
    "ISUP": "Carrier/Telecom", "M3UA": "Carrier/Telecom", "SIGTRAN": "Carrier/Telecom", 
    "TPKT": "Carrier/Telecom", "RAS": "Carrier/Telecom",
    
    # VPN/Tunneling
    "GRE": "VPN/Tunneling", "ESP": "VPN/Tunneling", "AH": "VPN/Tunneling",
    
    # Wireless
    "802.11": "Wireless", "RADIOTAP": "Wireless", "EAPOL": "Wireless"
}


_mac_vendor_cache = {}

def _resolve_mac(mac: str | None) -> tuple[str, str]:
    if not mac:
        return "Incomplete Capture", "Unknown"
    # Normalize formats (hyphens, colons, lower/uppercase) to standard uppercase 12 hex chars
    normalized = "".join(char for char in mac if char.isalnum()).upper()
    if len(normalized) != 12:
        return "Incomplete Capture", "Unknown"
    if normalized in _mac_vendor_cache:
        return _mac_vendor_cache[normalized]
    # Check for Ethernet Broadcast
    if normalized == "FFFFFFFFFFFF":
        res = ("Ethernet Broadcast", "Network Infrastructure")
        _mac_vendor_cache[normalized] = res
        return res
    # Check for IPv6 Multicast
    if normalized.startswith("3333"):
        res = ("IPv6 Multicast", "Network Infrastructure")
        _mac_vendor_cache[normalized] = res
        return res
    # Check Locally Administered Address (LAA) bit for randomized MAC Address
    if len(normalized) >= 2 and normalized[1] in {"2", "3", "6", "7", "A", "B", "E", "F"}:
        res = ("Randomized MAC Address", "Unknown Device")
        _mac_vendor_cache[normalized] = res
        return res
    # Match longest prefix first: 36-bit (9 chars), 28-bit (7 chars), 24-bit (6 chars)
    for prefix_len in (9, 7, 6):
        prefix = normalized[:prefix_len]
        if prefix in OUI_DATABASE:
            res = OUI_DATABASE[prefix]
            _mac_vendor_cache[normalized] = res
            return res
    res = ("Unknown Vendor", "Unknown Device")
    _mac_vendor_cache[normalized] = res
    return res

def resolve_mac_vendor(mac: str | None) -> str:
    return _resolve_mac(mac)[0]

def resolve_mac_category(mac: str | None) -> str:
    return _resolve_mac(mac)[1]


def enrichment_gate(endpoints: list[dict]) -> tuple[list[dict], list[dict]]:
    """Splits endpoints into (eligible, excluded) before any enrichment call is made."""
    eligible, excluded = [], []
    for ep in endpoints:
        if ep.get("tier") == 1 or ep.get("role") == "UNKNOWN":
            excluded.append(ep)
        else:
            eligible.append(ep)
    return eligible, excluded


def analyze_records(records: list[ConnectionRecord]) -> dict:
    from app.analysis.vpn_classifier import ClassificationEngine, EndpointRole, ROLE_TIERS
    from pathlib import Path
    
    raw_records = [r.to_dict() if hasattr(r, "to_dict") else dict(r) for r in records]
    classifier = ClassificationEngine(Path("registry/interfaces"))
    
    threat_manager = ThreatIntelManager()
    grouped: dict[str, list[dict]] = defaultdict(list)
    packet_rows: list[dict] = []
    stun_context = _build_stun_context(records)

    # Pre-cache telecom enrichment for all unique destination IPs to avoid duplicate API/GeoIP hits
    unique_dsts = {r.destination_ip for r in records if r.destination_ip}
    unique_sources = {r.source_ip for r in records if r.source_ip}
    all_ips = unique_dsts | unique_sources
    
    # Classify all unique IPs
    classified_endpoints = {}
    for ip in all_ips:
        role, confidence, matched_sig, paired_addr, evidence = classifier.classify(ip, raw_records)
        tier = ROLE_TIERS[role]
        classified_endpoints[ip] = {
            "ip": ip,
            "role": role.value,
            "confidence": float(confidence),
            "tier": tier,
            "matched_signature": matched_sig,
            "paired_address": paired_addr,
            "evidence": evidence
        }
        
    eligible, excluded = enrichment_gate(list(classified_endpoints.values()))
    eligible_ips = {ep["ip"] for ep in eligible}
    
    telecom_cache = {}
    for ip in unique_dsts:
        if ip in eligible_ips:
            try:
                telecom_cache[ip] = enrich_telecom(ip)
            except Exception:
                telecom_cache[ip] = {}
        else:
            telecom_cache[ip] = {
                "isp": "Capture Internal",
                "asn": "AS0",
                "asn_number": 0,
                "asn_org": "Capture Internal / VPN",
                "network_prefix": "Unknown",
                "country": "Local",
                "region": "Capture Internal",
                "city": "Local",
                "latitude": None,
                "longitude": None,
                "hostname": "",
                "ip_source": "Local GeoIP"
            }

    from app.dpi.engine import dpi_engine

    # Run DPI Engine on all packet details using enriched context
    for record in records:
        row = record.to_dict()
        telecom = telecom_cache.get(row.get("destination_ip"), {})
        for packet in row.get("packet_details", []) or []:
            raw_payload = None
            hex_str = packet.get("payload_hex")
            if hex_str:
                try:
                    raw_payload = bytes.fromhex(hex_str.replace(" ", ""))
                except Exception:
                    pass
            inspect_data = {
                **packet,
                "asn_org": telecom.get("asn_org"),
                "isp": telecom.get("isp"),
                "hostname": telecom.get("hostname"),
            }
            packet["dpi_alerts"] = dpi_engine.inspect_packet(inspect_data, raw_payload)

    for record in records:
        row = record.to_dict()
        try:
            addr = ip_address(row["destination_ip"])
        except ValueError:
            continue
        # Keep private unicast peers because they are real packet destinations
        # in LAN and peer-to-peer captures. Exclude only non-host destinations.
        if _exclude_destination(addr):
            packet_rows.extend(_flatten_packet_rows(row))
            continue
        # Exclude verbose/application protocols from high-level destination dashboard grouped list.
        # Still flatten their packet details into packet_rows for the Packet Analyzer.
        if str(row.get("protocol") or "").upper() in IGNORE_PROTOCOLS:
            packet_rows.extend(_flatten_packet_rows(row))
            continue
        grouped[row["destination_ip"]].append(row)
        packet_rows.extend(_flatten_packet_rows(row))

    packet_rows.sort(key=lambda item: (item.get("timestamp") or "", item.get("flow_label") or "", item.get("packet_index") or 0))

    enriched = []
    for destination_ip, rows in grouped.items():
        telecom = telecom_cache.get(destination_ip) or {
            "isp": "Capture Internal",
            "asn": "AS0",
            "asn_number": 0,
            "asn_org": "Capture Internal / VPN",
            "network_prefix": "Unknown",
            "country": "Local",
            "region": "Capture Internal",
            "city": "Local",
            "latitude": None,
            "longitude": None,
            "hostname": "",
            "ip_source": "Local GeoIP"
        }
        top_port = _most_common([row.get("destination_port") for row in rows if row.get("destination_port")])
        top_src_port = _most_common([row.get("source_port") for row in rows if row.get("source_port")])
        protocol = _most_common([row.get("protocol") for row in rows if row.get("protocol")]) or "UNKNOWN"
        service = identify_service(destination_ip, telecom.get("asn_number"), top_port, telecom.get("asn_org"))
        port_info = port_intelligence(top_port, protocol)
        
        if destination_ip in eligible_ips:
            threat = threat_manager.lookup(destination_ip)
        else:
            threat = {
                "malicious": False,
                "reputation_score": 0,
                "abuse_reports": 0,
                "threat_category": None
            }
            
        timestamps = [_parse_timestamp(row.get("timestamp")) for row in rows if row.get("timestamp")]
        timestamps = [stamp for stamp in timestamps if stamp]
        first_seen = min(timestamps).isoformat() if timestamps else ""
        last_seen = max(timestamps).isoformat() if timestamps else ""

        # Aggregate MAC addresses from raw connection rows
        source_macs = sorted({row.get("source_mac") for row in rows if row.get("source_mac")})
        destination_macs = sorted({row.get("destination_mac") for row in rows if row.get("destination_mac")})
        # Aggregate TCP flags across all connection rows
        all_tcp_flags = set()
        for row in rows:
            flags_str = row.get("tcp_flags") or ""
            for flag in flags_str.replace(",", " ").split():
                flag = flag.strip()
                if flag:
                    all_tcp_flags.add(flag)
        # Aggregate DNS queries across all connection rows
        all_dns = set()
        for row in rows:
            dns_str = row.get("dns_query") or ""
            for domain in dns_str.replace(",", " ").split():
                domain = domain.strip()
                if domain:
                    all_dns.add(domain)

        # Determine if source and destination IPs are private/local
        is_src_private = False
        try:
            is_src_private = ip_address(rows[0]["source_ip"]).is_private
        except ValueError:
            pass

        is_dst_private = False
        try:
            is_dst_private = ip_address(destination_ip).is_private
        except ValueError:
            pass

        # For routed public IP traffic, the MAC address belongs to the gateway, not the host.
        if is_src_private:
            source_vendor = resolve_mac_vendor(source_macs[0]) if source_macs else "Incomplete Capture"
            source_vendor_category = resolve_mac_category(source_macs[0]) if source_macs else "Unknown"
        else:
            source_vendor = "Unknown (Routed IP)"
            source_vendor_category = "External Endpoint"

        if is_dst_private:
            destination_vendor = resolve_mac_vendor(destination_macs[0]) if destination_macs else "Incomplete Capture"
            destination_vendor_category = resolve_mac_category(destination_macs[0]) if destination_macs else "Unknown"
        else:
            destination_vendor = "Unknown (Routed IP)"
            destination_vendor_category = "External Endpoint"

        # Collect and deduplicate DPI alerts across all rows and packets in this group
        flow_dpi_alerts = []
        seen_alerts = set()
        for row in rows:
            for packet in row.get("packet_details", []) or []:
                for alert in packet.get("dpi_alerts", []) or []:
                    alert_key = (alert["rule_name"], alert["category"], alert["matched_text"])
                    if alert_key not in seen_alerts:
                        seen_alerts.add(alert_key)
                        flow_dpi_alerts.append(alert)

        enriched.append(
            {
                "dpi_alerts": flow_dpi_alerts,
                "destination_ip": destination_ip,
                "source_ips": sorted({row["source_ip"] for row in rows}),
                "source_ip": rows[0]["source_ip"],
                "source_port": top_src_port,
                "destination_port": top_port,
                "protocol": protocol,
                "packet_count": sum(int(row.get("packet_count") or 0) for row in rows),
                "bytes_transferred": sum(int(row.get("bytes_transferred") or 0) for row in rows),
                "connection_count": len(rows),
                "raw_connections": rows,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "duration_seconds": _duration_seconds(first_seen, last_seen),
                "source_mac": source_macs[0] if source_macs else None,
                "destination_mac": destination_macs[0] if destination_macs else None,
                "source_macs": source_macs,
                "destination_macs": destination_macs,
                "source_vendor": source_vendor,
                "source_vendor_category": source_vendor_category,
                "destination_vendor": destination_vendor,
                "destination_vendor_category": destination_vendor_category,
                "tcp_flags": ", ".join(sorted(all_tcp_flags)) if all_tcp_flags else None,
                "dns_query": ", ".join(sorted(all_dns)) if all_dns else None,
                **telecom,
                **service,
                "port_name": port_info["name"],
                "unusual_port": port_info["is_unusual"],
                "port_notes": port_info["notes"],
                **threat,
                "role": classified_endpoints.get(destination_ip, {}).get("role", "UNKNOWN"),
                "role_confidence": int(classified_endpoints.get(destination_ip, {}).get("confidence", 0.0) * 100),
                "role_reasons": classified_endpoints.get(destination_ip, {}).get("evidence", []),
                "tier": classified_endpoints.get(destination_ip, {}).get("tier", 4),
                "matched_signature": classified_endpoints.get(destination_ip, {}).get("matched_signature"),
                "paired_address": classified_endpoints.get(destination_ip, {}).get("paired_address"),
            }
        )

    network = build_network_intelligence(records, enriched)
    _apply_stun_context(enriched, network, stun_context)
    enriched.sort(key=lambda row: (row.get("relevance_rank", 100), -int(row.get("packet_count") or 0), row["destination_ip"]))

    summary = summarize(enriched)
    summary["total_packets"] = len(packet_rows)
    summary["unique_ips"] = len(enriched)
    summary["protocols"] = len({row["protocol"] for row in enriched})
    summary["suspicious_ips"] = len([row for row in enriched if row["malicious"] or row["reputation_score"] >= 50])
    summary["endpoints"] = len(enriched)
    
    # Calculate protocol mix based on packet counts
    proto_counts = Counter()
    for row in enriched:
        proto_counts[row["protocol"]] += row.get("packet_count", 1)
    total_proto_packets = sum(proto_counts.values()) or 1
    protocol_mix = []
    for label, count in proto_counts.most_common(5):
        pct = round((count / total_proto_packets) * 100)
        protocol_mix.append({"label": label, "pct": pct})
    if len(proto_counts) > 5:
        others_count = sum(count for label, count in proto_counts.most_common()[5:])
        pct = round((others_count / total_proto_packets) * 100)
        protocol_mix.append({"label": "Others", "pct": pct})
    summary["protocol_mix"] = protocol_mix

    # Calculate category mix based on protocol mapping
    category_counts = Counter()
    for row in enriched:
        proto = str(row.get("protocol") or "UNKNOWN").upper()
        cat = PROTOCOL_CATEGORIES.get(proto, "Other Protocols")
        category_counts[cat] += row.get("packet_count", 1)
    total_cat_packets = sum(category_counts.values()) or 1
    category_mix = []
    for cat, count in category_counts.most_common():
        pct = round((count / total_cat_packets) * 100)
        if pct > 0:
            category_mix.append({"label": cat, "pct": pct, "count": count})
    summary["category_mix"] = category_mix


    # Calculate IP ranges (Private vs Public)
    private_count = sum(1 for row in enriched if row["destination_ip"].startswith("192.168.") or row["destination_ip"].startswith("10.") or row["destination_ip"].startswith("172."))
    public_count = len(enriched) - private_count
    summary["ip_ranges"] = {
        "private": private_count,
        "public": public_count
    }

    summary["primary_destination_ip"] = stun_context.get("primary_destination_ip", "")
    summary["session_destination_count"] = sum(1 for row in enriched if row.get("session_relevant", True))
    summary.update(
        {
            "total_hosts": network.get("host_overview", {}).get("total_hosts", 0),
            "private_hosts": network.get("host_overview", {}).get("private_hosts", 0),
            "public_hosts": network.get("host_overview", {}).get("public_hosts", 0),
            "total_sessions": network.get("session_summary", {}).get("total_sessions", 0),
            "bidirectional_sessions": network.get("session_summary", {}).get("bidirectional_sessions", 0),
            "top_protocol": network.get("session_summary", {}).get("top_protocol", "UNKNOWN"),
        }
    )
    return {
        "rows": enriched,
        "packet_rows": packet_rows,
        "summary": summary,
        "raw_connection_count": len(records),
        "raw_packet_count": len(packet_rows),
        "session_focus": stun_context,
        **network,
    }


def summarize(rows: list[dict]) -> dict:
    asns = {row["asn"] for row in rows}
    countries = {row["country"] for row in rows if row["country"] != "Unknown"}
    providers = Counter(row["isp"] for row in rows)
    ports = Counter(str(row["destination_port"]) for row in rows if row["destination_port"])
    services = Counter(row["category"] for row in rows)
    threats = [row for row in rows if row["malicious"] or row["reputation_score"] >= 50]
    return {
        "total_destination_ips": len(rows),
        "unique_asns": len(asns),
        "countries_contacted": len(countries),
        "top_telecom_providers": providers.most_common(5),
        "top_ports": ports.most_common(8),
        "top_services": services.most_common(8),
        "threat_indicators": len(threats),
        "total_bytes": sum(row["bytes_transferred"] for row in rows),
        "total_connections": sum(row["connection_count"] for row in rows),
    }


def _most_common(values: list):
    if not values:
        return None
    return Counter(values).most_common(1)[0][0]


def _exclude_destination(addr) -> bool:
    if addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified:
        return True
    if isinstance(addr, IPv4Address):
        if str(addr) == "255.255.255.255":
            return True
        # Capture metadata does not include the interface netmask, so a final
        # .255 is the strongest available signal for private broadcast noise.
        if addr.is_private and int(str(addr).rsplit(".", 1)[1]) == 255:
            return True
    return False


def _build_stun_context(records: list[ConnectionRecord]) -> dict:
    rows = [record.to_dict() if hasattr(record, "to_dict") else dict(record) for record in records]
    stun_rows = [row for row in rows if _is_stun_row(row)]
    if not stun_rows:
        return {}

    request_sources = Counter()
    for row in stun_rows:
        request_count = sum(
            1
            for packet in row.get("packet_details") or []
            if "STUN" in str(packet.get("decoded_type") or "").upper()
            and "REQUEST" in str(packet.get("decoded_type") or "").upper()
        )
        if request_count:
            request_sources[row.get("source_ip")] += request_count
    if not request_sources:
        return {}

    local_endpoint = request_sources.most_common(1)[0][0]
    infrastructure_ips: set[str] = set()
    direct_candidates: Counter = Counter()
    public_candidates: Counter = Counter()

    for row in stun_rows:
        src = row.get("source_ip")
        dst = row.get("destination_ip")
        sport = row.get("source_port")
        dport = row.get("destination_port")
        if sport in STUN_TURN_PORTS:
            infrastructure_ips.add(src)
        if dport in STUN_TURN_PORTS:
            infrastructure_ips.add(dst)
        if src != local_endpoint or not dst or dport in STUN_TURN_PORTS:
            continue
        try:
            destination = ip_address(dst)
        except ValueError:
            continue
        if destination.is_private and not _exclude_destination(destination):
            direct_candidates[dst] += int(row.get("packet_count") or 0)
        elif destination.is_global:
            public_candidates[dst] += int(row.get("packet_count") or 0)

    primary_destination = direct_candidates.most_common(1)[0][0] if direct_candidates else ""
    relevant_ips = {
        local_endpoint,
        *infrastructure_ips,
        *direct_candidates.keys(),
        *public_candidates.keys(),
    }
    return {
        "protocol": "STUN/TURN",
        "local_endpoint_ip": local_endpoint,
        "primary_destination_ip": primary_destination,
        "direct_peer_ips": list(direct_candidates),
        "public_candidate_ips": list(public_candidates),
        "infrastructure_ips": sorted(infrastructure_ips),
        "relevant_ips": sorted(ip for ip in relevant_ips if ip),
    }


def _is_stun_row(row: dict) -> bool:
    return any(
        str(packet.get("decoded_type") or "").upper().startswith("STUN ")
        for packet in row.get("packet_details") or []
    )


def _apply_stun_context(rows: list[dict], network: dict, context: dict) -> None:
    if not context:
        for row in rows:
            row.setdefault("session_relevant", True)
            row.setdefault("destination_kind", "captured destination")
            row.setdefault("relevance_rank", 50)
        return

    primary = context.get("primary_destination_ip")
    local_endpoint = context.get("local_endpoint_ip")
    direct_peers = set(context.get("direct_peer_ips") or [])
    public_candidates = set(context.get("public_candidate_ips") or [])
    infrastructure = set(context.get("infrastructure_ips") or [])
    relevant = set(context.get("relevant_ips") or [])

    for row in rows:
        ip = row.get("destination_ip")
        row["session_relevant"] = ip in relevant
        row["is_primary_destination"] = ip == primary
        if ip == primary:
            row.update(
                {
                    "destination_kind": "Primary Direct Peer",
                    "role": "primary direct peer",
                    "role_confidence": 99,
                    "role_reasons": ["Repeated STUN Binding Requests directly target this private peer address"],
                    "relevance_rank": 0,
                }
            )
        elif ip in direct_peers:
            row.update(
                {
                    "destination_kind": "Direct Peer",
                    "role": "direct peer",
                    "role_confidence": 95,
                    "role_reasons": ["STUN Binding Requests directly target this private peer address"],
                    "relevance_rank": 1,
                }
            )
        elif ip in public_candidates:
            row.update(
                {
                    "destination_kind": "Public Peer Candidate",
                    "role": "public peer candidate",
                    "role_confidence": 92,
                    "role_reasons": ["STUN Binding Requests target this public candidate on an ephemeral port"],
                    "relevance_rank": 2,
                }
            )
        elif ip == local_endpoint:
            row.update(
                {
                    "destination_kind": "Local Endpoint",
                    "role": "local endpoint",
                    "role_confidence": 99,
                    "role_reasons": ["This host originates the capture's STUN and TURN requests"],
                    "relevance_rank": 3,
                }
            )
        elif ip in infrastructure:
            row.update(
                {
                    "destination_kind": "STUN/TURN Infrastructure",
                    "role": "STUN/TURN infrastructure",
                    "role_confidence": 99,
                    "role_reasons": ["Traffic uses a standard STUN/TURN service port"],
                    "relevance_rank": 4,
                }
            )
        else:
            row["destination_kind"] = "Background Capture Traffic"
            row["relevance_rank"] = 90

    for host in network.get("hosts", []):
        ip = host.get("ip")
        host["session_relevant"] = ip in relevant
        host["is_primary_destination"] = ip == primary
        if ip == primary:
            host.update({"role": "primary direct peer", "role_confidence": 99, "relevance_rank": 0})
        elif ip == local_endpoint:
            host.update({"role": "local endpoint", "role_confidence": 99, "relevance_rank": 1})
        elif ip in direct_peers:
            host.update({"role": "direct peer", "role_confidence": 95, "relevance_rank": 2})
        elif ip in public_candidates:
            host.update({"role": "public peer candidate", "role_confidence": 92, "relevance_rank": 3})
        elif ip in infrastructure:
            host.update({"role": "STUN/TURN infrastructure", "role_confidence": 99, "relevance_rank": 4})
        else:
            host["relevance_rank"] = 90
    network["hosts"].sort(key=lambda host: (host.get("relevance_rank", 90), -int(host.get("total_packets") or 0), host.get("ip", "")))

    for session in network.get("sessions", []):
        participants = set(session.get("participants") or [])
        session["session_relevant"] = bool(participants) and participants.issubset(relevant)

    flow = network.get("flow_diagram") or {}
    hosts_by_ip = {host.get("ip"): host for host in network.get("hosts", [])}
    flow["nodes"] = [
        {
            "id": ip,
            "label": ip,
            "role": hosts_by_ip.get(ip, {}).get("role", ""),
            "confidence": hosts_by_ip.get(ip, {}).get("role_confidence", 0),
            "asn": hosts_by_ip.get(ip, {}).get("asn", ""),
            "country": hosts_by_ip.get(ip, {}).get("country", ""),
        }
        for ip in sorted(relevant, key=lambda item: hosts_by_ip.get(item, {}).get("relevance_rank", 90))
        if ip in hosts_by_ip
    ]
    flow["edges"] = [
        edge
        for edge in network.get("communication_matrix", [])
        if edge.get("source_ip") in relevant and edge.get("destination_ip") in relevant
    ]


def _parse_timestamp(value: str) -> datetime | None:
    try:
        timestamp = float(value)
        if timestamp <= 0:
            return None
        return datetime.fromtimestamp(timestamp, timezone.utc)
    except (TypeError, ValueError):
        pass

    try:
        parsed = date_parser.parse(str(value))
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except Exception:
        return None


def _duration_seconds(first_seen: str, last_seen: str) -> int:
    if not first_seen or not last_seen:
        return 0
    try:
        return int((date_parser.parse(last_seen) - date_parser.parse(first_seen)).total_seconds())
    except Exception:
        return 0


def _flatten_packet_rows(row: dict) -> list[dict]:
    packets = []
    flow_label = f"{row.get('source_ip', 'Unknown')}:{row.get('source_port') or 'n/a'} -> {row.get('destination_ip', 'Unknown')}:{row.get('destination_port') or 'n/a'}"
    for index, packet in enumerate(row.get("packet_details", []) or [], start=1):
        packets.append(
            {
                **packet,
                "packet_index": index,
                "flow_label": flow_label,
                "flow_source_ip": row.get("source_ip", ""),
                "flow_destination_ip": row.get("destination_ip", ""),
                "flow_source_port": row.get("source_port"),
                "flow_destination_port": row.get("destination_port"),
                "flow_protocol": row.get("protocol", "UNKNOWN"),
                "flow_packet_count": row.get("packet_count", 0),
                "flow_bytes_transferred": row.get("bytes_transferred", 0),
                "flow_destination": row.get("destination_ip", ""),
                "source_mac": row.get("source_mac"),
                "destination_mac": row.get("destination_mac"),
                "tcp_flags": row.get("tcp_flags"),
            }
        )
    return packets
