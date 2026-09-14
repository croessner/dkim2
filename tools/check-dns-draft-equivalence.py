#!/usr/bin/env python3
"""Compare archived DNS draft bodies without interpreting protocol semantics."""
import hashlib
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

archive = Path(sys.argv[1])
names = ("draft-chuang-dkim2-dns-04", "draft-ietf-dkim-dkim2-dns-00")
bodies = []
receipts = {}
for name in names:
    source = (archive / (name + ".xml")).read_bytes()
    middle = ET.fromstring(source).find("middle")
    if middle is None:
        raise SystemExit("missing normative middle")
    body = ET.tostring(middle)
    bodies.append(body)
    receipts[name] = {"source_sha256": hashlib.sha256(source).hexdigest(),
                      "middle_sha256": hashlib.sha256(body).hexdigest()}
if bodies[0] != bodies[1]:
    raise SystemExit("DNS normative bodies differ; migration requires review")
print(json.dumps({"equal": True, "documents": receipts}, indent=2))
