#!/usr/bin/env -S rye run python

from pathlib import Path
import asn1tools

schema = asn1tools.compile_files("schema.asn", codec="jer")

for path in Path("output/programs").iterdir():
    print(path)
    schema.encode("Testcase", schema.decode("Testcase", open(path, "rb").read()))
