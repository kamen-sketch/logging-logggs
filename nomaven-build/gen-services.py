#!/usr/bin/env python3
"""Generate META-INF/services/* from @ServiceProvider annotations.

The real Maven build derives these registrations from bnd's @ServiceProvider
annotation. Our stub annotation is a no-op, so without this step log4j-api's
ProviderUtil finds no Provider and LogManager silently degrades to SimpleLogger.

For each `@ServiceProvider(value = X.class)`, resolve X to a fully-qualified
name via the declaring file's imports, then write the declaring class into
META-INF/services/<service-fqn>.
"""
import os
import re
import sys
from collections import defaultdict

SRC_ROOTS = sys.argv[1:-1]
OUT = sys.argv[-1]

ANN = re.compile(r"@ServiceProvider\s*\(\s*value\s*=\s*([A-Za-z0-9_.]+)\.class")
PKG = re.compile(r"^\s*package\s+([a-zA-Z0-9_.]+)\s*;", re.M)
IMP = re.compile(r"^\s*import\s+(?:static\s+)?([a-zA-Z0-9_.]+)\s*;", re.M)

# Skip annotation processors: we invoke PluginProcessor explicitly, and
# registering it would make javac auto-run it on every later compile.
SKIP = {"javax.annotation.processing.Processor"}

services = defaultdict(set)

for root in SRC_ROOTS:
    for dirpath, _, files in os.walk(root):
        for fn in files:
            if not fn.endswith(".java"):
                continue
            path = os.path.join(dirpath, fn)
            with open(path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
            hits = ANN.findall(text)
            if not hits:
                continue
            pkg_m = PKG.search(text)
            if not pkg_m:
                continue
            pkg = pkg_m.group(1)
            impl = f"{pkg}.{fn[:-5]}"
            imports = IMP.findall(text)
            for simple in hits:
                head = simple.split(".")[0]
                fqn = next((i for i in imports if i.split(".")[-1] == head), None)
                if fqn is None:
                    fqn = f"{pkg}.{simple}"          # same package
                elif "." in simple:                   # e.g. Outer.Inner
                    fqn = f"{fqn}.{simple.split('.', 1)[1]}"
                if fqn in SKIP:
                    continue
                services[fqn].add(impl)

os.makedirs(os.path.join(OUT, "META-INF", "services"), exist_ok=True)
written = 0
for service, impls in sorted(services.items()):
    # A nested service type (Outer.Inner) is Outer$Inner on disk.
    name = service
    if not os.path.exists(os.path.join(OUT, *service.split("."))) and "." in service:
        head, _, tail = service.rpartition(".")
        if os.path.exists(os.path.join(OUT, *head.split(".")) + ".class"):
            name = f"{head}${tail}"
    dest = os.path.join(OUT, "META-INF", "services", name)
    with open(dest, "w", encoding="utf-8") as fh:
        fh.write("".join(f"{i}\n" for i in sorted(impls)))
    print(f"   {name} -> {', '.join(sorted(impls))}")
    written += 1
print(f"   ({written} service files)")
