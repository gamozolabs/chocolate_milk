import os, re

dmp = "redacted.dmp"
server = "pleb@192.168.100.129"
filename = "coverage.txt"
output_lcov = "/mnt/storage/winresearch/18362.752.200316-1744.19h1_release_svc_prod3/main.info"

orig_commands = set(open(filename).read().splitlines())
commands = set()
for line in orig_commands:
    # Convert "ntoskrnl.exe" references to just "nt"
    if line.lower().startswith("ntoskrnl.exe"):
        line = "nt" + line[12:]

    commands.add(f"u {line} L1")

commands = "\n".join(commands)

open(os.path.join("/tmp", filename), "w").write(f".lines\n.logopen windbglog.txt\n{commands}\n.logclose\nq\n")

os.system(f"scp /tmp/{filename} {server}:")
os.system(f"ssh {server} kd -z {dmp} -cf {filename}")
os.system(f"scp {server}:windbglog.txt /tmp")

# Mapping of files to lines which have been covered
files = {}

# Parse the KD output to get the source file and line
file_line = re.compile(" \[(.*?) @ ([0-9]+)\]")
for line in open("/tmp/windbglog.txt", "r").read().splitlines():
    mc = file_line.findall(line)
    if len(mc) > 0:
        source, line = mc[0]

        if source not in files:
            files[source] = set()
        files[source].add(int(line))

# Create the LCOV file
lcov = ""

for fn, lines in files.items():
    lcov += f"TN:\nSF:{fn}\n"

    for line in sorted(list(lines)):
        lcov += f"DA:{line},1\n"

    lcov += "end_of_record\n"

open(output_lcov, "w").write(lcov)

