import sys
import binascii, struct

from elftools.elf.elffile import ELFFile
from elftools.elf.segments import NoteSegment

def process_file(filename, output_filename):
    with open(output_filename, 'wb') as out:
        elf = ELFFile(open(filename, 'rb'))

        # Write the file header
        out.write(b"FALKDUMP")

        # Find the register state and make sure only one register state exists
        regs = []
        for seg in elf.iter_segments():
            if isinstance(seg, NoteSegment):
                for note in seg.iter_notes():
                    if note.n_name == "QEMU":
                        regs.append(note.n_desc.encode("raw_unicode_escape"))

        # Set of physical memory regions
        regions = []

        # Find all physical loaded sections
        for seg in elf.iter_segments():
            if seg.header.p_type == "PT_LOAD":
                assert (seg.header.p_paddr & 0xfff) == 0
                assert seg.header.p_filesz == seg.header.p_memsz
                assert seg.header.p_filesz > 0
                assert (seg.header.p_filesz & 0xfff) == 0
                regions.append((seg.header.p_paddr, seg.header.p_paddr + (seg.header.p_filesz - 1)))

        # Write out the regions
        out.write(struct.pack("<Q", len(regions)))
        offset = 32 * 1024
        for (start, end) in regions:
            out.write(struct.pack("<QQQ", start, end, offset))
            offset += end + 1 - start
        
        # Write the number of CPUs
        out.write(struct.pack("<Q", len(regs)))

        # Write all register states for all CPUs
        for regs in regs:
            out.write(struct.pack("<Q", len(regs)))
            out.write(regs)

        # Pad to 32 KiB
        assert out.tell() <= (32 * 1024)
        while out.tell() < 32 * 1024:
            out.write(b"\x00")
        
        # Write out the actual data
        for seg in elf.iter_segments():
            if seg.header.p_type == "PT_LOAD":
                # Write out the data for this region
                out.write(seg.data())

        # Make sure the file was exactly what we expected
        assert offset == out.tell()

if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} <input dump-guest-memory> <output falkdump>")
    quit()

process_file(sys.argv[1], sys.argv[2])

