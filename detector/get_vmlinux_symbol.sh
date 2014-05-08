cp -v /vmlinuz .
file vmlinuz
./extract-vmlinux vmlinuz > vmlinux
file vmlinux
objdump -D vmlinux -M intel > disass_intel_vmlinux
echo 'disassembled in disass_intel_vmlinux'
dwarfdump -di vmlinux  2> dwarf_vmlinux
