## DO NOT EXECUTE THIS FILE

cp -v /vmlinuz .
file vmlinuz
./extract-vmlinux vmlinuz > vmlinux
file vmlinux
objdump -D vmlinux -M intel > disass_intel_vmlinux
echo 'disassembled in disass_intel_vmlinux'
dwarfdump -di vmlinux  2> dwarf_vmlinux
# Our kernel is not compiled with RELOCATED
# and RANDOMIZE* (i.e. KALSR)
# So I think it might work...

grep  -e ' sys_open$' /boot/System.map-3.2*
cd lime && make
insmod lime-*.ko "path=/vagrant/git/detector/memory_dump format=lime"
