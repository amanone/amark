
if [ $# -ne 0 ]
then
   cp -v /vmlinuz .
   file vmlinuz
   ./extract-vmlinux vmlinuz > vmlinux
   file vmlinux
   objdump -D vmlinux -M intel > disass_intel_vmlinux
   echo 'disassembled in disass_intel_vmlinux'
   #dwarfdump -di vmlinux  2> dwarf_vmlinux
   # Our kernel is not compiled with RELOCATED
   # and RANDOMIZE* (i.e. KALSR)
   # So I think it might work...
   
   #cd lime && make
   #insmod lime-*.ko "path=/vagrant/git/detector/memory_dump format=lime"
fi

SYSTEM_MAP=/boot/System.map-3.2*
ASSEMBLY_VMLINUX_INTEL_SYNTAX=disass_intel_vmlinux
SYS_OPEN_ADDR_IN_VMLINUX=`grep  -e ' sys_open$' $SYSTEM_MAP  | cut -d' ' -f1`

grep -A 20 -m 1 $SYS_OPEN_ADDR_IN_VMLINUX $ASSEMBLY_VMLINUX_INTEL_SYNTAX > SYS_OPEN_VMLINUX.data  # FIXME PLEASE
cat SYS_OPEN_VMLINUX.data


