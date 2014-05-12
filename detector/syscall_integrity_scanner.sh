./dump_virtual_sys_open.sh
./dump_vmlinux_sys_open.sh
python check_syscall_integrity.py SYS_OPEN_VMLINUX.data SYS_OPEN_VIRTUAL.data 


