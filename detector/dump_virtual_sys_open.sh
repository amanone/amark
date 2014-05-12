(cd dump_virtual_sys_open && make && rmmod -s *.ko &&  insmod *.ko)
dmesg | tail -n 35 > SYS_OPEN_VIRTUAL.data
cat SYS_OPEN_VIRTUAL.data # FIXME
