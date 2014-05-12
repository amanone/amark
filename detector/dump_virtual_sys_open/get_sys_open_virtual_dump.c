#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/slab.h>

typedef asmlinkage long (*orig_open_t)(const char __user *filename, int flags, int mode);
typedef void (*sys_call_ptr_t)(void);
orig_open_t orig_open = NULL;
sys_call_ptr_t *_sys_call_table = NULL;

static void get_sys_call_table() {
	gate_desc *idt_table;
	gate_desc *system_call_gate;
	struct desc_ptr idtr;
	unsigned char *_system_call_ptr;
	unsigned char *off;
	unsigned int _system_call_off;
	unsigned int i;

	asm ("sidt %0" : "=m" (idtr));
	printk("+ IDT is at %08lx\n", idtr.address);

	idt_table = (gate_desc *) idtr.address;
	system_call_gate = &idt_table[0x80];

	_system_call_off = (system_call_gate->a & 0xffff) | (system_call_gate->b & 0xffff0000);
	_system_call_ptr = (unsigned char *) _system_call_off;

	printk("+ system_call is at %08x\n", _system_call_off);

	for (i = 0; i < 128; i++) {
		off = _system_call_ptr + i;
		if (*(off) == 0xff && *(off+1) == 0x14 && *(off+2) == 0x85) {
			_sys_call_table = *(sys_call_ptr_t **)(off+3);
			printk("+ found sys_call_table at %08lx!\n",(unsigned long) _sys_call_table);
			return ;
		}
	}
}

static int __init dump_sys_open(void) {
	get_sys_call_table();

	if (_sys_call_table == NULL) {
		printk("+ unable to locate sys_call_table\n");
		return 0;
	}
	orig_open = (void *) _sys_call_table[__NR_open];
	printk("+ virtual memory for sys_open {%p}\n", orig_open);
	printk("[0xCAFEBABE] START DUMP\n");
	print_hex_dump_bytes("", DUMP_PREFIX_NONE, orig_open, 500);
	printk("[0xCAFEBABE] END DUMP\n");
	return 0;
}

static void __exit stop_dump_sys_open(void) {
	printk ("+ dump_sys_open unloaded\n");

}

module_init(dump_sys_open);
module_exit(stop_dump_sys_open);
