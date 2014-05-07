/* ts=4 sw=4 */

#include <linux/module.h>
#include <linux/syscalls.h>

MODULE_LICENSE("GPL");

typedef void (*sys_call_ptr_t)(void);
typedef asmlinkage long (*orig_open_t)(const char __user *filename, int flags, int mode);

pte_t *pte;
unsigned int level;
orig_open_t orig_open = NULL;
static struct timer_list my_timer;
sys_call_ptr_t *_sys_call_table = NULL;

asmlinkage long hooked_open(const char __user *filename, int flags, int mode) {
    long ret;
    ret = orig_open(filename, flags, mode);
    printk(KERN_DEBUG "file %s has been opened with mode %d {ret=%lu]\n", filename, mode, ret);
    return ret;
}

static void timer_callback(unsigned long data)
{
	printk( "timer_callback: put orig_sys_open in syscall table.\n");
	_sys_call_table[__NR_open] = orig_open;
}

static void get_sys_call_table(void) {
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

    // scan for known pattern in system_call (int 0x80) handler
    // pattern is just before sys_call_table address
    for (i = 0; i < 128; i++) {
        off = _system_call_ptr + i;
        if (*(off) == 0xff && *(off+1) == 0x14 && *(off+2) == 0x85) {
            _sys_call_table = *(sys_call_ptr_t **)(off+3);
            printk("+ found sys_call_table at %08lx!\n",(unsigned long) _sys_call_table);
            return ;
        }
    }
}

static int __init amark_init(void) {
    int timeout_ms = 10000;

    printk("+ amark loaded\n");

    get_sys_call_table();

    if (_sys_call_table == NULL) {
        printk("+ unable to locate sys_call_table\n");
        return 0;
    }

    orig_open = (orig_open_t) _sys_call_table[__NR_open];

    // unprotect sys_call_table memory page
    pte = lookup_address((unsigned long) _sys_call_table, &level);

    // change PTE to allow writing
    set_pte_atomic(pte, pte_mkwrite(*pte));

    printk("+ unprotected kernel memory page containing sys_call_table\n");

    _sys_call_table[__NR_open] = (sys_call_ptr_t) hooked_open;

    printk("+ open hooked!\n");

    setup_timer(&my_timer, timer_callback, 0);
    printk("+ starting timer the hijacked syscall by the real one in %dms (%ld)\n", timeout_ms, jiffies);
    mod_timer(&my_timer, jiffies + msecs_to_jiffies(timeout_ms));

    return 0;
}

static void __exit amark_cleanup(void) {
    if (orig_open != NULL) {
        _sys_call_table[__NR_open] = (sys_call_ptr_t) orig_open;
        set_pte_atomic(pte, pte_clear_flags(*pte, _PAGE_RW));
    }

    printk("+ Unloading module\n");
}

module_init(amark_init);
module_exit(amark_cleanup);
