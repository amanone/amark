#include <linux/module.h>

MODULE_LICENSE("GPL");

int init_module() {
	printk("+ amark loaded\n");
	return 0;
}

void cleanup_module() {
	printk("+ Unloading module\n");
}

