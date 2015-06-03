/*
 * 
 *
 * Copyright (C) 2015 Chen Feng <infi.chen@spreadtrum.com>
 * Copyright (C) 2015 Spreadtrum Inc.
 *
 * Released under the GPL version 2 only.
 *
 */
#include <linux/kobject.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <asm/uaccess.h>
#include <linux/errno.h>
#include <asm/processor.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <asm/current.h>
#include <linux/fcntl.h>	/* O_ACCMODE */
#include <linux/kallsyms.h>
#include <linux/list.h>
#include "ucall.h"
//#ifdef KERNEL310
#define CONFIG_KERNEL310
//#endif

#ifdef CONFIG_KERNEL310
#include <linux/slab.h>
#endif

static int ucall_func;
static struct ucall_data ucall;

#define UCALL_ATTR(__name)  \
	static ssize_t __name##_show(struct kobject *kobj, struct kobj_attribute *attr, \
								 char *buf); \
static ssize_t __name##_store(struct kobject *kobj, struct kobj_attribute *attr, \
							  const char *buf, size_t count); \
static struct kobj_attribute __name##_attribute =   \
__ATTR(__name,0666,__name##_show,__name##_store)
UCALL_ATTR(ucall_func);

static char *ucall_func_name;
static void *ucall_func_addr; 

static ssize_t ucall_func_show(struct kobject *kobj, struct kobj_attribute *attr,
							   char *buf)
{
	return sprintf(buf, "%d\n", ucall_func);
}

static ssize_t ucall_func_store(struct kobject *kobj, struct kobj_attribute *attr,
								const char *buf, size_t count)
{
	int ret=0;
	// mm_segment_t fs = get_fs();
	// set_fs(KERNEL_DS);

	sscanf(buf, "%x", &ucall_func_addr);
	if (!ucall_func_addr) {
		PDEBUG("Null point\n");
		return -EINVAL;
	}
	PDEBUG("ucall_func_addr:[%p] (%pS)\n",ucall_func_addr,ucall_func_addr);
	// set_fs(fs);

	asm("mov %0, r0\n"
		"sub sp, sp, #8\n"
		"mov r4, %1\n"
		"blx r4\n"
		"add sp, sp, #8\n"
		"mov %0, r0\n"
		: "+r"(ret)
		: "r"(ucall_func_addr)
		: "r0", "r1", "r2", "r3", "r4", "ip", "memory");

	// PDEBUG("current process information [%s] <%d> \n",current->comm,current->pid);
	PDEBUG("ret = %d\n",ret);

	return count;
}
//################################# breakdebug #################################################

//################################# breakdebug #################################################
//################################# hack_func #################################################
void __hack_func_temp(void){
	asm("mov	ip, sp\n"
		"push	{fp, ip, lr, pc}\n"
		"sub	fp, ip, #4\n"
		"ldr pc, [pc, #-4]\n"   //e51ff004
		"NOP\n"
		"NOP\n"
		"NOP\n"
		"NOP\n"
		"NOP\n"
	   );
}
#define MAX_HACK_NUM 10
struct hack_func_code{
	unsigned *from;
	unsigned *to;
	unsigned *code[2];
}hacked_code[MAX_HACK_NUM]={0};
int hack_func_empty(void){
	PDEBUG(" call,return 0\n");
	return 0;
}
int hack_func(unsigned *from,unsigned *to){
	int i;
	int is_full = 1;
	for(i=0;i<MAX_HACK_NUM;i++){
		if(hacked_code[i].from){
			PDEBUG("hacked_code: 0x%x\n",hacked_code[i].from);
			continue;
		}
		PDEBUG("xxxx 0x%x\n",hacked_code[i].from);
		hacked_code[i].from = from;
		hacked_code[i].to = to;
		hacked_code[i].code[0]=from[0];
		hacked_code[i].code[1]=from[1];
		is_full = 0;
		break;
	}
	if(is_full){
		PDEBUG("full backup list, hack fail\n");
		return -1;
	}

	from[0] = 0xe51ff004;	//ldr	pc, [pc, #-4]
	from[1] = to;
	return 0;
}
int unhack_func(unsigned *from){
	int i;
	int is_unhack=0;
	for(i=0;i<MAX_HACK_NUM;i++){
		PDEBUG(" 0x%x 0x%x!\n",hacked_code[i].from,from);
		if(hacked_code[i].from== from)
		{
			from[0]=hacked_code[i].code[0];
			from[1]=hacked_code[i].code[1];
			
			hacked_code[i].from = 0;
			hacked_code[i].to = 0;
			is_unhack = 1;
			PDEBUG(" unhack_func success!\n");
			break;
		}
	}
	if(!is_unhack) {
		PDEBUG("unhack_func fail\n");
		return -1;
	};
	return 0;
}


//################################# hack_func #################################################
static inline int clean_paramters(struct ucall_data *ucall){
	int i;
	for(i=0;i<6;i++){
		if(ucall->parameters[i].type > 0)
			kfree((void *)ucall->parameters[i].para);
	}
	return 0;
}
static int do_call_func(struct ucall_data *ucall){

	int ret=0;
	if (!ucall) {
		PDEBUG("Null point\n");
		return -EINVAL;
	}
	PDEBUG("%s call\n",ucall->func_name);
	PDEBUG("ucall->func_addr:%p \n",ucall->func_addr);
	struct func_parameter *ucallpara=ucall->parameters;
	//LOGD(kallsyms_lookup_name("test"));

	asm("sub sp, sp, #8\n"
		"mov r3, %0\n"
		"str r3, [sp, #0]\n"
		"mov r3, %1\n"
		"str r3, [sp, #4]\n"
		"add sp, sp, #8\n"
		:
		:"r"(ucallpara[4].para),"r"(ucallpara[5].para)
		:"r3", "sp", "memory");

	asm("mov r0, %2\n"
		"mov r1, %3\n"
		"mov r2, %4\n"
		"mov r3, %5\n"
		"sub sp, sp, #8\n"
		"mov r4, %1\n"
		"blx r4\n"
		"add sp, sp, #8\n"
		"mov %0, r0\n"
		: "+r"(ret)
		: "r"(ucall->func_addr),"r"(ucallpara[0].para),"r"(ucallpara[1].para),
		"r"(ucallpara[2].para),"r"(ucallpara[3].para)
		: "r0", "r1", "r2", "r3", "r4", "ip", "memory");

	PDEBUG("ret = %d\n",ret);
	return ret;
}

int test_multi_str(char *stra,char *strb,char *strc){
	printk("\n..............\nstra:%s\nstrb:%s\nstrc:%s\n ...............\n",stra,strb,strc);
	return 0xa;
}

int test_str(int n,char *str,int len){
	while(n--)
		PDEBUG(" %d %s %d\n",n,str,len);
	return 0xa;
}
int test(int a,int b,int c){
	PDEBUG("a,b,c=(0x%x,0x%x,0x%x)\n",a,b,c);
	return 0xa;
}

static struct attribute *attrs[] = {
	&ucall_func_attribute.attr,
	NULL,	/* need to NULL terminate the list of attributes */
};

static struct attribute_group attr_group = {
	.attrs = attrs,
};

static struct kobject *ucall_kobj;

#ifdef CONFIG_KERNEL310
long ucall_ioctl (struct file *file, unsigned int cmd, unsigned long arg)
#else
static int ucall_ioctl(struct inode *inode, struct file *filp, unsigned int cmd , unsigned long arg)
#endif
{
	int err = 0;
	static int retval=0;
	/* don't even decode wrong cmds: better returning  ENOTTY than EFAULT */
	if (_IOC_TYPE(cmd) != UCALL_IOC_MAGIC) return -ENOTTY;
	if (_IOC_NR(cmd) > UCALL_IOC_MAXNR) return -ENOTTY;

	/*
	 * the type is a bitmask, and VERIFY_WRITE catches R/W
	 * transfers. Note that the type is user-oriented, while
	 * verify_area is kernel-oriented, so the concept of "read" and
	 * "write" is reversed
	 */
	if (_IOC_DIR(cmd) & _IOC_READ)
		err = !access_ok(VERIFY_WRITE, (void __user *)arg, _IOC_SIZE(cmd));
	else if (_IOC_DIR(cmd) & _IOC_WRITE)
		err =  !access_ok(VERIFY_READ, (void __user *)arg, _IOC_SIZE(cmd));
	if (err)
		return -EFAULT;
	switch(cmd){
	case UCALL_CALL_FUNC:
		err=copy_from_user(&ucall,(void __user*)arg,sizeof(struct ucall_data));
		PDEBUG("ucall.func_name : %s\n",ucall.func_name);
		break;
	case UCALL_DATA_SET:
		{
			int i = 0;
			char *tempstr;
			err=copy_from_user(&ucall,(void __user*)arg,sizeof(struct ucall_data));
			for(i=0;i<6;i++){
				int len = ucall.parameters[i].type;
				if( len > 0){
					len += 2;
					tempstr = (char *)kmalloc(len,GFP_KERNEL);
					memset(tempstr,0,len);
					err=copy_from_user(tempstr,(void __user * )ucall.parameters[i].para,len);
					pr_debug("tempstr = %s %p\n",tempstr,ucall.parameters[i].para);
					ucall.parameters[i].para =(unsigned) tempstr;
				}
				if(len)
					PDEBUG("parameters[%d] type:%d value:\"%s\"\n",i,ucall.parameters[i].type,ucall.parameters[i].para);
				else
					PDEBUG("parameters[%d] type:%d value:0x%x\n",i,ucall.parameters[i].type,ucall.parameters[i].para);
			}
			retval=do_call_func(&ucall);
			clean_paramters(&ucall);
		}
		break;
	case UCALL_RESULT_GET:
		PDEBUG("ucall.retval : 0x%x %d\n",retval,retval);
		err=copy_to_user((void __user * )arg,&retval,sizeof(retval));
		break;
	default:
		break;
	}

	return 0;
}

struct file_operations ucall_ops = {
	.owner = THIS_MODULE,
#ifdef CONFIG_KERNEL310
	.unlocked_ioctl = ucall_ioctl,
#else
	.ioctl = ucall_ioctl,
#endif
};

static struct miscdevice ucall_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "ucall_misc",
	.fops = &ucall_ops,
};

static int __init ucall_init(void)
{
	int retval;

	PDEBUG("call\n");
	/*
	 * Create a simple kobject with the name of "kobject_ucall",
	 * located under /sys/kernel/
	 *
	 * As this is a simple directory, no uevent will be sent to
	 * userspace.  That is why this function should not be used for
	 * any type of dynamic kobjects, where the name and number are
	 * not known ahead of time.
	 */

	misc_register(&ucall_misc);
	ucall_kobj = kobject_create_and_add("ucall",NULL);
	if (!ucall_kobj)
		return -ENOMEM;

	/* Create the files associated with this kobject */
	retval = sysfs_create_group(ucall_kobj, &attr_group);
	if (retval)
		kobject_put(ucall_kobj);

	return retval;
}

static void __exit ucall_exit(void)
{
	PDEBUG("call\n");
	misc_deregister(&ucall_misc);
	kobject_put(ucall_kobj);
}

module_init(ucall_init);
module_exit(ucall_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Chen Feng <infi.chen@spreadtrum.com>");
