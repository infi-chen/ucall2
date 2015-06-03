/* -*- C -*-
 * scullc.h -- definitions for the scullc char module
 *
 * Copyright (C) 2001 Alessandro Rubini and Jonathan Corbet
 * Copyright (C) 2001 O'Reilly & Associates
 *
 * The source code in this file can be freely used, adapted,
 * and redistributed in source or binary form, so long as an
 * acknowledgment appears in derived source files.  The citation
 * should list that the code comes from the book "Linux Device
 * Drivers" by Alessandro Rubini and Jonathan Corbet, published
 * by O'Reilly & Associates.   No warranty is attached;
 * we cannot take responsibility for errors or fitness for use.
 */

#include <linux/ioctl.h>
//#include <linux/cdev.h>

/*
 * Macros to help debugging
 */
#undef PDEBUG             /* undef it, just in case */
#ifdef UCALL_DEBUG
#  ifdef __KERNEL__
/* This one if debugging is on, and kernel space */
#    define PDEBUG(fmt, args...) printk( KERN_INFO "scullc:[%s] " fmt,__FUNCTION__, ## args)
#  else
/* This one for user space */
#    define PDEBUG(fmt, args...) fprintf(stderr, "ucall:[%s] "fmt,__FUNCTION__, ## args)
#  endif
#else
#  define PDEBUG(fmt, args...) /* not debugging: nothing */
#endif

#define LOGD(x) PDEBUG(#x" %d\n",x)
#undef PDEBUGG
#define PDEBUGG(fmt, args...) /* nothing: it's a placeholder */
typedef enum {
	UCALL_UINT=0,
	UCALL_CHARP,
	UCALL_MAX_TYPE,
}ucall_type;
struct func_parameter{
	int type;
	unsigned int para;
};
struct hack_func{
	char func_name[20];
	void* func_addr;
};
struct ucall_data{
	char func_name[20];
	void* func_addr;
	int func_ret;
	struct func_parameter parameters[6];	
	void *hack_func_addr;
};



/** Ioctl definitions*/

/* Use 'K' as magic number */
#define UCALL_IOC_MAGIC  'K'

#define UCALL_IOCRESET    _IO(UCALL_IOC_MAGIC, 0)

/*
 * S means "Set" through a ptr,
 * T means "Tell" directly
 * G means "Get" (to a pointed var)
 * Q means "Query", response is on the return value
 * X means "eXchange": G and S atomically
 * H means "sHift": T and Q atomically
 */
#define UCALL_DATA_SET _IOW(UCALL_IOC_MAGIC,  1, struct ucall_data*)
#define UCALL_DATA_GET _IOR(UCALL_IOC_MAGIC,  2, struct ucall_data*)
#define UCALL_RESULT_GET _IOR(UCALL_IOC_MAGIC, 3, int)
#define UCALL_CALL_FUNC _IOR(UCALL_IOC_MAGIC, 4, int)
#define UCALL_IOC_MAXNR  5

unsigned get_symbol_addr(const char *addr_str);
unsigned __check_string(char *str);
