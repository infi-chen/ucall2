/*
 *
 * Copyright (C) 2015 Chen Feng <infi.chen@spreadtrum.com>
 * 
 *
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <regex.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include "ucall.h"
#include <regex.h>

void *systemmap;
struct stat st;
struct ucall_data ucall;
//#define DEV "/data/systemmap"
#define DEV "/proc/kallsyms"
void cleanup(void){
	if(systemmap > 0) 
		munmap(systemmap,st.st_size);
	exit(-errno);
}
#define handle_error(prestr) do{ \
	printf("%s : %s \n",prestr,strerror(errno)); \
	printf("%s <%d>: exit...\n",__FUNCTION__,__LINE__); \
	cleanup(); \
}while(0)
void usage(){
	printf("Call kernel function directly!");
	printf("ucall func_name [para0 para1... para5]\n");
}
char *substr(const char *buf,int start,int end){
	if(end-start >128 || end-start < 0) {
		PDEBUG("%d:%d\n",start,end);
		handle_error("substr position");
	}
	static char linebuf[128];
	memcpy(linebuf,buf+start,end-start);
	linebuf[end-start]='\0';
	return linebuf;
}
void *get_systemmap(){
	if(systemmap > 0) return systemmap;
	int fd=open(DEV,O_RDONLY);
	if(fd <0)
		handle_error("open");
	if(fstat(fd,&st))
		handle_error("fstat");
	LOGD(st.st_size);
	systemmap = mmap(NULL,0x100000,PROT_READ,MAP_PRIVATE,fd,0);
	if(systemmap < 0)
		handle_error("systemmap");
	close(fd);
	return systemmap;
}
char *readline(const char *buf){
	static int pos=0;
	int i=pos;
	if(pos >= st.st_size) return NULL;
	while(++pos <= st.st_size && buf[pos] != '\n');
	char *line=substr(buf,i+1,pos);
	return line;
}
int call_func(unsigned int func_addr){
	int err;
	int func_result=0;

	int fd=open("/dev/ucall_misc",O_RDWR);
	if(fd <0) handle_error("open"); 
	ucall.func_addr=(void *)func_addr;
	err=ioctl(fd,UCALL_DATA_SET,&ucall);
	if(err < 0)
		handle_error("ioctl UCALL_DATA_SET");
	err=ioctl(fd,UCALL_RESULT_GET,&func_result);
	if(err < 0)
		handle_error("ioctl UCALL_RESULT_GET");
	PDEBUG("func_result: 0x%x %d\n",func_result,func_result);
	close(fd);
	return 0;
}
int write_int(const char *path,int value){
	const char *buf = value?"1":"0";

	int fd=open(path,O_RDWR);
	if(fd < 0) handle_error("open");
	
	write(fd,buf,1);
	close(fd);
	return 0;
}
unsigned get_symbol_addr(const char *addr_str){
	// PDEBUG(" addr_str : %s\n",addr_str);
	char cmd[256];
	static int n = 0;
	sprintf(cmd,"grep -w %s /proc/kallsyms",addr_str);
	//PDEBUG("cmd : %s\n",cmd);
	FILE *fp=popen(cmd,"r");
	char line[256];
	fread(line,256,1,fp);
	PDEBUG(" line : %s\n",line);
	pclose(fp);	
	int addr=strtoul(substr(line,0,8),NULL,16);
	if(addr == 0){
		errno = 1;
		if(n++) handle_error("get_symbol_addr cannot get addr");
		write_int("/proc/sys/kernel/kptr_restrict",0);
		return get_symbol_addr(addr_str);
	}
	
	return addr;

}
int add_string_param(int index,const char* str){
	if(index < 0 || index > 5) {
		handle_error("add_string_param");
		return -1;
	}
	ucall.parameters[index].type = strlen(str);
	ucall.parameters[index].para = (unsigned int)str;
	// PDEBUG("str = %p,0x%x\n",str,str);
	return index;
}
int add_param(int index,const unsigned para){
	if(index < 0 || index > 5) {
		handle_error("add_param");
		return -1;
	}
	ucall.parameters[index].para = para;
	return index;
}
unsigned __check_string(char *str){
	int dd = strtoul(str,NULL,0);
	if(dd == 0){
		char *p=str;
		if(0 == strncmp(p,"0x",2) || 0 == strncmp(p,"0X",2)){
			p = str+2;
		}
		while(*(p++) == '0');  //in case like "0x000000"
		int ifzero=(p-str-1 == strlen(str))?0:1;
		if(ifzero)
			return	get_symbol_addr(str);
		else
			return 0;
	}else
		return dd;
}
int ucall_prepare(){
	//skip check_version() function
	//const unsigned skip_code[2]={0xE3A00001,0xE12FFF1E}; //hanjie
	const unsigned skip_code[2]={0xE3A00001,0xE1A0F00E};  //mov r0,#1 ; mov pc,lr
	unsigned line[10];
	PDEBUG(" call\n");
	int addr=get_symbol_addr("check_version");
	int fd=open("/dev/kmem",O_RDWR);
	if(fd < 0) handle_error("open /dev/kmem");
	lseek(fd,addr,SEEK_SET);
	write(fd,skip_code,sizeof(skip_code));
	PDEBUG("addr=0x%x 0x%x 0x%x\n",addr,line[0],line[1]);
	close(fd);
	return 0;
}
int main(int argc,char *argv[]){
	int i;
	int ch;  
	opterr = 0;  
	
	while ((ch = getopt(argc,argv,"hst:"))!=-1)  
	{  
		switch(ch)  
		{  
		case 'h':  
			usage();
			PDEBUG("argc = %d\n",argc);
			exit(0);
			break;  
		case 't':  
			PDEBUG("addr: 0x%x\n",__check_string(optarg));
			exit(0);
			break;  
		case 's':
			ucall_prepare();
			exit(0);
			break;
		default:  
			printf("other option :%c\n",ch);  
			exit(1);
			break;
		}  
	} 

#if 0
	regex_t regex;
	regmatch_t pm[4];
	char pattern[128];
	const int nmatch=4;
	sprintf(pattern,". %s.","test");
	PDEBUG("pattern = %s\n",pattern);
	if(regcomp(&regex,pattern,0))
		handle_error("regcompile");
	char *line;
	char *kallsyms = (char *)get_systemmap();

	while((line=readline(kallsyms)) != NULL){
		int status=regexec(&regex,line,nmatch,pm,0);
		if(status == REG_NOMATCH){
		}else{
			PDEBUG("%s\n",line);
			call_func(strtoul(substr(line,0,8),NULL,16));
		}
	}
	cleanup();
#endif
#if 0
	unsigned addr =__check_string(argv[1]);
	strcpy(ucall.func_name,argv[1]);
	PDEBUG("addr = 0x%x\n",addr);
	add_param(0,21);
	add_string_param(1,"Hello infi,this is a string parameters");
	add_param(2,0x20);
	add_string_param(0,"This is string a");
	add_string_param(1,"This is string b");
	add_string_param(2,"This is string c");
#endif
	if(argc < 2 || argc > 8) 
	{
		usage();
		PDEBUG("argc = %d\n",argc);
		exit(0);
	}
	if(argc > 2 ){
		PDEBUG(" Call Function: %s(",argv[1]);
		for(i=2;i<argc;i++){
			if(argv[i][0] == '"'){
				int len=strlen(argv[i]);
				add_string_param(i-2,strndup(argv[i]+1,len-2));
			}
			else
				add_param(i-2,__check_string(argv[i]));
			printf("%s,",argv[i]);
		}
			printf("\b)\n");
	}else{
		PDEBUG(" Call Function: %s()\n",argv[1]);
	}
	unsigned addr = __check_string(argv[1]);
	strcpy(ucall.func_name,argv[1]);
	if(addr > 0xb0000000)
		call_func(addr);
	else
	{
		PDEBUG("maybe you can try:\n\techo 0 > /proc/sys/kernel/kptr_restrict");
		usage();
		return -1;
	}
	PDEBUG("done\n");
	return 0;
}
