#include <stdio.h>    
#include <stdlib.h>    
#include <sys/user.h>    
#include <asm/ptrace.h>    
#include <sys/ptrace.h>    
#include <sys/wait.h>    
#include <sys/mman.h>    
#include <dlfcn.h>    
#include <dirent.h>    
#include <unistd.h>    
#include <string.h>    
#include <elf.h>    
#include <android/log.h>    
#include <sys/uio.h>
#include <stdarg.h>
#include <sys/syscall.h> 
#include <fcntl.h>
#include <sys/types.h>
#include <stdbool.h>
  
#define LOG_TAG "INJECT"
#define LOGD(fmt, args...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, fmt, ##args)

#define GETLR(store_lr)  \
  __asm__ __volatile__(  \
    "mov %0, lr\n\t"  \
    :  "=r"(store_lr)  \
  ) 

int hook_entry(char * a){
	LOGD("Hook success\n");
    LOGD("Start hooking\n");
    hook_fopen();
	

    return 0;

}

void* get_module_base(pid_t pid, const char* module_name)
{
    FILE *fp;
    long addr = 0;
    char *pch;
    char filename[32];
    char line[1024];
 
    if (pid < 0) {
        /* self process */
        snprintf(filename, sizeof(filename), "/proc/self/maps", pid);
    } else {
        snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    }
 
    fp = fopen(filename, "r");
 
    if (fp != NULL) {
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, module_name)) {
                pch = strtok( line, "-" );
                addr = strtoul( pch, NULL, 16 );
 
                if (addr == 0x8000)
                    addr = 0;
 
                break;
            }
        }
 
        fclose(fp) ;
    }
 
    return (void *)addr;
}
FILE* (*old_fopen)(const char *path,const char * mode);
FILE* new_fopen(const char *path,const char * mode){
	  unsigned lr;
	  GETLR(lr);

	  if(strstr(path, "status") != NULL){
	    LOGD("Traced-fopen Call function: 0x%x\n", lr);
	    if(strstr(path, "task") != NULL){
	      LOGD("Traced-anti-task/status");
	    }else
	      LOGD("Traced-anti-status");
	  }else if(strstr(path, "wchan") != NULL){
	    LOGD("Traced-fopen Call function: 0x%x\n", lr);
	    LOGD("Traced-anti-wchan");
	  } 
	  return old_fopen(path, mode);
	}


#define LIBSF_PATH "/system/lib/libc.so"
int hook_fopen(){
	old_fopen = fopen;
	LOGD("Orig fopen %p\n",old_fopen);
	void * base_addr = get_module_base(getpid(),LIBSF_PATH);
	LOGD("libc.so.addr %p\n",base_addr);
	int fd;
	fd = open(LIBSF_PATH,O_RDONLY);
	if(fd == -1){
		LOGD("error");
		return -1;
	}
	Elf32_Ehdr ehdr;
	read(fd, &ehdr, sizeof(Elf32_Ehdr));
	unsigned long shdr_addr = ehdr.e_shoff;
	int shnum = ehdr.e_shnum;
	int shent_size = ehdr.e_shentsize;
	unsigned long stridx = ehdr.e_shstrndx;
	Elf32_Shdr shdr;
	lseek(fd, shdr_addr + stridx * shent_size, SEEK_SET);
	read(fd, &shdr, shent_size);
	char * string_table = (char *)malloc(shdr.sh_size);
	lseek(fd, shdr.sh_offset, SEEK_SET);
	read(fd, string_table, shdr.sh_size);
	lseek(fd, shdr_addr, SEEK_SET);
	int i;
	uint32_t out_addr = 0;
	uint32_t out_size = 0;
	uint32_t got_item = 0;
	int32_t got_found = 0;
	for (i = 0; i < shnum; i++){
		read(fd, &shdr, shent_size);
		if (shdr.sh_type == SHT_PROGBITS){
			int name_idx = shdr.sh_name;
			if (strcmp(&(string_table[name_idx]), ".got.plt") == 0 || strcmp(&(string_table[name_idx]), ".got") == 0){
				out_addr = base_addr + shdr.sh_addr;
				out_size = shdr.sh_size;
				LOGD("out_addr = %lx, out_size = %lx\n", out_addr, out_size);
				for (i = 0; i < out_size; i += 4){
					got_item = *(uint32_t *)(out_addr + i);
					LOGD("got_item %x\n",got_item);
					if (got_item  == old_fopen){
						LOGD("Found fopen in got");
						got_found = 1;
						uint32_t page_size = getpagesize();
						uint32_t entry_page_start = (out_addr + i) & (~(page_size - 1));
						if(mprotect((uint32_t *)entry_page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) == -1){
							LOGD("mprotect false\n");
							return -1;
						}
						*(uint32_t *)(out_addr + i) = new_fopen;
						if(mprotect((uint32_t *)entry_page_start, page_size, PROT_READ | PROT_WRITE) == -1){
							LOGD("mprotect false\n");
							return -1;
						}
						break;


					}else if (got_item == new_fopen){
						LOGD("Already hooked\n");
						break;
					}
				}
				if(got_found){
					break;
				}
			}
		}
		
	}
	free(string_table);
	close(fd);
}
	// bool HasGenFile(const char *re_path) {
	// 	FILE *fpr;
	// 	char buffer[1024];
	// 	fpr = old_fopen(re_path, "r");
	// 	if (fpr == NULL) {
	// 		return false;
	// 	}
	// 	while (fgets(buffer, 1024, fpr) != NULL) {
	// 		if (strstr(buffer, "State") != NULL) {
	// 			return true;
	// 		}
	// 		if (strstr(buffer, "TracerPid") != NULL) {
	// 			return true;
	// 		}
	// 	}
	// 	LOGD("[*] HasGenFile return false");
	// 	return false;
	// }
	// FILE* hookToNewFile(const char *path, const char * mode) {
	// 	char re_path[256];
	// 	sprintf(re_path, "/data/local/tmp/status");
	// 	if (!HasGenFile(re_path)) {
	// 		char buffer[1024];
	// 		FILE *fpr, *fpw;
	// 		fpr = old_fopen(path, "r");
	// 		fpw = old_fopen(re_path, "w");
	// 		if (fpr == NULL || fpw == NULL) {
	// 			LOGD("[E] re-path [%s]failed", path);
	// 			return old_fopen(path, mode);
	// 		}
	// 		while (fgets(buffer, 1024, fpr) != NULL) {
	// 			if (strstr(buffer, "State") != NULL) {
	// 				fputs("State:\tS (sleeping)\n", fpw);
	// 			}
	// 			if (strstr(buffer, "TracerPid") != NULL) {
	// 				fputs("TracerPid:\t0\n", fpw);
	// 			} else {
	// 				fputs(buffer, fpw);
	// 			}
	// 		}
	// 		fclose(fpr);
	// 		fclose(fpw);
	// 	}
	// 	LOGD("[*] hookToNewFile Success");
	// 	return old_fopen(re_path, mode);

	// FILE* new_fopen(const char *path,const char * mode){
	// 	unsigned lr;
	// 	GETLR(lr);
	// 	if(strstr(path, "status") != NULL){
	// 		LOGD("[*] Traced-fopen Call function: 0x%x\n", lr);
	// 		if(strstr(path, "task") != NULL){
	// 			LOGD("[*] Traced-anti-task/status");
	// 		}else {
	// 			LOGD("[*] Traced-anti-status");
	// 			return hookToNewFile(path, mode);
	// 		}
	// 	}else if(strstr(path, "wchan") != NULL){
	// 		LOGD("[*] Traced-fopen Call function: 0x%x\n", lr);
	// 		LOGD("[*] Traced-anti-wchan");
	// 	}
	// 	return old_fopen(path, mode);
	// }


