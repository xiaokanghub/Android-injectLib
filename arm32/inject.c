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

#if defined(__i386__)  
#define pt_regs user_regs_struct  
#endif

#define LOG_TAG "INJECT"
#define LOGD(fmt, args...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, fmt, ##args)
#define CPSR_T_MASK (1u << 5)

const char* libc_path = "/system/lib/libc.so";
const char* linker_path = "/system/bin/linker";

/*--------------------------------------------------
*   功能:   向目标进程指定的地址中读取数据
*
*   参数:
*           pid       需要注入的进程pid
*           src       需要读取的目标进程地址
*           buf       需要读取的数据缓冲区
*           size      需要读取的数据长度
*
*   返回值: -1
*--------------------------------------------------*/
int ptrace_readdata(pid_t pid, uint8_t *src, uint8_t *buf, size_t size){
    uint32_t i, j, remain;
    uint8_t *laddr;

    union u{
        long val;
        char chars[sizeof(long)];
    }d;

    j = size/4;
    remain = size%4;
    laddr = buf;

    for(i = 0; i<j; i++){
        //从内存地址src中读取四个字节
        d.val = ptrace(PTRACE_PEEKTEXT, pid, src, 0);
        memcpy(laddr, d.chars, 4);
        src += 4;
        laddr += 4;
    }

    if(remain > 0){
        d.val = ptrace(PTRACE_PEEKTEXT, pid, src, 0);
        memcpy(laddr, d.chars, remain);
    }
    return 0;
}

/*--------------------------------------------------
*   功能:   向目标进程指定的地址中写入数据
*
*   参数:
*           pid       需要注入的进程pid
*           dest      需要写入的目标进程地址
*           data      需要写入的数据缓冲区
*           size      需要写入的数据长度
*
*   返回值: -1
*--------------------------------------------------*/
int ptrace_writedata(pid_t pid, uint8_t *dest, uint8_t *data, size_t size){
    uint32_t i, j, remain;
    uint8_t *laddr;
    
    union u{
        long val;
        char u_data[sizeof(long)];
    }d;

    j = size/4;
    remain = size%4;

    laddr = data;

    //先4字节拷贝
    for(i = 0; i<j; i++){
        memcpy(d.u_data, laddr, 4);
        //往内存地址中写入四个字节,内存地址由dest给出
        ptrace(PTRACE_POKETEXT, pid, dest, d.val);

        dest += 4;
        laddr += 4;
    }

    //最后不足4字节的，单字节拷贝
    //为了最大程度的保持原栈的数据，需要先把原程序最后四字节读出来
    //然后把多余的数据remain覆盖掉四字节中前面的数据
    if(remain > 0){        
        d.val = ptrace(PTRACE_PEEKTEXT, pid, dest, 0);    //从内存地址中读取四个字节，内存地址由dest给出
        for(i = 0; i<remain; i++){
            d.u_data[i] = *laddr++;        
        }
        ptrace(PTRACE_POKETEXT, pid, dest, d.val);
    }
    return 0;
}

/*--------------------------------------------------
*   功能:   获取指定进程的寄存器信息
*
*   返回值: 失败返回-1
*--------------------------------------------------*/
int ptrace_getregs(pid_t pid, struct pt_regs *regs){
    if(ptrace(PTRACE_GETREGS, pid, NULL, regs) < 0){
        perror("ptrace_getregs: Can not get register values.");
        return -1;
    }
    return 0;
}

/*--------------------------------------------------
*   功能:   修改目标进程寄存器的值
*
*   参数:
*           pid        需要注入的进程pid
*           pt_regs    需要修改的新寄存器信息
*
*   返回值: -1
*--------------------------------------------------*/
int ptrace_setregs(pid_t pid, struct pt_regs *regs){
    if(ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0){
        perror("ptrace_setregs:Can not set regsiter values.");
        return -1;
    }
    return 0;
}

/*--------------------------------------------------
*   功能:   恢复程序运行
*
*   参数:
*           pid        需要注入的进程pid
*
*   返回值: -1
*--------------------------------------------------*/
int ptrace_continue(pid_t pid){
    if(ptrace(PTRACE_CONT, pid, NULL, 0) < 0){
        perror("ptrace_cont");
        return -1;
    }
    return 0;
}

/*--------------------------------------------------
*   功能:   附加进程
*
*   返回值: 失败返回-1
*--------------------------------------------------*/
int ptrace_attach(pid_t pid){
    if(ptrace(PTRACE_ATTACH, pid, NULL, 0) < 0){
        perror("ptrace_attach");
        return -1;
    }
    return 0;
}

// 释放对目标进程的附加调试  
int ptrace_detach(pid_t pid)  
{  
    if (ptrace(PTRACE_DETACH, pid, NULL, 0) < 0) {  
        perror("ptrace_detach");  
        return -1;  
    }  
  
    return 0;  
}  
/*--------------------------------------------------
*   功能:   获取进程中指定模块的首地址
*    原理：  通过遍历/proc/pid/maps文件，来找到目的module_name的内存映射起始地址。
*    由于内存地址的表达方式是startAddrxxxxxxx-endAddrxxxxxxx的，所以通过使用strtok(line,"-")来分割字符串获取地址
*    如果pid = -1,表示获取本地进程的某个模块的地址，否则就是pid进程的某个模块的地址
*   参数:
*           pid             需要注入的进程pid, 如果为0则获取自身进程
*           module_name        需要获取模块路径
*
*   返回值: 失败返回NULL, 成功返回addr
*--------------------------------------------------*/
void *get_module_base(pid_t pid, const char* module_name)
{
    FILE* fp;
    long addr = 0;
    char* pch;
    char filename[32];
    char line[1024];
    
    if(pid < 0){
        snprintf(filename, sizeof(filename), "/proc/self/maps");
    }else{
        snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    }

    fp = fopen(filename, "r");

    if(fp != NULL){
        while(fgets(line, sizeof(line), fp)){
            if(strstr(line, module_name)){
                pch = strtok(line, "-");
                //将参数pch字符串根据参数base(表示进制)来转换成无符号的长整型数 
                addr = strtoul(pch, NULL, 16);
                if(addr == 0x8000)
                    addr = 0;
                break;
            }
        }
        fclose(fp);
    }
    return (void*)addr;
}


/*--------------------------------------------------
*   功能:   获取目标进程中函数指针
*
*   参数:
*           target_pid          需要注入的进程pid
*           module_name            需要获取的函数所在的lib库路径
*           local_addr            需要获取的函数所在当前进程内存中的地址
*
*           目标进程中函数指针 = 目标进程模块基址 - 自身进程模块基址 + 内存中的地址
*
*   返回值: 失败返回NULL, 成功返回ret_addr
*--------------------------------------------------*/
void* get_remote_addr(pid_t target_pid, const char* module_name, void* local_addr){
    void* local_handle, *remote_handle;
    //获取本地某个模块的起始地址
    local_handle = get_module_base(-1, module_name);
    //获取远程pid的某个模块的起始地址
    remote_handle = get_module_base(target_pid, module_name);
    
    LOGD("[+]get remote address: local[%x], remote[%x]\n", local_handle, remote_handle);

    //local_addr - local_handle的值为指定函数(如mmap)在该模块中的偏移量，然后再加上remote_handle，结果就为指定函数在目标进程的虚拟地址
    void* ret_addr = (void*)((uint32_t)local_addr - (uint32_t)local_handle) + (uint32_t)remote_handle;
    //增加对x86的支持，x86模式下对“/system/lib/libc.so”中，函数调用地址的特殊处理
#if defined(__i386__)
    if(!strcmp(module_name,libc_path)){
        //函数调用地址加2
        ret_addr += 2;

    }
#endif
    return ret_addr;
}

/*--------------------------------------------------
*   功能:   通过进程的名称获取对应的进程pid
*   原理：  通过遍历/proc目录下的所有子目录，获取这些子目录的目录名(一般就是进程的进程号pid)。
*            获取子目录名后，就组合成/proc/pid/cmdline文件名，然后依次打开这些文件，cmdline文件
*            里面存放的就是进程名，通过这样就可以获取进程的pid了
*   返回值: 未找到返回-1
*--------------------------------------------------*/
int find_pid_of(const char* process_name){
    int id;
    pid_t pid = -1;
    DIR* dir;
    FILE* fp;
    char filename[32];
    char cmdline[296];
    
    struct dirent* entry;
    
    if(process_name == NULL){
        return -1;
    }
    
    dir = opendir("/proc");
    if(dir == NULL){
        return -1;
    }

    while((entry = readdir(dir)) != NULL){
        id = atoi(entry->d_name);
        if(id != 0){
            sprintf(filename, "/proc/%d/cmdline", id);
            fp = fopen(filename, "r");
            if(fp){
                fgets(cmdline, sizeof(cmdline), fp);
                fclose(fp);// 释放对目标进程的附加调试   

                if(strcmp(process_name, cmdline) == 0){
                    pid = id;
                    break;
                }
            }
        }
    }
    closedir(dir);
    return pid;
}

long ptrace_retval(struct pt_regs* regs){
    return regs->ARM_r0;
}

long ptrace_ip(struct pt_regs* regs){
    return regs->ARM_pc;
}

/*--------------------------------------------------
*   功能:   调用远程函数指针
*    原理：    1，将要执行的指令写入寄存器中，指令长度大于4个long的话，需要将剩余的指令通过ptrace_writedata函数写入栈中；
*            2，使用ptrace_continue函数运行目的进程，直到目的进程返回状态值0xb7f（对该值的分析见后面红字）；
*            3，函数执行完之后，目标进程挂起，使用ptrace_getregs函数获取当前的所有寄存器值，方便后面使用ptrace_retval函数获取函数的返回值。
*   参数:
*           pid             需要注入的进程pid
*           addr             调用的函数指针地址
*           params          调用的参数
*           num_params      调用的参数个数
*           regs            远程进程寄存器信息(ARM前4个参数由r0 ~ r3传递)
*
*   返回值: 失败返回-1
*--------------------------------------------------*/
int ptrace_call(pid_t pid, uint32_t addr, long* params, uint32_t num_params, struct pt_regs* regs){
    uint32_t i;
    for(i = 0; i<num_params && i < 4; i++){
        regs->uregs[i] = params[i];
    }
    
    if(i < num_params){
        regs->ARM_sp -= (num_params - i) * sizeof(long);
        ptrace_writedata(pid, (void*)regs->ARM_sp, (uint8_t*)&params[i], (num_params - i)*sizeof(long));
    }
    //将PC寄存器值设为目标函数的地址
    regs->ARM_pc = addr;
    ////指令集判断
    if(regs->ARM_pc & 1){
        /* thumb */
        regs->ARM_pc &= (~1u);
        regs->ARM_cpsr |= CPSR_T_MASK;
    }else{
         /* arm */   
        regs->ARM_cpsr &= ~CPSR_T_MASK;
    }
    ///设置子程序的返回地址为空，以便函数执行完后，返回到null地址，产生SIGSEGV错误
    regs->ARM_lr = 0;

    //将修改后的regs写入寄存器中，然后调用ptrace_continue来执行我们指定的代码
    if(ptrace_setregs(pid, regs) == -1 || ptrace_continue(pid) == -1){
        printf("error.\n");
        return -1;
    }

    int stat = 0;
    /* WUNTRACED告诉waitpid，如果子进程进入暂停状态，那么就立即返回。如果是被ptrace的子进程，那么即使不提供WUNTRACED参数，也会在子进程进入暂停状态的时候立即返回。
    对于使用ptrace_cont运行的子进程，它会在3种情况下进入暂停状态：①下一次系统调用；②子进程退出；③子进程的执行发生错误。这里的0xb7f就表示子进程进入了暂停状态，
    且发送的错误信号为11(SIGSEGV)，它表示试图访问未分配给自己的内存, 或试图往没有写权限的内存地址写数据。那么什么时候会发生这种错误呢？显然，当子进程执行完注入的
    函数后，由于我们在前面设置了regs->ARM_lr = 0，它就会返回到0地址处继续执行，这样就会产生SIGSEGV了！
    */   
    waitpid(pid, &stat, WUNTRACED);
    /*stat的值：高2字节用于表示导致子进程的退出或暂停状态信号值，低2字节表示子进程是退出(0x0)还是暂停(0x7f)状态。
    0xb7f就表示子进程为暂停状态，导致它暂停的信号量为11即sigsegv错误。*/
    while(stat != 0xb7f){
        if(ptrace_continue(pid) == -1){
            printf("error.\n");
            return -1;
        }
        waitpid(pid, &stat, WUNTRACED);
    }
    return 0;
}

/*--------------------------------------------------
*   功能:   调用远程函数指针
*
*   参数:
*           pid            需要注入的进程pid
*           func_name      调用的函数名称, 此参数仅作Debug输出用
*           func_addr      调用的函数指针地址
*           param          调用的参数
*           param_num      调用的参数个数
*           regs           远程进程寄存器信息(ARM前4个参数由r0 ~ r3传递)
*
*   返回值: 失败返回-1
*--------------------------------------------------*/
int ptrace_call_wrapper(pid_t target_pid, const char* func_name, void* func_addr, long* param, int param_num, struct pt_regs* regs){
    LOGD("[+]Calling %s in target process.\n", func_name);
    if(ptrace_call(target_pid, (uint32_t)func_addr, param, param_num, regs) == -1)
        return -1;
    if(ptrace_getregs(target_pid, regs) == -1){
        return -1;
    }
    LOGD("[+] Target process returned from %s, return value = %x, pc = %x \n", func_name, ptrace_retval(regs), ptrace_ip(regs));
    return 0;
}

/*--------------------------------------------------
*   功能:   远程注入
*
*   参数:
*           target_pid          需要注入的进程Pid
*           library_path           需要注入的.so路径
*           function_name          .so中导出的函数名
*           param                 函数的参数
*            param_size            参数大小，以字节为单位
*
*   返回值: 注入失败返回-1
*--------------------------------------------------*/
int inject_remote_process(pid_t target_pid, const char* library_path, const char* function_name, const char* param, size_t param_size){
    int ret = -1;
    void* mmap_addr, *dlopen_addr, *dlsym_addr, *dlclose_addr, *dlerror_addr;
    void *local_handle, *remote_handle, *dlhandle;
    uint8_t *map_base = 0;
    uint8_t *dlopen_param1_ptr, *dlsym_param2_ptr, *saved_r0_pc_ptr, *inject_param_ptr, *remote_code_ptr, *local_code_ptr;

    struct pt_regs regs, original_regs;
    extern uint32_t _dlopen_addr_s, _dlopen_param1_s, _dlopen_param2_s, _dlsym_addr_s, _dlsym_param2_s, _dlclose_addr_s, _inject_start_s, _inject_end_s, _inject_function_param_s, _saved_cpsr_s, _saved_r0_pc_s;

    uint32_t code_length;
    long parameters[10];
    
    LOGD("[+] Injecting process: %d\n", target_pid);

    //①ATTATCH，指定目标进程，开始调试
    if(ptrace_attach(target_pid) == -1){
        goto exit;
    }

    //②GETREGS，获取目标进程的寄存器，保存现场
    if(ptrace_getregs(target_pid, &regs) == -1)
        goto exit;

    //保存原始寄存器
    memcpy(&original_regs, &regs, sizeof(regs));

    //③通过get_remote_addr函数获取目标进程的mmap函数的地址，以便为libxxx.so分配内存
    //由于mmap函数在libc.so库中，为了将libxxx.so加载到目标进程中，就需要使用目标进程的mmap函数，所以需要查找到libc.so库在目标进程的起始地址。
    mmap_addr = get_remote_addr(target_pid, libc_path, (void*)mmap);//libc_path = "/system/lib/libc.so"
    LOGD("[+] Remote mmap address: %x\n", mmap_addr);

    parameters[0] = 0;// 设置为NULL表示让系统自动选择分配内存的地址
    parameters[1] = 0x4000;// 映射内存的大小
    parameters[2] = PROT_READ | PROT_WRITE |PROT_EXEC;// 表示映射内存区域可读可写可执行
    parameters[3] = MAP_ANONYMOUS | MAP_PRIVATE;// 建立匿名映射
    parameters[4] = 0;//若需要映射文件到内存中，则为文件的fd
    parameters[5] = 0;//文件映射偏移量

    //④通过ptrace_call_wrapper调用mmap函数，在目标进程中为libxxx.so分配内存
    if(ptrace_call_wrapper(target_pid, "mmap", mmap_addr, parameters, 6, &regs) == -1)
        goto exit;
    //⑤从寄存器中获取mmap函数的返回值，即申请的内存首地址：
    map_base = ptrace_retval(&regs);

    //⑥依次获取linker中dlopen、dlsym、dlclose、dlerror函数的地址
    dlopen_addr = get_remote_addr(target_pid, linker_path, (void*)dlopen);
    dlsym_addr = get_remote_addr(target_pid, linker_path, (void*)dlsym);
    dlclose_addr = get_remote_addr(target_pid, linker_path, (void*)dlclose);
    dlerror_addr = get_remote_addr(target_pid, linker_path, (void*)dlerror);
    
    LOGD("[+] Get imports: dlopen: %x, dlsym: %x, dlclose: %x, dlerror: %x\n", dlopen_addr, dlsym_addr, dlclose_addr, dlerror_addr);

    printf("library path = %s\n", library_path);
    //⑦调用dlopen函数
    //(1)将要注入的so名写入前面mmap出来的内存
    ptrace_writedata(target_pid, map_base, library_path, strlen(library_path) + 1);

    parameters[0] = map_base;
    parameters[1] = RTLD_NOW | RTLD_GLOBAL;

    //(2)执行dlopen
    if(ptrace_call_wrapper(target_pid, "dlopen", dlopen_addr, parameters, 2, &regs) == -1){
        goto exit;
    }
    //(3)取得dlopen的返回值，存放在sohandle变量中
    void* sohandle = ptrace_retval(&regs);
    
    //⑧调用dlsym函数
    //为functionname另找一块区域
    #define FUNCTION_NAME_ADDR_OFFSET 0X100
    ptrace_writedata(target_pid, map_base + FUNCTION_NAME_ADDR_OFFSET, function_name, strlen(function_name) + 1);
    parameters[0] = sohandle;
    parameters[1] = map_base + FUNCTION_NAME_ADDR_OFFSET;

    //调用dlsym
    if(ptrace_call_wrapper(target_pid, "dlsym", dlsym_addr, parameters, 2, &regs) == -1)
        goto exit;
    void* hook_entry_addr = ptrace_retval(&regs);
    LOGD("hooke_entry_addr = %p\n", hook_entry_addr);

    //⑨调用被注入函数hook_entry
    #define FUNCTION_PARAM_ADDR_OFFSET 0X200
    ptrace_writedata(target_pid, map_base + FUNCTION_PARAM_ADDR_OFFSET, parameters, strlen(parameters) + 1);
    parameters[0] = map_base + FUNCTION_PARAM_ADDR_OFFSET;

    if(ptrace_call_wrapper(target_pid, "hook_entry", hook_entry_addr, parameters, 1, &regs) == -1)
        goto exit;
    //⑩调用dlclose关闭lib
    printf("Press enter to dlclose and detach.\n");
    getchar();
    parameters[0] = sohandle;

    if(ptrace_call_wrapper(target_pid, "dlclose", dlclose, parameters, 1, &regs) == -1)
        goto exit;
    
    //⑪恢复现场并退出ptrace
    ptrace_setregs(target_pid, &original_regs);
    ptrace_detach(target_pid);
    ret = 0;

exit:
    return ret;
}

int main(int argc, char** argv) {    
    pid_t target_pid;    
    target_pid = find_pid_of("zygote");    
    if (-1 == target_pid) {  
        printf("Can't find the process\n");  
        return -1;  
    }  
    inject_remote_process(target_pid, "/data/local/tmp/libhello.so", "hook_entry",  "Fuck you!", strlen("Fuck you!"));    
    return 0;  
}