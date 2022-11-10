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
#include <errno.h>
    
#if defined(__i386__)    
#define pt_regs         user_regs_struct    
#elif defined(__aarch64__)
#define pt_regs         user_pt_regs  
#define uregs   regs
#define ARM_pc  pc
#define ARM_sp  sp
#define ARM_cpsr    pstate
#define ARM_lr      regs[30]
#define ARM_r0      regs[0]  
#define PTRACE_GETREGS PTRACE_GETREGSET
#define PTRACE_SETREGS PTRACE_SETREGSET
#endif    
    
#define ENABLE_DEBUG 1    
    
#if ENABLE_DEBUG    
#define  LOG_TAG "INJECT"    
#define  LOGD(fmt, args...)  __android_log_print(ANDROID_LOG_DEBUG,LOG_TAG, fmt, ##args)    
#define DEBUG_PRINT(format,args...) \
    LOGD(format, ##args);
#else    
#define DEBUG_PRINT(format,args...)    
#endif    
    
#define CPSR_T_MASK     ( 1u << 5 )    
    
#if defined(__aarch64__)    
const char *libc_path = "/apex/com.android.runtime/lib64/bionic/libc.so";    
const char *linker_path = "/apex/com.android.runtime/bin/linker64";
const char *libdl_path = "/apex/com.android.runtime/lib64/bionic/libdl.so";    
#else
const char *libc_path = "/apex/com.android.runtime/lib/bionic/libc.so";    
const char *linker_path = "/apex/com.android.runtime/bin/linker";
const char *libdl_path = "/apex/com.android.runtime/lib/bionic/libdl.so";    
#endif

#define MAX_PATH 256
    
/**
  * @brief 使用ptrace从远程进程内存中读取数据
  * 这里的*_t类型是typedef定义一些基本类型的别名，用于跨平台。例如uint8_t表示无符号8位也就是无符号的char类型
  * @param pid pid表示远程进程的ID
  * @param pSrcBuf pSrcBuf表示从远程进程读取数据的内存地址
  * @param pDestBuf pDestBuf表示用于存储读取出数据的地址
  * @param size size表示读取数据的大小
  * @return 返回0表示读取数据成功
  */
int ptrace_readdata(pid_t pid, uint8_t *pSrcBuf, uint8_t *pDestBuf, size_t size) {
    long nReadCount = 0;
    long nRemainCount = 0;
    uint8_t *pCurSrcBuf = pSrcBuf;
    uint8_t *pCurDestBuf = pDestBuf;
    long lTmpBuf = 0;
    long i = 0;

    nReadCount = size / sizeof(long);
    nRemainCount = size % sizeof(long);

    for (i = 0; i < nReadCount; i++) {
        lTmpBuf = ptrace(PTRACE_PEEKTEXT, pid, pCurSrcBuf, 0);
        memcpy(pCurDestBuf, (char *) (&lTmpBuf), sizeof(long));
        pCurSrcBuf += sizeof(long);
        pCurDestBuf += sizeof(long);
    }

    if (nRemainCount > 0) {
        lTmpBuf = ptrace(PTRACE_PEEKTEXT, pid, pCurSrcBuf, 0);
        memcpy(pCurDestBuf, (char *) (&lTmpBuf), nRemainCount);
    }

    return 0;
}

/**
 * @brief 使用ptrace将数据写入到远程进程空间中
 *
 * @param pid pid表示远程进程的ID
 * @param pWriteAddr pWriteAddr表示写入数据到远程进程的内存地址
 * @param pWriteData pWriteData用于存储写入数据的地址
 * @param size size表示写入数据的大小
 * @return int 返回0表示写入数据成功，返回-1表示写入数据失败
 */
int ptrace_writedata(pid_t pid, uint8_t *pWriteAddr, uint8_t *pWriteData, size_t size){

    long nWriteCount = 0;
    long nRemainCount = 0;
    uint8_t *pCurSrcBuf = pWriteData;
    uint8_t *pCurDestBuf = pWriteAddr;
    long lTmpBuf = 0;
    long i = 0;

    nWriteCount = size / sizeof(long);
    nRemainCount = size % sizeof(long);

    // 先讲数据以sizeof(long)字节大小为单位写入到远程进程内存空间中
    for (i = 0; i < nWriteCount; i++){
        memcpy((void *)(&lTmpBuf), pCurSrcBuf, sizeof(long));
        if (ptrace(PTRACE_POKETEXT, pid, (void *)pCurDestBuf, (void *)lTmpBuf) < 0){ // PTRACE_POKETEXT表示从远程内存空间写入一个sizeof(long)大小的数据
            printf("[-] Write Remote Memory error, MemoryAddr:0x%lx, err:%s\n", (uintptr_t)pCurDestBuf, strerror(errno));
            return -1;
        }
        pCurSrcBuf += sizeof(long);
        pCurDestBuf += sizeof(long);
    }
    // 将剩下的数据写入到远程进程内存空间中
    if (nRemainCount > 0){
        lTmpBuf = ptrace(PTRACE_PEEKTEXT, pid, pCurDestBuf, NULL); //先取出原内存中的数据，然后将要写入的数据以单字节形式填充到低字节处
        memcpy((void *)(&lTmpBuf), pCurSrcBuf, nRemainCount);
        if (ptrace(PTRACE_POKETEXT, pid, pCurDestBuf, lTmpBuf) < 0){
            printf("[-] Write Remote Memory error, MemoryAddr:0x%lx, err:%s\n", (uintptr_t)pCurDestBuf, strerror(errno));
            return -1;
        }
    }
    return 0;
}

/**
 * @brief 在指定进程中搜索对应模块的基址
 *
 * @param pid pid表示远程进程的ID 若为-1表示自身进程
 * @param ModuleName ModuleName表示要搜索的模块的名称
 * @return void* 返回0表示获取模块基址失败，返回非0为要搜索的模块基址
 */
void *get_module_base_addr(pid_t pid, const char *ModuleName){
    FILE *fp = NULL;
    long ModuleBaseAddr = 0;
    char szFileName[50] = {0};
    char szMapFileLine[1024] = {0};

    // 读取"/proc/pid/maps"可以获得该进程加载的模块
    if (pid < 0){
        //  枚举自身进程模块
        snprintf(szFileName, sizeof(szFileName), "/proc/self/maps");
    } else {
        snprintf(szFileName, sizeof(szFileName), "/proc/%d/maps", pid);
    }

    fp = fopen(szFileName, "r");

    if (fp != NULL){
        while (fgets(szMapFileLine, sizeof(szMapFileLine), fp)){
            if (strstr(szMapFileLine, ModuleName)){
                char *Addr = strtok(szMapFileLine, "-");
                ModuleBaseAddr = strtoul(Addr, NULL, 16);

                if (ModuleBaseAddr == 0x8000)
                    ModuleBaseAddr = 0;

                break;
            }
        }

        fclose(fp);
    }

    return (void *)ModuleBaseAddr;
} 

/**
 * @brief 使用ptrace设置远程进程的寄存器值
 *
 * @param pid pid表示远程进程的ID
 * @param regs regs为pt_regs结构 存储需要修改的寄存器值
 * @return int 返回0表示设置寄存器成功 返回-1表示失败
 */
int ptrace_setregs(pid_t pid, struct pt_regs *regs){
#if defined(__aarch64__)
    int regset = NT_PRSTATUS;
    struct iovec ioVec;

    ioVec.iov_base = regs;
    ioVec.iov_len = sizeof(*regs);
    if (ptrace(PTRACE_SETREGSET, pid, (void *)regset, &ioVec) < 0){
        perror("[-] ptrace_setregs: Can not get register values");
        return -1;
    }

    return 0;
#else
    if (ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0){
        printf("[-] Set Regs error, pid:%d, err:%s\n", pid, strerror(errno));
        return -1;
    }
#endif
    return 0;
}

/**
 * @brief 使用ptrace获取远程进程的寄存器值
 *
 * @param pid pid表示远程进程的ID
 * @param regs regs为pt_regs结构，存储了寄存器值
 * @return int 返回0表示获取寄存器成功，返回-1表示失败
 */
int ptrace_getregs(pid_t pid, struct pt_regs *regs){
#if defined(__aarch64__)
    int regset = NT_PRSTATUS;
    struct iovec ioVec;

    ioVec.iov_base = regs;
    ioVec.iov_len = sizeof(*regs);
    if (ptrace(PTRACE_GETREGSET, pid, (void *)regset, &ioVec) < 0){
        printf("[-] ptrace_getregs: Can not get register values, io %llx, %d\n", ioVec.iov_base,ioVec.iov_len);
        return -1;
    }

    return 0;
#else
    if (ptrace(PTRACE_GETREGS, pid, NULL, regs) < 0){
        printf("[-] Get Regs error, pid:%d, err:%s\n", pid, strerror(errno));
        return -1;
    }
#endif
    return 0;
}

   
    
/**
 * @brief ptrace使远程进程继续运行
 *
 * @param pid pid表示远程进程的ID
 * @return int 返回0表示continue成功，返回-1表示失败
 */
int ptrace_continue(pid_t pid){
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0){
        printf("[-] ptrace continue process error, pid:%d, err:%ss\n", pid, strerror(errno));
        return -1;
    }

    printf("[+] ptrace continue process success, pid:%d\n", pid);
    return 0;
}   
    
/**
 * @brief 使用ptrace远程call函数
 *
 * @param pid pid表示远程进程的ID
 * @param ExecuteAddr ExecuteAddr为远程进程函数的地址
 * @param parameters parameters为函数参数的地址
 * @param num_params regs为远程进程call函数前的寄存器环境
 * @param regs
 * @return 返回0表示call函数成功，返回-1表示失败
 */
int ptrace_call(pid_t pid, uintptr_t ExecuteAddr, long *parameters, long num_params,struct pt_regs *regs){
#if defined(__i386__) // 模拟器
    // 写入参数到堆栈
    regs->esp -= (num_params) * sizeof(long); // 分配栈空间，栈的方向是从高地址到低地址
    if (0 != ptrace_writedata(pid, (uint8_t *)regs->esp, (uint8_t *)parameters,(num_params) * sizeof(long))){
        return -1;
    }

    long tmp_addr = 0x0;
    regs->esp -= sizeof(long);
    if (0 != ptrace_writedata(pid, (uint8_t *)regs->esp, (uint8_t *)&tmp_addr, sizeof(tmp_addr))){
        return -1;
    }

    //设置eip寄存器为需要调用的函数地址
    regs->eip = ExecuteAddr;

    // 开始执行
    if (-1 == ptrace_setregs(pid, regs) || -1 == ptrace_continue(pid)){
        printf("[-] ptrace set regs or continue error, pid:%d\n", pid);
        return -1;
    }

    int stat = 0;
    // 对于使用ptrace_cont运行的子进程，它会在3种情况下进入暂停状态：①下一次系统调用；②子进程退出；③子进程的执行发生错误。
    // 参数WUNTRACED表示当进程进入暂停状态后，立即返回
    waitpid(pid, &stat, WUNTRACED);

    // 判断是否成功执行函数
    printf("[+] ptrace call ret status is %d\n", stat);
    while (stat != 0xb7f){
        if (ptrace_continue(pid) == -1){
            printf("[-] ptrace call error");
            return -1;
        }
        waitpid(pid, &stat, WUNTRACED);
    }

    // 获取远程进程的寄存器值，方便获取返回值
    if (ptrace_getregs(pid, regs) == -1){
        printf("[-] After call getregs error");
        return -1;
    }

#elif defined(__x86_64__) // ？？
    int num_param_registers = 6;
    // x64处理器，函数传递参数，将整数和指针参数前6个参数从左到右保存在寄存器rdi,rsi,rdx,rcx,r8和r9
    // 更多的参数则按照从右到左的顺序依次压入堆栈。
    if (num_params > 0)
        regs->rdi = parameters[0];
    if (num_params > 1)
        regs->rsi = parameters[1];
    if (num_params > 2)
        regs->rdx = parameters[2];
    if (num_params > 3)
        regs->rcx = parameters[3];
    if (num_params > 4)
        regs->r8 = parameters[4];
    if (num_params > 5)
        regs->r9 = parameters[5];

    if (num_param_registers < num_params){
        regs->esp -= (num_params - num_param_registers) * sizeof(long); // 分配栈空间，栈的方向是从高地址到低地址
        if (0 != ptrace_writedata(pid, (uint8_t *)regs->esp, (uint8_t *)&parameters[num_param_registers], (num_params - num_param_registers) * sizeof(long))){
            return -1;
        }
    }

    long tmp_addr = 0x0;
    regs->esp -= sizeof(long);
    if (0 != ptrace_writedata(pid, (uint8_t *)regs->esp, (uint8_t *)&tmp_addr, sizeof(tmp_addr))){
        return -1;
    }

    //设置eip寄存器为需要调用的函数地址
    regs->eip = ExecuteAddr;

    // 开始执行
    if (-1 == ptrace_setregs(pid, regs) || -1 == ptrace_continue(pid)){
        printf("[-] ptrace set regs or continue error, pid:%d", pid);
        return -1;
    }

    int stat = 0;
    // 对于使用ptrace_cont运行的子进程，它会在3种情况下进入暂停状态：①下一次系统调用；②子进程退出；③子进程的执行发生错误。
    // 参数WUNTRACED表示当进程进入暂停状态后，立即返回
    waitpid(pid, &stat, WUNTRACED);

    // 判断是否成功执行函数
    printf("ptrace call ret status is %lX\n", stat);
    while (stat != 0xb7f){
        if (ptrace_continue(pid) == -1){
            printf("[-] ptrace call error");
            return -1;
        }
        waitpid(pid, &stat, WUNTRACED);
    }

#elif defined(__arm__) || defined(__aarch64__) // 真机
#if defined(__arm__) // 32位真机
    int num_param_registers = 4;
#elif defined(__aarch64__) // 64位真机
    int num_param_registers = 8;
#endif
    int i = 0;
    // ARM处理器，函数传递参数，将前四个参数放到r0-r3，剩下的参数压入栈中
    for (i = 0; i < num_params && i < num_param_registers; i++){
        regs->uregs[i] = parameters[i];
    }

    if (i < num_params){
        regs->ARM_sp -= (num_params - i) * sizeof(long); // 分配栈空间，栈的方向是从高地址到低地址
        if (ptrace_writedata(pid, (uint8_t *)(regs->ARM_sp), (uint8_t *)&parameters[i], (num_params - i) * sizeof(long)) == -1)
            return -1;
    }

    regs->ARM_pc = ExecuteAddr; //设置ARM_pc寄存器为需要调用的函数地址
    // 与BX跳转指令类似，判断跳转的地址位[0]是否为1，如果为1，则将CPST寄存器的标志T置位，解释为Thumb代码
    // 若为0，则将CPSR寄存器的标志T复位，解释为ARM代码
    if (regs->ARM_pc & 1){
        /* thumb */
        regs->ARM_pc &= (~1u);
        regs->ARM_cpsr |= CPSR_T_MASK;
    } else {
        /* arm */
        regs->ARM_cpsr &= ~CPSR_T_MASK;
    }

    regs->ARM_lr = 0;

    // Android 7.0以上修正lr为libc.so的起始地址 getprop获取ro.build.version.sdk
    long lr_val = 0;
    char sdk_ver[32];
    memset(sdk_ver, 0, sizeof(sdk_ver));
    __system_property_get("ro.build.version.sdk", sdk_ver);
    printf("[+] ro.build.version.sdk: %s\n", sdk_ver);
    if (atoi(sdk_ver) <= 23){
        lr_val = 0;
    } else { // Android 7.0
        static long start_ptr = 0;
        if (start_ptr == 0){
            start_ptr = (long)get_module_base_addr(pid, libc_path);
        }
        lr_val = start_ptr;
    }
    regs->ARM_lr = lr_val;

    if (ptrace_setregs(pid, regs) == -1 || ptrace_continue(pid) == -1){
        printf("[-] ptrace set regs or continue error, pid:%d\n", pid);
        return -1;
    }

    int stat = 0;
    // 对于使用ptrace_cont运行的子进程，它会在3种情况下进入暂停状态：①下一次系统调用；②子进程退出；③子进程的执行发生错误。
    // 参数WUNTRACED表示当进程进入暂停状态后，立即返回
    // 将ARM_lr（存放返回地址）设置为0，会导致子进程执行发生错误，则子进程进入暂停状态
    waitpid(pid, &stat, WUNTRACED);

    // 判断是否成功执行函数
    printf("[+] ptrace call ret status is %d\n", stat);
    while ((stat & 0xFF) != 0x7f){
        if (ptrace_continue(pid) == -1){
            printf("[-] ptrace call error\n");
            return -1;
        }
        waitpid(pid, &stat, WUNTRACED);
    }

    // 获取远程进程的寄存器值，方便获取返回值
    if (ptrace_getregs(pid, regs) == -1){
        printf("[-] After call getregs error\n");
        return -1;
    }

#else // 设备不符合注入器构架
    printf("[-] Not supported Environment %s\n", __FUNCTION__);
#endif
    return 0;
}    
      
    
/**
 * @brief 使用ptrace Attach附加到指定进程,发送SIGSTOP信号给指定进程让其停止下来并对其进行跟踪。
 * 但是被跟踪进程(tracee)不一定会停下来，因为同时attach和传递SIGSTOP可能会将SIGSTOP丢失。
 * 所以需要waitpid(2)等待被跟踪进程被停下
 *
 * @param pid pid表示远程进程的ID
 * @return int 返回0表示attach成功，返回-1表示失败
 */
int ptrace_attach(pid_t pid){
    int status = 0;
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0){
        printf("[-] ptrace attach process error, pid:%d, err:%s\n", pid, strerror(errno));
        return -1;
    }

    printf("[+] attach porcess success, pid:%d\n", pid);
    waitpid(pid, &status, WUNTRACED);

    return 0;
} 
    
/**
 * @brief 使用ptrace detach指定进程,完成对指定进程的跟踪操作后，使用该参数即可解除附加
 *
 * @param pid pid表示远程进程的ID
 * @return int 返回0表示detach成功，返回-1表示失败
 */
int ptrace_detach(pid_t pid){
    if (ptrace(PTRACE_DETACH, pid, NULL, 0) < 0){
        printf("[-] detach process error, pid:%d, err:%s\n", pid, strerror(errno));
        return -1;
    }

    printf("[+] detach process success, pid:%d\n", pid);
    return 0;
}   
    


void* get_remote_addr(pid_t target_pid, const char* module_name, void* local_addr)    
{    
    void* local_handle, *remote_handle;    
    
    local_handle = get_module_base_addr(-1, module_name);    
    remote_handle = get_module_base_addr(target_pid, module_name);    
    
    DEBUG_PRINT("[+] get_remote_addr: local[%llx], remote[%llx]\n", local_handle, remote_handle);    
    
    void * ret_addr = (void *)((uintptr_t)local_addr + (uintptr_t)remote_handle - (uintptr_t)local_handle);    
    
#if defined(__i386__)    
    if (!strcmp(module_name, libc_path)) {    
        ret_addr += 2;    
    }    
#endif    
    return ret_addr;    
}

/**
 * @brief 获取mmap函数在远程进程中的地址
 *
 * @param pid pid表示远程进程的ID
 * @return void* mmap函数在远程进程中的地址
 */
void *get_mmap_address(pid_t pid){
    return get_remote_addr(pid, libc_path, (void *)mmap);
}

/**
 * @brief 获取dlopen函数在远程进程中的地址
 * @param pid pid表示远程进程的ID
 * @return void* dlopen函数在远程进程中的地址
 */
void *get_dlopen_address(pid_t pid) {
    void *dlopen_addr;
    char sdk_ver[32];
    memset(sdk_ver, 0, sizeof(sdk_ver));
    __system_property_get("ro.build.version.sdk", sdk_ver);

    printf("[+] linker_path value:%s\n",linker_path);
    if (atoi(sdk_ver) <= 23) { // 安卓7
        dlopen_addr = get_remote_addr(pid, linker_path, (void *) dlopen);
    } else {
        dlopen_addr = get_remote_addr(pid, libdl_path, (void *) dlopen);
    }
    printf("[+] dlopen RemoteFuncAddr:0x%lx\n", (uintptr_t) dlopen_addr);
    return dlopen_addr;
}

/**
 * @brief 获取dlclose函数在远程进程中的地址
 * @param pid pid表示远程进程的ID
 * @return void* dlclose函数在远程进程中的地址
 */
void *get_dlclose_address(pid_t pid) {
    void *dlclose_addr;
    char sdk_ver[32];
    memset(sdk_ver, 0, sizeof(sdk_ver));
    __system_property_get("ro.build.version.sdk", sdk_ver);

    if (atoi(sdk_ver) <= 23) {
        dlclose_addr = get_remote_addr(pid, linker_path, (void *) dlclose);
    } else {
        dlclose_addr = get_remote_addr(pid, libdl_path, (void *) dlclose);
    }
    printf("[+] dlclose RemoteFuncAddr:0x%lx\n", (uintptr_t) dlclose_addr);
    return dlclose_addr;
}

/**
 * @brief 获取dlsym函数在远程进程中的地址
 * @param pid pid表示远程进程的ID
 * @return void* dlsym函数在远程进程中的地址
 */
void *get_dlsym_address(pid_t pid) {
    void *dlsym_addr;
    char sdk_ver[32];
    memset(sdk_ver, 0, sizeof(sdk_ver));
    __system_property_get("ro.build.version.sdk", sdk_ver);

    if (atoi(sdk_ver) <= 23) {
        dlsym_addr = get_remote_addr(pid, linker_path, (void *) dlsym);
    } else {
        dlsym_addr = get_remote_addr(pid, libdl_path, (void *) dlsym);
    }
    printf("[+] dlsym RemoteFuncAddr:0x%lx\n", (uintptr_t) dlsym_addr);
    return dlsym_addr;
}

/**
 * @brief 获取dlerror函数在远程进程中的地址
 * @param pid pid表示远程进程的ID
 * @return void* dlerror函数在远程进程中的地址
 */
void *get_dlerror_address(pid_t pid) {
    void *dlerror_addr;
    char sdk_ver[32];
    memset(sdk_ver, 0, sizeof(sdk_ver));
    __system_property_get("ro.build.version.sdk", sdk_ver);

    if (atoi(sdk_ver) <= 23) {
        dlerror_addr = get_remote_addr(pid, linker_path, (void *) dlerror);
    } else {
        dlerror_addr = get_remote_addr(pid, libdl_path, (void *) dlerror);
    }
    printf("[+] dlerror RemoteFuncAddr:0x%lx\n", (uintptr_t) dlerror_addr);
    return dlerror_addr;
}    
    
    
    
int find_pid_of(const char *process_name)    
{    
    int id;    
    pid_t pid = -1;    
    DIR* dir;    
    FILE *fp;    
    char filename[32];    
    char cmdline[256];    
    
    struct dirent * entry;    
    
    if (process_name == NULL)    
        return -1;    
    
    dir = opendir("/proc");    
    if (dir == NULL)    
        return -1;    
    
    while((entry = readdir(dir)) != NULL) {    
        id = atoi(entry->d_name);    
        if (id != 0) {    
            sprintf(filename, "/proc/%d/cmdline", id);    
            fp = fopen(filename, "r");    
            if (fp) {    
                fgets(cmdline, sizeof(cmdline), fp);    
                fclose(fp);    
    
                if (strcmp(process_name, cmdline) == 0) {    
                    /* process found */    
                    pid = id;    
                    break;    
                }    
            }    
        }    
    }    
    
    closedir(dir);    
    return pid;    
}    
    
/**
 * @brief 获取返回值，ARM处理器中返回值存放在ARM_r0寄存器中
 * @param regs regs存储远程进程当前的寄存器值
 * @return 在ARM处理器下返回r0寄存器值
 */
long ptrace_getret(struct pt_regs *regs) {
#if defined(__i386__) || defined(__x86_64__) // 模拟器&x86_64
    return regs->eax;
#elif defined(__arm__) || defined(__aarch64__) // 真机
    return regs->ARM_r0;
#else
    printf("Not supported Environment %s\n", __FUNCTION__);
#endif
}

/**
 * @brief 获取当前执行代码的地址 ARM处理器下存放在ARM_pc中
 * @param regs regs存储远程进程当前的寄存器值
 * @return 在ARM处理器下返回pc寄存器值
 */
long ptrace_getpc(struct pt_regs *regs) {
#if defined(__i386__) || defined(__x86_64__)
    return regs->eip;
#elif defined(__arm__) || defined(__aarch64__)
    return regs->ARM_pc;
#else
    printf("Not supported Environment %s\n", __FUNCTION__);
#endif
}
    
// int ptrace_call_wrapper(pid_t target_pid, const char * func_name, void * func_addr, long * parameters, int param_num, struct pt_regs * regs)     
// {    
//     DEBUG_PRINT("[+] Calling %s in target process.\n", func_name); 
//     DEBUG_PRINT("func_addr %llx, parameters %d, param_num %d", func_addr,parameters,param_num);
      
//     if (ptrace_call(target_pid, (uintptr_t)func_addr, parameters, param_num, regs) == -1)
//         //DEBUG_PRINT("RET1");    
//         return -1;    
    
//     if (ptrace_getregs(target_pid, regs) == -1)
//         //DEBUG_PRINT("RET2");    
//         return -1;    
//     DEBUG_PRINT("[+] Target process returned from %s, return value=%llx, pc=%llx \n",     
//             func_name, ptrace_retval(regs), ptrace_ip(regs));    
//     return 0;    
// }

/**
 * @brief 通过maps获取模块基址
 *
 * @param pid pid表示远程进程的ID
 * @param moduleName moduleName为远程加载的模块名
 * @return 返回模块基址
 */
// void *getModuleBaseAddr(pid_t pid,const char*moduleName){
//     if(pid==-1)pid=getpid();
//     // 通过解析/proc/pid/maps 获得基址
//     char filepath[MAX_PATH];
//     void*moduleBaseAddr=NULL;
//     snprintf(filepath,MAX_PATH,"/proc/%d/maps",pid);
//     FILE *f = fopen(filepath,"r");
//     char line[MAX_PATH];
//     char base[MAX_PATH],name[MAX_PATH];
//     size_t cnt,start;
//     while(!feof(f)){
//         memset(line,0,MAX_PATH);
//         memset(name,0,MAX_PATH);
//         fgets(line,MAX_PATH,f);
//         cnt=0;
//         while(line[cnt]!='/')cnt++;
//         start=cnt;
//         while(line[cnt]){
//             name[cnt-start]=line[cnt];
//             cnt++;
//         }
//         name[cnt-start-1]=0;

//         if(strncmp(name,moduleName,MAX_PATH))continue;
//         memset(base,0,MAX_PATH);
//         cnt=0;
//         while(line[cnt]!='-'){
//             base[cnt]=line[cnt];
//             cnt++;
//         }
//         base[cnt]=0;
//         sscanf(base,"%llx",(long long*)(&moduleBaseAddr));
//         printf("[INJECT] GotBaseAddr %p of %s\n",moduleBaseAddr,moduleName);
//         break;
//     }
//     fclose(f);
//     return moduleBaseAddr;
// }   
    
/**
 * @brief 通过远程直接调用dlopen/dlsym的方法ptrace注入so模块到远程进程中
 *
 * @param pid pid表示远程进程的ID
 * @param LibPath LibPath为被远程注入的so模块路径
 * @param NeedLibPath NeedLibPath为被远程注入的so模块依赖的模块路径
 * @param FunctionName FunctionName为远程注入的模块后调用的函数
 * @param parameter FuncParameter指向被远程调用函数的参数（若传递字符串，需要先将字符串写入到远程进程空间中）
 * @param NumParameter NumParameter为参数的个数
 * @return int 返回0表示注入成功，返回-1表示失败
 */
int inject_remote_process(pid_t pid, char *LibPath, char *NeedLibPath, char *FunctionName){
    int iRet = -1;
    long parameters[6];
    long parameters1[6];
    // attach到目标进程
    if (ptrace_attach(pid) != 0){
        return iRet;
    }

    /**
     * @brief 开始主要步骤
     */
    do{
        // CurrentRegs 当前寄存器
        // OriginalRegs 保存注入前寄存器
        struct pt_regs CurrentRegs, OriginalRegs;
        if (ptrace_getregs(pid, &CurrentRegs) != 0){
            break;
        }
        // 保存原始寄存器
        memcpy(&OriginalRegs, &CurrentRegs, sizeof(CurrentRegs));

        // 获取mmap函数在远程进程中的地址 以便为libxxx.so分配内存
        // 由于mmap函数在libc.so库中 为了将libxxx.so加载到目标进程中 就需要使用目标进程的mmap函数 所以需要查找到libc.so库在目标进程的起始地址
        void *mmap_addr = get_mmap_address(pid);
        printf("[+] mmap RemoteFuncAddr:0x%lx\n", (uintptr_t)mmap_addr);

        // mmap映射 <-- 设置mmap的参数
        // void *mmap(void *start, size_t length, int prot, int flags, int fd, off_t offsize);
        parameters[0] = 0; // 设置为NULL表示让系统自动选择分配内存的地址
        parameters[1] = 0x3000; // 映射内存的大小
        parameters[2] = PROT_READ | PROT_WRITE | PROT_EXEC; // 表示映射内存区域 可读|可写|可执行
        parameters[3] = MAP_ANONYMOUS | MAP_PRIVATE; // 建立匿名映射
        parameters[4] = 0; //  若需要映射文件到内存中，则为文件的fd
        parameters[5] = 0; //文件映射偏移量

        parameters1[0] = 0; // 设置为NULL表示让系统自动选择分配内存的地址
        parameters1[1] = 0x3000; // 映射内存的大小
        parameters1[2] = PROT_READ | PROT_WRITE | PROT_EXEC; // 表示映射内存区域 可读|可写|可执行
        parameters1[3] = MAP_ANONYMOUS | MAP_PRIVATE; // 建立匿名映射
        parameters1[4] = 0; //  若需要映射文件到内存中，则为文件的fd
        parameters1[5] = 0; //文件映射偏移量

        // 调用远程进程的mmap函数 建立远程进程的内存映射 在目标进程中为libxxx.so分配内存
        if (ptrace_call(pid, (uintptr_t)mmap_addr, parameters, 6, &CurrentRegs) == -1){
            printf("[-] Call Remote mmap Func Failed, err:%s\n", strerror(errno));
            break;
        }

        if (ptrace_call(pid, (uintptr_t)mmap_addr, parameters1, 6, &CurrentRegs) == -1){
            printf("[-] Call Remote mmap Func Failed, err:%s\n", strerror(errno));
            break;
        }

        // 打印一下
        printf("[+] ptrace_call mmap success, return value=%lX, pc=%lX\n", ptrace_getret(&CurrentRegs), ptrace_getpc(&CurrentRegs));

        // 获取mmap函数执行后的返回值，也就是内存映射的起始地址
        // 从寄存器中获取mmap函数的返回值 即申请的内存首地址
        void *RemoteMapMemoryAddr = (void *)ptrace_getret(&CurrentRegs);
        printf("[+] Remote Process Map Memory Addr:0x%lx\n", (uintptr_t)RemoteMapMemoryAddr);

        // 分别获取dlopen、dlsym、dlclose等函数的地址
        void *dlopen_addr, *dlsym_addr, *dlclose_addr, *dlerror_addr;
        dlopen_addr = get_dlopen_address(pid);
        dlsym_addr = get_dlsym_address(pid);
        dlclose_addr = get_dlclose_address(pid);
        dlerror_addr = get_dlerror_address(pid);

        // 打印一下
        printf("[+] Get imports: dlopen: %x, dlsym: %x, dlclose: %x, dlerror: %x\n", dlopen_addr, dlsym_addr, dlclose_addr, dlerror_addr);

        // 打印注入so的路径
        printf("[+] LibPath = %s\n", LibPath);
        printf("[+] NeedLibPath = %s\n", NeedLibPath);

        // 将依赖的so库路径写入到远程进程内存空间中
        /**
         * pid  开始写入数据的地址   写入内容    写入数据大小
         */
        if (ptrace_writedata(pid, (uint8_t *) RemoteMapMemoryAddr, (uint8_t *) NeedLibPath,strlen(NeedLibPath) + 1) == -1) {
            printf("[-] Write NeedLibPath:%s to RemoteProcess error\n", NeedLibPath);
            break;
        }

        // 将要加载的so库路径写入到远程进程内存空间中
        /**
         * pid  开始写入数据的地址   写入内容    写入数据大小
         */
        if (ptrace_writedata(pid, (uint8_t *) RemoteMapMemoryAddr + 1000, (uint8_t *) LibPath,strlen(LibPath) + 1) == -1) {
            printf("[-] Write LibPath:%s to RemoteProcess error\n", LibPath);
            break;
        }

        // 设置dlopen的参数,返回值为模块加载的地址
        // void *dlopen(const char *filename, int flag);
        parameters1[0] = (uintptr_t) RemoteMapMemoryAddr; // 写入的NeedLibPath
        parameters1[1] = RTLD_NOW | RTLD_GLOBAL; // dlopen的标识
        parameters[0] = (uintptr_t) RemoteMapMemoryAddr + 1000; // 写入的libPath
        parameters[1] = RTLD_NOW | RTLD_GLOBAL; // dlopen的标识

        // 执行dlopen 载入so
        if (ptrace_call(pid, (uintptr_t) dlopen_addr, parameters1, 2, &CurrentRegs) == -1) {
            printf("[+] Call Remote dlopen Func Failed\n");
            break;
        }
        if (ptrace_call(pid, (uintptr_t) dlopen_addr, parameters, 2, &CurrentRegs) == -1) {
            printf("[+] Call Remote dlopen Func Failed\n");
            break;
        }

        // RemoteModuleAddr为远程进程加载注入模块的地址
        void *RemoteModuleAddr = (void *) ptrace_getret(&CurrentRegs);
        // void *RemoteModuleAddr = getModuleBaseAddr(pid,LibPath);
        printf("[+] ptrace_call dlopen success, Remote Process load module Addr:0x%lx\n",(long) RemoteModuleAddr);

        // dlopen 错误
        if ((long) RemoteModuleAddr == 0x0){
            printf("[-] dlopen error\n");
            if (ptrace_call(pid, (uintptr_t) dlerror_addr, parameters, 0, &CurrentRegs) == -1) {
                printf("[-] Call Remote dlerror Func Failed\n");
                break;
            }
            char *Error = (char *) ptrace_getret(&CurrentRegs);
            char LocalErrorInfo[1024] = {0};
            ptrace_readdata(pid, (uint8_t *) Error, (uint8_t *) LocalErrorInfo, 1024);
            printf("[-] dlopen error:%s\n", LocalErrorInfo);
            break;
        }

        // 判断是否传入symbols
        if (strcmp(FunctionName,"symbols") != 0){
            printf("[+] func symbols is %s\n", FunctionName);
            // 传入了函数的symbols
            printf("[+] Have func !!\n");
            // 将so库中需要调用的函数名称写入到远程进程内存空间中
            if (ptrace_writedata(pid, (uint8_t *) RemoteMapMemoryAddr + strlen(LibPath) + 2,(uint8_t *) FunctionName, strlen(FunctionName) + 1) == -1) {
                printf("[-] Write FunctionName:%s to RemoteProcess error\n", FunctionName);
                break;
            }

            // 设置dlsym的参数，返回值为远程进程内函数的地址 调用XXX功能
            // void *dlsym(void *handle, const char *symbol);
            parameters[0] = (uintptr_t) RemoteModuleAddr;
            printf("[+] RemoteModuleAddr: 0x%lx\n", (uintptr_t) RemoteModuleAddr);
            parameters[1] = (uintptr_t) ((uint8_t *) RemoteMapMemoryAddr + strlen(LibPath) + 2);
            //调用dlsym
            if (ptrace_call(pid, (uintptr_t) dlsym_addr, parameters, 2, &CurrentRegs) == -1) {
                printf("[-] Call Remote dlsym Func Failed\n");
                break;
            }

            // RemoteModuleFuncAddr为远程进程空间内获取的函数地址
            // void *localModuleAddr = getModuleBaseAddr(-1,LibPath);
            void *RemoteModuleFuncAddr = (void *) ptrace_getret(&CurrentRegs);
            printf("[+] ptrace_call dlsym success, Remote Process ModuleFunc Addr:0x%lx\n",(uintptr_t) RemoteModuleFuncAddr);

            // 调用远程进程到某功能 不支持参数传递 ！！
            if (ptrace_call(pid, (uintptr_t) RemoteModuleFuncAddr, parameters, 0,&CurrentRegs) == -1) {
                printf("[-] Call Remote injected Func Failed\n");
                break;
            }
        } else {
            // 没有传入函数的symbols
            printf("[+] No func !!\n");
        }

        if (ptrace_setregs(pid, &OriginalRegs) == -1) {
            printf("[-] Recover reges failed\n");
            break;
        }

        printf("[+] Recover Regs Success\n");

        ptrace_getregs(pid, &CurrentRegs);
        if (memcmp(&OriginalRegs, &CurrentRegs, sizeof(CurrentRegs)) != 0) {
            printf("[-] Set Regs Error\n");
        }
        iRet = 0;
    } while (false);
    
    // 解除attach
    ptrace_detach(pid);

    // 如果原SELinux状态为严格 则恢复状态
    // if (strcmp(FlagSELinux,"Enforcing") == 0){
    //     if (set_selinux_state(1)){
    //         printf("[+] SELinux has been rec\n");
    //     }
    // }

    return iRet;
}    
    


int main(int argc, char** argv) {
    pid_t target_pid;
    target_pid = find_pid_of("com.irgltjnmt.jlpom");
    if (-1 == target_pid) {
        printf("Can't find the process\n");
        return -1;
    }
    //target_pid = find_pid_of("/data/test");
    if(inject_remote_process(target_pid, argv[1], argv[2], argv[3]) == 0) {
        printf("[+] Finish Inject\n");
    } else {
        printf("[-] Inject Erro\n");
    }
    return 0;
}
