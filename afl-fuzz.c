/*
  Copyright 2013 Google LLC All rights reserved.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

/*
   american fuzzy lop - fuzzer code
   --------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   This is the real deal: the program takes an instrumented binary and
   attempts a variety of basic fuzzing tricks, paying close attention to
   how they affect the execution path.

*/

#define AFL_MAIN
#include "android-ashmem.h"   //安卓系统
#define MESSAGES_TO_STDOUT   //消息打印到标准输出

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#define _FILE_OFFSET_BITS 64

#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"
#include "hash.h"   //哈希计算

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <ctype.h>
#include <fcntl.h>
#include <termios.h>
#include <dlfcn.h>
#include <sched.h>

#include <sys/wait.h>
#include <sys/time.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/file.h>

#if defined(__APPLE__) || defined(__FreeBSD__) || defined (__OpenBSD__)
#  include <sys/sysctl.h>  //特殊系统包含额外的库
#endif /* __APPLE__ || __FreeBSD__ || __OpenBSD__ */

/* For systems that have sched_setaffinity; right now just Linux, but one
   can hope... */

//Linux中用于设置线程CPU亲和性的系统调用。线程的CP 亲和性定义了一个线程可以在哪些CPU上运行
#ifdef __linux__
#  define HAVE_AFFINITY 1   
#endif /* __linux__ */

/* A toggle to export some variables when building as a library. Not very
   useful for the general public. */

//构建为库文件时，导出部分变量
#ifdef AFL_LIB
#  define EXP_ST
#else
#  define EXP_ST static
#endif /* ^AFL_LIB */

/* Lots of globals, but mostly for the status UI and other things where it
   really makes no sense to haul them around as function parameters. */


EXP_ST u8 *in_dir,                    /* Input directory with test cases  */
          *out_file,                  /* File to fuzz, if any             */
          *out_dir,                   /* Working & output directory       */
          *sync_dir,                  /* Synchronization directory        */    //同步目录，实际为输出目录（主从模式下的真实输出目录为实际输出目录下的以当前sync_id命令的文件夹）
          *sync_id,                   /* Fuzzer ID                        */
          *use_banner,                /* Display banner                   */
          *in_bitmap,                 /* Input bitmap                     */
          *doc_path,                  /* Path to documentation dir        */
          *target_path,               /* Path to target binary            */      //被测试程序的路径
          *orig_cmdline;              /* Original command line            */

EXP_ST u32 exec_tmout = EXEC_TIMEOUT; /* Configurable exec timeout (ms)   */
static u32 hang_tmout = EXEC_TIMEOUT; /* Timeout used for hang det (ms)   */

EXP_ST u64 mem_limit  = MEM_LIMIT;    /* Memory cap for child (MB)        */

EXP_ST u32 cpu_to_bind = 0;           /* id of free CPU core to bind      */

static u32 stats_update_freq = 1;     /* Stats update frequency (execs)   */    //统计数据更新频率 

EXP_ST u8  skip_deterministic,        /* Skip deterministic stages?       */
           force_deterministic,       /* Force deterministic stages?      */
           use_splicing,              /* Recombine input files?           */    //建议拼接输入文件
                                                                                // -d参数、-S模式和执行完一轮变异未发现新的测试用例会将该值设置为1
           dumb_mode,                 /* Run in non-instrumented mode?    */
           score_changed,             /* Scoring for favorites changed?   */    //针对共享内存每个字节的最优测试用例发送改变
           kill_signal,               /* Signal that killed the child     */
           resuming_fuzz,             /* Resuming an older fuzzing job?   */  //pivot_inputs函数，移动输入目录中的测试用例到queue文件时，
                                                                              //发现了测试用例名为ID:x格式
                                                                              //用于恢复上次工作任务 1为恢复任务
           timeout_given,             /* Specific timeout given?          */
                                          //值为3表示，表示恢复工作时从fuzzer_stats文件中加载 find_timeout()
           cpu_to_bind_given,         /* Specified cpu_to_bind given?     */
           not_on_tty,                /* stdout is not a tty              */
           term_too_small,            /* terminal dimensions too small    */    //终端尺寸太小
           uses_asan,                 /* Target uses ASAN?                */
           no_forkserver,             /* Disable forkserver?              */
           crash_mode,                /* Crash mode! Yeah!                */
           in_place_resume,           /* Attempt in-place resume?         */    //恢复上次任务
           auto_changed,              /* Auto-generated tokens changed?   */    //？？？
           no_cpu_meter_red,          /* Feng shui on the status screen   */
           no_arith,                  /* Skip most arithmetic ops         */  //跳过算术变异
           shuffle_queue,             /* Shuffle input queue?             */  //打乱测试样本顺序
           bitmap_changed = 1,        /* Time to update bitmap?           */  //该值为1，表示位图没有发生改变
           qemu_mode,                 /* Running in QEMU mode?            */
           skip_requested,            /* Skip request, via SIGUSR1        */    //使用SIGUSR1信号，表示跳过本次测试用例
           run_over10m,               /* Run time over 10 minutes?        */    //程序运行超过10分钟
           persistent_mode,           /* Running in persistent mode?      */
           deferred_mode,             /* Deferred forkserver mode?        */
           fast_cal;                  /* Try to calibrate faster?         */

static s32 out_fd,                    /* Persistent fd for out_file       */
           dev_urandom_fd = -1,       /* Persistent fd for /dev/urandom   */
           dev_null_fd = -1,          /* Persistent fd for /dev/null      */
           fsrv_ctl_fd,               /* Fork server control pipe (write) */
           fsrv_st_fd;                /* Fork server status pipe (read)   */

static s32 forksrv_pid,               /* PID of the fork server           */
           child_pid = -1,            /* PID of the fuzzed program        */
           out_dir_fd = -1;           /* FD of the lock file              */

EXP_ST u8* trace_bits;                /* SHM with instrumentation bitmap  */  //插桩代码修改的共享内存 ；当前的路径信息

EXP_ST u8  virgin_bits[MAP_SIZE],     /* Regions yet untouched by fuzzing */    //标识尚未被触发的路径，以及路径尚未被被触发次数（涉及数据规整）
                                      //尚未受到模糊测试影响的区域；之前的路径信息    未指定-B参数，设置virgin_bits数组值为0xff
           virgin_tmout[MAP_SIZE],    /* Bits we haven't seen in tmouts   */    //标识发生执行超时时，未被触发的路径
           virgin_crash[MAP_SIZE];    /* Bits we haven't seen in crashes  */    //标识发生crash时，未被触发的路径

static u8  var_bytes[MAP_SIZE];       /* Bytes that appear to be variable */

static s32 shm_id;                    /* ID of the SHM region             */

static volatile u8 stop_soon,         /* Ctrl-C pressed?                  */      //Ctrl-C信号将该值置为1；show_stats会根据条件置2
                   clear_screen = 1,  /* Window resized?                  */
                   child_timed_out;   /* Traced process timed out?        */    //跟踪进程超时？

EXP_ST u32 queued_paths,              /* Total number of queued testcases */  //排队测试用例总数
           queued_variable,           /* Testcases with variable behavior */
           queued_at_start,           /* Total number of initial inputs   */
           queued_discovered,         /* Items discovered during this run */    //本次运行期间发现的新的测试用例数量
           queued_imported,           /* Items imported via -S            */    //导入测试用例数量
           queued_favored,            /* Paths deemed favorable           */    //被视为有利的路径
           queued_with_cov,           /* Paths with new coverage bytes    */    //具有新覆盖字节的路径
           pending_not_fuzzed,        /* Queued but not done yet          */    //已排队但尚未完成的测试用例数量
           pending_favored,           /* Pending favored paths            */    //待定fuzz的受青睐用例数量
           cur_skipped_paths,         /* Abandoned inputs in cur cycle    */    //当前周期中放弃的输入？？？
           cur_depth,                 /* Current path depth               */
           max_depth,                 /* Max path depth                   */    //测试用例的数量
           useless_at_start,          /* Number of useless starting paths */    //没有路径的测试用例数量
           var_byte_count,            /* Bitmap bytes with var behavior   */ //具有 var 行为的位图字节
                                                                              //过程中发生变化的字节数
           current_entry,             /* Current queue entry ID           */    //当前的测试用例ID，0起始
           havoc_div = 1;             /* Cycle count divisor for havoc    */    //造成严重破坏的周期计数除数

EXP_ST u64 total_crashes,             /* Total number of crashes          */    //崩溃总数
           unique_crashes,            /* Crashes with unique signatures   */    //具有独特签名的崩溃数量
           total_tmouts,              /* Total number of timeouts         */
           unique_tmouts,             /* Timeouts with unique signatures  */
           unique_hangs,              /* Hangs with unique signatures     */    
           total_execs,               /* Total execve() calls             */    //被测试用例程序执行的次数
           slowest_exec_ms,           /* Slowest testcase non hang in ms  */
           start_time,                /* Unix start time (ms)             */
           last_path_time,            /* Time for most recent path (ms)   */
           last_crash_time,           /* Time for most recent crash (ms)  */
           last_hang_time,            /* Time for most recent hang (ms)   */
           last_crash_execs,          /* Exec counter at last crash       */    //最后一次发现crash时总的测试时间
           queue_cycle,               /* Queue round counter              */    //测试队列的循环次数
           cycles_wo_finds,           /* Cycles without any new paths     */    //没有任何新路径的循环
           trim_execs,                /* Execs done to trim input files   */    //测试裁剪后的测试用例的数量
           bytes_trim_in,             /* Bytes coming into the trimmer    */    //进入修剪器的字节数
           bytes_trim_out,            /* Bytes coming outa the trimmer    */
           blocks_eff_total,          /* Blocks subject to effector maps  */    //效应器图处理过的块数量
           blocks_eff_select;         /* Blocks selected as fuzzable      */    //效应器图发现对路径有影响的块数量

static u32 subseq_tmouts;             /* Number of timeouts in a row      */    //连续超时次数

static u8 *stage_name = "init",       /* Name of the current fuzz stage   */    //命令行显示的阶段名称
          *stage_short,               /* Short stage name                 */    //命令行显示的阶段短名称
          *syncing_party;             /* Currently syncing with...        */

static s32 stage_cur, stage_max;      /* Stage progression                */    //阶段进展
static s32 splicing_with = -1;        /* Splicing with which test case?   */

static u32 master_id, master_max;     /* Master instance job splitting    */

static u32 syncing_case;              /* Syncing with case #...           */

static s32 stage_cur_byte,            /* Byte offset of current stage op  */  //当前阶段操作的字节偏移量
           stage_cur_val;             /* Value used for stage op          */    //当前阶段使用的值

static u8  stage_val_type;            /* Value type (STAGE_VAL_*)         */    //阶段值类型

static u64 stage_finds[32],           /* Patterns found per fuzz stage    */    //每个模糊阶段发现的样本
           stage_cycles[32];          /* Execs per fuzz stage             */    //Execs per fuzz stage 

static u32 rand_cnt;                  /* Random number counter            */

static u64 total_cal_us,              /* Total calibration time (us)      */    //统计总的校准程序运行时间
           total_cal_cycles;          /* Total calibration cycles         */    //统计总的校准样本执行次数

static u64 total_bitmap_size,         /* Total bit count for all bitmaps  */    //所有位图的总位数
           total_bitmap_entries;      /* Number of bitmaps counted        */    //统计的位图数量

static s32 cpu_core_count;            /* CPU core count                   */

#ifdef HAVE_AFFINITY

static s32 cpu_aff = -1;       	      /* Selected CPU core                */

#endif /* HAVE_AFFINITY */

static FILE* plot_file;               /* Gnuplot output file              */

struct queue_entry {

  u8* fname;                          /* File name for the test case      */
  u32 len;                            /* Input length                     */

  u8  cal_failed,                     /* Calibration failed?              */
      trim_done,                      /* Trimmed?                         */
      was_fuzzed,                     /* Had any fuzzing done yet?        */    //已经完成了确定性变异测试
      passed_det,                     /* Deterministic stages passed?     */
      has_new_cov,                    /* Triggers new coverage?           */
      var_behavior,                   /* Variable behavior?               */
      favored,                        /* Currently favored?               */
      fs_redundant;                   /* Marked as redundant in the fs?   */

  u32 bitmap_size,                    /* Number of bits set in bitmap     */    //统计共享内存中不为0的字节数量，发现的路径数量？？
      exec_cksum;                     /* Checksum of the execution trace  */

  u64 exec_us,                        /* Execution time (us)              */    //测试用例校准时的平均运行时间
      handicap,                       /* Number of queue cycles behind    */    //测试用例在哪轮队列循环中被处理，越受到青睐，越会优先处理
      depth;                          /* Path depth                       */

  u8* trace_mini;                     /* Trace bytes, if kept             */    //测试用例执行后的共享内存压缩，每个bit表示一个字节是否有值
  u32 tc_ref;                         /* Trace bytes ref count            */

  struct queue_entry *next,           /* Next element, if any             */
                     *next_100;       /* 100 elements ahead               */

};

static struct queue_entry *queue,     /* Fuzzing queue (linked list)      */
                          *queue_cur, /* Current offset within the queue  */    //当前fuzz的测试用例
                          *queue_top, /* Top of the list                  */
                          *q_prev100; /* Previous 100 marker              */

static struct queue_entry*
  top_rated[MAP_SIZE];                /* Top entries for bitmap bytes     */    //共享内存每个字节的最优测试用例

struct extra_data {
  u8* data;                           /* Dictionary token data            */
  u32 len;                            /* Dictionary token length          */
  u32 hit_cnt;                        /* Use count in the corpus          */
};

static struct extra_data* extras;     /* Extra tokens to fuzz with        */
static u32 extras_cnt;                /* Total number of tokens read      */    //从文件中加载的字典条目数量

static struct extra_data* a_extras;   /* Automatically selected extras    */    //程序发现的字典列表
static u32 a_extras_cnt;              /* Total number of tokens available */     //1bit翻转阶段发现的字典条目数量

static u8* (*post_handler)(u8* buf, u32* len);    //后处理函数，用于处理测试结束后的工作

/* Interesting values, as per config.h */

static s8  interesting_8[]  = { INTERESTING_8 };
static s16 interesting_16[] = { INTERESTING_8, INTERESTING_16 };
static s32 interesting_32[] = { INTERESTING_8, INTERESTING_16, INTERESTING_32 };

/* Fuzzing stages */

enum {
  /* 00 */ STAGE_FLIP1,
  /* 01 */ STAGE_FLIP2,
  /* 02 */ STAGE_FLIP4,
  /* 03 */ STAGE_FLIP8,
  /* 04 */ STAGE_FLIP16,
  /* 05 */ STAGE_FLIP32,
  /* 06 */ STAGE_ARITH8,
  /* 07 */ STAGE_ARITH16,
  /* 08 */ STAGE_ARITH32,
  /* 09 */ STAGE_INTEREST8,
  /* 10 */ STAGE_INTEREST16,
  /* 11 */ STAGE_INTEREST32,
  /* 12 */ STAGE_EXTRAS_UO,
  /* 13 */ STAGE_EXTRAS_UI,
  /* 14 */ STAGE_EXTRAS_AO,
  /* 15 */ STAGE_HAVOC,
  /* 16 */ STAGE_SPLICE
};

/* Stage value types */

enum {
  /* 00 */ STAGE_VAL_NONE,
  /* 01 */ STAGE_VAL_LE,
  /* 02 */ STAGE_VAL_BE
};

/* Execution status fault codes */

enum {
  /* 00 */ FAULT_NONE,
  /* 01 */ FAULT_TMOUT,
  /* 02 */ FAULT_CRASH,
  /* 03 */ FAULT_ERROR,
  /* 04 */ FAULT_NOINST,
  /* 05 */ FAULT_NOBITS
};


/* Get unix time in milliseconds */

//获取当前系统时间 - 毫秒
static u64 get_cur_time(void) {

  struct timeval tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000ULL) + (tv.tv_usec / 1000);

}


/* Get unix time in microseconds */

//获取当前系统时间 - 微秒
static u64 get_cur_time_us(void) {

  struct timeval tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000000ULL) + tv.tv_usec;

}


/* Generate a random number (from 0 to limit - 1). This may
   have slight bias. */

//生成指定范围内的随机数
static inline u32 UR(u32 limit) {

  //检测随机数种子设置次数，为0则重新设置，否则次数-1
  if (unlikely(!rand_cnt--)) {

    u32 seed[2];

    //从/dev/urandom读取随机数
    ck_read(dev_urandom_fd, &seed, sizeof(seed), "/dev/urandom");

    //设置种子
    srandom(seed[0]);
    //计算重新设置随机数种子的次数，避免伪随机
    rand_cnt = (RESEED_RNG / 2) + (seed[1] % RESEED_RNG);

  }

  return random() % limit;

}


/* Shuffle an array of pointers. Might be slightly biased. */

//依靠随机数，打乱指针数组顺序；随机数的规律性，可能不是彻底的随机
static void shuffle_ptrs(void** ptrs, u32 cnt) {

  u32 i;

  for (i = 0; i < cnt - 2; i++) {

    u32 j = i + UR(cnt - i);
    void *s = ptrs[i];
    ptrs[i] = ptrs[j];
    ptrs[j] = s;

  }

}


// cpu亲和性
// 建立绑定到特性内核的进程列表
#ifdef HAVE_AFFINITY

/* Build a list of processes bound to specific cores. Returns -1 if nothing
   can be found. Assumes an upper bound of 4k CPUs. */

static void bind_to_free_cpu(void) {

  DIR* d;
  struct dirent* de;
  cpu_set_t c;

  u8 cpu_used[4096] = { 0 };  //使用的cpu内核
  u32 i;

  //一个内核，不进行处理
  if (cpu_core_count < 2) return;

  //环境变量指定不绑定到cpu内核
  if (getenv("AFL_NO_AFFINITY")) {

    WARNF("Not binding to a CPU core (AFL_NO_AFFINITY set).");
    return;

  }

  //打开进程目录  /proc是一个虚拟文件系统，提供了对系统内核和进程信息的访问
  d = opendir("/proc");

  //打开目录失败
  if (!d) {

    WARNF("Unable to access /proc - can't scan for free CPU cores.");
    return;

  }

  //提示信息
  ACTF("Checking CPU core loadout...");

  /* Introduce some jitter, in case multiple AFL tasks are doing the same
     thing at the same time... */

  //避免多个AFL同时执行相同操作
  usleep(R(1000) * 250);

  /* Scan all /proc/<pid>/status entries, checking for Cpus_allowed_list.
     Flag all processes bound to a specific CPU using cpu_used[]. This will
     fail for some exotic binding setups, but is likely good enough in almost
     all real-world use cases. */

  //遍历/proc下的文件
  while ((de = readdir(d))) {

    u8* fn;
    FILE* f;
    u8 tmp[MAX_LINE];
    u8 has_vmsize = 0;

    //只处理数字文件，即进程id
    if (!isdigit(de->d_name[0])) continue;

    //拼接进程状态路径
    fn = alloc_printf("/proc/%s/status", de->d_name);

    //打开状态文件
    if (!(f = fopen(fn, "r"))) {
      ck_free(fn);
      continue; //打开失败，遍历下一个文件
    }

    //遍历状态文件行
    while (fgets(tmp, MAX_LINE, f)) {

      u32 hval;

      /* Processes without VmSize are probably kernel tasks. */

      //检测VmSize行，没有可能是内核任务
      if (!strncmp(tmp, "VmSize:\t", 8)) has_vmsize = 1;


      //如果找到 Cpus_allowed_list 行，且该行不包含横杠 - 和逗号 ,，则解析 Cpus_allowed_list 的值，并将相应的 cpu_used 数组元素置为1
      if (!strncmp(tmp, "Cpus_allowed_list:\t", 19) &&
          !strchr(tmp, '-') && !strchr(tmp, ',') &&
          sscanf(tmp + 19, "%u", &hval) == 1 && hval < sizeof(cpu_used) &&
          has_vmsize) {


        //通过这样的扫描，代码可以获取到系统中每个进程使用的 CPU 内核号，并将相关信息存储在 cpu_used 数组中。
        //这有助于后续的亲和性设置，确保 AFL 在运行时能够绑定到尽可能空闲的 CPU 核心上。
        cpu_used[hval] = 1;
        break;

      }

    }

    ck_free(fn);
    fclose(f);

  }
  //关闭目录
  closedir(d);

 
  if (cpu_to_bind_given) {
    //命令行参数指定绑定cpu内核
    
    //检测指定内核是否可用
    if (cpu_to_bind >= cpu_core_count)
      FATAL("The CPU core id to bind should be between 0 and %u", cpu_core_count - 1);
    
    if (cpu_used[cpu_to_bind])
      FATAL("The CPU core #%u to bind is not free!", cpu_to_bind);

    i = cpu_to_bind;
    
  } else {
    //宏定义绑定cpu内核，检测空闲内核
    for (i = 0; i < cpu_core_count; i++) if (!cpu_used[i]) break;
    
  }

  //检测即将绑定的内核是否可用
  if (i == cpu_core_count) {

    SAYF("\n" cLRD "[-] " cRST
         "Uh-oh, looks like all %u CPU cores on your system are allocated to\n"
         "    other instances of afl-fuzz (or similar CPU-locked tasks). Starting\n"
         "    another fuzzer on this machine is probably a bad plan, but if you are\n"
         "    absolutely sure, you can set AFL_NO_AFFINITY and try again.\n",
         cpu_core_count);

    FATAL("No more free CPU cores");

  }

  OKF("Found a free CPU core, binding to #%u.", i);

  //指定选择的内核
  cpu_aff = i;
  
  //指定内核
  CPU_ZERO(&c);
  CPU_SET(i, &c);
  //设置当前进程亲和性
  if (sched_setaffinity(0, sizeof(c), &c))
    PFATAL("sched_setaffinity failed");

}

#endif /* HAVE_AFFINITY */

#ifndef IGNORE_FINDS

/* Helper function to compare buffers; returns first and last differing offset. We
   use this to find reasonable locations for splicing two files. 
   比较缓冲区的辅助函数； 返回第一个和最后一个不同的偏移量。 我们用它来找到拼接两个文件的合理位置。 */

static void locate_diffs(u8* ptr1, u8* ptr2, u32 len, s32* first, s32* last) {

  s32 f_loc = -1;
  s32 l_loc = -1;
  u32 pos;

  //遍历文件
  for (pos = 0; pos < len; pos++) {

    //当作指针数据是否不同
    if (*(ptr1++) != *(ptr2++)) {
      
      //如果第一个不同数据的偏移量未设置，则设置
      if (f_loc == -1) f_loc = pos;
      //每次都设置最后一个不同的偏移量
      l_loc = pos;

    }

  }

  //写出
  *first = f_loc;
  *last = l_loc;

  return;

}

#endif /* !IGNORE_FINDS */


/* Describe integer. Uses 12 cyclic static buffers for return values. The value
   returned should be five characters or less for all the integers we reasonably
   expect to see. 
   描述整数。 使用12个循环静态缓冲区作为返回值。 对于我们合理期望看到的所有整数，返回的值应该是五个字符或更少。*/

//将整数转为便于人类阅读的形式；比如10000转换为10.0k，1000000转换为10M
static u8* DI(u64 val) {

  static u8 tmp[12][16];
  static u8 cur;   //初始化为0

  cur = (cur + 1) % 12;  //cur范围 0~11

#define CHK_FORMAT(_divisor, _limit_mult, _fmt, _cast) do { \
    /*检查值范围*/
    if (val < (_divisor) * (_limit_mult)) { \  
      /*将数值转为数值+符号的描述*/
      sprintf(tmp[cur], _fmt, ((_cast)val) / (_divisor)); \
      //返回简短描述
      return tmp[cur]; \
    } \
  } while (0)

  /* 0-9999 */
  CHK_FORMAT(1, 10000, "%llu", u64);

  /* 10.0k - 99.9k */
  CHK_FORMAT(1000, 99.95, "%0.01fk", double);

  /* 100k - 999k */
  CHK_FORMAT(1000, 1000, "%lluk", u64);

  /* 1.00M - 9.99M */
  CHK_FORMAT(1000 * 1000, 9.995, "%0.02fM", double);

  /* 10.0M - 99.9M */
  CHK_FORMAT(1000 * 1000, 99.95, "%0.01fM", double);

  /* 100M - 999M */
  CHK_FORMAT(1000 * 1000, 1000, "%lluM", u64);

  /* 1.00G - 9.99G */
  CHK_FORMAT(1000LL * 1000 * 1000, 9.995, "%0.02fG", double);

  /* 10.0G - 99.9G */
  CHK_FORMAT(1000LL * 1000 * 1000, 99.95, "%0.01fG", double);

  /* 100G - 999G */
  CHK_FORMAT(1000LL * 1000 * 1000, 1000, "%lluG", u64);

  /* 1.00T - 9.99G */
  CHK_FORMAT(1000LL * 1000 * 1000 * 1000, 9.995, "%0.02fT", double);

  /* 10.0T - 99.9T */
  CHK_FORMAT(1000LL * 1000 * 1000 * 1000, 99.95, "%0.01fT", double);

  //数值超过了以上范围，返回infty
  /* 100T+ */
  strcpy(tmp[cur], "infty");
  return tmp[cur];

}


/* Describe float. Similar to the above, except with a single 
   static buffer. */

//将浮点数转为便于人类阅读的形式
static u8* DF(double val) {

  static u8 tmp[16];

  if (val < 99.995) {
    sprintf(tmp, "%0.02f", val);
    return tmp;
  }

  if (val < 999.95) {
    sprintf(tmp, "%0.01f", val);
    return tmp;
  }

  //超过999.95，使用描述整数函数
  return DI((u64)val);

}


/* Describe integer as memory size. */

//将内存大小转为便于人类阅读的形式，转换比例是1024
static u8* DMS(u64 val) {

  static u8 tmp[12][16];
  static u8 cur;

  cur = (cur + 1) % 12;

  /* 0-9999 */
  CHK_FORMAT(1, 10000, "%llu B", u64);

  /* 10.0k - 99.9k */
  CHK_FORMAT(1024, 99.95, "%0.01f kB", double);

  /* 100k - 999k */
  CHK_FORMAT(1024, 1000, "%llu kB", u64);

  /* 1.00M - 9.99M */
  CHK_FORMAT(1024 * 1024, 9.995, "%0.02f MB", double);

  /* 10.0M - 99.9M */
  CHK_FORMAT(1024 * 1024, 99.95, "%0.01f MB", double);

  /* 100M - 999M */
  CHK_FORMAT(1024 * 1024, 1000, "%llu MB", u64);

  /* 1.00G - 9.99G */
  CHK_FORMAT(1024LL * 1024 * 1024, 9.995, "%0.02f GB", double);

  /* 10.0G - 99.9G */
  CHK_FORMAT(1024LL * 1024 * 1024, 99.95, "%0.01f GB", double);

  /* 100G - 999G */
  CHK_FORMAT(1024LL * 1024 * 1024, 1000, "%llu GB", u64);

  /* 1.00T - 9.99G */
  CHK_FORMAT(1024LL * 1024 * 1024 * 1024, 9.995, "%0.02f TB", double);

  /* 10.0T - 99.9T */
  CHK_FORMAT(1024LL * 1024 * 1024 * 1024, 99.95, "%0.01f TB", double);

#undef CHK_FORMAT

  /* 100T+ */
  strcpy(tmp[cur], "infty");
  return tmp[cur];

}


/* Describe time delta. Returns one static buffer, 34 chars of less. */

//将经过时间整数转为人类可读格式 天-时-分-秒
static u8* DTD(u64 cur_ms, u64 event_ms) {

  static u8 tmp[64];
  u64 delta;
  s32 t_d, t_h, t_m, t_s;

  if (!event_ms) return "none seen yet";

  delta = cur_ms - event_ms;  //计算经过的时间

  //计算时间
  t_d = delta / 1000 / 60 / 60 / 24;
  t_h = (delta / 1000 / 60 / 60) % 24;
  t_m = (delta / 1000 / 60) % 60;
  t_s = (delta / 1000) % 60;

  sprintf(tmp, "%s days, %u hrs, %u min, %u sec", DI(t_d), t_h, t_m, t_s);
  return tmp;

}


/* Mark deterministic checks as done for a particular queue entry. We use the
   .state file to avoid repeating deterministic fuzzing when resuming aborted
   scans.
   将确定性检查标记为对特定队列条目完成。 我们使用 .state 文件来避免在恢复中止的扫描时重复确定性模糊测试。 */

//创建状态标识文件，标识队列项已经完成了确定性变异
static void mark_as_det_done(struct queue_entry* q) {

  u8* fn = strrchr(q->fname, '/');
  s32 fd;

  //指定状态路径
  fn = alloc_printf("%s/queue/.state/deterministic_done/%s", out_dir, fn + 1);

  //创建文件，标识当前文件已经执行完了确定性变异
  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) PFATAL("Unable to create '%s'", fn);
  close(fd);

  ck_free(fn);

  q->passed_det = 1;  //标识确定性变异结束

}


/* Mark as variable. Create symlinks if possible to make it easier to examine
   the files.
   标记为变量。 如果可能的话，创建符号链接，以便更轻松地检查文件。 */

//标记为变量（目前推测该标识为进行变异）
static void mark_as_variable(struct queue_entry* q) {

  //获取文件名
  u8 *fn = strrchr(q->fname, '/') + 1, *ldest;

  //拼接符号链接原路径
  ldest = alloc_printf("../../%s", fn);
  //拼接符号链接目的路径
  fn = alloc_printf("%s/queue/.state/variable_behavior/%s", out_dir, fn);

  //将文件链接到variable_behavior目录下
  if (symlink(ldest, fn)) {
    
    //链接失败手动创建空文件，标识状态
    s32 fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) PFATAL("Unable to create '%s'", fn);
    close(fd);

  }

  ck_free(ldest);
  ck_free(fn);

  //变量行为
  q->var_behavior = 1;

}


/* Mark / unmark as redundant (edge-only). This is not used for restoring state,
   but may be useful for post-processing datasets. 标记/取消标记为冗余（仅限边缘）。 这不用于恢复状态，但可能对后处理数据集有用。 */

//标记为不太有用的测试用例
static void mark_as_redundant(struct queue_entry* q, u8 state) {

  u8* fn;
  s32 fd;

  //检测是否与之前状态一致
  if (state == q->fs_redundant) return;

  //设置新状态
  q->fs_redundant = state;

  //拼接路径名
  fn = strrchr(q->fname, '/');
  fn = alloc_printf("%s/queue/.state/redundant_edges/%s", out_dir, fn + 1);

  //检测设置状态或移除状态
  if (state) {
    
    //创建状态文件
    fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) PFATAL("Unable to create '%s'", fn);
    close(fd);

  } else {

    //移除状态文件
    if (unlink(fn)) PFATAL("Unable to remove '%s'", fn);

  }

  ck_free(fn);

}


/* Append new test case to the queue. */

//添加新的测试用例到队列
static void add_to_queue(u8* fname, u32 len, u8 passed_det) {

  //申请队列结构体
  struct queue_entry* q = ck_alloc(sizeof(struct queue_entry));

  q->fname        = fname; //文件名
  q->len          = len;    //文件大小
  q->depth        = cur_depth + 1;  //当前路径深度
  q->passed_det   = passed_det;   //为1时标识确定性变异结束，即不执行确定性变异

  //检测最大路径深度
  if (q->depth > max_depth) max_depth = q->depth;

  
  if (queue_top) {
    
    //已存在测试用例
    queue_top->next = q;  //上一个测试用例的链表指针指向当前测试用例
    queue_top = q;  //更新最新的测试用例

  } else q_prev100 = queue = queue_top = q;  //queue_top为0，则q_prev100 = queue = queue_top都为q

  queued_paths++;  //测试用例数量数量+1
  pending_not_fuzzed++;  //待使用的用例数量+1

  cycles_wo_finds = 0; // 没有新路径的循环？？？

  /* Set next_100 pointer for every 100th element (index 0, 100, etc) to allow faster iteration. */
  //链接每100个测试用例的节点，用于快速迭代
  if ((queued_paths - 1) % 100 == 0 && queued_paths > 1) {

    //更新每100个测试用例指针
    q_prev100->next_100 = q;   //上100个测试用例的链表指针指向当前测试用例
    q_prev100 = q;  //更新最新的100个测试用例指针

  }

  //设置最后一次测试用例的添加时间，表示发现新的路径
  last_path_time = get_cur_time();

}


/* Destroy the entire queue. */

//销毁队列
EXP_ST void destroy_queue(void) {

  struct queue_entry *q = queue, *n;

  //遍历队列
  while (q) {

    //保存下一项
    n = q->next;
    //释放当前项资源
    ck_free(q->fname);
    ck_free(q->trace_mini);
    ck_free(q);
    //指向下一项
    q = n;

  }

}


/* Write bitmap to file. The bitmap is useful mostly for the secret
   -B option, to focus a separate fuzzing session on a particular
   interesting input without rediscovering all the others. */
//将virgin_bits数组（位图）写入到fuzz_bitmap文件 ; 与-B选项有关
EXP_ST void write_bitmap(void) {

  u8* fname;
  s32 fd;

  //如果位图未改变，则不写入
  if (!bitmap_changed) return;    //bitmap_changed为1，则表示位图发生了变化


  //将改变标志置0，然后将当前位图写入文件
  //这样下次位图没有改变时，将不会重复写入到文件
  bitmap_changed = 0;

  fname = alloc_printf("%s/fuzz_bitmap", out_dir);
  fd = open(fname, O_WRONLY | O_CREAT | O_TRUNC, 0600);

  if (fd < 0) PFATAL("Unable to open '%s'", fname);

  ck_write(fd, virgin_bits, MAP_SIZE, fname);

  close(fd);
  ck_free(fname);

}


/* Read bitmap from file. This is for the -B option again. */
//从指定文件读取数据到virgin_bits数组（位图）  ; 与-B选项有关
EXP_ST void read_bitmap(u8* fname) {

  s32 fd = open(fname, O_RDONLY);

  if (fd < 0) PFATAL("Unable to open '%s'", fname);

  ck_read(fd, virgin_bits, MAP_SIZE, fname);

  close(fd);

}


/* Check if the current execution path brings anything new to the table.
   Update virgin bits to reflect the finds. Returns 1 if the only change is
   the hit-count for a particular tuple; 2 if there are new tuples seen. 
   Updates the map, so subsequent calls will always return 0.
  检查当前执行路径是否给表带来了任何新内容。 更新原始位以反映发现。 
  如果唯一的变化是特定元组的命中计数，则返回 1； 2 如果有新的元组出现。 更新地图，因此后续调用将始终返回 0。


   This function is called after every exec() on a fairly large buffer, so
   it needs to be fast. We do this in 32-bit and 64-bit flavors.
   这个函数是在相当大的缓冲区上的每个exec（）之后调用的，因此它需要很快。我们有32位和64位两种风格。 */

//检测是否存在新的路径（返回2），或某个路径存在新的状态（返回1），无新路径返回0
//检测路径信息是否存在差变化
static inline u8 has_new_bits(u8* virgin_map) {

//64位位图
#ifdef WORD_SIZE_64

  u64* current = (u64*)trace_bits;
  u64* virgin  = (u64*)virgin_map;

  u32  i = (MAP_SIZE >> 3); //32位下是8kb, 但单位是u64；即共享内存大小为8*8=64kb

#else

  //32位位图
  u32* current = (u32*)trace_bits;  //插桩代码修改的共享内存 
  u32* virgin  = (u32*)virgin_map;  //初始化时

  u32  i = (MAP_SIZE >> 2);  //32位下是16kb,但单位是u32；即共享内存大小为16*4=64kb

#endif /* ^WORD_SIZE_64 */

  u8   ret = 0;

  //遍历共享内存空间
  while (i--) {

    /* Optimize for (*current & *virgin) == 0 - i.e., no bits in current bitmap
       that have not been already cleared from the virgin map - since this will
       almost always be the case. 
       优化 (*current & *virgin) == 0 - 即当前位图中没有尚未从原始映射中清除的位 - 因为这种情况几乎总是如此。*/

    
    if (unlikely(*current) && unlikely(*current & *virgin)) {
      // (*current & *virgin) 且不等于0,说明某些位相同


      if (likely(ret < 2)) {
        //ret小于2进行检测

        u8* cur = (u8*)current; //局部变量赋值
        u8* vir = (u8*)virgin;  //局部变量赋值

        /* Looks like we have not found any new bytes yet; see if any non-zero
           bytes in current[] are pristine in virgin[].   看起来我们还没有找到任何新的字节； 查看 current[] 中的任何非零字节在 virgin[] 中是否是原始的。*/

#ifdef WORD_SIZE_64

        if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
            (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff) ||
            (cur[4] && vir[4] == 0xff) || (cur[5] && vir[5] == 0xff) ||
            (cur[6] && vir[6] == 0xff) || (cur[7] && vir[7] == 0xff)) ret = 2;
        else ret = 1;

#else

        //每次运行被测试程序处理完测试用例后，会调用classify_counts函数对路径触发次数进行整理，使其为2的n次方
        //simplify_trace也会规整数据，virgin_bits仅为virgin_map的一种情况，存在多种情况，需要分别讨论


        if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
            (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff)) ret = 2;    //未指定-B参数，设置virgin_bits数组值为0xff
                                                                                  //当virgin_bits字节为0xff时，标识这个路径之前没被触发，是一个新的路径
                                                                                  //返回2，标识发现了新的路径
        else ret = 1;   //当virgin_bits字节不为0xff时，但是又有位相同，说明本次的路径触发次数与之前触发的次数不同
                        //说明这个测试用例的某个路径触发次数达到了一个新的状态，也需要标识
                        //比如用例A触发了某个路径1次，但是用例B触发了30次，明显两个用例存在区别
                        //返回1，标识没有新的路径，但是已知的路径存在新状态

#endif /* ^WORD_SIZE_64 */

      }
      /*1100  *virgin
        0100  *current
        1000  *virgin &= ~*current;
        */
      *virgin &= ~*current; //在virgin中将current为1的位置为0，标识这个路径的触发范围之前检测过

    }
    //下一个
    current++;  
    virgin++;

  }

  if (ret && virgin_map == virgin_bits) bitmap_changed = 1;   //发现了相同位，然后传入的变量值等于virgin_bits，这设置bitmap_changed

  return ret;   //返回检测结果

}


/* Count the number of bits set in the provided bitmap. Used for the status
   screen several times every second, does not have to be fast.
   计算提供的位图中设置的位数。 每秒用于状态屏幕几次，不必很快。 */
//计算位图中置1的位数量
static u32 count_bits(u8* mem) {

  u32* ptr = (u32*)mem;
  u32  i   = (MAP_SIZE >> 2);   //一次遍历4字节
  u32  ret = 0;

  while (i--) {   //遍历64kb内存

    u32 v = *(ptr++);

    /* This gets called on the inverse, virgin bitmap; optimize for sparse
       data. */

    if (v == 0xffffffff) {    //32位都为1
      ret += 32;
      continue;
    }

    //通过算法计算剩余位
    v -= ((v >> 1) & 0x55555555);   
    v = (v & 0x33333333) + ((v >> 2) & 0x33333333);
    ret += (((v + (v >> 4)) & 0xF0F0F0F) * 0x01010101) >> 24;

  }

  return ret;

}


#define FF(_b)  (0xff << ((_b) << 3))   //b*8

/* Count the number of bytes set in the bitmap. Called fairly sporadically,
   mostly to update the status screen or calibrate and examine confirmed
   new paths. 计算位图中设置的字节数。 相当偶尔地调用，主要是为了更新状态屏幕或校准和检查已确认的新路径。*/
//统计共享内存中不为0的字节数量
static u32 count_bytes(u8* mem) {

  u32* ptr = (u32*)mem;
  u32  i   = (MAP_SIZE >> 2);
  u32  ret = 0;

  while (i--) {   //4字节格式，遍历共享内存

    u32 v = *(ptr++);

    if (!v) continue;   //为0,下一个
    if (v & FF(0)) ret++;   //0-7位有置1位,ret++
    if (v & FF(1)) ret++;   //8-15位有置1位,ret++
    if (v & FF(2)) ret++;   //16-23位有置1位,ret++
    if (v & FF(3)) ret++;   //24-31位有置1位,ret++

  }

  return ret;

}


/* Count the number of non-255 bytes set in the bitmap. Used strictly for the
   status screen, several calls per second or so.
   计算位图中设置的非 255 字节的数量。 严格用于状态屏幕，每秒调用几次左右。 */
//统计64kb内存中不是0xff值的数量
static u32 count_non_255_bytes(u8* mem) {

  u32* ptr = (u32*)mem;
  u32  i   = (MAP_SIZE >> 2); //64kb/4 = 16kb
  u32  ret = 0;

  while (i--) {   //遍历64kb共享内存，每次4字节

    u32 v = *(ptr++);

    /* This is called on the virgin bitmap, so optimize for the most likely
       case. */

    if (v == 0xffffffff) continue;    //4字节为0xff
    if ((v & FF(0)) != FF(0)) ret++;  //0-7位非0xff；ret++
    if ((v & FF(1)) != FF(1)) ret++;  //8-15位非0xff；ret++
    if ((v & FF(2)) != FF(2)) ret++;  //16-23位非0xff；ret++
    if ((v & FF(3)) != FF(3)) ret++;  //24-31位非0xff；ret++

  }

  return ret;

}


/* Destructively simplify trace by eliminating hit count information
   and replacing it with 0x80 or 0x01 depending on whether the tuple
   is hit or not. Called on every new crash or timeout, should be
   reasonably fast.
   通过消除命中计数信息并根据元组是否命中将其替换为 0x80 或 0x01 来破坏性地简化跟踪。 每次新的崩溃或超时时调用，应该相当快。 */

static const u8 simplify_lookup[256] = { 

  [0]         = 1,
  [1 ... 255] = 128

};

#ifdef WORD_SIZE_64

static void simplify_trace(u64* mem) {

  u32 i = MAP_SIZE >> 3;

  while (i--) {

    /* Optimize for sparse bitmaps. */

    if (unlikely(*mem)) {

      u8* mem8 = (u8*)mem;

      mem8[0] = simplify_lookup[mem8[0]];
      mem8[1] = simplify_lookup[mem8[1]];
      mem8[2] = simplify_lookup[mem8[2]];
      mem8[3] = simplify_lookup[mem8[3]];
      mem8[4] = simplify_lookup[mem8[4]];
      mem8[5] = simplify_lookup[mem8[5]];
      mem8[6] = simplify_lookup[mem8[6]];
      mem8[7] = simplify_lookup[mem8[7]];

    } else *mem = 0x0101010101010101ULL;

    mem++;

  }

}

#else
//针对每个字节，0变为1，其他值变为0x80
static void simplify_trace(u32* mem) {

  u32 i = MAP_SIZE >> 2;

  while (i--) {

    /* Optimize for sparse bitmaps. 针对稀疏位图进行优化。 */

    if (unlikely(*mem)) {

      u8* mem8 = (u8*)mem;

      //0变为1，其他值变为0x80
      mem8[0] = simplify_lookup[mem8[0]];   
      mem8[1] = simplify_lookup[mem8[1]];
      mem8[2] = simplify_lookup[mem8[2]];
      mem8[3] = simplify_lookup[mem8[3]];

    } else *mem = 0x01010101;   //每个字节都是0，所以每个字节都更改为1

    mem++;
  }

}

#endif /* ^WORD_SIZE_64 */


/* Destructively classify execution counts in a trace. This is used as a
   preprocessing step for any newly acquired traces. Called on every exec,
   must be fast. */

static const u8 count_class_lookup8[256] = {

  [0]           = 0,
  [1]           = 1,
  [2]           = 2,
  [3]           = 4,
  [4 ... 7]     = 8,
  [8 ... 15]    = 16,
  [16 ... 31]   = 32,
  [32 ... 127]  = 64,
  [128 ... 255] = 128

};

static u16 count_class_lookup16[65536]; 

//初始化count_class_lookup16 - 16位的计数归类
EXP_ST void init_count_class16(void) {

  u32 b1, b2;
  /*
    (b1 << 8) + b2  = b1*256+b2 等同于遍历了count_class_lookup16数组
    设置数据
      (count_class_lookup8[0]<<8)|  count_class_lookup8[0]   0x0
      (count_class_lookup8[0]<<8)| count_class_lookup8[1]   0x1
        ....
      (count_class_lookup8[16]<<8)| count_class_lookup8[31]   0x2020
      ....
      (count_class_lookup8[255]<<8)| count_class_lookup8[255]   0xffff     
  */

  for (b1 = 0; b1 < 256; b1++) 
    for (b2 = 0; b2 < 256; b2++)
      count_class_lookup16[(b1 << 8) + b2] = 
        (count_class_lookup8[b1] << 8) |
        count_class_lookup8[b2];

}


#ifdef WORD_SIZE_64

static inline void classify_counts(u64* mem) {

  u32 i = MAP_SIZE >> 3;

  while (i--) {

    /* Optimize for sparse bitmaps. */

    if (unlikely(*mem)) {

      u16* mem16 = (u16*)mem;

      mem16[0] = count_class_lookup16[mem16[0]];
      mem16[1] = count_class_lookup16[mem16[1]];
      mem16[2] = count_class_lookup16[mem16[2]];
      mem16[3] = count_class_lookup16[mem16[3]];

    }

    mem++;

  }

}

#else
//数据规整，将某个路径的次数整理为2的n次方，用于后续校验
static inline void classify_counts(u32* mem) {

  u32 i = MAP_SIZE >> 2;    //64kb/4

  while (i--) { //遍历64kb内存

    /* Optimize for sparse bitmaps. */

    if (unlikely(*mem)) {

      u16* mem16 = (u16*)mem;

      mem16[0] = count_class_lookup16[mem16[0]];    //进行数据规整
      mem16[1] = count_class_lookup16[mem16[1]];    //进行数据规整

    }

    mem++;

  }

}

#endif /* ^WORD_SIZE_64 */


/* Get rid of shared memory (atexit handler). */

static void remove_shm(void) {

  shmctl(shm_id, IPC_RMID, NULL);   //删除共享内存

}


/* Compact trace bytes into a smaller bitmap. We effectively just drop the
   count information here. This is called only sporadically, for some
   new paths. 将跟踪字节压缩为较小的位图。 我们实际上只是将计数信息放在这里。 对于某些新路径，这只是偶尔被调用。*/

static void minimize_bits(u8* dst, u8* src) {

  u32 i = 0;

  while (i < MAP_SIZE) {

    if (*(src++)) dst[i >> 3] |= 1 << (i & 7);    //用一个字节标识8个字节，字节有数据则对应bit置1
    i++;

    // 11，12，13，0，0，0，0，0    8字节
    // 00000111     压缩后的字节


  }

}


/* When we bump into a new path, we call this to see if the path appears
   more "favorable" than any of the existing ones. The purpose of the
   "favorables" is to have a minimal set of paths that trigger all the bits
   seen in the bitmap so far, and focus on fuzzing them at the expense of
   the rest.

   The first step of the process is to maintain a list of top_rated[] entries
   for every byte in the bitmap. We win that slot if there is no previous
   contender, or if the contender has a more favorable speed x size factor. 
   当我们遇到一条新路径时，我否们称其为查看该路径是比任何现有路径更“有利”。 
   “有利条件”的目的是拥有一组最小的路径来触发迄今为止在位图中看到的所有位，并专注于对它们进行模糊测试，而以其余部分为代价。
   该过程的第一步是维护位图中每个字节的 top_erated[] 条目列表。 如果没有先前的竞争者，或者竞争者具有更有利的速度 x 尺寸系数，我们将赢得该位置。*/

//更新共享内存字节的最优测试用例
static void update_bitmap_score(struct queue_entry* q) {

  u32 i;
  u64 fav_factor = q->exec_us * q->len;   //计算因子，测试用例执行时间*文件大小

  /* For every byte set in trace_bits[], see if there is a previous winner,
     and how it compares to us. 对于trace_bits[]中的每个字节集，查看是否有先前的获胜者，以及它与我们相比如何。*/

  for (i = 0; i < MAP_SIZE; i++)  //遍历整个共享内存

    if (trace_bits[i]) {    //当前字节有值

       if (top_rated[i]) {    //当前字节有对应的最优测试用例
         
         /* Faster-executing or smaller test cases are favored. 执行速度更快或更小的测试用例受到青睐。 */
         
         //比较新旧两个测试用例的优先级
         if (fav_factor > top_rated[i]->exec_us * top_rated[i]->len) continue;    //当前因子大于已存在的测试用例的因子，即当前测试用例对于该字节不是最优的

         /* Looks like we're going to win. Decrease ref count for the
            previous winner, discard its trace_bits[] if necessary. 
            看来我们要赢了。 减少前一个获胜者的引用计数，如有必要，丢弃其trace_bits[]。 */

        //当前测试用例的因子在该字节更优
         if (!--top_rated[i]->tc_ref) {   //减少原有测试用例的tc_ref
          //tc_ref减少后为0
           ck_free(top_rated[i]->trace_mini);   //释放资源
           top_rated[i]->trace_mini = 0;  //设置值
         }

       }

     
       /* Insert ourselves as the new winner.   让我们自己成为新的赢家。*/

       //设置当前测试用例
       top_rated[i] = q;    //更新当前字节最优测试用例
       q->tc_ref++;   //测试用例引用+1

       if (!q->trace_mini) {    //当前测试trace_mini未指定
         q->trace_mini = ck_alloc(MAP_SIZE >> 3);   //申请空间
         minimize_bits(q->trace_mini, trace_bits);    //用bit记录共享内存中非0数据的位置
       }

       score_changed = 1;   //设置全局标志

     }

}


/* The second part of the mechanism discussed above is a routine that
   goes over top_rated[] entries, and then sequentially grabs winners for
   previously-unseen bytes (temp_v) and marks them as favored, at least
   until the next run. The favored entries are given more air time during
   all fuzzing steps.
   上面讨论的机制的第二部分是一个例程，它遍历 top_lated[] 条目，然后顺序抓取以前未见过的字节 (temp_v) 的获胜者，并将它们标记为受欢迎的，
   至少直到下一次运行。 在所有模糊测试步骤中，受青睐的条目都会获得更多的播放时间。 */
//根据测试用例是否为共享内存字节的最优测试用例设置其受青睐标记和不太有用标记
static void cull_queue(void) {

  struct queue_entry* q;
  static u8 temp_v[MAP_SIZE >> 3];  //静态局部变量    
  u32 i;

  if (dumb_mode || !score_changed) return;    //哑模式 或 针对共享内存每个字节的最优测试用例没有改变

  score_changed = 0;    //重置共享内存每个字节的最优测试用例状态

  //注意，初始值为0xff
  memset(temp_v, 255, MAP_SIZE >> 3);   //temp_v为共享内存空间的压缩，8字节使用1字节进行表示

  queued_favored  = 0;
  pending_favored = 0;

  q = queue;

  while (q) {   //遍历测试用例
    q->favored = 0;     //受青睐状态为0
    q = q->next;
  }

  /* Let's see if anything in the bitmap isn't captured in temp_v.
     If yes, and if it has a top_rated[] contender, let's use it. 
     让我们看看 temp_v 中是否未捕获位图中的任何内容。 如果是，并且它有 top_erated[] 竞争者，我们就使用它。*/

  for (i = 0; i < MAP_SIZE; i++)    //遍历64kb
    //共享内存字节的存在最优测试用例 且 temp_v中的对应位被置1   //temp_v字节初始值为0xff，因此top_rated[i]有值则肯定会执行
    if (top_rated[i] && (temp_v[i >> 3] & (1 << (i & 7)))) {          //第一次执行时，会将所有通用路径的bit位置0

      u32 j = MAP_SIZE >> 3;    //8kb

      /* Remove all bits belonging to the current entry from temp_v. 
        从temp_v中删除属于当前条目的所有位。*/
      
      //遍历当前字节最优测试用例的trace_mini  //update_bitmap_score函数中设置了trace_mini成员
      while (j--) 
        if (top_rated[i]->trace_mini[j])      // trace_mini字节有值
          temp_v[j] &= ~top_rated[i]->trace_mini[j];    //将temp_v中trace_mini字节的置1位，置为0
          //当前字节最优测试用例的所有路径位都变为了0，后续不在处理这个测试用例
          //如果其他测试用例和这个路径一样呢？一样的话不就是同一个测试用例了吗，不然两个测试用例存在相同路径，没有含义呀。说得好 good

      top_rated[i]->favored = 1;  //设置其受青睐状态
      queued_favored++;   //受青睐的测试用例数量+1

      if (!top_rated[i]->was_fuzzed) pending_favored++;   //最优测试用例未完成fuzz，则待执行的青睐的测试用例数量+1

    }

  q = queue;

  while (q) {
    mark_as_redundant(q, !q->favored);    //第二个参数为1，将测试用例标记为不太有用的测试用例
    q = q->next;
  }

}


/* Configure shared memory and virgin_bits. This is called at startup. */
//设置共享内存和相关退出回调函数
EXP_ST void setup_shm(void) {

  u8* shm_str;
  //未指定-B参数，设置virgin_bits数组值为0xff 
  if (!in_bitmap) memset(virgin_bits, 255, MAP_SIZE);   //-B参数指定加载的位图文件，读取后in_bitmap置为1

  memset(virgin_tmout, 255, MAP_SIZE);  //设置virgin_tmout数组值为0xff 
  memset(virgin_crash, 255, MAP_SIZE);  //设置virgin_bits数值为0xff 

  shm_id = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600);    //创建共享内存

  if (shm_id < 0) PFATAL("shmget() failed");    //创建失败退出

  atexit(remove_shm);     //注册程序退出时的回调函数，用于删除共享内存

  shm_str = alloc_printf("%d", shm_id);   //将共享内存ID转为字符串

  /* If somebody is asking us to fuzz instrumented binaries in dumb mode,
     we don't want them to detect instrumentation, since we won't be sending
     fork server commands. This should be replaced with better auto-detection
     later on, perhaps? */

  if (!dumb_mode) setenv(SHM_ENV_VAR, shm_str, 1);    //非哑模式，设置共享内存ID到环境变量

  ck_free(shm_str); //释放字符串

  trace_bits = shmat(shm_id, NULL, 0);    //将共享内存附加到当前进程空间，并返回共享内存起始地址
  
  if (trace_bits == (void *)-1) PFATAL("shmat() failed");   //检测内存是否附加成功

}


/* Load postprocessor, if available. */
//加载后处理函数，用于处理测试结束后的工作
static void setup_post(void) {

  void* dh;
  u8* fn = getenv("AFL_POST_LIBRARY");  //获取环境变量
  u32 tlen = 6;

  if (!fn) return;    //获取失败

  ACTF("Loading postprocessor from '%s'...", fn);

  dh = dlopen(fn, RTLD_NOW);    //打开指定的动态链接库文件
                                //RTLD_NOW表示在 dlopen 过程中立即解析库中的所有未定义符号
                                //这意味着在打开库时就会解析并加载库中的所有符号，如果有未解析的符号，dlopen 将失败。
  if (!dh) FATAL("%s", dlerror());

  post_handler = dlsym(dh, "afl_postprocess");  //在动态链接库中查询afl_postprocess函数
  if (!post_handler) FATAL("Symbol 'afl_postprocess' not found.");

  /* Do a quick test. It's better to segfault now than later =) */

  post_handler("hello", &tlen);   //测试afl_postprocess函数

  OKF("Postprocessor installed successfully.");

}


/* Read all testcases from the input directory, then queue them for testing.
   Called at startup.  从输入目录中读取所有测试用例，然后将它们排队进行测试。 在启动时调用。*/

static void read_testcases(void) {

  struct dirent **nl;
  s32 nl_cnt;
  u32 i;
  u8* fn;

  /* Auto-detect non-in-place resumption attempts. */   //检测恢复尝试

  fn = alloc_printf("%s/queue", in_dir);    
  if (!access(fn, F_OK)) in_dir = fn; else ck_free(fn);   //如果in_dir目录下存在queue子目录，则将queue子目录作为输入目录
                                                          //指定out目录作为输入目录

  ACTF("Scanning '%s'...", in_dir);

  /* We use scandir() + alphasort() rather than readdir() because otherwise,
     the ordering  of test cases would vary somewhat randomly and would be
     difficult to control. 
     使用scandir() + alphasort()进行排序   */

  //获取排序后的文件列表
  nl_cnt = scandir(in_dir, &nl, NULL, alphasort);

  if (nl_cnt < 0) {   //读取失败，程序终止

    if (errno == ENOENT || errno == ENOTDIR)  //目录不存在或非目录错误，进行提示

      SAYF("\n" cLRD "[-] " cRST
           "The input directory does not seem to be valid - try again. The fuzzer needs\n"
           "    one or more test case to start with - ideally, a small file under 1 kB\n"
           "    or so. The cases must be stored as regular files directly in the input\n"
           "    directory.\n");

    PFATAL("Unable to open '%s'", in_dir);    //退出

  }

  if (shuffle_queue && nl_cnt > 1) { 
    //环境变量设置了AFL_SHUFFLE_QUEUE且存在目录下存在文件

    ACTF("Shuffling queue...");
    shuffle_ptrs((void**)nl, nl_cnt);   //打乱测试样本顺序

  }

  for (i = 0; i < nl_cnt; i++) {  //遍历文件


    struct stat st;

    u8* fn = alloc_printf("%s/%s", in_dir, nl[i]->d_name);    //拼接输入文件路径
    u8* dfn = alloc_printf("%s/.state/deterministic_done/%s", in_dir, nl[i]->d_name); //拼接确定性变异文件路径

    u8  passed_det = 0;

    free(nl[i]); /* not tracked */    //释放原始文件名
 
    if (lstat(fn, &st) || access(fn, R_OK))   
      PFATAL("Unable to access '%s'", fn);    //文件不存在、或不可访问，终止程序

    /* This also takes care of . and .. */

    if (!S_ISREG(st.st_mode) || !st.st_size || strstr(fn, "/README.testcases")) {
      //跳过目录、大小为0文件、README.testcases文件
      ck_free(fn);
      ck_free(dfn);
      continue;

    }

    if (st.st_size > MAX_FILE)    //测试用例文件大小超过了1M，终止程序
      FATAL("Test case '%s' is too big (%s, limit is %s)", fn,
            DMS(st.st_size), DMS(MAX_FILE));

    /* Check for metadata that indicates that deterministic fuzzing
       is complete for this entry. We don't want to repeat deterministic
       fuzzing when resuming aborted scans, because it would be pointless
       and probably very time-consuming. */

    if (!access(dfn, F_OK)) passed_det = 1;   //检测是否存在确定性变异结束的文件；这用于恢复工作时，检查上次确定性变异的执行情况
                                              //新任务，一般没有这个文件
    ck_free(dfn);

    add_to_queue(fn, st.st_size, passed_det);   //添加新的测试用例到队列，同时指定是否跳过确定性变异

  }

  free(nl); /* not tracked */   //释放文件目录数组

  if (!queued_paths) {    //测试用例数量为0
    
    SAYF("\n" cLRD "[-] " cRST
         "Looks like there are no valid test cases in the input directory! The fuzzer\n"
         "    needs one or more test case to start with - ideally, a small file under\n"
         "    1 kB or so. The cases must be stored as regular files directly in the\n"
         "    input directory.\n");

    FATAL("No usable test cases in '%s'", in_dir);    //打印提示信息，并终止程序

  }

  last_path_time = 0; //最后一次测试用例的添加时间设置为0，表示没有发现新的路径
  queued_at_start = queued_paths;   //指定队列的起始值

}


/* Helper function for load_extras. */

static int compare_extras_len(const void* p1, const void* p2) {
  struct extra_data *e1 = (struct extra_data*)p1,
                    *e2 = (struct extra_data*)p2;
  //比较字典文本的长度
  return e1->len - e2->len;
}

static int compare_extras_use_d(const void* p1, const void* p2) {
  struct extra_data *e1 = (struct extra_data*)p1,
                    *e2 = (struct extra_data*)p2;
  //比较字典文本的命中次数
  return e2->hit_cnt - e1->hit_cnt;
}


/* Read extras from a file, sort by size. */
//从文件读取字典，再根据大小排序 ；格式 xxxx@number "字典"
static void load_extras_file(u8* fname, u32* min_len, u32* max_len,
                             u32 dict_level) {

  FILE* f;
  u8  buf[MAX_LINE];
  u8  *lptr;
  u32 cur_line = 0;

  f = fopen(fname, "r");    //打开文件

  if (!f) PFATAL("Unable to open '%s'", fname);   //打开失败，终止程序

  while ((lptr = fgets(buf, MAX_LINE, f))) {    //遍历文件每行

    u8 *rptr, *wptr;
    u32 klen = 0;

    cur_line++;   //行数+1

    /* Trim on left and right. 左右修剪，移除前后格 */

    while (isspace(*lptr)) lptr++;    //跳过行起始空格

    rptr = lptr + strlen(lptr) - 1;     
    while (rptr >= lptr && isspace(*rptr)) rptr--;
    rptr++;
    *rptr = 0;    //从后向前遍历空白字符，然后将在第一个非空白字符后设置终止符

    /* Skip empty lines and comments. 跳过空行和注释。 */

    if (!*lptr || *lptr == '#') continue;

    /* All other lines must end with '"', which we can consume. 
    字典文件的行，必须以"结尾
    */

    rptr--;

    if (rptr < lptr || *rptr != '"')    //检测" ,失败退出
      FATAL("Malformed name=\"value\" pair in line %u.", cur_line);

    *rptr = 0;  //移除"

    /* Skip alphanumerics and dashes (label). 跳过跳过字母数字和破折号（标签）*/

    while (isalnum(*lptr) || *lptr == '_') lptr++;

    /* If @number follows, parse that. 如果后面跟着@number，则解析它*/

    if (*lptr == '@') {

      lptr++;
      if (atoi(lptr) > dict_level) continue;  //大于给定的字典级别，则遍历下一行
      while (isdigit(*lptr)) lptr++;    //跳过表示字典级别的数字

    }

    /* Skip whitespace and = signs. 跳过空格和 = 符号。*/

    while (isspace(*lptr) || *lptr == '=') lptr++;

    /* Consume opening '"'. */

    if (*lptr != '"')
      FATAL("Malformed name=\"keyword\" pair in line %u.", cur_line);   //检测起始"，失败终止

    lptr++; //跳过起始"

    if (!*lptr) FATAL("Empty keyword in line %u.", cur_line);   //字典为空

    /* Okay, let's allocate memory and copy data between "...", handling
       \xNN escaping, \\, and \". 好吧，让我们在“...”之间分配内存并复制数据，处理 \xNN 转义、\\ 和 \”。 */
    //处理字典字符
    extras = ck_realloc_block(extras, (extras_cnt + 1) *    //追加一个字典结构体
               sizeof(struct extra_data));

    wptr = extras[extras_cnt].data = ck_alloc(rptr - lptr);  //申请保存字典字符的缓冲区

    while (*lptr) {   //遍历字典字符串

      //支持\\ \" \x123 和可打印字符
      char* hexdigits = "0123456789abcdef";

      switch (*lptr) {

        case 1 ... 31:
        case 128 ... 255:
          FATAL("Non-printable characters in line %u.", cur_line);      //行中存在不可打印的字符，终止程序

        case '\\':  //处理转义字符

          lptr++; //指向\下一个

          if (*lptr == '\\' || *lptr == '"') {    // \和"直接追加
            *(wptr++) = *(lptr++);
            klen++;  
            break;
          }

          if (*lptr != 'x' || !isxdigit(lptr[1]) || !isxdigit(lptr[2]))   //非\xff 这种16进制格式，终止程序
            FATAL("Invalid escaping (not \\xNN) in line %u.", cur_line);

          *(wptr++) =   //16进制字符转为char
            ((strchr(hexdigits, tolower(lptr[1])) - hexdigits) << 4) |
            (strchr(hexdigits, tolower(lptr[2])) - hexdigits);

          lptr += 3;
          klen++; 

          break;

        default:
          //可打印字符直接复制
          *(wptr++) = *(lptr++);
          klen++;
      }

    }

    extras[extras_cnt].len = klen;  //字典字符的最终长度

    if (extras[extras_cnt].len > MAX_DICT_FILE)     //超过了字典的最大长度
      FATAL("Keyword too big in line %u (%s, limit is %s)", cur_line,
            DMS(klen), DMS(MAX_DICT_FILE));

    if (*min_len > klen) *min_len = klen;   //设置当前文件中字典字符串的最小长度
    if (*max_len < klen) *max_len = klen;   //设置当前文件中字典字符串的最大长度

    extras_cnt++;   //更新字典字符串数量

  }

  fclose(f);    

}


/* Read extras from the extras directory and sort them by size.
从 extras 目录或文件中读取 extras 并按大小排序。 */
//文件或目录格式 xxx@level,；如果是目录，则目录下每个文件保存一个字典字符串；如果是文件，则文件每行保存一个特定格式的字典字符串
//加载字典
static void load_extras(u8* dir) {

  DIR* d;
  struct dirent* de;
  u32 min_len = MAX_DICT_FILE, max_len = 0, dict_level = 0;
  u8* x;

  /* If the name ends with @, extract level and continue. 
    如果名称以 @ 结尾，则提取级别并继续*/

  if ((x = strchr(dir, '@'))) {

    *x = 0;   //将@替换为终止符
    dict_level = atoi(x + 1);  //提取@后面的数值作为字典级别

  }

  ACTF("Loading extra dictionary from '%s' (level %u)...", dir, dict_level);

  d = opendir(dir);   //打开目录

  if (!d) {

    if (errno == ENOTDIR) {   //非目录，而是文件
      load_extras_file(dir, &min_len, &max_len, dict_level);    //从文件中加字典字符串
      goto check_and_sort;
    }

    PFATAL("Unable to open '%s'", dir);   //非文件或目录，终止程序

  }

  if (x) FATAL("Dictionary levels not supported for directories.");   //目录不支持字典级别

  while ((de = readdir(d))) {

    struct stat st;
    u8* fn = alloc_printf("%s/%s", dir, de->d_name);    //拼接文件路径
    s32 fd;

    if (lstat(fn, &st) || access(fn, R_OK)) 
      PFATAL("Unable to access '%s'", fn);    //文件不允许访问，终止程序

    /* This also takes care of . and .. */
    if (!S_ISREG(st.st_mode) || !st.st_size) {    ///跳过目录、大小为0文件

      ck_free(fn);
      continue;

    }

    if (st.st_size > MAX_DICT_FILE)   //文件太大
      FATAL("Extra '%s' is too big (%s, limit is %s)", fn,
            DMS(st.st_size), DMS(MAX_DICT_FILE));

    //设置最小行和最大行大小
    if (min_len > st.st_size) min_len = st.st_size;   
    if (max_len < st.st_size) max_len = st.st_size;

    extras = ck_realloc_block(extras, (extras_cnt + 1) *    //多申请一个extra_data结构体
               sizeof(struct extra_data));

    extras[extras_cnt].data = ck_alloc(st.st_size);   //申请空间
    extras[extras_cnt].len  = st.st_size;   //设置大小

    fd = open(fn, O_RDONLY);    //打开文件

    if (fd < 0) PFATAL("Unable to open '%s'", fn);    //打开失败，终止程序

    ck_read(fd, extras[extras_cnt].data, st.st_size, fn);     //从文件读取字典文本

    close(fd);
    ck_free(fn);

    extras_cnt++;   //字典文本数量+1

  }

  closedir(d);

//排序
check_and_sort:

  if (!extras_cnt) FATAL("No usable files in '%s'", dir);   //字典文件读取失败，或是空文件，终止程序

  qsort(extras, extras_cnt, sizeof(struct extra_data), compare_extras_len);   //根据字典字符串的长度进行排序

  OKF("Loaded %u extra tokens, size range %s to %s.", extras_cnt,
      DMS(min_len), DMS(max_len));

  if (max_len > 32)   
    WARNF("Some tokens are relatively large (%s) - consider trimming.",   //有些标记相对较大 (%s) - 考虑修剪。
          DMS(max_len));

  if (extras_cnt > MAX_DET_EXTRAS)    //字典字符串数量超过了最大值。
    WARNF("More than %u tokens - will use them probabilistically.", //会概率性地使用它们。
          MAX_DET_EXTRAS);

}




/* Helper function for maybe_add_auto() */

static inline u8 memcmp_nocase(u8* m1, u8* m2, u32 len) {

  while (len--) if (tolower(*(m1++)) ^ tolower(*(m2++))) return 1;
  return 0;

}


/* Maybe add automatic extra.  也许添加自动额外功能。 */
//尝试添加字典到程序发现的字典列表中
static void maybe_add_auto(u8* mem, u32 len) {

  u32 i;

  /* Allow users to specify that they don't want auto dictionaries.   允许用户指定他们不需要自动词典。*/
  //宏定义设置为0时，则不使用自动字典
  if (!MAX_AUTO_EXTRAS || !USE_AUTO_EXTRAS) return;
  
  
  /* Skip runs of identical bytes. 字典为重复值则返回，比如AAAAAAA*/
  
  for (i = 1; i < len; i++)   //遍历数组
    if (mem[0] ^ mem[i]) break;   //定位到第一个不同数值

  if (i == len) return; //整个数组都是相同数值，返回

  /* Reject builtin interesting values. 拒绝内置的有趣的值  //字典包含内置的有趣数值，则返回*/

  if (len == 2) {   //前2个值相同 

    i = sizeof(interesting_16) >> 1;    //遍历interesting_16数组

    while (i--)     
      if (*((u16*)mem) == interesting_16[i] ||
          *((u16*)mem) == SWAP16(interesting_16[i])) return;    //前两个值存在于内置的感兴趣数组中，则返回

  }

  if (len == 4) { //前4个值相同 

    i = sizeof(interesting_32) >> 2;    //遍历interesting_32数组

    while (i--) 
      if (*((u32*)mem) == interesting_32[i] ||
          *((u32*)mem) == SWAP32(interesting_32[i])) return;   //前4个值存在于内置的感兴趣数组中，则返回

  }

  /* Reject anything that matches existing extras. Do a case-insensitive
     match. We optimize by exploiting the fact that extras[] are sorted
     by size. 拒绝任何与现有附加内容相匹配的内容。 进行不区分大小写的匹配。 我们通过利用 extras[] 按大小排序的事实进行优化。*/

  for (i = 0; i < extras_cnt; i++)
    if (extras[i].len >= len) break;    //跳过长度小于本次添加长度的字典

  for (; i < extras_cnt && extras[i].len == len; i++)   
    if (!memcmp_nocase(extras[i].data, mem, len)) return;   //如果与之前的字典相同，则返回  (//比较时不区分大小写)

  /* Last but not least, check a_extras[] for matches. There are no
     guarantees of a particular sort order. */

  auto_changed = 1;
  //遍历自动选择的字典列表，检测相同值
  for (i = 0; i < a_extras_cnt; i++) {

    if (a_extras[i].len == len && !memcmp_nocase(a_extras[i].data, mem, len)) {   //比较时不区分大小写

      a_extras[i].hit_cnt++;    //存在相同值，则命中+1
      goto sort_a_extras; //字典排序

    }

  }

  /* At this point, looks like we're dealing with a new entry. So, let's
     append it if we have room. Otherwise, let's randomly evict some other
     entry from the bottom half of the list.
     此时，看起来我们正在处理一个新条目。 因此，如果有空间，我们将其附加。 否则，让我们从列表的下半部分随机驱逐一些条目。 */
 
  if (a_extras_cnt < MAX_AUTO_EXTRAS) {
    //自动选择的字典空间有剩余

    a_extras = ck_realloc_block(a_extras, (a_extras_cnt + 1) *
                                sizeof(struct extra_data));   //多申请一个结构体的空间，同时保留之前的数据

    a_extras[a_extras_cnt].data = ck_memdup(mem, len);    //追加一个自动选择字典
    a_extras[a_extras_cnt].len  = len;
    a_extras_cnt++; //自动选择的字典数量+1

  } else {
    //自动选择的字典空间已满

    //随机替换自动选择字典空间后半部的一项
    i = MAX_AUTO_EXTRAS / 2 +
        UR((MAX_AUTO_EXTRAS + 1) / 2);

    ck_free(a_extras[i].data);  //释放旧字典

    a_extras[i].data    = ck_memdup(mem, len);    //设置为新字典
    a_extras[i].len     = len;
    a_extras[i].hit_cnt = 0;

  }

sort_a_extras:

  /* First, sort all auto extras by use count, descending order. 首先，按使用次数降序对所有自动附加功能进行排序。*/

  qsort(a_extras, a_extras_cnt, sizeof(struct extra_data),
        compare_extras_use_d);      //根据字典的命中次数进行整理排序

  /* Then, sort the top USE_AUTO_EXTRAS entries by size. 然后，按大小对顶部的 USE_AUTO_EXTRAS 条目进行排序。*/

  qsort(a_extras, MIN(USE_AUTO_EXTRAS, a_extras_cnt),   //最排序数量为USE_AUTO_EXTRAS
        sizeof(struct extra_data), compare_extras_len);   //顶部的字典根据文本的长度进行排序

}


/* Save automatically generated extras. 保存自动生成的附加内容。*/
//保存自动发现的字典条目
static void save_auto(void) {

  u32 i;

  if (!auto_changed) return;
  auto_changed = 0;

  for (i = 0; i < MIN(USE_AUTO_EXTRAS, a_extras_cnt); i++) {    //遍历字典列表，最大不超过USE_AUTO_EXTRAS个

    u8* fn = alloc_printf("%s/queue/.state/auto_extras/auto_%06u", out_dir, i);   //文件路径
    s32 fd;

    fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0600);    //打开

    if (fd < 0) PFATAL("Unable to create '%s'", fn);  //打开失败。终止

    ck_write(fd, a_extras[i].data, a_extras[i].len, fn);  //写入

    close(fd);  //释放资源
    ck_free(fn);

  }

}


/* Load automatically generated extras. 加载自动生成的附加内容。*/

static void load_auto(void) {

  u32 i;

  for (i = 0; i < USE_AUTO_EXTRAS; i++) {   //遍历序号

    u8  tmp[MAX_AUTO_EXTRA + 1];
    u8* fn = alloc_printf("%s/.state/auto_extras/auto_%06u", in_dir, i);    //拼接路径名
                      //这个路径新任务不会存在，推测用于恢复上次任务；
                      //因为设置目录时，恢复上次任务会将之前的queue作为输入目录，其中包含了.state目录
    s32 fd, len;

    fd = open(fn, O_RDONLY, 0600);    //打开文件

    if (fd < 0) {

      if (errno != ENOENT) PFATAL("Unable to open '%s'", fn);   //非文件不存在错误，终止程序
      ck_free(fn);
      break;    //文件不存在退出循环，结束函数

    }

    /* We read one byte more to cheaply detect tokens that are too
       long (and skip them). */

    len = read(fd, tmp, MAX_AUTO_EXTRA + 1);    //读取上限+1个数据

    if (len < 0) PFATAL("Unable to read from '%s'", fn);    //读取失败，终止程序

    if (len >= MIN_AUTO_EXTRA && len <= MAX_AUTO_EXTRA)   //在最小值和最大值区间内
      maybe_add_auto(tmp, len);   //添加字典文件

    close(fd);
    ck_free(fn);

  }

  if (i) OKF("Loaded %u auto-discovered dictionary tokens.", i);
  else OKF("No auto-generated dictionary tokens to reuse.");

}


/* Destroy extras. */
//销毁字典
static void destroy_extras(void) {

  u32 i;

  //释放extras资源
  for (i = 0; i < extras_cnt; i++)    
    ck_free(extras[i].data);

  ck_free(extras);

  //释放a_extras资源
  for (i = 0; i < a_extras_cnt; i++) 
    ck_free(a_extras[i].data);

  ck_free(a_extras);

}


/* Spin up fork server (instrumented mode only). The idea is explained here:  启动fork服务器（仅限检测模式）。 这个想法解释如下：

   http://lcamtuf.blogspot.com/2014/10/fuzzing-binaries-without-execve.html

   In essence, the instrumentation allows us to skip execve(), and just keep
   cloning a stopped child. So, we just execute once, and then send commands
   through a pipe. The other part of this logic is in afl-as.h. 
   从本质上讲，检测允许我们跳过execve()，并继续克隆停止的子进程。 因此，我们只执行一次，然后通过管道发送命令。 该逻辑的另一部分位于 afl-as.h 中。*/

EXP_ST void init_forkserver(char** argv) {

  static struct itimerval it;
  int st_pipe[2], ctl_pipe[2];
  int status;
  s32 rlen;

  ACTF("Spinning up the fork server...");

  if (pipe(st_pipe) || pipe(ctl_pipe)) PFATAL("pipe() failed");   //创建两个管道，失败终止

  forksrv_pid = fork();   //设置全局变量

  if (forksrv_pid < 0) PFATAL("fork() failed");   //fork失败，终止

  if (!forksrv_pid) { //当前进程

    struct rlimit r;

    /* Umpf. On OpenBSD, the default fd limit for root users is set to
       soft 128. Let's try to fix that... 在 OpenBSD 上，root 用户的默认 fd 限制设置为 soft 128。让我们尝试修复这个问题... */

    //设置文件描述符
    if (!getrlimit(RLIMIT_NOFILE, &r) && r.rlim_cur < FORKSRV_FD + 2) {    
      
       //检测文明描述的最大数量，如果小于当前使用的描述符，则重新设置
      r.rlim_cur = FORKSRV_FD + 2;
      setrlimit(RLIMIT_NOFILE, &r); /* Ignore errors */

    }
  
    //设置内存限制
    if (mem_limit) {
      
      //指定了内存限制，则设置当前进程的数据段内存限制

      r.rlim_max = r.rlim_cur = ((rlim_t)mem_limit) << 20;    //MB转为B

#ifdef RLIMIT_AS

      setrlimit(RLIMIT_AS, &r); /* Ignore errors */

#else

      /* This takes care of OpenBSD, which doesn't have RLIMIT_AS, but
         according to reliable sources, RLIMIT_DATA covers anonymous
         maps - so we should be getting good protection against OOM bugs. 
          这适用于没有 RLIMIT_AS 的 OpenBSD，但根据可靠来源，RLIMIT_DATA 涵盖了匿名映射 - 因此我们应该针对 OOM 错误获得良好的保护。*/

      setrlimit(RLIMIT_DATA, &r); /* Ignore errors */

#endif /* ^RLIMIT_AS */


    }

    /* Dumping cores is slow and can lead to anomalies if SIGKILL is delivered
       before the dump is complete. 转储核心的速度很慢，如果在转储完成之前发出 SIGKILL，可能会导致异常。 */

    r.rlim_max = r.rlim_cur = 0;

    //设置核心转储文件的大小限制;禁用核心转储,这意味着在程序崩溃时，操作系统将不会生成包含程序崩溃时内存映像的核心转储文件
    setrlimit(RLIMIT_CORE, &r); /* Ignore errors */

    /* Isolate the process and configure standard descriptors. If out_file is
       specified, stdin is /dev/null; otherwise, out_fd is cloned instead.
       隔离进程并配置标准描述符。 如果指定了out_file，则stdin为/dev/null； 否则，将克隆 out_fd。 */

    setsid();   //断开与原来控制终端的关联，将当前进程转为守护进程

    dup2(dev_null_fd, 1); //设置标准输出重定向为/dev/null
    dup2(dev_null_fd, 2); //设置错误输出重定向为/dev/null

    if (out_file) {   
      //如果指定了输出文件，则被测试程序将通过文件获取数据。因此将标准输入重定向为/dev/null
      dup2(dev_null_fd, 0);

    } else {
      //未指定输出文件，则被测试程序将从标准输入获取数据，因此将标准输入重定向为中间文件
      dup2(out_fd, 0);
      close(out_fd);

    }

    /* Set up control and status pipes, close the unneeded original fds. 设置控制和状态管道，关闭不需要的原始fd。 */

    if (dup2(ctl_pipe[0], FORKSRV_FD) < 0) PFATAL("dup2() failed");   //198绑定到读取管道，因为当前进程为被测试进程，因此从198管道读取控制信息
    if (dup2(st_pipe[1], FORKSRV_FD + 1) < 0) PFATAL("dup2() failed");   //199绑定到写入管道，因为当前进程为被测试进程，因此从199管道告知状态信息

    close(ctl_pipe[0]);   //关闭管道，计数-1
    close(ctl_pipe[1]); //关闭管道
    close(st_pipe[0]);  //关闭管道
    close(st_pipe[1]);  //关闭管道
    //关闭其他文件描述符
    close(out_dir_fd);  
    close(dev_null_fd);
    close(dev_urandom_fd);
    close(fileno(plot_file));   //图形统计使用的描述符

    /* This should improve performance a bit, since it stops the linker from
       doing extra work post-fork(). 这应该会稍微提高性能，因为它可以阻止链接器在 fork() 之后执行额外的工作。*/

    if (!getenv("LD_BIND_LAZY")) setenv("LD_BIND_NOW", "1", 0);     //根据条件设置延迟绑定环境变量

    /* Set sane defaults for ASAN if nothing else specified. 如果没有其他指定，请为 ASAN 设置合理的默认值。*/

    setenv("ASAN_OPTIONS", "abort_on_error=1:"
                           "detect_leaks=0:"
                           "symbolize=0:"
                           "allocator_may_return_null=1", 0);

    /* MSAN is tricky, because it doesn't support abort_on_error=1 at this
       point. So, we do this in a very hacky way.  
       MSAN 很棘手，因为它不支持 abort_on_error=1   观点。 所以，我们用一种非常hacky的方式来做这件事。*/

    setenv("MSAN_OPTIONS", "exit_code=" STRINGIFY(MSAN_ERROR) ":"
                           "symbolize=0:"
                           "abort_on_error=1:"
                           "allocator_may_return_null=1:"
                           "msan_track_origins=0", 0);

    execv(target_path, argv);   //将当前进程转为被测试程序。执行成功，当前进程转为了被测试程序，且不会返回

    /* Use a distinctive bitmap signature to tell the parent about execv()
       falling through. 使用独特的位图签名告诉父级 execv() 失败。*/

    //执行失败，将共享内存设置为指定标记，告知fuzzer程序 被测试程序运行失败
    *(u32*)trace_bits = EXEC_FAIL_SIG;
    exit(0);    //退出

  }

  //子进程

  /* Close the unneeded endpoints. 关闭不需要的端点*/

  close(ctl_pipe[0]);   
  close(st_pipe[1]);

  fsrv_ctl_fd = ctl_pipe[1];  //保存为全局变量,用于向被测试进程写入控制信息
  fsrv_st_fd  = st_pipe[0];   //保存为全局变量,用于读取被测试进程写入的状态信息

  /* Wait for the fork server to come up, but don't wait too long. 等待fork服务器出现，但不要等待太久 */
  //使用执行超时时间x等待比率作为定时器时间
  it.it_value.tv_sec = ((exec_tmout * FORK_WAIT_MULT) / 1000);        //将毫秒转为秒
  it.it_value.tv_usec = ((exec_tmout * FORK_WAIT_MULT) % 1000) * 1000;    //剩余将毫秒

  setitimer(ITIMER_REAL, &it, NULL);    //设置定时器，时间一到发送SIGALRM信号
                                        //setup_signal_handlers中设置了SIGALRM处理函数为handle_timeout，当child_pid == -1 && forksrv_pid > 0,则关闭forksrv_pid，然后设置child_timed_out
                                        //

  rlen = read(fsrv_st_fd, &status, 4);    //尝试读取状态信息
                                          //当超时关闭了被测试程序时，会释放st_pipe[1],此时会报错，导致该函数返回
  //关闭定时器
  it.it_value.tv_sec = 0;   
  it.it_value.tv_usec = 0;
  setitimer(ITIMER_REAL, &it, NULL);

  /* If we have a four-byte "hello" message from the server, we're all set.
     Otherwise, try to figure out what went wrong. 
     如果我们收到来自服务器的四字节“hello”消息，则一切就绪。 否则，尝试找出问题所在。*/

  if (rlen == 4) {    //读取了4字节，说明被测试程序运作正常
    OKF("All right - fork server is up.");
    return; //返回
  }

  //由于超时导致
  if (child_timed_out)
    FATAL("Timeout while initializing fork server (adjusting -t may help)");    //报错，终止

  //其他情况（如切换被测试程序失败，被测试程序异常终止等）

  //获取子进程状态
  if (waitpid(forksrv_pid, &status, 0) <= 0)    
    PFATAL("waitpid() failed");   //获取失败，终止

  if (WIFSIGNALED(status)) {
    //子进程由于信号而终止

    if (mem_limit && mem_limit < 500 && uses_asan) {
      //设置了内存限制，且内存限制小于500，且启用了asan 则打印相关信息
      SAYF("\n" cLRD "[-] " cRST
           "Whoops, the target binary crashed suddenly, before receiving any input\n"
           "    from the fuzzer! Since it seems to be built with ASAN and you have a\n"
           "    restrictive memory limit configured, this is expected; please read\n"
           "    %s/notes_for_asan.txt for help.\n", doc_path);

    } else if (!mem_limit) {
      //未设置内存限制， 打印相关信息
      SAYF("\n" cLRD "[-] " cRST
           "Whoops, the target binary crashed suddenly, before receiving any input\n"
           "    from the fuzzer! There are several probable explanations:\n\n"

           "    - The binary is just buggy and explodes entirely on its own. If so, you\n"
           "      need to fix the underlying problem or find a better replacement.\n\n"

#ifdef __APPLE__

           "    - On MacOS X, the semantics of fork() syscalls are non-standard and may\n"
           "      break afl-fuzz performance optimizations when running platform-specific\n"
           "      targets. To fix this, set AFL_NO_FORKSRV=1 in the environment.\n\n"

#endif /* __APPLE__ */

           "    - Less likely, there is a horrible bug in the fuzzer. If other options\n"
           "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n");

    } else {
      //打印其他信息
      SAYF("\n" cLRD "[-] " cRST
           "Whoops, the target binary crashed suddenly, before receiving any input\n"
           "    from the fuzzer! There are several probable explanations:\n\n"

           "    - The current memory limit (%s) is too restrictive, causing the\n"
           "      target to hit an OOM condition in the dynamic linker. Try bumping up\n"
           "      the limit with the -m setting in the command line. A simple way confirm\n"
           "      this diagnosis would be:\n\n"

#ifdef RLIMIT_AS
           "      ( ulimit -Sv $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#else
           "      ( ulimit -Sd $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#endif /* ^RLIMIT_AS */

           "      Tip: you can use http://jwilk.net/software/recidivm to quickly\n"
           "      estimate the required amount of virtual memory for the binary.\n\n"

           "    - The binary is just buggy and explodes entirely on its own. If so, you\n"
           "      need to fix the underlying problem or find a better replacement.\n\n"

#ifdef __APPLE__

           "    - On MacOS X, the semantics of fork() syscalls are non-standard and may\n"
           "      break afl-fuzz performance optimizations when running platform-specific\n"
           "      targets. To fix this, set AFL_NO_FORKSRV=1 in the environment.\n\n"

#endif /* __APPLE__ */

           "    - Less likely, there is a horrible bug in the fuzzer. If other options\n"
           "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n",
           DMS(mem_limit << 20), mem_limit - 1);

    }

    FATAL("Fork server crashed with signal %d", WTERMSIG(status));    //打印终止信号，终止当前程序

  }

  if (*(u32*)trace_bits == EXEC_FAIL_SIG)   //父进程切换为被测试程序失败
    FATAL("Unable to execute target application ('%s')", argv[0]);    //打印信息，终止

  //程序没有因为收到信号而终止。这意味着程序可能正常退出，也可能被某种方式中止，例如调用了exi 函数或者执行了_exit系统调用
  if (mem_limit && mem_limit < 500 && uses_asan) {
   //设置了内存限制，且内存限制小于500，且启用了asan 则打印相关信息
    SAYF("\n" cLRD "[-] " cRST
           "Hmm, looks like the target binary terminated before we could complete a\n"
           "    handshake with the injected code. Since it seems to be built with ASAN and\n"
           "    you have a restrictive memory limit configured, this is expected; please\n"
           "    read %s/notes_for_asan.txt for help.\n", doc_path);

  } else if (!mem_limit) {
    //未设置内存限制， 打印相关信息
    SAYF("\n" cLRD "[-] " cRST
         "Hmm, looks like the target binary terminated before we could complete a\n"
         "    handshake with the injected code. Perhaps there is a horrible bug in the\n"
         "    fuzzer. Poke <lcamtuf@coredump.cx> for troubleshooting tips.\n");

  } else {
    //打印其他信息
    SAYF("\n" cLRD "[-] " cRST
         "Hmm, looks like the target binary terminated before we could complete a\n"
         "    handshake with the injected code. There are %s probable explanations:\n\n"

         "%s"
         "    - The current memory limit (%s) is too restrictive, causing an OOM\n"
         "      fault in the dynamic linker. This can be fixed with the -m option. A\n"
         "      simple way to confirm the diagnosis may be:\n\n"

#ifdef RLIMIT_AS
         "      ( ulimit -Sv $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#else
         "      ( ulimit -Sd $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#endif /* ^RLIMIT_AS */

         "      Tip: you can use http://jwilk.net/software/recidivm to quickly\n"
         "      estimate the required amount of virtual memory for the binary.\n\n"

         "    - Less likely, there is a horrible bug in the fuzzer. If other options\n"
         "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n",
         getenv(DEFER_ENV_VAR) ? "three" : "two",
         getenv(DEFER_ENV_VAR) ?
         "    - You are using deferred forkserver, but __AFL_INIT() is never\n"
         "      reached before the program terminates.\n\n" : "",
         DMS(mem_limit << 20), mem_limit - 1);

  }

  FATAL("Fork server handshake failed");    //打印信息，终止

}


/* Execute target application, monitoring for timeouts. Return status
   information. The called program will update trace_bits[]. 执行目标应用程序，监视超时。 返回状态信息。 被调用的程序会更新trace_bits[] */
/*
  清空共享内存值

  哑模式和noforkserver通过fork将本进程转为测试程序,然后fork子进程作为fuzz主程序
  非上述情况，则通过管道控制之前的fork进程创建子进程
  
  随后通过设置定时器，检测子进程的运行状态，返回对应的状态码

  该函数涉及到了路径规整，用于后续检测是否发现新的路径

*/
static u8 run_target(char** argv, u32 timeout) {    //程序参数、执行超时时间

  static struct itimerval it;
  static u32 prev_timed_out = 0;
  static u64 exec_ms = 0;

  int status = 0;
  u32 tb4;

  child_timed_out = 0;  // 跟踪进程超时？

  /* After this memset, trace_bits[] are effectively volatile, so we
     must prevent any earlier operations from venturing into that
     territory. */

  memset(trace_bits, 0, MAP_SIZE);    //共享内存置0
  MEM_BARRIER();

  /* If we're running in "dumb" mode, we can't rely on the fork server
     logic compiled into the target program, so we will just keep calling
     execve(). There is a bit of code duplication between here and 
     init_forkserver(), but c'est la vie.  
     如果我们在“哑”模式下运行，我们不能依赖编译到目标程序中的 fork 服务器逻辑，因此我们将继续调用 execve()。 这里和 init_forkserver() 之间有一些代码重复，但这就是生活。*/

  if (dumb_mode == 1 || no_forkserver) {  //哑模式或者不允许启用forkserver

    child_pid = fork();   //创建子进程

    if (child_pid < 0) PFATAL("fork() failed");   //fork失败，终止

    if (!child_pid) {   //当前进程

      struct rlimit r;

      if (mem_limit) {    //指定了内存限制

        r.rlim_max = r.rlim_cur = ((rlim_t)mem_limit) << 20;    //MB转为KB

#ifdef RLIMIT_AS

        setrlimit(RLIMIT_AS, &r); /* Ignore errors */   //设置进程空间的大小

#else

        setrlimit(RLIMIT_DATA, &r); /* Ignore errors */   //设置数据段的大小

#endif /* ^RLIMIT_AS */

      }

      //设置核心转储文件的大小限制;禁用核心转储,这意味着在程序崩溃时，操作系统将不会生成包含程序崩溃时内存映像的核心转储文件
      r.rlim_max = r.rlim_cur = 0;
      setrlimit(RLIMIT_CORE, &r); /* Ignore errors */     //设置转储

      /* Isolate the process and configure standard descriptors. If out_file is
         specified, stdin is /dev/null; otherwise, out_fd is cloned instead. */

      setsid();   //断开与原来控制终端的关联，将当前进程转为守护进程

      dup2(dev_null_fd, 1); //设置标准输出重定向为/dev/null
      dup2(dev_null_fd, 2);  //设置错误输出重定向为/dev/null

      if (out_file) {
        //如果指定了输出文件，则被测试程序将通过文件获取数据。因此将标准输入重定向为/dev/null
        dup2(dev_null_fd, 0);

      } else {
        //未指定输出文件，则被测试程序将从标准输入获取数据，因此将标准输入重定向为中间文件
        dup2(out_fd, 0);
        close(out_fd);

      }

      /* On Linux, would be faster to use O_CLOEXEC. Maybe TODO. 在 Linux 上，使用 O_CLOEXEC 会更快。 也许待办事项。 */
      //关闭文件描述符
      close(dev_null_fd);
      close(out_dir_fd);
      close(dev_urandom_fd);
      close(fileno(plot_file));   //Gnuplot输出文件（图形数据统计）

      /* Set sane defaults for ASAN if nothing else specified.  如果没有其他指定，请为 ASAN 设置合理的默认值。*/

      setenv("ASAN_OPTIONS", "abort_on_error=1:"
                             "detect_leaks=0:"
                             "symbolize=0:"
                             "allocator_may_return_null=1", 0);

      setenv("MSAN_OPTIONS", "exit_code=" STRINGIFY(MSAN_ERROR) ":"
                             "symbolize=0:"
                             "msan_track_origins=0", 0);

      execv(target_path, argv);   //将当前进程转为被测试程序。执行成功，当前进程转为了被测试程序，且不会返回

      /* Use a distinctive bitmap value to tell the parent about execv()
         falling through. */

      //执行失败，将共享内存设置为指定标记，告知fuzzer程序 被测试程序运行失败
      *(u32*)trace_bits = EXEC_FAIL_SIG;
      exit(0);  //退出

    }

  } else {
     //非哑模式且允许启用forkserver

    s32 res;

    /* In non-dumb mode, we have the fork server up and running, so simply
       tell it to have at it, and then read back PID. 
       在非哑模式下，我们让fork服务器启动并运行，所以简单告诉它有它，然后读回PID。*/

    if ((res = write(fsrv_ctl_fd, &prev_timed_out, 4)) != 4) {  //检测是否可以向子进程写入数据

      if (stop_soon) return 0;    //检测失败，查询stop_soon，返回
      RPFATAL(res, "Unable to request new process from fork server (OOM?)");    //检测失败，终止程序

    }

    if ((res = read(fsrv_st_fd, &child_pid, 4)) != 4) {   //读取失败子进程数据失败

      if (stop_soon) return 0;   //检测失败，查询stop_soon，返回
      RPFATAL(res, "Unable to request new process from fork server (OOM?)");     //检测失败，终止程序

    }

    if (child_pid <= 0) FATAL("Fork server is misbehaving (OOM?)");   //子进程异常，终止

  }

  /* Configure timeout, as requested by user, then wait for child to terminate.   根据用户的请求配置超时，然后等待子进程终止。*/

  
  it.it_value.tv_sec = (timeout / 1000);
  it.it_value.tv_usec = (timeout % 1000) * 1000;

  setitimer(ITIMER_REAL, &it, NULL);  //设置超时定时器，时间一到发送SIGALRM信号
                                      //setup_signal_handlers中设置了SIGALRM处理函数为handle_timeout，当child_pid == -1 && forksrv_pid > 0,则关闭forksrv_pid，然后设置child_timed_out
                                      
  /* The SIGALRM handler simply kills the child_pid and sets child_timed_out. SIGALRM 处理程序只是杀死 child_pid 并设置 child_timed_out。 */

  if (dumb_mode == 1 || no_forkserver) {   //哑模式或者不允许启用forkserver

    if (waitpid(child_pid, &status, 0) <= 0) PFATAL("waitpid() failed");    //等待子进程退出，超时杀死进程从而获得函数执行

  } else {

    s32 res;

    if ((res = read(fsrv_st_fd, &status, 4)) != 4) {    //读取子进程状态，超时杀死进程从而获得函数执行

      if (stop_soon) return 0;  //检测失败，查询stop_soon，返回
      RPFATAL(res, "Unable to communicate with fork server (OOM?)");   //检测失败，终止程序

    }

  }

  if (!WIFSTOPPED(status)) child_pid = 0;   //子进程未被停止则置为0

  getitimer(ITIMER_REAL, &it);    //获取定时器
  exec_ms = (u64) timeout - (it.it_value.tv_sec * 1000 +    //计算本次测试程序执行的时间
                             it.it_value.tv_usec / 1000);
  //关闭定时器
  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;
  setitimer(ITIMER_REAL, &it, NULL);

  total_execs++;    //被测试程序执行次数+1

  /* Any subsequent operations on trace_bits must not be moved by the
     compiler below this point. Past this location, trace_bits[] behave
     very normally and do not have to be treated as volatile. 
     编译器不得将trace_bits 上的任何后续操作移至此点以下。 过了这个位置，trace_bits[] 的行为就非常正常，不必被视为易失性的。*/

  MEM_BARRIER();

  tb4 = *(u32*)trace_bits;    //获取共享内存起始值，用于检测运行被测试程序失败

#ifdef WORD_SIZE_64
  classify_counts((u64*)trace_bits);
#else
  classify_counts((u32*)trace_bits);    //进行数据规整
#endif /* ^WORD_SIZE_64 */

  prev_timed_out = child_timed_out;   //进程超时

  /* Report outcome to caller. */
  //检测程序执行状态
  if (WIFSIGNALED(status) && !stop_soon) {    //子进程是因为一个信号终止，且没有stop_soon标志

    kill_signal = WTERMSIG(status);   //获取导致子进程终止的信号编号

    if (child_timed_out && kill_signal == SIGKILL) return FAULT_TMOUT;    //存在超时状态，则子进程信号为SIGKILL，说明本次测试超时，子进程被强制关闭，返回状态码

    return FAULT_CRASH;   //其他状态为程序crash

  }

  /* A somewhat nasty hack for MSAN, which doesn't support abort_on_error and
     must use a special exit code. 对MSAN来说有点令人讨厌的hack，它不支持bort_on_error并且必须使用特殊的退出代码。*/

  if (uses_asan && WEXITSTATUS(status) == MSAN_ERROR) {   //启用了uses_asan，且退出状态码为MSAN_ERROR，说明程序崩溃
    kill_signal = 0;
    return FAULT_CRASH;   
  }

  if ((dumb_mode == 1 || no_forkserver) && tb4 == EXEC_FAIL_SIG)    //哑模式或不启用foreserver，同时共享内存起始设置为了被测试进程执行失败标志
    return FAULT_ERROR;   //程序执行错误

  /* It makes sense to account for the slowest units only if the testcase was run
  under the user defined timeout.仅当测试用例在用户定义的超时下运行时，才有意义考虑最慢的单元。 */
  if (!(timeout > exec_tmout) && (slowest_exec_ms < exec_ms)) {   
    slowest_exec_ms = exec_ms;      //用户指定的超时时间小于默认超时时间且本次执行时间更慢，则设置最慢执行时间
  }

  return FAULT_NONE;    //无异常

}


/* Write modified data to file for testing. If out_file is set, the old file
   is unlinked and a new one is created. Otherwise, out_fd is rewound and
   truncated. 
   将修改后的数据写入文件进行测试。 如果设置了 out_file，则取消旧文件的链接并创建一个新文件。 否则，out_fd将被倒回并被截断。*/

static void write_to_testcase(void* mem, u32 len) {   //文件内存，文件大小

  s32 fd = out_fd;

  if (out_file) {   //指定输出文件

    unlink(out_file); /* Ignore errors. */    //删除文件

    fd = open(out_file, O_WRONLY | O_CREAT | O_EXCL, 0600);   //创建文件

    if (fd < 0) PFATAL("Unable to create '%s'", out_file);    //打开失败，终止

  } else lseek(fd, 0, SEEK_SET);    //设置文件偏移

  ck_write(fd, mem, len, out_file);   //写入数据

  if (!out_file) {    //没有指定输出文件

    if (ftruncate(fd, len)) PFATAL("ftruncate() failed");   //截断文件
    lseek(fd, 0, SEEK_SET); //设置文件偏移

  } else close(fd);   //关闭本次打开的文件

}


/* The same, but with an adjustable gap. Used for trimming. 相同，但间隙可调。 用于修剪。*/

//排除内存指定区域的数据并写入到输出文件
static void write_with_gap(void* mem, u32 len, u32 skip_at, u32 skip_len) {

  s32 fd = out_fd;
  u32 tail_len = len - skip_at - skip_len;

  if (out_file) {   

    //指定了输出文件则删除并重新打开
    unlink(out_file); /* Ignore errors. */

    fd = open(out_file, O_WRONLY | O_CREAT | O_EXCL, 0600);

    if (fd < 0) PFATAL("Unable to create '%s'", out_file);

  } else lseek(fd, 0, SEEK_SET);    //未指定输出文件，则设置全局fd文件描述符偏移为0

  if (skip_at) ck_write(fd, mem, skip_at, out_file);    //指定了跳过的起始点，则将跳过起始点的数据写入文件

  if (tail_len) ck_write(fd, mem + skip_at + skip_len, tail_len, out_file);   //跳过指定数据后，还存在数据，则将剩余数据写入到文件

  if (!out_file) {  
    
    //未指定输出文件，则截断临时文件
    if (ftruncate(fd, len - skip_len)) PFATAL("ftruncate() failed");
    lseek(fd, 0, SEEK_SET);   //设置文件偏移

  } else close(fd);

}


static void show_stats(void);

/* Calibrate a new test case. This is done when processing the input directory
   to warn about flaky or otherwise problematic test cases early on; and when
   new paths are discovered to detect variable behavior and so on.
   校准新的测试用例。 这是在处理输入目录以尽早警告不稳定或其他有问题的测试用例时完成的； 当发现新路径来检测可变行为时等等。 */
// 多次运行被测试程序，评估同一个测试用例，并根据共享内存信息，更新测试用例和全局通信信息
static u8 calibrate_case(char** argv, struct queue_entry* q, u8* use_mem,   //参数、测试用例、文件内存
                         u32 handicap, u8 from_queue) {   

  static u8 first_trace[MAP_SIZE];

  u8  fault = 0, new_bits = 0, var_detected = 0, hnb = 0,
      first_run = (q->exec_cksum == 0);

  u64 start_us, stop_us;
   
  s32 old_sc = stage_cur, old_sm = stage_max;   //保存原始值
  u32 use_tmout = exec_tmout;   //运行超时时间
  u8* old_sn = stage_name;    //保存原始值

  /* Be a bit more generous about timeouts when resuming sessions, or when
     trying to calibrate already-added finds. This helps avoid trouble due
     to intermittent latency. 在恢复会话或尝试校准已添加的发现时，对超时要宽容一些。 这有助于避免由于间歇性延迟而产生的问题*/

  if (!from_queue || resuming_fuzz)     //恢复会话或尝试校准已添加的测试用例
    use_tmout = MAX(exec_tmout + CAL_TMOUT_ADD,
                    exec_tmout * CAL_TMOUT_PERC / 100);     //设置宽容的运行超时时间

  q->cal_failed++;    //假定校准失败，后续会置0

  stage_name = "calibration"; //
  stage_max  = fast_cal ? 3 : CAL_CYCLES;   //指定当前测试用例的校准次数

  /* Make sure the forkserver is up before we do anything, and let's not
     count its spin-up time toward binary calibration. 在我们做任何事情之前，请确保forkserver已启动，并且我们不要将其旋转时间计入二进制校准。*/

  if (dumb_mode != 1 && !no_forkserver && !forksrv_pid)   //不是哑模式、允许运行forkserver，且forkserver当前没有初始化
    init_forkserver(argv);  //初始化forkserver  //当前进程在这个函数内通过execv转为被测试程序，fuzzer程序则通过fork子进程继续执行;设置通信管道和检测失败原因

  if (q->exec_cksum) {      //测试用例执行后的共享内存hash，检测测试用例是否为第一次运行

    //测试用例非第一次运行
    memcpy(first_trace, trace_bits, MAP_SIZE);    //备份当前共享内存
    hnb = has_new_bits(virgin_bits);     //检测路径信息是否存在差变化
    if (hnb > new_bits) new_bits = hnb;  //更新存在新位的标识

  }

  start_us = get_cur_time_us();   //获取当前系统时间微秒

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {   //校准指定次数（样本运行的次数）
    
    u32 cksum;

    if (!first_run && !(stage_cur % stats_update_freq)) show_stats();   //非第一次运行，且达到状态更新频率，则打印状态  
                                                                      //打印状态信息，并根据条件保存相关数据到文件和设置stop_soon

    write_to_testcase(use_mem, q->len); //将测试用例写入到输出文件

    fault = run_target(argv, use_tmout);    //清空共享内存，运行被测试程序，并返回状态码

    /* stop_soon is set by the handler for Ctrl+C. When it's pressed,
       we want to bail out quickly. 
       stop_soon由Ctrl+C的处理程序设置（show_stats也会设置）。 当受到压力时，我们想迅速摆脱困境。*/

    //crash_mode通过-C参数指定为FAULT_CRASH,默认为FAULT_NONE（0）
    if (stop_soon || fault != crash_mode) goto abort_calibration;   //检测到ctrl+c 或 返回状态码与crash_mode不同时，终止校准

    if (!dumb_mode && !stage_cur && !count_bytes(trace_bits)) { //非哑模式、且是第一次校准、 且共享内存数据都为0；也就是第一校准时没有获取到路径反馈信息
      fault = FAULT_NOINST;   //设置标识
      goto abort_calibration; //终止校准
    }

    cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);   //计算共享内存的32位哈希

    if (q->exec_cksum != cksum) {   //两次执行后的共享内存hash不同（路径不同？？？）

      hnb = has_new_bits(virgin_bits);    //存在新的bit
      if (hnb > new_bits) new_bits = hnb;   //更新存在新位的标识

      if (q->exec_cksum) {  //非第一次执行

        u32 i;

        for (i = 0; i < MAP_SIZE; i++) {    //遍历64kb共享，单字节遍历

          if (!var_bytes[i] && first_trace[i] != trace_bits[i]) {   //var_bytes[i]==0 并且 本次共享内存结果与上次共享内存结果不同

            var_bytes[i] = 1;   //设置对应var_bytes值为1
            stage_max    = CAL_CYCLES_LONG;   //更新校准次数为更多，说明发现了路径变化

          }

        }

        var_detected = 1;   //设置检测标志

      } else {    //第一次执行

        q->exec_cksum = cksum;    //设置共享内存hash
        memcpy(first_trace, trace_bits, MAP_SIZE);    //备份内存

      }

    }

  }

  stop_us = get_cur_time_us();    //本次测试用例计数时间

  total_cal_us     += stop_us - start_us;     //统计总的校准程序运行时间
  total_cal_cycles += stage_max;    //统计总的校准样本执行次数

  /* OK, let's collect some stats about the performance of this test case.
     This is used for fuzzing air time calculations in calculate_score().
     好的，让我们收集一些有关此测试用例性能的统计数据。这用于在calculate_score()中模糊测试通话时间。 */

  q->exec_us     = (stop_us - start_us) / stage_max;    //计算平均执行时间
  q->bitmap_size = count_bytes(trace_bits);   //统计共享内存中不为0的字节数量
  q->handicap    = handicap;    //在哪轮循环时添加的
  q->cal_failed  = 0;     //校准状态

  total_bitmap_size += q->bitmap_size;    //统计所有位图的总位数
  total_bitmap_entries++;   //统计的位图数量   用于统计信息

  update_bitmap_score(q);   //更新共享内存字节的最优测试用例

  /* If this case didn't result in new output from the instrumentation, tell
     parent. This is a non-critical problem, but something to warn the user
     about. 如果这种情况没有导致仪器产生新的输出，请告诉家长。 这是一个不严重的问题，但需要警告用户。*/

  if (!dumb_mode && first_run && !fault && !new_bits) fault = FAULT_NOBITS;   //非哑模式、第一次校验测试用例、未检测异常、未发现新的bit

abort_calibration:

  if (new_bits == 2 && !q->has_new_cov) { //未指定-B参数时，发现了新的bit
    q->has_new_cov = 1;   //发现了新路径
    queued_with_cov++;    //具有新覆盖字节的路径
  }

  /* Mark variable paths. 标记变量路径 */

  if (var_detected) {   //发现了新的路径

 
    var_byte_count = count_bytes(var_bytes);    //统计更新后的路径数量

    if (!q->var_behavior) {   //未检测到变化
      mark_as_variable(q);    //创建状态文件，并标记为变化行为var_behavior
      queued_variable++;    //变化次数+1
    }

  }

  stage_name = old_sn;    //恢复数据
  stage_cur  = old_sc;
  stage_max  = old_sm;

  if (!first_run) show_stats();   //非第一次运行，打印运行状态

  return fault;

}


/* Examine map coverage. Called once, for first test case. */
//检查路径覆盖范围。 针对第一个测试用例调用一次。
static void check_map_coverage(void) {

  u32 i;

  if (count_bytes(trace_bits) < 100) return;      //共享内存中不为0的字节数量小于100 返回
  //遍历后32kb内存的数据
  for (i = (1 << (MAP_SIZE_POW2 - 1)); i < MAP_SIZE; i++)
    if (trace_bits[i]) return;    //发现数据

  //检测路径覆盖率，如果路径覆盖数量多，但未涉及到共享内存后32kb空间，说明计算方式存在问题
  WARNF("Recompile binary with newer version of afl to improve coverage!");

}


/* Perform dry run of all test cases to confirm that the app is working as
   expected. This is done only for the initial inputs, and only once. 
   对所有测试用例执行试运行，以确认应用程序按预期工作。 这仅针对初始输入执行，并且仅执行一次。*/
//运行被测试程序处理每个测试用例（每次测试起一个子进程，每个测试用例会测试多次），查看运行结果并输出提示
static void perform_dry_run(char** argv) {

  struct queue_entry* q = queue;
  u32 cal_failures = 0;
  u8* skip_crashes = getenv("AFL_SKIP_CRASHES");

  while (q) {   //遍历测试用例

    u8* use_mem;
    u8  res;
    s32 fd;

    u8* fn = strrchr(q->fname, '/') + 1;
    ACTF("Attempting dry run with '%s'...", fn);  //提示信息

    fd = open(q->fname, O_RDONLY);
    if (fd < 0) PFATAL("Unable to open '%s'", q->fname);    //打开文件，失败终止

    use_mem = ck_alloc_nozero(q->len);    //分配文件大小内存

    if (read(fd, use_mem, q->len) != q->len)
      FATAL("Short read from '%s'", q->fname);    //读取文件，失败终止

    close(fd);    //关闭文件

    res = calibrate_case(argv, q, use_mem, 0, 1);   //校准测试用例  //当前进程在这个函数内通过execv转为被测试程序，fuzzer程序则通过fork子进程继续执行
                                                    //多次运行被测试程序，评估同一个测试用例，并根据共享内存信息，更新测试用例和全局通信信息
    ck_free(use_mem);   //释放内存

    if (stop_soon) return;    //检测终止信号，calibrate_case中的showstate函数内设置

    if (res == crash_mode || res == FAULT_NOBITS)     //被测试程序崩溃或没有发现新的路径,打印测试用例信息
      SAYF(cGRA "    len = %u, map size = %u, exec speed = %llu us\n" cRST, 
           q->len, q->bitmap_size, q->exec_us);

    switch (res) {    //检测返回值

      case FAULT_NONE:    //正常
        //第一个测试用例
        if (q == queue) check_map_coverage();   //检测路径覆盖情况

        if (crash_mode) FATAL("Test case '%s' does *NOT* crash", fn);   //crash模式返回了正常，终止程序

        break;

      case FAULT_TMOUT:   //执行超时

        if (timeout_given) {    //通过命令行指定了执行超时时间参数

          /* The -t nn+ syntax in the command line sets timeout_given to '2' and
             instructs afl-fuzz to tolerate but skip queue entries that time
             out. 命令行中的 -t nn+ 语法将 timeout_given 设置为“2”，并指示 afl-fuzz 容忍但跳过超时的队列条目。*/


          //命令超时时间包含+，该值为2
          //从恢复文件读取超时时间，该值标识为3
          if (timeout_given > 1) {    
            WARNF("Test case results in a timeout (skipping)");
            q->cal_failed = CAL_CHANCES;    //测试用例校准失败设置为CAL_CHANCES
            cal_failures++;   //失败次数+1
            break;
          }
          //timeout_given为1，终止程序
          SAYF("\n" cLRD "[-] " cRST
               "The program took more than %u ms to process one of the initial test cases.\n"
               "    Usually, the right thing to do is to relax the -t option - or to delete it\n"
               "    altogether and allow the fuzzer to auto-calibrate. That said, if you know\n"
               "    what you are doing and want to simply skip the unruly test cases, append\n"
               "    '+' at the end of the value passed to -t ('-t %u+').\n", exec_tmout,
               exec_tmout);

          FATAL("Test case '%s' results in a timeout", fn);

        } else {
          //命令行未指定了执行超时时间参数，终止程序
          SAYF("\n" cLRD "[-] " cRST
               "The program took more than %u ms to process one of the initial test cases.\n"
               "    This is bad news; raising the limit with the -t option is possible, but\n"
               "    will probably make the fuzzing process extremely slow.\n\n"

               "    If this test case is just a fluke, the other option is to just avoid it\n"
               "    altogether, and find one that is less of a CPU hog.\n", exec_tmout);

          FATAL("Test case '%s' results in a timeout", fn);

        }

      case FAULT_CRASH:   //crash

        if (crash_mode) break;    //指定了crash模式

        if (skip_crashes) {   //指定了跳过crash
          WARNF("Test case results in a crash (skipping)");
          q->cal_failed = CAL_CHANCES;    //测试用例校准失败设置为CAL_CHANCES
          cal_failures++;   //失败次数+1
          break;
        }
        
        
        if (mem_limit) {
          //指定了内存限制的提示信息
          SAYF("\n" cLRD "[-] " cRST
               "Oops, the program crashed with one of the test cases provided. There are\n"
               "    several possible explanations:\n\n"

               "    - The test case causes known crashes under normal working conditions. If\n"
               "      so, please remove it. The fuzzer should be seeded with interesting\n"
               "      inputs - but not ones that cause an outright crash.\n\n"

               "    - The current memory limit (%s) is too low for this program, causing\n"
               "      it to die due to OOM when parsing valid files. To fix this, try\n"
               "      bumping it up with the -m setting in the command line. If in doubt,\n"
               "      try something along the lines of:\n\n"

#ifdef RLIMIT_AS
               "      ( ulimit -Sv $[%llu << 10]; /path/to/binary [...] <testcase )\n\n"
#else
               "      ( ulimit -Sd $[%llu << 10]; /path/to/binary [...] <testcase )\n\n"
#endif /* ^RLIMIT_AS */

               "      Tip: you can use http://jwilk.net/software/recidivm to quickly\n"
               "      estimate the required amount of virtual memory for the binary. Also,\n"
               "      if you are using ASAN, see %s/notes_for_asan.txt.\n\n"

#ifdef __APPLE__
  
               "    - On MacOS X, the semantics of fork() syscalls are non-standard and may\n"
               "      break afl-fuzz performance optimizations when running platform-specific\n"
               "      binaries. To fix this, set AFL_NO_FORKSRV=1 in the environment.\n\n"

#endif /* __APPLE__ */

               "    - Least likely, there is a horrible bug in the fuzzer. If other options\n"
               "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n",
               DMS(mem_limit << 20), mem_limit - 1, doc_path);

        } else {
          //未指定内存限制的提示信息
          SAYF("\n" cLRD "[-] " cRST
               "Oops, the program crashed with one of the test cases provided. There are\n"
               "    several possible explanations:\n\n"

               "    - The test case causes known crashes under normal working conditions. If\n"
               "      so, please remove it. The fuzzer should be seeded with interesting\n"
               "      inputs - but not ones that cause an outright crash.\n\n"

#ifdef __APPLE__
  
               "    - On MacOS X, the semantics of fork() syscalls are non-standard and may\n"
               "      break afl-fuzz performance optimizations when running platform-specific\n"
               "      binaries. To fix this, set AFL_NO_FORKSRV=1 in the environment.\n\n"

#endif /* __APPLE__ */

               "    - Least likely, there is a horrible bug in the fuzzer. If other options\n"
               "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n");

        }
        //终止
        FATAL("Test case '%s' results in a crash", fn);

      case FAULT_ERROR:   //执行被测试程序错误

        FATAL("Unable to execute target application ('%s')", argv[0]);  //终止

      case FAULT_NOINST:    //未检测到指令

        FATAL("No instrumentation detected"); //终止

      case FAULT_NOBITS:    //未检测到路径

        useless_at_start++;   //没有路径的测试用例数量+1

        if (!in_bitmap && !shuffle_queue) //未指定-B参数和AFL_SHUFFLE_QUEUE环境变量
          WARNF("No new instrumentation output, test case may be useless.");  

        break;

    }

    if (q->var_behavior) WARNF("Instrumentation output varies across runs.");   //发现了行为变化

    q = q->next;  //遍历下一个

  }

  if (cal_failures) { //存在测试失败的用例

    if (cal_failures == queued_paths)   //所有测试用例都失败
      FATAL("All test cases time out%s, giving up!",
            skip_crashes ? " or crash" : "");

    WARNF("Skipped %u test cases (%0.02f%%) due to timeouts%s.", cal_failures,
          ((double)cal_failures) * 100 / queued_paths,
          skip_crashes ? " or crashes" : "");

    if (cal_failures * 5 > queued_paths)    //5分之一的测试用例出现了问题
      WARNF(cLRD "High percentage of rejected test cases, check settings!");

  }

  OKF("All test cases processed.");

}


/* Helper function: link() if possible, copy otherwise. */
//尝试硬链接，失败则创建复制，存在或创建失败终止程序
static void link_or_copy(u8* old_path, u8* new_path) {

  s32 i = link(old_path, new_path);   //创建硬链接
  s32 sfd, dfd;
  u8* tmp;

  if (!i) return;   //创建成功，返回

  sfd = open(old_path, O_RDONLY);   //尝试只读打开旧文件，失败终止程序
  if (sfd < 0) PFATAL("Unable to open '%s'", old_path);

  dfd = open(new_path, O_WRONLY | O_CREAT | O_EXCL, 0600);  //尝试只写方式创建新文件（已存在创建失败），失败终止程序
  if (dfd < 0) PFATAL("Unable to create '%s'", new_path);

  tmp = ck_alloc(64 * 1024);    //分配64kb缓冲区

  while ((i = read(sfd, tmp, 64 * 1024)) > 0)     //写入到创建的文件
    ck_write(dfd, tmp, i, new_path);

  if (i < 0) PFATAL("read() failed");   //写入失败，终止程序

  ck_free(tmp);
  close(sfd);
  close(dfd);

}


static void nuke_resume_dir(void);

/* Create hard links for input test cases in the output directory, choosing
   good names and pivoting accordingly. 在输出目录中为输入测试用例创建硬链接，选择好的名称并相应地进行旋转。*/

static void pivot_inputs(void) {

  struct queue_entry* q = queue;
  u32 id = 0;

  ACTF("Creating hard links for all input files...");

  while (q) {   //遍历测试用例

    u8  *nfn, *rsl = strrchr(q->fname, '/');
    u32 orig_id;

    if (!rsl) rsl = q->fname; else rsl++;   //定位到文件名

    /* If the original file name conforms to the syntax and the recorded
       ID matches the one we'd assign, just use the original file name.
       This is valuable for resuming fuzzing runs. 
       如果原始文件名符合语法并且记录的 ID 与我们分配的 ID 匹配，则只需使用原始文件名即可。 这对于恢复模糊测试运行很有价值。*/

#ifndef SIMPLE_FILES
#  define CASE_PREFIX "id:"
#else
#  define CASE_PREFIX "id_"
#endif /* ^!SIMPLE_FILES */

    if (!strncmp(rsl, CASE_PREFIX, 3) &&    
        sscanf(rsl + 3, "%06u", &orig_id) == 1 && orig_id == id) {      
      
      //检测到id:格式，且ID与分配的ID相同,使用原始文件

      u8* src_str;
      u32 src_id;

      resuming_fuzz = 1;    //设置恢复工作标识  
      nfn = alloc_printf("%s/queue/%s", out_dir, rsl);    //使用原始名称

      /* Since we're at it, let's also try to find parent and figure out the
         appropriate depth for this entry. 既然我们已经做到了，让我们也尝试找到父项并找出该条目的适当深度。 */

      src_str = strchr(rsl + 3, ':'); //下一个:位置

      if (src_str && sscanf(src_str + 1, "%06u", &src_id ) == 1) {
        //查询到原始id

        struct queue_entry* s = queue;
        while (src_id-- && s) s = s->next;    //使用id作为数量，进行遍历
        if (s) q->depth = s->depth + 1;   //如果存在对应测试样本，则将当前样本的深度设置为父样本的深度+1

        if (max_depth < q->depth) max_depth = q->depth;   //更新最大的样本深度

      }

    } else {
      //非ID:格式，或ID不匹配
      /* No dice - invent a new name, capturing the original one as a
         substring. */
      
#ifndef SIMPLE_FILES

      u8* use_name = strstr(rsl, ",orig:");   //检测原始名偏移

      if (use_name) use_name += 6; else use_name = rsl;   //存在偏移则使用偏移后名称，否则使用当前名称
      nfn = alloc_printf("%s/queue/id:%06u,orig:%s", out_dir, id, use_name);  //拼接分配的ID和原始名称

#else

      nfn = alloc_printf("%s/queue/id_%06u", out_dir, id);

#endif /* ^!SIMPLE_FILES */

    }

    /* Pivot to the new queue entry. */

    link_or_copy(q->fname, nfn);    //链接或复制测试样本到输出目录下，并修改名称
    ck_free(q->fname);
    q->fname = nfn;   //更新测试用例的文件名

    /* Make sure that the passed_det value carries over, too. */

    if (q->passed_det) mark_as_det_done(q);   //创建确定性变异状态标识文件，确保不存在问题

    q = q->next;  //下一个
    id++;

  }

  if (in_place_resume) nuke_resume_dir();   //删除用于会话恢复的临时目录_resume，标志输入目录的工作到此结束

}


#ifndef SIMPLE_FILES

/* Construct a file name for a new test case, capturing the operation
   that led to its discovery. Uses a static buffer. 
   为新的测试用例构造一个文件名，捕获导致其发现的操作。使用静态缓冲区。*/

//根据当运行值，构建测试固定格式的用例文件名
static u8* describe_op(u8 hnb) {

  static u8 ret[256];

  if (syncing_party) {

    sprintf(ret, "sync:%s,src:%06u", syncing_party, syncing_case);

  } else {

    sprintf(ret, "src:%06u", current_entry);

    if (splicing_with >= 0)
      sprintf(ret + strlen(ret), "+%06u", splicing_with);

    sprintf(ret + strlen(ret), ",op:%s", stage_short);

    if (stage_cur_byte >= 0) {

      sprintf(ret + strlen(ret), ",pos:%u", stage_cur_byte);

      if (stage_val_type != STAGE_VAL_NONE)
        sprintf(ret + strlen(ret), ",val:%s%+d", 
                (stage_val_type == STAGE_VAL_BE) ? "be:" : "",
                stage_cur_val);

    } else sprintf(ret + strlen(ret), ",rep:%u", stage_cur_val);

  }

  if (hnb == 2) strcat(ret, ",+cov");

  return ret;

}

#endif /* !SIMPLE_FILES */


/* Write a message accompanying the crash directory :-) 在崩溃目录中写一条消息:-)*/
//在crashes目录中写入提示信息
static void write_crash_readme(void) {

  u8* fn = alloc_printf("%s/crashes/README.txt", out_dir);
  s32 fd;
  FILE* f;

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);   //打开xx/crashes/README.txt文件
  ck_free(fn);

  /* Do not die on errors here - that would be impolite. 不要在这里因错误而死——那是不礼貌的*/

  if (fd < 0) return;   //打开失败

  f = fdopen(fd, "w");    //写入流

  if (!f) {
    close(fd);
    return;  //打开失败
  }

  fprintf(f, "Command line used to find this crash:\n\n"

             "%s\n\n"

             "If you can't reproduce a bug outside of afl-fuzz, be sure to set the same\n"
             "memory limit. The limit used for this fuzzing session was %s.\n\n"

             "Need a tool to minimize test cases before investigating the crashes or sending\n"
             "them to a vendor? Check out the afl-tmin that comes with the fuzzer!\n\n"

             "Found any cool bugs in open-source tools using afl-fuzz? If yes, please drop\n"
             "me a mail at <lcamtuf@coredump.cx> once the issues are fixed - I'd love to\n"
             "add your finds to the gallery at:\n\n"

             "  http://lcamtuf.coredump.cx/afl/\n\n"

             "Thanks :-)\n",

             orig_cmdline, DMS(mem_limit << 20)); /* ignore errors */

  fclose(f);

}


/* Check if the result of an execve() during routine fuzzing is interesting,
   save or queue the input test case for further analysis if so. Returns 1 if
   entry is saved, 0 otherwise. 
   检查例程模糊处理过程中execve（）的结果是否有趣，如果是，则保存或排队输入测试用例以进行进一步分析。如果保存了条目，则返回1，否则返回0。*/
// 测试用例存在新路径则添加到用例队列并创建文件，随后检测状态码并创建挂起或崩溃文件
static u8 save_if_interesting(char** argv, void* mem, u32 len, u8 fault) {  //被测试程序参数、文件数据、文件大小、被测试程序处理测试用例的结果

  u8  *fn = "";
  u8  hnb;
  s32 fd;
  u8  keeping = 0, res;

  if (fault == crash_mode) {    //通过命令行参数指定了crash模式，未指定则为0
                                //命令行指定crash则关注crash样本，没有指定则关注普通样本？

    /* Keep only if there are new bits in the map, add to queue for
       future fuzzing, etc. 仅当映射中有新位时才保留，添加到队列以供将来模糊测试等*/

    if (!(hnb = has_new_bits(virgin_bits))) {   //检测路径信息是否存在差变化
      //未发现路径变化
      if (crash_mode) total_crashes++;    //如果是crash模式则total_crashes+1
      return 0; //因为没有发现新的路径状态，所有测试用例没有意义，返回
    }    

#ifndef SIMPLE_FILES
    //测试用例路径
    fn = alloc_printf("%s/queue/id:%06u,%s", out_dir, queued_paths,
                      describe_op(hnb));

#else

    fn = alloc_printf("%s/queue/id_%06u", out_dir, queued_paths);

#endif /* ^!SIMPLE_FILES */

    add_to_queue(fn, len, 0);   //添加新的测试用例到队列

    if (hnb == 2) {   //发现了新的路径
      queue_top->has_new_cov = 1;   //queue_top指向新添加的测试用例，设置发现了新路径标记
      queued_with_cov++;    //具有新路径的测试用例数量+1
    }

    queue_top->exec_cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);   //计算hash

    /* Try to calibrate inline; this also calls update_bitmap_score() when
       successful. 尝试在线校准； 成功时也会调用 update_bitmap_score() 。*/

    res = calibrate_case(argv, queue_top, mem, queue_cycle - 1, 0);   //校准当前测试用例

    if (res == FAULT_ERROR)
      FATAL("Unable to execute target application");    //被测试程序无法执行，退出

    //测试用例写入文件
    fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) PFATAL("Unable to create '%s'", fn);
    ck_write(fd, mem, len, fn);
    close(fd);

    keeping = 1;    //保存了测试用例

  }




  //检测运行状态
  switch (fault) {

    case FAULT_TMOUT: //超时

      /* Timeouts are not very interesting, but we're still obliged to keep
         a handful of samples. We use the presence of new bits in the
         hang-specific bitmap as a signal of uniqueness. In "dumb" mode, we
         just keep everything. -
         超时并不是很有趣，但我们仍然有义务保留一些样本。 我们使用特定于挂起的位图中新位的存在作为唯一性信号。 在“哑巴”模式下，我们只保留所有内容*/

      total_tmouts++;   //超时次数+1

      if (unique_hangs >= KEEP_UNIQUE_HANG) return keeping;   //超过了挂起测试用例上限，返回

      if (!dumb_mode) {   //非哑模式

#ifdef WORD_SIZE_64
        simplify_trace((u64*)trace_bits);
#else
        simplify_trace((u32*)trace_bits);     //简化追踪 //针对每个字节，0变为1，其他值变为0x80 
#endif /* ^WORD_SIZE_64 */

        if (!has_new_bits(virgin_tmout)) return keeping;      //超时测试用例没有发现新路径  

      }

      //超时发现了新路径 或 哑模式
      unique_tmouts++;    // 触发挂起的唯一测试用例数量+1 （新的路径状态的挂起状态）

      /* Before saving, we make sure that it's a genuine hang by re-running
         the target with a more generous timeout (unless the default timeout
         is already generous). 
         在保存之前，我们通过使用更宽松的超时重新运行目标来确保它是真正的挂起（除非默认超时已经很宽松）。*/

     
      if (exec_tmout < hang_tmout) {    
        
        //执行超时时间小于挂起超时间，再次进行检测

        u8 new_fault;
        write_to_testcase(mem, len);    //写入输出文件
        new_fault = run_target(argv, hang_tmout);   //使用挂起时间作为超时定时器运行

        /* A corner case that one user reported bumping into: increasing the
           timeout actually uncovers a crash. Make sure we don't discard it if
           so. */

        if (!stop_soon && new_fault == FAULT_CRASH) goto keep_as_crash;   //如果发现crash，则作为crash处理

        if (stop_soon || new_fault != FAULT_TMOUT) return keeping;    //指定了停止标记，或错误码不是超时，返回

      }

      //确定了程序挂起
#ifndef SIMPLE_FILES
      
      fn = alloc_printf("%s/hangs/id:%06llu,%s", out_dir,   //指定挂起文件路径
                        unique_hangs, describe_op(0));

#else

      fn = alloc_printf("%s/hangs/id_%06llu", out_dir,
                        unique_hangs);

#endif /* ^!SIMPLE_FILES */

      unique_hangs++;   //唯一挂起次数+1，前面检测了挂起时的路径

      last_hang_time = get_cur_time();    //设置最后一次挂起时间

      break;

    case FAULT_CRASH:
    //crash状态码
keep_as_crash:

      /* This is handled in a manner roughly similar to timeouts,
         except for slightly different limits and no need to re-run test
         cases. 处理方式与超时大致相似，只是限制略有不同并且无需重新运行测试用例。*/

      total_crashes++;    //总的crash次数+1

      if (unique_crashes >= KEEP_UNIQUE_CRASH) return keeping;    //唯一的crash次数拆过了最大值，返回

      if (!dumb_mode) {   //非哑模式

#ifdef WORD_SIZE_64
        simplify_trace((u64*)trace_bits);
#else
        simplify_trace((u32*)trace_bits);   //简化路径追踪
#endif /* ^WORD_SIZE_64 */

        if (!has_new_bits(virgin_crash)) return keeping;    //未发现crash路径变化，返回

      }

      if (!unique_crashes) write_crash_readme();    //首次发现crash文件，在crashes目录中写入提示信息

#ifndef SIMPLE_FILES

      fn = alloc_printf("%s/crashes/id:%06llu,sig:%02u,%s", out_dir,    //指定crash文件路径
                        unique_crashes, kill_signal, describe_op(0));

#else

      fn = alloc_printf("%s/crashes/id_%06llu_%02u", out_dir, unique_crashes,
                        kill_signal);

#endif /* ^!SIMPLE_FILES */

      unique_crashes++;   //唯一路径的crash测试用例数量+1

      last_crash_time = get_cur_time();   //设置最后一次发现crash的时间
      last_crash_execs = total_execs;   //最后一次发现crash时总的测试时间

      break;

    case FAULT_ERROR: FATAL("Unable to execute target application");      //执行时发生错误，终止程序

    default: return keeping;    //无异常，返回

  }

  /* If we're here, we apparently want to save the crash or hang
     test case, too. 如果我们在这里，我们显然也想保存崩溃或挂起测试用例。*/

  //保存挂起或crash测试用例
  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) PFATAL("Unable to create '%s'", fn);
  ck_write(fd, mem, len, fn);
  close(fd);

  ck_free(fn);

  return keeping;   //返回测试用例添加情况

}


/* When resuming, try to find the queue position to start from. This makes sense
   only when resuming, and when we can find the original fuzzer_stats. */
//查询测试用例的队列偏移（新任务从0开始，恢复任务根据状态文件中的数值决定）
static u32 find_start_position(void) {

  static u8 tmp[4096]; /* Ought to be enough for anybody. */

  u8  *fn, *off;
  s32 fd, i;
  u32 ret;

  if (!resuming_fuzz) return 0; //resuming_fuzz为0表示新的工作  
                                //测试用例目录文件名为为ID:x格式，为上次遗留的测试用例
  
  if (in_place_resume) 
    //输入路径为-时，in_place_resume置1，直接复用out_dir目录下的fuzzer_stats
    fn = alloc_printf("%s/fuzzer_stats", out_dir);//手动恢复工作
  else
    //read_testcases时，尝试检测in_dir目录下是否存在queue子目录，存在将queue子目录作为输入目录  指定out目录作为输入目录
   fn = alloc_printf("%s/../fuzzer_stats", in_dir);//自动恢复工作,查询上层目录中的fuzzer_stats文件

  fd = open(fn, O_RDONLY);   

  ck_free(fn);

  if (fd < 0) return 0; //尝试打开文件

  i = read(fd, tmp, sizeof(tmp) - 1); (void)i; /* Ignore errors */    //尝试读取整个文件
  close(fd);

  off = strstr(tmp, "cur_path          : ");  //检索cur_path
  if (!off) return 0;

  ret = atoi(off + 20);   //转为数值
  if (ret >= queued_paths) ret = 0;   //大于测试用例总数量
  return ret;   //返回测试用例的队列偏移

}


/* The same, but for timeouts. The idea is that when resuming sessions without
   -t given, we don't want to keep auto-scaling the timeout over and over
   again to prevent it from growing due to random flukes. */

static void find_timeout(void) {

  static u8 tmp[4096]; /* Ought to be enough for anybody. */

  u8  *fn, *off;
  s32 fd, i;
  u32 ret;

  if (!resuming_fuzz) return; //测试用例目录文件名为为ID:x格式，为上次遗留的测试用例
 
  if (in_place_resume)    
     //输入路径为-时，in_place_resume置1，直接复用out_dir目录下的fuzzer_stats
    fn = alloc_printf("%s/fuzzer_stats", out_dir);   //手动恢复工作
  else 
    //read_testcases时，尝试检测in_dir目录下是否存在queue子目录，存在将queue子目录作为输入目录  指定out目录作为输入目录
    fn = alloc_printf("%s/../fuzzer_stats", in_dir);   //自动恢复工作,查询上层目录中的fuzzer_stats文件

  fd = open(fn, O_RDONLY);
  ck_free(fn);

  if (fd < 0) return;   //尝试打开文件

  i = read(fd, tmp, sizeof(tmp) - 1); (void)i; /* Ignore errors */    //尝试读取整个文件
  close(fd);

  off = strstr(tmp, "exec_timeout      : ");    //检索exec_timeout
  if (!off) return;

  ret = atoi(off + 20);   //转为数值

  if (ret <= 4) return;   //太小不设置

  exec_tmout = ret;   //设置执行超时时间
  timeout_given = 3;

}


/* Update stats file for unattended monitoring.更新统计文件以进行无人值守监控。 */
//保存状态信息到文件
static void write_stats_file(double bitmap_cvg, double stability, double eps) {

  static double last_bcvg, last_stab, last_eps;
  static struct rusage usage;

  u8* fn = alloc_printf("%s/fuzzer_stats", out_dir);  //指定文件名
  s32 fd;
  FILE* f;

  fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0600);  //打开

  if (fd < 0) PFATAL("Unable to create '%s'", fn);  //打开失败，终止

  ck_free(fn);

  f = fdopen(fd, "w");  //打开写入流

  if (!f) PFATAL("fdopen() failed");    //打开失败

  /* Keep last values in case we're called from another context
     where exec/sec stats and such are not readily available.
     保留最后的值，以防我们从另一个上下文调用，其中 exec/sec 统计信息等不易获得。 */

  //保存最后一次的值，如果传入值为0，则使用最后一次值
  if (!bitmap_cvg && !stability && !eps) {
    bitmap_cvg = last_bcvg;
    stability  = last_stab;
    eps        = last_eps;
  } else {
    last_bcvg = bitmap_cvg;
    last_stab = stability;
    last_eps  = eps;
  }
  //格式化写入到文件
  fprintf(f, "start_time        : %llu\n"
             "last_update       : %llu\n"
             "fuzzer_pid        : %u\n"
             "cycles_done       : %llu\n"
             "execs_done        : %llu\n"
             "execs_per_sec     : %0.02f\n"
             "paths_total       : %u\n"
             "paths_favored     : %u\n"
             "paths_found       : %u\n"
             "paths_imported    : %u\n"
             "max_depth         : %u\n"
             "cur_path          : %u\n" /* Must match find_start_position() */
             "pending_favs      : %u\n"
             "pending_total     : %u\n"
             "variable_paths    : %u\n"
             "stability         : %0.02f%%\n"
             "bitmap_cvg        : %0.02f%%\n"
             "unique_crashes    : %llu\n"
             "unique_hangs      : %llu\n"
             "last_path         : %llu\n"
             "last_crash        : %llu\n"
             "last_hang         : %llu\n"
             "execs_since_crash : %llu\n"
             "exec_timeout      : %u\n" /* Must match find_timeout() */
             "afl_banner        : %s\n"
             "afl_version       : " VERSION "\n"
             "target_mode       : %s%s%s%s%s%s%s\n"
             "command_line      : %s\n"
             "slowest_exec_ms   : %llu\n",
             start_time / 1000, get_cur_time() / 1000, getpid(),
             queue_cycle ? (queue_cycle - 1) : 0, total_execs, eps,
             queued_paths, queued_favored, queued_discovered, queued_imported,
             max_depth, current_entry, pending_favored, pending_not_fuzzed,
             queued_variable, stability, bitmap_cvg, unique_crashes,
             unique_hangs, last_path_time / 1000, last_crash_time / 1000,
             last_hang_time / 1000, total_execs - last_crash_execs,
             exec_tmout, use_banner,
             qemu_mode ? "qemu " : "", dumb_mode ? " dumb " : "",
             no_forkserver ? "no_forksrv " : "", crash_mode ? "crash " : "",
             persistent_mode ? "persistent " : "", deferred_mode ? "deferred " : "",
             (qemu_mode || dumb_mode || no_forkserver || crash_mode ||
              persistent_mode || deferred_mode) ? "" : "default",
             orig_cmdline, slowest_exec_ms);
             /* ignore errors */

  /* Get rss value from the children
     We must have killed the forkserver process and called waitpid
     before calling getrusage 
     从孩子那里获取 rss 值 我们必须在调用 getrusage 之前杀死 forkserver 进程并调用 waitpid*/
  if (getrusage(RUSAGE_CHILDREN, &usage)) {
      WARNF("getrusage failed");
  } else if (usage.ru_maxrss == 0) {
    fprintf(f, "peak_rss_mb       : not available while afl is running\n");
  } else {
#ifdef __APPLE__
    fprintf(f, "peak_rss_mb       : %zu\n", usage.ru_maxrss >> 20);
#else
    fprintf(f, "peak_rss_mb       : %zu\n", usage.ru_maxrss >> 10);
#endif /* ^__APPLE__ */
  }

  fclose(f);

}


/* Update the plot file if there is a reason to. 如果有理由更新绘图文件*/
//尝试更新绘图数据到文件
static void maybe_update_plot_file(double bitmap_cvg, double eps) {

  static u32 prev_qp, prev_pf, prev_pnf, prev_ce, prev_md;
  static u64 prev_qc, prev_uc, prev_uh;

  if (prev_qp == queued_paths && prev_pf == pending_favored && 
      prev_pnf == pending_not_fuzzed && prev_ce == current_entry &&
      prev_qc == queue_cycle && prev_uc == unique_crashes &&
      prev_uh == unique_hangs && prev_md == max_depth) return;    //没有数据需要更新时返回

  prev_qp  = queued_paths;    //更新绘图数据
  prev_pf  = pending_favored;
  prev_pnf = pending_not_fuzzed;
  prev_ce  = current_entry;
  prev_qc  = queue_cycle;
  prev_uc  = unique_crashes;
  prev_uh  = unique_hangs;
  prev_md  = max_depth;

  /* Fields in the file:

     unix_time, cycles_done, cur_path, paths_total, paths_not_fuzzed,
     favored_not_fuzzed, unique_crashes, unique_hangs, max_depth,
     execs_per_sec */

  fprintf(plot_file,    //写入到绘图文件
          "%llu, %llu, %u, %u, %u, %u, %0.02f%%, %llu, %llu, %u, %0.02f\n",
          get_cur_time() / 1000, queue_cycle - 1, current_entry, queued_paths,
          pending_not_fuzzed, pending_favored, bitmap_cvg, unique_crashes,
          unique_hangs, max_depth, eps); /* ignore errors */

  fflush(plot_file);

}



/* A helper function for maybe_delete_out_dir(), deleting all prefixed
   files in a directory. */

static u8 delete_files(u8* path, u8* prefix) {

  DIR* d;
  struct dirent* d_ent;

  d = opendir(path);    //打开目录

  if (!d) return 0;   //失败返回

  while ((d_ent = readdir(d))) {    //遍历文件

    //文件名不以.起始的；如果prefix为0，则都删除，否则匹配删除匹配前缀的
    if (d_ent->d_name[0] != '.' && (!prefix ||    
        !strncmp(d_ent->d_name, prefix, strlen(prefix)))  ) {

      u8* fname = alloc_printf("%s/%s", path, d_ent->d_name);   //拼接路径
      if (unlink(fname)) PFATAL("Unable to delete '%s'", fname);    //删除
      ck_free(fname);

    }

  }

  closedir(d);

  return !!rmdir(path);   //删除空目录
                          //如果目录下还有其他文件，则不删除

}


/* Get the number of runnable processes, with some simple smoothing. */
//获取当前可以运行进程的数量
static double get_runnable_processes(void) {

  static double res;

#if defined(__APPLE__) || defined(__FreeBSD__) || defined (__OpenBSD__)

  /* I don't see any portable sysctl or so that would quickly give us the
     number of runnable processes; the 1-minute load average can be a
     semi-decent approximation, though. */

  if (getloadavg(&res, 1) != 1) return 0;

#else

  /* On Linux, /proc/stat is probably the best way; load averages are
     computed in funny ways and sometimes don't reflect extremely short-lived
     processes well. */

  //遍历/proc/stat文件行，获取正在运行的进程和被阻塞的进程的总数量
  FILE* f = fopen("/proc/stat", "r");
  u8 tmp[1024];
  u32 val = 0;

  if (!f) return 0;

  while (fgets(tmp, sizeof(tmp), f)) {

    if (!strncmp(tmp, "procs_running ", 14) ||
        !strncmp(tmp, "procs_blocked ", 14)) val += atoi(tmp + 14);   

  }
 
  fclose(f);

  if (!res) {   
    //第一次调用该函数，res=正在运行的进程和被阻塞的进程的总数量（res为局部静态变量）
    res = val;

  } else {
    //指数移动平均算法，用于和之前的数据计算更加平滑的平均值
    res = res * (1.0 - 1.0 / AVG_SMOOTHING) +
          ((double)val) * (1.0 / AVG_SMOOTHING);

  }

#endif /* ^(__APPLE__ || __FreeBSD__ || __OpenBSD__) */

  return res;

}


/* Delete the temporary directory used for in-place session resume. */

static void nuke_resume_dir(void) {

  u8* fn;

  fn = alloc_printf("%s/_resume/.state/deterministic_done", out_dir);
  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/_resume/.state/auto_extras", out_dir);
  if (delete_files(fn, "auto_")) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/_resume/.state/redundant_edges", out_dir);
  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/_resume/.state/variable_behavior", out_dir);
  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/_resume/.state", out_dir);
  if (rmdir(fn) && errno != ENOENT) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/_resume", out_dir);
  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  return;

dir_cleanup_failed:

  FATAL("_resume directory cleanup failed");

}


/* Delete fuzzer output directory if we recognize it as ours, if the fuzzer
   is not currently running, and if the last run time isn't too great. 
   如果我们认为模糊器输出目录是我们的，如果模糊器当前没有运行，并且上次运行时间不是太长，则删除模糊器输出目录。*/

//
static void maybe_delete_out_dir(void) {

  FILE* f;
  u8 *fn = alloc_printf("%s/fuzzer_stats", out_dir);

  /* See if the output directory is locked. If yes, bail out. If not,
     create a lock that will persist for the lifetime of the process
     (this requires leaving the descriptor open).*/

  out_dir_fd = open(out_dir, O_RDONLY);   //打开输出目录
  if (out_dir_fd < 0) PFATAL("Unable to open '%s'", out_dir); //失败终止程序

#ifndef __sun
  //尝试独占目录

  if (flock(out_dir_fd, LOCK_EX | LOCK_NB) && errno == EWOULDBLOCK) { //其他进程持有了输出目录的独占锁
  
    SAYF("\n" cLRD "[-] " cRST
         "Looks like the job output directory is being actively used by another\n"
         "    instance of afl-fuzz. You will need to choose a different %s\n"
         "    or stop the other process first.\n",
         sync_id ? "fuzzer ID" : "output location");

    FATAL("Directory '%s' is in use", out_dir);   //打印消息并退出

  }

#endif /* !__sun */

  f = fopen(fn, "r");   //只读打开输出目录下的fuzzer_stats文件

  if (f) {    //存在fuzzer_stats文件
    //判决存在fuzzer_stats文件的输出目录的重要性
    //当目录重要，且指定了输入目录则退出

    u64 start_time, last_update;

    if (fscanf(f, "start_time     : %llu\n"
                  "last_update    : %llu\n", &start_time, &last_update) != 2)   //读取fuzzer起始和最后更新时间
      FATAL("Malformed data in '%s'", fn);    //读取失败退出

    fclose(f);

    /* Let's see how much work is at stake. */
    //输入路径为'-'时，设置in_place_resume

    //这里说明指定了输入路径，且最后一个更新超过起始时间25分钟
    if (!in_place_resume && last_update - start_time > OUTPUT_GRACE * 60) {
      
      /*
        超过了25分钟的有效作业，为了避免丢失数据，建议 -i - 继续延续上次工作
      */
      SAYF("\n" cLRD "[-] " cRST
           "The job output directory already exists and contains the results of more\n"
           "    than %u minutes worth of fuzzing. To avoid data loss, afl-fuzz will *NOT*\n"
           "    automatically delete this data for you.\n\n"

           "    If you wish to start a new session, remove or rename the directory manually,\n"
           "    or specify a different output location for this job. To resume the old\n"
           "    session, put '-' as the input directory in the command line ('-i -') and\n"
           "    try again.\n", OUTPUT_GRACE);

       FATAL("At-risk data found in '%s'", out_dir);    //退出

    }

  }

  ck_free(fn);

  /* The idea for in-place resume is pretty simple: we temporarily move the old
     queue/ to a new location that gets deleted once import to the new queue/
     is finished. If _resume/ already exists, the current queue/ may be
     incomplete due to an earlier abort, so we want to use the old _resume/
     dir instead, and we let rename() fail silently. */


  //未指定输入路径（恢复上次工作）   
  //指定输入路径 && 目录不重要
  //目录不重要
  //三种状态到达这里


  if (in_place_resume) {    //恢复工作

    u8* orig_q = alloc_printf("%s/queue", out_dir);

    in_dir = alloc_printf("%s/_resume", out_dir);   //指定输入目录

    rename(orig_q, in_dir); /* Ignore errors */     //将queue重命名为_resume，用做本次输入

    OKF("Output directory exists, will attempt session resume.");

    ck_free(orig_q);

  } else {
    //指定了输入目录，但是检测到目录不重要，复用

    OKF("Output directory exists but deemed OK to reuse.");

  }

  ACTF("Deleting old session data...");

  /* Okay, let's get the ball rolling! First, we need to get rid of the entries
     in <out_dir>/.synced/.../id:*, if any are present. */

  if (!in_place_resume) {   //新工作，非恢复

    fn = alloc_printf("%s/.synced", out_dir);   //删除同步目录即文件
    if (delete_files(fn, NULL)) goto dir_cleanup_failed;    //delete_files删除目录下指定前缀的文件，然后尝试删除目录
    ck_free(fn);

  }

  /* Next, we need to clean up <out_dir>/queue/.state/ subdirectories: */
  //删除queue目录及文件
  fn = alloc_printf("%s/queue/.state/deterministic_done", out_dir);
  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;   
  ck_free(fn);

  fn = alloc_printf("%s/queue/.state/auto_extras", out_dir);
  if (delete_files(fn, "auto_")) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/queue/.state/redundant_edges", out_dir);
  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/queue/.state/variable_behavior", out_dir);
  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  /* Then, get rid of the .state subdirectory itself (should be empty by now)
     and everything matching <out_dir>/queue/id:*. */

  fn = alloc_printf("%s/queue/.state", out_dir);
  if (rmdir(fn) && errno != ENOENT) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/queue", out_dir);
  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  /* All right, let's do <out_dir>/crashes/id:* and <out_dir>/hangs/id:*. */

  if (!in_place_resume) { //新工作，非恢复
    //删除crashes目录下的README.txt
    fn = alloc_printf("%s/crashes/README.txt", out_dir);
    unlink(fn); /* Ignore errors */
    ck_free(fn);

  }

  fn = alloc_printf("%s/crashes", out_dir);

  /* Make backup of the crashes directory if it's not empty and if we're
     doing in-place resume. */
  //恢复工作时，检测crashes目录；有文件备份
  if (in_place_resume && rmdir(fn)) {   //rmdir用于删除空目录

    //恢复工作，但crashes目录非空，则备份目录（重命令）

    time_t cur_t = time(0);
    struct tm* t = localtime(&cur_t);   //获取当前时间

#ifndef SIMPLE_FILES
    //根据当前时间拼接crashed目录名
    u8* nfn = alloc_printf("%s.%04u-%02u-%02u-%02u:%02u:%02u", fn,
                           t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                           t->tm_hour, t->tm_min, t->tm_sec);

#else

    u8* nfn = alloc_printf("%s_%04u%02u%02u%02u%02u%02u", fn,
                           t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                           t->tm_hour, t->tm_min, t->tm_sec);

#endif /* ^!SIMPLE_FILES */

    rename(fn, nfn); /* Ignore errors. */   //重命名目录作为备份
    ck_free(nfn);

  }

  //删除crashed目录
  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

 
  fn = alloc_printf("%s/hangs", out_dir);

  /* Backup hangs, too. */
  //恢复工作时，检测hangs目录；有文件备份
  if (in_place_resume && rmdir(fn)) {   //恢复工作，并且hang目录不为空

    time_t cur_t = time(0);
    struct tm* t = localtime(&cur_t);

#ifndef SIMPLE_FILES
    //拼接目录名
    u8* nfn = alloc_printf("%s.%04u-%02u-%02u-%02u:%02u:%02u", fn,
                           t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                           t->tm_hour, t->tm_min, t->tm_sec);

#else

    u8* nfn = alloc_printf("%s_%04u%02u%02u%02u%02u%02u", fn,
                           t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                           t->tm_hour, t->tm_min, t->tm_sec);

#endif /* ^!SIMPLE_FILES */

    rename(fn, nfn); /* Ignore errors. */   //重命名目录作为备份
    ck_free(nfn);

  }
  
  //删除目录
  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  /* And now, for some finishing touches. */
  //清理其他文件
  fn = alloc_printf("%s/.cur_input", out_dir);
  if (unlink(fn) && errno != ENOENT) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/fuzz_bitmap", out_dir);
  if (unlink(fn) && errno != ENOENT) goto dir_cleanup_failed;
  ck_free(fn);

  if (!in_place_resume) { //新工作，则删除状态文件
    fn  = alloc_printf("%s/fuzzer_stats", out_dir);
    if (unlink(fn) && errno != ENOENT) goto dir_cleanup_failed;
    ck_free(fn);
  }

  fn = alloc_printf("%s/plot_data", out_dir);
  if (unlink(fn) && errno != ENOENT) goto dir_cleanup_failed;
  ck_free(fn);

  OKF("Output dir cleanup successful.");

  /* Wow... is that all? If yes, celebrate! */

  return;   //清理结束

//清理输出目录失败，终止程序
dir_cleanup_failed:

  SAYF("\n" cLRD "[-] " cRST
       "Whoops, the fuzzer tried to reuse your output directory, but bumped into\n"
       "    some files that shouldn't be there or that couldn't be removed - so it\n"
       "    decided to abort! This happened while processing this path:\n\n"

       "    %s\n\n"
       "    Please examine and manually delete the files, or specify a different\n"
       "    output location for the tool.\n", fn);

  FATAL("Output directory cleanup failed");

}


static void check_term_size(void);


/* A spiffy retro stats screen! This is called every stats_update_freq
   execve() calls, plus in several other circumstances. 
   漂亮的复古统计屏幕！ 每次 stats_update_freq execve() 调用以及其他几种情况下都会调用此函数。*/
//打印状态信息，并根据条件保存相关数据到文件，并根据条件设置stop_soon
static void show_stats(void) {

  static u64 last_stats_ms, last_plot_ms, last_ms, last_execs;
  static double avg_exec;
  double t_byte_ratio, stab_ratio;

  u64 cur_ms;
  u32 t_bytes, t_bits;

  u32 banner_len, banner_pad;
  u8  tmp[256];

  cur_ms = get_cur_time();    //当前时间

  /* If not enough time has passed since last UI update, bail out. 如果自上次 UI 更新以来没有过去足够的时间，请退出。*/

  if (cur_ms - last_ms < 1000 / UI_TARGET_HZ) return;     //未达到UI刷新频率

  /* Check if we're past the 10 minute mark. 检查我们是否已超过 10 分钟标记。*/

  if (cur_ms - start_time > 10 * 60 * 1000) run_over10m = 1;    //当前程序运行了10分钟

  /* Calculate smoothed exec speed stats.   计算平滑的执行速度统计数据。*/

  if (!last_execs) {
  
    avg_exec = ((double)total_execs) * 1000 / (cur_ms - start_time);    //第一次调用该函数，执行这个，计算每秒平均执行的次数
    //执行次数/运行时间 = 每秒的执行次数

  } else {
    //计算了一个指示程序执行速度的平均值，并进行了平滑处理

    //当前一段时间内的平均执行速度
    double cur_avg = ((double)(total_execs - last_execs)) * 1000 /      //total_execs - last_execs指示前一次调用这个函数到本次调用，程序执行的次数
                     (cur_ms - last_ms);                                //然后计算每秒的执行次数

    /* If there is a dramatic (5x+) jump in speed, reset the indicator
       more quickly. 如果速度出现急剧 (5x+) 跳跃，请更快地重置指示器。*/

    if (cur_avg * 5 < avg_exec || cur_avg / 5 > avg_exec)   //如果当前平均速度的5倍小于整体平均速度或者5分之1大于整体平均速度
      avg_exec = cur_avg;

    avg_exec = avg_exec * (1.0 - 1.0 / AVG_SMOOTHING) +   //使用指数平滑处理，将当前平均速度与整体平均速度进行混合。这样可以使平均速度更加稳定。
               cur_avg * (1.0 / AVG_SMOOTHING);

  }

  last_ms = cur_ms;   //最后一次调用该函数的时间
  last_execs = total_execs;   //最后一次调用该函数时的执行总次数

  /* Tell the callers when to contact us (as measured in execs). 告诉调用者何时联系我们（以高管衡量）。*/

  stats_update_freq = avg_exec / (UI_TARGET_HZ * 10);   //状态更新频率
  if (!stats_update_freq) stats_update_freq = 1; 

  /* Do some bitmap stats. 做一些位图统计。*/

  t_bytes = count_non_255_bytes(virgin_bits);   //统计64kb内存中非0xff的字节数量
  t_byte_ratio = ((double)t_bytes * 100) / MAP_SIZE;    //计算测试用例的覆盖率

  if (t_bytes) 
    stab_ratio = 100 - ((double)var_byte_count) * 100 / t_bytes;    //路径未变化的比例
  else
    stab_ratio = 100;   //路径没有变化

  /* Roughly every minute, update fuzzer stats and save auto tokens.
    大约每分钟更新一次模糊器统计数据并保存自动令牌。 */

  if (cur_ms - last_stats_ms > STATS_UPDATE_SEC * 1000) {   //当前时间距离最后一次状态更新时间超过了1分钟

    last_stats_ms = cur_ms; //设置最后一次状态更新时间
    write_stats_file(t_byte_ratio, stab_ratio, avg_exec);   //保存状态信息到文件；路径未变化比例、测试用例的覆盖率、每秒的执行次数
    save_auto();  //保存自动发现的字典条目
    write_bitmap(); //保存virgin_bits数组到fuzz_bitmap文件

  }

  /* Every now and then, write plot data.  时不时地写入绘图数据*/

  if (cur_ms - last_plot_ms > PLOT_UPDATE_SEC * 1000) {     //当前时间距离最后一次绘图时间超过了5秒

    last_plot_ms = cur_ms;    //更新绘图时间
    maybe_update_plot_file(t_byte_ratio, avg_exec);   //尝试更新绘图数据到文件
 
  }

  /* Honor AFL_EXIT_WHEN_DONE and AFL_BENCH_UNTIL_CRASH. */

  if (!dumb_mode && cycles_wo_finds > 100 && !pending_not_fuzzed &&     
      getenv("AFL_EXIT_WHEN_DONE")) stop_soon = 2;    //非哑模式、100次未查询到新路径、测试用例数量为0、并且设置了AFL_EXIT_WHEN_DONE；停止状态设置为2

  if (total_crashes && getenv("AFL_BENCH_UNTIL_CRASH")) stop_soon = 2;  //AFL_BENCH_UNTIL_CRASH环境变量下发现了crash;停止状态设置为2

  /* If we're not on TTY, bail out.  如果我们不在 TTY 上，就退出。*/

  if (not_on_tty) return;   //没有在tty，直接返回

  /* Compute some mildly useful bitmap stats. 计算一些稍微有用的位图统计数据。*/

  t_bits = (MAP_SIZE << 3) - count_bits(virgin_bits);   //计算64kb中置0的位的数量

  /* Now, for the visuals... */

  if (clear_screen) {   

    SAYF(TERM_CLEAR CURSOR_HIDE);   //清空屏幕
    clear_screen = 0;

    check_term_size();    //检查终端大小是否满足输出条件

  }

  SAYF(TERM_HOME);

  if (term_too_small) {   //终端太小

    SAYF(cBRI "Your terminal is too small to display the UI.\n"
         "Please resize terminal window to at least 80x25.\n" cRST);

    return;   //打印提示信息，返回

  }


  //拼接各种数据，进行打印
  /* Let's start by drawing a centered banner. */

  banner_len = (crash_mode ? 24 : 22) + strlen(VERSION) + strlen(use_banner);
  banner_pad = (80 - banner_len) / 2;
  memset(tmp, ' ', banner_pad);

  sprintf(tmp + banner_pad, "%s " cLCY VERSION cLGN
          " (%s)",  crash_mode ? cPIN "peruvian were-rabbit" : 
          cYEL "american fuzzy lop", use_banner);

  SAYF("\n%s\n\n", tmp);

  /* "Handy" shortcuts for drawing boxes... */

#define bSTG    bSTART cGRA
#define bH2     bH bH
#define bH5     bH2 bH2 bH
#define bH10    bH5 bH5
#define bH20    bH10 bH10
#define bH30    bH20 bH10
#define SP5     "     "
#define SP10    SP5 SP5
#define SP20    SP10 SP10

  /* Lord, forgive me this. */

  SAYF(SET_G1 bSTG bLT bH bSTOP cCYA " process timing " bSTG bH30 bH5 bH2 bHB
       bH bSTOP cCYA " overall results " bSTG bH5 bRT "\n");

  if (dumb_mode) {

    strcpy(tmp, cRST);

  } else {

    u64 min_wo_finds = (cur_ms - last_path_time) / 1000 / 60;

    /* First queue cycle: don't stop now! */
    if (queue_cycle == 1 || min_wo_finds < 15) strcpy(tmp, cMGN); else

    /* Subsequent cycles, but we're still making finds. */
    if (cycles_wo_finds < 25 || min_wo_finds < 30) strcpy(tmp, cYEL); else

    /* No finds for a long time and no test cases to try. */
    if (cycles_wo_finds > 100 && !pending_not_fuzzed && min_wo_finds > 120)
      strcpy(tmp, cLGN);

    /* Default: cautiously OK to stop? */
    else strcpy(tmp, cLBL);

  }

  SAYF(bV bSTOP "        run time : " cRST "%-34s " bSTG bV bSTOP
       "  cycles done : %s%-5s  " bSTG bV "\n",
       DTD(cur_ms, start_time), tmp, DI(queue_cycle - 1));

  /* We want to warn people about not seeing new paths after a full cycle,
     except when resuming fuzzing or running in non-instrumented mode. */

  if (!dumb_mode && (last_path_time || resuming_fuzz || queue_cycle == 1 ||
      in_bitmap || crash_mode)) {

    SAYF(bV bSTOP "   last new path : " cRST "%-34s ",
         DTD(cur_ms, last_path_time));

  } else {

    if (dumb_mode)

      SAYF(bV bSTOP "   last new path : " cPIN "n/a" cRST 
           " (non-instrumented mode)        ");

     else

      SAYF(bV bSTOP "   last new path : " cRST "none yet " cLRD
           "(odd, check syntax!)      ");

  }

  SAYF(bSTG bV bSTOP "  total paths : " cRST "%-5s  " bSTG bV "\n",
       DI(queued_paths));

  /* Highlight crashes in red if found, denote going over the KEEP_UNIQUE_CRASH
     limit with a '+' appended to the count. */

  sprintf(tmp, "%s%s", DI(unique_crashes),
          (unique_crashes >= KEEP_UNIQUE_CRASH) ? "+" : "");

  SAYF(bV bSTOP " last uniq crash : " cRST "%-34s " bSTG bV bSTOP
       " uniq crashes : %s%-6s " bSTG bV "\n",
       DTD(cur_ms, last_crash_time), unique_crashes ? cLRD : cRST,
       tmp);

  sprintf(tmp, "%s%s", DI(unique_hangs),
         (unique_hangs >= KEEP_UNIQUE_HANG) ? "+" : "");

  SAYF(bV bSTOP "  last uniq hang : " cRST "%-34s " bSTG bV bSTOP 
       "   uniq hangs : " cRST "%-6s " bSTG bV "\n",
       DTD(cur_ms, last_hang_time), tmp);

  SAYF(bVR bH bSTOP cCYA " cycle progress " bSTG bH20 bHB bH bSTOP cCYA
       " map coverage " bSTG bH bHT bH20 bH2 bH bVL "\n");

  /* This gets funny because we want to print several variable-length variables
     together, but then cram them into a fixed-width field - so we need to
     put them in a temporary buffer first. */

  sprintf(tmp, "%s%s (%0.02f%%)", DI(current_entry),
          queue_cur->favored ? "" : "*",
          ((double)current_entry * 100) / queued_paths);

  SAYF(bV bSTOP "  now processing : " cRST "%-17s " bSTG bV bSTOP, tmp);

  sprintf(tmp, "%0.02f%% / %0.02f%%", ((double)queue_cur->bitmap_size) * 
          100 / MAP_SIZE, t_byte_ratio);

  SAYF("    map density : %s%-21s " bSTG bV "\n", t_byte_ratio > 70 ? cLRD : 
       ((t_bytes < 200 && !dumb_mode) ? cPIN : cRST), tmp);

  sprintf(tmp, "%s (%0.02f%%)", DI(cur_skipped_paths),
          ((double)cur_skipped_paths * 100) / queued_paths);

  SAYF(bV bSTOP " paths timed out : " cRST "%-17s " bSTG bV, tmp);

  sprintf(tmp, "%0.02f bits/tuple",
          t_bytes ? (((double)t_bits) / t_bytes) : 0);

  SAYF(bSTOP " count coverage : " cRST "%-21s " bSTG bV "\n", tmp);

  SAYF(bVR bH bSTOP cCYA " stage progress " bSTG bH20 bX bH bSTOP cCYA
       " findings in depth " bSTG bH20 bVL "\n");

  sprintf(tmp, "%s (%0.02f%%)", DI(queued_favored),
          ((double)queued_favored) * 100 / queued_paths);

  /* Yeah... it's still going on... halp? */

  SAYF(bV bSTOP "  now trying : " cRST "%-21s " bSTG bV bSTOP 
       " favored paths : " cRST "%-22s " bSTG bV "\n", stage_name, tmp);

  if (!stage_max) {

    sprintf(tmp, "%s/-", DI(stage_cur));

  } else {

    sprintf(tmp, "%s/%s (%0.02f%%)", DI(stage_cur), DI(stage_max),
            ((double)stage_cur) * 100 / stage_max);

  }

  SAYF(bV bSTOP " stage execs : " cRST "%-21s " bSTG bV bSTOP, tmp);

  sprintf(tmp, "%s (%0.02f%%)", DI(queued_with_cov),
          ((double)queued_with_cov) * 100 / queued_paths);

  SAYF("  new edges on : " cRST "%-22s " bSTG bV "\n", tmp);

  sprintf(tmp, "%s (%s%s unique)", DI(total_crashes), DI(unique_crashes),
          (unique_crashes >= KEEP_UNIQUE_CRASH) ? "+" : "");

  if (crash_mode) {

    SAYF(bV bSTOP " total execs : " cRST "%-21s " bSTG bV bSTOP
         "   new crashes : %s%-22s " bSTG bV "\n", DI(total_execs),
         unique_crashes ? cLRD : cRST, tmp);

  } else {

    SAYF(bV bSTOP " total execs : " cRST "%-21s " bSTG bV bSTOP
         " total crashes : %s%-22s " bSTG bV "\n", DI(total_execs),
         unique_crashes ? cLRD : cRST, tmp);

  }

  /* Show a warning about slow execution. */

  if (avg_exec < 100) {

    sprintf(tmp, "%s/sec (%s)", DF(avg_exec), avg_exec < 20 ?
            "zzzz..." : "slow!");

    SAYF(bV bSTOP "  exec speed : " cLRD "%-21s ", tmp);

  } else {

    sprintf(tmp, "%s/sec", DF(avg_exec));
    SAYF(bV bSTOP "  exec speed : " cRST "%-21s ", tmp);

  }

  sprintf(tmp, "%s (%s%s unique)", DI(total_tmouts), DI(unique_tmouts),
          (unique_hangs >= KEEP_UNIQUE_HANG) ? "+" : "");

  SAYF (bSTG bV bSTOP "  total tmouts : " cRST "%-22s " bSTG bV "\n", tmp);

  /* Aaaalmost there... hold on! */

  SAYF(bVR bH cCYA bSTOP " fuzzing strategy yields " bSTG bH10 bH bHT bH10
       bH5 bHB bH bSTOP cCYA " path geometry " bSTG bH5 bH2 bH bVL "\n");

  if (skip_deterministic) {

    strcpy(tmp, "n/a, n/a, n/a");

  } else {

    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            DI(stage_finds[STAGE_FLIP1]), DI(stage_cycles[STAGE_FLIP1]),
            DI(stage_finds[STAGE_FLIP2]), DI(stage_cycles[STAGE_FLIP2]),
            DI(stage_finds[STAGE_FLIP4]), DI(stage_cycles[STAGE_FLIP4]));

  }

  SAYF(bV bSTOP "   bit flips : " cRST "%-37s " bSTG bV bSTOP "    levels : "
       cRST "%-10s " bSTG bV "\n", tmp, DI(max_depth));

  if (!skip_deterministic)
    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            DI(stage_finds[STAGE_FLIP8]), DI(stage_cycles[STAGE_FLIP8]),
            DI(stage_finds[STAGE_FLIP16]), DI(stage_cycles[STAGE_FLIP16]),
            DI(stage_finds[STAGE_FLIP32]), DI(stage_cycles[STAGE_FLIP32]));

  SAYF(bV bSTOP "  byte flips : " cRST "%-37s " bSTG bV bSTOP "   pending : "
       cRST "%-10s " bSTG bV "\n", tmp, DI(pending_not_fuzzed));

  if (!skip_deterministic)
    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            DI(stage_finds[STAGE_ARITH8]), DI(stage_cycles[STAGE_ARITH8]),
            DI(stage_finds[STAGE_ARITH16]), DI(stage_cycles[STAGE_ARITH16]),
            DI(stage_finds[STAGE_ARITH32]), DI(stage_cycles[STAGE_ARITH32]));

  SAYF(bV bSTOP " arithmetics : " cRST "%-37s " bSTG bV bSTOP "  pend fav : "
       cRST "%-10s " bSTG bV "\n", tmp, DI(pending_favored));

  if (!skip_deterministic)
    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            DI(stage_finds[STAGE_INTEREST8]), DI(stage_cycles[STAGE_INTEREST8]),
            DI(stage_finds[STAGE_INTEREST16]), DI(stage_cycles[STAGE_INTEREST16]),
            DI(stage_finds[STAGE_INTEREST32]), DI(stage_cycles[STAGE_INTEREST32]));

  SAYF(bV bSTOP "  known ints : " cRST "%-37s " bSTG bV bSTOP " own finds : "
       cRST "%-10s " bSTG bV "\n", tmp, DI(queued_discovered));

  if (!skip_deterministic)
    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            DI(stage_finds[STAGE_EXTRAS_UO]), DI(stage_cycles[STAGE_EXTRAS_UO]),
            DI(stage_finds[STAGE_EXTRAS_UI]), DI(stage_cycles[STAGE_EXTRAS_UI]),
            DI(stage_finds[STAGE_EXTRAS_AO]), DI(stage_cycles[STAGE_EXTRAS_AO]));

  SAYF(bV bSTOP "  dictionary : " cRST "%-37s " bSTG bV bSTOP
       "  imported : " cRST "%-10s " bSTG bV "\n", tmp,
       sync_id ? DI(queued_imported) : (u8*)"n/a");

  sprintf(tmp, "%s/%s, %s/%s",
          DI(stage_finds[STAGE_HAVOC]), DI(stage_cycles[STAGE_HAVOC]),
          DI(stage_finds[STAGE_SPLICE]), DI(stage_cycles[STAGE_SPLICE]));

  SAYF(bV bSTOP "       havoc : " cRST "%-37s " bSTG bV bSTOP, tmp);

  if (t_bytes) sprintf(tmp, "%0.02f%%", stab_ratio);
    else strcpy(tmp, "n/a");

  SAYF(" stability : %s%-10s " bSTG bV "\n", (stab_ratio < 85 && var_byte_count > 40) 
       ? cLRD : ((queued_variable && (!persistent_mode || var_byte_count > 20))
       ? cMGN : cRST), tmp);

  if (!bytes_trim_out) {

    sprintf(tmp, "n/a, ");

  } else {

    sprintf(tmp, "%0.02f%%/%s, ",
            ((double)(bytes_trim_in - bytes_trim_out)) * 100 / bytes_trim_in,
            DI(trim_execs));

  }

  if (!blocks_eff_total) {

    u8 tmp2[128];

    sprintf(tmp2, "n/a");
    strcat(tmp, tmp2);

  } else {

    u8 tmp2[128];

    sprintf(tmp2, "%0.02f%%",
            ((double)(blocks_eff_total - blocks_eff_select)) * 100 /
            blocks_eff_total);

    strcat(tmp, tmp2);

  }

  SAYF(bV bSTOP "        trim : " cRST "%-37s " bSTG bVR bH20 bH2 bH2 bRB "\n"
       bLB bH30 bH20 bH2 bH bRB bSTOP cRST RESET_G1, tmp);

  /* Provide some CPU utilization stats. */

  if (cpu_core_count) {

    double cur_runnable = get_runnable_processes();
    u32 cur_utilization = cur_runnable * 100 / cpu_core_count;

    u8* cpu_color = cCYA;

    /* If we could still run one or more processes, use green. */

    if (cpu_core_count > 1 && cur_runnable + 1 <= cpu_core_count)
      cpu_color = cLGN;

    /* If we're clearly oversubscribed, use red. */

    if (!no_cpu_meter_red && cur_utilization >= 150) cpu_color = cLRD;

#ifdef HAVE_AFFINITY

    if (cpu_aff >= 0) {

      SAYF(SP10 cGRA "[cpu%03u:%s%3u%%" cGRA "]\r" cRST, 
           MIN(cpu_aff, 999), cpu_color,
           MIN(cur_utilization, 999));

    } else {

      SAYF(SP10 cGRA "   [cpu:%s%3u%%" cGRA "]\r" cRST,
           cpu_color, MIN(cur_utilization, 999));
 
   }

#else

    SAYF(SP10 cGRA "   [cpu:%s%3u%%" cGRA "]\r" cRST,
         cpu_color, MIN(cur_utilization, 999));

#endif /* ^HAVE_AFFINITY */

  } else SAYF("\r");

  /* Hallelujah! */

  fflush(0);

}


/* Display quick statistics at the end of processing the input directory,
   plus a bunch of warnings. Some calibration stuff also ended up here,
   along with several hardcoded constants. Maybe clean up eventually.
   在处理输入目录结束时显示快速统计信息，以及一堆警告。 一些校准内容以及几个硬编码常量也最终出现在这里。 也许最终会清理干净。 */

//显示初始化状态信息，同时根据条件设置执行超时时间和挂起时间
static void show_init_stats(void) {

  struct queue_entry* q = queue;
  u32 min_bits = 0, max_bits = 0;
  u64 min_us = 0, max_us = 0;
  u64 avg_us = 0;
  u32 max_len = 0;

  if (total_cal_cycles) avg_us = total_cal_us / total_cal_cycles;     //校准样本文件的平均时间

  while (q) {   //遍历测试用例

    if (!min_us || q->exec_us < min_us) min_us = q->exec_us;  //获取所有测试用例中最小的执行时间
    if (q->exec_us > max_us) max_us = q->exec_us;  //获取所有测试用例中最大的执行时间

    if (!min_bits || q->bitmap_size < min_bits) min_bits = q->bitmap_size;    //获取所有测试用例中最小的不为0字节数量
    if (q->bitmap_size > max_bits) max_bits = q->bitmap_size;   //获取所有测试用例中最大的不为0字节数量

    if (q->len > max_len) max_len = q->len;   //最大的测试用例大小

    q = q->next;

  }

  SAYF("\n");

  if (avg_us > (qemu_mode ? 50000 : 10000))     //执行时间是否过慢
    WARNF(cLRD "The target binary is pretty slow! See %s/perf_tips.txt.",
          doc_path);

  /* Let's keep things moving with slow binaries.  让我们用慢速二进制文件来保持进展。*/

  //造成严重破坏的周期计数除数？？？用于计算某个比例
  if (avg_us > 50000) havoc_div = 10;     /* 0-19 execs/sec   */
  else if (avg_us > 20000) havoc_div = 5; /* 20-49 execs/sec  */
  else if (avg_us > 10000) havoc_div = 2; /* 50-100 execs/sec */

  if (!resuming_fuzz) {   //不是恢复上次工作

    if (max_len > 50 * 1024)    //判断文件大小
      WARNF(cLRD "Some test cases are huge (%s) - see %s/perf_tips.txt!",
            DMS(max_len), doc_path);
    else if (max_len > 10 * 1024)
      WARNF("Some test cases are big (%s) - see %s/perf_tips.txt.",
            DMS(max_len), doc_path);

    if (useless_at_start && !in_bitmap)   //存在没有路径的测试用例数量 且没有指定-B参数              
      WARNF(cLRD "Some test cases look useless. Consider using a smaller set.");

    if (queued_paths > 100)   //判断测试用例数量
      WARNF(cLRD "You probably have far too many input files! Consider trimming down.");
    else if (queued_paths > 20)
      WARNF("You have lots of input files; try starting small.");

  }

  OKF("Here are some useful stats:\n\n"

      cGRA "    Test case count : " cRST "%u favored, %u variable, %u total\n"
      cGRA "       Bitmap range : " cRST "%u to %u bits (average: %0.02f bits)\n"
      cGRA "        Exec timing : " cRST "%s to %s us (average: %s us)\n",
      queued_favored, queued_variable, queued_paths, min_bits, max_bits, 
      ((double)total_bitmap_size) / (total_bitmap_entries ? total_bitmap_entries : 1),
      DI(min_us), DI(max_us), DI(avg_us));

  if (!timeout_given) {   //未给定执行超时时间

    /* Figure out the appropriate timeout. The basic idea is: 5x average or
       1x max, rounded up to EXEC_TM_ROUND ms and capped at 1 second. 
       找出适当的超时时间。 基本思想是：5x 平均值或 1x 最大值，四舍五入为 EXEC_TM_ROUND 毫秒，上限为 1 秒。

       If the program is slow, the multiplier is lowered to 2x or 3x, because
       random scheduler jitter is less likely to have any impact, and because
       our patience is wearing thin =) 
       如果程序很慢，乘数会降低到2倍或3倍，因为随机调度程序抖动不太可能产生任何影响，而且因为我们的耐心正在减弱=）*/

    //根据校准样本文件的平均时间计算超时时间
    if (avg_us > 50000) exec_tmout = avg_us * 2 / 1000;
    else if (avg_us > 10000) exec_tmout = avg_us * 3 / 1000;
    else exec_tmout = avg_us * 5 / 1000;

    exec_tmout = MAX(exec_tmout, max_us / 1000);
    exec_tmout = (exec_tmout + EXEC_TM_ROUND) / EXEC_TM_ROUND * EXEC_TM_ROUND;

    if (exec_tmout > EXEC_TIMEOUT) exec_tmout = EXEC_TIMEOUT;

    ACTF("No -t option specified, so I'll use exec timeout of %u ms.", 
         exec_tmout);

    timeout_given = 1;

  } else if (timeout_given == 3) {    //恢复上次工作获取的超时时间

    ACTF("Applying timeout settings from resumed session (%u ms).", exec_tmout);

  }

  /* In dumb mode, re-running every timing out test case with a generous time
     limit is very expensive, so let's select a more conservative default. 
     在dumb模式下，在有充足时间限制的情况下重新运行每个超时测试用例是非常昂贵的，所以让我们选择一个更保守的默认值。*/

  //当哑模式下没有给定挂起时间时，计算挂起时间
  if (dumb_mode && !getenv("AFL_HANG_TMOUT"))
    hang_tmout = MIN(EXEC_TIMEOUT, exec_tmout * 2 + 100);

  OKF("All set and ready to roll!");

}


/* Find first power of two greater or equal to val (assuming val under
   2^31).  求两个大于或等于 val 的第一个幂（假设 val 在 2^31 以下）*/

static u32 next_p2(u32 val) {

  u32 ret = 1;
  while (val > ret) ret <<= 1;
  return ret;

} 


/* Trim all new test cases to save cycles when doing deterministic checks. The
   trimmer uses power-of-two increments somewhere between 1/16 and 1/1024 of
   file size, to keep the stage short and sweet. 
   修剪所有新的测试用例以在进行确定性检查时节省周期。
    修剪器使用文件大小的 1/16 到 1/1024 之间的二次幂增量，以保持阶段简短而甜美。 */

//尝试依次剔除2的n次方大小数据来修剪测试用例
static u8 trim_case(char** argv, struct queue_entry* q, u8* in_buf) {
                    //被测试程序命令行参数、当前测试用例、测试用例文件映射地址



  static u8 tmp[64];
  static u8 clean_trace[MAP_SIZE];

  u8  needs_write = 0, fault = 0;
  u32 trim_exec = 0;
  u32 remove_len;
  u32 len_p2;

  /* Although the trimmer will be less useful when variable behavior is
     detected, it will still work to some extent, so we don't check for
     this. 
     尽管当检测到可变行为时，修剪器的用处会降低，但它仍然会在某种程度上起作用，因此我们不检查这一点。*/

  if (q->len < 5) return 0; //测试用例大小小于5直接返回

  stage_name = tmp;   //指定终端显示的阶段名称
  bytes_trim_in += q->len;    //进入修剪器的字节数

  /* Select initial chunk len, starting with large steps. 选择初始块长度，从大步长开始。*/

  len_p2 = next_p2(q->len);   //查询比测试用例大的2的n次方值

  remove_len = MAX(len_p2 / TRIM_START_STEPS, TRIM_MIN_BYTES);    //取两者的大值
      //len_p2 / TRIM_START_STEPS 标识约等于将当前文件分成16个块，然后获取每个块的大小
      //如果每个块大小比TRIM_MIN_BYTES小，则使用TRIM_MIN_BYTES

  /* Continue until the number of steps gets too high or the stepover
     gets too small.  继续，直到步数变得过高或步距变得太小。*/

  //len_p2 / TRIM_END_STEPS 标识约等于将当前文件分成1024个块，然后获取每个块的大小
  //如果每个块大小比TRIM_MIN_BYTES小，则使用TRIM_MIN_BYTES

  while (remove_len >= MAX(len_p2 / TRIM_END_STEPS, TRIM_MIN_BYTES)) {    //如果块大小比最小块大小大，则尝试剔除每一个块，然后检测路径变化

    u32 remove_pos = remove_len;    //设置初始的剔除位置，跳过第一个快

    sprintf(tmp, "trim %s/%s", DI(remove_len), DI(remove_len)); //打印提示信息

    stage_cur = 0;   
    stage_max = q->len / remove_len;   //计算本次剔除的最大次数

    while (remove_pos < q->len) {   //尝试文件所有块

      u32 trim_avail = MIN(remove_len, q->len - remove_pos);      //如果到了文件末尾，则使用结尾剩余的大小
      u32 cksum;

      //参数为3移除索引，参数4为移除数据长度，这个范围的数据不会被写入到输出文件
      write_with_gap(in_buf, q->len, remove_pos, trim_avail);   //排除内存指定区域的数据并写入到输出文件
                                                                //尝试移除某一个块

      fault = run_target(argv, exec_tmout);   //运行被测试程序处理裁剪后的文件
      trim_execs++;   //测试裁剪后的测试用例的数量

      if (stop_soon || fault == FAULT_ERROR) goto abort_trimming;   //检测到了终止记号，或裁剪后程序执行错误则终止裁剪

      /* Note that we don't keep track of crashes or hangs here; maybe TODO? 请注意，我们不跟踪此处的崩溃或挂起情况； 也许待办事项？*/

      cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);   //计算共享内存的hash

      /* If the deletion had no impact on the trace, make it permanent. This
         isn't perfect for variable-path inputs, but we're just making a
         best-effort pass, so it's not a big deal if we end up with false
         negatives every now and then. 
         如果删除对跟踪没有影响，请将其永久化。 这对于可变路径输入来说并不完美，但我们只是尽力通过，所以如果我们时不时地出现漏报，那也没什么大不了的。*/

      if (cksum == q->exec_cksum) {   
        //裁剪前后路径没有发生变化

        //使用尾部数据覆盖中间排除部分数据
        u32 move_tail = q->len - remove_pos - trim_avail;   //计算移动的数据大小
        q->len -= trim_avail;   //重新设置文件大小
        len_p2  = next_p2(q->len);
        memmove(in_buf + remove_pos, in_buf + remove_pos + trim_avail, 
                move_tail);   //不用担心数据问题，因为重新设置了文件大小，后续根据文件大小重新写入到文件

        /* Let's save a clean trace, which will be needed by
           update_bitmap_score once we're done with the trimming stuff.
           让我们保存一个干净的跟踪，一旦我们完成修剪工作， update_bitmap_score 将需要它。 */

        if (!needs_write) {   //未设置测试用例更新标识

          needs_write = 1;    //设置标识
          memcpy(clean_trace, trace_bits, MAP_SIZE);    //备份原始的共享内存数据，用于后续更新字节的最优测试用例
                                                        //后续还会执行，后续数据可能还会改变

        }

      } else remove_pos += remove_len;    //尝试下一个移除块

      /* Since this can be slow, update the screen every now and then. */

      if (!(trim_exec++ % stats_update_freq)) show_stats();   //裁剪次数满足了更新频率，显示当前状态
      stage_cur++;    //裁剪阶段的索引，用于显示状态信息

    } ///内部循环结束

    remove_len >>= 1;   //减小剔除数据的大小

  }

  /* If we have made changes to in_buf, we also need to update the on-disk
     version of the test case. 如果我们对 in_buf 进行了更改，我们还需要更新磁盘上的测试用例的版本。*/

  if (needs_write) {
    //修建后路径无变化，则替换原有测试用例
    s32 fd;

    unlink(q->fname); /* ignore errors */   //尝试移除

    fd = open(q->fname, O_WRONLY | O_CREAT | O_EXCL, 0600);   //打开

    if (fd < 0) PFATAL("Unable to create '%s'", q->fname);    //失败终止

    ck_write(fd, in_buf, q->len, q->fname);   //写入
    close(fd);

    memcpy(trace_bits, clean_trace, MAP_SIZE);    //还原最初的路径信息
    update_bitmap_score(q);   //更新共享内存字节的最优测试用例

  }

abort_trimming:

  bytes_trim_out += q->len;   //累加修建后的文件大小
  return fault;   //返回被测试程序运行状态码

}


/* Write a modified test case, run program, process results. Handle
   error conditions, returning 1 if it's time to bail out. This is
   a helper function for fuzz_one(). 
   编写修改后的测试用例，运行程序，处理结果。 处理错误情况，如果需要退出则返回 1。 这是 fuzz_one() 的辅助函数。*/
//运行被测试程序处理修改后的测试用例，根据运行情况决定是否放弃本次测试用例处理，不放弃则检测修改后的测试用例是否可以加入到测试用例队列
EXP_ST u8 common_fuzz_stuff(char** argv, u8* out_buf, u32 len) {
                            //被测试程序命令行参数、测试用例缓冲区、测试用例大小

  u8 fault;

  if (post_handler) {   
    //存在后处理函数，则调用该函数处理测试用例数据
    out_buf = post_handler(out_buf, &len);
    if (!out_buf || !len)   //处理后，缓冲区或大小为0则返回
      return 0;   //返回值0标识继续进行测试

  }

  write_to_testcase(out_buf, len);    //写入测试用例到输出文件

  fault = run_target(argv, exec_tmout);   //运行被测试程序处理测试用例

  if (stop_soon) return 1;    //检测到终止标志，返回值1表示不进行后续测试

  if (fault == FAULT_TMOUT) {
      //运行超时

    if (subseq_tmouts++ > TMOUT_LIMIT) {  //连续超时次数达到了阈值
      cur_skipped_paths++;  //跳过当前测试用例
      return 1; //返回值1表示不进行后续测试
    }

  } else subseq_tmouts = 0;   //连续超时次数设置为0

  /* Users can hit us with SIGUSR1 to request the current input
     to be abandoned. 用户可以使用 SIGUSR1 来请求放弃当前输入。*/

  if (skip_requested) {   
    //检测到用户自定义SIGUSR1信号，跳过本次测试用例

     skip_requested = 0;  //重置
     cur_skipped_paths++; //跳过当前测试用例
     return 1;  //返回值1表示不进行后续测试

  }

  /* This handles FAULT_ERROR for us: 这里处理FAULT_ERROR */
  
  queued_discovered += save_if_interesting(argv, out_buf, len, fault);    // 测试用例存在新路径则添加到用例队列并创建文件，随后检测状态码并创建挂起或崩溃文件

  //测试次数达到状态更新频率或者是本阶段最后一次测试
  if (!(stage_cur % stats_update_freq) || stage_cur + 1 == stage_max)   
    show_stats();   //打印状态信息

  return 0;   //正常返回

}


/* Helper to choose random block len for block operations in fuzz_one().
   Doesn't return zero, provided that max_len is > 0. 
   克隆和删除操作的块大小上限。 这些范围中的每一个都有 33% 的概率被选中，除了前两个周期，较小的块更受青睐：*/

//根据运行状态随机选择一个区间大小，用于复制和删除
static u32 choose_block_len(u32 limit) {

  u32 min_value, max_value;
  u32 rlim = MIN(queue_cycle, 3); //取测试队列的循环次数和3的最小值

  if (!run_over10m) rlim = 1;   //程序运行未超过10分钟

  //根据条件选择块区间
  switch (UR(rlim)) {

    case 0:  min_value = 1;
             max_value = HAVOC_BLK_SMALL;
             break;

    case 1:  min_value = HAVOC_BLK_SMALL;
             max_value = HAVOC_BLK_MEDIUM;
             break;

    default: 

             if (UR(10)) {

               min_value = HAVOC_BLK_MEDIUM;
               max_value = HAVOC_BLK_LARGE;

             } else {

               min_value = HAVOC_BLK_LARGE;
               max_value = HAVOC_BLK_XL;

             }

  }

  if (min_value >= limit) min_value = 1;    //最小值超过了限制

  return min_value + UR(MIN(max_value, limit) - min_value + 1);   //随机计算一个区间大小   
                                                //有可能结果为0，因此+1

}


/* Calculate case desirability score to adjust the length of havoc fuzzing.
   A helper function for fuzz_one(). Maybe some of these constants should
   go into config.h. 
   计算案例合意性分数以调整破坏模糊测试的长度。 fuzz_one() 的辅助函数。 也许其中一些常量应该放入config.h中。*/
//通过执行时间、路径信息、青睐程度、队列位置评估测试用例性能
static u32 calculate_score(struct queue_entry* q) {

  u32 avg_exec_us = total_cal_us / total_cal_cycles;    //平均校准时间
  u32 avg_bitmap_size = total_bitmap_size / total_bitmap_entries;   //平均位图大小
  u32 perf_score = 100;   //性能分数

  /* Adjust score based on execution speed of this path, compared to the
     global average. Multiplier ranges from 0.1x to 3x. Fast inputs are
     less expensive to fuzz, so we're giving them more air time. 
     与该路径相比，根据该路径的执行速度调整分数全球平均水平。 
     乘数范围从 0.1x 到 3x。 快速输入是模糊测试的成本较低，因此我们为他们提供了更多的通话时间。*/

  //比较当前测试用例的平均校准时间和总体测试用例平均校准时间的差距
  //执行时间越快越好
  if (q->exec_us * 0.1 > avg_exec_us) perf_score = 10;
  else if (q->exec_us * 0.25 > avg_exec_us) perf_score = 25;
  else if (q->exec_us * 0.5 > avg_exec_us) perf_score = 50;
  else if (q->exec_us * 0.75 > avg_exec_us) perf_score = 75;
  else if (q->exec_us * 4 < avg_exec_us) perf_score = 300;
  else if (q->exec_us * 3 < avg_exec_us) perf_score = 200;
  else if (q->exec_us * 2 < avg_exec_us) perf_score = 150;

  /* Adjust score based on bitmap size. The working theory is that better
     coverage translates to better targets. Multiplier from 0.25x to 3x.
     根据位图大小调整分数。 其工作原理是，更好的覆盖范围意味着更好的目标。 乘数从 0.25 倍到 3 倍。 */

  //比较当前测试用例的位图大小和总体测试用例平均位图大小的差距    
  //位图路径越多越好
  if (q->bitmap_size * 0.3 > avg_bitmap_size) perf_score *= 3;
  else if (q->bitmap_size * 0.5 > avg_bitmap_size) perf_score *= 2;
  else if (q->bitmap_size * 0.75 > avg_bitmap_size) perf_score *= 1.5;
  else if (q->bitmap_size * 3 < avg_bitmap_size) perf_score *= 0.25;
  else if (q->bitmap_size * 2 < avg_bitmap_size) perf_score *= 0.5;
  else if (q->bitmap_size * 1.5 < avg_bitmap_size) perf_score *= 0.75;

  /* Adjust score based on handicap. Handicap is proportional to how late
     in the game we learned about this path. Latecomers are allowed to run
     for a bit longer until they catch up with the rest. 
     根据差点调整分数。 障碍与我们在游戏中了解到这条路径的晚晚程度成正比。 迟到者可以多跑一会儿，直到赶上其他人。*/

  ////测试用例在哪轮队列循环中被处理，越受到青睐，越会优先处理
  if (q->handicap >= 4) {
    //不受到青睐的测试用例，分值比例多给些，这样虽然运行的晚，但是可以追赶上其他测试用例
    perf_score *= 4;
    q->handicap -= 4;

  } else if (q->handicap) {
    //受到青睐的测试用例，分值比例少给些，为了与其他测试用例达到均衡
    perf_score *= 2;
    q->handicap--;

  }

  /* Final adjustment based on input depth, under the assumption that fuzzing
     deeper test cases is more likely to reveal stuff that can't be
     discovered with traditional fuzzers. 
     基于输入深度的最终调整，假设模糊更深的测试用例更有可能揭示传统模糊器无法发现的东西。*/

  switch (q->depth) {  
    //测试用例的位置靠后，说明是后续添加的，可能价值更高

    case 0 ... 3:   break;    //一般为初始测试用例了
    case 4 ... 7:   perf_score *= 2; break;
    case 8 ... 13:  perf_score *= 3; break;
    case 14 ... 25: perf_score *= 4; break;
    default:        perf_score *= 5;

  }

  /* Make sure that we don't go over limit. 确保我们不超过限制。 */

  if (perf_score > HAVOC_MAX_MULT * 100) perf_score = HAVOC_MAX_MULT * 100;   //性能分数超过了最大值，设置为最大值

  return perf_score;

}


/* Helper function to see if a particular change (xor_val = old ^ new) could
   be a product of deterministic bit flips with the lengths and stepovers
   attempted by afl-fuzz. This is used to avoid dupes in some of the
   deterministic fuzzing operations that follow bit flips. We also
   return 1 if xor_val is zero, which implies that the old and attempted new
   values are identical and the exec would be a waste of time. 
   辅助函数，用于查看特定更改 (xor_val = old ^ new) 是否可能是确定性位翻转与 afl-fuzz 尝试的长度和步距的乘积。
   这用于避免位翻转之后的一些确定性模糊操作中的欺骗。
   如果 xor_val 为零，我们也会返回 1，这意味着旧值和尝试的新值是相同的，并且 exec 会浪费时间。*/

//检测运算结果的位翻转情况，是否在位翻转阶段出现过，移除重复的位翻转测试
static u8 could_be_bitflip(u32 xor_val) {
  //xor_val为计算后，发生翻转的位

  u32 sh = 0;

  if (!xor_val) return 1;   //所有位都没有翻转，说明与原值相同，这样初始化测试用例的时候就执行过了，跳过

  /* Shift left until first bit set. 左移直到设置第一位。*/

  while (!(xor_val & 1)) { sh++; xor_val >>= 1; }   //右移，移除0

  /* 1-, 2-, and 4-bit patterns are OK anywhere. */
  //仅存在1bit,连续的2bit,连续的4bit翻转
  if (xor_val == 1 || xor_val == 3 || xor_val == 15) return 1;

  /* 8-, 16-, and 32-bit patterns are OK only if shift factor is
     divisible by 8, since that's the stepover for these ops.
     仅当移位因子可被 8 整除时，8 位、16 位和 32 位模式才可以，因为这是这些操作的步长。 */

  //不可被8整除，说明存在之前未被检测的位翻转情况
  if (sh & 7) return 0;

  //仅存在1字节,连续的2字节,连续的4字节翻转
  if (xor_val == 0xff || xor_val == 0xffff || xor_val == 0xffffffff)
    return 1;

  //其他情况
  return 0;

}


/* Helper function to see if a particular value is reachable through
   arithmetic operations. Used for similar purposes. 辅助函数，用于查看是否可以通过算术运算达到特定值。 用于类似目的。*/

//检测运算结果的算术情况，是否在算术阶段出现过，移除重复的算术变异测试
static u8 could_be_arith(u32 old_val, u32 new_val, u8 blen) {

  u32 i, ov = 0, nv = 0, diffs = 0;

  if (old_val == new_val) return 1;   //值相同，初始化测试用例的时候就执行过了，跳过

  /* See if one-byte adjustments to any byte could produce this result.
  看看对任何字节进行一字节调整是否会产生此结果。 */

  //查看两个数值存在几个单字节值不同
  for (i = 0; i < blen; i++) {

    u8 a = old_val >> (8 * i),
       b = new_val >> (8 * i);

    if (a != b) { diffs++; ov = a; nv = b; }

  }

  /* If only one byte differs and the values are within range, return 1.
    如果只有一个字节不同并且值在范围内，则返回 1 */

  
  if (diffs == 1) {
    //当只有1字节不同时,查看这个字节的变化是否满足算术阶段的变化

    if ((u8)(ov - nv) <= ARITH_MAX ||
        (u8)(nv - ov) <= ARITH_MAX) return 1;   //值在加减范围内，则算术阶段处理过了，返回1

  }

  if (blen == 1) return 0;    //类型为1字节，且算术阶段未处理，则为新的变异，返回0

  /* See if two-byte adjustments to any byte would produce this result. 
    看看对任何字节进行两字节调整是否会产生此结果。 */

  diffs = 0;

  //查看两个数值存在几个双字节值不同
  for (i = 0; i < blen / 2; i++) {

    u16 a = old_val >> (16 * i),
        b = new_val >> (16 * i);

    if (a != b) { diffs++; ov = a; nv = b; }

  }

  /* If only one word differs and the values are within range, return 1.
    如果只有一个字不同且值在范围内，则返回 1。 */

   //当只有1个双字节不同时,查看这个字节的变化是否满足算术阶段的变化
  if (diffs == 1) {
    
    //小端序
    if ((u16)(ov - nv) <= ARITH_MAX ||
        (u16)(nv - ov) <= ARITH_MAX) return 1;    //值在小端序2字节加减范围内，则算术阶段处理过了，返回1

    //大端序
    ov = SWAP16(ov); nv = SWAP16(nv);

    if ((u16)(ov - nv) <= ARITH_MAX ||
        (u16)(nv - ov) <= ARITH_MAX) return 1;  //值在大端序2字节加减范围内，则算术阶段处理过了，返回1

  }

  /* Finally, let's do the same thing for dwords. 
    最后，让我们对双字做同样的事情。*/

  if (blen == 4) {  //类型长度为4字节才处理

    if ((u32)(old_val - new_val) <= ARITH_MAX ||
        (u32)(new_val - old_val) <= ARITH_MAX) return 1;  //值在小端序4字节加减范围内，则算术阶段处理过了，返回1

    new_val = SWAP32(new_val);
    old_val = SWAP32(old_val);

    if ((u32)(old_val - new_val) <= ARITH_MAX ||
        (u32)(new_val - old_val) <= ARITH_MAX) return 1;  //值在大端序4字节加减范围内，则算术阶段处理过了，返回1


  }

  return 0;   //表明当前数值未在算术变异阶段处理

}


/* Last but not least, a similar helper to see if insertion of an 
   interesting integer is redundant given the insertions done for
   shorter blen. The last param (check_le) is set if the caller
   already executed LE insertion for current blen and wants to see
   if BE variant passed in new_val is unique.
   最后但并非最不重要的一点是，有一个类似的帮助器来查看插入一个有趣的整数是否是多余的，因为插入的时间较短。
   如果调用者已经对当前blen执行了LE插入并且想要查看new_val中传递的BE变体是否唯一，则设置最后一个参数（check_le）。 */

//检测新值是否在插入有趣值的某个阶段出现过
static u8 could_be_interest(u32 old_val, u32 new_val, u8 blen, u8 check_le) {

  u32 i, j;

  if (old_val == new_val) return 1;  //值相同，初始化测试用例的时候就执行过了，跳过

  //查看检测代码时，配合对应有趣值阶段的处理逻辑食用
  //2字节有趣值分为2个阶段，小端序和大端序
  //  小端序仅检测单字节有趣值
  //  大端序则检测单字节有趣值+2字节小端序

  //4字节有趣值分为2个阶段，小端序和大端序
  //  小端序检测单字节有趣值 + 2字节大小端序
  //  大端序检测单字节有趣值 + 2字节大小端序 + 4字节小端序

  //因此这段代码要结合有趣值处理逻辑进行分析

  /* See if one-byte insertions from interesting_8 over old_val could
     produce new_val. 看看从interesting_8到old_val的一字节插入是否可以产生new_val。 */

  //单字节插入阶段
  //将每个字节替换为interesting_8元素值，检测是否产生过该值
  for (i = 0; i < blen; i++) {
    
    //遍历interesting_8
    for (j = 0; j < sizeof(interesting_8); j++) {

      u32 tval = (old_val & ~(0xff << (i * 8))) |   //将old_val的i字节值置0
                 (((u8)interesting_8[j]) << (i * 8));   //或interesting_8元素值，则将interesting_8元素插入到的i字节处

      if (new_val == tval) return 1;    //插入后与当前值相同说明有趣值阶段处理过了，返回1

    }

  }

  /* Bail out unless we're also asked to examine two-byte LE insertions
     as a preparation for BE attempts.  除非我们还被要求检查两字节 LE 插入作为 BE 尝试的准备，否则就放弃吧。*/
  //只有2字节，且不要求检查元素小端序，且之前未出现过
  if (blen == 2 && !check_le) return 0; //新的变异项目

  /* See if two-byte insertions over old_val could give us new_val. 看看在 old_val 上插入两个字节是否可以得到 new_val。 */
  //2字节插入阶段

  //将每2个字节替换为interesting_16元素值，检测是否产生过该值
  for (i = 0; i < blen - 1; i++) {
    
     //遍历interesting_16
    for (j = 0; j < sizeof(interesting_16) / 2; j++) {
      
      //2字节插入
      u32 tval = (old_val & ~(0xffff << (i * 8))) |
                 (((u16)interesting_16[j]) << (i * 8));

      if (new_val == tval) return 1;    //插入后与当前值相同说明有趣值阶段处理过了，返回1

      /* Continue here only if blen > 2.  仅当blen > 2 时才继续此处。 */

      if (blen > 2) {
        
        //检测另外一种端序的值
        tval = (old_val & ~(0xffff << (i * 8))) |
               (SWAP16(interesting_16[j]) << (i * 8));

        if (new_val == tval) return 1;     //插入后与当前值相同说明有趣值阶段处理过了，返回1

      }

    }

  }

  //4字节插入阶段

  //4字节仅作小端序检查；这是个4字节有趣值阶段使用的
  if (blen == 4 && check_le) {

    /* See if four-byte insertions could produce the same result
       (LE only).  看看四字节插入是否可以产生相同的结果（仅限 LE）。*/

    //遍历interesting_32
    for (j = 0; j < sizeof(interesting_32) / 4; j++)
      if (new_val == (u32)interesting_32[j]) return 1;    //两个值相同，返回1

  }

  return 0;   //新的变异数值

}


/* Take the current entry from the queue, fuzz it for a while. This
   function is a tad too long... returns 0 if fuzzed successfully, 1 if
   skipped or bailed out. 
   从队列中获取当前条目，模糊它一段时间。这个函数有点太长了。。。如果模糊处理成功，则返回0；如果跳过或离开，则返回1。*/

//fuzz核心函数
static u8 fuzz_one(char** argv) {

  s32 len, fd, temp_len, i, j;
  u8  *in_buf, *out_buf, *orig_in, *ex_tmp, *eff_map = 0;
  u64 havoc_queued,  orig_hit_cnt, new_hit_cnt;
  u32 splice_cycle = 0, perf_score = 100, orig_perf, prev_cksum, eff_cnt = 1;

  u8  ret_val = 1, doing_det = 0;

  u8  a_collect[MAX_AUTO_EXTRA];
  u32 a_len = 0;

#ifdef IGNORE_FINDS

  /* In IGNORE_FINDS mode, skip any entries that weren't in the
     initial data set. 在 IGNORE_FINDS 模式下，跳过初始数据集中不存在的任何条目。*/

  if (queue_cur->depth > 1) return 1;

#else
  //判断是否跳过当前测试用例

  if (pending_favored) {    
    //存在优先级较高的测试用例

    /* If we have any favored, non-fuzzed new arrivals in the queue,
       possibly skip to them at the expense of already-fuzzed or non-favored
       cases. 如果队列中有任何受青睐的、非模糊化的新来者，可能会以已经模糊化或不受青睐的情况为代价跳到它们。*/

    if ((queue_cur->was_fuzzed || !queue_cur->favored) &&       //（当前用例完成了模糊测试或不是受青睐的）同时满足跳到下一个用例概率，则跳过当前用例
        UR(100) < SKIP_TO_NEW_PROB) return 1;

  } else if (!dumb_mode && !queue_cur->favored && queued_paths > 10) {
    //非哑模式、当前测试用例不是青睐的、且测试用例数量超过10个 同时不存在优先级较高的测试用例


    /* Otherwise, still possibly skip non-favored cases, albeit less often.
       The odds of skipping stuff are higher for already-fuzzed inputs and
       lower for never-fuzzed entries.
       否则，仍然可能会跳过不受欢迎的情况，尽管频率较低。 对于已经模糊化的输入和较低或从未模糊化的条目来说，跳过内容的可能性较高。 */

    if (queue_cycle > 1 && !queue_cur->was_fuzzed) {
      //完了一轮的用例测试 且当前用例不是受青睐的

      if (UR(100) < SKIP_NFAV_NEW_PROB) return 1;   //满足跳过不受青睐的新测试用例概率

    } else {

      if (UR(100) < SKIP_NFAV_OLD_PROB) return 1;  //满足跳过不受青睐的旧测试用例概率

    }

  }

#endif /* ^IGNORE_FINDS */

  if (not_on_tty) {   //不存在tty，打印信息
    ACTF("Fuzzing test case #%u (%u total, %llu uniq crashes found)...",
         current_entry, queued_paths, unique_crashes);
    fflush(stdout);
  }

  /* Map the test case into memory.  将测试用例映射到内存中*/

  fd = open(queue_cur->fname, O_RDONLY);

  if (fd < 0) PFATAL("Unable to open '%s'", queue_cur->fname);

  len = queue_cur->len;

  orig_in = in_buf = mmap(0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

  if (orig_in == MAP_FAILED) PFATAL("Unable to mmap '%s'", queue_cur->fname);

  close(fd);

  /* We could mmap() out_buf as MAP_PRIVATE, but we end up clobbering every
     single byte anyway, so it wouldn't give us any performance or memory usage
     benefits. 
     我们可以将 mmap() out_buf 作为 MAP_PRIVATE，但无论如何我们最终都会破坏每个字节，因此它不会给我们带来任何性能或内存使用方面的好处。*/

  out_buf = ck_alloc_nozero(len);   //申请测试用例文件大小的内存

  subseq_tmouts = 0;    //连续超时次数

  cur_depth = queue_cur->depth;   //当前的测试用例编号

  /*******************************************
   * CALIBRATION (only if failed earlier on) 校准（仅当之前失败时）*
   *******************************************/

  if (queue_cur->cal_failed) {    //之前校准测试用例失败时，重新校准

    u8 res = FAULT_TMOUT;

    if (queue_cur->cal_failed < CAL_CHANCES) {    //校准失败次数小于重新校准机会

      /* Reset exec_cksum to tell calibrate_case to re-execute the testcase
         avoiding the usage of an invalid trace_bits. 重置 exec_cksum 以告诉 calibrate_case 重新执行测试用例，避免使用无效的 Trace_bits。
         For more info: https://github.com/AFLplusplus/AFLplusplus/pull/425 */

      queue_cur->exec_cksum = 0;    //重置exec_cksum以告诉calibrate_case重新执行测试用例，否则可能会使用错误的共享内存进行比较

      res = calibrate_case(argv, queue_cur, in_buf, queue_cycle - 1, 0);    //重新尝试校准，因此queue_cycle-1标识为上次循环时校准的

      if (res == FAULT_ERROR)   //被测试程序运行异常，终止
        FATAL("Unable to execute target application");

    }

    if (stop_soon || res != crash_mode) { //检测到终止或结果与crash模式不匹配
      cur_skipped_paths++;    //跳过测试用例的数量+
      goto abandon_entry;   //放弃这个测试用例
    }

  }

  /************
   * TRIMMING 修剪*
   ************/

  if (!dumb_mode && !queue_cur->trim_done) {    
    //非哑模式并且未被修剪过

    u8 res = trim_case(argv, queue_cur, in_buf);      //尝试依次剔除2的n次方大小数据来修剪测试用例  

    if (res == FAULT_ERROR)   //被测试程序运行异常，终止
      FATAL("Unable to execute target application");

    if (stop_soon) {   //检测到终止
      cur_skipped_paths++;    //跳过测试用例的数量+
      goto abandon_entry;   //放弃这个测试用例
    }

    /* Don't retry trimming, even if it failed. 即使失败，也不要重试修剪。*/

    queue_cur->trim_done = 1;   //设置裁剪标识

    if (len != queue_cur->len) len = queue_cur->len;    //裁剪成功，更新文件大小

  }

  memcpy(out_buf, in_buf, len);   //将文件最终数据复制到输出缓冲区

  /*********************
   * PERFORMANCE SCORE 表现得分 *
   *********************/

  orig_perf = perf_score = calculate_score(queue_cur);  //通过执行时间、路径信息、青睐程度、队列位置评估测试用例表现得分

  /* Skip right away if -d is given, if we have done deterministic fuzzing on
     this entry ourselves (was_fuzzed), or if it has gone through deterministic
     testing in earlier, resumed runs (passed_det). 
     如果给出-d，如果我们自己对此条目进行了确定性模糊测试（was_fuzzed），或者如果它在之前恢复的运行中经过了确定性测试（passed_det），则立即跳过。*/

  //跳过确定性变异、完成了确定性模糊测试、在恢复上次工作时发现已经完成了确定性变异
  if (skip_deterministic || queue_cur->was_fuzzed || queue_cur->passed_det)
    goto havoc_stage;   //进入非确定性变异模式

  /* Skip deterministic fuzzing if exec path checksum puts this out of scope
     for this master instance.  如果exec路径校验和超出了该主实例的范围，则跳过确定性模糊测试。*/
  //Master模式指定了master_max最大值，且exec路径校验不等于该主实例的ID-1 
  //（可能存在多个Master测试器，然后每个测试器根据测试用例的校验和来选择自己处理的测试用例，用于做确定性变异）
  if (master_max && (queue_cur->exec_cksum % master_max) != master_id - 1)
    goto havoc_stage;   //进入非确定性变异模式

  doing_det = 1;    //进行确定性变异

  /*********************************************
   * SIMPLE BITFLIP (+dictionary construction) 简单的位翻转（+字典构造）*
   *********************************************/

//翻转位
#define FLIP_BIT(_ar, _b) do { \
    u8* _arf = (u8*)(_ar); \
    u32 _bf = (_b); \
    _arf[(_bf) >> 3] ^= (128 >> ((_bf) & 7)); \
  } while (0)
  //(_bf) >> 3 ==  (_bf)/8，计算出位对应的数组索引
  //128 >> ((_bf) & 7) 用于将对应的位置1（这个置位数据是从高位向低位操作的）
  //异或用于取反 0^1=1  1^1=0

  /* Single walking bit.  1bit翻转*/

  stage_short = "flip1";    //命令行显示的阶段短名称
  stage_max   = len << 3;     //阶段处理的总次数
                              //len << 3 == len * 8 说明后续对文件的每个位都进行操作
  stage_name  = "bitflip 1/1";    //命令行显示的阶段名称

  stage_val_type = STAGE_VAL_NONE;    //阶段值类型

  orig_hit_cnt = queued_paths + unique_crashes;   //执行变异测试前用例和崩溃样本的总数量

  prev_cksum = queue_cur->exec_cksum;   //上次执行的用例校验和

  //遍历文件每一位
  //运行被测试程序处理修改后的测试用例，根据运行情况决定是否放弃本次测试用例处理，不放弃则检测修改后的测试用例是否可以加入到测试用例队列
  //通信还会根据路径信息状态，检测是否存在字典
  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    stage_cur_byte = stage_cur >> 3;    //当前操作的字节偏移量

    FLIP_BIT(out_buf, stage_cur);   //翻转位

    if (common_fuzz_stuff(argv, out_buf, len))  //运行被测试程序处理修改后的测试用例，根据运行情况决定是否放弃本次测试用例处理，不放弃则检测修改后的测试用例是否可以加入到测试用例队列
      goto abandon_entry;    //处理当前测试用例并退出函数

    FLIP_BIT(out_buf, stage_cur); //还原位

    /* While flipping the least significant bit in every byte, pull of an extra
       trick to detect possible syntax tokens. In essence, the idea is that if
       you have a binary blob like this:

       xxxxxxxxIHDRxxxxxxxx

       ...and changing the leading and trailing bytes causes variable or no
       changes in program flow, but touching any character in the "IHDR" string
       always produces the same, distinctive path, it's highly likely that
       "IHDR" is an atomically-checked magic value of special significance to
       the fuzzed format.

       We do this here, rather than as a separate stage, because it's a nice
       way to keep the operation approximately "free" (i.e., no extra execs).
       
       Empirically, performing the check when flipping the least significant bit
       is advantageous, compared to doing it at the time of more disruptive
       changes, where the program flow may be affected in more violent ways.

       The caveat is that we won't generate dictionaries in the -d mode or -S
       mode - but that's probably a fair trade-off.

       This won't work particularly well with paths that exhibit variable
       behavior, but fails gracefully, so we'll carry out the checks anyway.
      
      在翻转每个字节中的最低有效位时，使用额外的技巧来检测可能的语法标记。 本质上，这个想法是，如果你有一个像这样的二进制 blob：
        xxxxxxxxIHDRxxxxxxxx

      ...并且更改前导和尾随字节会导致程序流发生变化或没有变化，但是触摸“IHDR”字符串中的任何字符总是会产生相同的、独特的路径，“IHDR”很可能是一个原子检查的魔法 对于模糊格式具有特殊意义的值。

      我们在这里这样做，而不是作为一个单独的阶段，因为这是保持操作大致“自由”的好方法（即，没有额外的执行人员）。
            
      根据经验，与在发生更具破坏性的更改时执行检查相比，在翻转最低有效位时执行检查是有利的，在发生更具破坏性的更改时执行检查可能会以更剧烈的方式影响程序流程。

      需要注意的是，我们不会在 -d 模式或 -S 模式下生成字典 - 但这可能是一个公平的权衡。

      对于表现出可变行为的路径，这不会特别有效，但会优雅地失败，因此我们无论如何都会执行检查。
      */

    if (!dumb_mode && (stage_cur & 7) == 7) {
      //非哑模式，并且翻转完一个字节最后一位

      u32 cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);   //计算翻转一个字节最后一位的hash

      //处理的为文件的最后一位且路径校验和没有变化
      if (stage_cur == stage_max - 1 && cksum == prev_cksum) {

        /* If at end of file and we are still collecting a string, grab the
           final character and force output. 如果在文件末尾并且我们仍在收集字符串，则获取最后一个字符并强制输出。*/

        //检测的字典数组还有位置，则将文件最后一个字符加进去
        if (a_len < MAX_AUTO_EXTRA) 
          a_collect[a_len] = out_buf[stage_cur >> 3];
        a_len++;

        //检测到的字典数据满足长度要求，则尝试添加到全局字典列表中
        if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA)
          maybe_add_auto(a_collect, a_len);   //尝试添加字典到程序发现的字典列表中

      } else if (cksum != prev_cksum) {
        //检测到了路径变化

        //这里用于检测路径的状态切换，比如翻转了ABCD后，路径A切换到了B，然后翻转D后面的字符时，路径回到了A或去往了C
        //此时说明ABCD是字典，此时这个快保存本次字典，然后重新设置字典数据索引，并保存本次hash,用于后续状态切换检测
        //下面的if块是实际填充字典数据的逻辑

        /* Otherwise, if the checksum has changed, see if we have something
           worthwhile queued up, and collect that if the answer is yes. 
           否则，如果校验和已更改，请查看是否有值得排队的内容，如果答案是肯定的，则收集该内容。*/

        //检测到的字典数据满足长度要求，则尝试添加到全局字典列表中
        if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA)
          maybe_add_auto(a_collect, a_len);   //尝试添加字典到程序发现的字典列表中

        a_len = 0;    //设置字典索引为0，表示重新开始
        prev_cksum = cksum;   //更新校验和

      }

      /* Continue collecting string, but only if the bit flip actually made
         any difference - we don't want no-op tokens. 
         继续收集字符串，但前提是位翻转确实产生了任何影响 - 我们不需要无操作令牌。*/

      //本次的校验和与测试用例初始校验和不同
      if (cksum != queue_cur->exec_cksum) {
        
        //这里为实际字典数组写入字符的快，因为比较的是测试用例的初始hash

        //字典数组有空间，则添加当前字符
        if (a_len < MAX_AUTO_EXTRA) a_collect[a_len] = out_buf[stage_cur >> 3];        
        a_len++;  //字典数组索引+1

      }

    }

  }

  new_hit_cnt = queued_paths + unique_crashes;    //执行完1bit翻转后，测试用例和崩溃样本的总数量 

  stage_finds[STAGE_FLIP1]  += new_hit_cnt - orig_hit_cnt;    //1bit翻转阶段发现的新的测试用例或崩溃样本的数量
  stage_cycles[STAGE_FLIP1] += stage_max;   //1bit翻转阶段运行被测试程序处理变异用例的次数

  /* Two walking bits. 2bit翻转 */

  stage_name  = "bitflip 2/1";    //命令行显示的阶段名称
  stage_short = "flip2";  //命令行显示的阶段短名称
  stage_max   = (len << 3) - 1; //阶段处理的总次数
                              //len << 3 == len * 8 说明后续对文件的每2个位都进行操作
                              //-1是因为一次处理2个bit，不-1就超出范围了

  orig_hit_cnt = new_hit_cnt;   //执行完1bit翻转后，测试用例和崩溃样本的总数量

  //遍历文件每一位
  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    stage_cur_byte = stage_cur >> 3;    //当前操作的字节偏移量

    //翻转连续的两个位
    FLIP_BIT(out_buf, stage_cur);   
    FLIP_BIT(out_buf, stage_cur + 1);

    if (common_fuzz_stuff(argv, out_buf, len))  //运行被测试程序处理修改后的测试用例，根据运行情况决定是否放弃本次测试用例处理，不放弃则检测修改后的测试用例是否可以加入到测试用例队列
      goto abandon_entry;    //处理当前测试用例并退出函数

    //恢复连续的两个位
    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);

  }

  new_hit_cnt = queued_paths + unique_crashes;    //执行完2bit翻转后，测试用例和崩溃样本的总数量

  stage_finds[STAGE_FLIP2]  += new_hit_cnt - orig_hit_cnt;    //2bit翻转阶段发现的新的测试用例或崩溃样本的数量
  stage_cycles[STAGE_FLIP2] += stage_max;    //2bit翻转阶段运行被测试程序处理变异用例的次数

  /* Four walking bits. 四字节翻转  */

  stage_name  = "bitflip 4/1";    //命令行显示的阶段名称
  stage_short = "flip4";    //命令行显示的阶段短名称
  stage_max   = (len << 3) - 3;   //阶段处理的总次数
                              //len << 3 == len * 8 说明后续对文件的每2个位都进行操作
                              //-3是因为一次处理4个bit，不-3就超出范围了

  orig_hit_cnt = new_hit_cnt; //执行完2bit翻转后，测试用例和崩溃样本的总数量

  //遍历文件每一位
  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    stage_cur_byte = stage_cur >> 3;  //当前操作的字节偏移量

    //翻转连续的4个位
    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);
    FLIP_BIT(out_buf, stage_cur + 2);
    FLIP_BIT(out_buf, stage_cur + 3);

    if (common_fuzz_stuff(argv, out_buf, len)) //运行被测试程序处理修改后的测试用例，根据运行情况决定是否放弃本次测试用例处理，不放弃则检测修改后的测试用例是否可以加入到测试用例队列
      goto abandon_entry;    //处理当前测试用例并退出函数

    //恢复连续的4个位
    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);
    FLIP_BIT(out_buf, stage_cur + 2);
    FLIP_BIT(out_buf, stage_cur + 3);

  }

  new_hit_cnt = queued_paths + unique_crashes;    //执行完4bit翻转后，测试用例和崩溃样本的总数量

  stage_finds[STAGE_FLIP4]  += new_hit_cnt - orig_hit_cnt;   //4bit翻转阶段发现的新的测试用例或崩溃样本的数量
  stage_cycles[STAGE_FLIP4] += stage_max;  //4bit翻转阶段运行被测试程序处理变异用例的次数

  /* Effector map setup. These macros calculate:    效应器图设置。 这些宏计算：

     EFF_APOS      - position of a particular file offset in the map.   EFF_APOS - 映射中特定文件偏移的位置。
     EFF_ALEN      - length of a map with a particular number of bytes. EFF_ALEN - 具有特定字节数的映射的长度。
     EFF_SPAN_ALEN - map span for a sequence of bytes.  EFF_SPAN_ALEN - 字节序列的映射范围。

   */

//_p /8
#define EFF_APOS(_p)          ((_p) >> EFF_MAP_SCALE2)
//_x & 7
#define EFF_REM(_x)           ((_x) & ((1 << EFF_MAP_SCALE2) - 1))
// (_l/8) + (_x & 7)?1:0
#define EFF_ALEN(_l)          (EFF_APOS(_l) + !!EFF_REM(_l))
// ((_p+_l-1)/8) - (_p/8) +1
#define EFF_SPAN_ALEN(_p, _l) (EFF_APOS((_p) + (_l) - 1) - EFF_APOS(_p) + 1)

  /* Initialize effector map for the next step (see comments below). Always
     flag first and last byte as doing something. 
     初始化下一步的效应器图（参见下面的评论）。 始终将第一个和最后一个字节标记为正在执行某些操作。*/

  eff_map    = ck_alloc(EFF_ALEN(len));   //压缩文件大小，每个字节使用一个位表示
                                        //EFF_ALEN(len)表示，最后不满8字节，也是用一个字节表示
  eff_map[0] = 1;   //起始字节置1

  if (EFF_APOS(len - 1) != 0) {     //检测文件最后一个字节所在的数组索引  -1为了取索引
    eff_map[EFF_APOS(len - 1)] = 1;     //将文件最后一个字节所在的数组元素设置为1
    eff_cnt++;    //有效值+1
  }

  /* Walking byte. 单字节翻转*/
  stage_name  = "bitflip 8/8";  //命令行显示的阶段名称
  stage_short = "flip8";  //命令行显示的阶段短名称
  stage_max   = len;  //阶段处理的总次数，根据字节翻转，所以等于文件大小
    

  orig_hit_cnt = new_hit_cnt; //执行完4bit翻转后，测试用例和崩溃样本的总数量

  //遍历每个字节
  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    stage_cur_byte = stage_cur;   //当前操作的字节偏移量

    out_buf[stage_cur] ^= 0xFF;   //翻转单字节

    if (common_fuzz_stuff(argv, out_buf, len)) //运行被测试程序处理修改后的测试用例，根据运行情况决定是否放弃本次测试用例处理，不放弃则检测修改后的测试用例是否可以加入到测试用例队列
      goto abandon_entry;    //处理当前测试用例并退出函数

    /* We also use this stage to pull off a simple trick: we identify
       bytes that seem to have no effect on the current execution path
       even when fully flipped - and we skip them during more expensive
       deterministic stages, such as arithmetics or known ints. 
       我们还使用此阶段来完成一个简单的技巧：我们识别即使完全翻转也似乎对当前执行路径没有影响的字节 - 并且我们在更昂贵的确定性标记（例如算术或已知整数）期间跳过它们。*/

    if (!eff_map[EFF_APOS(stage_cur)]) {  //当前字节对应bit的元素值不为0

      u32 cksum;

      /* If in dumb mode or if the file is very short, just flag everything
         without wasting time on checksums. 如果处于哑模式或文件非常短，只需标记所有内容，而无需在校验和上浪费时间。 */

      //非哑模式、且文件大于127字节
      if (!dumb_mode && len >= EFF_MIN_LEN)
        cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);   //计算校验和
      else
        cksum = ~queue_cur->exec_cksum;   //校验和取反

      if (cksum != queue_cur->exec_cksum) {   //翻转单字节后发现了新的路径
        eff_map[EFF_APOS(stage_cur)] = 1;   //设置对应元素的值为1
        eff_cnt++;  //计数+1
        //eff_map中为0的元素说明连续的8个字节翻转后对执行路径没有影响
      }

    }
    //恢复单字节
    out_buf[stage_cur] ^= 0xFF;

  }

  /* If the effector map is more than EFF_MAX_PERC dense, just flag the
     whole thing as worth fuzzing, since we wouldn't be saving much time
     anyway. 如果效应器图的密度超过 EFF_MAX_PERC，只需将整个事情标记为值得模糊测试，因为无论如何我们都不会节省太多时间。 */

  if (eff_cnt != EFF_ALEN(len) &&
      eff_cnt * 100 / EFF_ALEN(len) > EFF_MAX_PERC) {   //超过百分90的元素置为了1

    memset(eff_map, 1, EFF_ALEN(len));    //将所有元素置1

    blocks_eff_select += EFF_ALEN(len);   //效应器图发现对路径有影响的块数量

  } else {

    blocks_eff_select += eff_cnt;    //效应器图发现对路径有影响的块数量

  }

  blocks_eff_total += EFF_ALEN(len);    //效应器图处理过的块数量

  new_hit_cnt = queued_paths + unique_crashes;    //执行完1字节翻转后，测试用例和崩溃样本的总数量


  stage_finds[STAGE_FLIP8]  += new_hit_cnt - orig_hit_cnt;  //1字节翻转阶段发现的新的测试用例或崩溃样本的数量
  stage_cycles[STAGE_FLIP8] += stage_max;   //1字节翻转阶段运行被测试程序处理变异用例的次数

  /* Two walking bytes. 2字节翻转 */

  if (len < 2) goto skip_bitflip;   //测试用例小于2字节，则跳过后续翻转

    
  stage_name  = "bitflip 16/8";   //命令行显示的阶段名称
  stage_short = "flip16";   //命令行显示的阶段短名称
  stage_cur   = 0;
  stage_max   = len - 1;    //阶段处理的总次数，根据2字节翻转，所以文件大小-1避免溢出

  orig_hit_cnt = new_hit_cnt; //执行完1字节翻转后，测试用例和崩溃样本的总数量

  for (i = 0; i < len - 1; i++) {   //遍历每个字节

    /* Let's consult the effector map... 让我们查阅效应器图... */

    //判断连续两个字节对应effmap中值是否为0，如果为0表示两个字节相关的连续N个字节的翻转都没有触发新路径
    //effmap1字节对应文件8字节，因此存在跨字节情况，这样需要16个字节都没有影响路径才会跳过
    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) { 
      stage_max--;  //检测到连续多个字节对路径没有影响，本阶段测试用例数量-1
      continue; //下一字节
    }

    stage_cur_byte = i;  //当前操作的字节偏移量

    //翻转2字节
    *(u16*)(out_buf + i) ^= 0xFFFF;

    if (common_fuzz_stuff(argv, out_buf, len)) //运行被测试程序处理修改后的测试用例，根据运行情况决定是否放弃本次测试用例处理，不放弃则检测修改后的测试用例是否可以加入到测试用例队列
        goto abandon_entry;    //处理当前测试用例并退出函数
    
    stage_cur++; //阶段索引

    //恢复2字节
    *(u16*)(out_buf + i) ^= 0xFFFF;

  }

  new_hit_cnt = queued_paths + unique_crashes;         //执行完2字节翻转后，测试用例和崩溃样本的总数量

  stage_finds[STAGE_FLIP16]  += new_hit_cnt - orig_hit_cnt;   //2字节翻转阶段发现的新的测试用例或崩溃样本的数量
  stage_cycles[STAGE_FLIP16] += stage_max;     //2字节翻转阶段运行被测试程序处理变异用例的次数

  if (len < 4) goto skip_bitflip; //测试用例小于4字节，则跳过后续翻转

  /* Four walking bytes. 4字节翻转*/

  stage_name  = "bitflip 32/8"; //命令行显示的阶段名称
  stage_short = "flip32"; //命令行显示的阶段短名称
  stage_cur   = 0;  
  stage_max   = len - 3;  //阶段处理的总次数，根据4字节翻转，所以文件大小-3避免溢出

  orig_hit_cnt = new_hit_cnt;     //执行完2字节翻转后，测试用例和崩溃样本的总数量

  for (i = 0; i < len - 3; i++) {     //遍历每个字节

    /* Let's consult the effector map... */
    //判断连续4个字节对应effmap中值是否为0，如果为0表示两个字节相关的连续N个字节的翻转都没有触发新路径
    //effmap1字节对应文件8字节，因此存在跨字节情况，这样需要16个字节都没有影响路径才会跳过
    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
        !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {
      stage_max--;  //检测到连续多个字节对路径没有影响，本阶段测试用例数量-1
      continue; //下一字节
    }

    stage_cur_byte = i;   //当前操作的字节偏移量
                
    *(u32*)(out_buf + i) ^= 0xFFFFFFFF;     //4字节翻转

    if (common_fuzz_stuff(argv, out_buf, len))  //运行被测试程序处理修改后的测试用例，根据运行情况决定是否放弃本次测试用例处理，不放弃则检测修改后的测试用例是否可以加入到测试用例队列
        goto abandon_entry;    //处理当前测试用例并退出函数

    stage_cur++;  //阶段索引

    *(u32*)(out_buf + i) ^= 0xFFFFFFFF;    //4字节恢复

  }

  new_hit_cnt = queued_paths + unique_crashes;    //执行完4字节翻转后，测试用例和崩溃样本的总数量
  
  stage_finds[STAGE_FLIP32]  += new_hit_cnt - orig_hit_cnt;     //4字节翻转阶段发现的新的测试用例或崩溃样本的数量
  stage_cycles[STAGE_FLIP32] += stage_max;     //4字节翻转阶段运行被测试程序处理变异用例的次数

skip_bitflip:
  //根据环境变量AFL_NO_ARITH跳过算术变异阶段
  if (no_arith) goto skip_arith;

  /**********************
   * ARITHMETIC INC/DEC 算术递增/递减 *
   **********************/

  /* 8-bit arithmetics.   1字节算术 */

  stage_name  = "arith 8/8";    //命令行显示的阶段名称
  stage_short = "arith8";   //命令行显示的阶段短名称
  stage_cur   = 0;
  stage_max   = 2 * len * ARITH_MAX;    //阶段处理的总次数
                                        //每个字节涉及到加法和减法，然后ARITH_MAX指定了对每个字节的处理次数，因此*2*ARITH_MAX

  stage_val_type = STAGE_VAL_LE;    //阶段值类型

  orig_hit_cnt = new_hit_cnt;   //执行完某次翻转后，测试用例和崩溃样本的总数量
  
  //变量每个字节
  for (i = 0; i < len; i++) {

    u8 orig = out_buf[i];   //保存原始字节值

    /* Let's consult the effector map... */

    //检测当前字节对应的效应器图元素是否为0，为0说明翻转该字节没有路径变化，跳过
    if (!eff_map[EFF_APOS(i)]) {
      stage_max -= 2 * ARITH_MAX;     //本阶段测试用例数量-2*ARITH_MAX ；因为每个字节处理ARITH_MAX次的加法和减法计算
      continue;   //下一字节
    }

    stage_cur_byte = i;    //当前操作的字节偏移量

    //进行ARITH_MAX次递增加减法计算
    for (j = 1; j <= ARITH_MAX; j++) {

      u8 r = orig ^ (orig + j);   //加法计算后，发生翻转的位

      /* Do arithmetic operations only if the result couldn't be a product
         of a bitflip. 仅当结果不是位翻转的乘积时才进行算术运算。*/

      //检测运算结果的位翻转情况，是否在位翻转阶段出现过，移除重复的位翻转测试
      if (!could_be_bitflip(r)) {
        
        //新的位翻转情况
        stage_cur_val = j;    //当前阶段使用的值
        out_buf[i] = orig + j;    //设置字节数值

        //运行被测试程序处理修改后的测试用例，根据运行情况决定是否放弃本次测试用例处理，不放弃则检测修改后的测试用例是否可以加入到测试用例队列
        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;    //放弃检测，则处理当前测试用例并退出函数
        stage_cur++;    //阶段索引

      } else stage_max--;   //与位翻转阶段操作相同,本阶段测试用例数量-1

      r =  orig ^ (orig - j);   //减法计算后，发生翻转的位

      //检测运算结果的位翻转情况，是否在位翻转阶段出现过，移除重复的位翻转测试
      if (!could_be_bitflip(r)) {

        stage_cur_val = -j;   //阶段处理的计算值
        out_buf[i] = orig - j;    //设置字节数值

        //运行被测试程序处理修改后的测试用例，根据运行情况决定是否放弃本次测试用例处理，不放弃则检测修改后的测试用例是否可以加入到测试用例队列
        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;    //放弃检测，则处理当前测试用例并退出函数        
        stage_cur++;    //阶段索引

      } else stage_max--;   //与位翻转阶段操作相同,本阶段测试用例数量-1

      out_buf[i] = orig;    //恢复原始字节值

    }

  }

  new_hit_cnt = queued_paths + unique_crashes;    //执行完1字节算术运算后，测试用例和崩溃样本的总数量

  stage_finds[STAGE_ARITH8]  += new_hit_cnt - orig_hit_cnt;   //1字节算术运算阶段发现的新的测试用例或崩溃样本的数量
  stage_cycles[STAGE_ARITH8] += stage_max;   //1字节算术运算阶段运行被测试程序处理变异用例的次数

  /* 16-bit arithmetics, both endians.  2字节算术*/

  if (len < 2) goto skip_arith;   //样本长度小于2字节，跳过后续算术运算

  stage_name  = "arith 16/8";    //命令行显示的阶段名称
  stage_short = "arith16";    //命令行显示的阶段短名称
  stage_cur   = 0;    //阶段索引
  stage_max   = 4 * (len - 1) * ARITH_MAX;  //阶段处理的总次数
                                        //每2个字节涉及大端序和小端序的加减法
                                        //-1避免溢出
                                    


  orig_hit_cnt = new_hit_cnt;   //执行完1字节算术运算后，测试用例和崩溃样本的总数量

  //遍历每个字节
  for (i = 0; i < len - 1; i++) {

    u16 orig = *(u16*)(out_buf + i);    //保存原始2字节值

    /* Let's consult the effector map... */

    //检测当前连续2字节对应的效应器图元素是否为0，为0说明翻转该字节没有路径变化，跳过
    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {
      stage_max -= 4 * ARITH_MAX;    //本阶段测试用例数量-4*ARITH_MAX ；因为每2个字节处理ARITH_MAX次的大端序和小端序的加减法
      continue; //下一字节
    }

    stage_cur_byte = i; //当前操作的字节偏移量

    //进行ARITH_MAX次递增加减法计算
    for (j = 1; j <= ARITH_MAX; j++) {

      u16 r1 = orig ^ (orig + j),   //2字节加法
          r2 = orig ^ (orig - j),   //2字节减法
          r3 = orig ^ SWAP16(SWAP16(orig) + j),   //2字节大端序加法
          r4 = orig ^ SWAP16(SWAP16(orig) - j);   //2字节大端序减法

      /* Try little endian addition and subtraction first. Do it only
         if the operation would affect more than one byte (hence the 
         & 0xff overflow checks) and if it couldn't be a product of
         a bitflip. 
         首先尝试小端加法和减法。 仅当该操作影响多个字节（因此进行 & 0xff 溢出检查）并且它不是位翻转的产物时才执行此操作。*/

      stage_val_type = STAGE_VAL_LE;   //阶段值类型
      //小端序

      if ((orig & 0xff) + j > 0xff && !could_be_bitflip(r1)) {
        //低字节发生溢出，并且位翻转情况未在位翻转阶段出现过

        stage_cur_val = j;    //阶段处理的计算值
        *(u16*)(out_buf + i) = orig + j;    //设置2字节数值

        //运行被测试程序处理修改后的测试用例，根据运行情况决定是否放弃本次测试用例处理，不放弃则检测修改后的测试用例是否可以加入到测试用例队列
        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;    //放弃检测，则处理当前测试用例并退出函数
        stage_cur++;  //阶段索引
 
      } else stage_max--;   //低字节未发生溢出，或位翻转情况在位翻转阶段出现过,本阶段测试用例数量-1

      if ((orig & 0xff) < j && !could_be_bitflip(r2)) {
        //低字节发生溢出，并且位翻转情况未在位翻转阶段出现过
        //小于j，再减去j才能溢出

        stage_cur_val = -j;   //阶段处理的计算值
        *(u16*)(out_buf + i) = orig - j;  //设置2字节数值

        //运行被测试程序处理修改后的测试用例，根据运行情况决定是否放弃本次测试用例处理，不放弃则检测修改后的测试用例是否可以加入到测试用例队列
        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;    //放弃检测，则处理当前测试用例并退出函数
        stage_cur++;  //阶段索引

      } else stage_max--;   //低字节未发生溢出，或位翻转情况在位翻转阶段出现过,本阶段测试用例数量-1

      /* Big endian comes next. Same deal. */

      stage_val_type = STAGE_VAL_BE;  //阶段值类型
      //大端序

      if ((orig >> 8) + j > 0xff && !could_be_bitflip(r3)) {
        //低字节发生溢出，并且位翻转情况未在位翻转阶段出现过

        stage_cur_val = j;    //阶段处理的计算值
        *(u16*)(out_buf + i) = SWAP16(SWAP16(orig) + j);  //设置2字节数值

        //运行被测试程序处理修改后的测试用例，根据运行情况决定是否放弃本次测试用例处理，不放弃则检测修改后的测试用例是否可以加入到测试用例队列
        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;    //放弃检测，则处理当前测试用例并退出函数
        stage_cur++;  //阶段索引

      } else stage_max--;

      if ((orig >> 8) < j && !could_be_bitflip(r4)) {
        //低字节发生溢出，并且位翻转情况未在位翻转阶段出现过
        //小于j，再减去j才能溢出

        stage_cur_val = -j;   //阶段处理的计算值
        *(u16*)(out_buf + i) = SWAP16(SWAP16(orig) - j);  //设置2字节数值

        //运行被测试程序处理修改后的测试用例，根据运行情况决定是否放弃本次测试用例处理，不放弃则检测修改后的测试用例是否可以加入到测试用例队列
        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;    //放弃检测，则处理当前测试用例并退出函数
        stage_cur++;  //阶段索引

      } else stage_max--;

      *(u16*)(out_buf + i) = orig;  //恢复原始2字节值

    }

  }

  new_hit_cnt = queued_paths + unique_crashes;    //执行完2字节算术运算后，测试用例和崩溃样本的总数量

  stage_finds[STAGE_ARITH16]  += new_hit_cnt - orig_hit_cnt;    //2字节算术运算阶段发现的新的测试用例或崩溃样本的数量
  stage_cycles[STAGE_ARITH16] += stage_max;   //2字节算术运算阶段运行被测试程序处理变异用例的次数

  /* 32-bit arithmetics, both endians. 4字节算术*/

  if (len < 4) goto skip_arith;   //样本长度小于4字节，跳过后续算术运算

  stage_name  = "arith 32/8";   //命令行显示的阶段名称
  stage_short = "arith32";    //命令行显示的阶段短名称
  stage_cur   = 0;    //阶段索引
  stage_max   = 4 * (len - 3) * ARITH_MAX;  //阶段处理的总次数
                                        //每4个字节涉及大端序和小端序的加减法
                                        //-3避免溢出

  orig_hit_cnt = new_hit_cnt; //执行完4字节算术运算后，测试用例和崩溃样本的总数量
  
  //遍历4个字节
  for (i = 0; i < len - 3; i++) {

    u32 orig = *(u32*)(out_buf + i);  //保存原始4字节值

    /* Let's consult the effector map... */

    //检测当前连续4字节对应的效应器图元素是否为0，为0说明翻转该字节没有路径变化，跳过
    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
        !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {
      stage_max -= 4 * ARITH_MAX; //本阶段测试用例数量-4*ARITH_MAX ；因为每2个字节处理ARITH_MAX次的大端序和小端序的加减法
      continue; //下一字节
    }

    stage_cur_byte = i; //当前操作的字节偏移量

    //进行ARITH_MAX次递增加减法计算
    for (j = 1; j <= ARITH_MAX; j++) {

      u32 r1 = orig ^ (orig + j), //4字节加法
          r2 = orig ^ (orig - j), //4字节减法
          r3 = orig ^ SWAP32(SWAP32(orig) + j), //4字节大端序加法
          r4 = orig ^ SWAP32(SWAP32(orig) - j); //4字节大端序减法

      /* Little endian first. Same deal as with 16-bit: we only want to
         try if the operation would have effect on more than two bytes.
         小端优先。 与 16 位处理相同：我们只想尝试操作是否会对两个以上字节产生影响。 */

      stage_val_type = STAGE_VAL_LE;    //阶段值类型
      //小端序

      if ((orig & 0xffff) + j > 0xffff && !could_be_bitflip(r1)) {
        //低2字节发生溢出，并且位翻转情况未在位翻转阶段出现过

        stage_cur_val = j;  //阶段处理的计算值
        *(u32*)(out_buf + i) = orig + j;  //设置4字节数值

         //运行被测试程序处理修改后的测试用例，根据运行情况决定是否放弃本次测试用例处理，不放弃则检测修改后的测试用例是否可以加入到测试用例队列
        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;    //放弃检测，则处理当前测试用例并退出函数
        stage_cur++;  //阶段索引
 
      } else stage_max--;   //低字节未发生溢出，或位翻转情况在位翻转阶段出现过,本阶段测试用例数量-1

      if ((orig & 0xffff) < j && !could_be_bitflip(r2)) {
        //低2字节发生溢出，并且位翻转情况未在位翻转阶段出现过

        stage_cur_val = -j; //阶段处理的计算值
        *(u32*)(out_buf + i) = orig - j;  //设置4字节数值

        //运行被测试程序处理修改后的测试用例，根据运行情况决定是否放弃本次测试用例处理，不放弃则检测修改后的测试用例是否可以加入到测试用例队列
        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;    //放弃检测，则处理当前测试用例并退出函数
        stage_cur++;  //阶段索引

      } else stage_max--; //低2字节未发生溢出，或位翻转情况在位翻转阶段出现过,本阶段测试用例数量-1

      /* Big endian next.  接下来是大尾数。*/

      stage_val_type = STAGE_VAL_BE;  //阶段值类型
      //大端序

      if ((SWAP32(orig) & 0xffff) + j > 0xffff && !could_be_bitflip(r3)) {
        //低2字节发生溢出，并且位翻转情况未在位翻转阶段出现过

        stage_cur_val = j;  //阶段处理的计算值
        *(u32*)(out_buf + i) = SWAP32(SWAP32(orig) + j);  //设置2字节数值

        //运行被测试程序处理修改后的测试用例，根据运行情况决定是否放弃本次测试用例处理，不放弃则检测修改后的测试用例是否可以加入到测试用例队列
        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;    //放弃检测，则处理当前测试用例并退出函数
        stage_cur++;  //阶段索引

      } else stage_max--; //低2字节未发生溢出，或位翻转情况在位翻转阶段出现过,本阶段测试用例数量-1

      if ((SWAP32(orig) & 0xffff) < j && !could_be_bitflip(r4)) {
        //低2字节发生溢出，并且位翻转情况未在位翻转阶段出现过

        stage_cur_val = -j; //阶段处理的计算值
        *(u32*)(out_buf + i) = SWAP32(SWAP32(orig) - j);  //设置2字节数值

        //运行被测试程序处理修改后的测试用例，根据运行情况决定是否放弃本次测试用例处理，不放弃则检测修改后的测试用例是否可以加入到测试用例队列
        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;    //放弃检测，则处理当前测试用例并退出函数
        stage_cur++;  //阶段索引

      } else stage_max--; //低2字节未发生溢出，或位翻转情况在位翻转阶段出现过,本阶段测试用例数量-1

      *(u32*)(out_buf + i) = orig;      //恢复原始4字节值

    }

  }

  new_hit_cnt = queued_paths + unique_crashes;    //执行完4字节算术运算后，测试用例和崩溃样本的总数量

  stage_finds[STAGE_ARITH32]  += new_hit_cnt - orig_hit_cnt;    //4字节算术运算阶段发现的新的测试用例或崩溃样本的数量
  stage_cycles[STAGE_ARITH32] += stage_max;   //4字节算术运算阶段运行被测试程序处理变异用例的次数

skip_arith:

  /**********************
   * INTERESTING VALUES  有趣的值*
   **********************/

  stage_name  = "interest 8/8"; //命令行显示的阶段名称
  stage_short = "int8"; //命令行显示的阶段短名称
  stage_cur   = 0;  //阶段索引
  stage_max   = len * sizeof(interesting_8);   //阶段处理的总次数
                                                //每个字节都使用有趣数值的值替换一遍

  stage_val_type = STAGE_VAL_LE;     //阶段值类型

  orig_hit_cnt = new_hit_cnt;   //执行完4字节算术运算后，测试用例和崩溃样本的总数量

  /* Setting 8-bit integers. 设置 8 位整数。*/

  //遍历每个字节
  for (i = 0; i < len; i++) {

    u8 orig = out_buf[i]; //保留原始值

    /* Let's consult the effector map... */

     //检测当前字节对应的效应器图元素是否为0，为0说明翻转该字节没有路径变化，跳过
    if (!eff_map[EFF_APOS(i)]) {
      stage_max -= sizeof(interesting_8); //本阶段测试用例数量-interesting_8数组大小
      continue; //下一个字节
    }

    stage_cur_byte = i;    //当前操作的字节偏移量

    //遍历interesting_8数组
    for (j = 0; j < sizeof(interesting_8); j++) {

      /* Skip if the value could be a product of bitflips or arithmetics. 
      如果该值可能是位翻转或算术的乘积，则跳过*/

      if (could_be_bitflip(orig ^ (u8)interesting_8[j]) ||    //在位翻转阶段出现过
          could_be_arith(orig, (u8)interesting_8[j], 1)) {    //在算术阶段出现过
        stage_max--;    //本阶段测试用例数量-1
        continue;   //下一个有趣值
      }

      stage_cur_val = interesting_8[j];   //阶段处理的有趣值
      out_buf[i] = interesting_8[j];  //设置1字节有趣值

      //运行被测试程序处理修改后的测试用例，根据运行情况决定是否放弃本次测试用例处理，不放弃则检测修改后的测试用例是否可以加入到测试用例队列
      if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;    //放弃检测，则处理当前测试用例并退出函数
      
      out_buf[i] = orig;  //恢复原始1字节值
      stage_cur++;  //阶段索引

    }

  }

  new_hit_cnt = queued_paths + unique_crashes;  //执行完1字节有趣值替换后，测试用例和崩溃样本的总数量

  stage_finds[STAGE_INTEREST8]  += new_hit_cnt - orig_hit_cnt;    //1字节有趣值替换阶段发现的新的测试用例或崩溃样本的数量
  stage_cycles[STAGE_INTEREST8] += stage_max;    //1字节有趣值替换阶段运行被测试程序处理变异用例的次数

  /* Setting 16-bit integers, both endians. 2字节有趣值*/

  //根据环境变量AFL_NO_ARITH和文件大小跳过后续有趣替换阶段
  if (no_arith || len < 2) goto skip_interest;

  stage_name  = "interest 16/8";  //命令行显示的阶段名称
  stage_short = "int16";  //命令行显示的阶段短名称
  stage_cur   = 0;  //阶段索引
  stage_max   = 2 * (len - 1) * (sizeof(interesting_16) >> 1);  //阶段处理的总次数
                                                                //2 * (len - 1)  为每两个字节存在大小端
                                                                //sizeof(interesting_16) >> 1 为保存的有趣值为2字节，sizeof根据字节计算

  orig_hit_cnt = new_hit_cnt;   //执行完1字节有趣值替换后，测试用例和崩溃样本的总数量

  //遍历文件字节
  for (i = 0; i < len - 1; i++) {

    u16 orig = *(u16*)(out_buf + i);   //保留原始2字节值

    /* Let's consult the effector map...  让我们查阅效应器图...*/

    //检测连续2字节对应的效应器图元素是否为0，为0说明翻转该字节没有路径变化，跳过
    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {
      stage_max -= sizeof(interesting_16);    //本阶段测试用例数量-interesting_16数组元素数量
      continue;   //下一个字节
    }

    stage_cur_byte = i;   //当前操作的字节偏移量

    //遍历interesting_16数组
    for (j = 0; j < sizeof(interesting_16) / 2; j++) {

      stage_cur_val = interesting_16[j];     //阶段处理的有趣值

      /* Skip if this c ould be a product of a bitflip, arithmetics,
         or single-byte interesting value insertion. */

      if (!could_be_bitflip(orig ^ (u16)interesting_16[j]) &&    //未在位翻转阶段出现过
          !could_be_arith(orig, (u16)interesting_16[j], 2) &&   //未在算术阶段出现过
          !could_be_interest(orig, (u16)interesting_16[j], 2, 0)) { //未在过往有趣值阶段出现过

        stage_val_type = STAGE_VAL_LE;     //阶段值类型
        //小端序

        *(u16*)(out_buf + i) = interesting_16[j];     //设置2字节有趣值

        //运行被测试程序处理修改后的测试用例，根据运行情况决定是否放弃本次测试用例处理，不放弃则检测修改后的测试用例是否可以加入到测试用例队列
        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;    //放弃检测，则处理当前测试用例并退出函数
        stage_cur++;  //阶段索引  

      } else stage_max--; //本阶段测试用例数量-1

      if ((u16)interesting_16[j] != SWAP16(interesting_16[j]) &&    //小端序和大端序值不同
          !could_be_bitflip(orig ^ SWAP16(interesting_16[j])) &&   //未在算术阶段出现过
          !could_be_arith(orig, SWAP16(interesting_16[j]), 2) &&   //未在算术阶段出现过
          !could_be_interest(orig, SWAP16(interesting_16[j]), 2, 1)) {  //未在过往有趣值阶段出现过

        stage_val_type = STAGE_VAL_BE;     //阶段值类型
        //大端序

        *(u16*)(out_buf + i) = SWAP16(interesting_16[j]); //设置2字节有趣值
        
        //运行被测试程序处理修改后的测试用例，根据运行情况决定是否放弃本次测试用例处理，不放弃则检测修改后的测试用例是否可以加入到测试用例队列
        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;    //放弃检测，则处理当前测试用例并退出函数
        stage_cur++;  //阶段索引

      } else stage_max--; //本阶段测试用例数量-1

    }

    *(u16*)(out_buf + i) = orig;  //恢复原始2字节值

  }

  new_hit_cnt = queued_paths + unique_crashes;    //执行完2字节有趣值替换后，测试用例和崩溃样本的总数量

  stage_finds[STAGE_INTEREST16]  += new_hit_cnt - orig_hit_cnt;  //2字节有趣值替换阶段发现的新的测试用例或崩溃样本的数量
  stage_cycles[STAGE_INTEREST16] += stage_max;    //2字节有趣值替换阶段运行被测试程序处理变异用例的次数

  //文件大小小于4跳过后续有趣替换阶段
  if (len < 4) goto skip_interest;

  /* Setting 32-bit integers, both endians. 4字节有趣值*/

  stage_name  = "interest 32/8";    //命令行显示的阶段名称
  stage_short = "int32";    //命令行显示的阶段短名称
  stage_cur   = 0;    //阶段索引
  stage_max   = 2 * (len - 3) * (sizeof(interesting_32) >> 2);  //阶段处理的总次数
                                                                //2 * (len - 1)  为每4个字节存在大小端
                                                                //sizeof(interesting_32) >> 2 为保存的有趣值为4字节，sizeof根据字节计算


  orig_hit_cnt = new_hit_cnt;   //执行完2字节有趣值替换后，测试用例和崩溃样本的总数量

  //遍历文件字节
  for (i = 0; i < len - 3; i++) {

    u32 orig = *(u32*)(out_buf + i);  //保留原始值

    /* Let's consult the effector map... */
    //检测连续4字节对应的效应器图元素是否为0，为0说明翻转该字节没有路径变化，跳过
    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
        !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {
      stage_max -= sizeof(interesting_32) >> 1; //本阶段测试用例数量-interesting_32元素数量
                                          //应该>>2吧，这里有问题吧？？？
      continue; //下一个字节
    }

    stage_cur_byte = i;    //当前操作的字节偏移量


    //遍历interesting_32元素
    for (j = 0; j < sizeof(interesting_32) / 4; j++) {

      stage_cur_val = interesting_32[j];     //阶段处理的有趣值

      /* Skip if this could be a product of a bitflip, arithmetics,
         or word interesting value insertion. 
         如果这可能是位翻转、算术或单词有趣值插入的产物，则跳过。 
          */

      if (!could_be_bitflip(orig ^ (u32)interesting_32[j]) &&  //未在位翻转阶段出现过
          !could_be_arith(orig, interesting_32[j], 4) &&    //未在算术转阶段出现过
          !could_be_interest(orig, interesting_32[j], 4, 0)) {    //未在过往有趣值阶段出现过

        stage_val_type = STAGE_VAL_LE;  //阶段值类型
        //小端序

        *(u32*)(out_buf + i) = interesting_32[j];    //设置4字节有趣值

        //运行被测试程序处理修改后的测试用例，根据运行情况决定是否放弃本次测试用例处理，不放弃则检测修改后的测试用例是否可以加入到测试用例队列
        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;    //放弃检测，则处理当前测试用例并退出函数
        stage_cur++;  //阶段索引

      } else stage_max--;   //本阶段测试用例数量-1

      if ((u32)interesting_32[j] != SWAP32(interesting_32[j]) &&  //小端序和大端序值不同
          !could_be_bitflip(orig ^ SWAP32(interesting_32[j])) &&  //未在位翻转阶段出现过
          !could_be_arith(orig, SWAP32(interesting_32[j]), 4) &&  //未在算术转阶段出现过
          !could_be_interest(orig, SWAP32(interesting_32[j]), 4, 1)) {  //未在过往有趣值阶段出现过

        stage_val_type = STAGE_VAL_BE; //阶段值类型
        //大端序

        *(u32*)(out_buf + i) = SWAP32(interesting_32[j]); //设置4字节有趣值

        //运行被测试程序处理修改后的测试用例，根据运行情况决定是否放弃本次测试用例处理，不放弃则检测修改后的测试用例是否可以加入到测试用例队列
        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;    //放弃检测，则处理当前测试用例并退出函数
        stage_cur++;  //阶段索引

      } else stage_max--;   //本阶段测试用例数量-1

    }

    *(u32*)(out_buf + i) = orig;    //恢复原始值

  }

  new_hit_cnt = queued_paths + unique_crashes;   //执行完4字节有趣值替换后，测试用例和崩溃样本的总数量

  stage_finds[STAGE_INTEREST32]  += new_hit_cnt - orig_hit_cnt;   //4字节有趣值替换阶段发现的新的测试用例或崩溃样本的数量
  stage_cycles[STAGE_INTEREST32] += stage_max;   //4字节有趣值替换阶段运行被测试程序处理变异用例的次数

skip_interest:

  /********************
   * DICTIONARY STUFF 字典的东西*
   ********************/
  //处理字典

  //没有指定字典文件则跳过用户字典阶段
  if (!extras_cnt) goto skip_user_extras;   

  /* Overwrite with user-supplied extras. 使用用户提供的附加内容覆盖。 */

  stage_name  = "user extras (over)";  //命令行显示的阶段名称
  stage_short = "ext_UO"; //命令行显示的阶段短名称
  stage_cur   = 0;   //阶段索引
  stage_max   = extras_cnt * len;    //阶段处理的总次数
                                    //遍历字典替换每个字节

  stage_val_type = STAGE_VAL_NONE;    //阶段值类型

  orig_hit_cnt = new_hit_cnt;   //执行完上一阶段后（存在跳过某个阶段的情况），测试用例和崩溃样本的总数量

  //遍历文件字节
  for (i = 0; i < len; i++) {

    u32 last_len = 0;   

    stage_cur_byte = i;  //当前操作的字节偏移量

    /* Extras are sorted by size, from smallest to largest. This means
       that we don't have to worry about restoring the buffer in
       between writes at a particular offset determined by the outer
       loop. 额外内容按大小从小到大排序。 这意味着我们不必担心在由外循环确定的特定偏移量处的写入之间恢复缓冲区。*/
    
    //遍历字典条目
    for (j = 0; j < extras_cnt; j++) {

      /* Skip extras probabilistically if extras_cnt > MAX_DET_EXTRAS. Also
         skip them if there's no room to insert the payload, if the token
         is redundant, or if its entire span has no bytes set in the effector
         map. 
         如果 extras_cnt > MAX_DET_EXTRAS，则概率性地跳过额外内容。
         如果没有空间插入有效负载，如果令牌是冗余的，或者如果其整个跨度在效应器映射中没有设置字节，也请跳过它们。*/

      if ((extras_cnt > MAX_DET_EXTRAS && UR(extras_cnt) >= MAX_DET_EXTRAS) ||    //字典条目超过了限制，则随机跳过某些字典条目
          extras[j].len > len - i ||    //当前位置写入字典条目后会超出文件大小
          !memcmp(extras[j].data, out_buf + i, extras[j].len) ||  //字典与文件原始数据相同
        //检测字典大小连续字节对应的效应器图元素是否为0，为0说明翻转该字节没有路径变化，跳过
          !memchr(eff_map + EFF_APOS(i), 1, EFF_SPAN_ALEN(i, extras[j].len))) {  
        stage_max--;  //本阶段测试用例数量-1
        continue;  //下一个字节

      }

      last_len = extras[j].len;   //更新替换的字节数量
      memcpy(out_buf + i, extras[j].data, last_len);    //字典替换原有数据

      //运行被测试程序处理修改后的测试用例，根据运行情况决定是否放弃本次测试用例处理，不放弃则检测修改后的测试用例是否可以加入到测试用例队列
      if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;    //放弃检测，则处理当前测试用例并退出函数
      stage_cur++;  //阶段索引

    }

    /* Restore all the clobbered memory. 恢复所有被破坏的内存 */
    memcpy(out_buf + i, in_buf + i, last_len);

  }

  new_hit_cnt = queued_paths + unique_crashes;  //执行用户字典替换阶段后（存在跳过某个阶段的情况），测试用例和崩溃样本的总数量

  stage_finds[STAGE_EXTRAS_UO]  += new_hit_cnt - orig_hit_cnt;   //用户字典替换阶段发现的新的测试用例或崩溃样本的数量
  stage_cycles[STAGE_EXTRAS_UO] += stage_max; //用户字典替换阶段运行被测试程序处理变异用例的次数

  /* Insertion of user-supplied extras. 插入用户提供的附加内容*/

  stage_name  = "user extras (insert)";   //命令行显示的阶段名称
  stage_short = "ext_UI";   //命令行显示的阶段短名称
  stage_cur   = 0;    //阶段索引
  stage_max   = extras_cnt * (len + 1); //阶段处理的总次数
                                    //遍历字典最近每个字节后面，文件结尾处也要追加，因此（len+1）

  orig_hit_cnt = new_hit_cnt;   //执行用户字典替换阶段后，测试用例和崩溃样本的总数量

  ex_tmp = ck_alloc(len + MAX_DICT_FILE);   //申请内存，用于字典插入使用
                                            //MAX_DICT_FILE为字典长度限制
  //遍历文件
  for (i = 0; i <= len; i++) {

    stage_cur_byte = i;   //当前操作的字节偏移量

    //遍历用户字典
    for (j = 0; j < extras_cnt; j++) {

      if (len + extras[j].len > MAX_FILE) {   //插入字典后超出了文件大小限制
        stage_max--;  //本阶段测试用例数量-1
        continue;   //下一字节
      }

      /* Insert token 插入字典 */
      memcpy(ex_tmp + i, extras[j].data, extras[j].len);

      /* Copy tail 复制剩余数据 */
      memcpy(ex_tmp + i + extras[j].len, out_buf + i, len - i);

       //运行被测试程序处理修改后的测试用例，根据运行情况决定是否放弃本次测试用例处理，不放弃则检测修改后的测试用例是否可以加入到测试用例队列
      if (common_fuzz_stuff(argv, ex_tmp, len + extras[j].len)) {
        ck_free(ex_tmp);      //释放内存
        goto abandon_entry;    //放弃检测，则处理当前测试用例并退出函数
      }

      stage_cur++;    //阶段索引
    }

    /* Copy head  复制头*/
    //更新tmp数组本次元素为正确值，否则为最后一个字典的第一个字符
    ex_tmp[i] = out_buf[i];

  }

  ck_free(ex_tmp);

  new_hit_cnt = queued_paths + unique_crashes;    //执行用户字典插入阶段后，测试用例和崩溃样本的总数量

  stage_finds[STAGE_EXTRAS_UI]  += new_hit_cnt - orig_hit_cnt;    //用户字典插入阶段发现的新的测试用例或崩溃样本的数量
  stage_cycles[STAGE_EXTRAS_UI] += stage_max;   //用户字典插入阶段运行被测试程序处理变异用例的次数

skip_user_extras:
  
  //在1bit翻转阶段没有发现字典，则跳过自动发现的字典阶段
  if (!a_extras_cnt) goto skip_extras;
  //自动发现的字典，只进行替换，没有进行插入

  stage_name  = "auto extras (over)"; //命令行显示的阶段名称
  stage_short = "ext_AO";   //命令行显示的阶段短名称
  stage_cur   = 0;    //阶段索引
  stage_max   = MIN(a_extras_cnt, USE_AUTO_EXTRAS) * len; //阶段处理的总次数
                                                        //遍历1bit翻转阶段发现的字典替换每个字节，上限数量为USE_AUTO_EXTRAS

  stage_val_type = STAGE_VAL_NONE;     //阶段值类型

  orig_hit_cnt = new_hit_cnt;   //执行完上一阶段后（存在跳过某个阶段的情况），测试用例和崩溃样本的总数量

  //遍历文件
  for (i = 0; i < len; i++) {

    u32 last_len = 0;

    stage_cur_byte = i;   //当前操作的字节偏移量

    //遍历1bit翻转阶段发现的字典
    for (j = 0; j < MIN(a_extras_cnt, USE_AUTO_EXTRAS); j++) {

      /* See the comment in the earlier code; extras are sorted by size. 参见前面代码中的注释； 额外内容按大小排序。 */

      if (a_extras[j].len > len - i ||    //当前位置写入字典条目后会超出文件大小
          !memcmp(a_extras[j].data, out_buf + i, a_extras[j].len) ||  //字典与文件原始数据相同
          !memchr(eff_map + EFF_APOS(i), 1, EFF_SPAN_ALEN(i, a_extras[j].len))) {   //检测字典大小连续字节对应的效应器图元素是否为0，为0说明翻转该字节没有路径变化，跳过
        stage_max--;    //本阶段测试用例数量-1
        continue;   //下一个字节
      }

      last_len = a_extras[j].len;   //更新替换的字节数量
      memcpy(out_buf + i, a_extras[j].data, last_len);   //字典替换原有数据

      //运行被测试程序处理修改后的测试用例，根据运行情况决定是否放弃本次测试用例处理，不放弃则检测修改后的测试用例是否可以加入到测试用例队列
      if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;    //放弃检测，则处理当前测试用例并退出函数
      stage_cur++;  //阶段索引

    }

    /* Restore all the clobbered memory.  恢复所有被破坏的内存*/
    memcpy(out_buf + i, in_buf + i, last_len);

  }

  new_hit_cnt = queued_paths + unique_crashes;  //执行1bit翻转阶段发现的字典插入阶段后，测试用例和崩溃样本的总数量

  stage_finds[STAGE_EXTRAS_AO]  += new_hit_cnt - orig_hit_cnt;    //1bit翻转阶段发现的字典的插入阶段发现的新的测试用例或崩溃样本的数量
  stage_cycles[STAGE_EXTRAS_AO] += stage_max;    //1bit翻转阶段发现的字典的插入阶段运行被测试程序处理变异用例的次数

skip_extras:

  /* If we made this to here without jumping to havoc_stage or abandon_entry,
     we're properly done with deterministic steps and can mark it as such
     in the .state/ directory. 
     如果我们在没有跳转到 havoc_stage 或 abandon_entry 的情况下做到了这一点，那么我们就正确地完成了确定性步骤，并且可以在 .state/ 目录中将其标记为这样。*/

  //位翻转、算术、有趣值、用户字典、自动发现字典 为确定性变异阶段

  //完成了确定变异，且测试用例未设置完成确定性变异的状态（mark_as_det_done会设置测试用例的passed_det标记为1）
  if (!queue_cur->passed_det) mark_as_det_done(queue_cur);      ////创建状态标识文件，标识队列项已经完成了确定性变异

  /****************
   * RANDOM HAVOC 随机破坏*
   ****************/

havoc_stage:

  stage_cur_byte = -1;    //当前操作的字节偏移量

  /* The havoc stage mutation code is also invoked when splicing files; if the
     splice_cycle variable is set, generate different descriptions and such. 
     拼接文件时也会调用havoc阶段变异代码； 如果设置了 splice_cycle 变量，则生成不同的描述等。 */

  if (!splice_cycle) {    
    //首次进入破坏阶段

    stage_name  = "havoc";   //命令行显示的阶段名称
    stage_short = "havoc";  //命令行显示的阶段短名称
    //doing_det为1表示进行了确定性变异
    
    //根据释放进行了确定性变异计算随机性变异的次数
    stage_max   = (doing_det ? HAVOC_CYCLES_INIT : HAVOC_CYCLES) *
                  perf_score / havoc_div / 100;

  } else {
    //非首次进入破坏阶段，由后续阶段跳转回来

    static u8 tmp[32];

    perf_score = orig_perf;     //初始的性能分数

    sprintf(tmp, "splice %u", splice_cycle);
    stage_name  = tmp;    //命令行显示的阶段名称
    stage_short = "splice";   //命令行显示的阶段短名称
    stage_max   = SPLICE_HAVOC * perf_score / havoc_div / 100;    //根据性能得分计算拼接文件的随机性变异的次数

  }

   //计算得到随机性变异的次数小于最小随机变异次数，则使用最小随机变异次数
  if (stage_max < HAVOC_MIN) stage_max = HAVOC_MIN;  

  temp_len = len;

  orig_hit_cnt = queued_paths + unique_crashes;   //随机变异阶段起始前，测试用例和崩溃样本的总数量

  havoc_queued = queued_paths;    //记录随机变异前测试用例数量

  /* We essentially just do several thousand runs (depending on perf_score)
     where we take the input file and make random stacked tweaks. 
     我们本质上只是进行数千次运行（取决于 perf_score），其中我们获取输入文件并进行随机堆叠调整。*/

  //进行stage_max次随机变异
  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    u32 use_stacking = 1 << (1 + UR(HAVOC_STACK_POW2));     // 1 << (0~7) 随机左移0到7位

    stage_cur_val = use_stacking;   //当前阶段使用的值

    //组合use_stacking次变异
    for (i = 0; i < use_stacking; i++) {

      //根据随机数选择一种变异方式
      //最后两种方式位替换或插入字典，因此(extras_cnt + a_extras_cnt) ? 2 : 0)为2时，可以随机到字典操作
      switch (UR(15 + ((extras_cnt + a_extras_cnt) ? 2 : 0))) {   

        case 0:   //随机翻转文件某1bit

          /* Flip a single bit somewhere. Spooky! 在某处翻转一点。 幽灵般的！*/

          FLIP_BIT(out_buf, UR(temp_len << 3));       //temp_len << 3 ==   temp_len * 8，表示文件所有bit数量
          break;

        case 1:    //随机将文件某1字节设置为随机的1字节有趣值

          /* Set byte to interesting value. 将字节设置为有趣的值。*/

          out_buf[UR(temp_len)] = interesting_8[UR(sizeof(interesting_8))];
          break;

        case 2: //随机将文件某2字节设置为随机的2字节有趣值的大端序或小端序

          /* Set word to interesting value, randomly choosing endian.  将2字节设置为有趣的值，随机选择字节序。*/

          if (temp_len < 2) break;    //文件长度小于2字节，跳过本次变异
          
          //随机大小端序
          if (UR(2)) {
            //小端序
            *(u16*)(out_buf + UR(temp_len - 1)) = //随机2字节
              interesting_16[UR(sizeof(interesting_16) >> 1)];  //随机2字节有趣值

          } else {
            //大端序
            *(u16*)(out_buf + UR(temp_len - 1)) = SWAP16(   //随机2字节
              interesting_16[UR(sizeof(interesting_16) >> 1)]);   //随机2字节有趣值

          }

          break;

        case 3:   //随机将文件某4字节设置为随机的4字节有趣值的大端序或小端序

          /* Set dword to interesting value, randomly choosing endian. 将 dword 设置为有趣的值，随机选择字节序。  */

          if (temp_len < 4) break;  //文件长度小于4字节，跳过本次变异
          //随机大小端序
          if (UR(2)) {
            //小端序
            *(u32*)(out_buf + UR(temp_len - 3)) =   //随机4字节
              interesting_32[UR(sizeof(interesting_32) >> 2)];  //随机4字节有趣值

          } else {
            //大端序
            *(u32*)(out_buf + UR(temp_len - 3)) = SWAP32(   //随机4字节
              interesting_32[UR(sizeof(interesting_32) >> 2)]); //随机4字节有趣值

          }

          break;

        case 4:   //将文件某1字节减去ARITH_MAX范围内的随机一个数值

          /* Randomly subtract from byte. */

          out_buf[UR(temp_len)] -= 1 + UR(ARITH_MAX);
          break;

        case 5: //将文件某1字节加上ARITH_MAX范围内的随机一个数值

          /* Randomly add to byte.  随机添加到字节*/

          out_buf[UR(temp_len)] += 1 + UR(ARITH_MAX);
          break;

        case 6: //将文件随机2字节作为大/小端序减去ARITH_MAX范围内的随机一个数值

          /* Randomly subtract from word, random endian.  从字中随机减去，随机字节序。 */

          if (temp_len < 2) break;  //文件长度小于2字节，跳过本次变异
          //随机大小端序
          if (UR(2)) {
            
            u32 pos = UR(temp_len - 1);   //随机位置

            *(u16*)(out_buf + pos) -= 1 + UR(ARITH_MAX);    //作为小端序减去随机数

          } else {
            
            u32 pos = UR(temp_len - 1);   //随机位置
            u16 num = 1 + UR(ARITH_MAX);  //随机数

            *(u16*)(out_buf + pos) =
              SWAP16(SWAP16(*(u16*)(out_buf + pos)) - num);   //作为大端序减去随机数

          }

          break;

        case 7: //将文件随机2字节作为大/小端序加上ARITH_MAX范围内的随机一个数值

          /* Randomly add to word, random endian. 随机添加到单词，随机字节序。*/

          if (temp_len < 2) break;  //文件长度小于2字节，跳过本次变异
          //随机大小端序
          if (UR(2)) {

            u32 pos = UR(temp_len - 1);  //随机位置

            *(u16*)(out_buf + pos) += 1 + UR(ARITH_MAX);  //作为小端序加上随机数

          } else {

            u32 pos = UR(temp_len - 1);  //随机位置
            u16 num = 1 + UR(ARITH_MAX);  //随机数

            *(u16*)(out_buf + pos) =
              SWAP16(SWAP16(*(u16*)(out_buf + pos)) + num); //作为大端序加上随机数

          }

          break;

        case 8: //将文件随机4字节作为大/小端序减去ARITH_MAX范围内的随机一个数值

          /* Randomly subtract from dword, random endian. */

          if (temp_len < 4) break;  //文件长度小于4字节，跳过本次变异
          //随机大小端序
          if (UR(2)) {

            u32 pos = UR(temp_len - 3);   //随机位置

            *(u32*)(out_buf + pos) -= 1 + UR(ARITH_MAX);  //作为小端序减去随机数

          } else {

            u32 pos = UR(temp_len - 3);   //随机位置
            u32 num = 1 + UR(ARITH_MAX);  //随机数

            *(u32*)(out_buf + pos) =
              SWAP32(SWAP32(*(u32*)(out_buf + pos)) - num); //作为大端序减去随机数

          }

          break;

        case 9: //将文件随机4字节作为大/小端序加上ARITH_MAX范围内的随机一个数值

          /* Randomly add to dword, random endian. 随机添加到双字，随机字节序。*/

          if (temp_len < 4) break;  //文件长度小于4字节，跳过本次变异
          //随机大小端序
          if (UR(2)) {

            u32 pos = UR(temp_len - 3);  //随机位置

            *(u32*)(out_buf + pos) += 1 + UR(ARITH_MAX);   //作为小端序加上随机数

          } else {

            u32 pos = UR(temp_len - 3);  //随机位置
            u32 num = 1 + UR(ARITH_MAX);  //随机数

            *(u32*)(out_buf + pos) =
              SWAP32(SWAP32(*(u32*)(out_buf + pos)) + num);  //作为大端序加上随机数

          }

          break;

        case 10:    //将随机字节设置为随机值

          /* Just set a random byte to a random value. Because,
             why not. We use XOR with 1-255 to eliminate the
             possibility of a no-op. 
             只需将随机字节设置为随机值即可。 因为，为什么不呢。 我们使用 XOR 与 1-255 来消除空操作的可能性。*/

          out_buf[UR(temp_len)] ^= 1 + UR(255);   //如果不使用异或，可能会设置为原始值
          break;

        case 11 ... 12: {   //随机删除测试用例部分数据

            /* Delete bytes. We're making this a bit more likely
               than insertion (the next option) in hopes of keeping
               files reasonably small. 删除字节。 我们使这比插入（下一个选项）更有可能，希望保持文件相当小。*/

            u32 del_from, del_len;

            if (temp_len < 2) break;  //文件长度小于2字节，跳过本次变异

            /* Don't delete too much. 不要删除太多。*/

            del_len = choose_block_len(temp_len - 1);     //根据运行状态随机选择一个区间大小，用于复制和删除
                                                //-1用于避免随机大小与当前文件大小一样，不然后面会出现异常

            del_from = UR(temp_len - del_len + 1);    //从文件可删除范围随机挑选一个值

            memmove(out_buf + del_from, out_buf + del_from + del_len,
                    temp_len - del_from - del_len);   //覆盖被删除部分数据

            temp_len -= del_len;    //修正文件大小

            break;

          }

        case 13:  //将测试用例数据或随机数插入到测试用例

          if (temp_len + HAVOC_BLK_XL < MAX_FILE) {

            /* Clone bytes (75%) or insert a block of constant bytes (25%).
            克隆字节 (75%) 或插入常量字节块 (25%)。 */

            u8  actually_clone = UR(4);
            u32 clone_from, clone_to, clone_len;
            u8* new_buf;

            if (actually_clone) {   
              //3/4的几率

              clone_len  = choose_block_len(temp_len);    //克隆块的大小
              clone_from = UR(temp_len - clone_len + 1);    //克隆块的起始位置

            } else {
              //1/4的几率

              clone_len = choose_block_len(HAVOC_BLK_XL);   //插入块的大小
              clone_from = 0;   //插入模式没有用到

            }

            clone_to   = UR(temp_len);    //插入的位置

            new_buf = ck_alloc_nozero(temp_len + clone_len);    //分配对应的内存空间

            /* Head */

            memcpy(new_buf, out_buf, clone_to);   //复制插入块前的数据

            /* Inserted part */

            if (actually_clone)   //克隆模式
              memcpy(new_buf + clone_to, out_buf + clone_from, clone_len);    //从测试用例中复制一块数据插入到指定位置 
            else
              memset(new_buf + clone_to,
                     UR(2) ? UR(256) : out_buf[UR(temp_len)], clone_len);  //随机使用随机数或测试用例随机挑选一个字节，填充指定位置

            /* Tail */
            memcpy(new_buf + clone_to + clone_len, out_buf + clone_to,
                   temp_len - clone_to);    //复制测试用例剩余部分

            ck_free(out_buf);   //释放之前测试用例内存
            out_buf = new_buf;    //更新测试用例内存
            temp_len += clone_len;    //更新文件大小

          }

          break;

        case 14: {    //使用测试用例数据或随机数覆盖测试用例数据

            /* Overwrite bytes with a randomly selected chunk (75%) or fixed
               bytes (25%). 使用随机选择的块 (75%) 或固定字节 (25%) 覆盖字节。*/

            u32 copy_from, copy_to, copy_len;

            if (temp_len < 2) break;  //文件长度小于2字节，跳过本次变异

            copy_len  = choose_block_len(temp_len - 1);   //随机选择被覆盖的数据长度

            copy_from = UR(temp_len - copy_len + 1);    //选择测试用例的覆盖数据起始位置
            copy_to   = UR(temp_len - copy_len + 1);    //选择测试用例的被覆盖数据起始位置

            if (UR(4)) {
              //使用测试用例数据覆盖
              if (copy_from != copy_to)   //使用的数据与被覆盖的位置不同
                memmove(out_buf + copy_to, out_buf + copy_from, copy_len);    //目的和源可能重叠，使用memmove进行安全复制

            } else //使用随机数或测试用例数据覆盖
            memset(out_buf + copy_to,
                          UR(2) ? UR(256) : out_buf[UR(temp_len)], copy_len);

            break;

          }

        /* Values 15 and 16 can be selected only if there are any extras
           present in the dictionaries. 仅当字典中存在任何额外内容时才可以选择值 15 和 16。*/

        case 15: {    //随机使用字典替换原始数据

            /* Overwrite bytes with an extra.   使用字典覆盖字节*/

            if (!extras_cnt || (a_extras_cnt && UR(2))) {
              //不存在用户字典则仅使用查询到的字典
              //同时存在用户字典和查询到在字典，则通过随机数检测使用哪个字典

              /* No user-specified extras or odds in our favor. Let's use an
                 auto-detected one.  
                 没有用户指定的额外费用或对我们有利的赔率。 让我们使用自动检测到的一个。*/

              u32 use_extra = UR(a_extras_cnt);   //随机选择一个字典
              u32 extra_len = a_extras[use_extra].len;
              u32 insert_at;

              if (extra_len > temp_len) break;    //字典长度大于用例长度，跳出switch

              insert_at = UR(temp_len - extra_len + 1); //随机替换位置
              memcpy(out_buf + insert_at, a_extras[use_extra].data, extra_len);   //使用字典替换原有数据

            } else {
              //不存在查询到在字典，则仅使用用户字典
              //同时存在用户字典和查询到在字典，则通过随机数检测使用哪个字典

              /* No auto extras or odds in our favor. Use the dictionary.  没有对您有利的汽车附加费或赔率。 使用字典。*/

              u32 use_extra = UR(extras_cnt);  //随机选择一个字典
              u32 extra_len = extras[use_extra].len;
              u32 insert_at;

              if (extra_len > temp_len) break;  //字典长度大于用例长度，跳出switch

              insert_at = UR(temp_len - extra_len + 1); //随机替换位置
              memcpy(out_buf + insert_at, extras[use_extra].data, extra_len);    //使用字典替换原有数据

            }

            break;

          }

        case 16: {  //随机使用字典插入到测试用例

            u32 use_extra, extra_len, insert_at = UR(temp_len + 1);   //随机插入位置
            u8* new_buf;

            /* Insert an extra. Do the same dice-rolling stuff as for the
               previous case. 插入一个额外的。 进行与前一个案例相同的掷骰子操作。 */

            if (!extras_cnt || (a_extras_cnt && UR(2))) {
              //不存在用户字典则仅使用查询到的字典
              //同时存在用户字典和查询到在字典，则通过随机数检测使用哪个字典

              use_extra = UR(a_extras_cnt);     //随机选择一个字典
              extra_len = a_extras[use_extra].len;

              if (temp_len + extra_len >= MAX_FILE) break;    //用例大小+字典大小超过文件大小限制，跳出switch

              new_buf = ck_alloc_nozero(temp_len + extra_len);

              /* Head */
              memcpy(new_buf, out_buf, insert_at);    //复制插入位置前的数据

              /* Inserted part */
              memcpy(new_buf + insert_at, a_extras[use_extra].data, extra_len);   //插入字典

            } else {
              //不存在查询到在字典，则仅使用用户字典
              //同时存在用户字典和查询到在字典，则通过随机数检测使用哪个字典

              use_extra = UR(extras_cnt); //随机选择一个字典
              extra_len = extras[use_extra].len;

              if (temp_len + extra_len >= MAX_FILE) break;  //用例大小+字典大小超过文件大小限制，跳出switch

              new_buf = ck_alloc_nozero(temp_len + extra_len);

              /* Head */
              memcpy(new_buf, out_buf, insert_at);  //复制插入位置前的数据

              /* Inserted part */
              memcpy(new_buf + insert_at, extras[use_extra].data, extra_len);  //插入字典

            }

            /* Tail */
            memcpy(new_buf + insert_at + extra_len, out_buf + insert_at,
                   temp_len - insert_at);  //复制插入位置后的数据

            ck_free(out_buf);     //释放之前的测试用例内存
            out_buf   = new_buf;    //更新测试用例内存
            temp_len += extra_len;    //更新文件大小

            break;

          }

      }

    }
    
    //运行被测试程序处理修改后的测试用例，根据运行情况决定是否放弃本次测试用例处理，不放弃则检测修改后的测试用例是否可以加入到测试用例队列
    if (common_fuzz_stuff(argv, out_buf, temp_len))
      goto abandon_entry;   //放弃检测，则处理当前测试用例并退出函数

    /* out_buf might have been mangled a bit, so let's restore it to its
       original size and shape. out_buf可能已经被破坏了一点，所以让我们将其恢复到原来的大小和形状。*/

    //还原测试用例数据；如果内存小了则重新申请，内存大了则等待后续释放即可
    if (temp_len < len) out_buf = ck_realloc(out_buf, len);
    temp_len = len;
    memcpy(out_buf, in_buf, len);

    /* If we're finding new stuff, let's run for a bit longer, limits
       permitting.如果我们发现新的东西，在限制允许的情况下，让我们跑得更久一点。 */

    //本次变异测试后发现了新的测试用例，让这次随机变异运行更久一些
    if (queued_paths != havoc_queued) { 

      if (perf_score <= HAVOC_MAX_MULT * 100) {   //性能分数小于最大值
        stage_max  *= 2;    //本阶段最大测试次数*2
        perf_score *= 2;    //性能分数*2
      }

      havoc_queued = queued_paths;    //记录本次变异测试用例数量

    }

  }

  new_hit_cnt = queued_paths + unique_crashes;    //随机变异阶段后，测试用例和崩溃样本的总数量

  if (!splice_cycle) {
    //首次进入破坏阶段
    stage_finds[STAGE_HAVOC]  += new_hit_cnt - orig_hit_cnt;    //随机变异阶段发现的新的测试用例或崩溃样本的数量
    stage_cycles[STAGE_HAVOC] += stage_max;   //随机变异阶段运行被测试程序处理变异用例的次数
  } else {
    //拼接后进入破坏阶段
    stage_finds[STAGE_SPLICE]  += new_hit_cnt - orig_hit_cnt;     //拼接后随机变异阶段发现的新的测试用例或崩溃样本的数量
    stage_cycles[STAGE_SPLICE] += stage_max;     //拼接后随机变异阶段运行被测试程序处理变异用例的次数
  }

#ifndef IGNORE_FINDS

  /************
   * SPLICING 拼接 *
   ************/

  /* This is a last-resort strategy triggered by a full round with no findings.
     It takes the current input file, randomly selects another input, and
     splices them together at some offset, then relies on the havoc
     code to mutate that blob. 
     这是在没有结果的情况下进行整轮触发的最后手段。 它获取当前的输入文件，随机选择另一个输入，并以某个偏移量将它们拼接在一起，然后依赖破坏代码来改变该 blob。*/

retry_splicing:

  //指定了文件拼接、本次测试用例拼接的次数未超过限制、测试用例数量大于1、当前用例的文件大小大于1
  if (use_splicing && splice_cycle++ < SPLICE_CYCLES &&
      queued_paths > 1 && queue_cur->len > 1) {

    struct queue_entry* target;
    u32 tid, split_at;
    u8* new_buf;
    s32 f_diff, l_diff;

    /* First of all, if we've modified in_buf for havoc, let's clean that up... 
      首先，如果我们修改了in_buf用于随机变异，那么让我们清理它......*/

    //in_buf变为了拼接后的用例，这里进行恢复
    if (in_buf != orig_in) {    
      ck_free(in_buf);    //释放
      in_buf = orig_in;   //指向测试用例
      len = queue_cur->len;   //设置文件大小
    }

    /* Pick a random queue entry and seek to it. Don't splice with yourself. 
      选择一个随机队列条目并寻找它。 不要和自己拼接。*/

    do { tid = UR(queued_paths); } while (tid == current_entry);    //随机获取测非当前试用例的ID

    splicing_with = tid;    //用于拼接的测试用例ID
    target = queue;   //用于tid小于100时的遍历

    //用于定位到tid对应的测试用例
    while (tid >= 100) { target = target->next_100; tid -= 100; }   //tid大于100，则100个查找 
    while (tid--) target = target->next;  //小于100，则单个遍历

    /* Make sure that the target has a reasonable length. 确保目标具有合理的长度。*/
  
    //存在拼接用例，拼接的测试用例长度小于2，或为自身，则查询下一个
    while (target && (target->len < 2 || target == queue_cur)) {
      target = target->next;    //下一个测试用例
      splicing_with++;    //拼接ID+1，用于后续生成测试用例文件名
    }

    if (!target) goto retry_splicing;   //没有合适的测试用例，重新尝试随机拼接

    /* Read the testcase into a new buffer. 将测试用例读入新的缓冲区。*/

    fd = open(target->fname, O_RDONLY);   //打开文件

    if (fd < 0) PFATAL("Unable to open '%s'", target->fname);   //打开失败，终止

    new_buf = ck_alloc_nozero(target->len);   //申请文件内存

    ck_read(fd, new_buf, target->len, target->fname);   //读取文件

    close(fd);    //关闭文件

    /* Find a suitable splicing location, somewhere between the first and
       the last differing byte. Bail out if the difference is just a single
       byte or so. 找到合适的拼接位置，位于第一个和最后一个不同字节之间的某个位置。 如果差异只有一个字节左右，则退出。*/

    locate_diffs(in_buf, new_buf, MIN(len, target->len), &f_diff, &l_diff);   //查询两个测试用例的第一个和最后一个不同字节的位置

    //没有不同、或前两字节不同、或只有一个字节不同
    if (f_diff < 0 || l_diff < 2 || f_diff == l_diff) {
      ck_free(new_buf);   //释放第二个测试用例内存
      goto retry_splicing;    //重新尝试拼接
    }

    /* Split somewhere between the first and last differing byte. 在第一个和最后一个不同字节之间的某个位置进行分割。*/

    split_at = f_diff + UR(l_diff - f_diff);    //在第一个不同字节和最后一个不同字节选择一个位置

    /* Do the thing. */

    len = target->len;    //使用第二个测试用例的大小
    memcpy(new_buf, in_buf, split_at);    //随机将本次测试用例的前半部分与第二个测试用例的后半部分进行拼接
    in_buf = new_buf;   //更新测试用例

    ck_free(out_buf);   //重新申请输出缓冲区
    out_buf = ck_alloc_nozero(len);
    memcpy(out_buf, in_buf, len);   //将拼接后的测试用例复制到输出缓冲区

    goto havoc_stage;   //跳转到随机变异

  }

#endif /* !IGNORE_FINDS */

  ret_val = 0;    //测试完成

abandon_entry:    //处理当前测试用例并退出函数

  splicing_with = -1;   //测试用例拼接标识

  /* Update pending_not_fuzzed count if we made it through the calibration
     cycle and have not seen this entry before. 
     如果我们完成了校准周期并且之前没有看到此条目，请更新未决模糊计数。*/

  //无终止标记、校准成功、未fuzz完成
  if (!stop_soon && !queue_cur->cal_failed && !queue_cur->was_fuzzed) {
    queue_cur->was_fuzzed = 1;    //设置完成fuzz
    pending_not_fuzzed--;   //待fuzz的用例数量-1
    if (queue_cur->favored) pending_favored--;    //如果是受青睐的测试用例，则待定fuzz的受青睐用例数量-1
  }

  munmap(orig_in, queue_cur->len);    //取消内存映射

  //释放资源
  if (in_buf != orig_in) ck_free(in_buf);   //in_buf用于了其他用途
  ck_free(out_buf);
  ck_free(eff_map);

  return ret_val; //返回测试结果

#undef FLIP_BIT

}


/* Grab interesting test cases from other fuzzers. 从其他模糊器中获取有趣的测试用例。*/
// 遍历根输出目录，检测其他进程是否存在队列文件，然后通过同步目录下记录文件检测本次读取的测试用例名称，随后对运行被测试程序处理测试用例，并根据路径反馈信息决定是否添加到测试用例队列
static void sync_fuzzers(char** argv) {

  DIR* sd;
  struct dirent* sd_ent;
  u32 sync_cnt = 0;

  //打开同步目录
  sd = opendir(sync_dir);   //fix_up_sync函数为sync_dir设置逻辑
  if (!sd) PFATAL("Unable to open '%s'", sync_dir); //失败终止

  stage_max = stage_cur = 0;
  cur_depth = 0;

  /* Look at the entries created for every other fuzzer in the sync directory.  查看同步目录中为每个其他模糊器创建的条目。 */
  
  while ((sd_ent = readdir(sd))) {    //遍历目录

    static u8 stage_tmp[128];

    DIR* qd;
    struct dirent* qd_ent;
    u8 *qd_path, *qd_synced_path;
    u32 min_accept = 0, next_min_accept;

    s32 id_fd;

    /* Skip dot files and our own output directory. 跳过点文件和我们自己的输出目录。*/

    if (sd_ent->d_name[0] == '.' || !strcmp(sync_id, sd_ent->d_name)) continue;

    /* Skip anything that doesn't have a queue/ subdirectory.  跳过没有队列/子目录的任何内容。*/

    qd_path = alloc_printf("%s/%s/queue", sync_dir, sd_ent->d_name);    //拼接路径

    if (!(qd = opendir(qd_path))) {   //打开目录失败
      ck_free(qd_path);
      continue;
    }

    /* Retrieve the ID of the last seen test case. 检索最后看到的测试用例的 ID。*/

    //打开输出目录下.synced目录中其他模糊器名称的文件
    qd_synced_path = alloc_printf("%s/.synced/%s", out_dir, sd_ent->d_name);    

    id_fd = open(qd_synced_path, O_RDWR | O_CREAT, 0600);

    if (id_fd < 0) PFATAL("Unable to create '%s'", qd_synced_path);   //打开失败终止

    //读取 这次要同步的ID值
    if (read(id_fd, &min_accept, sizeof(u32)) > 0) 
      lseek(id_fd, 0, SEEK_SET);  //读取成功，将偏移设置为起始处，用于后续写入

    next_min_accept = min_accept;   //设置

    /* Show stats */    
    //设置全局变量，用于打印信息
    sprintf(stage_tmp, "sync %u", ++sync_cnt);
    stage_name = stage_tmp;
    stage_cur  = 0;
    stage_max  = 0;

    /* For every file queued by this fuzzer, parse ID and see if we have looked at
       it before; exec a test case if not.
       对于这个模糊器排队的每个文件，解析ID并看看我们之前是否看过它； 如果没有，则执行测试用例。 */

    while ((qd_ent = readdir(qd))) {    //遍历其他模糊器输出目录下的queue目录

      u8* path;
      s32 fd;
      struct stat st;

      if (qd_ent->d_name[0] == '.' || //当前目录
          sscanf(qd_ent->d_name, CASE_PREFIX "%06u", &syncing_case) != 1 ||     //读取ID失败
          syncing_case < min_accept) continue;    //ID小于本次要获取的ID

      /* OK, sounds like a new one. Let's give it a try. 好的，听起来像是新的。让我们试一试。*/

      if (syncing_case >= next_min_accept)    //文件ID大于或等于本次要读取ID
        next_min_accept = syncing_case + 1;   //设置下次要读取的ID

      path = alloc_printf("%s/%s", qd_path, qd_ent->d_name);    //拼接文件路径

      /* Allow this to fail in case the other fuzzer is resuming or so... */

      fd = open(path, O_RDONLY);    //打开路径

      if (fd < 0) {   //打开失败，检测下一个
         ck_free(path);
         continue;
      }

      if (fstat(fd, &st)) PFATAL("fstat() failed");   //获取文件状态

      /* Ignore zero-sized or oversized files. 忽略零大小或超大文件。*/

      if (st.st_size && st.st_size <= MAX_FILE) {   //文件满足大小要求

        u8  fault;
        u8* mem = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);   //映射文件到内存

        if (mem == MAP_FAILED) PFATAL("Unable to mmap '%s'", path);   //映射失败终止

        /* See what happens. We rely on save_if_interesting() to catch major
           errors and save the test case.  走着瞧吧。 我们依靠 save_if_interesting() 来捕获主要错误并保存测试用例*/

        write_to_testcase(mem, st.st_size);   //写入到输出文件，即被测试程序读取的文件

        fault = run_target(argv, exec_tmout);   //运行被测试程序，获取状态码

        if (stop_soon) return;    //设置了终止标记，返回

        syncing_party = sd_ent->d_name;   //同步的文件名，用于创建测试用例文件

        
        queued_imported += save_if_interesting(argv, mem, st.st_size, fault);   //// 测试用例存在新路径则添加到用例队列并创建文件，随后检测状态码并创建挂起或崩溃文件
                                                                                //成功保存，导入测试用例数量+1
        syncing_party = 0;

        munmap(mem, st.st_size);    //取消映射

        if (!(stage_cur++ % stats_update_freq)) show_stats();   //根据映射频率打印信息

      }

      ck_free(path);  //释放资源
      close(fd);

    }

    ck_write(id_fd, &next_min_accept, sizeof(u32), qd_synced_path);   //将下一次要读取的ID写入到文件

    //释放资源
    close(id_fd);
    closedir(qd);
    ck_free(qd_path);
    ck_free(qd_synced_path);
    
  }  

  //关闭目录
  closedir(sd);

}


/* Handle stop signal (Ctrl-C, etc). */
//终止程序的信号
static void handle_stop_sig(int sig) {

  stop_soon = 1;  //设置停止标记

  if (child_pid > 0) kill(child_pid, SIGKILL);    //关闭被fuzz程序的主进程
  if (forksrv_pid > 0) kill(forksrv_pid, SIGKILL);    //关闭被fuzz程序的子进程

}


/* Handle skip request (SIGUSR1). */
//用户自定义信号处理函数
static void handle_skipreq(int sig) {

  skip_requested = 1; //跳过请求？？？

}

/* Handle timeout (SIGALRM). */
//超时处理函数
static void handle_timeout(int sig) {

 
  if (child_pid > 0) {
    //被测试程序的主进程存在,则关闭主进程
    child_timed_out = 1;  //设置超时状态
    kill(child_pid, SIGKILL);

  } else if (child_pid == -1 && forksrv_pid > 0) {

    //被测试程序的主进程不存在,但子进程存在，则关闭子进程
    child_timed_out = 1;  //设置超时状态
    kill(forksrv_pid, SIGKILL);

  }

}


/* Do a PATH search and find target binary to see that it exists and
   isn't a shell script - a common and painful mistake. We also check for
   a valid ELF header and for evidence of AFL instrumentation.
   执行PATH搜索并找到目标二进制文件以查看它是否存在并且不是shell 脚本——这是一个常见且痛苦的错误。 
   我们还检查有效的ELF标头和AFL检测的证据 */

EXP_ST void check_binary(u8* fname) {

  u8* env_path = 0;
  struct stat st;

  s32 fd;
  u8* f_data;
  u32 f_len = 0;

  ACTF("Validating target binary...");

  //这个if检测程序所在位置
  if (strchr(fname, '/') || !(env_path = etenv("PATH"))) {    //文件名包含/或者PATH环境变量不存在
    //文件在指定路径，或当前路径下

    target_path = ck_strdup(fname);   //备份文件名
    if (stat(target_path, &st) || !S_ISREG(st.st_mode) ||   
        !(st.st_mode & 0111) || (f_len = st.st_size) < 4)
      //给定文件名不是有效路径、不是普通文件、没有可执行权限、文件大小小于4 说明不是可执行文件
      FATAL("Program '%s' not found or not executable", fname); //报错并终止

  } else {

    while (env_path) {    //遍历PATH环境中保存的路径

      u8 *cur_elem, *delim = strchr(env_path, ':');

      if (delim) {  //查询到了:
        //复制:前的路径
        cur_elem = ck_alloc(delim - env_path + 1);
        memcpy(cur_elem, env_path, delim - env_path);
        delim++;

      } else cur_elem = ck_strdup(env_path);    //最后一个路径，直接复制

      env_path = delim;   //更新环境遍历字符串为:后一个字符

      if (cur_elem[0])    
        //存在路径，进行拼接
        target_path = alloc_printf("%s/%s", cur_elem, fname);
      else
        //空路径，直接使用原始文件名
        target_path = ck_strdup(fname);

      ck_free(cur_elem);

      //给定文件名是有效路径、是普通文件、有可执行权限、文件大小大于4 ；说明是可执行文件
      if (!stat(target_path, &st) && S_ISREG(st.st_mode) &&
          (st.st_mode & 0111) && (f_len = st.st_size) >= 4) break;

      ck_free(target_path);   //释放资源
      target_path = 0;

    }
    //遍历完所有路径也没找到程序，终止
    if (!target_path) FATAL("Program '%s' not found or not executable", fname);

  }
  //此时查询到了可执行程序路径，该环境变量标识是否检查二进制文件内容
  if (getenv("AFL_SKIP_BIN_CHECK")) return;   

  /* Check for blatant user errors. 检查是否存在明显的用户错误。*/

  if ((!strncmp(target_path, "/tmp/", 5) && !strchr(target_path + 5, '/')) ||
      (!strncmp(target_path, "/var/tmp/", 9) && !strchr(target_path + 9, '/')))
     FATAL("Please don't keep binaries in /tmp or /var/tmp");     //程序在/tmp/或/var/tmp/目录下，终止程序

  fd = open(target_path, O_RDONLY);   //只读打开文件

  if (fd < 0) PFATAL("Unable to open '%s'", target_path);   //打开失败，终止程序

  f_data = mmap(0, f_len, PROT_READ, MAP_PRIVATE, fd, 0);   //

  if (f_data == MAP_FAILED) PFATAL("Unable to mmap file '%s'", target_path);      //映射文件到内存失败，终止程序

  close(fd);

  if (f_data[0] == '#' && f_data[1] == '!') {   //疑似shell文件，终止程序

    SAYF("\n" cLRD "[-] " cRST
         "Oops, the target binary looks like a shell script. Some build systems will\n"
         "    sometimes generate shell stubs for dynamically linked programs; try static\n"
         "    library mode (./configure --disable-shared) if that's the case.\n\n"

         "    Another possible cause is that you are actually trying to use a shell\n" 
         "    wrapper around the fuzzed component. Invoking shell can slow down the\n" 
         "    fuzzing process by a factor of 20x or more; it's best to write the wrapper\n"
         "    in a compiled language instead.\n");

    FATAL("Program '%s' is a shell script", target_path);

  }

#ifndef __APPLE__
  //非ELF文件格式，终止程序
  if (f_data[0] != 0x7f || memcmp(f_data + 1, "ELF", 3))
    FATAL("Program '%s' is not an ELF binary", target_path);

#else
  //非apple文件格式，终止程序
  if (f_data[0] != 0xCF || f_data[1] != 0xFA || f_data[2] != 0xED)
    FATAL("Program '%s' is not a 64-bit Mach-O binary", target_path);

#endif /* ^!__APPLE__ */

  //非qemu模式、非哑模式、并且文件数据中不存在共享内存环境变量（SHM_ENV_VAR）的值，则终止程序
  //当通过afl-gcc和afl-as处理源代码文件后，会在文件结尾处追加环境变量SHM_ENV_VAR的值，这里检测这个值，以此判断是否为afl生成的可执行文件
  if (!qemu_mode && !dumb_mode &&         
      !memmem(f_data, f_len, SHM_ENV_VAR, strlen(SHM_ENV_VAR) + 1)) {   

    SAYF("\n" cLRD "[-] " cRST    
         "Looks like the target binary is not instrumented! The fuzzer depends on\n"
         "    compile-time instrumentation to isolate interesting test cases while\n"
         "    mutating the input data. For more information, and for tips on how to\n"
         "    instrument binaries, please see %s/README.\n\n"

         "    When source code is not available, you may be able to leverage QEMU\n"
         "    mode support. Consult the README for tips on how to enable this.\n"

         "    (It is also possible to use afl-fuzz as a traditional, \"dumb\" fuzzer.\n"
         "    For that, you can use the -n option - but expect much worse results.)\n",
         doc_path);

    FATAL("No instrumentation detected"); 

  }

  if (qemu_mode &&      //qemu模式下检测到二进制文件存在环境变量SHM_ENV_VAR值，终止程序 //说明该文件是afl生成的可执行文件，不建议使用qemu模式，效率低
      memmem(f_data, f_len, SHM_ENV_VAR, strlen(SHM_ENV_VAR) + 1)) {

    SAYF("\n" cLRD "[-] " cRST
         "This program appears to be instrumented with afl-gcc, but is being run in\n"
         "    QEMU mode (-Q). This is probably not what you want - this setup will be\n"
         "    slow and offer no practical benefits.\n");

    FATAL("Instrumentation found in -Q mode");

  }

  if (memmem(f_data, f_len, "libasan.so", 10) ||
      memmem(f_data, f_len, "__msan_init", 11)) uses_asan = 1;      //检测到可执行程序存在asan标记，启用asan

  /* Detect persistent & deferred init signatures in the binary.  检测二进制文件中的持久和延迟初始化签名。*/

  if (memmem(f_data, f_len, PERSIST_SIG, strlen(PERSIST_SIG) + 1)) {      
    //检测到持久初始化签名

    OKF(cPIN "Persistent mode binary detected.");
    setenv(PERSIST_ENV_VAR, "1", 1);    //设置环境变量
    persistent_mode = 1;    //指定持久初始化模式

  } else if (getenv("AFL_PERSISTENT")) {
    //未检测到签名，但是指定了相关环境变量
    WARNF("AFL_PERSISTENT is no longer supported and may misbehave!");

  }

  if (memmem(f_data, f_len, DEFER_SIG, strlen(DEFER_SIG) + 1)) {    
    //检测到延迟初始化签名

    OKF(cPIN "Deferred forkserver binary detected.");
    setenv(DEFER_ENV_VAR, "1", 1);    //设置环境变量
    deferred_mode = 1;    //指定延迟初始化模式

  } else if (getenv("AFL_DEFER_FORKSRV")) {
    //未检测到签名，但是指定了相关环境变量
    WARNF("AFL_DEFER_FORKSRV is no longer supported and may misbehave!");

  }

  //取消内存映射
  if (munmap(f_data, f_len)) PFATAL("unmap() failed");

}


/* Trim and possibly create a banner for the run. */

static void fix_up_banner(u8* name) {

  if (!use_banner) {
    //未指定banner
    if (sync_id) {
      //存在sync_id，则将其作为banner
      use_banner = sync_id;

    } else {
      
      u8* trim = strrchr(name, '/');  //检索name中是否有/
      if (!trim) use_banner = name; else use_banner = trim + 1; //存在/则使用/后面的名称，没有则使用name
                                                               

    }

  }
  //banner字符大于40，则截断
  if (strlen(use_banner) > 40) {

    u8* tmp = ck_alloc(44);
    sprintf(tmp, "%.40s...", use_banner);
    use_banner = tmp;

  }

}


/* Check if we're on TTY. */

static void check_if_tty(void) {

  struct winsize ws;

  if (getenv("AFL_NO_UI")) {    //检测到AFL_NO_UI环境变量
    OKF("Disabling the UI because AFL_NO_UI is set.");
    not_on_tty = 1;    //设置未在tty运行变量
    return;
  }

  if (ioctl(1, TIOCGWINSZ, &ws)) {  //获取标准输出的终端大小

    if (errno == ENOTTY) {  //如果错误为ENOTTY，则表明程序可能在终端上运行
      OKF("Looks like we're not running on a tty, so I'll be a bit less verbose.");
      not_on_tty = 1;   //设置未在tty运行变量
    }

    return;
  }

}


/* Check terminal dimensions after resize. 调整尺寸后检查终端尺寸 */
//检测终端大小
static void check_term_size(void) {

  struct winsize ws;

  term_too_small = 0;

  if (ioctl(1, TIOCGWINSZ, &ws)) return;    //获取终端大小失败

  if (ws.ws_row == 0 && ws.ws_col == 0) return;   //终端大小为0，返回
  if (ws.ws_row < 25 || ws.ws_col < 80) term_too_small = 1; //终端大小小于指定值，设置term_too_small

}



/* Display usage hints. */  //显示AFL使用方法

static void usage(u8* argv0) {

  SAYF("\n%s [ options ] -- /path/to/fuzzed_app [ ... ]\n\n"

       "Required parameters:\n\n"

       "  -i dir        - input directory with test cases\n"
       "  -o dir        - output directory for fuzzer findings\n\n"

       "Execution control settings:\n\n"

       "  -f file       - location read by the fuzzed program (stdin)\n"
       "  -t msec       - timeout for each run (auto-scaled, 50-%u ms)\n"
       "  -m megs       - memory limit for child process (%u MB)\n"
       "  -Q            - use binary-only instrumentation (QEMU mode)\n\n"     
 
       "Fuzzing behavior settings:\n\n"

       "  -d            - quick & dirty mode (skips deterministic steps)\n"
       "  -n            - fuzz without instrumentation (dumb mode)\n"
       "  -x dir        - optional fuzzer dictionary (see README)\n\n"

       "Other stuff:\n\n"

       "  -T text       - text banner to show on the screen\n"
       "  -M / -S id    - distributed mode (see parallel_fuzzing.txt)\n"
       "  -C            - crash exploration mode (the peruvian rabbit thing)\n"
       "  -V            - show version number and exit\n\n"
       "  -b cpu_id     - bind the fuzzing process to the specified CPU core\n\n"

       "For additional tips, please consult %s/README.\n\n",

       argv0, EXEC_TIMEOUT, MEM_LIMIT, doc_path);

  exit(1);

}


/* Prepare output directories and fds. */
//准备输出目录和文件描述符
EXP_ST void setup_dirs_fds(void) {

  u8* tmp;
  s32 fd;

  ACTF("Setting up output directories...");

  //主从模式下sync_id有值，且在fix_up_sync函数中被设置该值为输出根目录，out_dir为输出子目录
  if (sync_id && mkdir(sync_dir, 0700) && errno != EEXIST)    //创建输出根目录
      PFATAL("Unable to create '%s'", sync_dir);

  if (mkdir(out_dir, 0700)) {   //主从模式下设置输出子目录，非主从模式创建输出根目录
    //创建目录失败

    if (errno != EEXIST) PFATAL("Unable to create '%s'", out_dir);    //非目录已存在错误码
    
    maybe_delete_out_dir();   //目录存在，尝试删除

  } else {
    //创建目录成功

    if (in_place_resume)    //输入路径为'-'时，设置该标记；标识查询旧的路径
      FATAL("Resume attempted but old output directory not found");     //这里标识没有查询到旧的目录，退出

    out_dir_fd = open(out_dir, O_RDONLY); //打开目录

#ifndef __sun

    if (out_dir_fd < 0 || flock(out_dir_fd, LOCK_EX | LOCK_NB))   //打开目录失败或无法获取独占锁则退出
      PFATAL("Unable to flock() output directory.");

#endif /* !__sun */

  }

  //准备各种子目录

  /* Queue directory for any starting & discovered paths. 任何起始和发现路径的队列目录 */

  tmp = alloc_printf("%s/queue", out_dir);    //队列目录
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* Top-level directory for queue metadata used for session
     resume and related tasks.  用于会话恢复和相关任务的队列元数据的顶级目录*/

  tmp = alloc_printf("%s/queue/.state/", out_dir);    //队列状态
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* Directory for flagging queue entries that went through
     deterministic fuzzing in the past. 用于标记过去经过确定性模糊测试的队列条目的目录。*/

  tmp = alloc_printf("%s/queue/.state/deterministic_done/", out_dir);   //完成了确定性变异的文件目录
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* Directory with the auto-selected dictionary entries. 包含自动选择的字典条目的目录。*/

  tmp = alloc_printf("%s/queue/.state/auto_extras/", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* The set of paths currently deemed redundant. 当前被视为冗余的路径集。*/

  tmp = alloc_printf("%s/queue/.state/redundant_edges/", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* The set of paths showing variable behavior. 显示可变行为的路径集。 */

  tmp = alloc_printf("%s/queue/.state/variable_behavior/", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* Sync directory for keeping track of cooperating fuzzers. 用于跟踪协作模糊器的同步目录。 */

  if (sync_id) {    //启用了主从模式

    //创建协同目录
    tmp = alloc_printf("%s/.synced/", out_dir);   

    if (mkdir(tmp, 0700) && (!in_place_resume || errno != EEXIST))
      PFATAL("Unable to create '%s'", tmp);

    ck_free(tmp);

  }

  /* All recorded crashes. 崩溃样本的目录 */

  tmp = alloc_printf("%s/crashes", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* All recorded hangs. 挂起样本的目录 */

  tmp = alloc_printf("%s/hangs", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* Generally useful file descriptors.  常用的文件描述符 */

  dev_null_fd = open("/dev/null", O_RDWR);      //丢弃输出
  if (dev_null_fd < 0) PFATAL("Unable to open /dev/null");

  dev_urandom_fd = open("/dev/urandom", O_RDONLY);    //随机数
  if (dev_urandom_fd < 0) PFATAL("Unable to open /dev/urandom");

  /* Gnuplot output file. Gnuplot输出文件（图形数据统计） */

  tmp = alloc_printf("%s/plot_data", out_dir);    //
  fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  plot_file = fdopen(fd, "w");    //获取文件描述符
  if (!plot_file) PFATAL("fdopen() failed");

  fprintf(plot_file, "# unix_time, cycles_done, cur_path, paths_total, "
                     "pending_total, pending_favs, map_size, unique_crashes, "
                     "unique_hangs, max_depth, execs_per_sec\n");
                     /* ignore errors */

}


/* Setup the output file for fuzzed data, if not using -f. */
//设置fuzz数据的输出文件，在未使用-f参数时
EXP_ST void setup_stdio_file(void) {

  u8* fn = alloc_printf("%s/.cur_input", out_dir);

  unlink(fn); /* Ignore errors */   //尝试移除.cur_input文件

  out_fd = open(fn, O_RDWR | O_CREAT | O_EXCL, 0600);   //创建并打开.cur_input文件

  if (out_fd < 0) PFATAL("Unable to create '%s'", fn);    //打开失败终止程序

  ck_free(fn);

}


/* Make sure that core dumps don't go to a program. */
//确保核心转储不会进入程序
static void check_crash_handling(void) {

#ifdef __APPLE__
  
  /* Yuck! There appears to be no simple C API to query for the state of 
     loaded daemons on MacOS X, and I'm a bit hesitant to do something
     more sophisticated, such as disabling crash reporting via Mach ports,
     until I get a box to test the code. So, for now, we check for crash
     reporting the awful way. */
  
  if (system("launchctl list 2>/dev/null | grep -q '\\.ReportCrash$'")) return;

  SAYF("\n" cLRD "[-] " cRST
       "Whoops, your system is configured to forward crash notifications to an\n"
       "    external crash reporting utility. This will cause issues due to the\n"
       "    extended delay between the fuzzed binary malfunctioning and this fact\n"
       "    being relayed to the fuzzer via the standard waitpid() API.\n\n"
       "    To avoid having crashes misinterpreted as timeouts, please run the\n" 
       "    following commands:\n\n"

       "    SL=/System/Library; PL=com.apple.ReportCrash\n"
       "    launchctl unload -w ${SL}/LaunchAgents/${PL}.plist\n"
       "    sudo launchctl unload -w ${SL}/LaunchDaemons/${PL}.Root.plist\n");

  if (!getenv("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"))
    FATAL("Crash reporter detected");

#else

  /* This is Linux specific, but I don't think there's anything equivalent on
     *BSD, so we can just let it slide for now. 这是 Linux 特有的，但我认为 *BSD 上没有任何等效的东西，所以我们现在可以让它滑动。*/

  s32 fd = open("/proc/sys/kernel/core_pattern", O_RDONLY); //proc/sys/kernel/core_pattern文件用于设置核心转储文件（core dump）的命名模式
                                                            //核心转储文件命名模式决定了系统在发生崩溃时如何创建核心转储文件
  u8  fchar;  

  if (fd < 0) return;

  ACTF("Checking core_pattern...");
  ///proc/sys/kernel/core_pattern文件以|起始，说明程序崩溃时核心转储将被发送到一个外部实用程序而不是直接写入文件系统
  if (read(fd, &fchar, 1) == 1 && fchar == '|') {

    //打印建议信息
    SAYF("\n" cLRD "[-] " cRST
         "Hmm, your system is configured to send core dump notifications to an\n"
         "    external utility. This will cause issues: there will be an extended delay\n"
         "    between stumbling upon a crash and having this information relayed to the\n"
         "    fuzzer via the standard waitpid() API.\n\n"

         "    To avoid having crashes misinterpreted as timeouts, please log in as root\n" 
         "    and temporarily modify /proc/sys/kernel/core_pattern, like so:\n\n"

         "    echo core >/proc/sys/kernel/core_pattern\n");

    if (!getenv("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"))   //检测不关心崩溃信息的环境变量
      FATAL("Pipe at the beginning of 'core_pattern'");   //没有不关心环境变量则退出

  }
 
  close(fd);

#endif /* ^__APPLE__ */

}


/* Check CPU governor. */
//检查CPU频率调整策略，非performance或频率为动态调整，则打印提示信息退出
static void check_cpu_governor(void) {

  FILE* f;
  u8 tmp[128];
  u64 min = 0, max = 0;

  if (getenv("AFL_SKIP_CPUFREQ")) return;   //环境变量指示不检查CPU 频率调整策略
  //打开策略文件
  f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor", "r");
  if (!f) return;   //打开文件失败

  ACTF("Checking CPU scaling governor...");

  if (!fgets(tmp, 128, f)) PFATAL("fgets() failed");  //读取行失败

  fclose(f);

  if (!strncmp(tmp, "perf", 4)) return;   //cpu频率调整策略为performance，直接返回

  //获取CPU最小频率
  f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_min_freq", "r");    

  if (f) {
    if (fscanf(f, "%llu", &min) != 1) min = 0;    //读取失败设置为0
    fclose(f);
  }

  //获取CPU最大频率
  f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq", "r");

  if (f) {
    if (fscanf(f, "%llu", &max) != 1) max = 0;  //读取失败设置为0
    fclose(f);
  }

  if (min == max) return;   //CPU的频率是固定的，没有动态调整的需求，因此可以直接返回

  //设置建议
  SAYF("\n" cLRD "[-] " cRST
       "Whoops, your system uses on-demand CPU frequency scaling, adjusted\n"
       "    between %llu and %llu MHz. Unfortunately, the scaling algorithm in the\n"
       "    kernel is imperfect and can miss the short-lived processes spawned by\n"
       "    afl-fuzz. To keep things moving, run these commands as root:\n\n"

       "    cd /sys/devices/system/cpu\n"
       "    echo performance | tee cpu*/cpufreq/scaling_governor\n\n"

       "    You can later go back to the original state by replacing 'performance' with\n"
       "    'ondemand'. If you don't want to change the settings, set AFL_SKIP_CPUFREQ\n"
       "    to make afl-fuzz skip this check - but expect some performance drop.\n",
       min / 1024, max / 1024);

  FATAL("Suboptimal CPU scaling governor");

}


/* Count the number of logical CPU cores. */
//计算逻辑CPU核心数，并根据系统运行状态，给出优化建议或警告信息
static void get_core_count(void) {

  u32 cur_runnable = 0;

//其他操作系统
#if defined(__APPLE__) || defined(__FreeBSD__) || defined (__OpenBSD__)

  size_t s = sizeof(cpu_core_count);

  /* On *BSD systems, we can just use a sysctl to get the number of CPUs. */

#ifdef __APPLE__

  if (sysctlbyname("hw.logicalcpu", &cpu_core_count, &s, NULL, 0) < 0) 
    return;

#else

  int s_name[2] = { CTL_HW, HW_NCPU };

  if (sysctl(s_name, 2, &cpu_core_count, &s, NULL, 0) < 0) return;   

#endif /* ^__APPLE__ */

#else

#ifdef HAVE_AFFINITY    //CPU亲和性

  cpu_core_count = sysconf(_SC_NPROCESSORS_ONLN); //获取系统配置信息

#else
  //根据/proc/stat文件中的cpu信息计算cpu内核数量
  FILE* f = fopen("/proc/stat", "r");
  u8 tmp[1024];

  if (!f) return;

  while (fgets(tmp, sizeof(tmp), f))
    if (!strncmp(tmp, "cpu", 3) && isdigit(tmp[3])) cpu_core_count++;   //cpu标识信息

  fclose(f);

#endif /* ^HAVE_AFFINITY */

#endif /* ^(__APPLE__ || __FreeBSD__ || __OpenBSD__) */

  if (cpu_core_count > 0) { 
    //检测到cpu内核数量
    
    cur_runnable = (u32)get_runnable_processes();   //获取可以运行进程的数量

#if defined(__APPLE__) || defined(__FreeBSD__) || defined (__OpenBSD__)
    
    /* Add ourselves, since the 1-minute average doesn't include that yet. */
    //其他系统的运行进程数要加+1，以包含当前进程？
    cur_runnable++;

#endif /* __APPLE__ || __FreeBSD__ || __OpenBSD__ */
    //打印提示信息
    OKF("You have %u CPU core%s and %u runnable tasks (utilization: %0.0f%%).",
        cpu_core_count, cpu_core_count > 1 ? "s" : "",
        cur_runnable, cur_runnable * 100.0 / cpu_core_count);

    if (cpu_core_count > 1) {
      
      if (cur_runnable > cpu_core_count * 1.5) {
        //进程数量大于内核的1.5倍

        //警告信息
        WARNF("System under apparent load, performance may be spotty.");
      
      } else if (cur_runnable + 1 <= cpu_core_count) {
        //进程数量+1，小于等于内核数量

        //推荐并行，提高效率
        OKF("Try parallel jobs - see %s/parallel_fuzzing.txt.", doc_path);
  
      }

    }

  } else {
    //未检测到cpu内核数量，打印警告信息
    cpu_core_count = 0;
    WARNF("Unable to figure out the number of CPU cores.");

  }

}


/* Validate and fix up out_dir and sync_dir when using -S. */
//使用 -S 时验证并修复 out_dir 和sync_dir
static void fix_up_sync(void) {

  u8* x = sync_id;  //sync_id为-M -S参数指定的字符串

  if (dumb_mode)  //哑模式不支持主从
    FATAL("-S / -M and -n are mutually exclusive");

  if (skip_deterministic) {   //-d指定skip_deterministic

    if (force_deterministic)  //-M指定force_deterministic
      FATAL("use -S instead of -M -d"); //-M -d不可以一起使用
    else
      FATAL("-S already implies -d"); //-S包含了-d

  }

  while (*x) {  //遍历字符串
    //只可以包含数字、字母、_和-
    if (!isalnum(*x) && *x != '_' && *x != '-')
      FATAL("Non-alphanumeric fuzzer ID specified via -S or -M");

    x++;

  }
  //限制32个字符长度
  if (strlen(sync_id) > 32) FATAL("Fuzzer ID too long");

  x = alloc_printf("%s/%s", out_dir, sync_id);  //拼接目录

  sync_dir = out_dir;   //保持原有目录，用于后续同步
  out_dir  = x; //主从模式的目录更新为原本目录下的子目录，且目录为主从模式的ID

  if (!force_deterministic) { //-S slave模式
    skip_deterministic = 1; //跳过确定性变异
    use_splicing = 1; //？？？重新组合输入文件
  }

}


/* Handle screen resize (SIGWINCH). */
//窗口大小变更处理函数
static void handle_resize(int sig) {
  clear_screen = 1;   //后续清空屏幕
}


/* Check ASAN options. */
//检查asan选项
static void check_asan_opts(void) {
  u8* x = getenv("ASAN_OPTIONS"); //获取asan环境变量

  if (x) {
      
    //设置bort_on_error=1表示当 AddressSanitizer（ASan）检测到与内存安全相关的错误时，程序应立即终止（中止）执行
    if (!strstr(x, "abort_on_error=1")) //没有设置abort_on_error=1
      FATAL("Custom ASAN_OPTIONS set without abort_on_error=1 - please fix!");  
    //symbolize=0表示禁用 AddressSanitizer（ASan） 的符号化功能。
    if (!strstr(x, "symbolize=0"))  //没有设置symbolize=0
      FATAL("Custom ASAN_OPTIONS set without symbolize=0 - please fix!");

  }

  x = getenv("MSAN_OPTIONS"); //获取msan环境变量

  if (x) {
    //将msan错误状态码设置为86
    if (!strstr(x, "exit_code=" STRINGIFY(MSAN_ERROR))) //未设置退出状态码
      FATAL("Custom MSAN_OPTIONS set without exit_code="
            STRINGIFY(MSAN_ERROR) " - please fix!");
    //symbolize=0表示禁用msan 符号化功能,MSan将不会尝试将地址转换为符号（例如函数名或源代码行号），而是直接显示原始的地址信息
    if (!strstr(x, "symbolize=0"))  //没有设置symbolize=0
      FATAL("Custom MSAN_OPTIONS set without symbolize=0 - please fix!");

  }

} 


/* Detect @@ in args. */
//检测被测试软件的命令行参数；将所有的@@替换为测试用例的输出文件名
EXP_ST void detect_file_args(char** argv) {

  u32 i = 0;
  u8* cwd = getcwd(NULL, 0);    //获取当前工作目录

  if (!cwd) PFATAL("getcwd() failed");    //获取失败，终止程序

  while (argv[i]) {   //遍历参数

    u8* aa_loc = strstr(argv[i], "@@");   //检测包含@@，@@用于指定被测试程序的输入文件

    if (aa_loc) {   //包含

      u8 *aa_subst, *n_arg;

      /* If we don't have a file name chosen yet, use a safe default. */

      if (!out_file)    //未指定输出文件名
        out_file = alloc_printf("%s/.cur_input", out_dir);    //分配输出文件名，用于被测试程序的输入文件

      /* Be sure that we're always using fully-qualified paths. */
      //确保使用绝对路径
      if (out_file[0] == '/') aa_subst = out_file;        
      else aa_subst = alloc_printf("%s/%s", cwd, out_file);

      /* Construct a replacement argv value. 构造一个替换argv的值*/
      
      *aa_loc = 0;  
      n_arg = alloc_printf("%s%s%s", argv[i], aa_subst, aa_loc + 2);   //使用文件名替换@@
      argv[i] = n_arg;  //重新设置输入文件参数
      *aa_loc = '@';  //恢复原始参数

      if (out_file[0] != '/') ck_free(aa_subst);    //不为/时，拼接字符串，因此需要释放

    }

    i++;    //遍历下一个参数

  }

  free(cwd); /* not tracked */

}


/* Set up signal handlers. More complicated that needs to be, because libc on
   Solaris doesn't resume interrupted reads(), sets SA_RESETHAND when you call
   siginterrupt(), and does other unnecessary things. */

//设置信号量处理程序
EXP_ST void setup_signal_handlers(void) {

  struct sigaction sa;

  sa.sa_handler   = NULL;
  sa.sa_flags     = SA_RESTART;   //信号处理器执行系统调用时自动重启被中断的系统调用 
  sa.sa_sigaction = NULL;

  sigemptyset(&sa.sa_mask);   //清空信号集合

  /* Various ways of saying "stop". */
  //停止进程的多种信号

  //将下列3种信号的处理函数，设置为handle_stop_sig
  sa.sa_handler = handle_stop_sig;    //指定函数
  sigaction(SIGHUP, &sa, NULL);   //当用户从终端注销（logout）时，会发送 SIGHUP 信号给相关的进程
  sigaction(SIGINT, &sa, NULL);   //当用户按下 Ctrl + C 时，发送该信号
  sigaction(SIGTERM, &sa, NULL);  //当系统管理员想要关闭或终止一个正在运行的程序时，通常会使用 kill 命令发送 SIGTERM 信号。以此告知程序正常终止
                           

  /* Exec timeout notifications. */
  //将超时信号的处理函数，设置为handle_timeout
  sa.sa_handler = handle_timeout;
  sigaction(SIGALRM, &sa, NULL);  /*SIGALRM 是一个由定时器超时引发的信号。当使用 alarm() 或 setitimer() 设置的定时器到达指定的时间时，
                                    系统会向进程发送 SIGALRM 信号。*/

  /* Window resize */

  //设置窗口大小改变的处理函数为handle_resize
  sa.sa_handler = handle_resize;
  sigaction(SIGWINCH, &sa, NULL); //当终端窗口的大小发生变化时，系统会向前台进程组中的所有进程发送 SIGWINCH 信号。

  /* SIGUSR1: skip entry */
  //设置用户自定义信号的处理函数为handle_skipreq
  sa.sa_handler = handle_skipreq;
  sigaction(SIGUSR1, &sa, NULL);  //用户自定义的信号，可以通过kill命令发送给进程

  /* Things we don't care about. */
  //忽略SIGTSTP和SIGPIPE信号，不进行处理
  sa.sa_handler = SIG_IGN;
  sigaction(SIGTSTP, &sa, NULL);  //按下 Ctrl + Z 发送此信号，将当前进程放到后台并停止它
  sigaction(SIGPIPE, &sa, NULL);  /*当进程尝试写入已经被关闭的管道（或者尝试通过管道写给一个没有读取的进程）时，系统会发送 SIGPIPE 信号给进程
                                  默认情况下，这将终止进程。在给定的代码中，通过将信号处理程序设置为 SIG_IGN，表明进程将忽略 SIGPIPE 信号，
                                  而不会因为管道写入问题而终止。*/

}


/* Rewrite argv for QEMU. */

static char** get_qemu_argv(u8* own_loc, char** argv, int argc) {

  char** new_argv = ck_alloc(sizeof(char*) * (argc + 4));   //多申请4个char*成员的数组
  u8 *tmp, *cp, *rsl, *own_copy;

  /* Workaround for a QEMU stability glitch. QEMU稳定性故障的解决方法 */

  setenv("QEMU_LOG", "nochain", 1);   //设置环境变量

  memcpy(new_argv + 3, argv + 1, sizeof(char*) * argc);   //复制除程序名外的所有命令参数

  new_argv[2] = target_path;    //设置被测试程序的路径
  new_argv[1] = "--"; //

  /* Now we need to actually find the QEMU binary to put in argv[0]. 现在我们需要实际找到 QEMU 二进制文件并将其放入 argv[0] 中。*/

  tmp = getenv("AFL_PATH");   

  if (tmp) {   
    //在AFL_PATH环境变量指定的路径下查询qemu执行程序

    cp = alloc_printf("%s/afl-qemu-trace", tmp);    //拼接路径

    if (access(cp, X_OK))   
      FATAL("Unable to find '%s'", tmp);  //qemu文件没有可执行权限，终止程序

    target_path = new_argv[0] = cp;   //更新被测试文件和命令行参数为qemu
    return new_argv;    //返回命令行参数

  }

  //AFL_PATH环境变量获取失败

  own_copy = ck_strdup(own_loc);    
  rsl = strrchr(own_copy, '/');

  if (rsl) {

    //在被测试程序路径下查询qemu执行程序
    *rsl = 0;

    cp = alloc_printf("%s/afl-qemu-trace", own_copy);
    ck_free(own_copy);

    if (!access(cp, X_OK)) {   

      target_path = new_argv[0] = cp; //qemu文件存在可执行权限，更新被测试文件和命令行参数
      return new_argv;

    }

  } else ck_free(own_copy);

  if (!access(BIN_PATH "/afl-qemu-trace", X_OK)) {
     //在被BIN_PATH路径下查询qemu执行程序
    target_path = new_argv[0] = ck_strdup(BIN_PATH "/afl-qemu-trace");  //qemu文件存在可执行权限，更新被测试文件和命令行参数
    return new_argv;

  }

  //在AFL_PATH环境变量指定目录、被测试程序所在目录、编译器BIN_PATH宏标记目录下均为查询到qemu程序，终止
  SAYF("\n" cLRD "[-] " cRST
       "Oops, unable to find the 'afl-qemu-trace' binary. The binary must be built\n"
       "    separately by following the instructions in qemu_mode/README.qemu. If you\n"
       "    already have the binary installed, you may need to specify AFL_PATH in the\n"
       "    environment.\n\n"

       "    Of course, even without QEMU, afl-fuzz can still work with binaries that are\n"
       "    instrumented at compile time with afl-gcc. It is also possible to use it as a\n"
       "    traditional \"dumb\" fuzzer by specifying '-n' in the command line.\n");

  FATAL("Failed to locate 'afl-qemu-trace'.");

}


/* Make a copy of the current command line. */
//将所有参数拼接为一个字符串，使用空格分隔
static void save_cmdline(u32 argc, char** argv) {

  u32 len = 1, i;
  u8* buf;

  for (i = 0; i < argc; i++)    //遍历所有参数字符串
    len += strlen(argv[i]) + 1;   //计算长度，包括一个空格 
  
  buf = orig_cmdline = ck_alloc(len); //为所有参数字符串申请内存

  for (i = 0; i < argc; i++) {    //遍历所有参数字符串

    u32 l = strlen(argv[i]);  

    memcpy(buf, argv[i], l);    //复制当前参数
    buf += l;

    if (i != argc - 1) *(buf++) = ' ';  //不是最后一个参数，添加空格

  }

  *buf = 0; //最后一个参数结束添加0

}


#ifndef AFL_LIB

/* Main entry point */

int main(int argc, char** argv) {

  s32 opt;
  u64 prev_queued = 0;
  u32 sync_interval_cnt = 0, seek_to;
  u8  *extras_dir = 0;
  u8  mem_limit_given = 0;
  u8  exit_1 = !!getenv("AFL_BENCH_JUST_ONE");  //转为boolean值
  char** use_argv;

  struct timeval tv;
  struct timezone tz;
  
  //展示版本信息
  SAYF(cCYA "afl-fuzz " cBRI VERSION cRST " by <lcamtuf@google.com>\n");

  //检查DOC_PATH宏定义的文件是否存在，不存在使用docs
  //DOC_PATH再Makefile文件中定义，F_OK是access函数的一个标志，表示检查文件是否存在
  doc_path = access(DOC_PATH, F_OK) ? "docs" : DOC_PATH;

  //基于系统时间设置随机数种子
  gettimeofday(&tv, &tz);
  srandom(tv.tv_sec ^ tv.tv_usec ^ getpid());

  //遍历命令行参数,getopt是一个库函数，用于解析命令行参数
  //返回-1表示没有有效参数了
  while ((opt = getopt(argc, argv, "+i:o:f:m:b:t:T:dnCB:S:M:x:QV")) > 0)        //getopt遇到--后停止，并且optind为下一个参数的索引

    switch (opt) {
      
      //-i 测试用例输入目录
      case 'i': /* input dir */

        //指定了多个-i
        if (in_dir) FATAL("Multiple -i options not supported");

        //设置全局变量
        in_dir = optarg;

        //没有指定路径，使用其他方法？
        if (!strcmp(in_dir, "-")) in_place_resume = 1;

        break;

      //-o 测试用例输出目录
      case 'o': /* output dir */

        //指定了多个-o
        if (out_dir) FATAL("Multiple -o options not supported");
        out_dir = optarg; //设置全局变量
        break;


      //分布式模式的主程序（Master）
      case 'M': { /* master sync ID */

          u8* c;

          //参数指定多次
          if (sync_id) FATAL("Multiple -S or -M options not supported");

          //备份参数值并保存
          sync_id = ck_strdup(optarg);

          //检测参数中的:，:前的值为名称，后面为xx
          if ((c = strchr(sync_id, ':'))) {

            *c = 0; //截断，用于后续fix_up_sync检测
            
            //读取:后面的数值给全局变量，并检测
            if (sscanf(c + 1, "%u/%u", &master_id, &master_max) != 2 ||
                !master_id || !master_max || master_id > master_max ||
                master_max > 1000000) FATAL("Bogus master ID passed to -M");
          }

          //指定当前进程仅使用确定性检测
          force_deterministic = 1;

        }

        break;

      //分布式模式的从程序（slave）
      case 'S': 

        //参数指定多次
        if (sync_id) FATAL("Multiple -S or -M options not supported");

        //备份参数值并保存
        sync_id = ck_strdup(optarg);
        break;

      //输出文件名，用于后续被fuzz程序读取
      case 'f': /* target file */

        //参数指定多次
        if (out_file) FATAL("Multiple -f options not supported");

        //保存参数
        out_file = optarg;
        break;

      //字典  
      case 'x': /* dictionary */
        //参数指定多次
        if (extras_dir) FATAL("Multiple -x options not supported");
        extras_dir = optarg;  //保存参数，参数是一个目录或文件
        break;

      //执行超时时间（挂起超时时间通过环境变量配置）
      case 't': { /* timeout */

          u8 suffix = 0;
          
          //参数指定多次
          if (timeout_given) FATAL("Multiple -t options not supported");

          //读取时间到变量，并检测
          if (sscanf(optarg, "%u%c", &exec_tmout, &suffix) < 1 ||
              optarg[0] == '-') FATAL("Bad syntax used for -t");

          //超时时间太短
          if (exec_tmout < 5) FATAL("Dangerously low value of -t");

          //？？？
          if (suffix == '+') timeout_given = 2; else timeout_given = 1;

          break;

      }

      //指定内存限制
      case 'm': { /* mem limit */

          u8 suffix = 'M';

          //参数指定多次
          if (mem_limit_given) FATAL("Multiple -m options not supported");
          mem_limit_given = 1;    //表示使用给定的内存限制

          //none 不限制内存大小
          if (!strcmp(optarg, "none")) {

            mem_limit = 0;  
            break;

          }

          //读取内存限制到变量，并检测
          if (sscanf(optarg, "%llu%c", &mem_limit, &suffix) < 1 ||
              optarg[0] == '-') FATAL("Bad syntax used for -m");

          //检测给定的内存限制规格并计算，默认为MB
          switch (suffix) {

            case 'T': mem_limit *= 1024 * 1024; break;
            case 'G': mem_limit *= 1024; break;
            case 'k': mem_limit /= 1024; break;
            case 'M': break;

            default:  FATAL("Unsupported suffix or bad syntax for -m");

          }

          //小于5MB，退出
          if (mem_limit < 5) FATAL("Dangerously low value of -m");

          //32位系统，内存限制接近2G，退出
          if (sizeof(rlim_t) == 4 && mem_limit > 2000)
            FATAL("Value of -m out of range on 32-bit systems");

        }

        break;
      
      case 'b': { /* bind CPU core */

          if (cpu_to_bind_given) FATAL("Multiple -b options not supported");
          cpu_to_bind_given = 1;

          if (sscanf(optarg, "%u", &cpu_to_bind) < 1 ||
              optarg[0] == '-') FATAL("Bad syntax used for -b");

          break;

      }

      //不进行确定性检测
      case 'd': /* skip deterministic */

        //
        if (skip_deterministic) FATAL("Multiple -d options not supported");
        skip_deterministic = 1;   //跳过确定性检测
        use_splicing = 1; //？？？
        break;

      //加载位图，将测试点同步到位图时间节点
      case 'B': /* load bitmap */

        /* This is a secret undocumented option! It is useful if you find
           an interesting test case during a normal fuzzing process, and want
           to mutate it without rediscovering any of the test cases already
           found during an earlier run.

           To use this mode, you need to point -B to the fuzz_bitmap produced
           by an earlier run for the exact same binary... and that's it.

           I only used this once or twice to get variants of a particular
           file, so I'm not making this an official setting. 
           
           这是一个秘密的未记录选项！ 如果您在正常的模糊测试过程中发现了一个有趣的测试用例，
           并且想要对其进行修改而不重新发现在早期运行期间已找到的任何测试用例，那么它会很有用。
           要使用此模式，您需要将 -B 指向由先前运行的完全相同的二进制文件生成的 fuzz_bitmap...就是这样。
           我只使用过一次或两次来获取特定文件的变体，因此我不会将其作为官方设置。
           */
        
       
        if (in_bitmap) FATAL("Multiple -B options not supported");  //参数重复指定

        in_bitmap = optarg;//保存数据文件名
        read_bitmap(in_bitmap);  //加载位图文件到virgin_bits数组，而不是共享内存
        break;

      //指定崩溃模式
      case 'C': /* crash mode */

        if (crash_mode) FATAL("Multiple -C options not supported");//重复指定
        crash_mode = FAULT_CRASH;
        break;

      //哑模式？？？
      case 'n': /* dumb mode */

        if (dumb_mode) FATAL("Multiple -n options not supported");  //参数重复指定
        if (getenv("AFL_DUMB_FORKSRV")) dumb_mode = 2; else dumb_mode = 1;  //根据环境变量确定具体值？？？

        break;

      //指定横幅信息
      case 'T': /* banner */

        if (use_banner) FATAL("Multiple -T options not supported"); //参数重复指定
        use_banner = optarg;
        break;

      //QEMU模式
      case 'Q': /* QEMU mode */

        if (qemu_mode) FATAL("Multiple -Q options not supported");  //参数重复指定
        qemu_mode = 1;    //qemu模式标识
      
        if (!mem_limit_given) mem_limit = MEM_LIMIT_QEMU;   //未通过-m参数指定内存限制大小，则使用默认qemu模式内存限制 200M

        break;

      //显示版本信息
      case 'V': /* Show version number */

        /* Version number has been printed already, just quit. */
        exit(0);  //版本信息已经打印了，直接退出

      default:  //其他情况

        usage(argv[0]);  //显示AFL使用方法，并退出

    }

  //解析完了所有参数，但是没有指定输入目录和输出目录，则显示AFL使用方法，并退出
  if (optind == argc || !in_dir || !out_dir) usage(argv[0]);

  setup_signal_handlers();  //设置信号量处理程序
  check_asan_opts();  //检查asan选项
  //主从模式指定sync_id
  if (sync_id) fix_up_sync();     //主从模式下，修改文件输出目录，并设置确定性变异跳过或强制标识

  if (!strcmp(in_dir, out_dir)) //输入和输出目录不可相同
    FATAL("Input and output directories can't be the same");

  if (dumb_mode) {
    //哑模式不可以与崩溃模式、qemu模式一起使用
    if (crash_mode) FATAL("-C and -n are mutually exclusive");
    if (qemu_mode)  FATAL("-Q and -n are mutually exclusive");

  }
  //根据环境变量设置全局标识
  if (getenv("AFL_NO_FORKSRV"))    no_forkserver    = 1;
  if (getenv("AFL_NO_CPU_RED"))    no_cpu_meter_red = 1;
  if (getenv("AFL_NO_ARITH"))      no_arith         = 1;
  if (getenv("AFL_SHUFFLE_QUEUE")) shuffle_queue    = 1;  //打乱测试样本顺序
  if (getenv("AFL_FAST_CAL"))      fast_cal         = 1;

  if (getenv("AFL_HANG_TMOUT")) { //设置挂起超时时间
    hang_tmout = atoi(getenv("AFL_HANG_TMOUT"));
    if (!hang_tmout) FATAL("Invalid value of AFL_HANG_TMOUT");    //设置失败
  }

  if (dumb_mode == 2 && no_forkserver)    //DUMB_FORKSRV哑模式和no_forkserver不可一起使用，哑模式有两种
    FATAL("AFL_DUMB_FORKSRV and AFL_NO_FORKSRV are mutually exclusive");

  if (getenv("AFL_PRELOAD")) {  //通过AFL_PRELOAD环境变量，指定程序运行时需要加载的共享库
    setenv("LD_PRELOAD", getenv("AFL_PRELOAD"), 1); //LINUX环境变量
    setenv("DYLD_INSERT_LIBRARIES", getenv("AFL_PRELOAD"), 1);    //MACOS环境变量
  }

  if (getenv("AFL_LD_PRELOAD"))   //确保使用正确的环境变量，以避免潜在的错误或混淆。
    FATAL("Use AFL_PRELOAD instead of AFL_LD_PRELOAD");

  save_cmdline(argc, argv);   //将所有参数拼接为一个字符串，使用空格分隔，然后保存到全局变量

  fix_up_banner(argv[optind]);    //使用被测试程序名称设置banner

  check_if_tty();   //检测是否在终端/控制台运行程序

  get_core_count(); //计算逻辑CPU核心数，并根据系统运行状态，给出优化建议或警告信息

#ifdef HAVE_AFFINITY    //CPU亲和性
  //绑定进程到某个内核
  bind_to_free_cpu();    
#endif /* HAVE_AFFINITY */

  check_crash_handling();   //检测崩溃程序的核心转储文件如何保存，如何写入外部文件，且不忽略核心转储文件，则打印提示信息退出
  check_cpu_governor();   //检查CPU频率调整策略，非performance或频率为动态调整，则打印提示信息退出

  setup_post();   //加载后处理函数，用于处理测试结束后的工作
  setup_shm();    //设置共享内存和相关退出回调函数
  init_count_class16();   //初始化count_class_lookup16数组，用于16位的数据规整

  setup_dirs_fds();   //准备输出目录和文件描述符；如果输出目录存在，则会根据根据情况决定是否恢复上次会话
  read_testcases();   //读取测试用例，加入队列
  load_auto();    //加载上次工作自动发现的字典文件

  pivot_inputs();   //链接或复制输入目录的测试样本到输出目录，并命名为ID:x格式；
                    //如果是恢复会话，则删除_resume目录，也表示输入目录的相关工作到此结束

  if (extras_dir) load_extras(extras_dir);      //从文件或目录加载字典文件

  if (!timeout_given) find_timeout();   //命令行未指定执行超时时间，则尝试根据之前任务的fuzzer_stats恢复时间

  detect_file_args(argv + optind + 1);    //检测被测试程序的参数，此时optind为被测试程序的索引，+1指向其参数
                                          //检测被测试程序的命令行参数；将所有的@@替换为测试用例的输出文件名，(如果out_file未设置，则会设置默认文件)

  if (!out_file) setup_stdio_file();    //未指定输出文件名，且被测试程序的命令行参数也不存在@@标识，设置fuzz数据的输出文件（未使用-f参数）
                                        //区别在于，后续是通过文件（out_file有值）还是标准输入（out_file无值）传递数据给被测试文件
  
  check_binary(argv[optind]);     //检查被测试程序；文件路径是否存在、是否为可执行文件；检测文件内容是否满足可执行文件格式以及是否存在特定标识等

  start_time = get_cur_time();    //获取当前系统时间

  if (qemu_mode)    
    //qemu模式
    use_argv = get_qemu_argv(argv[0], argv + optind, argc - optind);    //为qemu模式构造命令参数   
                                       //在AFL_PATH环境变量指定目录、被测试程序所在目录和编译器BIN_PATH宏标记目录下查询到qemu程序，并修改命令行参数
  else
    use_argv = argv + optind;  //使用--后面的被测试程序的命令参数

  perform_dry_run(use_argv);    //运行被测试程序处理每个测试用例（每次测试起一个子进程，每个测试用例会测试多次），查看运行结果并输出提示
                                //当前进程在这个函数内通过execv转为被测试程序，fuzzer程序则通过fork子进程继续执行

  cull_queue();   //根据测试用例是否为共享内存字节的最优测试用例设置其受青睐标记和不太有用标记

  show_init_stats();    //显示初始化状态信息，同时根据条件设置执行超时时间和挂起时间

  seek_to = find_start_position();    //查询测试用例的队列偏移（新任务从0开始，恢复任务根据状态文件中的数值决定）

  write_stats_file(0, 0, 0);    //保存状态信息到文件，参数0表示使用全局的信息
  save_auto();    //保存自动发现的字典条目

  if (stop_soon) goto stop_fuzzing;   //检测到停止标志（目前该标志在show_stats()或ctrl+c处理程序中设置）

  /* Woop woop woop */

  if (!not_on_tty) {    //不存在终端，等待四秒，查看是否存在ctrl+c信号
    sleep(4);
    start_time += 4000;
    if (stop_soon) goto stop_fuzzing;
  }

  while (1) {

    u8 skipped_fuzz;

    cull_queue(); //根据测试用例是否为共享内存字节的最优测试用例设置其受青睐标记和不太有用标记

    if (!queue_cur) {   //当前没有指定测试用例，初始化fuzz环境

      queue_cycle++;    //测试队列的循环次数+1
      current_entry     = 0;
      cur_skipped_paths = 0;
      queue_cur         = queue;    //指定为测试用例队列头

      while (seek_to) {   //计算跳过几个测试用例
        current_entry++;    //测试用例ID
        seek_to--;
        queue_cur = queue_cur->next;    //下一个测试用例
      }

      show_stats();    //打印状态信息，并根据条件保存相关数据到文件，并根据条件设置stop_soon

      if (not_on_tty) {     //没有tty
        ACTF("Entering queue cycle %llu.", queue_cycle);
        fflush(stdout);
      }

      /* If we had a full queue cycle with no new finds, try
         recombination strategies next. 如果我们有一个完整的队列周期而没有新的发现，那么接下来尝试重组策略*/

      if (queued_paths == prev_queued) {    //当前测试用例数量和上次一样
        
        //use_splicing由-d参数指定，表示重新排列输入文件
        if (use_splicing) //指定了use_splicing由 
          cycles_wo_finds++;  //循环没发现新路径数+1
        else 
          use_splicing = 1; //未指定use_splicing则指定use_splicing

      } else cycles_wo_finds = 0;   //当前测试用例数量和上次不同，没发现新路径数量置0

      prev_queued = queued_paths;   //设置本次测试用例数量

      //指定了主从模式，且第一次处理测试队列，且指定环境变量AFL_IMPORT_FIRST
      if (sync_id && queue_cycle == 1 && getenv("AFL_IMPORT_FIRST"))
        sync_fuzzers(use_argv); // 获取其他进程的有趣测试用例
                                // 遍历根输出目录，检测其他进程是否存在队列文件，然后通过同步目录下记录文件检测本次读取的测试用例名称，随后对运行被测试程序处理测试用例，并根据路径反馈信息决定是否添加到测试用例队列
    }

    skipped_fuzz = fuzz_one(use_argv);    //fuzz核心函数 根据条件进行确定变异、随机变异、拼接文件；测试结束，返回0；跳过当前测试用例返回1  
                                          //会根据条件跳过当前测试用例，因此一个循环结束后，可能并非所有测试用例都处理一次

    //不终止程序、指定主从模式、fuzz_one结束
    if (!stop_soon && sync_id && !skipped_fuzz) {
      
      if (!(sync_interval_cnt++ % SYNC_INTERVAL))   //达到了主从模式测试用例同步周期
        sync_fuzzers(use_argv);  // 获取其他进程的有趣测试用例
                                 // 遍历根输出目录，检测其他进程是否存在队列文件，然后通过同步目录下记录文件检测本次读取的测试用例名称，随后对运行被测试程序处理测试用例，并根据路径反馈信息决定是否添加到测试用例队列
    }

    //不终止程序，但是检测到了只允许一次的标识，用于对第一个测试用例进行验证
    if (!stop_soon && exit_1) stop_soon = 2;

    if (stop_soon) break;   //检测到停止标记，退出循环

    queue_cur = queue_cur->next;    //下一个测试用例（为最后一个测试用例时，queue_cur为0，然后重置循环数据）
    current_entry++;    //下一个测试用例的ID

  }

  if (queue_cur) show_stats();      //打印状态信息，并根据条件保存相关数据到文件，并根据条件设置stop_soon

  /* If we stopped programmatically, we kill the forkserver and the current runner. 
     If we stopped manually, this is done by the signal handler.
     如果我们以编程方式停止，我们就会杀死forkserver和当前的runner。如果我们手动停止，这是由信号处理程序完成的。 */

  if (stop_soon == 2) {   //stop_soon为2表示编程方式停止，需要关闭子进程
      if (child_pid > 0) kill(child_pid, SIGKILL);  //关闭子进程
      if (forksrv_pid > 0) kill(forksrv_pid, SIGKILL);    //关闭forserver进程
  }

  /* Now that we've killed the forkserver, we wait for it to be able to get rusage stats.
  现在我们已经杀死了forkserver，我们等待它能够获得rusage统计数据。 */

  if (waitpid(forksrv_pid, NULL, 0) <= 0) {   //等到子进程结束
    WARNF("error waitpid\n");
  }

  write_bitmap(); //保存virgin_bits数组到fuzz_bitmap文件
  write_stats_file(0, 0, 0);  //保存状态信息到文件，参数0表示使用全局的信息
  save_auto();   //保存自动发现的字典条目

stop_fuzzing:

  //打印停止信息
  SAYF(CURSOR_SHOW cLRD "\n\n+++ Testing aborted %s +++\n" cRST,
       stop_soon == 2 ? "programmatically" : "by user");

  /* Running for more than 30 minutes but still doing first cycle? */
  
  //第一个测试队列运行了30分钟
  if (queue_cycle == 1 && get_cur_time() - start_time > 30 * 60 * 1000) {

    SAYF("\n" cYEL "[!] " cRST
           "Stopped during the first cycle, results may be incomplete.\n"
           "    (For info on resuming, see %s/README.)\n", doc_path);

  }

  fclose(plot_file);    //关闭Gnuplot输出文件（图形数据统计）
  destroy_queue();    //销毁队列
  destroy_extras();   //销毁字典
  ck_free(target_path);   //释放内存
  ck_free(sync_id);   //释放内存

  alloc_report();   //根据宏定义,在DEBUG模式下会打印信息

  OKF("We're done here. Have a nice day!\n");

  exit(0);  //退出

}

#endif /* !AFL_LIB */
