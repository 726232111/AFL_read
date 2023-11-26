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
   american fuzzy lop - wrapper for GNU as
   ---------------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>

   The sole purpose of this wrapper is to preprocess assembly files generated
   by GCC / clang and inject the instrumentation bits included from afl-as.h. It
   is automatically invoked by the toolchain when compiling programs using
   afl-gcc / afl-clang.

   Note that it's an explicit non-goal to instrument hand-written assembly,
   be it in separate .s files or in __asm__ blocks. The only aspiration this
   utility has right now is to be able to skip them gracefully and allow the
   compilation process to continue.

   That said, see experimental/clang_asm_normalize/ for a solution that may
   allow clang users to make things work even with hand-crafted assembly. Just
   note that there is no equivalent for GCC.

*/

#define AFL_MAIN

#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"

#include "afl-as.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <fcntl.h>

#include <sys/wait.h>
#include <sys/time.h>

static u8** as_params;          /* Parameters passed to the real 'as' 传递给实际as的参数  */

static u8*  input_file;         /* Originally specified input file    最初指定的输入文件  */
static u8*  modified_file;      /* Instrumented file for the real 'as' 实际as的输入文件 */

static u8   be_quiet,           /* Quiet mode (no stderr output)   安静模式（无stderr输出）     */
            clang_mode,         /* Running in clang mode?               */
            pass_thru,          /* Just pass data through?       只是传递数据？       */
            just_version,       /* Just show version?                   */
            sanitizer;          /* Using ASAN / MSAN                    */

static u32  inst_ratio = 100,   /* Instrumentation probability (%)      */
            as_par_cnt = 1;     /* Number of params to 'as'             */

/* If we don't find --32 or --64 in the command line, default to 
   instrumentation for whichever mode we were compiled with. This is not
   perfect, but should do the trick for almost all use cases. */

//64位系统
#ifdef WORD_SIZE_64

static u8   use_64bit = 1;

#else

static u8   use_64bit = 0;

//苹果系统
#ifdef __APPLE__
#  error "Sorry, 32-bit Apple platforms are not supported."
#endif /* __APPLE__ */

#endif /* ^WORD_SIZE_64 */


/* Examine and modify parameters to pass to 'as'. Note that the file name
   is always the last parameter passed by GCC, so we exploit this property
   to keep the code simple.
   文件名始终是GCC传递的最后一个参数 */
//指定汇编器，然后复制除输入文件外的所有参数到新的参数列表中，最后创建一个临时文件名称作输入文件
static void edit_params(int argc, char** argv) {

  //获取临时目录、AFL_AS环境变量
  u8 *tmp_dir = getenv("TMPDIR"), *afl_as = getenv("AFL_AS");
  u32 i;

//苹果系统
#ifdef __APPLE__

  u8 use_clang_as = 0;

  /* On MacOS X, the Xcode cctool 'as' driver is a bit stale and does not work
     with the code generated by newer versions of clang that are hand-built
     by the user. See the thread here: http://goo.gl/HBWDtn.

     To work around this, when using clang and running without AFL_AS
     specified, we will actually call 'clang -c' instead of 'as -q' to
     compile the assembly file.

     The tools aren't cmdline-compatible, but at least for now, we can
     seemingly get away with this by making only very minor tweaks. Thanks
     to Nico Weber for the idea. */

  if (clang_mode && !afl_as) {

    use_clang_as = 1;

    afl_as = getenv("AFL_CC");
    if (!afl_as) afl_as = getenv("AFL_CXX");
    if (!afl_as) afl_as = "clang";

  }

#endif /* __APPLE__ */

  /* Although this is not documented, GCC also uses TEMP and TMP when TMPDIR
     is not set. We need to check these non-standard variables to properly
     handle the pass_thru logic later on. */

  //查询是否指定临时目录
  if (!tmp_dir) tmp_dir = getenv("TEMP");
  if (!tmp_dir) tmp_dir = getenv("TMP");
  if (!tmp_dir) tmp_dir = "/tmp";

  //多申请32个参数的指针
  as_params = ck_alloc((argc + 32) * sizeof(u8*));

  //环境变量没有指定汇编器，则使用as
  as_params[0] = afl_as ? afl_as : (u8*)"as";

  //设置参数结束标志
  as_params[argc] = 0;

  //遍历参数，最后一个参数不处理，后面单独处理
  for (i = 1; i < argc - 1; i++) {

    //检测64位模式
    if (!strcmp(argv[i], "--64")) use_64bit = 1;
    else if (!strcmp(argv[i], "--32")) use_64bit = 0;

#ifdef __APPLE__

    /* The Apple case is a bit different... */

    if (!strcmp(argv[i], "-arch") && i + 1 < argc) {

      if (!strcmp(argv[i + 1], "x86_64")) use_64bit = 1;
      else if (!strcmp(argv[i + 1], "i386"))
        FATAL("Sorry, 32-bit Apple platforms are not supported.");

    }

    /* Strip options that set the preference for a particular upstream
       assembler in Xcode. */

    if (clang_mode && (!strcmp(argv[i], "-q") || !strcmp(argv[i], "-Q")))
      continue;

#endif /* __APPLE__ */

    //复制所有参数
    as_params[as_par_cnt++] = argv[i];

  }

//苹果系统的clang汇编器，添加额外参数
#ifdef __APPLE__

  /* When calling clang as the upstream assembler, append -c -x assembler
     and hope for the best. */

  if (use_clang_as) {

    as_params[as_par_cnt++] = "-c";
    as_params[as_par_cnt++] = "-x";
    as_params[as_par_cnt++] = "assembler";

  }

#endif /* __APPLE__ */

  //默认约定将输入文件作为最后一个参数
  input_file = argv[argc - 1];

  //检测最后一个参数是为命令选项
  if (input_file[0] == '-') {

    //最后一个参数为显示版本信息
    if (!strcmp(input_file + 1, "-version")) {
      just_version = 1;  //设置仅显示版本信息的标识
      modified_file = input_file;  //文件名指定为--version
      goto wrap_things_up;  //填充参数，结束处理
    }

    //最后一个参数不是--version,报错并退出
    if (input_file[1]) FATAL("Incorrect use (not called through afl-gcc?)");
    //最后一个单独一个 -，标识没有输入文件
      else input_file = NULL;

  } else {
    //最后一个参数不是命令选项

    /* Check if this looks like a standard invocation as a part of an attempt
       to compile a program, rather than using gcc on an ad-hoc .s file in
       a format we may not understand. This works around an issue compiling
       NSS. */

    //如果输入文件的路径不是临时目录，则设置pass_thru
    if (strncmp(input_file, tmp_dir, strlen(tmp_dir)) &&
        strncmp(input_file, "/var/tmp/", 9) &&
        strncmp(input_file, "/tmp/", 5)) pass_thru = 1;

  }

  //指定临时文件的名称
  modified_file = alloc_printf("%s/.afl-%u-%u.s", tmp_dir, getpid(),
                               (u32)time(NULL));

wrap_things_up:

  as_params[as_par_cnt++] = modified_file;   //指定修改的文件
  as_params[as_par_cnt]   = NULL;  //参数结束标记

}


/* Process input file, generate modified_file. Insert instrumentation in all
   the appropriate places. */

/*
  插桩思路
    遍历汇编文件每一行
      检测intel风格、嵌入汇编代码、操作码位数、代码段、标签、指令
      在jcc指令下一行插入插桩代码
      在.L<num> / .LBB<num>标签和函数标签下一行插入插桩代码(会根据插桩比率和其他参数进行条件判断)
    在汇编文件最后写入与fuzz进程交互、初始化环境和计算路径覆盖率的代码
*/

//对输入文件进行插桩，并生成新文件
static void add_instrumentation(void) {

  static u8 line[MAX_LINE];

  FILE* inf;
  FILE* outf;
  s32 outfd;
  u32 ins_lines = 0;

  u8  instr_ok = 0, skip_csect = 0, skip_next_label = 0,
      skip_intel = 0, skip_app = 0, instrument_next = 0;

#ifdef __APPLE__

  u8* colon_pos;

#endif /* __APPLE__ */

  //将文件或标准输入设置为输入文件流
  if (input_file) {

    inf = fopen(input_file, "r");
    if (!inf) PFATAL("Unable to read '%s'", input_file);  //打开失败，exit()

  } else inf = stdin;

  //打开临时文件
  outfd = open(modified_file, O_WRONLY | O_EXCL | O_CREAT, 0600);

  if (outfd < 0) PFATAL("Unable to write to '%s'", modified_file);

  //设置输出文件流
  outf = fdopen(outfd, "w");

  if (!outf) PFATAL("fdopen() failed");  

  //从输入流中一次读取一行，每行最大为MAX_LINE-1个字符
  while (fgets(line, MAX_LINE, inf)) {

    /* In some cases, we want to defer writing the instrumentation trampoline
       until after all the labels, macros, comments, etc. If we're in this
       mode, and if the line starts with a tab followed by a character, dump
       the trampoline now. */

    
    //在符号标签的下一行插桩
    /*
      检测到合适的符号标记，通过下面的代码插入代码，然后写入之前的汇编指令
    */

    //非数据传递模式，且不是intel风格，且不是嵌入汇编代码，且匹配当前代码位数、且是代码段、
    //并且之前可用行代码是.L<num> / .LBB<num>标签，且当前行满足代码指令格式，则写入插桩代码
    if (!pass_thru && !skip_intel && !skip_app && !skip_csect && instr_ok &&
        instrument_next && line[0] == '\t' && isalpha(line[1])) {

      //写入插桩代码
      fprintf(outf, use_64bit ? trampoline_fmt_64 : trampoline_fmt_32,
              R(MAP_SIZE));

      //插桩标识复位
      instrument_next = 0;
      ins_lines++;  //插桩的数量

    }


    /* Output the actual line, call it a day in pass-thru mode. */

    //pass_thru置为1时，则仅复制文件，并不做修改
    //将文件复制到临时目录？？不太理解
    fputs(line, outf);

    if (pass_thru) continue;

    /* All right, this is where the actual fun begins. For one, we only want to
       instrument the .text section. So, let's keep track of that in processed
       files - and let's set instr_ok accordingly. */

    //当前行是否以\t.起始
    if (line[0] == '\t' && line[1] == '.') {

      /* OpenBSD puts jump tables directly inline with the code, which is
         a bit annoying. They use a specific format of p2align directives
         around them, so we use that as a signal. */

      //非clang模式，且是代码段，且存在openbsd标记，则skip_next_label=1
      //检测openbsd格式，用于跳过下个标签
      if (!clang_mode && instr_ok && !strncmp(line + 2, "p2align ", 8) &&
          isdigit(line[10]) && line[11] == '\n') skip_next_label = 1;

      //代码段标志，instr_ok=1
      if (!strncmp(line + 2, "text\n", 5) ||
          !strncmp(line + 2, "section\t.text", 13) ||
          !strncmp(line + 2, "section\t__TEXT,__text", 21) ||
          !strncmp(line + 2, "section __TEXT,__text", 21)) {
        instr_ok = 1;
        continue; 
      }

       //非代码段标志，instr_ok=0
      if (!strncmp(line + 2, "section\t", 8) ||
          !strncmp(line + 2, "section ", 8) ||
          !strncmp(line + 2, "bss\n", 4) ||
          !strncmp(line + 2, "data\n", 5)) {
        instr_ok = 0;
        continue;
      }

    }

    /* Detect off-flavor assembly (rare, happens in gdb). When this is
       encountered, we set skip_csect until the opposite directive is
       seen, and we do not instrument. */

    //检测代码是32位还是64位的？？
    if (strstr(line, ".code")) {

      if (strstr(line, ".code32")) skip_csect = use_64bit;  //64位系统下，该值是1；32位系统下，该值是0
      if (strstr(line, ".code64")) skip_csect = !use_64bit; //64位系统下，该值是0；32位系统下，该值是1
                                                            //根据赋值情况，可以发现满足当前系统位数则位0，否则为1，后续将跳过不匹配的代码段
    }

    /* Detect syntax changes, as could happen with hand-written assembly.
       Skip Intel blocks, resume instrumentation when back to AT&T. */

    //是否为intel风格汇编，如果是则设置skip_intel
    if (strstr(line, ".intel_syntax")) skip_intel = 1;
    if (strstr(line, ".att_syntax")) skip_intel = 0;

    /* Detect and skip ad-hoc __asm__ blocks, likewise skipping them. */
    //"ad-hoc asm 块" 指的是在汇编语言中嵌入在源代码中的 __asm__ 块 (c代码中通过__asm__ 形式嵌入的汇编块，而不是编译器解析出来的)

    if (line[0] == '#' || line[1] == '#') {
      /*在汇编文件中，#APP 和 #NO_APP 是 GNU 汇编器 (as) 特定的伪指令，用于标记 __asm__ 块的开始和结束
      #APP 表示开始 __asm__ 块，#NO_APP 表示结束。*/
      if (strstr(line, "#APP")) skip_app = 1;
      if (strstr(line, "#NO_APP")) skip_app = 0;

    }

    /* If we're in the right mood for instrumenting, check for function
       names or conditional labels. This is a bit messy, but in essence,
       we want to catch:

         ^main:      - function entry point (always instrumented)
         ^.L0:       - GCC branch label
         ^.LBB0_0:   - clang branch label (but only in clang mode)
         ^\tjnz foo  - conditional branches

       ...but not:

         ^# BB#0:    - clang comments
         ^ # BB#0:   - ditto
         ^.Ltmp0:    - clang non-branch labels
         ^.LC0       - GCC non-branch labels
         ^.LBB0_0:   - ditto (when in GCC mode)
         ^\tjmp foo  - non-conditional jumps

       Additionally, clang and GCC on MacOS X follow a different convention
       with no leading dots on labels, hence the weird maze of #ifdefs
       later on.

     */

    //跳过inter风格汇编、嵌入汇编、不匹配位数的代码段、非代码段、注释行，空白行
    if (skip_intel || skip_app || skip_csect || !instr_ok ||
        line[0] == '#' || line[0] == ' ') continue;

    /* Conditional branch instruction (jnz, etc). We append the instrumentation
       right after the branch (to instrument the not-taken path) and at the
       branch destination label (handled later on). */

    //在跳转指令的下一行插桩
    if (line[0] == '\t') {
      
      //\tjcc指令，且非jmp,并且随机数小于分布率则插入插桩代码
      if (line[1] == 'j' && line[2] != 'm' && R(100) < inst_ratio) {

        fprintf(outf, use_64bit ? trampoline_fmt_64 : trampoline_fmt_32,
                R(MAP_SIZE));  //指定一个随机数，不会存在重复情况吗

        ins_lines++;   //插桩的数量

      }
      //插桩成功，继续读取下一行
      continue;

    }

    /* Label of some sort. This may be a branch destination, but we need to
       tread carefully and account for several different formatting
       conventions. */

#ifdef __APPLE__

    /* Apple: L<whatever><digit>: */

    if ((colon_pos = strstr(line, ":"))) {

      if (line[0] == 'L' && isdigit(*(colon_pos - 1))) {

#else

    /* Everybody else: .L<whatever>: */

    //行内存在: 即有标签
    if (strstr(line, ":")) {

      if (line[0] == '.') {

#endif /* __APPLE__ */

        /* .L0: or LBB0_0: style jump destination */

#ifdef __APPLE__

        /* Apple: L<num> / LBB<num> */

        if ((isdigit(line[1]) || (clang_mode && !strncmp(line, "LBB", 3)))
            && R(100) < inst_ratio) {

#else

        /* Apple: .L<num> / .LBB<num> */
        //跳转到的标签，且非jmp跳转,并且随机数小于分布率则插入插桩代码
        if ((isdigit(line[2]) || (clang_mode && !strncmp(line + 1, "LBB", 3)))
            && R(100) < inst_ratio) {

#endif /* __APPLE__ */

          /* An optimization is possible here by adding the code only if the
             label is mentioned in the code in contexts other than call / jmp.
             That said, this complicates the code by requiring two-pass
             processing (messy with stdin), and results in a speed gain
             typically under 10%, because compilers are generally pretty good
             about not generating spurious intra-function jumps.

             We use deferred output chiefly to avoid disrupting
             .Lfunc_begin0-style exception handling calculations (a problem on
             MacOS X). */
          
          //如果不跳过下一次标记，即上述的openbsd风格，则instrument_next置为1，满足条件后可插入插桩代码
          //否则将跳过下一次标记skip_next_label置为0
          if (!skip_next_label) instrument_next = 1; else skip_next_label = 0;

        }

      } else {
        
        /* Function label (always instrumented, deferred mode). */

        //不是以.开始的标签
        instrument_next = 1;
    
      }

    }

  }


//////////循环读取文件行结束后


  //将核心代码写入到文件尾部
  if (ins_lines)
    fputs(use_64bit ? main_payload_64 : main_payload_32, outf);

  //关闭输入输出流
  if (input_file) fclose(inf);
  fclose(outf);

  //非静默模式，打印详细信息
  if (!be_quiet) {

    //没有插入插桩代码
    if (!ins_lines) WARNF("No instrumentation targets found%s.",
                          pass_thru ? " (pass-thru mode)" : "");
    //插入了插桩代码
    else OKF("Instrumented %u locations (%s-bit, %s mode, ratio %u%%).",
             ins_lines, use_64bit ? "64" : "32",
             getenv("AFL_HARDEN") ? "hardened" : 
             (sanitizer ? "ASAN/MSAN" : "non-hardened"),
             inst_ratio);
 
  }

}


/* Main entry point */

int main(int argc, char** argv) {

  s32 pid;
  u32 rand_seed;
  int status;
  //环境变量
  u8* inst_ratio_str = getenv("AFL_INST_RATIO");

  struct timeval tv;
  struct timezone tz;

  //检测clang模式
  clang_mode = !!getenv(CLANG_ENV_VAR);  //!!用于转为布尔值

  //是否静默模式
  if (isatty(2) && !getenv("AFL_QUIET")) {

    SAYF(cCYA "afl-as " cBRI VERSION cRST " by <lcamtuf@google.com>\n");
 
  } else be_quiet = 1;

  //检测参数数量
  if (argc < 2) {

    SAYF("\n"
         "This is a helper application for afl-fuzz. It is a wrapper around GNU 'as',\n"
         "executed by the toolchain whenever using afl-gcc or afl-clang. You probably\n"
         "don't want to run this program directly.\n\n"

         "Rarely, when dealing with extremely complex projects, it may be advisable to\n"
         "set AFL_INST_RATIO to a value less than 100 in order to reduce the odds of\n"
         "instrumenting every discovered branch.\n\n");

    exit(1);

  }

  //获取当前时间
  gettimeofday(&tv, &tz);

  //计算伪随机数生成器的种子
  rand_seed = tv.tv_sec ^ tv.tv_usec ^ getpid();

  //初始化伪随机数生成器的种子
  srandom(rand_seed);

  //编辑传递给as的参数；//指定汇编器，然后复制除输入文件外的所有参数到新的参数列表中，最后创建一个临时文件名称作输入文件
  edit_params(argc, argv);

  //插桩比例，100%即所有代码路径都插桩
  if (inst_ratio_str) {
    //设置了AFL_INST_RATIO环境变量

    //解析环境变量失败，或给定的值大于100，打印错误信息并退出
    if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || inst_ratio > 100) 
      FATAL("Bad value of AFL_INST_RATIO (must be between 0 and 100)");

  }

  //__AFL_AS_LOOPCHECK环境变量；意思是调用as时无休止的循环，说明发生了异常
  if (getenv(AS_LOOP_ENV_VAR))
    FATAL("Endless loop when calling 'as' (remove '.' from your PATH)");

  //这里设置了AS_LOOP_ENV_VAR环境变量，当重复调用afl-as时，上行代码会检测报错
  setenv(AS_LOOP_ENV_VAR, "1", 1);

  /* When compiling with ASAN, we don't have a particularly elegant way to skip
     ASAN-specific branches. But we can probabilistically compensate for
     that... */

  //检测是否启用ASAN或MSAN
  if (getenv("AFL_USE_ASAN") || getenv("AFL_USE_MSAN")) {
    sanitizer = 1;  //ASAN或MSAN启用标志
    inst_ratio /= 3;  //减少代码插桩覆盖率，提高执行效率
  }

  //不是显示版本信息，则处理输入文件，并写入到modified_file指定的文件中
  //处理过程即实现插桩功能
  if (!just_version) add_instrumentation();

  
  if (!(pid = fork())) {

    //子进程执行as程序
    execvp(as_params[0], (char**)as_params);  //execvp执行成功，则当前的进程就会被替换为新程序，原先的进程代码和数据都会被新程序替代
                                              //因此下行代码不会执行
    FATAL("Oops, failed to execute '%s' - check your PATH", as_params[0]);  //execvp执行失败打印错误信息

  }

  //当前进程走这里

  //子进程创建失败，退出
  if (pid < 0) PFATAL("fork() failed");

  //等待子进程执行结束，执行异常则打印错误信息并退出
  if (waitpid(pid, &status, 0) <= 0) PFATAL("waitpid() failed");

  //没有环境变量AFL_KEEP_ASSEMBLY，则移除临时文件
  if (!getenv("AFL_KEEP_ASSEMBLY")) unlink(modified_file);

  //使用子进程的状态作为退出码
  exit(WEXITSTATUS(status));

}

