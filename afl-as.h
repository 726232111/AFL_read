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
   american fuzzy lop - injectable parts
   -------------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   This file houses the assembly-level instrumentation injected into fuzzed
   programs. The instrumentation stores XORed pairs of data: identifiers of the
   currently executing branch and the one that executed immediately before.

   TL;DR: the instrumentation does shm_trace_map[cur_loc ^ prev_loc]++

   The code is designed for 32-bit and 64-bit x86 systems. Both modes should
   work everywhere except for Apple systems. Apple does relocations differently
   from everybody else, so since their OSes have been 64-bit for a longer while,
   I didn't go through the mental effort of porting the 32-bit code.

   In principle, similar code should be easy to inject into any well-behaved
   binary-only code (e.g., using DynamoRIO). Conditional jumps offer natural
   targets for instrumentation, and should offer comparable probe density.

*/

#ifndef _HAVE_AFL_AS_H
#define _HAVE_AFL_AS_H

#include "config.h"
#include "types.h"

/* 
   ------------------
   Performances notes
   ------------------

   Contributions to make this code faster are appreciated! Here are some
   rough notes that may help with the task:

   - Only the trampoline_fmt and the non-setup __afl_maybe_log code paths are
     really worth optimizing; the setup / fork server stuff matters a lot less
     and should be mostly just kept readable.

   - We're aiming for modern CPUs with out-of-order execution and large
     pipelines; the code is mostly follows intuitive, human-readable
     instruction ordering, because "textbook" manual reorderings make no
     substantial difference.

   - Interestingly, instrumented execution isn't a lot faster if we store a
     variable pointer to the setup, log, or return routine and then do a reg
     call from within trampoline_fmt. It does speed up non-instrumented
     execution quite a bit, though, since that path just becomes
     push-call-ret-pop.

   - There is also not a whole lot to be gained by doing SHM attach at a
     fixed address instead of retrieving __afl_area_ptr. Although it allows us
     to have a shorter log routine inserted for conditional jumps and jump
     labels (for a ~10% perf gain), there is a risk of bumping into other
     allocations created by the program or by tools such as ASAN.

   - popf is *awfully* slow, which is why we're doing the lahf / sahf +
     overflow test trick. Unfortunately, this forces us to taint eax / rax, but
     this dependency on a commonly-used register still beats the alternative of
     using pushf / popf.

     One possible optimization is to avoid touching flags by using a circular
     buffer that stores just a sequence of current locations, with the XOR stuff
     happening offline. Alas, this doesn't seem to have a huge impact:

     https://groups.google.com/d/msg/afl-users/MsajVf4fRLo/2u6t88ntUBIJ

   - Preforking one child a bit sooner, and then waiting for the "go" command
     from within the child, doesn't offer major performance gains; fork() seems
     to be relatively inexpensive these days. Preforking multiple children does
     help, but badly breaks the "~1 core per fuzzer" design, making it harder to
     scale up. Maybe there is some middle ground.

   Perhaps of note: in the 64-bit version for all platforms except for Apple,
   the instrumentation is done slightly differently than on 32-bit, with
   __afl_prev_loc and __afl_area_ptr being local to the object file (.lcomm),
   rather than global (.comm). This is to avoid GOTRELPC lookups in the critical
   code path, which AFAICT, are otherwise unavoidable if we want gcc -shared to
   work; simple relocations between .bss and .text won't work on most 64-bit
   platforms in such a case.

   (Fun fact: on Apple systems, .lcomm can segfault the linker.)

   The side effect is that state transitions are measured in a somewhat
   different way, with previous tuple being recorded separately within the scope
   of every .c file. This should have no impact in any practical sense.

   Another side effect of this design is that getenv() will be called once per
   every .o file when running in non-instrumented mode; and since getenv() tends
   to be optimized in funny ways, we need to be very careful to save every
   oddball register it may touch.

 */


//esp-=16
//esp[]={edi,edx,ecx,eax}
//ecx=变量
//__afl_maybe_log()
//edi,edx,ecx,eax=esp[]
//esp+=16
//保护现场，然后给ecx赋值，随后调用__afl_maybe_log，然后在还原现场；32位程序
//**好像没有检测__afl_maybe_log返回值
static const u8* trampoline_fmt_32 =

  "\n"
  "/* --- AFL TRAMPOLINE (32-BIT) --- */\n"
  "\n"
  ".align 4\n"
  "\n"
  "leal -16(%%esp), %%esp\n"
  "movl %%edi,  0(%%esp)\n"
  "movl %%edx,  4(%%esp)\n"
  "movl %%ecx,  8(%%esp)\n"
  "movl %%eax, 12(%%esp)\n"
  "movl $0x%08x, %%ecx\n"   //格式化输出的时候，指定值
  "call __afl_maybe_log\n"
  "movl 12(%%esp), %%eax\n"
  "movl  8(%%esp), %%ecx\n"
  "movl  4(%%esp), %%edx\n"
  "movl  0(%%esp), %%edi\n"
  "leal 16(%%esp), %%esp\n"
  "\n"
  "/* --- END --- */\n"
  "\n";

//esp-=152
//esp[]={rdx,rcx,rax}
//rcx=变量
//__afl_maybe_log()
//rdx,rcx,rax=esp[]
//esp+=152
//保护现场，然后给rcx赋值，随后调用__afl_maybe_log，然后在还原现场；64位程序
static const u8* trampoline_fmt_64 =

  "\n"
  "/* --- AFL TRAMPOLINE (64-BIT) --- */\n"
  "\n"
  ".align 4\n"
  "\n"
  "leaq -(128+24)(%%rsp), %%rsp\n"
  "movq %%rdx,  0(%%rsp)\n"
  "movq %%rcx,  8(%%rsp)\n"
  "movq %%rax, 16(%%rsp)\n"
  "movq $0x%08x, %%rcx\n"
  "call __afl_maybe_log\n"
  "movq 16(%%rsp), %%rax\n"
  "movq  8(%%rsp), %%rcx\n"
  "movq  0(%%rsp), %%rdx\n"
  "leaq (128+24)(%%rsp), %%rsp\n"
  "\n"
  "/* --- END --- */\n"
  "\n";


//包含了多个函数


static const u8* main_payload_32 = 

  "\n"
  "/* --- AFL MAIN PAYLOAD (32-BIT) --- */\n"
  "\n"
  ".text\n"     //代码块
  ".att_syntax\n"   //att语法
  ".code32\n"  //汇编成32位机器码
  ".align 8\n"  //8字节对齐
  "\n"



  "__afl_maybe_log:\n"
  "\n"
  "  lahf\n"    // 加载EFLAGS寄存器中的标志位到AH寄存器
  "  seto %al\n"   //溢出标志被设置，则seto将AL寄存器设置为1；否则，将AL寄存器设置为0
  "\n"
  "  /* Check if SHM region is already mapped. */\n"
  "\n"
  //检测__afl_area_ptr值是否为0，为0则跳转到__afl_setup，进行处理
  "  movl  __afl_area_ptr, %edx\n"   
  "  testl %edx, %edx\n"
  "  je    __afl_setup\n"    
  "\n"


  //__afl_area_ptr不为0，则继续执行

  "__afl_store:\n"
  "\n"
  "  /* Calculate and store hit for the code location specified in ecx. There\n"
  "     is a double-XOR way of doing this without tainting another register,\n"
  "     and we use it on 64-bit systems; but it's slower for 32-bit ones. */\n"
  "\n"

//ecx是call __afl_maybe_log时传递的参数，edi时路径数据区域的索引
#ifndef COVERAGE_ONLY
  //路径反馈 ，根据上一个块和当前块标识计算区域索引，即两个块的关联性
  "  movl __afl_prev_loc, %edi\n"    //将__afl_prev_loc的值移动到%edi寄存器
  "  xorl %ecx, %edi\n"   //将%edi寄存器与%ecx寄存器的值进行异或操作，结果存储在%edi寄存器中
  "  shrl $1, %ecx\n"  //将%ecx寄存器的值右移1位
  "  movl %ecx, __afl_prev_loc\n"  //将%ecx寄存器的值移动到__afl_prev_loc变量
#else
  //覆盖率，将当前块的标识作为区域索引，即当前块被调用的次数
  "  movl %ecx, %edi\n"  // 将%ecx寄存器的值移动到%edi寄存器
#endif /* ^!COVERAGE_ONLY */
  "\n"

//（基址寄存器，索引寄存器，索引单位）
// 地址 = edx+edi*1
// edx = __afl_area_ptr 即覆盖区域指针
#ifdef SKIP_COUNTS
  //不统计数量，但是改变走过的路径状态
  "  orb  $1, (%edx, %edi, 1)\n"  //将1与指定内存地址的值进行按位或操作
#else
  //改变走过的路径状态，同时计数
  "  incb (%edx, %edi, 1)\n"  //将指定内存地址的值加1
#endif /* ^SKIP_COUNTS */
  "\n"


  //函数返回
  "__afl_return:\n"
  "\n"
  "  addb $127, %al\n"  //of标志为1，al=128，否则al=127;暂时不理解含义
  "  sahf\n"  //恢复eflags
  "  ret\n"
  "\n"
  ".align 8\n"
  "\n"



  //__afl_area_ptr为0时，跳转到该标号
  //根据__AFL_SHM_ID环境变量获取共享内存
  "__afl_setup:\n"
  "\n"
  "  /* Do not retry setup if we had previous failures. */\n"
  "\n"
  //检测是否设置失败过，之前失败过则不继续设置，直接退出
  "  cmpb $0, __afl_setup_failure\n"
  "  jne  __afl_return\n"
  "\n"

  "  /* Map SHM, jumping to __afl_setup_abort if something goes wrong.\n"
  "     We do not save FPU/MMX/SSE registers here, but hopefully, nobody\n"
  "     will notice this early in the game. */\n"
  "\n"
  //保护现场
  "  pushl %eax\n"
  "  pushl %ecx\n"
  "\n"
  //获取环境变量 __AFL_SHM_ID
  "  pushl $.AFL_SHM_ENV\n"
  "  call  getenv\n"
  "  addl  $4, %esp\n"   //恢复堆栈
  "\n"

  //环境变量获取失败，跳转到__afl_setup_abort，终止设置过程，并返回
  "  testl %eax, %eax\n"
  "  je    __afl_setup_abort\n"
  "\n"

  //调用atoi，将环境变量转为整数
  "  pushl %eax\n"
  "  call  atoi\n"
  "  addl  $4, %esp\n"
  "\n"

  //调用shmat，将共享内存区附加到进程的地址空间，并获取附加共享内存区的起始地址
  "  pushl $0          /* shmat flags    */\n"
  "  pushl $0          /* requested addr */\n"
  "  pushl %eax        /* SHM ID         */\n"
  "  call  shmat\n"
  "  addl  $12, %esp\n"
  "\n"
  //检测共享内存区的起始地址是否有效，无效终止设置
  "  cmpl $-1, %eax\n"
  "  je   __afl_setup_abort\n"
  "\n"
  //将共享内存区赋值给__afl_area_ptr变量和edx
  "  /* Store the address of the SHM region. */\n"
  "\n"
  "  movl %eax, __afl_area_ptr\n"
  "  movl %eax, %edx\n"
  "\n"
  //还原现场
  "  popl %ecx\n"
  "  popl %eax\n"
  "\n"

  //继续执行

  //
  "__afl_forkserver:\n"
  "\n"
  "  /* Enter the fork server mode to avoid the overhead of execve() calls. */\n"
  "\n"
  //保护现场
  "  pushl %eax\n"
  "  pushl %ecx\n"
  "  pushl %edx\n"
  "\n"
  "  /* Phone home and tell the parent that we're OK. (Note that signals with\n"
  "     no SA_RESTART will mess it up). If this fails, assume that the fd is\n"
  "     closed because we were execve()d from an instrumented binary, or because\n" 
  "     the parent doesn't want to use the fork server. */\n"
  "\n"
  //将__afl_temp数据写入到199管道中
  "  pushl $4          /* length    */\n" //常数4
  "  pushl $__afl_temp /* data      */\n"  //__afl_temp全局变量地址压栈
  "  pushl $" STRINGIFY((FORKSRV_FD + 1)) "  /* file desc */\n"  //199
  "  call  write\n"  //向199管道写入数据
  "  addl  $12, %esp\n"  //恢复堆栈
  "\n"
  //检测是否写入成功，不成功（已经关闭了描述符，当前为子进程）跳转到__afl_fork_resume
  "  cmpl  $4, %eax\n"
  "  jne   __afl_fork_resume\n"
  "\n"

  //继续执行

  "__afl_fork_wait_loop:\n"
  "\n"
  "  /* Wait for parent by reading from the pipe. Abort if read fails. */\n"
  "\n"
  //从198管道中读取数据，
  "  pushl $4          /* length    */\n"
  "  pushl $__afl_temp /* data      */\n"
  "  pushl $" STRINGIFY(FORKSRV_FD) "        /* file desc */\n" //198管道
  "  call  read\n"
  "  addl  $12, %esp\n"
  "\n"
  "  cmpl  $4, %eax\n"
  "  jne   __afl_die\n"  //读取失败，跳转__afl_die通过exit退出进程

  
  "\n"
  "  /* Once woken up, create a clone of our process. This is an excellent use\n"
  "     case for syscall(__NR_clone, 0, CLONE_PARENT), but glibc boneheadedly\n"
  "     caches getpid() results and offers no way to update the value, breaking\n"
  "     abort(), raise(), and a bunch of other things :-( */\n"
  "\n"
  "  call fork\n"   //fork进程
  "\n"
  "  cmpl $0, %eax\n"
  "  jl   __afl_die\n"  //fork失败，跳转__afl_die通过exit退出进程
  "  je   __afl_fork_resume\n" //子进程跳转到__afl_fork_resume

  //父进程程序继续向下执行
  "\n"
  "  /* In parent process: write PID to pipe, then wait for child. */\n"
  "\n"
  "  movl  %eax, __afl_fork_pid\n" //子进程ID写入__afl_fork_pid变量
  "\n"
  //将子进程ID通过管道告知fuzz进程
  "  pushl $4              /* length    */\n"
  "  pushl $__afl_fork_pid /* data      */\n"
  "  pushl $" STRINGIFY((FORKSRV_FD + 1)) "      /* file desc */\n"
  "  call  write\n"
  "  addl  $12, %esp\n"
  "\n"
  //等待子进程执行结束
  "  pushl $0             /* no flags  */\n"
  "  pushl $__afl_temp    /* status    */\n"  //获取子进程状态信息
  "  pushl __afl_fork_pid /* PID       */\n" //子进程PID
  "  call  waitpid\n"
  "  addl  $12, %esp\n"  //堆栈平衡
  "\n"
  //出现了错误，关闭当前程序
  "  cmpl  $0, %eax\n"
  "  jle   __afl_die\n"
  "\n"
  "  /* Relay wait status to pipe, then loop back. */\n"
  "\n"
  //将子进程状态通过管道告知fuzz进程
  "  pushl $4          /* length    */\n"
  "  pushl $__afl_temp /* data      */\n"
  "  pushl $" STRINGIFY((FORKSRV_FD + 1)) "  /* file desc */\n"
  "  call  write\n"
  "  addl  $12, %esp\n"
  "\n"
  "  jmp __afl_fork_wait_loop\n"  //跳回__afl_fork_wait_loop，循环创建子进程
  "\n"


  //子进程，关闭文件描述符，恢复程序执行
  "__afl_fork_resume:\n"
  "\n"
  "  /* In child process: close fds, resume execution. */\n"
  "\n"
  //关闭文件描述符198
  "  pushl $" STRINGIFY(FORKSRV_FD) "\n"
  "  call  close\n"
  "\n"
    //关闭文件描述符199
  "  pushl $" STRINGIFY((FORKSRV_FD + 1)) "\n"
  "  call  close\n"
  "\n"
  "  addl  $8, %esp\n"  //堆栈平衡
  "\n"
  //恢复现场，跳转到__afl_store并执行（第一次执行__afl_store）
  "  popl %edx\n"
  "  popl %ecx\n"
  "  popl %eax\n"
  "  jmp  __afl_store\n"
  "\n"

  //退出进程
  "__afl_die:\n"
  "\n"
  "  xorl %eax, %eax\n"
  "  call _exit\n"
  "\n"

  //
  "__afl_setup_abort:\n"
  "\n"
  "  /* Record setup failure so that we don't keep calling\n"
  "     shmget() / shmat() over and over again. */\n"
  "\n"
  //失败状态+1，然后恢复现场，并返回__afl_maybe_log
  "  incb __afl_setup_failure\n"
  "  popl %ecx\n"
  "  popl %eax\n"
  "  jmp __afl_return\n"
  "\n"




  //变量区域
  //.comm是汇编语言中的一个伪指令，用于定义一个未初始化的全局或静态变量
  ".AFL_VARS:\n"
  "\n"
  //4字节，32位对齐
  "  .comm   __afl_area_ptr, 4, 32\n"  
  //4字节，32位对齐
  "  .comm   __afl_setup_failure, 1, 32\n"  
#ifndef COVERAGE_ONLY
  "  .comm   __afl_prev_loc, 4, 32\n"
#endif /* !COVERAGE_ONLY */
  "  .comm   __afl_fork_pid, 4, 32\n"
  "  .comm   __afl_temp, 4, 32\n"
  "\n"



  //字符串区域
  ".AFL_SHM_ENV:\n"
  "  .asciz \"" SHM_ENV_VAR "\"\n"  //定义一个以null结尾的字符串
  "\n"
  "/* --- END --- */\n"
  "\n";

/* The OpenBSD hack is due to lahf and sahf not being recognized by some
   versions of binutils: http://marc.info/?l=openbsd-cvs&m=141636589924400

   The Apple code is a bit different when calling libc functions because
   they are doing relocations differently from everybody else. We also need
   to work around the crash issue with .lcomm and the fact that they don't
   recognize .string. */

#ifdef __APPLE__
#  define CALL_L64(str)		"call _" str "\n"
#else
#  define CALL_L64(str)		"call " str "@PLT\n"
#endif /* ^__APPLE__ */




static const u8* main_payload_64 = 

  "\n"
  "/* --- AFL MAIN PAYLOAD (64-BIT) --- */\n"
  "\n"
  ".text\n"
  ".att_syntax\n"
  ".code64\n"
  ".align 8\n"
  "\n"
  "__afl_maybe_log:\n"
  "\n"
#if defined(__OpenBSD__)  || (defined(__FreeBSD__) && (__FreeBSD__ < 9))
  "  .byte 0x9f /* lahf */\n"
#else
  "  lahf\n"
#endif /* ^__OpenBSD__, etc */
  "  seto  %al\n"
  "\n"
  "  /* Check if SHM region is already mapped. */\n"
  "\n"
  "  movq  __afl_area_ptr(%rip), %rdx\n"
  "  testq %rdx, %rdx\n"
  "  je    __afl_setup\n"
  "\n"
  "__afl_store:\n"
  "\n"
  "  /* Calculate and store hit for the code location specified in rcx. */\n"
  "\n"
#ifndef COVERAGE_ONLY
  "  xorq __afl_prev_loc(%rip), %rcx\n"
  "  xorq %rcx, __afl_prev_loc(%rip)\n"
  "  shrq $1, __afl_prev_loc(%rip)\n"
#endif /* ^!COVERAGE_ONLY */
  "\n"
#ifdef SKIP_COUNTS
  "  orb  $1, (%rdx, %rcx, 1)\n"
#else
  "  incb (%rdx, %rcx, 1)\n"
#endif /* ^SKIP_COUNTS */
  "\n"
  "__afl_return:\n"
  "\n"
  "  addb $127, %al\n"
#if defined(__OpenBSD__)  || (defined(__FreeBSD__) && (__FreeBSD__ < 9))
  "  .byte 0x9e /* sahf */\n"
#else
  "  sahf\n"
#endif /* ^__OpenBSD__, etc */
  "  ret\n"
  "\n"
  ".align 8\n"
  "\n"
  "__afl_setup:\n"
  "\n"
  "  /* Do not retry setup if we had previous failures. */\n"
  "\n"
  "  cmpb $0, __afl_setup_failure(%rip)\n"
  "  jne __afl_return\n"
  "\n"
  "  /* Check out if we have a global pointer on file. */\n"
  "\n"
#ifndef __APPLE__
  "  movq  __afl_global_area_ptr@GOTPCREL(%rip), %rdx\n"
  "  movq  (%rdx), %rdx\n"
#else
  "  movq  __afl_global_area_ptr(%rip), %rdx\n"
#endif /* !^__APPLE__ */
  "  testq %rdx, %rdx\n"
  "  je    __afl_setup_first\n"
  "\n"
  "  movq %rdx, __afl_area_ptr(%rip)\n"
  "  jmp  __afl_store\n" 
  "\n"
  "__afl_setup_first:\n"
  "\n"
  "  /* Save everything that is not yet saved and that may be touched by\n"
  "     getenv() and several other libcalls we'll be relying on. */\n"
  "\n"
  "  leaq -352(%rsp), %rsp\n"
  "\n"
  "  movq %rax,   0(%rsp)\n"
  "  movq %rcx,   8(%rsp)\n"
  "  movq %rdi,  16(%rsp)\n"
  "  movq %rsi,  32(%rsp)\n"
  "  movq %r8,   40(%rsp)\n"
  "  movq %r9,   48(%rsp)\n"
  "  movq %r10,  56(%rsp)\n"
  "  movq %r11,  64(%rsp)\n"
  "\n"
  "  movq %xmm0,  96(%rsp)\n"
  "  movq %xmm1,  112(%rsp)\n"
  "  movq %xmm2,  128(%rsp)\n"
  "  movq %xmm3,  144(%rsp)\n"
  "  movq %xmm4,  160(%rsp)\n"
  "  movq %xmm5,  176(%rsp)\n"
  "  movq %xmm6,  192(%rsp)\n"
  "  movq %xmm7,  208(%rsp)\n"
  "  movq %xmm8,  224(%rsp)\n"
  "  movq %xmm9,  240(%rsp)\n"
  "  movq %xmm10, 256(%rsp)\n"
  "  movq %xmm11, 272(%rsp)\n"
  "  movq %xmm12, 288(%rsp)\n"
  "  movq %xmm13, 304(%rsp)\n"
  "  movq %xmm14, 320(%rsp)\n"
  "  movq %xmm15, 336(%rsp)\n"
  "\n"
  "  /* Map SHM, jumping to __afl_setup_abort if something goes wrong. */\n"
  "\n"
  "  /* The 64-bit ABI requires 16-byte stack alignment. We'll keep the\n"
  "     original stack ptr in the callee-saved r12. */\n"
  "\n"
  "  pushq %r12\n"
  "  movq  %rsp, %r12\n"
  "  subq  $16, %rsp\n"
  "  andq  $0xfffffffffffffff0, %rsp\n"
  "\n"
  "  leaq .AFL_SHM_ENV(%rip), %rdi\n"
  CALL_L64("getenv")
  "\n"
  "  testq %rax, %rax\n"
  "  je    __afl_setup_abort\n"
  "\n"
  "  movq  %rax, %rdi\n"
  CALL_L64("atoi")
  "\n"
  "  xorq %rdx, %rdx   /* shmat flags    */\n"
  "  xorq %rsi, %rsi   /* requested addr */\n"
  "  movq %rax, %rdi   /* SHM ID         */\n"
  CALL_L64("shmat")
  "\n"
  "  cmpq $-1, %rax\n"
  "  je   __afl_setup_abort\n"
  "\n"
  "  /* Store the address of the SHM region. */\n"
  "\n"
  "  movq %rax, %rdx\n"
  "  movq %rax, __afl_area_ptr(%rip)\n"
  "\n"
#ifdef __APPLE__
  "  movq %rax, __afl_global_area_ptr(%rip)\n"
#else
  "  movq __afl_global_area_ptr@GOTPCREL(%rip), %rdx\n"
  "  movq %rax, (%rdx)\n"
#endif /* ^__APPLE__ */
  "  movq %rax, %rdx\n"
  "\n"
  "__afl_forkserver:\n"
  "\n"
  "  /* Enter the fork server mode to avoid the overhead of execve() calls. We\n"
  "     push rdx (area ptr) twice to keep stack alignment neat. */\n"
  "\n"
  "  pushq %rdx\n"
  "  pushq %rdx\n"
  "\n"
  "  /* Phone home and tell the parent that we're OK. (Note that signals with\n"
  "     no SA_RESTART will mess it up). If this fails, assume that the fd is\n"
  "     closed because we were execve()d from an instrumented binary, or because\n"
  "     the parent doesn't want to use the fork server. */\n"
  "\n"
  "  movq $4, %rdx               /* length    */\n"
  "  leaq __afl_temp(%rip), %rsi /* data      */\n"
  "  movq $" STRINGIFY((FORKSRV_FD + 1)) ", %rdi       /* file desc */\n"
  CALL_L64("write")
  "\n"
  "  cmpq $4, %rax\n"
  "  jne  __afl_fork_resume\n"
  "\n"
  "__afl_fork_wait_loop:\n"
  "\n"
  "  /* Wait for parent by reading from the pipe. Abort if read fails. */\n"
  "\n"
  "  movq $4, %rdx               /* length    */\n"
  "  leaq __afl_temp(%rip), %rsi /* data      */\n"
  "  movq $" STRINGIFY(FORKSRV_FD) ", %rdi             /* file desc */\n"
  CALL_L64("read")
  "  cmpq $4, %rax\n"
  "  jne  __afl_die\n"
  "\n"
  "  /* Once woken up, create a clone of our process. This is an excellent use\n"
  "     case for syscall(__NR_clone, 0, CLONE_PARENT), but glibc boneheadedly\n"
  "     caches getpid() results and offers no way to update the value, breaking\n"
  "     abort(), raise(), and a bunch of other things :-( */\n"
  "\n"
  CALL_L64("fork")
  "  cmpq $0, %rax\n"
  "  jl   __afl_die\n"
  "  je   __afl_fork_resume\n"
  "\n"
  "  /* In parent process: write PID to pipe, then wait for child. */\n"
  "\n"
  "  movl %eax, __afl_fork_pid(%rip)\n"
  "\n"
  "  movq $4, %rdx                   /* length    */\n"
  "  leaq __afl_fork_pid(%rip), %rsi /* data      */\n"
  "  movq $" STRINGIFY((FORKSRV_FD + 1)) ", %rdi             /* file desc */\n"
  CALL_L64("write")
  "\n"
  "  movq $0, %rdx                   /* no flags  */\n"
  "  leaq __afl_temp(%rip), %rsi     /* status    */\n"
  "  movq __afl_fork_pid(%rip), %rdi /* PID       */\n"
  CALL_L64("waitpid")
  "  cmpq $0, %rax\n"
  "  jle  __afl_die\n"
  "\n"
  "  /* Relay wait status to pipe, then loop back. */\n"
  "\n"
  "  movq $4, %rdx               /* length    */\n"
  "  leaq __afl_temp(%rip), %rsi /* data      */\n"
  "  movq $" STRINGIFY((FORKSRV_FD + 1)) ", %rdi         /* file desc */\n"
  CALL_L64("write")
  "\n"
  "  jmp  __afl_fork_wait_loop\n"
  "\n"
  "__afl_fork_resume:\n"
  "\n"
  "  /* In child process: close fds, resume execution. */\n"
  "\n"
  "  movq $" STRINGIFY(FORKSRV_FD) ", %rdi\n"
  CALL_L64("close")
  "\n"
  "  movq $" STRINGIFY((FORKSRV_FD + 1)) ", %rdi\n"
  CALL_L64("close")
  "\n"
  "  popq %rdx\n"
  "  popq %rdx\n"
  "\n"
  "  movq %r12, %rsp\n"
  "  popq %r12\n"
  "\n"
  "  movq  0(%rsp), %rax\n"
  "  movq  8(%rsp), %rcx\n"
  "  movq 16(%rsp), %rdi\n"
  "  movq 32(%rsp), %rsi\n"
  "  movq 40(%rsp), %r8\n"
  "  movq 48(%rsp), %r9\n"
  "  movq 56(%rsp), %r10\n"
  "  movq 64(%rsp), %r11\n"
  "\n"
  "  movq  96(%rsp), %xmm0\n"
  "  movq 112(%rsp), %xmm1\n"
  "  movq 128(%rsp), %xmm2\n"
  "  movq 144(%rsp), %xmm3\n"
  "  movq 160(%rsp), %xmm4\n"
  "  movq 176(%rsp), %xmm5\n"
  "  movq 192(%rsp), %xmm6\n"
  "  movq 208(%rsp), %xmm7\n"
  "  movq 224(%rsp), %xmm8\n"
  "  movq 240(%rsp), %xmm9\n"
  "  movq 256(%rsp), %xmm10\n"
  "  movq 272(%rsp), %xmm11\n"
  "  movq 288(%rsp), %xmm12\n"
  "  movq 304(%rsp), %xmm13\n"
  "  movq 320(%rsp), %xmm14\n"
  "  movq 336(%rsp), %xmm15\n"
  "\n"
  "  leaq 352(%rsp), %rsp\n"
  "\n"
  "  jmp  __afl_store\n"
  "\n"
  "__afl_die:\n"
  "\n"
  "  xorq %rax, %rax\n"
  CALL_L64("_exit")
  "\n"
  "__afl_setup_abort:\n"
  "\n"
  "  /* Record setup failure so that we don't keep calling\n"
  "     shmget() / shmat() over and over again. */\n"
  "\n"
  "  incb __afl_setup_failure(%rip)\n"
  "\n"
  "  movq %r12, %rsp\n"
  "  popq %r12\n"
  "\n"
  "  movq  0(%rsp), %rax\n"
  "  movq  8(%rsp), %rcx\n"
  "  movq 16(%rsp), %rdi\n"
  "  movq 32(%rsp), %rsi\n"
  "  movq 40(%rsp), %r8\n"
  "  movq 48(%rsp), %r9\n"
  "  movq 56(%rsp), %r10\n"
  "  movq 64(%rsp), %r11\n"
  "\n"
  "  movq  96(%rsp), %xmm0\n"
  "  movq 112(%rsp), %xmm1\n"
  "  movq 128(%rsp), %xmm2\n"
  "  movq 144(%rsp), %xmm3\n"
  "  movq 160(%rsp), %xmm4\n"
  "  movq 176(%rsp), %xmm5\n"
  "  movq 192(%rsp), %xmm6\n"
  "  movq 208(%rsp), %xmm7\n"
  "  movq 224(%rsp), %xmm8\n"
  "  movq 240(%rsp), %xmm9\n"
  "  movq 256(%rsp), %xmm10\n"
  "  movq 272(%rsp), %xmm11\n"
  "  movq 288(%rsp), %xmm12\n"
  "  movq 304(%rsp), %xmm13\n"
  "  movq 320(%rsp), %xmm14\n"
  "  movq 336(%rsp), %xmm15\n"
  "\n"
  "  leaq 352(%rsp), %rsp\n"
  "\n"
  "  jmp __afl_return\n"
  "\n"
  ".AFL_VARS:\n"
  "\n"

#ifdef __APPLE__

  "  .comm   __afl_area_ptr, 8\n"
#ifndef COVERAGE_ONLY
  "  .comm   __afl_prev_loc, 8\n"
#endif /* !COVERAGE_ONLY */
  "  .comm   __afl_fork_pid, 4\n"
  "  .comm   __afl_temp, 4\n"
  "  .comm   __afl_setup_failure, 1\n"

#else

  "  .lcomm   __afl_area_ptr, 8\n"
#ifndef COVERAGE_ONLY
  "  .lcomm   __afl_prev_loc, 8\n"
#endif /* !COVERAGE_ONLY */
  "  .lcomm   __afl_fork_pid, 4\n"
  "  .lcomm   __afl_temp, 4\n"
  "  .lcomm   __afl_setup_failure, 1\n"

#endif /* ^__APPLE__ */

  "  .comm    __afl_global_area_ptr, 8, 8\n"
  "\n"
  ".AFL_SHM_ENV:\n"
  "  .asciz \"" SHM_ENV_VAR "\"\n"
  "\n"
  "/* --- END --- */\n"
  "\n";

#endif /* !_HAVE_AFL_AS_H */
