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
   american fuzzy lop - wrapper for GCC and clang
   ----------------------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>

   This program is a drop-in replacement for GCC or clang. The most common way
   of using it is to pass the path to afl-gcc or afl-clang via CC when invoking
   ./configure.

   (Of course, use CXX and point it to afl-g++ / afl-clang++ for C++ code.)

   The wrapper needs to know the path to afl-as (renamed to 'as'). The default
   is /usr/local/lib/afl/. A convenient way to specify alternative directories
   would be to set AFL_PATH.

   If AFL_HARDEN is set, the wrapper will compile the target app with various
   hardening options that may help detect memory management issues more
   reliably. You can also specify AFL_USE_ASAN to enable ASAN.

   If you want to call a non-default compiler as a next step of the chain,
   specify its location via AFL_CC or AFL_CXX.

*/

#define AFL_MAIN

#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

//afl-as路径信息
static u8*  as_path;                /* Path to the AFL 'as' wrapper      */
//传递给真实gcc的参数
static u8** cc_params;              /* Parameters passed to the real CC  */
//参数个数，默认为1
static u32  cc_par_cnt = 1;         /* Param count, including argv0      */
//quite模式
static u8   be_quiet,               /* Quiet mode                        */
//使用afl-clang而不是alf-gcc
            clang_mode;             /* Invoked as afl-clang*?            */


/* Try to find our "fake" GNU assembler in AFL_PATH or at the location derived
   from argv[0]. If that fails, abort. */

/*尝试在AFL_PATH中或从argv[0]派生的位置找到我们的“伪”GNU汇编程序。如果失败，则中止。*/
static void find_as(u8* argv0) {

  //获取环境变量
  u8 *afl_path = getenv("AFL_PATH");
  u8 *slash, *tmp;

  //检测环境变量是否存在
  if (afl_path) {

    //拼接as路径
    tmp = alloc_printf("%s/as", afl_path);

    //检测执行权限
    if (!access(tmp, X_OK)) {
      //检测通过，设置as路径
      as_path = afl_path;
      //释放拼接的字符串
      ck_free(tmp);
      //返回
      return;
    }

    //检测失败，释放拼接的字符串
    ck_free(tmp);

  }

  //查询最后一次/出现的位置
  slash = strrchr(argv0, '/');

  if (slash) {

    u8 *dir;

    *slash = 0;
    dir = ck_strdup(argv0);
    *slash = '/';

    //使用当前程序所在路径拼接afl-as
    tmp = alloc_printf("%s/afl-as", dir);

    //检测执行权限
    if (!access(tmp, X_OK)) {
      as_path = dir;  //设置as所在路径
      ck_free(tmp);  //dir不释放吗？
      return;  //检测成功返回
    }

    ck_free(tmp);
    ck_free(dir);

  }

  //使用编译选项中的ALF_PATH作为路径并检测
  if (!access(AFL_PATH "/as", X_OK)) {
    as_path = AFL_PATH;  //设置as所在路径
    return;  //检测成功返回
  }

  //检测失败，退出
  FATAL("Unable to find AFL wrapper binary for 'as'. Please set AFL_PATH");
 
}


/* Copy argv to cc_params, making the necessary edits. */

static void edit_params(u32 argc, char** argv) {

  u8 fortify_set = 0, asan_set = 0;
  u8 *name;


//64位的__FreeBSD__系统
#if defined(__FreeBSD__) && defined(__x86_64__)
  u8 m32_set = 0;
#endif

  //申请128+当前参数个数的指针内存
  cc_params = ck_alloc((argc + 128) * sizeof(u8*));

  //设置name指向程序名
  name = strrchr(argv[0], '/');
  if (!name) name = argv[0]; else name++;

  //检测当前程序是否存在afl-clang
  if (!strncmp(name, "afl-clang", 9)) {

    //程序为afl-clang则指定clang模式
    clang_mode = 1;

    //设置环境变量__AFL_CLANG_MODE为1
    setenv(CLANG_ENV_VAR, "1", 1);

    if (!strcmp(name, "afl-clang++")) {
      //程序为afl-clang++，则将cc的第一个参数设置为AFL_CXX环境变量值或clang++
      u8* alt_cxx = getenv("AFL_CXX");
      cc_params[0] = alt_cxx ? alt_cxx : (u8*)"clang++";
    } else {
      //程序不为afl-clang++，则将cc的第一个参数设置为AFL_CC环境变量值或clang
      u8* alt_cc = getenv("AFL_CC");
      cc_params[0] = alt_cc ? alt_cc : (u8*)"clang";
    }

  } else {

    /* With GCJ and Eclipse installed, you can actually compile Java! The
       instrumentation will work (amazingly). Alas, unhandled exceptions do
       not call abort(), so afl-fuzz would need to be modified to equate
       non-zero exit codes with crash conditions when working with Java
       binaries. Meh. */

#ifdef __APPLE__

    //这里好像是苹果系统
    //统一使用环境变量，没有值则报错

    if (!strcmp(name, "afl-g++")) cc_params[0] = getenv("AFL_CXX");
    else if (!strcmp(name, "afl-gcj")) cc_params[0] = getenv("AFL_GCJ");
    else cc_params[0] = getenv("AFL_CC");

    if (!cc_params[0]) {

      SAYF("\n" cLRD "[-] " cRST
           "On Apple systems, 'gcc' is usually just a wrapper for clang. Please use the\n"
           "    'afl-clang' utility instead of 'afl-gcc'. If you really have GCC installed,\n"
           "    set AFL_CC or AFL_CXX to specify the correct path to that compiler.\n");

      FATAL("AFL_CC or AFL_CXX required on MacOS X");

    }

#else
    
    if (!strcmp(name, "afl-g++")) {
      //程序为afl-clang++，则将cc的第一个参数设置为AFL_CXX环境变量值或g++
      u8* alt_cxx = getenv("AFL_CXX");
      cc_params[0] = alt_cxx ? alt_cxx : (u8*)"g++";
    } else if (!strcmp(name, "afl-gcj")) {
      //程序为afl-clang++，则将cc的第一个参数设置为AFL_GCJ环境变量值或gcj
      u8* alt_cc = getenv("AFL_GCJ");
      cc_params[0] = alt_cc ? alt_cc : (u8*)"gcj";
    } else {
      //其他情况，则将cc的第一个参数设置为AFL_CC环境变量值或gcc
      u8* alt_cc = getenv("AFL_CC");
      cc_params[0] = alt_cc ? alt_cc : (u8*)"gcc";
    }

#endif /* __APPLE__ */

  }

  //循环遍历参数，当参数为0时，退出循环
  while (--argc) {
    u8* cur = *(++argv); //指向下一个参数

    //参数是否为-B，跳过-B选项
    if (!strncmp(cur, "-B", 2)) {
      
      //未设置静默模式，打印提示信息
      if (!be_quiet) WARNF("-B is already set, overriding");

      //如果还剩余2个及以上的参数，则跳过下个参数，也就是移除-B选项
      if (!cur[2] && argc > 1) { argc--; argv++; }
      continue;

    }

    //跳过-integrated-as选项，该选项强制GCC使用内置的汇编器
    if (!strcmp(cur, "-integrated-as")) continue;

    //跳过-pipe选项，该选项指示编译器在编译过程中使用管道而不是临时文件来传递数据。
    if (!strcmp(cur, "-pipe")) continue;

//64位的__FreeBSD__会额外检测一个选项
#if defined(__FreeBSD__) && defined(__x86_64__)
    if (!strcmp(cur, "-m32")) m32_set = 1;
#endif

    //检测是否开启asan或msan，然后将原参数复制一份
    //后面说明两者互斥，这里不做检测吗？
    if (!strcmp(cur, "-fsanitize=address") ||  //启用AddressSanitizer（ASan）工具
        !strcmp(cur, "-fsanitize=memory"))  //启用 MemorySanitizer（MSan）工具
        asan_set = 1;

    //检测是否启用用于启用强化的安全性功能，然后将原参数复制一份
    //-D_FORTIFY_SOURCE 的取值有：  
    //0：禁用 FORTIFY_SOURCE 功能。
    //1：启用 FORTIFY_SOURCE 功能，但只对某些函数进行增强，不对所有函数进行检查。
    //2：启用 FORTIFY_SOURCE 功能，并对所有可能的函数进行检查和增强
    if (strstr(cur, "FORTIFY_SOURCE")) fortify_set = 1;

    //其他选项直接复制
    cc_params[cc_par_cnt++] = cur;

  }

  //设置-B选项的参数，用于指定程序库（libraries）的搜索路径。
  cc_params[cc_par_cnt++] = "-B";
  cc_params[cc_par_cnt++] = as_path;

  //设置clang_mode的参数
  if (clang_mode)
    //用于指示编译器不使用内置的汇编器（integrated assembler）而使用外部汇编器
    cc_params[cc_par_cnt++] = "-no-integrated-as";  


  //是否开启困难模式
  if (getenv("AFL_HARDEN")) {

    cc_params[cc_par_cnt++] = "-fstack-protector-all";  //用于启用堆栈保护机制，以检测并防止堆栈溢出攻击。

    //不存在强化的安全性功能，则设置
    if (!fortify_set)
      cc_params[cc_par_cnt++] = "-D_FORTIFY_SOURCE=2";

  }

  
  //设置asan_set没有检测是否同事设置msan或asan
  if (asan_set) {

    /* Pass this on to afl-as to adjust map density. */
    //启用了ASAN或MSAN
    //设置环境变量
    setenv("AFL_USE_ASAN", "1", 1);

  } else if (getenv("AFL_USE_ASAN")) {

    //ASAN、MSAN、安全增强互相排斥，只能选一个

    if (getenv("AFL_USE_MSAN"))
      FATAL("ASAN and MSAN are mutually exclusive");

    if (getenv("AFL_HARDEN"))
      FATAL("ASAN and AFL_HARDEN are mutually exclusive");

    cc_params[cc_par_cnt++] = "-U_FORTIFY_SOURCE";
    cc_params[cc_par_cnt++] = "-fsanitize=address";

  } else if (getenv("AFL_USE_MSAN")) {

    //ASAN、MSAN、安全增强互相排斥，只能选一个
    
    if (getenv("AFL_USE_ASAN"))
      FATAL("ASAN and MSAN are mutually exclusive");

    if (getenv("AFL_HARDEN"))
      FATAL("MSAN and AFL_HARDEN are mutually exclusive");

    cc_params[cc_par_cnt++] = "-U_FORTIFY_SOURCE";
    cc_params[cc_par_cnt++] = "-fsanitize=memory";


  }

  //检测是否设置AFL不可优化
  if (!getenv("AFL_DONT_OPTIMIZE")) {

      //未设置AFL_DONT_OPTIMIZE，则进行优化

#if defined(__FreeBSD__) && defined(__x86_64__)

    /* On 64-bit FreeBSD systems, clang -g -m32 is broken, but -m32 itself
       works OK. This has nothing to do with us, but let's avoid triggering
       that bug. */

    if (!clang_mode || !m32_set)
      cc_params[cc_par_cnt++] = "-g";

#else
      
      //用于在生成的可执行文件中包含调试信息
      cc_params[cc_par_cnt++] = "-g";

#endif

    //-O3 是 GCC 编译器的优化选项，表示启用较高级别的优化。这个选项告诉编译器进行更多和更激进的代码优化，以提高程序的执行性能。
    cc_params[cc_par_cnt++] = "-O3"; 
    //-funroll-loops 是 GCC 编译器的一个优化选项，用于在编译时展开循环。
    //循环展开是一种优化技术，通过将循环体的多个迭代复制多次来减少循环控制的开销，从而提高性能。
    cc_params[cc_par_cnt++] = "-funroll-loops";

    /* Two indicators that you're building for fuzzing; one of them is
       AFL-specific, the other is shared with libfuzzer. 
       你为模糊化构建的两个指标；其中一个是AFL特有的，另一个与libfuzzer共享。*/

    //在编译时定义一个名为 __AFL_COMPILER 的宏的 GCC 编译器选项。
    cc_params[cc_par_cnt++] = "-D__AFL_COMPILER=1";
    //在编译时定义一个名为 FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION的宏的 GCC 编译器选项。
    cc_params[cc_par_cnt++] = "-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1";

  }

  //不适用内联函数，用覆盖率分析
  if (getenv("AFL_NO_BUILTIN")) {

    cc_params[cc_par_cnt++] = "-fno-builtin-strcmp";  //告诉编译器不要使用内联的 strcmp 函数
    cc_params[cc_par_cnt++] = "-fno-builtin-strncmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strcasecmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strncasecmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-memcmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strstr";
    cc_params[cc_par_cnt++] = "-fno-builtin-strcasestr";

  }

  //最终的终止符
  cc_params[cc_par_cnt] = NULL;

}


/* Main entry point */

int main(int argc, char** argv) {

  
  if (isatty(2) && !getenv("AFL_QUIET")) {
    //错误输出关联到终端，并且环境变量没有设置AFL_QUIET标识，则打印冗余信息
    SAYF(cCYA "afl-cc " cBRI VERSION cRST " by <lcamtuf@google.com>\n");

  } else be_quiet = 1;  //启动静默模式


  //参数小于2，报错
  if (argc < 2) {

    SAYF("\n"
         "This is a helper application for afl-fuzz. It serves as a drop-in replacement\n"
         "for gcc or clang, letting you recompile third-party code with the required\n"
         "runtime instrumentation. A common use pattern would be one of the following:\n\n"

         "  CC=%s/afl-gcc ./configure\n"
         "  CXX=%s/afl-g++ ./configure\n\n"

         "You can specify custom next-stage toolchain via AFL_CC, AFL_CXX, and AFL_AS.\n"
         "Setting AFL_HARDEN enables hardening optimizations in the compiled code.\n\n",
         BIN_PATH, BIN_PATH);

    exit(1);

  }

  //查询as路径
  find_as(argv[0]);

  //修改参数
  edit_params(argc, argv);

  //使用真正的编译器进行编译
  execvp(cc_params[0], (char**)cc_params);

  //打印错误信息
  FATAL("Oops, failed to execute '%s' - check your PATH", cc_params[0]);

  return 0;

}
