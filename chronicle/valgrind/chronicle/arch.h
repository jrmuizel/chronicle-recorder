/*
    Copyright (c) 2006 Novell and contributors:
        robert@ocallahan.org
    
    Permission is hereby granted, free of charge, to any person
    obtaining a copy of this software and associated documentation
    files (the "Software"), to deal in the Software without
    restriction, including without limitation the rights to use,
    copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the
    Software is furnished to do so, subject to the following
    conditions:
    
    The above copyright notice and this permission notice shall be
    included in all copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
    OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
    NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
    HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
    WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
    OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef ARCH_H_
#define ARCH_H_

/* 
 * Define architecture-specific details for the Chronicle database format
 * and for the logstream used to communicate between the traced process and
 * indexer.
 */

#include <stdint.h>

/**
 * CH_X86 is defined for x86 and AMD64 architectures. Currently this is all
 * we support. CH_X86 is defined for both variants.
 */
#define CH_X86 1

/*
 * Register numbering for x86 and AMD64 registers. 
 * Flags and misc registers are not currently tracked.
 * The general purpose registers are numbered in the following order:
 * AX,CX,DX,BX,SP,BP,SI,DI,R8-R15
 * We follow valgrind by treating the x87 floating point registers as
 * a bank of 8 registers plus an FPTOP register identifying the "top of stack".
 */
#define CH_X86_GP_REGS       0
#define CH_X86_SSE_REGS      16
#define CH_X86_FP_REGS       32
#define CH_X86_FP_REGS_COUNT 8
#define CH_X86_FPTOP_REG     40
#define CH_X86_NUM_REGS      41

typedef enum {
  CH_REGTYPE_UNKNOWN,
  CH_REGTYPE_GP,
  CH_REGTYPE_X86_FP,
  CH_REGTYPE_X86_SSE,
  CH_REGTYPE_X86_FPTOP
} CH_RegType;

#define CH_X86_AX   0
#define CH_X86_CX   1
#define CH_X86_DX   2
#define CH_X86_BX   3
#define CH_X86_SP   4
#define CH_X86_BP   5
#define CH_X86_SI   6
#define CH_X86_DI   7

typedef double CH_X86_FPReg;
typedef struct {
  uint64_t bits[2];
} CH_X86_SSEReg;

/**
 * CPU state for x86 processors.
 */
typedef struct {
  uint32_t      regs_GP[8];
  CH_X86_FPReg  regs_FP[8];
  CH_X86_SSEReg regs_SSE[8];
  uint8_t       FP_top;
} CH_X86Context;

/**
 * CPU state for AMD64 processors.
 */
typedef struct {
  uint64_t      regs_GP[16];
  CH_X86_FPReg  regs_FP[8];
  CH_X86_SSEReg regs_SSE[16];
  uint8_t       FP_top;
} CH_AMD64Context;

#endif /*ARCH_H_*/
