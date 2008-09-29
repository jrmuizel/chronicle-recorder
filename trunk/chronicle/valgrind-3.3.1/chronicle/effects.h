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

#ifndef EFFECTS_H_
#define EFFECTS_H_

/*
 * This file defines the format of the static register and memory effect
 * data for code blocks, produced by the tracer and stored in log databases.
 */

#include <stdint.h>

#define CH_EFFECT_ATOM_INSTRUCTION_INDEX_BITS 4
/**
 * Describe an effect within a bunch. The next 'length_increment' (1-15) bytes
 * of the memory range affected by a bunch are affected by the instruction
 * at 'instruction_index' relative to the first instruction of the bunch.
 */
typedef struct {
  uint8_t instruction_index:CH_EFFECT_ATOM_INSTRUCTION_INDEX_BITS;
  uint8_t length_increment:4;
} CH_BunchedEffectAtom;
#define CH_EFFECT_ATOMS 8
/**
 * Up to CH_EFFECT_ATOMS individual effects are gathered to form a single bunch.
 * When the first atom has length_increment 0, the bunch has just a single
 * instruction that is responsible for its entire effect. The 'length' field
 * of the CH_BunchedEffect record specifies the true length in that case.
 * (This allows for single instructions that affect more than 15 bytes
 * of memory, such as some SSE2 instructions and some x86 instructions that
 * are more than 15 bytes long.)
 */
typedef struct {
  CH_BunchedEffectAtom atoms[CH_EFFECT_ATOMS];
} CH_BunchedEffectAtoms;

#define CH_MAP_INSTR_EXEC  0 /* static offsets, no data */
#define CH_MAP_MEM_READ    1 /* dynamic offset, no data */
#define CH_MAP_MEM_WRITE   2 /* dynamic offset, data */
#define CH_MAP_ENTER_SP    3 /* dyanmic offset, no data */
#define CH_MAX_BUILTIN_MAP 3
#define CH_MAP_CUSTOM      255

/** Static description of a bunched memory effect performed by a code block. */
typedef struct {
  /**
   * The memory address affected by the bunch is the sum of a dynamic part
   * and a static part. This is the static part.
   */
  uintptr_t static_offset;
  /**
   * Which of the builtin maps this effect belongs to: one of the CH_MAP_
   * constants.
   */
  uint8_t   map:5;
  /**
   * True if this effect has associated data in the dynamic log (e.g.,
   * for memory writes.
   */
  uint8_t   has_data:1;
  /**
   * True if this effect has an associated dynamic offset saved in the dynamic
   * log.
   */
  uint8_t   has_dynamic_offset:1;
  /**
   * True if this effect uses a dynamic offset to calculate the memory
   * address of the start of the effect. If false, the dynamic offset is
   * effectively always zero.
   * Effects that use a dynamic offset, but don't have one, use the
   * dynamic offset of the previous bunched effect for the same map.
   */
  uint8_t   uses_dynamic_offset:1;
  /**
   * The index of the first instruction within the block that participates in
   * this bunched effect. The instruction_index values in the effect atoms
   * are relative to this.
   */
  uint8_t   first_instruction_index;
  /**
   * The index of the last instruction within the block that participates
   * in this bunched effect.
   */
  uint8_t   last_instruction_index;
  /** The total number of bytes affected by this bunched effect. */
  uint8_t   length;
  /** The atomic effects that have been bunched together. */
  CH_BunchedEffectAtoms atoms;
} CH_BunchedEffect;

/**
 * This struct encodes the static information about a register effect
 * performed by a code block.
 */
typedef struct {
  /** The index of the instruction within the block that causes this effect. */
  uint8_t instruction_index;
  /** The type of effect --- one of the CH_EFFECT_ constants below. */
  uint8_t type:5;
  /** The size of the effect; the actual size is 2^bytes_pow2 bytes. */
  uint8_t bytes_pow2:3;
  /** The static register affected, if known. */
  uint8_t reg;
  /** Immediate data pertaining to this effect. */
  uint8_t imm1; /* imm = (imm1 << 8) | imm0 */
  /** Immediate data pertaining to this effect. */
  uint8_t imm0;
} CH_RegEffect;
/** Read low 'size' bytes from register 'reg' */
#define CH_EFFECT_REG_READ      1
/** Setting low 'size' bytes of register 'reg';
    value is 'size' bytes in log */
#define CH_EFFECT_REG_WRITE     2
/** Reading low 'size' bytes from dynamic register,
    register is 1 byte in log  */
#define CH_EFFECT_DYNREG_READ   3
/** Setting low 'size' bytes of dynamic register; 
    value is 'size' bytes in log; register is 1 byte in log */
#define CH_EFFECT_DYNREG_WRITE  4
/** Setting low 'size' bytes of 'reg' to a sign-extended constant 'imm' */
#define CH_EFFECT_REG_SETCONST  5
/** Adding sign-extended value 'imm' to low 'size' bytes of 'reg' */
#define CH_EFFECT_REG_ADDCONST  6
/** Setting low 'size' bytes of 'reg' to the low 'size' bytes of register
    'imm1' plus sign-extended 'imm0' */
#define CH_EFFECT_REG_ADDREG    7
#define CH_EFFECT_REG_MAX       7

#endif /*EFFECTS_H_*/
