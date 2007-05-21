/*
   This file is part of Chronicle, a tool for recording the complete
   execution behaviour of a program.

   Copyright (C) 2002-2005 Novell and contributors:
      robert@ocallahan.org

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307, USA.

   The GNU General Public License is contained in the file COPYING.
*/

#ifndef DEBUG_DWARF2_CONSTANTS_H_
#define DEBUG_DWARF2_CONSTANTS_H_

/* Various constants required by DWARF2, taken directly from the specification. */

typedef enum _CH_Dwarf2_DW_TAG {
  DW_TAG_array_type = 0x01,
  DW_TAG_class_type = 0x02,
  DW_TAG_enumeration_type = 0x04,
  DW_TAG_formal_parameter = 0x05,
  DW_TAG_lexical_block = 0x0b,
  DW_TAG_member = 0x0d,
  DW_TAG_pointer_type = 0x0f,
  DW_TAG_reference_type = 0x10,
  DW_TAG_compile_unit = 0x11,
  DW_TAG_structure_type = 0x13,
  DW_TAG_subroutine_type = 0x15,
  DW_TAG_typedef = 0x16,
  DW_TAG_union_type = 0x17,
  DW_TAG_inheritance = 0x1c,
  DW_TAG_with_stmt = 0x22,
  DW_TAG_base_type = 0x24,
  DW_TAG_catch_block = 0x25,
  DW_TAG_const_type = 0x26,
  DW_TAG_enumerator = 0x28,
  DW_TAG_subprogram = 0x2e,
  DW_TAG_template_type_parameter = 0x2f,
  DW_TAG_template_value_parameter = 0x30,
  DW_TAG_try_block = 0x32,
  DW_TAG_variable = 0x34,
  DW_TAG_volatile_type = 0x35,
  DW_TAG_restrict_type = 0x37,
  DW_TAG_interface_type = 0x38,
  DW_TAG_namespace = 0x39,
  DW_TAG_MAX = 0xFFFF
} CH_Dwarf2_DW_TAG;

typedef enum _CH_Dwarf2_DW_AT {
  DW_AT_sibling = 0x01,
  DW_AT_location = 0x02,
  DW_AT_name = 0x03,
  DW_AT_byte_size = 0x0b,
  DW_AT_bit_offset = 0x0c,
  DW_AT_bit_size = 0x0d,
  DW_AT_stmt_list = 0x10,
  DW_AT_low_pc = 0x11,
  DW_AT_high_pc = 0x12,
  DW_AT_language = 0x13,
  DW_AT_comp_dir = 0x1b,
  DW_AT_const_value = 0x1c,
  DW_AT_start_scope = 0x2c,
  DW_AT_abstract_origin = 0x31,
  DW_AT_artificial = 0x34,
  DW_AT_data_member_location = 0x38,
  DW_AT_declaration = 0x3c,
  DW_AT_encoding = 0x3e,
  DW_AT_frame_base = 0x40,
  DW_AT_specification = 0x47,
  DW_AT_type = 0x49,
  DW_AT_entry_pc = 0x52,
  DW_AT_extension = 0x54,
  DW_AT_ranges = 0x55,
  DW_AT_MAX = 0xFFFF
} CH_Dwarf2_DW_AT;

typedef enum _CH_Dwarf2_DW_ATE {
  DW_ATE_address = 0x01,
  DW_ATE_boolean = 0x02,
  DW_ATE_float = 0x04,
  DW_ATE_signed = 0x05,
  DW_ATE_signed_char = 0x06,
  DW_ATE_unsigned = 0x07,
  DW_ATE_unsigned_char = 0x08
} CH_Dwarf2_DW_ATE;

typedef enum _CH_Dwarf2_DW_FORM {
  DW_FORM_addr = 0x01,
  DW_FORM_block2 = 0x03,
  DW_FORM_block4 = 0x04,
  DW_FORM_data2 = 0x05,
  DW_FORM_data4 = 0x06,
  DW_FORM_data8 = 0x07,
  DW_FORM_string = 0x08,
  DW_FORM_block = 0x09,
  DW_FORM_block1 = 0x0a,
  DW_FORM_data1 = 0x0b,
  DW_FORM_flag = 0x0c,
  DW_FORM_sdata = 0x0d,
  DW_FORM_strp = 0x0e,
  DW_FORM_udata = 0x0f,
  DW_FORM_ref_addr = 0x10,
  DW_FORM_ref1 = 0x11,
  DW_FORM_ref2 = 0x12,
  DW_FORM_ref4 = 0x13,
  DW_FORM_ref8 = 0x14,
  DW_FORM_ref_udata = 0x15,
  DW_FORM_indirect = 0x16,
  DW_FORM_MAX = 0xFFFF
} CH_Dwarf2_DW_FORM;

typedef enum _CH_Dwarf2_DW_LNS {
  DW_LNS_copy = 0x01,
  DW_LNS_advance_pc = 0x02,
  DW_LNS_advance_line = 0x03,
  DW_LNS_set_file = 0x04,
  DW_LNS_const_add_pc = 0x08,
  DW_LNS_fixed_advance_pc = 0x09
} CH_Dwarf2_DW_LNS;

typedef enum _CH_Dwarf2_DW_LNE {
  DW_LNE_end_sequence = 0x01,
  DW_LNE_set_address = 0x02,
  DW_LNE_define_file = 0x03
} CH_Dwarf2_DW_LNE;

typedef enum _CH_Dwarf2_DW_LANG {
  DW_LANG_C89 = 0x01,
  DW_LANG_C = 0x02,
  DW_LANG_Ada83 = 0x03,
  DW_LANG_C_plus_plus = 0x04,
  DW_LANG_Cobol74 = 0x05,
  DW_LANG_Cobol85 = 0x06,
  DW_LANG_Fortran77 = 0x07,
  DW_LANG_Fortran90 = 0x08,
  DW_LANG_Pascal83 = 0x09,
  DW_LANG_Modula2 = 0x0a,
  DW_LANG_Java = 0x0b,
  DW_LANG_C99 = 0x0c,
  DW_LANG_Ada95 = 0x0d,
  DW_LANG_Fortran95 = 0x0e,
  DW_LANG_PLI = 0x0f,
  DW_LANG_MIPSasm = 0x8001,
  DW_LANG_MAX = 0xFFFF
} CH_Dwarf2_DW_LANG;

typedef enum _CH_Dwarf2_DW_OP {
  DW_OP_addr = 0x03,
  DW_OP_deref = 0x06,
  DW_OP_const1u = 0x08,
  DW_OP_const1s = 0x09,
  DW_OP_const2u = 0x0a,
  DW_OP_const2s = 0x0b,
  DW_OP_const4u = 0x0c,
  DW_OP_const4s = 0x0d,
  DW_OP_const8u = 0x0e,
  DW_OP_const8s = 0x0f,
  DW_OP_constu = 0x10,
  DW_OP_consts = 0x11,
  DW_OP_dup = 0x12,
  DW_OP_drop = 0x13,
  DW_OP_over = 0x14,
  DW_OP_pick = 0x15,
  DW_OP_swap = 0x16,
  DW_OP_rot = 0x17,
  DW_OP_xderef = 0x18,
  DW_OP_abs = 0x19,
  DW_OP_and = 0x1a,
  DW_OP_div = 0x1b,
  DW_OP_minus = 0x1c,
  DW_OP_mod = 0x1d,
  DW_OP_mul = 0x1e,
  DW_OP_neg = 0x1f,
  DW_OP_not = 0x20,
  DW_OP_or = 0x21,
  DW_OP_plus = 0x22,
  DW_OP_plus_uconst = 0x23,
  DW_OP_shl = 0x24,
  DW_OP_shr = 0x25,
  DW_OP_shra = 0x26,
  DW_OP_xor = 0x27,
  DW_OP_skip = 0x2f,
  DW_OP_bra = 0x28,
  DW_OP_eq = 0x29,
  DW_OP_ge = 0x2a,
  DW_OP_gt = 0x2b,
  DW_OP_le = 0x2c,
  DW_OP_lt = 0x2d,
  DW_OP_ne = 0x2e,
  
  DW_OP_lit0 = 0x30,
  DW_OP_lit31 = 0x4f,
  DW_OP_reg0 = 0x50,
  DW_OP_reg31 = 0x6f,
  DW_OP_breg0 = 0x70,
  DW_OP_breg31 = 0x8f,
  
  DW_OP_regx = 0x90,
  DW_OP_fbreg = 0x91,
  DW_OP_bregx = 0x92,
  
  DW_OP_piece = 0x93,
  DW_OP_deref_size = 0x94,
  DW_OP_xderef_size = 0x95,
  DW_OP_nop = 0x96,
  DW_OP_push_object_address = 0x97,
  DW_OP_call2 = 0x98,
  DW_OP_call4 = 0x99,
  DW_OP_call_ref = 0x9a,
  DW_OP_form_tls_address = 0x9b,
  DW_OP_call_frame_cfa = 0x9c,
  DW_OP_bit_piece = 0x9d
} CH_Dwarf2_DW_OP;

#endif /*DEBUG_DWARF2_CONSTANTS_H_*/
