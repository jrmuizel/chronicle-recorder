
/*--------------------------------------------------------------------*/
/*--- Read DWARF1/2/3 debug info.                      readdwarf.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2000-2007 Julian Seward
      jseward@acm.org

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
/*
   Stabs reader greatly improved by Nick Nethercote, Apr 02.
   This module was also extensively hacked on by Jeremy Fitzhardinge
   and Tom Hughes.
*/

#include "pub_core_basics.h"
#include "pub_core_libcbase.h"
#include "pub_core_libcassert.h"
#include "pub_core_libcprint.h"
#include "pub_core_mallocfree.h"
#include "pub_core_options.h"
#include "pub_core_xarray.h"
#include "priv_storage.h"
#include "priv_readdwarf.h"        /* self */


/*------------------------------------------------------------*/
/*---                                                      ---*/
/*--- Read line number and CFI info from DWARF1, DWARF2    ---*/
/*--- and to some extent DWARF3 sections.                  ---*/
/*---                                                      ---*/
/*------------------------------------------------------------*/

/*------------------------------------------------------------*/
/*--- Expanding arrays of words, for holding file name and ---*/
/*--- directory name arrays.                               ---*/
/*------------------------------------------------------------*/

typedef
   struct {
      Word* tab;
      UInt  tab_size;
      UInt  tab_used;
   }
   WordArray;

static void init_WordArray ( WordArray* wa )
{
   wa->tab      = NULL;
   wa->tab_size = 0;
   wa->tab_used = 0;
}

static void free_WordArray ( WordArray* wa )
{
   if (wa->tab) {
      vg_assert(wa->tab_size > 0);
      VG_(arena_free)(VG_AR_SYMTAB, wa->tab);
   }
   init_WordArray(wa);
}

static void addto_WordArray ( WordArray* wa, Word w )
{
   UInt  new_size, i;
   Word* new_tab;

   if (0) VG_(printf)("<<ADD %p (new sz = %d) >>\n", 
                      (HChar*)w, wa->tab_used+1);

   if (wa->tab_used < wa->tab_size) {
      /* fine */
   } else {
      /* expand array */
      if (0) VG_(printf)("EXPAND ARRAY from %d\n", wa->tab_size);
      vg_assert(wa->tab_used == wa->tab_size);
      vg_assert( (wa->tab_size == 0 && wa->tab == NULL)
                 || (wa->tab_size != 0 && wa->tab != NULL) );
      new_size = wa->tab_size == 0 ? 8 : 2 * wa->tab_size;
      new_tab  = VG_(arena_malloc)(VG_AR_SYMTAB, 
                                   new_size * sizeof(Word));
      vg_assert(new_tab != NULL);
      for (i = 0; i < wa->tab_used; i++)
         new_tab[i] = wa->tab[i];
      wa->tab_size = new_size;
      if (wa->tab)
         VG_(arena_free)(VG_AR_SYMTAB, wa->tab);
      wa->tab = new_tab;
   }

   vg_assert(wa->tab_used < wa->tab_size);
   vg_assert(wa->tab_size > 0);
   wa->tab[wa->tab_used] = w;
   wa->tab_used++;
}

static Word index_WordArray ( /*OUT*/Bool* inRange, WordArray* wa, Int i )
{
   vg_assert(inRange);
   if (i >= 0 && i < wa->tab_used) {
      *inRange = True;
      return wa->tab[i];
   } else {
      *inRange = False;
      return 0;
   }
}


/*------------------------------------------------------------*/
/*--- Read DWARF2 format line number info.                 ---*/
/*------------------------------------------------------------*/

/* Structure holding info extracted from the a .debug_line
   section.  */
typedef struct
{
  ULong  li_length;
  UShort li_version;
  ULong  li_header_length;
  UChar  li_min_insn_length;
  UChar  li_default_is_stmt;
  Int    li_line_base;
  UChar  li_line_range;
  UChar  li_opcode_base;
}
DebugLineInfo;

/* Structure holding additional infos found from a .debug_info
 * compilation unit block */
typedef struct
{
  /* Feel free to add more members here if you need ! */
  Char* compdir;   /* Compilation directory - points to .debug_info */
  Char* name;      /* Main file name - points to .debug_info */
  ULong stmt_list; /* Offset in .debug_line */
  Bool  dw64;      /* 64-bit Dwarf? */
} 
UnitInfo;

/* Line number opcodes.  */
enum dwarf_line_number_ops
  {
    DW_LNS_extended_op = 0,
    DW_LNS_copy = 1,
    DW_LNS_advance_pc = 2,
    DW_LNS_advance_line = 3,
    DW_LNS_set_file = 4,
    DW_LNS_set_column = 5,
    DW_LNS_negate_stmt = 6,
    DW_LNS_set_basic_block = 7,
    DW_LNS_const_add_pc = 8,
    DW_LNS_fixed_advance_pc = 9,
    /* DWARF 3.  */
    DW_LNS_set_prologue_end = 10,
    DW_LNS_set_epilogue_begin = 11,
    DW_LNS_set_isa = 12
  };

/* Line number extended opcodes.  */
enum dwarf_line_number_x_ops
  {
    DW_LNE_end_sequence = 1,
    DW_LNE_set_address = 2,
    DW_LNE_define_file = 3
  };

typedef struct
{
  /* Information for the last statement boundary.
   * Needed to calculate statement lengths. */
  Addr  last_address;
  UInt  last_file;
  UInt  last_line;

  Addr  address;
  UInt  file;
  UInt  line;
  UInt  column;
  Int   is_stmt;
  Int   basic_block;
  Int   end_sequence;
} LineSMR;


static 
ULong read_leb128 ( UChar* data, Int* length_return, Int sign )
{
  ULong  result = 0;
  UInt   num_read = 0;
  Int    shift = 0;
  UChar  byte;

  vg_assert(sign == 0 || sign == 1);

  do
    {
      byte = * data ++;
      num_read ++;

      result |= ((ULong)(byte & 0x7f)) << shift;

      shift += 7;

    }
  while (byte & 0x80);

  if (length_return != NULL)
    * length_return = num_read;

  if (sign && (shift < 64) && (byte & 0x40))
    result |= (-1ULL) << shift;

  return result;
}

/* Small helper functions easier to use
 * value is returned and the given pointer is
 * moved past end of leb128 data */
static ULong read_leb128U( UChar **data )
{
  Int len;
  ULong val = read_leb128( *data, &len, 0 );
  *data += len;
  return val;
}

/* Same for signed data */
static Long read_leb128S( UChar **data )
{
   Int len;
   ULong val = read_leb128( *data, &len, 1 );
   *data += len;
   return (Long)val;
}

/* Read what the DWARF3 spec calls an "initial length field".  This
   uses up either 4 or 12 bytes of the input and produces a 32-bit or
   64-bit number respectively.

   Read 32-bit value from p.  If it is 0xFFFFFFFF, instead read a
   64-bit bit value from p+4.  This is used in 64-bit dwarf to encode
   some table lengths. 

   XXX this is a hack: the endianness of the initial length field is
   specified by the DWARF we're reading.  This happens to work only
   because we don't do cross-arch jitting, hence this code runs on a
   platform of the same endianness as the DWARF it is reading.  Same
   applies for initial lengths for CIE/FDEs and probably in zillions
   of other places -- to be precise, exactly the places where
   binutils/dwarf.c calls byte_get().
*/
static ULong read_initial_length_field ( UChar* p_img, /*OUT*/Bool* is64 )
{
   UInt w32 = *((UInt*)p_img);
   if (w32 == 0xFFFFFFFF) {
      *is64 = True;
      return *((ULong*)(p_img+4));
   } else {
      *is64 = False;
      return (ULong)w32;
   }
}


static LineSMR state_machine_regs;

static 
void reset_state_machine ( Int is_stmt )
{
   if (0) VG_(printf)("smr.a := %p (reset)\n", 0 );
   state_machine_regs.last_address = 0;
   state_machine_regs.last_file = 1;
   state_machine_regs.last_line = 1;
   state_machine_regs.address = 0;
   state_machine_regs.file = 1;
   state_machine_regs.line = 1;
   state_machine_regs.column = 0;
   state_machine_regs.is_stmt = is_stmt;
   state_machine_regs.basic_block = 0;
   state_machine_regs.end_sequence = 0;
}

/* Look up a directory name, or return NULL if unknown. */
static
Char* lookupDir ( Int filename_index,
                  WordArray* fnidx2dir,
                  WordArray* dirnames )
{
   Bool inRange;
   Word diridx, dirname;

   diridx = index_WordArray( &inRange, fnidx2dir, filename_index );
   if (!inRange) goto bad;

   dirname = index_WordArray( &inRange, dirnames, (Int)diridx );
   if (!inRange) goto bad;

   return (Char*)dirname;
  bad:
   return NULL;
}

////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////

/* Handled an extended line op starting at 'data'.  Returns the number
   of bytes that 'data' should be advanced by. */
static 
Word process_extended_line_op( struct _SegInfo* si, OffT debug_offset,
                               WordArray* filenames, 
                               WordArray* dirnames, 
                               WordArray* fnidx2dir, 
                               UChar* data, Int is_stmt)
{
   UChar  op_code;
   Int    bytes_read;
   UInt   len;
   UChar* name;
   Addr   adr;

   len = read_leb128 (data, & bytes_read, 0);
   data += bytes_read;

   if (len == 0) {
      VG_(message)(Vg_UserMsg,
                   "Warning: DWARF2 reader: "
                   "Badly formed extended line op encountered");
      return (Word)bytes_read;
   }

   len += bytes_read;
   op_code = * data ++;

   if (0) VG_(printf)("dwarf2: ext OPC: %d\n", op_code);

   switch (op_code) {
      case DW_LNE_end_sequence:
         if (0) VG_(printf)("1001: si->o %p, smr.a %p\n", 
                            debug_offset, state_machine_regs.address );
         /* JRS: added for compliance with spec; is pointless due to
            reset_state_machine below */
         state_machine_regs.end_sequence = 1; 

         if (state_machine_regs.is_stmt) {
            if (state_machine_regs.last_address) {
               Bool inRange = False;
               Char* filename
                  = (Char*)index_WordArray( &inRange, filenames, 
                                            state_machine_regs.last_file);
               if (!inRange || !filename)
                  filename = "???";
               ML_(addLineInfo) (
                  si, 
                  filename, 
                  lookupDir( state_machine_regs.last_file,
                             fnidx2dir, dirnames ),
                  debug_offset + state_machine_regs.last_address, 
                  debug_offset + state_machine_regs.address, 
                  state_machine_regs.last_line, 0
               );
            }
         }
         reset_state_machine (is_stmt);
         if (si->ddump_line)
            VG_(printf)("  Extended opcode %d: End of Sequence\n\n", 
                        (Int)op_code);
         break;

      case DW_LNE_set_address:
         adr = *((Addr *)data);
         state_machine_regs.address = adr;
         if (si->ddump_line)
            VG_(printf)("  Extended opcode %d: set Address to 0x%lx\n",
                        (Int)op_code, (Addr)adr);
         break;

      case DW_LNE_define_file:
         name = data;
         addto_WordArray( filenames, (Word)ML_(addStr)(si,name,-1) );
         data += VG_(strlen) ((char *) data) + 1;
         read_leb128 (data, & bytes_read, 0);
         data += bytes_read;
         read_leb128 (data, & bytes_read, 0);
         data += bytes_read;
         read_leb128 (data, & bytes_read, 0);
         if (si->ddump_line)
            VG_(printf)("  DWARF2-line: set_address\n");
         break;

      default:
         if (si->ddump_line)
            VG_(printf)("process_extended_line_op:default\n");
         break;
   }

   return (Word)len;
}

////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////

/* read a .debug_line section block for a compilation unit
 *
 * Input:   - theBlock must point to the start of the block
 *            for the given compilation unit
 *          - ui contains additional info like the compilation dir
 *            for this unit
 *
 * Output: - si debug info structures get updated
 */
static 
void read_dwarf2_lineblock ( struct _SegInfo*  si, OffT debug_offset,
                             UnitInfo* ui, 
                             UChar*    theBlock, /* IMAGE */
                             Int       noLargerThan )
{
   Int            i;
   DebugLineInfo  info;
   UChar*         standard_opcodes;
   UChar*         end_of_sequence;
   Bool           is64;
   WordArray      filenames;
   WordArray      dirnames;
   WordArray      fnidx2dir;

   UChar*         external = theBlock;
   UChar*         data = theBlock;

   /* filenames is an array of file names harvested from the DWARF2
      info.  Entry [0] is NULL and is never referred to by the state
      machine.

      Similarly, dirnames is an array of directory names.  Entry [0]
      is also NULL and denotes "we don't know what the path is", since
      that is different from "the path is the empty string".  Unlike
      the file name table, the state machine does refer to entry [0],
      which basically means "." ("the current directory of the
      compilation", whatever that means, according to the DWARF3
      spec.)

      fnidx2dir is an array of indexes into the dirnames table.
      (confused yet?)  filenames[] and fnidx2dir[] are indexed
      together.  That is, for some index i in the filename table, then

         the filename  is filenames[i]
         the directory is dirnames[ fnidx2dir[i] ] */

   /* Fails due to gcc padding ...
   vg_assert(sizeof(DWARF2_External_LineInfo)
             == sizeof(DWARF2_Internal_LineInfo));
   */

   init_WordArray(&filenames);
   init_WordArray(&dirnames);
   init_WordArray(&fnidx2dir);

   /* DWARF2 starts numbering filename entries at 1, so we need to
      add a dummy zeroth entry to the table.  The zeroth dirnames
      entry denotes 'current directory of compilation' so we might
      as well make the fnidx2dir zeroth entry denote that. 
   */
   addto_WordArray( &filenames, (Word)NULL );

   if (ui->compdir)
      addto_WordArray( &dirnames, (Word)ML_(addStr)(si, ui->compdir, -1) );
   else
      addto_WordArray( &dirnames, (Word)ML_(addStr)(si, ".", -1) );

   addto_WordArray( &fnidx2dir, (Word)0 );  /* compilation dir */

   info.li_length = read_initial_length_field( external, &is64 );
   external += is64 ? 12 : 4;
   if (si->ddump_line)
      VG_(printf)("  Length:                      %llu\n", 
                  info.li_length);

   /* Check the length of the block.  */
   if (info.li_length > noLargerThan) {
      ML_(symerr)("DWARF line info appears to be corrupt "
                  "- the section is too small");
      goto out;
   }

   /* Check its version number.  */
   info.li_version = * ((UShort *)external);
   external += 2;
   if (si->ddump_line)
      VG_(printf)("  DWARF Version:               %d\n", 
                  (Int)info.li_version);

   if (info.li_version != 2) {
      ML_(symerr)("Only DWARF version 2 line info "
                  "is currently supported.");
      goto out;
   }

   info.li_header_length = ui->dw64 ? *((ULong*)external) 
                                    : (ULong)(*((UInt*)external));
   external += ui->dw64 ? 8 : 4;
   if (si->ddump_line)
      VG_(printf)("  Prologue Length:             %llu\n", 
                  info.li_header_length);

   info.li_min_insn_length = * ((UChar *)external);
   external += 1;
   if (si->ddump_line)
      VG_(printf)("  Minimum Instruction Length:  %d\n", 
                  (Int)info.li_min_insn_length);

   info.li_default_is_stmt = * ((UChar *)external);
   external += 1;
   if (si->ddump_line)
      VG_(printf)("  Initial value of 'is_stmt':  %d\n", 
                  (Int)info.li_default_is_stmt);

   /* Josef Weidendorfer (20021021) writes:

      It seems to me that the Intel Fortran compiler generates bad
      DWARF2 line info code: It sets "is_stmt" of the state machine in
      the the line info reader to be always false. Thus, there is
      never a statement boundary generated and therefore never a
      instruction range/line number mapping generated for valgrind.

      Please have a look at the DWARF2 specification, Ch. 6.2
      (x86.ddj.com/ftp/manuals/tools/dwarf.pdf).  Perhaps I understand
      this wrong, but I don't think so.

      I just had a look at the GDB DWARF2 reader...  They completely
      ignore "is_stmt" when recording line info ;-) That's the reason
      "objdump -S" works on files from the the intel fortran compiler.

      Therefore: */
   info.li_default_is_stmt = True; 

   /* JRS: changed (UInt*) to (UChar*) */
   info.li_line_base = * ((UChar *)external);
   info.li_line_base = (Int)(signed char)info.li_line_base;
   external += 1;
   if (si->ddump_line)
      VG_(printf)("  Line Base:                   %d\n", 
                  info.li_line_base);

   info.li_line_range = * ((UChar *)external);
   external += 1;
   if (si->ddump_line)
      VG_(printf)("  Line Range:                  %d\n", 
                  (Int)info.li_line_range);

   info.li_opcode_base = * ((UChar *)external);
   external += 1;
   if (si->ddump_line)
      VG_(printf)("  Opcode Base:                 %d\n\n", 
                  info.li_opcode_base);

   if (0) VG_(printf)("dwarf2: line base: %d, range %d, opc base: %d\n",
                      (Int)info.li_line_base, 
                      (Int)info.li_line_range,
                      (Int)info.li_opcode_base);

   end_of_sequence = data + info.li_length 
                          + (is64 ? 12 : 4);

   reset_state_machine (info.li_default_is_stmt);

   /* Read the contents of the Opcodes table.  */
   standard_opcodes = external;
   if (si->ddump_line) {
      VG_(printf)(" Opcodes:\n");
      for (i = 1; i < (Int)info.li_opcode_base; i++) {
         VG_(printf)("  Opcode %d has %d args\n", 
                     i, (Int)standard_opcodes[i-1]);
      }
      VG_(printf)("\n");
   }

   /* Read the contents of the Directory table.  */
   data = standard_opcodes + info.li_opcode_base - 1;

   if (si->ddump_line)
      VG_(printf)(" The Directory Table%s\n", 
                  *data == 0 ? " is empty." : ":" );

   while (* data != 0) {

#     define NBUF 4096
      static Char buf[NBUF];

      if (si->ddump_line)
         VG_(printf)("  %s\n", data);

      /* If data[0] is '/', then 'data' is an absolute path and we
         don't mess with it.  Otherwise, if we can, construct the
         'path ui->compdir' ++ "/" ++ 'data'. */

      if (*data != '/' 
          /* not an absolute path */
          && ui->compdir != NULL
          /* actually got something sensible for compdir */
          && VG_(strlen)(ui->compdir) + VG_(strlen)(data) + 5/*paranoia*/ < NBUF
          /* it's short enough to concatenate */) 
      {
         buf[0] = 0;
         VG_(strcat)(buf, ui->compdir);
         VG_(strcat)(buf, "/");
         VG_(strcat)(buf, data);
         vg_assert(VG_(strlen)(buf) < NBUF);
         addto_WordArray( &dirnames, (Word)ML_(addStr)(si,buf,-1) );
         if (0) VG_(printf)("rel path  %s\n", buf);
      } else {
         /* just use 'data'. */
         addto_WordArray( &dirnames, (Word)ML_(addStr)(si,data,-1) );
         if (0) VG_(printf)("abs path  %s\n", data);
      }

      data += VG_(strlen)(data) + 1;

#     undef NBUF
   }

   if (si->ddump_line)
      VG_(printf)("\n");

   if (*data != 0) {
      ML_(symerr)("can't find NUL at end of DWARF2 directory table");
      goto out;
   }
   data ++;

   /* Read the contents of the File Name table.  This produces a bunch
      of file names, and for each, an index to the corresponding
      directory name entry. */
   if (si->ddump_line) {
      VG_(printf)(" The File Name Table:\n");
      VG_(printf)("  Entry	Dir	Time	Size	Name\n");
   }

   i = 1;
   while (* data != 0) {
      UChar* name;
      Int    bytes_read, diridx;
      Int    uu_time, uu_size; /* unused, and a guess */
      name = data;
      data += VG_(strlen) ((Char *) data) + 1;

      diridx = read_leb128 (data, & bytes_read, 0);
      data += bytes_read;
      uu_time = read_leb128 (data, & bytes_read, 0);
      data += bytes_read;
      uu_size = read_leb128 (data, & bytes_read, 0);
      data += bytes_read;

      addto_WordArray( &filenames, (Word)ML_(addStr)(si,name,-1) );
      addto_WordArray( &fnidx2dir, (Word)diridx );
      if (0) VG_(printf)("file %s diridx %d\n", name, diridx );
      if (si->ddump_line)
         VG_(printf)("  %d\t%d\t%d\t%d\t%s\n", 
                     i, diridx, uu_time, uu_size, name);
      i++;
   }

   if (si->ddump_line)
      VG_(printf)("\n");

   if (*data != 0) {
      ML_(symerr)("can't find NUL at end of DWARF2 file name table");
      goto out;
   }
   data ++;

   if (si->ddump_line)
      VG_(printf)(" Line Number Statements:\n");

   /* Now display the statements.  */

   while (data < end_of_sequence) {

      UChar op_code;
      Int           adv;
      Int           bytes_read;

      op_code = * data ++;

      if (0) VG_(printf)("dwarf2: OPC: %d\n", op_code);

      if (op_code >= info.li_opcode_base) {

         Int advAddr;
         op_code -= info.li_opcode_base;
         adv      = (op_code / info.li_line_range) 
                       * info.li_min_insn_length;
         advAddr = adv;
         state_machine_regs.address += adv;

         if (0) VG_(printf)("smr.a += %p\n", adv );
         adv = (op_code % info.li_line_range) + info.li_line_base;
         if (0) VG_(printf)("1002: si->o %p, smr.a %p\n", 
                            debug_offset, state_machine_regs.address );
         state_machine_regs.line += adv;

         if (si->ddump_line)
            VG_(printf)("  Special opcode %d: advance Address by %d "
                        "to 0x%lx and Line by %d to %d\n", 
                        (Int)op_code, advAddr, state_machine_regs.address,
                        (Int)adv, (Int)state_machine_regs.line );

         if (state_machine_regs.is_stmt) {
            /* only add a statement if there was a previous boundary */
            if (state_machine_regs.last_address) {
               Bool inRange = False;
               Char* filename
                  = (Char*)index_WordArray( &inRange, &filenames, 
                                            state_machine_regs.last_file);
               if (!inRange || !filename)
                  filename = "???";
               ML_(addLineInfo)(
                  si, 
                  filename,
                  lookupDir( state_machine_regs.last_file,
                             &fnidx2dir, &dirnames ),
                  debug_offset + state_machine_regs.last_address, 
                  debug_offset + state_machine_regs.address, 
                  state_machine_regs.last_line, 
                  0
               );
            }
            state_machine_regs.last_address = state_machine_regs.address;
            state_machine_regs.last_file = state_machine_regs.file;
            state_machine_regs.last_line = state_machine_regs.line;
         }

      }

      else { /* ! (op_code >= info.li_opcode_base) */

      switch (op_code) {
         case DW_LNS_extended_op:
            data += process_extended_line_op (
                       si, debug_offset, &filenames, &dirnames, &fnidx2dir,
                       data, info.li_default_is_stmt);
            break;

         case DW_LNS_copy:
            if (0) VG_(printf)("1002: si->o %p, smr.a %p\n", 
                               debug_offset, state_machine_regs.address );
            if (state_machine_regs.is_stmt) {
               /* only add a statement if there was a previous boundary */
               if (state_machine_regs.last_address) {
                  Bool inRange = False;
                  Char* filename
                     = (Char*)index_WordArray( &inRange, &filenames,
                                               state_machine_regs.last_file );
                  if (!inRange || !filename)
                     filename = "???";
                  ML_(addLineInfo)(
                     si, 
                     filename,
                     lookupDir( state_machine_regs.last_file,
                                &fnidx2dir, &dirnames ),
                     debug_offset + state_machine_regs.last_address, 
                     debug_offset + state_machine_regs.address,
                     state_machine_regs.last_line, 
                     0
                  );
               }
               state_machine_regs.last_address = state_machine_regs.address;
               state_machine_regs.last_file = state_machine_regs.file;
               state_machine_regs.last_line = state_machine_regs.line;
            }
            state_machine_regs.basic_block = 0; /* JRS added */
            if (si->ddump_line)
               VG_(printf)("  Copy\n");
            break;

         case DW_LNS_advance_pc:
            adv = info.li_min_insn_length 
                     * read_leb128 (data, & bytes_read, 0);
            data += bytes_read;
            state_machine_regs.address += adv;
            if (0) VG_(printf)("smr.a += %p\n", adv );
            if (si->ddump_line)
               VG_(printf)("  Advance PC by %d to 0x%lx\n", 
                           (Int)adv, state_machine_regs.address);
            break;

         case DW_LNS_advance_line:
            adv = read_leb128 (data, & bytes_read, 1);
            data += bytes_read;
            state_machine_regs.line += adv;
            if (si->ddump_line)
               VG_(printf)("  Advance Line by %d to %d\n", 
                           (Int)adv, (Int)state_machine_regs.line);
            break;

         case DW_LNS_set_file:
            adv = read_leb128 (data, & bytes_read, 0);
            data += bytes_read;
            state_machine_regs.file = adv;
            if (si->ddump_line)
               VG_(printf)("  Set File Name to entry %d in the File Name Table\n",
                           (Int)adv);
            break;

         case DW_LNS_set_column:
            adv = read_leb128 (data, & bytes_read, 0);
            data += bytes_read;
            state_machine_regs.column = adv;
            if (si->ddump_line)
               VG_(printf)("  DWARF2-line: set_column\n");
            break;

         case DW_LNS_negate_stmt:
            adv = state_machine_regs.is_stmt;
            adv = ! adv;
            state_machine_regs.is_stmt = adv;
            if (si->ddump_line)
               VG_(printf)("  DWARF2-line: negate_stmt\n");
            break;

         case DW_LNS_set_basic_block:
            state_machine_regs.basic_block = 1;
            if (si->ddump_line)
               VG_(printf)("  DWARF2-line: set_basic_block\n");
            break;

         case DW_LNS_const_add_pc:
            adv = (((255 - info.li_opcode_base) / info.li_line_range)
                   * info.li_min_insn_length);
            state_machine_regs.address += adv;
            if (0) VG_(printf)("smr.a += %p\n", adv );
            if (si->ddump_line)
               VG_(printf)("  Advance PC by constant %d to 0x%lx\n", 
                           (Int)adv, (Addr)state_machine_regs.address);
            break;

         case DW_LNS_fixed_advance_pc:
            /* XXX: Need something to get 2 bytes */
            adv = *((UShort *)data);
            data += 2;
            state_machine_regs.address += adv;
            if (0) VG_(printf)("smr.a += %p\n", adv );
            if (si->ddump_line)
               VG_(printf)("  DWARF2-line: fixed_advance_pc\n");
            break;

         case DW_LNS_set_prologue_end:
            if (si->ddump_line)
               VG_(printf)("  DWARF2-line: set_prologue_end\n");
            break;

         case DW_LNS_set_epilogue_begin:
            if (si->ddump_line)
               VG_(printf)("  DWARF2-line: set_epilogue_begin\n");
            break;

         case DW_LNS_set_isa:
            adv = read_leb128 (data, & bytes_read, 0);
            data += bytes_read;
            if (si->ddump_line)
               VG_(printf)("  DWARF2-line: set_isa\n");
            break;

         default: {
            Int j;
            for (j = standard_opcodes[op_code - 1]; j > 0 ; --j) {
               read_leb128 (data, &bytes_read, 0);
               data += bytes_read;
            }
            if (si->ddump_line)
               VG_(printf)("  Unknown opcode %d\n", (Int)op_code);
            break;
         }
      } /* switch (op_code) */

      } /* if (op_code >= info.li_opcode_base) */

   } /* while (data < end_of_sequence) */

   if (si->ddump_line)
      VG_(printf)("\n");

  out:
   free_WordArray(&filenames);
   free_WordArray(&dirnames);
   free_WordArray(&fnidx2dir);
}

////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////

/* Return abbrev for given code 
 * Returned pointer points to the tag
 * */
static UChar* lookup_abbrev( UChar* p, UInt acode )
{
   UInt code;
   UInt name;
   for( ; ; ) {
      code = read_leb128U( &p );
      if ( code == acode )
         return p;
      read_leb128U( &p ); /* skip tag */
      p++;                /* skip has_children flag */
      do {
         name = read_leb128U( &p ); /* name */
         read_leb128U( &p );   /* form */
      }
      while( name != 0 ); /* until name == form == 0 */
   }
   return NULL;
}

/* Read general information for a particular compile unit block in
 * the .debug_info section.
 * 
 * Input: - unitblock is the start of a compilation
 *          unit block in .debuginfo section
 *        - debugabbrev is start of .debug_abbrev section
 *        - debugstr is start of .debug_str section
 *        
 * Output: Fill members of ui pertaining to the compilation unit:
 *         - ui->name is the name of the compilation unit
 *         - ui->compdir is the compilation unit directory
 *         - ui->stmt_list is the offset in .debug_line section
 *                for the dbginfos of this compilation unit
 *                
 * Note : the output strings are not allocated and point
 * directly to the memory-mapped section.
 */
static 
void read_unitinfo_dwarf2( /*OUT*/UnitInfo* ui,
                                  UChar*    unitblock_img,
                                  UChar*    debugabbrev_img,
                                  UChar*    debugstr_img,
                                  struct _SegInfo* si )
{
   UInt   acode, abcode;
   ULong  atoffs, blklen;
   Int    level;
   UShort ver;

   UChar addr_size;
   UChar* p = unitblock_img;
   UChar* end_img;
   UChar* abbrev_img;

   VG_(memset)( ui, 0, sizeof( UnitInfo ) );
   ui->stmt_list = -1LL;
   
   /* Read the compilation unit header in .debug_info section - See p 70 */

   /* This block length */
   blklen = read_initial_length_field( p, &ui->dw64 );
   p += ui->dw64 ? 12 : 4;

   /* version should be 2 */
   ver = *((UShort*)p);
   p += 2;

   /* get offset in abbrev */
   atoffs = ui->dw64 ? *((ULong*)p) : (ULong)(*((UInt*)p));
   p += ui->dw64 ? 8 : 4;

   /* Address size */
   addr_size = *p;
   p += 1;

   end_img     = unitblock_img 
                 + blklen + (ui->dw64 ? 12 : 4); /* End of this block */
   level       = 0;                        /* Level in the abbrev tree */
   abbrev_img  = debugabbrev_img 
                 + atoffs; /* Abbreviation data for this block */
   
   /* Read the compilation unit entries */
   while ( p < end_img ) {
      Bool has_child;
      UInt tag;

      acode = read_leb128U( &p ); /* abbreviation code */
      if ( acode == 0 ) {
         /* NULL entry used for padding - or last child for a sequence
            - see para 7.5.3 */
         level--;
         continue;
      }
      
      /* Read abbreviation header */
      abcode = read_leb128U( &abbrev_img ); /* abbreviation code */
      if ( acode != abcode ) {
         /* We are in in children list, and must rewind to a
          * previously declared abbrev code.  This code works but is
          * not triggered since we shortcut the parsing once we have
          * read the compile_unit block.  This should only occur when
          * level > 0 */
         abbrev_img = lookup_abbrev( debugabbrev_img + atoffs, acode );
      }

      tag = read_leb128U( &abbrev_img );
      has_child = *(abbrev_img++) == 1; /* DW_CHILDREN_yes */

      if ( has_child )
         level++;

      /* And loop on entries */
      for ( ; ; ) {
         /* Read entry definition */
         UInt  name, form;
         ULong cval = -1LL;  /* Constant value read */
         Char  *sval = NULL; /* String value read */
         name = read_leb128U( &abbrev_img );
         form = read_leb128U( &abbrev_img );
         if ( name == 0 )
            break;
       
         /* Read data */
         /* Attributes encoding explained p 71 */
         if ( form == 0x16 /* FORM_indirect */ )
            form = read_leb128U( &p );
         /* Decode form. For most kinds, Just skip the amount of data since
            we don't use it for now */
         /* JRS 9 Feb 06: This now handles 64-bit DWARF too.  In
            64-bit DWARF, lineptr (and loclistptr,macptr,rangelistptr
            classes) use FORM_data8, not FORM_data4.  Also,
            FORM_ref_addr and FORM_strp are 64-bit values, not 32-bit
            values. */
         switch( form ) {
            /* Those cases extract the data properly */
            case 0x05: /* FORM_data2 */     cval = *((UShort*)p); p +=2; break;
            case 0x06: /* FORM_data4 */     cval = *((UInt*)p);p +=4; break;
            case 0x0e: /* FORM_strp */      /* pointer in .debug_str */
                       /* 2006-01-01: only generate a value if
                          debugstr is non-NULL (which means that a
                          debug_str section was found) */
                                            if (debugstr_img && !ui->dw64)
                                               sval = debugstr_img + *((UInt*)p); 
                                            if (debugstr_img && ui->dw64)
                                               sval = debugstr_img + *((ULong*)p); 
                                            p += ui->dw64 ? 8 : 4; 
                                            break;
            case 0x08: /* FORM_string */    sval = (Char*)p; 
                                            p += VG_(strlen)((Char*)p) + 1; break;
            case 0x0b: /* FORM_data1 */     cval = *p; p++; break;
            
            /* TODO : Following ones just skip data - implement if you need */
            case 0x01: /* FORM_addr */      p += addr_size; break;
            case 0x03: /* FORM_block2 */    p += *((UShort*)p) + 2; break;
            case 0x04: /* FORM_block4 */    p += *((UInt*)p) + 4; break;
            case 0x07: /* FORM_data8 */     if (ui->dw64) cval = *((ULong*)p);
                                            p += 8; break;
                       /* perhaps should assign unconditionally to cval? */
            case 0x09: /* FORM_block */     p += read_leb128U( &p ); break;
            case 0x0a: /* FORM_block1 */    p += *p + 1; break;
            case 0x0c: /* FORM_flag */      p++; break;
            case 0x0d: /* FORM_sdata */     read_leb128S( &p ); break;
            case 0x0f: /* FORM_udata */     read_leb128U( &p ); break;
            case 0x10: /* FORM_ref_addr */  p += ui->dw64 ? 8 : 4; break;
            case 0x11: /* FORM_ref1 */      p++; break;
            case 0x12: /* FORM_ref2 */      p += 2; break;
            case 0x13: /* FORM_ref4 */      p += 4; break;
            case 0x14: /* FORM_ref8 */      p += 8; break;
            case 0x15: /* FORM_ref_udata */ read_leb128U( &p ); break;
            
            default:
               VG_(printf)( "### unhandled dwarf2 abbrev form code 0x%x\n", form );
               break;
         }
         
         /* Now store the members we need in the UnitInfo structure */
         if ( tag == 0x0011 /*TAG_compile_unit*/ ) {
                 if ( name == 0x03 ) ui->name = sval;      /* DW_AT_name */
            else if ( name == 0x1b ) ui->compdir = sval;   /* DW_AT_compdir */
            else if ( name == 0x10 ) ui->stmt_list = cval; /* DW_AT_stmt_list */
         }
      }
      /* Shortcut the parsing once we have read the compile_unit block
       * That's enough info for us, and we are not gdb ! */
      if ( tag == 0x0011 /*TAG_compile_unit*/ )
         break;
   } /* Loop on each sub block */

   /* This test would be valid if we were not shortcutting the parsing
   if (level != 0)
      VG_(printf)( "#### Exiting debuginfo block at level %d !!!\n", level );
   */
}


////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////


/* Collect the debug info from dwarf2 debugging sections
 * of a given module.
 * 
 * Inputs: given .debug_xxx sections
 * Output: update si to contain all the dwarf2 debug infos
 */
void ML_(read_debuginfo_dwarf2) 
        ( struct _SegInfo* si, OffT debug_offset,
          UChar* debuginfo_img,   Int debug_info_sz, /* .debug_info */
          UChar* debugabbrev_img,                    /* .debug_abbrev */
          UChar* debugline_img,   Int debug_line_sz, /* .debug_line */
          UChar* debugstr_img )                      /* .debug_str */
{
   UnitInfo ui;
   UShort   ver;
   UChar*   block_img;
   UChar*   end_img = debuginfo_img + debug_info_sz;
   ULong    blklen;
   Bool     blklen_is_64;
   Int      blklen_len = 0;

   /* Make sure we at least have a header for the first block */
   if (debug_info_sz < 4) {
     ML_(symerr)( "Last block truncated in .debug_info; ignoring" );
      return;
   }

   /* Iterate on all the blocks we find in .debug_info */
   for ( block_img = debuginfo_img; block_img < end_img - 4; 
                                    block_img += blklen + blklen_len ) {

      /* Read the compilation unit header in .debug_info section - See
         p 70 */
      /* This block length */
      blklen     = read_initial_length_field( block_img, &blklen_is_64 );
      blklen_len = blklen_is_64 ? 12 : 4;
      if ( block_img + blklen + blklen_len > end_img ) {
         ML_(symerr)( "Last block truncated in .debug_info; ignoring" );
         return;
      }

      /* version should be 2 */
      ver = *((UShort*)( block_img + blklen_len ));
      if ( ver != 2 ) {
         ML_(symerr)( "Ignoring non-dwarf2 block in .debug_info" );
         continue;
      }
      
      /* Fill ui with offset in .debug_line and compdir */
      if (0)
         VG_(printf)( "Reading UnitInfo at 0x%x.....\n", 
                      block_img - debuginfo_img );
      read_unitinfo_dwarf2( &ui, block_img, debugabbrev_img, debugstr_img, si );
      if (0)
         VG_(printf)( "   => LINES=0x%llx    NAME=%s     DIR=%s\n", 
                      ui.stmt_list, ui.name, ui.compdir );
      
      /* Ignore blocks with no .debug_line associated block */
      if ( ui.stmt_list == -1LL )
         continue;
      
      if (0) 
         VG_(printf)("debug_line_sz %d, ui.stmt_list %lld  %s\n", 
                     debug_line_sz, ui.stmt_list, ui.name );
      /* Read the .debug_line block for this compile unit */
      read_dwarf2_lineblock( 
         si, debug_offset, &ui, debugline_img + ui.stmt_list, 
                                debug_line_sz - ui.stmt_list );
   }
}


////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////

/*------------------------------------------------------------*/
/*--- Read DWARF1 format line number info.                 ---*/
/*------------------------------------------------------------*/

/* DWARF1 appears to be redundant, but nevertheless the Lahey Fortran
   compiler generates it.
*/

/* The following three enums (dwarf_tag, dwarf_form, dwarf_attribute)
   are taken from the file include/elf/dwarf.h in the GNU gdb-6.0
   sources, which are Copyright 1992, 1993, 1995, 1999 Free Software
   Foundation, Inc and naturally licensed under the GNU General Public
   License version 2 or later. 
*/

/* Tag names and codes.  */

enum dwarf_tag {
    TAG_padding			= 0x0000,
    TAG_array_type		= 0x0001,
    TAG_class_type		= 0x0002,
    TAG_entry_point		= 0x0003,
    TAG_enumeration_type	= 0x0004,
    TAG_formal_parameter	= 0x0005,
    TAG_global_subroutine	= 0x0006,
    TAG_global_variable		= 0x0007,
    				/* 0x0008 -- reserved */
				/* 0x0009 -- reserved */
    TAG_label			= 0x000a,
    TAG_lexical_block		= 0x000b,
    TAG_local_variable		= 0x000c,
    TAG_member			= 0x000d,
				/* 0x000e -- reserved */
    TAG_pointer_type		= 0x000f,
    TAG_reference_type		= 0x0010,
    TAG_compile_unit		= 0x0011,
    TAG_string_type		= 0x0012,
    TAG_structure_type		= 0x0013,
    TAG_subroutine		= 0x0014,
    TAG_subroutine_type		= 0x0015,
    TAG_typedef			= 0x0016,
    TAG_union_type		= 0x0017,
    TAG_unspecified_parameters	= 0x0018,
    TAG_variant			= 0x0019,
    TAG_common_block		= 0x001a,
    TAG_common_inclusion	= 0x001b,
    TAG_inheritance		= 0x001c,
    TAG_inlined_subroutine	= 0x001d,
    TAG_module			= 0x001e,
    TAG_ptr_to_member_type	= 0x001f,
    TAG_set_type		= 0x0020,
    TAG_subrange_type		= 0x0021,
    TAG_with_stmt		= 0x0022,

    /* GNU extensions */

    TAG_format_label		= 0x8000,  /* for FORTRAN 77 and Fortran 90 */
    TAG_namelist		= 0x8001,  /* For Fortran 90 */
    TAG_function_template	= 0x8002,  /* for C++ */
    TAG_class_template		= 0x8003   /* for C++ */
};

/* Form names and codes.  */

enum dwarf_form {
    FORM_ADDR	= 0x1,
    FORM_REF	= 0x2,
    FORM_BLOCK2	= 0x3,
    FORM_BLOCK4	= 0x4,
    FORM_DATA2	= 0x5,
    FORM_DATA4	= 0x6,
    FORM_DATA8	= 0x7,
    FORM_STRING	= 0x8
};

/* Attribute names and codes.  */

enum dwarf_attribute {
    AT_sibling			= (0x0010|FORM_REF),
    AT_location			= (0x0020|FORM_BLOCK2),
    AT_name			= (0x0030|FORM_STRING),
    AT_fund_type		= (0x0050|FORM_DATA2),
    AT_mod_fund_type		= (0x0060|FORM_BLOCK2),
    AT_user_def_type		= (0x0070|FORM_REF),
    AT_mod_u_d_type		= (0x0080|FORM_BLOCK2),
    AT_ordering			= (0x0090|FORM_DATA2),
    AT_subscr_data		= (0x00a0|FORM_BLOCK2),
    AT_byte_size		= (0x00b0|FORM_DATA4),
    AT_bit_offset		= (0x00c0|FORM_DATA2),
    AT_bit_size			= (0x00d0|FORM_DATA4),
				/* (0x00e0|FORM_xxxx) -- reserved */
    AT_element_list		= (0x00f0|FORM_BLOCK4),
    AT_stmt_list		= (0x0100|FORM_DATA4),
    AT_low_pc			= (0x0110|FORM_ADDR),
    AT_high_pc			= (0x0120|FORM_ADDR),
    AT_language			= (0x0130|FORM_DATA4),
    AT_member			= (0x0140|FORM_REF),
    AT_discr			= (0x0150|FORM_REF),
    AT_discr_value		= (0x0160|FORM_BLOCK2),
				/* (0x0170|FORM_xxxx) -- reserved */
				/* (0x0180|FORM_xxxx) -- reserved */
    AT_string_length		= (0x0190|FORM_BLOCK2),
    AT_common_reference		= (0x01a0|FORM_REF),
    AT_comp_dir			= (0x01b0|FORM_STRING),
        AT_const_value_string	= (0x01c0|FORM_STRING),
        AT_const_value_data2	= (0x01c0|FORM_DATA2),
        AT_const_value_data4	= (0x01c0|FORM_DATA4),
        AT_const_value_data8	= (0x01c0|FORM_DATA8),
        AT_const_value_block2	= (0x01c0|FORM_BLOCK2),
        AT_const_value_block4	= (0x01c0|FORM_BLOCK4),
    AT_containing_type		= (0x01d0|FORM_REF),
        AT_default_value_addr	= (0x01e0|FORM_ADDR),
        AT_default_value_data2	= (0x01e0|FORM_DATA2),
        AT_default_value_data4	= (0x01e0|FORM_DATA4),
        AT_default_value_data8	= (0x01e0|FORM_DATA8),
        AT_default_value_string	= (0x01e0|FORM_STRING),
    AT_friends			= (0x01f0|FORM_BLOCK2),
    AT_inline			= (0x0200|FORM_STRING),
    AT_is_optional		= (0x0210|FORM_STRING),
        AT_lower_bound_ref	= (0x0220|FORM_REF),
        AT_lower_bound_data2	= (0x0220|FORM_DATA2),
        AT_lower_bound_data4	= (0x0220|FORM_DATA4),
        AT_lower_bound_data8	= (0x0220|FORM_DATA8),
    AT_private			= (0x0240|FORM_STRING),
    AT_producer			= (0x0250|FORM_STRING),
    AT_program			= (0x0230|FORM_STRING),
    AT_protected		= (0x0260|FORM_STRING),
    AT_prototyped		= (0x0270|FORM_STRING),
    AT_public			= (0x0280|FORM_STRING),
    AT_pure_virtual		= (0x0290|FORM_STRING),
    AT_return_addr		= (0x02a0|FORM_BLOCK2),
    AT_abstract_origin		= (0x02b0|FORM_REF),
    AT_start_scope		= (0x02c0|FORM_DATA4),
    AT_stride_size		= (0x02e0|FORM_DATA4),
        AT_upper_bound_ref	= (0x02f0|FORM_REF),
        AT_upper_bound_data2	= (0x02f0|FORM_DATA2),
        AT_upper_bound_data4	= (0x02f0|FORM_DATA4),
        AT_upper_bound_data8	= (0x02f0|FORM_DATA8),
    AT_virtual			= (0x0300|FORM_STRING),

    /* GNU extensions.  */

    AT_sf_names			= (0x8000|FORM_DATA4),
    AT_src_info			= (0x8010|FORM_DATA4),
    AT_mac_info			= (0x8020|FORM_DATA4),
    AT_src_coords		= (0x8030|FORM_DATA4),
    AT_body_begin		= (0x8040|FORM_ADDR),
    AT_body_end			= (0x8050|FORM_ADDR)
};

/* end of enums taken from gdb-6.0 sources */

void ML_(read_debuginfo_dwarf1) ( 
        struct _SegInfo* si, 
        UChar* dwarf1d, Int dwarf1d_sz, 
        UChar* dwarf1l, Int dwarf1l_sz )
{
   UInt   stmt_list;
   Bool   stmt_list_found;
   Int    die_offset, die_szb, at_offset;
   UShort die_kind, at_kind;
   UChar* at_base;
   UChar* src_filename;

   if (0) 
      VG_(printf)("read_debuginfo_dwarf1 ( %p, %d, %p, %d )\n",
	          dwarf1d, dwarf1d_sz, dwarf1l, dwarf1l_sz );

   /* This loop scans the DIEs. */
   die_offset = 0;
   while (True) {
      if (die_offset >= dwarf1d_sz) break;

      die_szb  = *(Int*)(dwarf1d + die_offset);
      die_kind = *(UShort*)(dwarf1d + die_offset + 4);

      /* We're only interested in compile_unit DIEs; ignore others. */
      if (die_kind != TAG_compile_unit) {
         die_offset += die_szb;
         continue; 
      }

      if (0) 
         VG_(printf)("compile-unit DIE: offset %d, tag 0x%x, size %d\n", 
                     die_offset, (Int)die_kind, die_szb );

      /* We've got a compile_unit DIE starting at (dwarf1d +
         die_offset+6).  Try and find the AT_name and AT_stmt_list
         attributes.  Then, finally, we can read the line number info
         for this source file. */

      /* The next 3 are set as we find the relevant attrs. */
      src_filename    = NULL;
      stmt_list_found = False;
      stmt_list       = 0;

      /* This loop scans the Attrs inside compile_unit DIEs. */
      at_base = dwarf1d + die_offset + 6;
      at_offset = 0;
      while (True) {
         if (at_offset >= die_szb-6) break;

         at_kind = *(UShort*)(at_base + at_offset);
         if (0) VG_(printf)("atoffset %d, attag 0x%x\n", 
                            at_offset, (Int)at_kind );
         at_offset += 2; /* step over the attribute itself */
	 /* We have to examine the attribute to figure out its
            length. */
         switch (at_kind) {
            case AT_stmt_list:
            case AT_language:
            case AT_sibling:
               if (at_kind == AT_stmt_list) {
                  stmt_list_found = True;
                  stmt_list = *(Int*)(at_base+at_offset);
               }
               at_offset += 4; break;
            case AT_high_pc:
            case AT_low_pc: 
               at_offset += sizeof(void*); break;
            case AT_name: 
            case AT_producer:
            case AT_comp_dir:
               /* Zero terminated string, step over it. */
               if (at_kind == AT_name)
                  src_filename = at_base + at_offset;
               while (at_offset < die_szb-6 && at_base[at_offset] != 0)
                  at_offset++;
               at_offset++;
               break;
            default: 
               VG_(printf)("Unhandled DWARF-1 attribute 0x%x\n", 
                           (Int)at_kind );
               VG_(core_panic)("Unhandled DWARF-1 attribute");
         } /* switch (at_kind) */
      } /* looping over attributes */

      /* So, did we find the required stuff for a line number table in
         this DIE?  If yes, read it. */
      if (stmt_list_found /* there is a line number table */
          && src_filename != NULL /* we know the source filename */
         ) {
         /* Table starts:
               Length: 
                  4 bytes, includes the entire table
               Base address: 
                  unclear (4? 8?), assuming native pointer size here.
            Then a sequence of triples
               (source line number -- 32 bits
                source line column -- 16 bits
                address delta -- 32 bits)
	 */
         Addr   base;
	 Int    len;
         Char*  curr_filenm;
         UChar* ptr;
         UInt   prev_line, prev_delta;

         curr_filenm = ML_(addStr) ( si, src_filename, -1 );
         prev_line = prev_delta = 0;

         ptr = dwarf1l + stmt_list;
         len  =        *(Int*)ptr;    ptr += sizeof(Int);
         base = (Addr)(*(void**)ptr); ptr += sizeof(void*);
         len -= (sizeof(Int) + sizeof(void*));
         while (len > 0) {
            UInt   line;
            UShort col;
            UInt   delta;
            line = *(UInt*)ptr;  ptr += sizeof(UInt);
            col = *(UShort*)ptr;  ptr += sizeof(UShort);
            delta = *(UShort*)ptr;  ptr += sizeof(UInt);
	    if (0) VG_(printf)("line %d, col %d, delta %d\n", 
                               line, (Int)col, delta );
            len -= (sizeof(UInt) + sizeof(UShort) + sizeof(UInt));

	    if (delta > 0 && prev_line > 0) {
	       if (0) VG_(printf) ("     %d  %d-%d\n",
                                   prev_line, prev_delta, delta-1);
	       ML_(addLineInfo) ( si, curr_filenm, NULL,
		 	          base + prev_delta, base + delta,
			          prev_line, 0 );
	    }
	    prev_line = line;
	    prev_delta = delta;
	 }        
      }  

      /* Move on the the next DIE. */
      die_offset += die_szb;

   } /* Looping over DIEs */

}


/*------------------------------------------------------------*/
/*--- Read call-frame info from an .eh_frame section       ---*/
/*------------------------------------------------------------*/

/* Sources of info:

   The DWARF3 spec, available from http://www.dwarfstd.org/Download.php 

   This describes how to read CFA data from .debug_frame sections.
   So as to maximise everybody's annoyance and confusion, .eh_frame
   sections are almost the same as .debug_frame sections, but differ
   in a few subtle and ill documented but important aspects.

   Generic ELF Specification, sections 7.5 (DWARF Extensions) and 7.6
   (Exception Frames), available from

   http://www.linux-foundation.org/spec/book/ELF-generic/ELF-generic.html

   This really does describe .eh_frame, at least the aspects that
   differ from standard DWARF3.  It's better than guessing, and
   (marginally) more fun than reading the gdb source code.
*/

/* Useful info ..

   In general:
   gdb-6.3/gdb/dwarf2-frame.c

   gdb-6.3/gdb/i386-tdep.c:

   DWARF2/GCC uses the stack address *before* the function call as a
   frame's CFA.  [jrs: I presume this means %esp before the call as
   the CFA]. 

   JRS: on amd64, the dwarf register numbering is, as per
   gdb-6.3/gdb/tdep-amd64.c and also amd64-abi-0.98.pdf:

      0    1    2    3    4    5    6    7
      RAX  RDX  RCX  RBX  RSI  RDI  RBP  RSP

      8  ...  15
      R8 ... R15

      16 is the return address (RIP)
      "The table defines Return Address to have a register number,
      even though the address is stored in 0(%rsp) and not in a 
      physical register."

      17   ...   24
      XMM0 ... XMM7

      25   ...    32
      XMM8 ... XMM15

      33   ...   40
      ST0  ...  ST7

      41   ...   48
      MM0  ...  MM7

      49                  RFLAGS
      50,51,52,53,54,55   ES,CS,SS,DS,FS,GS
      58                  FS.BASE  (what's that?)
      59                  GS.BASE  (what's that?)
      62                  TR (task register)
      63                  LDTR (LDT register)
      64                  MXCSR
      65                  FCW (x87 control word)
      66                  FSW (x86 status word)

   On x86 I cannot find any documentation.  It _appears_ to be the
   actual instruction encoding, viz:

      0    1    2    3    4    5    6    7
      EAX  ECX  EDX  EBX  ESP  EBP  ESI  EDI

      8 is the return address (EIP) */


/* Comments re DW_CFA_set_loc, 16 Nov 06.

   JRS:
   Someone recently sent me a libcrypto.so.0.9.8 as distributed with
   Ubuntu of some flavour, compiled with gcc 4.1.2 on amd64.  It
   causes V's CF reader to complain a lot:

   >> --19976-- DWARF2 CFI reader: unhandled CFI instruction 0:24
   >> --19976-- DWARF2 CFI reader: unhandled CFI instruction 0:24
   >> --19976-- DWARF2 CFI reader: unhandled CFI instruction 0:24
   >> --19976-- DWARF2 CFI reader: unhandled CFI instruction 0:24
   >> --19976-- DWARF2 CFI reader: unhandled CFI instruction 0:48
   >> --19976-- DWARF2 CFI reader: unhandled CFI instruction 0:24

   After chasing this around a bit it seems that the CF bytecode
   parser lost sync at a DW_CFA_set_loc, which has a single argument
   denoting an address.

   As it stands that address is extracted by read_Addr().  On amd64
   that just fetches 8 bytes regardless of anything else.

   read_encoded_Addr() is more sophisticated.  This appears to take
   into account some kind of encoding flag.  When I replace the uses
   of read_Addr by read_encoded_Addr for DW_CFA_set_loc, the
   complaints go away, there is no loss of sync, and the parsed CF
   instructions are the same as shown by readelf --debug-dump=frames.

   So it seems a plausible fix.  The problem is I looked in the DWARF3
   spec and completely failed to figure out whether or not the arg to
   DW_CFA_set_loc is supposed to be encoded in a way suitable for
   read_encoded_Addr, nor for that matter any description of what it
   is that read_encoded_Addr is really decoding.

   TomH:
   The problem is that the encoding is not standard - the eh_frame
   section uses the same encoding as the dwarf_frame section except
   for a few small changes, and this is one of them. So this is not
   something the DWARF standard covers.

   There is an augmentation string to indicate what is going on though
   so that programs can recognise it.

   What we are doing seems to match what gdb 6.5 and libdwarf 20060614
   do though. I'm not sure about readelf though.

   (later): Well dwarfdump barfs on it:

      dwarfdump ERROR:  dwarf_get_fde_info_for_reg:  
                        DW_DLE_DF_FRAME_DECODING_ERROR(193) (193)

   I've looked at binutils as well now, and the code in readelf agrees
   with your patch - ie it treats set_loc as having an encoded address
   if there is a zR augmentation indicating an encoding.

   Quite why gdb and libdwarf don't understand this is an interesting
   question...

   Final outcome: all uses of read_Addr were replaced by
   read_encoded_Addr.  A new type AddressDecodingInfo was added to
   make it relatively clean to plumb through the extra info needed by
   read_encoded_Addr.
*/

/* More badness re address encoding, 12 Jan 07.

   Most gcc provided CIEs have a "zR" augmentation, which means they
   supply their own address encoding, and that works fine.  However,
   some icc9 supplied CIEs have no augmentation, which means they use
   the default_Addr_encoding().  That says to use a machine-word sized
   value, literally unmodified.

   Since .so's are, in general, relocated when loaded, having absolute
   addresses in the CFI data makes no sense when read_encoded_Addr is
   used to find the initial location for a FDE.  The resulting saga:

   TomH:
   > I'm chasing a stack backtrace failure for an amd64 .so which was 
   > created I believe by icc 9.1.  After a while I wound up looking at
   > this: (readdwarf.c)
   >
   >   5083        tom static UChar default_Addr_encoding ( void )
   >   3584        tom {
   >   3584        tom    switch (sizeof(Addr)) {
   >   3584        tom       case 4: return DW_EH_PE_udata4;
   >   3584        tom       case 8: return DW_EH_PE_udata8;
   >   3584        tom       default: vg_assert(0);
   >   3584        tom    }
   >   3584        tom }
   >
   > If a CIE does not have an "augmentation string" (typically "zR") then 
   > addresses are decoded as described by default_Addr_encoding.  If there
   > is an 'R' in the augmentation string then the encoding to use 
   > is specified by the CIE itself, which works fine with GCC compiled code
   > since that always appears to specify zR.

   Correct.

   > Problem is this .so has no augmentation string and so uses the
   > default encoding, viz DW_EH_PE_udata8.  That appears to mean
   > "read a 64 bit number" and use that as-is (for the starting value
   > of the program counter when running the CFA program).

   Strictly speaking the default is DW_EH_PE_absptr, but that amounts
   to either udata4 or udata8 depending on the platform's pointer size
   which is a shortcut I used.

   > For this .so that gives nonsense (very small) PCs which are later
   > rejected by the sanity check which ensures PC ranges fall inside
   > the mapped text segment.  It seems like the .so expects to have the
   > start VMA of the text segment added on.  This would correspond to
   >
   >   static UChar default_Addr_encoding ( void )
   >   {
   >      switch (sizeof(Addr)) {
   >         case 4: return DW_EH_PE_textrel + DW_EH_PE_udata4;
   >         case 8: return DW_EH_PE_textrel + DW_EH_PE_udata8;
   >         default: vg_assert(0);
   >      }
   >   }

   The problem you're seeing is that you have absolute pointers inside
   a shared library, which obviously makes little sense on the face of
   things as how would the linker know where the library will be
   loaded?

   The answer of course is that it doesn't, so if it points absolute
   pointers in the frame unwind data is has to include relocations for
   them, and I'm betting that if you look at the relocations in the
   library you will there are some for that data.

   That is fine of course when ld.so maps the library - it will
   relocate the eh_frame data as it maps it (or prelinking will
   already have done so) and when the g++ exception code kicks in and
   unwinds the stack it will see relocated data.

   We of course are mapping the section from the ELF file ourselves
   and are not applying the relocations, hence the problem you are
   seeing.

   Strictly speaking we should apply the relocations but the cheap
   solution is essentially to do what you've done - strictly speaking
   you should adjust by the difference between the address the library
   was linked for and the address it has been loaded at, but a shared
   library will normally be linked for address zero I believe. It's
   possible that prelinking might change that though?

   JRS:
   That all syncs with what I am seeing.

   So what I am inclined to do is:

   - Leave default_Addr_encoding as it is

   - Change read_encoded_Addr's handling of "case DW_EH_PE_absptr" so
     it sets base to, as you say, the difference between the address
     the library was linked for and the address it has been loaded at
     (== the SegInfo's text_bias)

   Does that sound sane?  I think it should even handle the prelinked
   case.

   (JRS, later)

   Hmm.  Plausible as it sounds, it doesn't work.  It now produces
   bogus backtraces for locations inside the (statically linked)
   memcheck executable.

   Besides, there are a couple of other places where read_encoded_Addr
   is used -- one of which is used to establish the length of the
   address range covered by the current FDE:

         fde_arange = read_encoded_Addr(&nbytes, &adi, data);

   and it doesn't seem to make any sense for read_encoded_Addr to add
   on the text segment bias in that context.  The DWARF3 spec says
   that both the initial_location and address_range (length) fields
   are encoded the same way ("target address"), so it is unclear at
   what stage in the process it would be appropriate to relocate the
   former but not the latter.

   One unprincipled kludge that does work is the following: just
   before handing one of the address range fragments off to
   ML_(addDiCfSI) for permanent storage, check its start address.  If
   that is very low (less than 2 M), and is far below the mapped text
   segment, and adding the text bias would move the fragment entirely
   inside the mapped text segment, then do so.  A kind of kludged
   last-minute relocation, if you like.

   12 Jan 07: committing said kludge (see kludge_then_addDiCfSI).  If
   the situation clarifies, it can easily enough be backed out and
   replaced by a better fix.
*/

/* --------------- Decls --------------- */

#if defined(VGP_x86_linux)
#  define FP_REG         5
#  define SP_REG         4
#  define RA_REG_DEFAULT 8
#elif defined(VGP_amd64_linux)
#  define FP_REG         6
#  define SP_REG         7
#  define RA_REG_DEFAULT 16
#elif defined(VGP_ppc32_linux)
#  define FP_REG         1
#  define SP_REG         1
#  define RA_REG_DEFAULT 8     // CAB: What's a good default ?
#elif defined(VGP_ppc64_linux)
#  define FP_REG         1
#  define SP_REG         1
#  define RA_REG_DEFAULT 8     // CAB: What's a good default ?
#else
#  error Unknown platform
#endif

/* the number of regs we are prepared to unwind */
#define N_CFI_REGS 20

/* Instructions for the automaton */
enum dwarf_cfa_primary_ops
  {
    DW_CFA_use_secondary = 0,
    DW_CFA_advance_loc   = 1,
    DW_CFA_offset        = 2,
    DW_CFA_restore       = 3
  };

enum dwarf_cfa_secondary_ops
  {
    DW_CFA_nop                = 0x00,
    DW_CFA_set_loc            = 0x01,
    DW_CFA_advance_loc1       = 0x02,
    DW_CFA_advance_loc2       = 0x03,
    DW_CFA_advance_loc4       = 0x04,
    DW_CFA_offset_extended    = 0x05,
    DW_CFA_restore_extended   = 0x06,
    DW_CFA_undefined          = 0x07,
    DW_CFA_same_value         = 0x08,
    DW_CFA_register           = 0x09,
    DW_CFA_remember_state     = 0x0a,
    DW_CFA_restore_state      = 0x0b,
    DW_CFA_def_cfa            = 0x0c,
    DW_CFA_def_cfa_register   = 0x0d,
    DW_CFA_def_cfa_offset     = 0x0e,
    DW_CFA_def_cfa_expression = 0x0f, /* DWARF3 only */
    DW_CFA_expression         = 0x10, /* DWARF3 only */
    DW_CFA_offset_extended_sf = 0x11, /* DWARF3 only */
    DW_CFA_def_cfa_sf         = 0x12, /* DWARF3 only */
    DW_CFA_def_cfa_offset_sf  = 0x13, /* DWARF3 only */
    DW_CFA_val_offset         = 0x14, /* DWARF3 only */
    DW_CFA_val_offset_sf      = 0x15, /* DWARF3 only */
    DW_CFA_val_expression     = 0x16, /* DWARF3 only */
    DW_CFA_lo_user            = 0x1c,
    DW_CFA_GNU_window_save    = 0x2d, /* GNU extension */
    DW_CFA_GNU_args_size      = 0x2e, /* GNU extension */
    DW_CFA_GNU_negative_offset_extended = 0x2f, /* GNU extension */
    DW_CFA_hi_user            = 0x3f
  };

#define DW_EH_PE_absptr		0x00
#define DW_EH_PE_omit		0xff

#define DW_EH_PE_uleb128	0x01
#define DW_EH_PE_udata2		0x02
#define DW_EH_PE_udata4		0x03
#define DW_EH_PE_udata8		0x04
#define DW_EH_PE_sleb128	0x09
#define DW_EH_PE_sdata2		0x0A
#define DW_EH_PE_sdata4		0x0B
#define DW_EH_PE_sdata8		0x0C
#define DW_EH_PE_signed		0x08

#define DW_EH_PE_pcrel		0x10
#define DW_EH_PE_textrel	0x20
#define DW_EH_PE_datarel	0x30
#define DW_EH_PE_funcrel	0x40
#define DW_EH_PE_aligned	0x50

#define DW_EH_PE_indirect	0x80


/* RegRule and UnwindContext are used temporarily to do the unwinding.
   The result is then summarised into a sequence of CfiSIs, if
   possible.  UnwindContext effectively holds the state of the
   abstract machine whilst it is running.

   The CFA can either be a signed offset from a register,
   or an expression:

   CFA = cfa_reg + cfa_off   when UnwindContext.cfa_is_regoff==True
       | [[ cfa_expr_id ]]

   When .cfa_is_regoff == True,  cfa_expr_id must be zero
   When .cfa_is_regoff == False, cfa_reg must be zero
                                 and cfa_off must be zero

   RegRule describes, for each register, how to get its
   value in the previous frame, where 'cfa' denotes the cfa
   for the frame as a whole:

   RegRule = RR_Undef          -- undefined
           | RR_Same           -- same as in previous frame
           | RR_CFAOff    arg  -- is at * ( cfa + arg )
           | RR_CFAValOff arg  -- is ( cfa + arg )
           | RR_Reg       arg  -- is in register 'arg' 
           | RR_Expr      arg  -- is at * [[ arg ]]
           | RR_ValExpr   arg  -- is [[ arg ]]
           | RR_Arch           -- dunno

   Note that RR_Expr is redundant since the same can be represented
   using RR_ValExpr with an explicit dereference (CfiExpr_Deref) at
   the outermost level.

   All expressions are stored in exprs in the containing
   UnwindContext.  Since the UnwindContext gets reinitialised for each
   new FDE, summarise_context needs to copy out any expressions it
   wants to keep into the cfsi_exprs field of the containing SegInfo.
*/
typedef
   struct {
      enum { RR_Undef, RR_Same, RR_CFAOff, RR_CFAValOff, 
             RR_Reg, /*RR_Expr,*/ RR_ValExpr, RR_Arch } tag;
      /* meaning:  int offset for CFAoff/CFAValOff
                   reg # for Reg
                   expr index for Expr/ValExpr */
      Int arg;
   }
   RegRule;

static void ppRegRule ( XArray* exprs, RegRule* rrule )
{
   vg_assert(exprs);
   switch (rrule->tag) {
      case RR_Undef:     VG_(printf)("u  "); break;
      case RR_Same:      VG_(printf)("s  "); break;
      case RR_CFAOff:    VG_(printf)("c%d ", rrule->arg); break;
      case RR_CFAValOff: VG_(printf)("v%d ", rrule->arg); break;
      case RR_Reg:       VG_(printf)("r%d ", rrule->arg); break;
      case RR_ValExpr:   VG_(printf)("ve{"); 
                         ML_(ppCfiExpr)( exprs, rrule->arg ); 
                         VG_(printf)("} "); 
                         break;
      case RR_Arch:      VG_(printf)("a  "); break;
      default:           VG_(core_panic)("ppRegRule");
   }
}


typedef
   struct {
      /* Read-only fields (set by the CIE) */
      Int     code_a_f;
      Int     data_a_f;
      Addr    initloc;
      Int     ra_reg;
      /* The rest of these fields can be modifed by
         run_CF_instruction. */
      /* The LOC entry */
      Addr    loc;
      /* The CFA entry.  This can be either reg+/-offset or an expr. */
      Bool    cfa_is_regoff; /* True=>is reg+offset; False=>is expr */
      Int     cfa_reg;
      Int     cfa_off;  /* in bytes */
      Int     cfa_expr_ix; /* index into cfa_exprs */
      /* register unwind rules */
      RegRule reg[N_CFI_REGS];
      /* array of CfiExpr, shared by reg[] and cfa_expr_ix */
      XArray* exprs;
   }
   UnwindContext;

static void ppUnwindContext ( UnwindContext* ctx )
{
   Int i;
   VG_(printf)("0x%llx: ", (ULong)ctx->loc);
   if (ctx->cfa_is_regoff) {
      VG_(printf)("%d(r%d) ",  ctx->cfa_off, ctx->cfa_reg);
   } else {
      vg_assert(ctx->exprs);
      VG_(printf)("{");
      ML_(ppCfiExpr)( ctx->exprs, ctx->cfa_expr_ix );
      VG_(printf)("} ");
   }
   for (i = 0; i < N_CFI_REGS; i++)
      ppRegRule(ctx->exprs, &ctx->reg[i]);
   VG_(printf)("\n");
}

static void* symtab_alloc ( SizeT szB ) {
   return VG_(arena_malloc)( VG_AR_SYMTAB, szB );
}
static void symtab_free ( void* v ) {
   VG_(arena_free)( VG_AR_SYMTAB, v );
}

static void initUnwindContext ( /*OUT*/UnwindContext* ctx )
{
   Int i;
   ctx->code_a_f      = 0;
   ctx->data_a_f      = 0;
   ctx->initloc       = 0;
   ctx->ra_reg        = RA_REG_DEFAULT;
   ctx->loc           = 0;
   ctx->cfa_is_regoff = True;
   ctx->cfa_reg       = 0;
   ctx->cfa_off       = 0;
   ctx->cfa_expr_ix   = 0;
   ctx->exprs         = NULL;
   for (i = 0; i < N_CFI_REGS; i++) {
      ctx->reg[i].tag = RR_Undef;
      ctx->reg[i].arg = 0;
   }
}


/* A structure which holds information needed by read_encoded_Addr(). 
*/
typedef
   struct {
      UChar  encoding;
      UChar* ehframe_image;
      Addr   ehframe_avma;
      Addr   text_bias;
   }
   AddressDecodingInfo;


/* ------------ Deal with summary-info records ------------ */

static void initCfiSI ( DiCfSI* si )
{
   si->base    = 0;
   si->len     = 0;
   si->cfa_how = 0;
   si->ra_how  = 0;
   si->sp_how  = 0;
   si->fp_how  = 0;
   si->cfa_off = 0;
   si->ra_off  = 0;
   si->sp_off  = 0;
   si->fp_off  = 0;
}


/* --------------- Summarisation --------------- */

/* Forward */
static 
Int copy_convert_CfiExpr_tree ( XArray*        dst,
                                UnwindContext* srcuc, 
                                Int            nd );

/* Summarise ctx into si, if possible.  Returns True if successful.
   This is taken to be just after ctx's loc advances; hence the
   summary is up to but not including the current loc.  This works
   on both x86 and amd64.
*/
static Bool summarise_context( /*OUT*/DiCfSI* si,
                               Addr loc_start,
	                       UnwindContext* ctx,
                               struct _SegInfo* seginfo )
{
   Int why = 0;
   initCfiSI(si);

   /* How to generate the CFA */
   if (!ctx->cfa_is_regoff) {
      /* it was set by DW_CFA_def_cfa_expression; try to convert */
      XArray *src, *dst;
      Int    conv;
      src = ctx->exprs;
      dst = seginfo->cfsi_exprs;
      if (src && (VG_(sizeXA)(src) > 0) && (!dst)) {
         dst = VG_(newXA)( symtab_alloc, symtab_free,
                           sizeof(CfiExpr) );
         vg_assert(dst);
         seginfo->cfsi_exprs = dst;
      }
      conv = copy_convert_CfiExpr_tree
                    ( dst, ctx, ctx->cfa_expr_ix );
      vg_assert(conv >= -1);
      if (conv == -1) { why = 6; goto failed; }
      si->cfa_how = CFIC_EXPR;
      si->cfa_off = conv;
      if (0 && seginfo->ddump_frames)
         ML_(ppCfiExpr)(dst, conv);
   } else
   if (ctx->cfa_is_regoff && ctx->cfa_reg == SP_REG) {
      si->cfa_how = CFIC_SPREL;
      si->cfa_off = ctx->cfa_off;
   } else
   if (ctx->cfa_is_regoff && ctx->cfa_reg == FP_REG) {
      si->cfa_how = CFIC_FPREL;
      si->cfa_off = ctx->cfa_off;
   } else {
      why = 1;
      goto failed;
   }

#  define SUMMARISE_HOW(_how, _off, _ctxreg)                  \
   switch (_ctxreg.tag) {                                     \
      case RR_Undef:                                          \
         _how = CFIR_UNKNOWN;   _off = 0; break;              \
      case RR_Same:                                           \
         _how = CFIR_SAME;      _off = 0; break;              \
      case RR_CFAOff:                                         \
         _how = CFIR_MEMCFAREL; _off = _ctxreg.arg; break;    \
      case RR_CFAValOff:                                      \
         _how = CFIR_CFAREL;    _off = _ctxreg.arg; break;    \
      case RR_ValExpr: {                                      \
         XArray *src, *dst;                                   \
         Int    conv;                                         \
         src = ctx->exprs;                                    \
         dst = seginfo->cfsi_exprs;                           \
         if (src && (VG_(sizeXA)(src) > 0) && (!dst)) {       \
            dst = VG_(newXA)( symtab_alloc, symtab_free,      \
                              sizeof(CfiExpr) );              \
            vg_assert(dst);                                   \
            seginfo->cfsi_exprs = dst;                        \
         }                                                    \
         conv = copy_convert_CfiExpr_tree                     \
                       ( dst, ctx, _ctxreg.arg );             \
         vg_assert(conv >= -1);                               \
         if (conv == -1) { why = 7; goto failed; }            \
         _how = CFIR_EXPR;                                    \
         _off = conv;                                         \
         if (0 && seginfo->ddump_frames)                      \
            ML_(ppCfiExpr)(dst, conv);                        \
         break;                                               \
      }                                                       \
      default:                                                \
         why = 2; goto failed; /* otherwise give up */        \
   }

   SUMMARISE_HOW(si->ra_how, si->ra_off, ctx->reg[ctx->ra_reg] );
   SUMMARISE_HOW(si->fp_how, si->fp_off, ctx->reg[FP_REG] );

#  undef SUMMARISE_HOW

   /* on x86/amd64, it seems the old %{e,r}sp value before the call is
      always the same as the CFA.  Therefore ... */
   si->sp_how = CFIR_CFAREL;
   si->sp_off = 0;

   /* also, gcc says "Undef" for %{e,r}bp when it is unchanged.  So
      .. */
   if (ctx->reg[FP_REG].tag == RR_Undef)
      si->fp_how = CFIR_SAME;

   /* knock out some obviously stupid cases */
   if (si->ra_how == CFIR_SAME) 
      { why = 3; goto failed; }

   /* bogus looking range?  Note, we require that the difference is
      representable in 32 bits. */
   if (loc_start >= ctx->loc) 
      { why = 4; goto failed; }
   if (ctx->loc - loc_start > 10000000 /* let's say */)
      { why = 5; goto failed; }

   si->base = loc_start + ctx->initloc;
   si->len  = (UInt)(ctx->loc - loc_start);

   return True;

  failed:
   if (VG_(clo_verbosity) > 2 || seginfo->trace_cfi) {
      VG_(message)(Vg_DebugMsg,
                  "summarise_context(loc_start = %p)"
                  ": cannot summarise(why=%d):   ", loc_start, why);
      ppUnwindContext(ctx);
   }
   return False;
}

/* Copy the tree rooted at srcuc->exprs node srcix to dstxa, on the
   way converting any DwReg regs (regs numbered using the Dwarf scheme
   defined by each architecture's ABI) into CfiRegs, which are
   platform independent.  If the conversion isn't possible because
   there is no equivalent register, return -1.  This has the
   undesirable side effect of de-dagifying the input; oh well. */
static Int copy_convert_CfiExpr_tree ( XArray*        dstxa,
                                       UnwindContext* srcuc, 
                                       Int            srcix )
{
   CfiExpr* src;
   Int      cpL, cpR, cpA, dwreg;
   XArray*  srcxa = srcuc->exprs;
   vg_assert(srcxa);
   vg_assert(dstxa);
   vg_assert(srcix >= 0 && srcix < VG_(sizeXA)(srcxa));

   src = VG_(indexXA)( srcxa, srcix );
   switch (src->tag) {
      case Cex_Undef:
         return ML_(CfiExpr_Undef)( dstxa );
      case Cex_Deref:
         cpA = copy_convert_CfiExpr_tree( dstxa, srcuc, src->Cex.Deref.ixAddr );
         if (cpA == -1)
            return -1; /* propagate failure */
         return ML_(CfiExpr_Deref)( dstxa, cpA );
      case Cex_Const:
         return ML_(CfiExpr_Const)( dstxa, src->Cex.Const.con );
      case Cex_Binop:
         cpL = copy_convert_CfiExpr_tree( dstxa, srcuc, src->Cex.Binop.ixL );
         cpR = copy_convert_CfiExpr_tree( dstxa, srcuc, src->Cex.Binop.ixR );
         vg_assert(cpL >= -1 && cpR >= -1);
         if (cpL == -1 || cpR == -1)
            return -1; /* propagate failure */
         return ML_(CfiExpr_Binop)( dstxa, src->Cex.Binop.op, cpL, cpR );
      case Cex_CfiReg:
         /* should not see these in input (are created only by this
            conversion step!) */
         VG_(core_panic)("copy_convert_CfiExpr_tree: CfiReg in input");
      case Cex_DwReg:
         /* This is the only place where the conversion can fail. */
         dwreg = src->Cex.DwReg.reg;
         if (dwreg == SP_REG)
            return ML_(CfiExpr_CfiReg)( dstxa, Creg_SP );
         if (dwreg == FP_REG)
            return ML_(CfiExpr_CfiReg)( dstxa, Creg_FP );
         if (dwreg == srcuc->ra_reg)
            return ML_(CfiExpr_CfiReg)( dstxa, Creg_IP ); /* correct? */
         /* else we must fail - can't represent the reg */
         return -1;
      default:
         VG_(core_panic)("copy_convert_CfiExpr_tree: default");
   }
}


static void ppUnwindContext_summary ( UnwindContext* ctx )
{
   VG_(printf)("0x%llx-1: ", (ULong)ctx->loc);

   if (ctx->cfa_reg == SP_REG) {
      VG_(printf)("SP/CFA=%d+SP   ", ctx->cfa_off);
   } else
   if (ctx->cfa_reg == FP_REG) {
      VG_(printf)("SP/CFA=%d+FP   ", ctx->cfa_off);
   } else {
      VG_(printf)("SP/CFA=unknown  ", ctx->cfa_off);
   }

   VG_(printf)("RA=");
   ppRegRule( ctx->exprs, &ctx->reg[ctx->ra_reg] );

   VG_(printf)("FP=");
   ppRegRule( ctx->exprs, &ctx->reg[FP_REG] );
   VG_(printf)("\n");
}


/* ------------ Pick apart DWARF2 byte streams ------------ */

static inline Bool host_is_little_endian ( void )
{
   UInt x = 0x76543210;
   UChar* p = (UChar*)(&x);
   return toBool(*p == 0x10);
}

static Short read_Short ( UChar* data )
{
   Short r = 0;
   vg_assert(host_is_little_endian());
   r = data[0] 
       | ( ((UInt)data[1]) << 8 );
   return r;
}

static Int read_Int ( UChar* data )
{
   Int r = 0;
   vg_assert(host_is_little_endian());
   r = data[0] 
       | ( ((UInt)data[1]) << 8 ) 
       | ( ((UInt)data[2]) << 16 ) 
       | ( ((UInt)data[3]) << 24 );
   return r;
}

static Long read_Long ( UChar* data )
{
   Long r = 0;
   vg_assert(host_is_little_endian());
   r = data[0] 
       | ( ((ULong)data[1]) << 8 ) 
       | ( ((ULong)data[2]) << 16 ) 
       | ( ((ULong)data[3]) << 24 )
       | ( ((ULong)data[4]) << 32 ) 
       | ( ((ULong)data[5]) << 40 ) 
       | ( ((ULong)data[6]) << 48 ) 
       | ( ((ULong)data[7]) << 56 );
   return r;
}

static UShort read_UShort ( UChar* data )
{
   UInt r = 0;
   vg_assert(host_is_little_endian());
   r = data[0] 
       | ( ((UInt)data[1]) << 8 );
   return r;
}

static UInt read_UInt ( UChar* data )
{
   UInt r = 0;
   vg_assert(host_is_little_endian());
   r = data[0] 
       | ( ((UInt)data[1]) << 8 ) 
       | ( ((UInt)data[2]) << 16 ) 
       | ( ((UInt)data[3]) << 24 );
   return r;
}

static ULong read_ULong ( UChar* data )
{
   ULong r = 0;
   vg_assert(host_is_little_endian());
   r = data[0] 
       | ( ((ULong)data[1]) << 8 ) 
       | ( ((ULong)data[2]) << 16 ) 
       | ( ((ULong)data[3]) << 24 )
       | ( ((ULong)data[4]) << 32 ) 
       | ( ((ULong)data[5]) << 40 ) 
       | ( ((ULong)data[6]) << 48 ) 
       | ( ((ULong)data[7]) << 56 );
   return r;
}

static UChar read_UChar ( UChar* data )
{
   return data[0];
}

static ULong read_le_u_encoded_literal ( UChar* data, UInt size )
{
   switch (size) {
      case 8:  return (ULong)read_ULong( data );
      case 4:  return (ULong)read_UInt( data );
      case 2:  return (ULong)read_UShort( data );
      case 1:  return (ULong)read_UChar( data );
      default: vg_assert(0); /*NOTREACHED*/ return 0;
   }
}

static Long read_le_s_encoded_literal ( UChar* data, UInt size )
{
   Long s64 = read_le_u_encoded_literal( data, size );
   switch (size) {
      case 8:  break;
      case 4:  s64 <<= 32; s64 >>= 32; break;
      case 2:  s64 <<= 48; s64 >>= 48; break;
      case 1:  s64 <<= 56; s64 >>= 56; break;
      default: vg_assert(0); /*NOTREACHED*/ return 0;
   }
   return s64;
}

static UChar default_Addr_encoding ( void )
{
   switch (sizeof(Addr)) {
      case 4: return DW_EH_PE_udata4;
      case 8: return DW_EH_PE_udata8;
      default: vg_assert(0);
   }
}

static UInt size_of_encoded_Addr ( UChar encoding )
{
   if (encoding == DW_EH_PE_omit)
      return 0;

   switch (encoding & 0x07) {
      case DW_EH_PE_absptr: return sizeof(Addr);
      case DW_EH_PE_udata2: return sizeof(UShort);
      case DW_EH_PE_udata4: return sizeof(UInt);
      case DW_EH_PE_udata8: return sizeof(ULong);
      default: vg_assert(0);
   }
}

static Addr read_encoded_Addr ( /*OUT*/Int* nbytes,
                                AddressDecodingInfo* adi,
                                UChar* data )
{
   /* Regarding the handling of DW_EH_PE_absptr.  DWARF3 says this
      denotes an absolute address, hence you would think 'base' is
      zero.  However, that is nonsensical (unless relocations are to
      be applied to the unwind data before reading it, which sounds
      unlikely).  My interpretation is that DW_EH_PE_absptr indicates
      an address relative to where the object was loaded (technically,
      relative to its stated load VMA, hence the use of text_bias
      rather than text_avma).  Hmm, should we use text_bias or
      text_avma here?  Not sure.

      This view appears to be supported by DWARF3 spec sec 7.3
      "Executable Objects and Shared Objects":

         This requirement makes the debugging information for shared
         objects position independent.  Virtual addresses in a shared
         object may be calculated by adding the offset to the base
         address at which the object was attached.  This offset is
         available in the run-time linker's data structures.
   */
   Addr   base;
   Word   offset;
   UChar  encoding      = adi->encoding;
   UChar* ehframe_image = adi->ehframe_image;
   Addr   ehframe_avma  = adi->ehframe_avma;

   vg_assert((encoding & DW_EH_PE_indirect) == 0);

   *nbytes = 0;

   switch (encoding & 0x70) {
      case DW_EH_PE_absptr:
         base = adi->text_bias;
         break;
      case DW_EH_PE_pcrel:
         base = ehframe_avma + ( data - ehframe_image );
         break;
      case DW_EH_PE_datarel:
         vg_assert(0);
         base = /* data base address */ 0;
         break;
      case DW_EH_PE_textrel:
         vg_assert(0);
         base = /* text base address */ 0;
         break;
      case DW_EH_PE_funcrel:
         base = 0;
         break;
      case DW_EH_PE_aligned:
         base = 0;
         offset = data - ehframe_image;
         if ((offset % sizeof(Addr)) != 0) {
            *nbytes = sizeof(Addr) - (offset % sizeof(Addr));
            data += *nbytes;
         }
         break;
      default:
         vg_assert(0);
   }

   if ((encoding & 0x07) == 0x00)
      encoding |= default_Addr_encoding();

   switch (encoding & 0x0f) {
      case DW_EH_PE_udata2:
         *nbytes += sizeof(UShort);
         return base + read_UShort(data);
      case DW_EH_PE_udata4:
         *nbytes += sizeof(UInt);
         return base + read_UInt(data);
      case DW_EH_PE_udata8:
         *nbytes += sizeof(ULong);
         return base + read_ULong(data);
      case DW_EH_PE_sdata2:
         *nbytes += sizeof(Short);
         return base + read_Short(data);
      case DW_EH_PE_sdata4:
         *nbytes += sizeof(Int);
         return base + read_Int(data);
      case DW_EH_PE_sdata8:
         *nbytes += sizeof(Long);
         return base + read_Long(data);
      default:
         vg_assert2(0, "read encoded address %d\n", encoding & 0x0f);
   }
}


/* ------------ Run/show DWARF3 expressions ---------- */

/* Taken from binutils-2.17/include/elf/dwarf2.h */
enum dwarf_location_atom
  {
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
    DW_OP_bra = 0x28,
    DW_OP_eq = 0x29,
    DW_OP_ge = 0x2a,
    DW_OP_gt = 0x2b,
    DW_OP_le = 0x2c,
    DW_OP_lt = 0x2d,
    DW_OP_ne = 0x2e,
    DW_OP_skip = 0x2f,
    DW_OP_lit0 = 0x30,
    DW_OP_lit1 = 0x31,
    DW_OP_lit2 = 0x32,
    DW_OP_lit3 = 0x33,
    DW_OP_lit4 = 0x34,
    DW_OP_lit5 = 0x35,
    DW_OP_lit6 = 0x36,
    DW_OP_lit7 = 0x37,
    DW_OP_lit8 = 0x38,
    DW_OP_lit9 = 0x39,
    DW_OP_lit10 = 0x3a,
    DW_OP_lit11 = 0x3b,
    DW_OP_lit12 = 0x3c,
    DW_OP_lit13 = 0x3d,
    DW_OP_lit14 = 0x3e,
    DW_OP_lit15 = 0x3f,
    DW_OP_lit16 = 0x40,
    DW_OP_lit17 = 0x41,
    DW_OP_lit18 = 0x42,
    DW_OP_lit19 = 0x43,
    DW_OP_lit20 = 0x44,
    DW_OP_lit21 = 0x45,
    DW_OP_lit22 = 0x46,
    DW_OP_lit23 = 0x47,
    DW_OP_lit24 = 0x48,
    DW_OP_lit25 = 0x49,
    DW_OP_lit26 = 0x4a,
    DW_OP_lit27 = 0x4b,
    DW_OP_lit28 = 0x4c,
    DW_OP_lit29 = 0x4d,
    DW_OP_lit30 = 0x4e,
    DW_OP_lit31 = 0x4f,
    DW_OP_reg0 = 0x50,
    DW_OP_reg1 = 0x51,
    DW_OP_reg2 = 0x52,
    DW_OP_reg3 = 0x53,
    DW_OP_reg4 = 0x54,
    DW_OP_reg5 = 0x55,
    DW_OP_reg6 = 0x56,
    DW_OP_reg7 = 0x57,
    DW_OP_reg8 = 0x58,
    DW_OP_reg9 = 0x59,
    DW_OP_reg10 = 0x5a,
    DW_OP_reg11 = 0x5b,
    DW_OP_reg12 = 0x5c,
    DW_OP_reg13 = 0x5d,
    DW_OP_reg14 = 0x5e,
    DW_OP_reg15 = 0x5f,
    DW_OP_reg16 = 0x60,
    DW_OP_reg17 = 0x61,
    DW_OP_reg18 = 0x62,
    DW_OP_reg19 = 0x63,
    DW_OP_reg20 = 0x64,
    DW_OP_reg21 = 0x65,
    DW_OP_reg22 = 0x66,
    DW_OP_reg23 = 0x67,
    DW_OP_reg24 = 0x68,
    DW_OP_reg25 = 0x69,
    DW_OP_reg26 = 0x6a,
    DW_OP_reg27 = 0x6b,
    DW_OP_reg28 = 0x6c,
    DW_OP_reg29 = 0x6d,
    DW_OP_reg30 = 0x6e,
    DW_OP_reg31 = 0x6f,
    DW_OP_breg0 = 0x70,
    DW_OP_breg1 = 0x71,
    DW_OP_breg2 = 0x72,
    DW_OP_breg3 = 0x73,
    DW_OP_breg4 = 0x74,
    DW_OP_breg5 = 0x75,
    DW_OP_breg6 = 0x76,
    DW_OP_breg7 = 0x77,
    DW_OP_breg8 = 0x78,
    DW_OP_breg9 = 0x79,
    DW_OP_breg10 = 0x7a,
    DW_OP_breg11 = 0x7b,
    DW_OP_breg12 = 0x7c,
    DW_OP_breg13 = 0x7d,
    DW_OP_breg14 = 0x7e,
    DW_OP_breg15 = 0x7f,
    DW_OP_breg16 = 0x80,
    DW_OP_breg17 = 0x81,
    DW_OP_breg18 = 0x82,
    DW_OP_breg19 = 0x83,
    DW_OP_breg20 = 0x84,
    DW_OP_breg21 = 0x85,
    DW_OP_breg22 = 0x86,
    DW_OP_breg23 = 0x87,
    DW_OP_breg24 = 0x88,
    DW_OP_breg25 = 0x89,
    DW_OP_breg26 = 0x8a,
    DW_OP_breg27 = 0x8b,
    DW_OP_breg28 = 0x8c,
    DW_OP_breg29 = 0x8d,
    DW_OP_breg30 = 0x8e,
    DW_OP_breg31 = 0x8f,
    DW_OP_regx = 0x90,
    DW_OP_fbreg = 0x91,
    DW_OP_bregx = 0x92,
    DW_OP_piece = 0x93,
    DW_OP_deref_size = 0x94,
    DW_OP_xderef_size = 0x95,
    DW_OP_nop = 0x96,
    /* DWARF 3 extensions.  */
    DW_OP_push_object_address = 0x97,
    DW_OP_call2 = 0x98,
    DW_OP_call4 = 0x99,
    DW_OP_call_ref = 0x9a,
    DW_OP_form_tls_address = 0x9b,
    DW_OP_call_frame_cfa = 0x9c,
    DW_OP_bit_piece = 0x9d,
    /* GNU extensions.  */
    DW_OP_GNU_push_tls_address = 0xe0,
    /* HP extensions.  */
    DW_OP_HP_unknown     = 0xe0, /* Ouch, the same as GNU_push_tls_address.  */
    DW_OP_HP_is_value    = 0xe1,
    DW_OP_HP_fltconst4   = 0xe2,
    DW_OP_HP_fltconst8   = 0xe3,
    DW_OP_HP_mod_range   = 0xe4,
    DW_OP_HP_unmod_range = 0xe5,
    DW_OP_HP_tls         = 0xe6
  };


/* Convert the DWARF3 expression in expr[0 .. exprlen-1] into a dag
   (of CfiExprs) stored in ctx->exprs, and return the index in
   ctx->exprs of the root node.  Or fail in which case return -1. */
/* IMPORTANT: when adding expression forms here, also remember to
   add suitable evaluation code in evalCfiExpr in debuginfo.c. */
static Int dwarfexpr_to_dag ( UnwindContext* ctx, 
                              UChar* expr, Int exprlen, 
                              Bool push_cfa_at_start,
                              Bool ddump_frames )
{
#  define N_EXPR_STACK 20

#  define PUSH(_arg)                               \
      do {                                         \
         vg_assert(sp >= -1 && sp < N_EXPR_STACK); \
         if (sp == N_EXPR_STACK-1)                 \
            return -1;                             \
         sp++;                                     \
         stack[sp] = (_arg);                       \
      } while (0)

#  define POP(_lval)                               \
      do {                                         \
         vg_assert(sp >= -1 && sp < N_EXPR_STACK); \
         if (sp == -1)                             \
            return -1;                             \
         _lval = stack[sp];                        \
         sp--;                                     \
      } while (0)

   Int    ix, ix2, reg;
   UChar  opcode;
   Word   sw;
   UWord  uw;
   CfiOp  op;
   HChar* opname;

   Int sp; /* # of top element: valid is -1 .. N_EXPR_STACK-1 */
   Int stack[N_EXPR_STACK];  /* indices into ctx->exprs */

   XArray* dst   = ctx->exprs;
   UChar*  limit = expr + exprlen;

   vg_assert(dst);
   vg_assert(exprlen >= 0);

   sp = -1; /* empty */

   /* Synthesise the CFA as a CfiExpr */
   if (push_cfa_at_start) {
      if (ctx->cfa_is_regoff) {
         /* cfa is reg +/- offset */
         ix = ML_(CfiExpr_Binop)( dst,
                 Cop_Add,
                 ML_(CfiExpr_DwReg)( dst, ctx->cfa_reg ),
                 ML_(CfiExpr_Const)( dst, (UWord)(Word)ctx->cfa_off )
              );
         PUSH(ix);
      } else {
         /* CFA is already an expr; use its root node */
         PUSH(ctx->cfa_expr_ix);
      }
   }

   while (True) {

      vg_assert(sp >= -1 && sp < N_EXPR_STACK);

      if (expr > limit) 
         return -1;  /* overrun - something's wrong */

      if (expr == limit) {
        /* end of expr - return expr on the top of stack. */
        if (sp == -1)
           return -1; /* stack empty.  Bad. */
        else
           break;
      }

      op = 0; opname = NULL; /* excessively conservative */

      opcode = *expr++;
      switch (opcode) {

         case DW_OP_lit0 ... DW_OP_lit31:
            /* push: literal 0 .. 31 */
            sw = (Word)opcode - (Word)DW_OP_lit0;
            vg_assert(sw >= 0 && sw <= 31);
            PUSH( ML_(CfiExpr_Const)( dst, (UWord)sw ) );
            if (ddump_frames)
               VG_(printf)("DW_OP_lit%ld", sw);
            break;

         case DW_OP_breg0 ... DW_OP_breg31:
            /* push: reg + sleb128 */
            reg = (Int)opcode - (Int)DW_OP_breg0;
            vg_assert(reg >= 0 && reg <= 31);
            sw = read_leb128S( &expr );
            ix = ML_(CfiExpr_Binop)( dst,
                    Cop_Add,
                    ML_(CfiExpr_DwReg)( dst, reg ),
                    ML_(CfiExpr_Const)( dst, (UWord)sw )
                 );
            PUSH(ix);
            if (ddump_frames)
               VG_(printf)("DW_OP_breg%d: %ld", reg, sw);
            break;

         case DW_OP_plus_uconst:
            uw = read_leb128U( &expr );
            PUSH( ML_(CfiExpr_Const)( dst, uw ) );
            POP( ix );
            POP( ix2 );
            PUSH( ML_(CfiExpr_Binop)( dst, op, ix2, ix ) );
            if (ddump_frames)
               VG_(printf)("DW_OP_plus_uconst: %lu", uw);
            break;

         case DW_OP_const4s:
            /* push: 32-bit signed immediate */
            sw = read_le_s_encoded_literal( expr, 4 );
            expr += 4;
            PUSH( ML_(CfiExpr_Const)( dst, (UWord)sw ) );
            if (ddump_frames)
               VG_(printf)("DW_OP_const4s: %ld", sw);
            break;

         case DW_OP_minus:
            op = Cop_Sub; opname = "minus"; goto binop;
         case DW_OP_plus:
            op = Cop_Add; opname = "plus"; goto binop;
         case DW_OP_and:
            op = Cop_And; opname = "and"; goto binop;
         case DW_OP_mul:
            op = Cop_Mul; opname = "mul"; goto binop;
         binop:
            POP( ix );
            POP( ix2 );
            PUSH( ML_(CfiExpr_Binop)( dst, op, ix2, ix ) );
            if (ddump_frames)
               VG_(printf)("DW_OP_%s", opname);
            break;

         case DW_OP_deref:
            POP( ix );
            PUSH( ML_(CfiExpr_Deref)( dst, ix ) );
            if (ddump_frames)
               VG_(printf)("DW_OP_deref");
            break;

         default:
            if (!VG_(clo_xml))
               VG_(message)(Vg_DebugMsg, 
                            "Warning: DWARF2 CFI reader: unhandled DW_OP_ "
                            "opcode 0x%x", (Int)opcode); 
            return -1;
      }

      if (expr < limit && ddump_frames)
         VG_(printf)("; ");

   }

   vg_assert(sp >= -1 && sp < N_EXPR_STACK);
   if (sp == -1)
      return -1;

   if (0 && ddump_frames)
      ML_(ppCfiExpr)( dst, stack[sp] );
   return stack[sp];

#  undef POP
#  undef PUSH
#  undef N_EXPR_STACK
}


/* ------------ Run/show CFI instructions ------------ */

/* Run a CFI instruction, and also return its length.
   Returns 0 if the instruction could not be executed. 
*/
static Int run_CF_instruction ( /*MOD*/UnwindContext* ctx, 
                                UChar* instr,
                                UnwindContext* restore_ctx,
                                AddressDecodingInfo* adi,
                                struct _SegInfo* si )
{
   Int    off, reg, reg2, nleb, len;
   UInt   delta;
   UChar* expr;
   Int    j;
   Int    i   = 0;
   UChar  hi2 = (instr[i] >> 6) & 3;
   UChar  lo6 = instr[i] & 0x3F;
   Addr   printing_bias = ((Addr)ctx->initloc) - ((Addr)si->text_bias);
   i++;

   if (hi2 == DW_CFA_advance_loc) {
      delta = (UInt)lo6;
      ctx->loc += delta;
      if (si->ddump_frames)
         VG_(printf)("  DW_CFA_advance_loc: %d to %08lx\n", 
                     (Int)delta, (Addr)ctx->loc + printing_bias);
      return i;
   }

   if (hi2 == DW_CFA_offset) {
      /* Set rule for reg 'lo6' to CFAOff(off * data_af) */
      off = read_leb128( &instr[i], &nleb, 0 );
      i += nleb;
      reg = (Int)lo6;
      if (reg < 0 || reg >= N_CFI_REGS) 
         return 0; /* fail */
      ctx->reg[reg].tag = RR_CFAOff;
      ctx->reg[reg].arg = off * ctx->data_a_f;
      if (si->ddump_frames)
         VG_(printf)("  DW_CFA_offset: r%d at cfa%s%d\n",
                     (Int)reg, ctx->reg[reg].arg < 0 ? "" : "+", 
                     (Int)ctx->reg[reg].arg );
      return i;
   }

   if (hi2 == DW_CFA_restore) {
      reg = (Int)lo6;
      if (reg < 0 || reg >= N_CFI_REGS) 
         return 0; /* fail */
      if (restore_ctx == NULL)
         return 0; /* fail */
      ctx->reg[reg] = restore_ctx->reg[reg];
      if (si->ddump_frames)
         VG_(printf)("  DW_CFA_restore: r%d\n", (Int)reg);
      return i;
   }

   vg_assert(hi2 == DW_CFA_use_secondary);

   switch (lo6) {
      case DW_CFA_nop: 
         if (si->ddump_frames)
            VG_(printf)("  DW_CFA_nop\n");
         break;
      case DW_CFA_set_loc:
         /* WAS: 
            ctx->loc = read_Addr(&instr[i]) - ctx->initloc; i+= sizeof(Addr);
            Was this ever right? */
         /* 2007 Feb 23: No.  binutils/dwarf.c treats it as an encoded
            address and that appears to be in accordance with the
            DWARF3 spec. */
         ctx->loc = read_encoded_Addr(&len, adi, &instr[i]);
         i += len;
         if (si->ddump_frames)
            VG_(printf)("  rci:DW_CFA_set_loc\n");
         break;
      case DW_CFA_advance_loc1:
         delta = (UInt)read_UChar(&instr[i]); i+= sizeof(UChar);
         ctx->loc += delta;
         if (si->ddump_frames)
            VG_(printf)("  DW_CFA_advance_loc1: %d to %08lx\n", 
                        (Int)delta, (Addr)ctx->loc + printing_bias);
         break;
      case DW_CFA_advance_loc2:
         delta = (UInt)read_UShort(&instr[i]); i+= sizeof(UShort);
         ctx->loc += delta;
         if (si->ddump_frames)
            VG_(printf)("  DW_CFA_advance_loc2: %d to %08lx\n", 
                        (Int)delta, (Addr)ctx->loc + printing_bias);
         break;
      case DW_CFA_advance_loc4:
         delta = (UInt)read_UInt(&instr[i]); i+= sizeof(UInt);
         ctx->loc += delta;
         if (si->ddump_frames)
            VG_(printf)("  DW_CFA_advance_loc4: %d to %08lx\n", 
                        (Int)delta, (Addr)ctx->loc + printing_bias);
         break;

      case DW_CFA_def_cfa:
         reg = read_leb128( &instr[i], &nleb, 0 );
         i += nleb;
         off = read_leb128( &instr[i], &nleb, 0 );
         i += nleb;
         if (reg < 0 || reg >= N_CFI_REGS) 
            return 0; /* fail */
         ctx->cfa_is_regoff = True;
         ctx->cfa_expr_ix   = 0;
         ctx->cfa_reg       = reg;
         ctx->cfa_off       = off;
         if (si->ddump_frames)
            VG_(printf)("  DW_CFA_def_cfa: r%d ofs %d\n", (Int)reg, (Int)off);
         break;

      case DW_CFA_def_cfa_sf:
         reg = read_leb128( &instr[i], &nleb, 0 );
         i += nleb;
         off = read_leb128( &instr[i], &nleb, 1 );
         i += nleb;
         if (reg < 0 || reg >= N_CFI_REGS)
            return 0; /* fail */
         ctx->cfa_is_regoff = True;
         ctx->cfa_expr_ix   = 0;
         ctx->cfa_reg       = reg;
         ctx->cfa_off       = off * ctx->data_a_f;
         if (si->ddump_frames)
            VG_(printf)("  rci:DW_CFA_def_cfa_sf\n");
         break;

      case DW_CFA_register:
         reg = read_leb128( &instr[i], &nleb, 0);
         i += nleb;
         reg2 = read_leb128( &instr[i], &nleb, 0);
         i += nleb;
         if (reg < 0 || reg >= N_CFI_REGS) 
            return 0; /* fail */
         if (reg2 < 0 || reg2 >= N_CFI_REGS) 
            return 0; /* fail */
         ctx->reg[reg].tag = RR_Reg;
         ctx->reg[reg].arg = reg2;
         if (si->ddump_frames)
            VG_(printf)("  DW_CFA_register: r%d in r%d\n", 
                        (Int)reg, (Int)reg2);
         break;

      case DW_CFA_offset_extended:
         reg = read_leb128( &instr[i], &nleb, 0 );
         i += nleb;
         off = read_leb128( &instr[i], &nleb, 0 );
         i += nleb;
         if (reg < 0 || reg >= N_CFI_REGS)
            return 0; /* fail */
         ctx->reg[reg].tag = RR_CFAOff;
         ctx->reg[reg].arg = off * ctx->data_a_f;
         if (si->ddump_frames)
            VG_(printf)("  rci:DW_CFA_offset_extended\n");
         break;

      case DW_CFA_offset_extended_sf:
         reg = read_leb128( &instr[i], &nleb, 0 );
         i += nleb;
         off = read_leb128( &instr[i], &nleb, 1 );
         i += nleb;
         if (reg < 0 || reg >= N_CFI_REGS) 
            return 0; /* fail */
         ctx->reg[reg].tag = RR_CFAOff;
         ctx->reg[reg].arg = off * ctx->data_a_f;
         if (si->ddump_frames)
            VG_(printf)("  DW_CFA_offset_extended_sf: r%d at cfa%s%d\n", 
                        reg, ctx->reg[reg].arg < 0 ? "" : "+", 
                        (Int)ctx->reg[reg].arg);
         break;

      case DW_CFA_GNU_negative_offset_extended:
         reg = read_leb128( &instr[i], &nleb, 0 );
         i += nleb;
         off = read_leb128( &instr[i], &nleb, 0 );
         i += nleb;
         if (reg < 0 || reg >= N_CFI_REGS)
            return 0; /* fail */
         ctx->reg[reg].tag = RR_CFAOff;
         ctx->reg[reg].arg = (-off) * ctx->data_a_f;
         if (si->ddump_frames)
            VG_(printf)("  rci:DW_CFA_GNU_negative_offset_extended\n");
         break;

      case DW_CFA_restore_extended:
         reg = read_leb128( &instr[i], &nleb, 0 );
         i += nleb;
         if (reg < 0 || reg >= N_CFI_REGS)
            return 0; /* fail */
	 if (restore_ctx == NULL)
	    return 0; /* fail */
	 ctx->reg[reg] = restore_ctx->reg[reg];
         if (si->ddump_frames)
            VG_(printf)("  rci:DW_CFA_restore_extended\n");
         break;

      case DW_CFA_val_offset:
         reg = read_leb128( &instr[i], &nleb, 0 );
         i += nleb;
         off = read_leb128( &instr[i], &nleb, 0 );
         i += nleb;
         if (reg < 0 || reg >= N_CFI_REGS)
            return 0; /* fail */
         ctx->reg[reg].tag = RR_CFAValOff;
         ctx->reg[reg].arg = off * ctx->data_a_f;
         if (si->ddump_frames)
            VG_(printf)("  rci:DW_CFA_val_offset\n");
         break;

      case DW_CFA_val_offset_sf:
         reg = read_leb128( &instr[i], &nleb, 0 );
         i += nleb;
         off = read_leb128( &instr[i], &nleb, 1 );
         i += nleb;
         if (reg < 0 || reg >= N_CFI_REGS)
            return 0; /* fail */
         ctx->reg[reg].tag = RR_CFAValOff;
         ctx->reg[reg].arg = off * ctx->data_a_f;
         if (si->ddump_frames)
            VG_(printf)("  rci:DW_CFA_val_offset_sf\n");
         break;

      case DW_CFA_def_cfa_register:
         reg = read_leb128( &instr[i], &nleb, 0);
         i += nleb;
         if (reg < 0 || reg >= N_CFI_REGS) 
            return 0; /* fail */
         ctx->cfa_is_regoff = True;
         ctx->cfa_expr_ix   = 0;
         ctx->cfa_reg       = reg;
         /* ->cfa_off unchanged */
         if (si->ddump_frames)
            VG_(printf)("  DW_CFA_def_cfa_reg: r%d\n", (Int)reg );
         break;

      case DW_CFA_def_cfa_offset:
         off = read_leb128( &instr[i], &nleb, 0);
         i += nleb;
         ctx->cfa_is_regoff = True;
         ctx->cfa_expr_ix   = 0;
         /* ->reg is unchanged */
         ctx->cfa_off       = off;
         if (si->ddump_frames)
            VG_(printf)("  DW_CFA_def_cfa_offset: %d\n", (Int)off);
         break;

      case DW_CFA_def_cfa_offset_sf:
         off = read_leb128( &instr[i], &nleb, 1);
         i += nleb;
         ctx->cfa_is_regoff = True;
         ctx->cfa_expr_ix   = 0;
         /* ->reg is unchanged */
         ctx->cfa_off       = off * ctx->data_a_f;
         if (si->ddump_frames)
            VG_(printf)("  DW_CFA_def_cfa_offset_sf: %d\n", ctx->cfa_off);
         break;

      case DW_CFA_undefined:
         reg = read_leb128( &instr[i], &nleb, 0);
         i += nleb;
         if (reg < 0 || reg >= N_CFI_REGS) 
            return 0; /* fail */
         ctx->reg[reg].tag = RR_Undef;
         ctx->reg[reg].arg = 0;
         if (si->ddump_frames)
            VG_(printf)("  rci:DW_CFA_undefined\n");
         break;

      case DW_CFA_GNU_args_size:
         /* No idea what is supposed to happen.  gdb-6.3 simply
            ignores these. */
         off = read_leb128( &instr[i], &nleb, 0 );
         i += nleb;
         if (si->ddump_frames)
            VG_(printf)("  rci:DW_CFA_GNU_args_size (ignored)\n");
         break;

      case DW_CFA_expression:
         /* Identical to DW_CFA_val_expression except that the value
            computed is an address and so needs one final
            dereference. */
         reg = read_leb128( &instr[i], &nleb, 0 );
         i += nleb;
         len = read_leb128( &instr[i], &nleb, 0 );
         i += nleb;
         expr = &instr[i];
         i += len;
         if (reg < 0 || reg >= N_CFI_REGS)
            return 0; /* fail */
         if (si->ddump_frames)
            VG_(printf)("  DW_CFA_expression: r%d (", 
                        (Int)reg);
         /* Convert the expression into a dag rooted at ctx->exprs index j,
            or fail. */
         j = dwarfexpr_to_dag ( ctx, expr, len, True/*push CFA at start*/, 
                                si->ddump_frames);
         if (si->ddump_frames)
            VG_(printf)(")\n");
         vg_assert(j >= -1);
         if (j >= 0) {
            vg_assert(ctx->exprs);
            vg_assert( j < VG_(sizeXA)(ctx->exprs) );
         }
         if (j == -1)
            return 0; /* fail */
         /* Add an extra dereference */
         j = ML_(CfiExpr_Deref)( ctx->exprs, j );
         ctx->reg[reg].tag = RR_ValExpr;
         ctx->reg[reg].arg = j;
         break;

      case DW_CFA_val_expression:
         reg = read_leb128( &instr[i], &nleb, 0 );
         i += nleb;
         len = read_leb128( &instr[i], &nleb, 0 );
         i += nleb;
         expr = &instr[i];
         i += len;
         if (reg < 0 || reg >= N_CFI_REGS)
            return 0; /* fail */
         if (si->ddump_frames)
            VG_(printf)("  DW_CFA_val_expression: r%d (", 
                        (Int)reg);
         /* Convert the expression into a dag rooted at ctx->exprs index j,
            or fail. */
         j = dwarfexpr_to_dag ( ctx, expr, len, True/*push CFA at start*/, 
                                si->ddump_frames);
         if (si->ddump_frames)
            VG_(printf)(")\n");
         vg_assert(j >= -1);
         if (j >= 0) {
            vg_assert(ctx->exprs);
            vg_assert( j < VG_(sizeXA)(ctx->exprs) );
         }
         if (j == -1)
            return 0; /* fail */
         ctx->reg[reg].tag = RR_ValExpr;
         ctx->reg[reg].arg = j;
         break;

      case DW_CFA_def_cfa_expression:
         len = read_leb128( &instr[i], &nleb, 0 );
         i += nleb;
         expr = &instr[i];
         i += len;
         if (si->ddump_frames)
            VG_(printf)("  DW_CFA_def_cfa_expression (");
         /* Convert the expression into a dag rooted at ctx->exprs index j,
            or fail. */
         j = dwarfexpr_to_dag ( ctx, expr, len, True/*push CFA at start*/, 
                                si->ddump_frames);
         if (si->ddump_frames)
            VG_(printf)(")\n");
         ctx->cfa_is_regoff = False;
         ctx->cfa_reg       = 0;
         ctx->cfa_off       = 0;
         ctx->cfa_expr_ix   = j;
         break;

      case DW_CFA_GNU_window_save:
         /* Ignored.  This appears to be sparc-specific; quite why it
            turns up in SuSE-supplied x86 .so's beats me. */
         if (si->ddump_frames)
            VG_(printf)("DW_CFA_GNU_window_save\n");
         break;

      default: 
         VG_(message)(Vg_DebugMsg, "DWARF2 CFI reader: unhandled CFI "
                                   "instruction 0:%d", (Int)lo6); 
         if (si->ddump_frames)
            VG_(printf)("  rci:run_CF_instruction:default\n");
         i = 0;
         break;
   }

   return i;   
}


/* Show a CFI instruction, and also return its length.  Show it as
   close as possible (preferably identical) to how GNU binutils
   readelf --debug-dump=frames would. */

static Int show_CF_instruction ( UChar* instr,
                                 AddressDecodingInfo* adi,
                                 Int code_a_f, Int data_a_f )
{
   UInt  delta;
   Int   off, coff, reg, reg2, nleb, len;
   Addr  loc;
   Int   i   = 0;
   UChar hi2 = (instr[i] >> 6) & 3;
   UChar lo6 = instr[i] & 0x3F;
   i++;

   if (0) VG_(printf)("raw:%x/%x:%x:%x:%x:%x:%x:%x:%x:%x\n",
                      hi2, lo6,
                      instr[i+0], instr[i+1], instr[i+2], instr[i+3],
                      instr[i+4], instr[i+5], instr[i+6], instr[i+7] );
   
   if (hi2 == DW_CFA_advance_loc) {
      VG_(printf)("  sci:DW_CFA_advance_loc(%d)\n", (Int)lo6);
      return i;
   }

   if (hi2 == DW_CFA_offset) {
      off = read_leb128( &instr[i], &nleb, 0 );
      i += nleb;
      coff = off * data_a_f;
      VG_(printf)("  DW_CFA_offset: r%d at cfa%s%d\n",
                  (Int)lo6, coff < 0 ? "" : "+", (Int)coff );
      return i;
   }

   if (hi2 == DW_CFA_restore) {
      VG_(printf)("  sci:DW_CFA_restore(r%d)\n", (Int)lo6);
      return i;
   }

   vg_assert(hi2 == DW_CFA_use_secondary);

   switch (lo6) {

      case DW_CFA_nop: 
         VG_(printf)("  DW_CFA_nop\n"); 
         break;

      case DW_CFA_set_loc:
         /* WAS: loc = read_Addr(&instr[i]); i+= sizeof(Addr); 
            (now known to be incorrect -- the address is encoded) */
         loc = read_encoded_Addr(&len, adi, &instr[i]);
         i += len;
         VG_(printf)("  sci:DW_CFA_set_loc(%p)\n", loc); 
         break;

      case DW_CFA_advance_loc1:
         delta = (UInt)read_UChar(&instr[i]); i+= sizeof(UChar);
         VG_(printf)("  sci:DW_CFA_advance_loc1(%d)\n", delta); 
         break;

      case DW_CFA_advance_loc2:
         delta = (UInt)read_UShort(&instr[i]); i+= sizeof(UShort);
         VG_(printf)("  sci:DW_CFA_advance_loc2(%d)\n", delta); 
         break;

      case DW_CFA_advance_loc4:
         delta = (UInt)read_UInt(&instr[i]); i+= sizeof(UInt);
         VG_(printf)("  DW_CFA_advance_loc4(%d)\n", delta); 
         break;

      case DW_CFA_def_cfa:
         reg = read_leb128( &instr[i], &nleb, 0 );
         i += nleb;
         off = read_leb128( &instr[i], &nleb, 0 );
         i += nleb;
         VG_(printf)("  DW_CFA_def_cfa: r%d ofs %d\n", (Int)reg, (Int)off); 
         break;

      case DW_CFA_def_cfa_sf:
         reg = read_leb128( &instr[i], &nleb, 0 );
         i += nleb;
         off = read_leb128( &instr[i], &nleb, 1 );
         i += nleb;
         VG_(printf)("  DW_CFA_def_cfa_sf: r%d ofs %d\n", 
                     (Int)reg, (Int)(off * data_a_f));
         break;

      case DW_CFA_register:
         reg = read_leb128( &instr[i], &nleb, 0);
         i += nleb;
         reg2 = read_leb128( &instr[i], &nleb, 0);
         i += nleb;
         VG_(printf)("  sci:DW_CFA_register(r%d, r%d)\n", reg, reg2); 
         break;

      case DW_CFA_def_cfa_register:
         reg = read_leb128( &instr[i], &nleb, 0);
         i += nleb;
         VG_(printf)("  sci:DW_CFA_def_cfa_register(r%d)\n", reg); 
         break;

      case DW_CFA_def_cfa_offset: 
         off = read_leb128( &instr[i], &nleb, 0);
         i += nleb;
         VG_(printf)("  sci:DW_CFA_def_cfa_offset(%d)\n", off); 
         break;

      case DW_CFA_def_cfa_offset_sf:
         off = read_leb128( &instr[i], &nleb, 1);
         i += nleb;
         VG_(printf)("  sci:DW_CFA_def_cfa_offset_sf(%d)\n", off);
         break;

      case DW_CFA_restore_extended:
         reg = read_leb128( &instr[i], &nleb, 0);
         i += nleb;
         VG_(printf)("  sci:DW_CFA_restore_extended(r%d)\n", reg);
         break;

      case DW_CFA_undefined:
         reg = read_leb128( &instr[i], &nleb, 0);
         i += nleb;
         VG_(printf)("  sci:DW_CFA_undefined(r%d)\n", reg);
         break;

      case DW_CFA_same_value:
         reg = read_leb128( &instr[i], &nleb, 0);
         i += nleb;
         VG_(printf)("  sci:DW_CFA_same_value(r%d)\n", reg);
         break;

      case DW_CFA_remember_state:
         VG_(printf)("  sci:DW_CFA_remember_state\n");
         break;

      case DW_CFA_restore_state:
         VG_(printf)("  sci:DW_CFA_restore_state\n");
         break;

      case DW_CFA_GNU_args_size:
         off = read_leb128( &instr[i], &nleb, 0 );
         i += nleb;
         VG_(printf)("  sci:DW_CFA_GNU_args_size(%d)\n", off ); 
         break;

      case DW_CFA_def_cfa_expression:
         len = read_leb128( &instr[i], &nleb, 0 );
         i += nleb;
         i += len;
         VG_(printf)("  sci:DW_CFA_def_cfa_expression(length %d)\n", len);
         break;

      case DW_CFA_expression:
         reg = read_leb128( &instr[i], &nleb, 0 );
         i += nleb;
         len = read_leb128( &instr[i], &nleb, 0 );
         i += nleb;
         i += len;
         VG_(printf)("  sci:DW_CFA_expression(r%d, length %d)\n", reg, len);
         break;

      case DW_CFA_val_expression:
         reg = read_leb128( &instr[i], &nleb, 0 );
         i += nleb;
         len = read_leb128( &instr[i], &nleb, 0 );
         i += nleb;
         i += len;
         VG_(printf)("  sci:DW_CFA_val_expression(r%d, length %d)\n", reg, len);
         break;

      case DW_CFA_offset_extended:
         reg = read_leb128( &instr[i], &nleb, 0 );
         i += nleb;
         off = read_leb128( &instr[i], &nleb, 0 );
         i += nleb;
         VG_(printf)("  sci:DW_CFA_offset_extended(r%d, "
                     "off %d x data_af)\n", reg, off);
         break;

      case DW_CFA_offset_extended_sf:
         reg = read_leb128( &instr[i], &nleb, 0 );
         i += nleb;
         off = read_leb128( &instr[i], &nleb, 1 );
         i += nleb;
	 coff = (Int)(off * data_a_f);
         VG_(printf)("  DW_CFA_offset_extended_sf: r%d at cfa%s%d\n", 
                        reg, coff < 0 ? "" : "+", coff);
         break;

      case DW_CFA_GNU_negative_offset_extended:
         reg = read_leb128( &instr[i], &nleb, 0 );
         i += nleb;
         off = read_leb128( &instr[i], &nleb, 0 );
         i += nleb;
         VG_(printf)("  sci:DW_CFA_GNU_negative_offset_extended"
                     "(r%d, off %d x data_af)\n", reg, -off);
         break;

      case DW_CFA_val_offset:
         reg = read_leb128( &instr[i], &nleb, 0 );
         i += nleb;
         off = read_leb128( &instr[i], &nleb, 0 );
         i += nleb;
         VG_(printf)("  sci:DW_CFA_val_offset(r%d, off %d x data_af)\n", 
                     reg, off);
         break;

       case DW_CFA_val_offset_sf:
         reg = read_leb128( &instr[i], &nleb, 0 );
         i += nleb;
         off = read_leb128( &instr[i], &nleb, 1 );
         i += nleb;
         VG_(printf)("  sci:DW_CFA_val_offset_sf(r%d, off %d x data_af)\n", 
                     reg, off);
         break;

      case DW_CFA_GNU_window_save:
         VG_(printf)("  sci:DW_CFA_GNU_window_save\n");
         break;

      default: 
         VG_(printf)("  sci:0:%d\n", (Int)lo6); 
         break;
   }

   return i;
}


/* Show the instructions in instrs[0 .. ilen-1]. */
static void show_CF_instructions ( UChar* instrs, Int ilen,
                                   AddressDecodingInfo* adi,
                                   Int code_a_f, Int data_a_f )
{
   Int i = 0;
   while (True) {
      if (i >= ilen) break;
      i += show_CF_instruction( &instrs[i], adi, code_a_f, data_a_f );
   }
}


/* Run the CF instructions in instrs[0 .. ilen-1], until the end is
   reached, or until there is a failure.  Return True iff success. 
*/
static 
Bool run_CF_instructions ( struct _SegInfo* si,
                           Bool record,
                           UnwindContext* ctx, UChar* instrs, Int ilen,
                           UWord fde_arange,
                           UnwindContext* restore_ctx,
                           AddressDecodingInfo* adi )
{
   DiCfSI cfsi;
   Bool summ_ok;
   Int j, i = 0;
   Addr loc_prev;
   if (0) ppUnwindContext(ctx);
   if (0) ppUnwindContext_summary(ctx);
   while (True) {
      loc_prev = ctx->loc;
      if (i >= ilen) break;
      if (0) (void)show_CF_instruction( &instrs[i], adi, 
                                        ctx->code_a_f, ctx->data_a_f );
      j = run_CF_instruction( ctx, &instrs[i], restore_ctx, adi, si );
      if (j == 0)
         return False; /* execution failed */
      i += j;
      if (0) ppUnwindContext(ctx);
      if (record && loc_prev != ctx->loc) {
         summ_ok = summarise_context ( &cfsi, loc_prev, ctx, si );
         if (summ_ok) {
            ML_(addDiCfSI)(si, &cfsi);
            if (si->trace_cfi)
               ML_(ppDiCfSI)(si->cfsi_exprs, &cfsi);
         }
      }
   }
   if (ctx->loc < fde_arange) {
      loc_prev = ctx->loc;
      ctx->loc = fde_arange;
      if (record) {
         summ_ok = summarise_context ( &cfsi, loc_prev, ctx, si );
         if (summ_ok) {
            ML_(addDiCfSI)(si, &cfsi);
            if (si->trace_cfi)
               ML_(ppDiCfSI)(si->cfsi_exprs, &cfsi);
         }
      }
   }
   return True;
}


/* ------------ Main entry point for CFI reading ------------ */

typedef
   struct {
      /* This gives the CIE an identity to which FDEs will refer. */
      ULong  offset;
      /* Code, data factors. */
      Int    code_a_f;
      Int    data_a_f;
      /* Return-address pseudo-register. */
      Int    ra_reg;
      UChar  address_encoding;
      /* Where are the instrs?  Note, this are simply pointers back to
         the transiently-mapped-in section. */
      UChar* instrs;
      Int    ilen;
      /* God knows .. don't ask */
      Bool   saw_z_augmentation;
   }
   CIE;

static void init_CIE ( CIE* cie )
{
   cie->offset             = 0;
   cie->code_a_f           = 0;
   cie->data_a_f           = 0;
   cie->ra_reg             = 0;
   cie->address_encoding   = 0;
   cie->instrs             = NULL;
   cie->ilen               = 0;
   cie->saw_z_augmentation = False;
}

#define N_CIEs 2000
static CIE the_CIEs[N_CIEs];


void ML_(read_callframe_info_dwarf3)
        ( /*OUT*/struct _SegInfo* si, 
          UChar* ehframe_image, Int ehframe_sz, Addr ehframe_avma )
{
   Int    nbytes;
   HChar* how = NULL;
   Int    n_CIEs = 0;
   UChar* data = ehframe_image;

#  if defined(VGP_ppc32_linux) || defined(VGP_ppc64_linux)
   /* These targets don't use CFI-based stack unwinding. */
   return;
#  endif

   if (si->trace_cfi) {
      VG_(printf)("\n-----------------------------------------------\n");
      VG_(printf)("CFI info: szB %d, _avma %p, _image %p\n",
	          ehframe_sz, (void*)ehframe_avma, (void*)ehframe_image );
      VG_(printf)("CFI info: name %s\n",
		  si->filename );
   }

   /* Loop over CIEs/FDEs */

   /* Conceptually, the frame info is a sequence of FDEs, one for each
      function.  Inside an FDE is a miniature program for a special
      state machine, which, when run, produces the stack-unwinding
      info for that function.

      Because the FDEs typically have much in common, and because the
      DWARF designers appear to have been fanatical about space
      saving, the common parts are factored out into so-called CIEs.
      That means that what we traverse is a sequence of structs, each
      of which is either a FDE (usually) or a CIE (occasionally).
      Each FDE has a field indicating which CIE is the one pertaining
      to it.

      The following loop traverses the sequence.  FDEs are dealt with
      immediately; once we harvest the useful info in an FDE, it is
      then forgotten about.  By contrast, CIEs are validated and
      dumped into an array, because later FDEs may refer to any
      previously-seen CIE.
   */
   while (True) {
      UChar* ciefde_start;
      ULong  ciefde_len;
      ULong  cie_pointer;
      Bool   dw64;

      /* Are we done? */
      if (data == ehframe_image + ehframe_sz)
         return;

      /* Overshot the end?  Means something is wrong */
      if (data > ehframe_image + ehframe_sz) {
         how = "overran the end of .eh_frame";
         goto bad;
      }

      /* Ok, we must be looking at the start of a new CIE or FDE.
         Figure out which it is. */

      ciefde_start = data;
      if (si->trace_cfi) 
         VG_(printf)("\ncie/fde.start   = %p (ehframe_image + 0x%lx)\n", 
                     ciefde_start, ciefde_start - ehframe_image);

      ciefde_len = (ULong) read_UInt(data); data += sizeof(UInt);
      if (si->trace_cfi) 
         VG_(printf)("cie/fde.length  = %lld\n", ciefde_len);

      /* Apparently, if the .length field is zero, we are at the end
         of the sequence.  This is stated in the Generic Elf
         Specification (see comments far above here) and is one of the
         places where .eh_frame and .debug_frame data differ. */
      if (ciefde_len == 0) {
         if (si->ddump_frames)
            VG_(printf)("%08lx ZERO terminator\n\n",
                        ((Addr)ciefde_start) - ((Addr)ehframe_image));
         return;
      }

      /* If the .length field is 0xFFFFFFFF then we're dealing with
         64-bit DWARF, and the real length is stored as a 64-bit
         number immediately following it. */
      dw64 = False;
      if (ciefde_len == 0xFFFFFFFFUL) {
         dw64 = True;
         ciefde_len = read_ULong(data); data += sizeof(ULong);
      }

      /* Now get the CIE ID, whose size depends on the DWARF 32 vs
	 64-ness. */
      if (dw64) {
         cie_pointer = read_ULong(data); 
         data += sizeof(ULong); /* XXX see XXX below */
      } else {
         cie_pointer = (ULong)read_UInt(data); 
         data += sizeof(UInt); /* XXX see XXX below */
      }

      if (si->trace_cfi) 
         VG_(printf)("cie.pointer     = %lld\n", cie_pointer);

      /* If cie_pointer is zero, we've got a CIE; else it's an FDE. */
      if (cie_pointer == 0) {

         Int    this_CIE;
         UChar  cie_version;
         UChar* cie_augmentation;

         /* --------- CIE --------- */
	 if (si->trace_cfi) 
            VG_(printf)("------ new CIE (#%d of 0 .. %d) ------\n", 
                        n_CIEs, N_CIEs - 1);

	 /* Allocate a new CIE record. */
         vg_assert(n_CIEs >= 0 && n_CIEs <= N_CIEs);
         if (n_CIEs == N_CIEs) {
            how = "N_CIEs is too low.  Increase and recompile.";
            goto bad;
         }

         this_CIE = n_CIEs;
         n_CIEs++;
         init_CIE( &the_CIEs[this_CIE] );

	 /* Record its offset.  This is how we will find it again
            later when looking at an FDE. */
         the_CIEs[this_CIE].offset = (ULong)(ciefde_start - ehframe_image);

         if (si->ddump_frames)
            VG_(printf)("%08lx %08lx %08lx CIE\n",
                        ((Addr)ciefde_start) - ((Addr)ehframe_image),
                        (Addr)ciefde_len,
                        (Addr)(UWord)cie_pointer );

         cie_version = read_UChar(data); data += sizeof(UChar);
         if (si->trace_cfi)
            VG_(printf)("cie.version     = %d\n", (Int)cie_version);
         if (si->ddump_frames)
            VG_(printf)("  Version:               %d\n", (Int)cie_version);
         if (cie_version != 1) {
            how = "unexpected CIE version (not 1)";
            goto bad;
         }

         cie_augmentation = data;
         data += 1 + VG_(strlen)(cie_augmentation);
         if (si->trace_cfi) 
            VG_(printf)("cie.augment     = \"%s\"\n", cie_augmentation);
         if (si->ddump_frames)
            VG_(printf)("  Augmentation:          \"%s\"\n", cie_augmentation);

         if (cie_augmentation[0] == 'e' && cie_augmentation[1] == 'h') {
            data += sizeof(Addr);
            cie_augmentation += 2;
         }

         the_CIEs[this_CIE].code_a_f = read_leb128( data, &nbytes, 0);
         data += nbytes;
         if (si->trace_cfi) 
            VG_(printf)("cie.code_af     = %d\n", 
                        the_CIEs[this_CIE].code_a_f);
         if (si->ddump_frames)
            VG_(printf)("  Code alignment factor: %d\n",
                        (Int)the_CIEs[this_CIE].code_a_f);

         the_CIEs[this_CIE].data_a_f = read_leb128( data, &nbytes, 1);
         data += nbytes;
         if (si->trace_cfi) 
            VG_(printf)("cie.data_af     = %d\n",
                        the_CIEs[this_CIE].data_a_f);
         if (si->ddump_frames)
            VG_(printf)("  Data alignment factor: %d\n",
                        (Int)the_CIEs[this_CIE].data_a_f);

         the_CIEs[this_CIE].ra_reg = (Int)read_UChar(data); 
         data += sizeof(UChar);
         if (si->trace_cfi) 
            VG_(printf)("cie.ra_reg      = %d\n", 
                        the_CIEs[this_CIE].ra_reg);
         if (si->ddump_frames)
            VG_(printf)("  Return address column: %d\n",
                        (Int)the_CIEs[this_CIE].ra_reg);

         if (the_CIEs[this_CIE].ra_reg < 0 
             || the_CIEs[this_CIE].ra_reg >= N_CFI_REGS) {
            how = "cie.ra_reg has implausible value";
            goto bad;
         }

         the_CIEs[this_CIE].saw_z_augmentation 
            = *cie_augmentation == 'z';
         if (the_CIEs[this_CIE].saw_z_augmentation) {
            UInt length = read_leb128( data, &nbytes, 0);
            data += nbytes;
            the_CIEs[this_CIE].instrs = data + length;
            cie_augmentation++;
            if (si->ddump_frames) {
               UInt i;
               VG_(printf)("  Augmentation data:    ");
               for (i = 0; i < length; i++)
                  VG_(printf)(" %02x", (UInt)data[i]);
               VG_(printf)("\n");
            }
         } else {
            the_CIEs[this_CIE].instrs = NULL;
         }

         the_CIEs[this_CIE].address_encoding = default_Addr_encoding();

         while (*cie_augmentation) {
            switch (*cie_augmentation) {
               case 'L':
                  data++;
                  cie_augmentation++;
                  break;
               case 'R':
                  the_CIEs[this_CIE].address_encoding 
                     = read_UChar(data); data += sizeof(UChar);
                  cie_augmentation++;
                  break;
               case 'P':
                  data += size_of_encoded_Addr( read_UChar(data) );
                  data++;
                  cie_augmentation++;
                  break;
               case 'S':
                  cie_augmentation++;
                  break;
               default:
                  if (the_CIEs[this_CIE].instrs == NULL) {
                     how = "unhandled cie.augmentation";
                     goto bad;
                  }
                  data = the_CIEs[this_CIE].instrs;
                  goto done_augmentation;
            }
         }

        done_augmentation:

         if (si->trace_cfi) 
            VG_(printf)("cie.encoding    = 0x%x\n", 
                        the_CIEs[this_CIE].address_encoding);

         the_CIEs[this_CIE].instrs = data;
         the_CIEs[this_CIE].ilen
            = ciefde_start + ciefde_len + sizeof(UInt) - data;
         if (si->trace_cfi) {
            VG_(printf)("cie.instrs      = %p\n", the_CIEs[this_CIE].instrs);
            VG_(printf)("cie.ilen        = %d\n", the_CIEs[this_CIE].ilen);
	 }

         if (the_CIEs[this_CIE].ilen < 0
             || the_CIEs[this_CIE].ilen > ehframe_sz) {
            how = "implausible # cie initial insns";
            goto bad;
         }

         data += the_CIEs[this_CIE].ilen;

         /* Show the CIE's instructions (the preamble for each FDE
            that uses this CIE). */ 
         if (si->ddump_frames)
            VG_(printf)("\n");

         if (si->trace_cfi || si->ddump_frames) {
            AddressDecodingInfo adi;
            adi.encoding      = the_CIEs[this_CIE].address_encoding;
            adi.ehframe_image = ehframe_image;
            adi.ehframe_avma  = ehframe_avma;
            adi.text_bias     = si->text_bias;
            show_CF_instructions( the_CIEs[this_CIE].instrs, 
                                  the_CIEs[this_CIE].ilen, &adi,
                                  the_CIEs[this_CIE].code_a_f,
                                  the_CIEs[this_CIE].data_a_f );
         }

         if (si->ddump_frames)
            VG_(printf)("\n");

      } else {

         AddressDecodingInfo adi;
         UnwindContext ctx, restore_ctx;
         Int    cie;
         ULong  look_for;
         Bool   ok;
         Addr   fde_initloc;
         UWord  fde_arange;
         UChar* fde_instrs;
         Int    fde_ilen;

         /* --------- FDE --------- */

         /* Find the relevant CIE.  The CIE we want is located
            cie_pointer bytes back from here. */

         /* re sizeof(UInt) / sizeof(ULong), matches XXX above. */
         look_for = (data - (dw64 ? sizeof(ULong) : sizeof(UInt)) 
                          - ehframe_image) 
                    - cie_pointer;

         for (cie = 0; cie < n_CIEs; cie++) {
            if (0) VG_(printf)("look for %lld   %lld\n",
                               look_for, the_CIEs[cie].offset );
            if (the_CIEs[cie].offset == look_for)
               break;
	 }
         vg_assert(cie >= 0 && cie <= n_CIEs);
         if (cie == n_CIEs) {
            how = "FDE refers to not-findable CIE";
            goto bad;
	 }

         adi.encoding      = the_CIEs[cie].address_encoding;
         adi.ehframe_image = ehframe_image;
         adi.ehframe_avma  = ehframe_avma;
         adi.text_bias     = si->text_bias;
         fde_initloc = read_encoded_Addr(&nbytes, &adi, data);
         data += nbytes;
         if (si->trace_cfi) 
            VG_(printf)("fde.initloc     = %p\n", (void*)fde_initloc);

         adi.encoding      = the_CIEs[cie].address_encoding & 0xf;
         adi.ehframe_image = ehframe_image;
         adi.ehframe_avma  = ehframe_avma;
         adi.text_bias     = si->text_bias;

         /* WAS (incorrectly):
            fde_arange = read_encoded_Addr(&nbytes, &adi, data);
            data += nbytes;
            The following corresponds to what binutils/dwarf.c does:
         */
         { UInt ptr_size = size_of_encoded_Addr( adi.encoding );
           switch (ptr_size) {
              case 8: case 4: case 2: case 1: 
                 fde_arange 
                    = (UWord)read_le_u_encoded_literal(data, ptr_size);
                 data += ptr_size;
                 break;
              default: 
                 how = "unknown arange field encoding in FDE";
                 goto bad;
           }
         }

         if (si->trace_cfi) 
            VG_(printf)("fde.arangec     = %p\n", (void*)fde_arange);

         if (si->ddump_frames)
            VG_(printf)("%08lx %08lx %08lx FDE cie=%08lx pc=%08lx..%08lx\n",
                        ((Addr)ciefde_start) - ((Addr)ehframe_image),
                        (Addr)ciefde_len,
                        (Addr)(UWord)cie_pointer,
                        (Addr)look_for, 
                        ((Addr)fde_initloc) - si->text_bias, 
                        ((Addr)fde_initloc) - si->text_bias + fde_arange);

         if (the_CIEs[cie].saw_z_augmentation) {
            UInt length = read_leb128( data, &nbytes, 0);
            data += nbytes;
            if (si->ddump_frames && (length > 0)) {
               UInt i;
               VG_(printf)("  Augmentation data:    ");
               for (i = 0; i < length; i++)
                  VG_(printf)(" %02x", (UInt)data[i]);
               VG_(printf)("\n\n");
            }
            data += length;
         }

         fde_instrs = data;
         fde_ilen   = ciefde_start + ciefde_len + sizeof(UInt) - data;
         if (si->trace_cfi) {
            VG_(printf)("fde.instrs      = %p\n", fde_instrs);
            VG_(printf)("fde.ilen        = %d\n", (Int)fde_ilen);
	 }

         if (fde_ilen < 0 || fde_ilen > ehframe_sz) {
            how = "implausible # fde insns";
            goto bad;
         }

	 data += fde_ilen;

         adi.encoding      = the_CIEs[cie].address_encoding;
         adi.ehframe_image = ehframe_image;
         adi.ehframe_avma  = ehframe_avma;
         adi.text_bias     = si->text_bias;

         if (si->trace_cfi)
            show_CF_instructions( fde_instrs, fde_ilen, &adi,
                                  the_CIEs[cie].code_a_f,
                                  the_CIEs[cie].data_a_f );

	 initUnwindContext(&ctx);
         ctx.code_a_f = the_CIEs[cie].code_a_f;
         ctx.data_a_f = the_CIEs[cie].data_a_f;
         ctx.initloc  = fde_initloc;
         ctx.ra_reg   = the_CIEs[cie].ra_reg;
         ctx.exprs    = VG_(newXA)( symtab_alloc, symtab_free, 
                                    sizeof(CfiExpr) );
         vg_assert(ctx.exprs);

	 /* Run the CIE's instructions.  Ugly hack: if
            --debug-dump=frames is in effect, suppress output for
            these instructions since they will already have been shown
            at the time the CIE was first encountered.  Note, not
            thread safe - if this reader is ever made threaded, should
            fix properly. */
	 { Bool hack = si->ddump_frames; 
           si->ddump_frames = False;
           initUnwindContext(&restore_ctx);
           ok = run_CF_instructions(
                   si, False, &ctx, the_CIEs[cie].instrs, 
                   the_CIEs[cie].ilen, 0, NULL, &adi
                );
           si->ddump_frames = hack;
         }
         /* And now run the instructions for the FDE, starting from
            the state created by running the CIE preamble
            instructions. */
         if (ok) {
            restore_ctx = ctx;
	    ok = run_CF_instructions(
                    si, True, &ctx, fde_instrs, fde_ilen, fde_arange, 
                    &restore_ctx, &adi
                 );
            if (si->ddump_frames)
               VG_(printf)("\n");
	 }

         VG_(deleteXA)( ctx.exprs );
      }
   }

   return;

   bad:
    if (!VG_(clo_xml) && VG_(clo_verbosity) > 1)
       VG_(message)(Vg_UserMsg, "Warning: %s in DWARF2 CFI reading", how);
    return;
}


/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
