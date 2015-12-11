/*===- util.h - SVA Utilities ---------------------------------------------===
 * 
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *===----------------------------------------------------------------------===
 *
 * This header file contains utility definitions that are exported to the
 * SVA Execution Engine but not to the operating system kernel.
 *
 *===----------------------------------------------------------------------===
 */

#ifndef _SVA_UTIL_H
#define _SVA_UTIL_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Function: set_kernel_pcid()
 *
 * Description:
 *  Sets the current PCID to be the kernel's. This prevents the kernel from
 *  accessing cached page table information that is associated with a different
 *  PCID.
 */
static inline void
set_kernel_pcid () {
  static const unsigned int reset_pcid  = 0x111u; 
  static const unsigned int kernel_pcid = 0x001u;
  unsigned int cr3;

  /* Set PCID to kernel_pcid */
  __asm__ __volatile__ ("mov %%cr3, %0\n"
                        "and %2, %0\n"
                        "or  %1, %0\n"
                        "mov %0, %%cr3\n"
                        : "=&r" (cr3)
                        : "r" (kernel_pcid), "r" (~reset_pcid));

  return;
}

/*
 * Function: set_sva_pcid()
 *
 * Description:
 *  Sets the current PCID to be SVA's. This should only be called when there
 *  is no chance that control could pass to the kernel. 
 */
static inline void
set_sva_pcid () {
  static const unsigned int reset_pcid = 0x111u; 
  static const unsigned int sva_pcid   = 0x002u;
  unsigned int cr3;

  /* Set PCID to sva_pcid */
  __asm__ __volatile__ ("mov %%cr3, %0\n"
                        "and %2, %0\n"
                        "or  %1, %0\n"
                        "mov %0, %%cr3\n"
                        : "=&r" (cr3)
                        : "r" (sva_pcid), "r" (~reset_pcid));

  return;
}

/* 
 * Function: is_pcid_supported()
 *
 * Description:
 *  Checks if the processor supports PCIDs. 
 *
 * Return value:
 *  1 - PCIDs are supported
 *  0 - PCIDs are not supported
 */
static inline unsigned char
is_pcid_supported () {
  const unsigned int pcid = 0x00020000u; // Bit 17
  unsigned int cpuid;

  __asm__ __volatile__ ("mov $0x1, %%eax\n"
                        "cpuid\n"
                        : "=c" (cpuid)
                        :
                        : "%ecx", "%eax", "%edx");

  return ((cpuid & pcid) != 0);
}

static inline void
sva_check_memory_read (void * memory, unsigned int size) {
  volatile unsigned char value;
  volatile unsigned char * p = (unsigned char *)(memory);

  /*
   * For now, we assume that all memory buffers are less than 4K in size, so
   * they can only be in two pages at most.
   */
  value = p[0];
  value = p[size - 1];
  return;
} 

static inline void
sva_check_memory_write (void * memory, unsigned int size) {
  volatile unsigned char value1;
  volatile unsigned char value2;
  volatile unsigned char * p = (unsigned char *)memory;

  /*
   * For now, we assume that all memory buffers are less than 4K in size, so
   * they can only be in two pages at most.
   */
  value1 = p[0];
  p[0] = value1;
  value2 = p[size - 1];
  p[size - 1] = value2;
  return;
}

/*
 * Function: sva_enter_critical()
 *
 * Description:
 *  Enter an SVA critical section.  This basically means that we need to
 *  disable interrupts so that the intrinsic acts like a single,
 *  uninterruptable instruction.
 */
static inline unsigned long
sva_enter_critical (void) {
  unsigned long rflags;
  __asm__ __volatile__ ("pushfq\n"
                        "popq %0\n"
                        "cli\n" : "=r" (rflags));
  return rflags;
}

/*
 * Function: sva_exit_critical()
 *
 * Description:
 *  Exit an SVA critical section.  This basically means that we need to
 *  enable interrupts if they had been enabled before the intrinsic was
 *  executed.
 */
static inline void
sva_exit_critical (unsigned long rflags) {
  if (rflags & 0x00000200)
    __asm__ __volatile__ ("sti":::"memory");
  return;
}

/*
 * Function: isNotWithinSecureMemory()
 *
 * Description:
 *  Determine if the specified pointer is within the secure memory region.
 *
 * Return value:
 *  true - The pointer is *not* within the secure memory region.
 *  false - The pointer is within the secure memory region.
 */
static inline unsigned char
isNotWithinSecureMemory (void * p) {
  const uintptr_t secmemstart = 0xffffff0000000000u;
  const uintptr_t secmemend   = 0xffffff8000000000u;
  uintptr_t i = (uintptr_t) p;
  if ((secmemstart <= i) && (i <= secmemend))
    return 0;
  else
    return 1;
}

static inline void
bochsBreak (void) {
  __asm__ __volatile__ ("xchg %bx, %bx\n");
  return;
}

#ifdef __cplusplus
}
#endif

#endif /* _SVA_UTIL_H */
