/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer
 *      in the documentation and/or other materials provided with the
 *      distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef _LIBACPI_H
#define _LIBACPI_H

#include "libfdt.h"

#pragma pack(1)
typedef struct {
  uint32_t  Signature;			/* ASCII Table identifier */
  uint32_t  Length;			/* Length of the table, including the header */
  uint8_t   Revision;			/* Revision of the structure */
  uint8_t   Checksum;			/* Sum of all fields must be 0 */
  uint8_t   OemId[6];			/* ASCII OEM identifier */
  uint64_t  OemTableId;			/* ASCII OEM table identifier */
  uint32_t  OemRevision;		/* OEM supplied revision number */
  uint32_t  CreatorId;			/* Vendor ID of utility creator of the table */
  uint32_t  CreatorRevision;		/* Revision of utility creator of the table */
} EFI_ACPI_DESCRIPTION_HEADER;
#pragma pack()

/**********************************************************************/
/* General functions                                                  */
/**********************************************************************/
#define acpi_get_header(acpi, field) \
  ((const EFI_ACPI_DESCRIPTION_HEADER *)(acpi))->field
#define acpi_signature(acpi)		(acpi_get_header(acpi, Signature))
#define acpi_length(acpi)		(acpi_get_header(acpi, Length))

/* convert 2 bytes ASCII to uint16 */
#define SIGNATURE_16(A, B)		((A) | (B << 8))
/* convert 4 bytes ASCII to uint32 */
#define SIGNATURE_32(A, B, C, D)	((SIGNATURE_16 (A, B)) | (SIGNATURE_16 (C, D) << 16))
/* convert 8 bytes ASCII to uint64 */
#define SIGNATURE_64(A, B, C, D, E, F, G, H) \
    (SIGNATURE_32 (A, B, C, D) | ((UINT64) (SIGNATURE_32 (E, F, G, H)) << 32))

#define SSDT_MAGIC		(const unsigned)SIGNATURE_32('S', 'S', 'D', 'T')
#define DSDT_MAGIC		(const unsigned)SIGNATURE_32('D', 'S', 'D', 'T')

#define ACPI_TABLE_MAGIC	0x41435049

/* checksum byte by byte for acpi table */
uint8_t acpi_csum(const void *base, int n);

#endif /* ifndef _LIBACPI_H */
