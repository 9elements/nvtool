"tpm-nvtool\n"
"Copyright (c) 2009,2010 The Chromium OS Authors. All rights reserved.\n"
"\n"
"tpm-nvtool is a command-line program for managing Trusted Platform Module \n"
"(TPM) Non-Volatile (NV) memory. It allows you to \"define\" (create) and\n"
"\"release\" (destroy) stores in a TPM's NV memory component. It requires a\n"
"TPM that complies with TPM Specification version 1.2.\n"
"\n"
"Usage:\n"
"\n"
"* Creating an NV store\n"
"\n"
"  --define --index INDEX --owner_password OWNER_PASSWORD --size SIZE \\\n"
"    [--pcr PCR] [--permissions PERMISSIONS] [--index_password INDEX_PASSWORD]\n"
"    [--rlocalities LOCALITIES] [--wlocalities LOCALITIES]\n"
"\n"
"  The parameters mean the following:\n"
"\n"
"  INDEX           A valid NV index\n"
"  OWNER_PASSWORD  TPM owner password\n"
"  SIZE            Requested NV store's size in bytes\n"
"  PCR             A PCR whose value will be required to read or write to the\n"
"                  NV store; multiple PCRs can be specified through multiple\n"
"                  instances of this argument\n"
"  PERMISSIONS     A comma-separated string consisting of zero or more of the\n"
"                  following keywords:\n"
"\n"
"                    AUTHREAD      Reads authorized by INDEX_PASSWORD\n"
"                    AUTHWRITE     Writes authorized by INDEX_PASSWORD\n"
"                    OWNERREAD     Reads authorized by OWNER_PASSWORD\n"
"                    OWNERWRITE    Writes authorized by OWNER_PASSWORD\n"
"                    PPREAD        Reads authorized by Physical Presence\n"
"                    PPWRITE       Writes authorized by Physical Presence\n"
"                    READ_STCLEAR  Cannot be read after a zero-sized write;\n"
"                                  will need a full TPM clear to unlock\n"
"                    WRITE_STCLEAR Cannot be written after a zero-sized write\n"
"                                  will need a full TPM clear to unlock\n"
"                    WRITEALL      Data must be written all at once\n"
"                      \n"
"  INDEX_PASSWORD  Password for reading and/or writing to the NV store; required\n"
"                  if PERMISSIONS has AUTHREAD or AUTHWRITE\n"
"  \n"
"  LOCALITIES      A comma-separated string consisting of zero or more of the\n"
"                  following keywords:\n"
"\n"
"                    LOCALITY_ZERO  TPM locality zero\n"
"                    LOCALITY_ONE   TPM locality one\n"
"                    LOCALITY_TWO   TPM locality two\n"
"                    LOCALITY_THREE TPM locality three\n"
"                    LOCALITY_FOUR  TPM locality four\n"
"\n"
"* Destroying an NV store\n"
"\n"
"  --release --index INDEX --owner_password OWNER_PASSWORD\n"
"\n"
"* Listing NV stores\n"
"\n"
"  --list [--index INDEX]\n"
"\n"
"  By default, all NV stores will be listed. If INDEX is specified, only that\n"
"  index, if it exists, will be listed.\n"
"\n"
"* Reading from an NV store\n"
"\n"
"  --read --index INDEX [--size SIZE] [--offset OFFSET] [--hexdump] \\\n"
"    [--password PASSWORD]\n"
"\n"
"  The parameters mean the following:\n"
"\n"
"  INDEX           A valid, existing NV index\n"
"  SIZE            Number of bytes to read; if specified, must be greater than\n"
"                  zero and no larger than the NV store's size; if not specified,\n"
"                  the entire NV store will be read\n"
"  OFFSET          Offset in bytes to read from; if specified, it must be such\n"
"                  that the requested data specified through OFFSET and SIZE\n"
"                  lies within the NV store; if not specified, an offset of 0\n"
"                  is implied\n"
"  PASSWORD        The appropriate password needed for reading\n"
"\n"
"  By default, data read from the NV store will be dumped as is (raw) to the\n"
"  standard output, which in turn can be redirected to a file. If --hexdump is\n"
"  specified, data bytes will be printed in hexadecimal format instead.o\n"
"\n"
"* Writing to an NV store\n"
"\n"
"  --write --index INDEX --string STRING [--size SIZE] [--offset OFFSET] \\\n"
"    [--password PASSWORD]\n"
"\n"
"  The parameters mean the following:\n"
"  \n"
"  STRING          A null-terminated string that will be written to the NV store\n"
"  SIZE            Number of bytes to write; if SIZE is not specified, the entire\n"
"                  length of the string (not including the terminating null) is\n"
"                  written, provided it fits in the NV store\n"
"  OFFSET          Offset in the NV store to write to; if not specified, an\n"
"                  offset of 0 is implied\n"
"  PASSWORD        The appropriate password needed for reading\n"
"\n"
"  You can also specify a file instead of an inline string as the source of\n"
"  data to write to the NV store:\n"
"\n"
"  --write --index INDEX --file PATH [--size SIZE] [--offset OFFSET] \\\n"
"    [--password PASSWORD]\n"
"\n"
"* Locking an NV store\n"
"\n"
"  --writezero --index INDEX [--password PASSWORD]\n"
"\n"
"  If the NV store's permission attributes contain READ_STCLEAR or WRITE_STCLEAR,\n"
"  using --writezero will lock that store for reading or writing, respectively.\n"
"\n"
