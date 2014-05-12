import sys, string

# SYS_OPEN_VMLINUX
# c1143c20:	      55                      push   ebp
# c1143c21:       89 e5                   mov    ebp,esp
# c1143c23:       83 ec 10                sub    esp,0x10
# c1143c26:       89 5d f4                mov    DWORD PTR [ebp-0xc],ebx
# c1143c29:       89 75 f8                mov    DWORD PTR [ebp-0x8],esi
# c1143c2c:       89 7d fc                mov    DWORD PTR [ebp-0x4],edi
# c1143c2f:       e8 74 bb 46 00          call   0xc15af7a8 <| STUB c3/RET
# ...


# SYS_OPEN_VIRTUAL
# JUNK JUNK 
# [259417.843574] + virtual memory for sys_open {c1143c20}
# [259417.843575] [0xCAFEBABE] START DUMP
# [259417.843577] 55 89 e5 83 ec 10 89 5d f4 89 75 f8 89 7d fc 3e  U......]..u..}.>
# [259417.843578] 8d 74 26 00 b8 9c ff ff ff 8b 7d 08 8b 75 0c 8b  .t&.......}..u..
# [259417.843584] 5d 10 89 fa 89 f1 89 1c 24 e8 e2 fd ff ff 8b 5d  ].......$......]
# ...
# [259417.843614] [0xCAFEBABE] END DUMP

def op_is_stub(dismatch_op):
    print 'dismatched %s' % dismatch_op
    for op, dis_op in zip(['e8', '74', 'bb', '46'], dismatch_op):
        if op == dis_op:
            print 'stub find {%s}' % op
        else:
            print 'hijacking detected'
            return False
    return True


def diff_and_remove_stub(opcodesVMLinux, opcodesVIRTUAL):
    count = 0
    dismatch_op = []
    for  Instr in opcodesVMLinux:
        for op in Instr:
            if op == opcodesVIRTUAL[count]:
                pass
            else: 
                print 'op {%s} and {%s} dismatch' % \
                (op, opcodesVIRTUAL[count])
                dismatch_op.append(op)
            count += 1
    return op_is_stub(dismatch_op)

def match_hex_files(VMLinuxFile, VIRTUALFile):
        opcodesVMLinux = []
        opcodesVIRTUAL = []

        with open(VMLinuxFile) as vmf:
            for vmLine in vmf:
                opcode = []
                for x in vmLine.split()[1:]:
                    if all(c in string.hexdigits for c in x) == True:
                        opcode.append(x)
                    else:
                        opcodesVMLinux.append(opcode)
                        break

        with open(VIRTUALFile) as virtf:
            START_VIRTUALKEYWORD='[0xCAFEBABE] START DUMP'
            record = False
            for virtLine in virtf:
                if record is False and  START_VIRTUALKEYWORD in virtLine:
                    record = True
                elif record is True:
                    for op in virtLine.split()[1:]:
                        if all(c in string.hexdigits for c in op) == True:
                            opcodesVIRTUAL.append(op)

        print "opcodes VMlinux: (%s)\n" % opcodesVMLinux
        print "opcodes Virtual: (%s)\n" % opcodesVIRTUAL

        diff_and_remove_stub(opcodesVMLinux, opcodesVIRTUAL)

def main(argvs):
    print 'usage {%s} SYS_OPEN_VMLINUX_FILE SYS_OPEN_VIRTUAL.FILE\n' % argvs[0]
    match_hex_files(argvs[1], argvs[2])

if __name__ == "__main__":
    main(sys.argv)
