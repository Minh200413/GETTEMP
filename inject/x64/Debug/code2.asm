section .text
      global _start
start:
   mov ax, 0x100
   mov bx, 0xFFF
   sub ax, bx      
