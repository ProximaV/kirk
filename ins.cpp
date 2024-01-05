/* KIRK IDP instructions - (c) Proxima 2023
*/

#include "kirk.hpp"
instruc_t Instructions[] =
{

{ "",            0                             }, //unknown                                                   
{ "--invalid--", 0                             }, //--invalid--                                               
{ "store",       CF_CHG1 | CF_USE2             }, //store             ($addr1),$data                          
{ "mov32",       CF_CHG1 | CF_USE2             }, //mov32            ($addr1), ($addr1)                        
{ "op0D",        CF_CHG1 | CF_USE2             }, //op0D            ($addr1), ($addr1)                        
{ "op0E",        CF_CHG1 | CF_USE2             }, //op0E            ($addr1), ($addr1)                        
{ "cmp",         CF_USE1 | CF_USE2             }, //cmp            ($addr1),$data                             
{ "op12",        CF_USE1 | CF_USE2             }, //op12          ($addr1),$data                              
{ "op13",        CF_CHG1 | CF_USE2             }, //op13            ($addr1), ($addr1)                        
{ "xor32",       CF_CHG1 | CF_USE2             }, //xor32            ($addr1), ($addr1)                        
{ "addi",        CF_CHG1 | CF_USE2             }, //addi             ($addr1),$data                           
{ "adda",        CF_CHG1 | CF_USE2             }, //adda            ($addr1), ($addr1)                        
{ "op21",        CF_USE1 | CF_USE2             }, //op21            ($addr1),$data                            
{ "sub",         CF_CHG1 | CF_USE2             }, //sub             ($addr1),$data                           
{ "andi",        CF_CHG1 | CF_USE2             }, //andi             ($addr1),$data                           
{ "ori",         CF_CHG1 | CF_USE2             }, //ori             ($addr1),$data                            
{ "mov16",       CF_CHG1 | CF_USE2             }, //mov16           ($addr1), ($addr1)                         
{ "op44",        CF_CHG1 | CF_USE2             }, //op44           ($addr1), ($addr1)                         
{ "op49",        CF_CHG1 | CF_USE2             }, //op49             ($addr1),$data                           
{ "op4B",        CF_CHG1 | CF_USE2             }, //op4B            ($addr1), ($addr1)                        
{ "mov128",      CF_CHG1 | CF_USE2             }, //mov128            ($addr1), ($addr1)                        
{ "inc32",       CF_CHG1                       }, //inc32            ($addr1), $imm                            
{ "dec32",       CF_CHG1                       }, //dec32            ($addr1), $imm                            
{ "lsh",         CF_SHFT | CF_CHG1 | CF_USE2   }, //lsh            ($addr1), $imm                            
{ "rsh",         CF_SHFT | CF_CHG1 | CF_USE2   }, //rsh            ($addr1), $imm                            
{ "setmode",     CF_CHG1 | CF_USE2             }, //setmode            ($addr1), $imm                            
{ "byteswap",    CF_CHG1 | CF_USE2             }, //byteswap            ($addr1), $imm                            
{ "test",        CF_CHG1 | CF_USE2             }, //test            ($addr1), $imm                            
{ "bitset",      CF_CHG1 | CF_USE2             }, //bitset            ($addr1), $imm                            
{ "bitclear",    CF_CHG1 | CF_USE2             }, //bitclear            ($addr1), $imm                            
{ "clrz",        0                             }, //clrz            $imm, $imm                                
{ "setz",        0                             }, //setz            $imm, $imm                                
{ "b",           CF_USE1 | CF_STOP | CF_JUMP   }, //bra $branch                                               
{ "bnz",         CF_USE1                       }, //bne $addr                                                 
{ "bz",          CF_USE1                       }, //beq $addr                                                 
{ "bgt",         CF_USE1                       }, //bgt $addr                                                 
{ "blt",         CF_USE1                       }, //blt $addr                                                 
{ "call",        CF_USE1 | CF_CALL             }, //call $addr                                                
{ "call2",       CF_USE1 | CF_CALL             }, //call2 $addr - this is a dara error only - E8 is the real instruction                                               
{ "ret",         CF_STOP                       }, //ret
{ "intr",        CF_USE1 | CF_USE2             }, // intr            $imm, $imm                                
                                                                                                             
};
