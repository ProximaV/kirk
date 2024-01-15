/* KIRK IDP instructions - (c) Proxima 2023
*/

#include "kirk.hpp"
instruc_t Instructions[] =
{

{ "",            0                             }, //unknown                                                   
{ "--invalid--", 0                             }, //--invalid--                                               
{ "store",       CF_CHG1 | CF_USE2             }, //store             ($addr1),$data                          
{ "mov32",       CF_CHG1 | CF_USE2             }, //mov32            ($addr1), ($addr1)                        
{ "mov32a",      CF_CHG1 | CF_USE2             }, //op0D            ($addr1), ($addr1)                        
{ "mov32aa",     CF_CHG1 | CF_USE2             }, //op0E            ($addr1), ($addr1)                        
{ "cmpi",        CF_USE1 | CF_USE2             }, //cmp            ($addr1),$data                             
{ "cmp+",        CF_USE1 | CF_USE2             }, //cmp+          ($addr1),$data                              
{ "cmpa",        CF_CHG1 | CF_USE2             }, //op13            ($addr1), ($addr1)                        
{ "suba",        CF_CHG1 | CF_USE2             }, //suba            ($addr1), ($addr1)                        
{ "addi",        CF_CHG1 | CF_USE2             }, //addi             ($addr1),$data                           
{ "adda",        CF_CHG1 | CF_USE2             }, //adda            ($addr1), ($addr1)                        
{ "addc",        CF_CHG1                       }, //addc            ($addr1)                            
{ "subi",        CF_CHG1 | CF_USE2             }, //subi             ($addr1),$data                           
{ "andi",        CF_CHG1 | CF_USE2             }, //andi             ($addr1),$data                           
{ "anda",        CF_CHG1 | CF_USE2             }, //andiu             ($addr1),$data                            
{ "mov16",       CF_CHG1 | CF_USE2             }, //mov16           ($addr1), ($addr1)                         
{ "ora",         CF_CHG1 | CF_USE2             }, //ora           ($addr1), ($addr1)                         
{ "xori",        CF_CHG1 | CF_USE2             }, //xori             ($addr1),$data                           
{ "xora",        CF_CHG1 | CF_USE2             }, //xora            ($addr1), ($addr1)                        
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
