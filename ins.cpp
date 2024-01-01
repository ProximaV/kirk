/* KIRK IDP instructions - (c) Proxima 2023
*/

#include "kirk.hpp"
instruc_t Instructions[] =
{

{ "",           0                             }, //unknown                                                   
{ "--invalid--",0                             }, //--invalid--                                               
{ "store",      CF_CHG1 | CF_USE2             }, //store             ($addr1),$data                          
{ "mov32",       CF_CHG1 | CF_USE2             }, //op0B            ($addr1), ($addr1)                        
{ "op0D",       CF_CHG1 | CF_USE2             }, //op0D            ($addr1), ($addr1)                        
{ "op0E",       CF_CHG1 | CF_USE2             }, //op0E            ($addr1), ($addr1)                        
{ "cmp",        CF_USE1 | CF_USE2             }, //cmp            ($addr1),$data                             
{ "op12",       CF_USE1 | CF_USE2             }, //op12          ($addr1),$data                              
{ "op13",       CF_CHG1 | CF_USE2             }, //op13            ($addr1), ($addr1)                        
{ "op16",       CF_CHG1 | CF_USE2             }, //op16            ($addr1), ($addr1)                        
{ "add",       CF_CHG1 | CF_USE2             }, //op19             ($addr1),$data                           
{ "op1B",       CF_CHG1 | CF_USE2             }, //op1B            ($addr1), ($addr1)                        
{ "op21",       CF_USE1 | CF_USE2             }, //op21            ($addr1),$data                            
{ "sub",       CF_CHG1 | CF_USE2             }, //op29             ($addr1),$data                           
{ "or",       CF_CHG1 | CF_USE2             }, //op39             ($addr1),$data                           
{ "and",        CF_CHG1 | CF_USE2             }, //and             ($addr1),$data                            
{ "op43",       CF_CHG1 | CF_USE2             }, //op43           ($addr1), ($addr1)                         
{ "op44",       CF_CHG1 | CF_USE2             }, //op44           ($addr1), ($addr1)                         
{ "op49",       CF_CHG1 | CF_USE2             }, //op49             ($addr1),$data                           
{ "op4B",       CF_CHG1 | CF_USE2             }, //op4B            ($addr1), ($addr1)                        
{ "mov128",       CF_CHG1 | CF_USE2             }, //op53            ($addr1), ($addr1)                        
{ "op80",       CF_CHG1                       }, //op80            ($addr1), $imm                            
{ "op88",       CF_CHG1                       }, //op88            ($addr1), $imm                            
{ "op90",       CF_CHG1 | CF_USE2             }, //op90            ($addr1), $imm                            
{ "nand",       CF_CHG1 | CF_USE2             }, //op98            ($addr1), $imm                            
{ "opA0",       CF_CHG1 | CF_USE2             }, //opA0            ($addr1), $imm                            
{ "opB0",       CF_CHG1 | CF_USE2             }, //opB0            ($addr1), $imm                            
{ "test",       CF_CHG1 | CF_USE2             }, //test            ($addr1), $imm                            
{ "opC8",       CF_CHG1 | CF_USE2             }, //opC8            ($addr1), $imm                            
{ "opD0",       CF_CHG1 | CF_USE2             }, //opD0            ($addr1), $imm                            
{ "opDA",       CF_USE1 | CF_USE2             }, //opDA            $imm, $imm                                
{ "opDB",       CF_USE1 | CF_USE2             }, //opDB            $imm, $imm                                
{ "bra",        CF_USE1 | CF_STOP | CF_JUMP   }, //bra $branch                                               
{ "bne",        CF_USE1                       }, //bne $addr                                                 
{ "beq",        CF_USE1                       }, //beq $addr                                                 
{ "bgt",        CF_USE1                       }, //bge $addr                                                 
{ "blt",        CF_USE1                       }, //ble $addr                                                 
{ "call",       CF_USE1 | CF_CALL             }, //call $addr                                                
{ "call2",      CF_USE1 | CF_CALL             }, //call2 $addr                                               
{ "ret",        CF_STOP                       }, //ret
{ "hw_crypto_hash_dma",       CF_USE1 | CF_USE2             }, // hwn_aes_encdec            $imm, $imm                                
                                                                                                             
};
