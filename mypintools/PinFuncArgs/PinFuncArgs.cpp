// NOTE, taint spread code derived from copyright below with modifications to
// correct it. 
//
//  Jonathan Salwan - Copyright (C) 2013-08
// 
//  http://shell-storm.org
//  http://twitter.com/JonathanSalwan
//
//  Note: Example 3 - http://shell-storm.org/blog/Taint-analysis-with-Pin/
//        Spread the taint in memory/registers and follow your data.
//

#include "pin.H"
#include <asm/unistd.h>
#include <fstream>
#include <iostream>
#include <list>

std::list<UINT64> addressTainted;
std::list<REG> regsTainted;

INT32 Usage()
{
    std::cerr << "Ex 3" << std::endl;
    return -1;
}

bool checkAlreadyRegTainted(REG reg)
{
  std::list<REG>::iterator i;

  for(i = regsTainted.begin(); i != regsTainted.end(); i++){
    if (*i == reg){
      return true;
    }
  }
  return false;
}

VOID removeMemTainted(UINT64 addr)
{
  addressTainted.remove(addr);
  std::cout << std::hex << "\t\t\t" << addr << " is now freed" << std::endl;
}

VOID addMemTainted(UINT64 addr)
{
  addressTainted.push_back(addr);
  std::cout << std::hex << "\t\t\t" << addr << " is now tainted" << std::endl;
}

bool taintReg(REG reg)
{
  if (checkAlreadyRegTainted(reg) == true){
    std::cout << "\t\t\t" << REG_StringShort(reg) << " is already tainted" << std::endl;
    return false;
  }

  switch(reg){

    case REG_RAX:  regsTainted.push_front(REG_RAX);
    case REG_EAX:  regsTainted.push_front(REG_EAX); 
    case REG_AX:   regsTainted.push_front(REG_AX); 
    case REG_AH:   regsTainted.push_front(REG_AH); 
    case REG_AL:   regsTainted.push_front(REG_AL); 
         break;

    case REG_RBX:  regsTainted.push_front(REG_RBX);
    case REG_EBX:  regsTainted.push_front(REG_EBX);
    case REG_BX:   regsTainted.push_front(REG_BX);
    case REG_BH:   regsTainted.push_front(REG_BH);
    case REG_BL:   regsTainted.push_front(REG_BL);
         break;

    case REG_RCX:  regsTainted.push_front(REG_RCX); 
    case REG_ECX:  regsTainted.push_front(REG_ECX);
    case REG_CX:   regsTainted.push_front(REG_CX);
    case REG_CH:   regsTainted.push_front(REG_CH);
    case REG_CL:   regsTainted.push_front(REG_CL);
         break;

    case REG_RDX:  regsTainted.push_front(REG_RDX); 
    case REG_EDX:  regsTainted.push_front(REG_EDX); 
    case REG_DX:   regsTainted.push_front(REG_DX); 
    case REG_DH:   regsTainted.push_front(REG_DH); 
    case REG_DL:   regsTainted.push_front(REG_DL); 
         break;

    case REG_RDI:  regsTainted.push_front(REG_RDI); 
    case REG_EDI:  regsTainted.push_front(REG_EDI); 
    case REG_DI:   regsTainted.push_front(REG_DI); 
    case REG_DIL:  regsTainted.push_front(REG_DIL); 
         break;

    case REG_RSI:  regsTainted.push_front(REG_RSI); 
    case REG_ESI:  regsTainted.push_front(REG_ESI); 
    case REG_SI:   regsTainted.push_front(REG_SI); 
    case REG_SIL:  regsTainted.push_front(REG_SIL); 
         break;
    
    case REG_R8:   regsTainted.push_front(REG_R8); 
    case REG_R8D:  regsTainted.push_front(REG_R8D); 
    case REG_R8W:  regsTainted.push_front(REG_R8W); 
    case REG_R8B:  regsTainted.push_front(REG_R8B); 
         break;
    
    case REG_R9:   regsTainted.push_front(REG_R9); 
    case REG_R9D:  regsTainted.push_front(REG_R9D); 
    case REG_R9W:  regsTainted.push_front(REG_R9W); 
    case REG_R9B:  regsTainted.push_front(REG_R9B); 
         break;

    case REG_R10:   regsTainted.push_front(REG_R10); 
    case REG_R10D:  regsTainted.push_front(REG_R10D); 
    case REG_R10W:  regsTainted.push_front(REG_R10W); 
    case REG_R10B:  regsTainted.push_front(REG_R10B); 
         break;
    
    case REG_R11:   regsTainted.push_front(REG_R11); 
    case REG_R11D:  regsTainted.push_front(REG_R11D); 
    case REG_R11W:  regsTainted.push_front(REG_R11W); 
    case REG_R11B:  regsTainted.push_front(REG_R11B); 
         break;
    
    case REG_R12:   regsTainted.push_front(REG_R12); 
    case REG_R12D:  regsTainted.push_front(REG_R12D); 
    case REG_R12W:  regsTainted.push_front(REG_R12W); 
    case REG_R12B:  regsTainted.push_front(REG_R12B); 
         break;
    
    case REG_R13:   regsTainted.push_front(REG_R13); 
    case REG_R13D:  regsTainted.push_front(REG_R13D); 
    case REG_R13W:  regsTainted.push_front(REG_R13W); 
    case REG_R13B:  regsTainted.push_front(REG_R13B); 
         break;
    
    case REG_R14:   regsTainted.push_front(REG_R14); 
    case REG_R14D:  regsTainted.push_front(REG_R14D); 
    case REG_R14W:  regsTainted.push_front(REG_R14W); 
    case REG_R14B:  regsTainted.push_front(REG_R14B); 
         break;
    
    case REG_R15:   regsTainted.push_front(REG_R15); 
    case REG_R15D:  regsTainted.push_front(REG_R15D); 
    case REG_R15W:  regsTainted.push_front(REG_R15W); 
    case REG_R15B:  regsTainted.push_front(REG_R15B); 
         break;
    
    default:
      std::cout << "\t\t\t" << REG_StringShort(reg) << " can't be tainted" << std::endl;
      return false;
  }
  std::cout << "\t\t\t" << REG_StringShort(reg) << " is now tainted" << std::endl;
  return true;
}

bool removeRegTainted(REG reg)
{
  switch(reg){

    case REG_RAX:  regsTainted.remove(REG_RAX);
    case REG_EAX:  regsTainted.remove(REG_EAX);
    case REG_AX:   regsTainted.remove(REG_AX);
    case REG_AH:   regsTainted.remove(REG_AH);
    case REG_AL:   regsTainted.remove(REG_AL);
         break;

    case REG_RBX:  regsTainted.remove(REG_RBX);
    case REG_EBX:  regsTainted.remove(REG_EBX);
    case REG_BX:   regsTainted.remove(REG_BX);
    case REG_BH:   regsTainted.remove(REG_BH);
    case REG_BL:   regsTainted.remove(REG_BL);
         break;

    case REG_RCX:  regsTainted.remove(REG_RCX); 
    case REG_ECX:  regsTainted.remove(REG_ECX);
    case REG_CX:   regsTainted.remove(REG_CX);
    case REG_CH:   regsTainted.remove(REG_CH);
    case REG_CL:   regsTainted.remove(REG_CL);
         break;

    case REG_RDX:  regsTainted.remove(REG_RDX); 
    case REG_EDX:  regsTainted.remove(REG_EDX); 
    case REG_DX:   regsTainted.remove(REG_DX); 
    case REG_DH:   regsTainted.remove(REG_DH); 
    case REG_DL:   regsTainted.remove(REG_DL); 
         break;

    case REG_RDI:  regsTainted.remove(REG_RDI); 
    case REG_EDI:  regsTainted.remove(REG_EDI); 
    case REG_DI:   regsTainted.remove(REG_DI); 
    case REG_DIL:  regsTainted.remove(REG_DIL); 
         break;

    case REG_RSI:  regsTainted.remove(REG_RSI); 
    case REG_ESI:  regsTainted.remove(REG_ESI); 
    case REG_SI:   regsTainted.remove(REG_SI); 
    case REG_SIL:  regsTainted.remove(REG_SIL); 
         break;
    
    case REG_R8:   regsTainted.remove(REG_R8); 
    case REG_R8D:  regsTainted.remove(REG_R8D); 
    case REG_R8W:  regsTainted.remove(REG_R8W); 
    case REG_R8B:  regsTainted.remove(REG_R8B); 
         break;
    
    case REG_R9:   regsTainted.remove(REG_R9); 
    case REG_R9D:  regsTainted.remove(REG_R9D); 
    case REG_R9W:  regsTainted.remove(REG_R9W); 
    case REG_R9B:  regsTainted.remove(REG_R9B); 
         break;

    case REG_R10:   regsTainted.remove(REG_R10); 
    case REG_R10D:  regsTainted.remove(REG_R10D); 
    case REG_R10W:  regsTainted.remove(REG_R10W); 
    case REG_R10B:  regsTainted.remove(REG_R10B); 
         break;
    
    case REG_R11:   regsTainted.remove(REG_R11); 
    case REG_R11D:  regsTainted.remove(REG_R11D); 
    case REG_R11W:  regsTainted.remove(REG_R11W); 
    case REG_R11B:  regsTainted.remove(REG_R11B); 
         break;
    
    case REG_R12:   regsTainted.remove(REG_R12); 
    case REG_R12D:  regsTainted.remove(REG_R12D); 
    case REG_R12W:  regsTainted.remove(REG_R12W); 
    case REG_R12B:  regsTainted.remove(REG_R12B); 
         break;
    
    case REG_R13:   regsTainted.remove(REG_R13); 
    case REG_R13D:  regsTainted.remove(REG_R13D); 
    case REG_R13W:  regsTainted.remove(REG_R13W); 
    case REG_R13B:  regsTainted.remove(REG_R13B); 
         break;
    
    case REG_R14:   regsTainted.remove(REG_R14); 
    case REG_R14D:  regsTainted.remove(REG_R14D); 
    case REG_R14W:  regsTainted.remove(REG_R14W); 
    case REG_R14B:  regsTainted.remove(REG_R14B); 
         break;
    
    case REG_R15:   regsTainted.remove(REG_R15); 
    case REG_R15D:  regsTainted.remove(REG_R15D); 
    case REG_R15W:  regsTainted.remove(REG_R15W); 
    case REG_R15B:  regsTainted.remove(REG_R15B); 
         break;

    default:
      std::cout << "\t\t\t" << REG_StringShort(reg) << " can't be freed" << std::endl;
      return false;
  }
  std::cout << "\t\t\t" << REG_StringShort(reg) << " is now freed" << std::endl;
  return true;
}

VOID ReadMem(UINT64 insAddr, std::string insDis, UINT32 opCount, REG reg_r, UINT64 memOp)
{
  std::list<UINT64>::iterator i;
  UINT64 addr = memOp;
  
  if (opCount != 2)
    return;

  for(i = addressTainted.begin(); i != addressTainted.end(); i++){
      if (addr == *i){
        std::cout << std::hex << "[READ in " << addr << "]\t" << insAddr << ": " << insDis << std::endl;
        taintReg(reg_r);
        return ;
      }
  }
  /* if mem != tained and reg == taint => free the reg */
  if (checkAlreadyRegTainted(reg_r)){
    std::cout << std::hex << "[READ in " << addr << "]\t" << insAddr << ": " << insDis << std::endl;
    removeRegTainted(reg_r);
  }
}

VOID WriteMem(UINT64 insAddr, std::string insDis, UINT32 opCount, REG reg_r, UINT64 memOp)
{
  std::list<UINT64>::iterator i;
  UINT64 addr = memOp;

  if (opCount != 2)
    return;

  for(i = addressTainted.begin(); i != addressTainted.end(); i++){
      if (addr == *i){
        std::cout << std::hex << "[WRITE in " << addr << "]\t" << insAddr << ": " << insDis << std::endl;
        if (!REG_valid(reg_r) || !checkAlreadyRegTainted(reg_r))
          removeMemTainted(addr);
        return ;
      }
  }
  if (checkAlreadyRegTainted(reg_r)){
    std::cout << std::hex << "[WRITE in " << addr << "]\t" << insAddr << ": " << insDis << std::endl;
    addMemTainted(addr);
  }
}

VOID spreadRegTaint(UINT64 insAddr, std::string insDis, UINT32 opCount, REG reg_r, REG reg_w)
{
  if (opCount != 2)
    return;

  if (REG_valid(reg_w)){
    if (checkAlreadyRegTainted(reg_w) && (!REG_valid(reg_r) || !checkAlreadyRegTainted(reg_r))){
      std::cout << "[SPREAD]\t\t" << insAddr << ": " << insDis << std::endl;
      std::cout << "\t\t\toutput: "<< REG_StringShort(reg_w) << " | input: " << (REG_valid(reg_r) ? REG_StringShort(reg_r) : "constant") << std::endl;
      removeRegTainted(reg_w);
    }
    else if (!checkAlreadyRegTainted(reg_w) && checkAlreadyRegTainted(reg_r)){
      std::cout << "[SPREAD]\t\t" << insAddr << ": " << insDis << std::endl;
      std::cout << "\t\t\toutput: " << REG_StringShort(reg_w) << " | input: "<< REG_StringShort(reg_r) << std::endl;
      taintReg(reg_w);
    }
  }
}

VOID followData(UINT64 insAddr, std::string insDis, REG reg)
{
  if (!REG_valid(reg))
    return;

  if (checkAlreadyRegTainted(reg)){
      std::cout << "[FOLLOW]\t\t" << insAddr << ": " << insDis << std::endl;
  }
}

VOID Instruction(INS ins, VOID *v)
{
  if (INS_OperandCount(ins) > 1 && INS_MemoryOperandIsRead(ins, 0) && INS_OperandIsReg(ins, 0)){
    INS_InsertCall(
        ins, IPOINT_BEFORE, (AFUNPTR)ReadMem,
        IARG_ADDRINT, INS_Address(ins),
        IARG_PTR, new std::string(INS_Disassemble(ins)),
        IARG_UINT32, INS_OperandCount(ins),
        IARG_UINT32, INS_OperandReg(ins, 0),
        IARG_MEMORYOP_EA, 0,
        IARG_END);
  }
  else if (INS_OperandCount(ins) > 1 && INS_MemoryOperandIsWritten(ins, 0)){
    INS_InsertCall(
        ins, IPOINT_BEFORE, (AFUNPTR)WriteMem,
        IARG_ADDRINT, INS_Address(ins),
        IARG_PTR, new std::string(INS_Disassemble(ins)),
        IARG_UINT32, INS_OperandCount(ins),
        IARG_UINT32, INS_OperandReg(ins, 1),
        IARG_MEMORYOP_EA, 0,
        IARG_END);
  }
  else if (INS_OperandCount(ins) > 1 && INS_OperandIsReg(ins, 0)){
    INS_InsertCall(
        ins, IPOINT_BEFORE, (AFUNPTR)spreadRegTaint,
        IARG_ADDRINT, INS_Address(ins),
        IARG_PTR, new std::string(INS_Disassemble(ins)),
        IARG_UINT32, INS_OperandCount(ins),
        IARG_UINT32, INS_RegR(ins, 0),
        IARG_UINT32, INS_RegW(ins, 0),
        IARG_END);
  }
  
  if (INS_OperandCount(ins) > 1 && INS_OperandIsReg(ins, 0)){
    INS_InsertCall(
        ins, IPOINT_BEFORE, (AFUNPTR)followData,
        IARG_ADDRINT, INS_Address(ins),
        IARG_PTR, new std::string(INS_Disassemble(ins)),
        IARG_UINT32, INS_RegR(ins, 0),
        IARG_END);
  }
}

static unsigned int tryksOpen;

#define TRICKS(){if (tryksOpen++ == 0)return;}

VOID Syscall_entry(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v)
{
  unsigned int i;
  UINT64 start, size;

  if (PIN_GetSyscallNumber(ctx, std) == __NR_read){

      TRICKS(); /* tricks to ignore the first open */

      start = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 1)));
      size  = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 2)));

      for (i = 0; i < size; i++)
        addressTainted.push_back(start+i);
      
      std::cout << "[TAINT]\t\t\tbytes tainted from " << std::hex << "0x" << start << " to 0x" << start+size << " (via read)"<< std::endl;
  }
}

// This function is called when the application exits
// It prints the name and count for each procedure
VOID Fini(INT32 code, VOID *v)
{
    std::cout << "analyzed binary is exiting!" << std::endl;
}

VOID hitafunc() {
}

// The arg stack for fmt.Fprintf is setup as:
// rsp + 0x0: return ptr
// rsp + 0x8: not sure??? (possibly previous stack frame)
// rsp + 0x10: io.Writer argument (is a pointer because its a go-interface)
// :::This is the end of a StringHeader struct put on the stack
// rsp + 0x18: address to byte buffer
// rsp + 0x20: string size
// :::This is the start of the StringHeader struct, Its upside down because
// :::I've diagrammed this stack upside down.

VOID fprintf_before(ADDRINT rsp) {
    std::cout << "fmt.Fprintf was called" << std::endl; 
    std::cout << "rsp size: " << sizeof(rsp) << std::endl;
    // return address
    std::cout << "rsp[0]: " << *((ADDRINT*)(rsp)) << std::endl;
    std::cout << "rsp[-1]: " << *((ADDRINT*)(rsp+0x8)) << std::endl;
    std::cout << "rsp[-2]: " << *((ADDRINT*)(rsp+0x10)) << std::endl;
    std::cout << "rsp[-3]: " << *((ADDRINT*)(rsp+0x18)) << std::endl;
    std::cout << "rsp[-4]: " << *((ADDRINT*)(rsp+0x20)) << std::endl;
    // this is really a utf8 encoded string.
    char *bufaddr = (char*)(*((ADDRINT*)(rsp+0x18)));
    size_t len = (*((ADDRINT*)(rsp+0x20)));

    printf("fmt.Fprintf passed format string:\n");
    printf("GoString {len: %lu, buf: %p}\n", len, bufaddr);
    printf("%p: ", bufaddr);
    for (size_t i=0; i<len; i++) {
        printf("%c", bufaddr[i]);
    }
    printf("\n");
}

VOID ImageLoad(IMG img, VOID *v)
{
    std::cout << "Loading " << IMG_Name(img) << ", Image id = " << IMG_Id(img) << std::endl;

    RTN go_fmt_fprintf_rtn = RTN_FindByName(img, "fmt.Fprintf");
    if (RTN_Valid(go_fmt_fprintf_rtn)) {
        RTN_Open(go_fmt_fprintf_rtn);
        RTN_InsertCall(go_fmt_fprintf_rtn, IPOINT_BEFORE,
                AFUNPTR(fprintf_before),
                IARG_REG_VALUE, REG_STACK_PTR,
                IARG_END);
    }
}

// Pin calls this function every time a new rtn is executed. I think this is
// called but the JIT compiler just to figure out how to create the
// instrumented code.
VOID Routine(RTN rtn, VOID *v)
{
    
    // Allocate a counter for this routine
    std::cout << "hooking func: " << RTN_Name(rtn) << std::endl;

    // The RTN goes away when the image is unloaded, so save it now
    // because we need it in the fini
    //rc->_image = StripPath(IMG_Name(SEC_Img(RTN_Sec(rtn))).c_str());
    //rc->_address = RTN_Address(rtn);
    //rc->_icount = 0;
    //rc->_rtnCount = 0;

    // Add to list of routines
    //rc->_next = RtnList;
    //RtnList = rc;
            
    RTN_Open(rtn);
            
    // Insert a call at the entry point of a routine to increment the call count
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)hitafunc,
            IARG_END);
    
    RTN_Close(rtn);
}

int main(int argc, char *argv[])
{
    // Initialize symbol table code, needed for rtn instrumentation
    PIN_InitSymbols();

    if (PIN_Init(argc, argv)) {
        return Usage();
    }
    
    PIN_SetSyntaxIntel();

    // Register ImageLoad to be called when an image is loaded
    IMG_AddInstrumentFunction(ImageLoad, 0);

    // used to taint the read call as a source
    PIN_AddSyscallEntryFunction(Syscall_entry, 0);

    // register callback when each instruction is executing
    INS_AddInstrumentFunction(Instruction, 0);
    
    // Register Routine to be called to instrument rtn
    //RTN_AddInstrumentFunction(Routine, 0);
    
    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);
    
    PIN_StartProgram();
    
    return 0;
}

