import ida_bytes
import ida_dbg
import ida_funcs
import ida_idd
import ida_idp
import ida_idaapi
import ida_name
import ida_nalt
import ida_typeinf
import idaapi
import idc

def apply_cdecl(ea: int, decl: str) -> ida_idaapi.object_t:
    """
    Returns object as type `type_string` from ea.

    :returns: ida_idaapi.object_t of object
    :rtype: ida_idaapi.object_t
    """
    tp = ida_idd.Appcall.typedobj(decl)
    ok, r = tp.retrieve(ea)
    return r

def apply_named_type(ea: int, type_string: str) -> ida_idaapi.object_t:
    """
    Returns object as type `type_string` from ea.

    :returns: ida_idaapi.object_t of object
    :rtype: ida_idaapi.object_t
    """
    tif = ida_typeinf.tinfo_t()
    tif.create_typedef(ida_typeinf.get_idati(), type_string)
    ida_typeinf.apply_tinfo(ea, tif, 0)

    tp = ida_idd.Appcall.typedobj(tif)
    ok, r = tp.retrieve(ea)
    return r

def get_func_type_from_til(func_name: str) -> ida_typeinf.tinfo_t:
    """
    Return ida_typeinf.tinfo_t object given a function name.
    
    :param str func_name: 
    :returns: 
    :rtype:
    """
    sym = ida_typeinf.til_symbol_t()
    sym.til = ida_typeinf.get_idati()
    sym.name = func_name

    tif = ida_typeinf.tinfo_t()
    named_type = ida_typeinf.get_named_type(sym.til, sym.name, 0)
    if named_type is not None:
        code, type_str, fields_str, cmt, fields_cmts, sclass, value = named_type 
        tif.deserialize(sym.til, type_str, fields_str)
    return tif



def LoadLibrary(module: str) -> int:
    """
    Loads DLL in IDA database from module name.

    :returns: effective eaess of module name.
    :rtype: int
    """
    if not module.endswith(".dll"):
        module += ".dll"
    # ida_inf = idaapi.get_inf_structure()
    # if ida_inf.is_64bit() == 64:
    #     ida_typeinf.add_til("ntapi64_win10", ida_typeinf.ADDTIL_DEFAULT)
    #     func_addressing_size = 8
    # elif ida_inf.is_32bit() == 32:
    #     ida_typeinf.add_til("ntapi_win10", ida_typeinf.ADDTIL_DEFAULT)
    #     func_addressing_size = 4
    # else:
    #     warnings.warn('unsure of system type, unable to load ntapi til', Warning)
    #     return None

    # size = idaapi.get_struc_size(idc.import_type(-1, "UNICODE_STRING"))    
    # RtlCreateHeap = WinAPI("ntdll.dll", "RtlCreateHeap")
    # RtlAllocateHeap = WinAPI("ntdll.dll", "RtlAllocateHeap")
    
    # # convert module to wide string, but im lazy to implement so we assume wide string

    # heap = RtlCreateHeap(0, 0, 0, 0, 0, 0)
    # ea = RtlAllocateHeap(heap, 0, size)
    # buf_ea = RtlAllocateHeap(heap, 0, len(module))
    
    # tp = ida_idd.Appcall.typedobj(f"struct {{char value[{len(module)}];}};")
    # obj = ida_idd.Appcall.obj(value = module)
    # tp.store(obj, buf_ea)

    # tp = ida_idd.Appcall.typedobj("typedef UNICODE_STRING a;")
    # obj = ida_idd.Appcall.obj(Length = len(module), MaximumLength = len(module) + 2, Buffer = buf_ea)
    # tp.store(obj, ea)

    # handle_ea = RtlAllocateHeap(heap, 0, func_addressing_size)
    # return WinAPI("ntdll.dll", "LdrLoadDll")(0, 0, ea, handle_ea)
    return WinAPI("LoadLibraryA", "kernel32")(module.lower())

class WinAPI(ida_idd.Appcall_callable__):
    """
    Returns IDAAppcall callable object, with automatic type information retrieved from TIL.
    """

    WHITELIST_DLL = ("hal.dll", "ntdll.dll", 
                    "kernel32.dll", "user32.dll", "ws2_32.dll", "netapi32.dll", "ole32.dll",
                    "comctl32.dll", "comdlg32.dll", "gdi32.dll", "advapi32.dll",
                    "msvcrt.dll", "crtdll.dll", "msvcirt.dll") 
                    # todo: increase whitelist to visual c++ eg. msvcp, vcruntime... https://learn.microsoft.com/en-us/cpp/windows/determining-which-dlls-to-redistribute

    def __init__(self, procedure: str, module = None):
        self.procedure  = procedure
        self.module     = module if module else self._get_module()
        super(WinAPI, self).__init__(self._get_addr())
        tif = get_func_type_from_til(procedure)
        ida_typeinf.apply_tinfo(self.ea, tif, 0)

    def _get_addr(self):
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, self.procedure)
        if ea != ida_idaapi.BADADDR:
            return ea
        
        name = self.module + "_" + self.procedure
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, name)
        if ea != ida_idaapi.BADADDR:
            return ea
            
        LoadLibrary(self.module)
        return ida_name.get_name_ea(ida_idaapi.BADADDR, name)
    
    def _get_module(self):
        cmp = self.procedure.encode('utf-8')
        for dll in self.WHITELIST_DLL:
            if cmp in self.EnumExports(dll):
                return dll[:-4]        

    @staticmethod
    def EnumExports(module):
        imageBase = LoadLibrary(module)
        if not imageBase:
            return

        lib = apply_named_type(imageBase, "IMAGE_DOS_HEADER")
        assert (lib.e_magic == 0x5a4d)

        header = apply_named_type(imageBase + lib.e_lfanew, "IMAGE_NT_HEADERS")
        assert header.Signature in (0x4500, 0x4550)
        assert header.OptionalHeader.NumberOfRvaAndSizes > 0
        
        IMAGE_DIRECTORY_ENTRY_EXPORT = '0'
        exportRVA = header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
        exportHead = apply_named_type(imageBase + exportRVA, "IMAGE_EXPORT_DIRECTORY")
        
        exportTableRVA = imageBase + exportHead.AddressOfNames
        exportTable = apply_cdecl(exportTableRVA, f"struct {{DWORD names[{exportHead.NumberOfNames}];}};")
        
        for i in range(exportHead.NumberOfNames):
            index = str(i)
            ea = imageBase + exportTable.names[index]
            strlen = ida_bytes.get_max_strlit_length(ea, ida_nalt.STRTYPE_C, ida_bytes.ALOPT_IGNHEADS)
            yield ida_bytes.get_strlit_contents(ea, strlen, ida_nalt.STRTYPE_C)
    
    def __call__(self, *args):
        obj = super(WinAPI, self).__call__(*args)
        if isinstance(obj, ida_idaapi.PyIdc_cvt_int64__):
            return obj.value
        return obj


def hook_function(procedure, module = None):
    ea = WinAPI(procedure, module).ea

    if not ida_dbg.exist_bpt(ea):
        ida_dbg.add_bpt(ea)
    
    bpt = ida_dbg.bpt_t()
    ida_dbg.get_bpt(ea, bpt)
    bpt.elang = 'Python'
    bpt.condition = f'print(*get_function_args({ea}))\nreturn True'
    
    ida_dbg.update_bpt(bpt)

def get_function_args(ea, tif = None):
    if tif is None:
        tif = ida_typeinf.tinfo_t()
        idaapi.get_tinfo(tif, ea)
    if tif is None:
        tif = get_func_type_from_til(ida_funcs.get_func_name(ea))

    funcdata = ida_typeinf.func_type_data_t()
    tif.get_func_details(funcdata)
    func = ida_funcs.get_func(ea)

    for arg in funcdata:
        argloc = arg.argloc
                
        if argloc.atype() == idaapi.ALOC_CUSTOM:
            pass
        elif argloc.atype() == idaapi.ALOC_STACK:
            import ida_bitrange
            bit = ida_bitrange.bitrange_t()
            stk_reg = ida_idp.get_reg_info("sp", bit)
            arg_ea = ida_dbg.get_reg_val(stk_reg) + argloc.stkoff() + func.get_func_bytes()
        elif argloc.atype() == idaapi.ALOC_REG1:
            reg_name = ida_idp.get_reg_name(argloc.reg1(), func.get_func_bytes(), -1)
            arg_ea = ida_dbg.get_reg_val(reg_name) + argloc.regoff()

        tp = ida_idd.Appcall.typedobj(arg.type)
        try:
            ok, r = tp.retrieve(arg_ea)
            yield (arg_ea, r, arg.type)
        except:
            yield arg_ea, arg.type