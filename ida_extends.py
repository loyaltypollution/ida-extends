import typing

import idautils
import ida_idd
import ida_typeinf
import ida_idaapi
import idc
import idaapi

def get_reg_bitsize() -> int:
	"""
	Returns bitsize of registers.
	64-bit architecture returns 64, 32-bit architecture returns 32..
	
	Assume 16 by default
	:returns: Bitsize of registers
	:rtype: int
	"""
	if idaapi.get_inf_structure().is_64bit():
		return 64
	if idaapi.get_inf_structure().is_32bit():
		return 32
	else:
		return 16   # assume 16-bit architecture

def get_all_segm() -> typing.Dict[str, int]:
	"""
	Returns all (segment_name, segment_address) as a Python dictionary.
	For duplicate segment_names, lowest segment_address is returned.

	:returns: Dictionary of (segment_name, segment_address)
	:rtype: typing.Dict[str, int]
	"""
	result = {}	
	for ea in idautils.Segments():
		name = idc.get_segm_name(ea)
		if name not in result or result[name] > ea:
			result[name] = ea
	return result

def is_segm_loaded(segm_name: str) -> bool:
	for name in get_all_segm().keys():
		if segm_name.lower() == name.lower():
			return True
	return False


def LoadLibrary(module: str) -> int:
	"""
	Loads DLL in IDA database from module name.

	:returns: effective address of module name.
	:rtype: int
	"""
	if is_segm_loaded("kernel32.dll"):
		return WinAPI("kernel32.dll", "LoadLibraryA")(module)
	
	if get_reg_bitsize() == 64:
		ida_typeinf.add_til("ntapi64_win10", ida_typeinf.ADDTIL_DEFAULT)
	elif get_reg_bitsize() == 32:
		ida_typeinf.add_til("ntapi_win10", ida_typeinf.ADDTIL_DEFAULT)
	else:
		warnings.warn('unsure of system type, unable to load ntapi til', Warning)

	size = idaapi.get_struc_size(idc.import_type(-1, "UNICODE_STRING"))	
	RtlCreateHeap = WinAPI("ntdll.dll", "RtlCreateHeap")
	RtlAllocateHeap = WinAPI("ntdll.dll", "RtlAllocateHeap")
	
	# convert module to wide string, but im lazy to implement so we assume wide string

	heap = RtlCreateHeap(0, 0, 0, 0, 0, 0)
	ea = RtlAllocateHeap(heap, 0, size)
	buf_ea = RtlAllocateHeap(heap, 0, len(module))
	
	tp = ida_idd.Appcall.typedobj(f"struct {{char value[{len(module)}];}};")
	obj = ida_idd.Appcall.obj(value = module)
	tp.store(obj, buf_ea)

	tp = ida_idd.Appcall.typedobj("typedef UNICODE_STRING a;")
	obj = ida_idd.Appcall.obj(Length = len(module), MaximumLength = len(module) + 2, Buffer = buf_ea)
	tp.store(obj, ea)

	handle_ea = RtlAllocateHeap(heap, 0, get_reg_bitsize() // 8)
	return WinAPI("ntdll.dll", "LdrLoadDll")(0, 0, ea, handle_ea)

def WinAPI(module: str | bytes, procedure: str | bytes) -> ida_idd.Appcall_callable__:
	"""
	Returns IDAAppcall callable object, with automatic type information retrieved from TIL.
	Supports wide-string auto-magically.

	:returns: Dictionary of (segment_name, segment_address)
	:rtype: typing.Dict[str, int]
	"""
	try:
		call = ida_idd.Appcall[procedure]
	except AttributeError:
		if not is_segm_loaded(module):
			LoadLibrary(module)
		call = ida_idd.Appcall[module[:-4] + "_" + procedure]
	
	tif = get_func_type_from_til(procedure)
	if not ida_typeinf.apply_tinfo(call.ea, tif, 0):
		warnings.warn(f"WinAPI: Failed to apply type info to {procedure} in {module}", Warning)
	return call

def get_func_type_from_til(func_name: str) -> ida_typeinf.tinfo_t:
	"""
	Return ida_typeinf.tinfo_t object given a function name.
	
	:param str func_name: 
	:returns: 
	:rtype:
	"""
	sym = ida_typeinf.til_symbol_t()
	sym.til = ida_typeinf.cvar.idati
	sym.name = func_name

	tif = ida_typeinf.tinfo_t()
	named_type = idaapi.get_named_type(sym.til, sym.name, 0)
	if named_type is not None:
		code, type_str, fields_str, cmt, fields_cmts, sclass, value = named_type 
		tif.deserialize(sym.til, type_str, fields_str)
	return tif

def apply_type_from_name(ea: int, type_string: str) -> ida_idaapi.object_t:
	"""
	Returns object as type `type_string` from ea.

	:returns: ida_idaapi.object_t of object
	:rtype: ida_idaapi.object_t
	"""
	tif = idaapi.create_typedef(type_string)
	tp = Appcall.typedobj(tif)
	ok, r = tp.retrieve(ea)
	return r