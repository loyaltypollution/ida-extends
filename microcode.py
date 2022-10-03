import ida_hexrays
import ida_idaapi

class const_optimizer_t(ida_hexrays.optinsn_t):
	mop = None
	class search_t(ida_hexrays.minsn_visitor_t):
		def __init__(self):
			super().__init__()
		
		def visit_minsn(self):
			ins = self.curins
			if ins.ea == 0x04004E2:
				self.mop = ins.d
				self.val = ins.l.nnn.value
			return 0

	class replace_t(ida_hexrays.minsn_visitor_t):
		def __init__(self, mop, val):
			self.mop = mop
			self.val = val
			super().__init__()
		
		def visit_minsn(self):
			ins = self.curins
			if ins.l.equal_mops(self.mop, ida_hexrays.EQ_IGNSIZE):
				ins.l.make_number(self.val, ins.l.size)
				self.cnt = 1
			return 0

	def func(self, blk, ins, optflags):
		if blk.mba.maturity != ida_hexrays.MMAT_LOCOPT:
			return 0
		if self.mop is None:
			search = self.search_t()
			blk.mba.for_all_insns(search)
			self.mop = search.mop
			self.val = search.val
		
		opt = self.replace_t(self.mop, self.val)
		ins.for_all_insns(opt)
		if opt.cnt != 0:
			blk.mba.verify(True)
		return opt.cnt

x = const_optimizer_t()
x.install()