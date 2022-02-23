from hashlib import pbkdf2_hmac, md5
from re import compile as regex
from binascii import unhexlify
from typing import Union

TITLEKEY_SECRET = bytearray([ 0xFD, 0x04, 0x01, 0x05, 0x06, 0x0B, 0x11, 0x1C, 0x2D, 0x49 ])
TID_REGEX = regex("^0004[0-9A-Fa-f]{12}$")
KNOWN_TITLEKEY_PASSWORDS = \
[
	"mypass",
	"nintendo",
	"password",
	"",
	"0000",
	"1234",
	"1234567890",
	"5037",
	"5678",
	"d4t4c3nt3r",
	"fbf10",
	"Lucy131211",
	"nintedno",
	"redsst",
	"test"
]

class TitleID:
	_raw_tid_bytes: bytes

	def _import_tid(self, tid: Union[str, int, bytearray], be: bool = None):
		if isinstance(tid, str):
			self._raw_tid_bytes = unhexlify(tid)
		elif isinstance(tid, bytearray):
			if not be:
				tid.reverse()
			self._raw_tid_bytes = tid
		elif isinstance(tid, int):
			self._raw_tid_bytes = tid.to_bytes(8, "big")

	def __init__(self, tid: Union[str, int, bytearray], be: bool = None) -> None:
		if isinstance(tid, str):
			if not len(tid) == 16:
				raise Exception("Invalid Title ID length")
			
			if not TID_REGEX.match(tid):
				raise Exception("Invalid Title ID format")
		elif isinstance(tid, int):
			if tid >> 48 != 0x0004: # CTR Title IDs only
				raise Exception("Invalid Title ID format")
		elif isinstance(tid, bytearray):
			if be == None:
				raise Exception("Byte order of Title ID bytes was not specified")

			if len(tid) != 8:
				raise Exception("Invalid Title ID length")
			
			if int.from_bytes(tid[6:8], "little") if not be else int.from_bytes(tid[0:2], "big") != 0x0004:
				raise Exception("Invalid Title ID format")

		self._import_tid(tid, be)

	def bytes(self) -> bytearray:
		return bytearray(self._raw_tid_bytes)

	def int(self) -> int:
		return int.from_bytes(self._raw_tid_bytes, "big")

	def str(self, upper: bool = False) -> str:
		st = self._raw_tid_bytes.hex()
		return st.upper() if upper else st

	def low_int(self) -> int:
		return self.int() & 0xFFFFFFFF

	def low_str(self, upper: bool = False) -> str:
		return self.str(upper)[8:16]

	def low_bytes(self) -> bytearray:
		return bytearray(self._raw_tid_bytes[4:8])

	def high_int(self) -> int:
		return self.int() << 32

	def high_str(self, upper: bool = False) -> str:
		return self.str(upper)[0:8]

	def high_bytes(self) -> bytearray:
		return bytearray(self._raw_tid_bytes[0:4])

	def content_category_int(self) -> int:
		return int.from_bytes(self._raw_tid_bytes[2:4], "big")

	def content_category_str(self, upper: bool = False) -> str:
		return self.str(upper)[4:8]
	
	def content_category_bytes(self) -> bytearray:
		return bytearray(self._raw_tid_bytes[2:4])

	def generate_titlekey(self, password: str = "mypass") -> bytearray:
		return pbkdf2_hmac('sha1', password.encode(), md5(TITLEKEY_SECRET + self._raw_tid_bytes.lstrip(b"\x00")).digest(), 20, 16)

	def generate_titlekey_str(self, password: str = "mypass", upper: bool = False) -> str:
		key = self.generate_titlekey(password).hex()
		return key.upper() if upper else key

	def is_twl(self) -> bool:
		return bool(self.content_category_int() & 0x8000)