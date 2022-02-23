from xml.dom.minidom import Element
from xmlrpc.client import Boolean
from util.titleid import TitleID, KNOWN_TITLEKEY_PASSWORDS
from pyctr.type.tmd import TitleMetadataReader
from typing import BinaryIO, Dict, List, Literal, Union
from pyctr.type.ncch import NCCHSection
from pyctr.type.cdn import CDNReader
from pyctr.type.smdh import AppTitle
from xml.etree import ElementTree
from re import compile as regex
from util.log import Logger
from enum import IntEnum
from util import verify
from io import BytesIO
import hashlib
import zlib
import os

HASHES_REGEX = regex(
	"SHA-256 : [A-Fa-f0-9]{64}\nSHA-1   : [A-Fa-f0-9]{40}\nMD5     : [A-Fa-f0-9]{32}\nCRC32   : [A-Fa-f0-9]{8}\nSize    : \d+\n")
INFO_REGEX = regex("0004[A-Fa-f0-9]{12}\n\d{4}-[\d{2}]{2}\n")
LANG_STRS = \
	{
		"English": "En",
		"English (USA)": "En-US",
		"English (United Kingdom)": "En-UK",
		"Japanese": "Ja",
		"French": "Fr",
		"French (France)": "Fr-FR",
		"French (Canada)": "Fr-CA",
		"German": "De",
		"Spanish": "Es",
		"Spanish (Spain)": "Es-ES",
		"Spanish (Latin America)": "Es-LX",
		"Italian": "It",
		"Dutch": "Nl",
		"Portuguese": "Pt",
		"Portuguese (Portugal)": "Pt-PT",
		"Portuguese (Brazil)": "Pt-BR",
		"Swedish": "Sv",
		"Norwegian": "No",
		"Danish": "Da",
		"Finnish": "Fi",
		"Chinese": "Zh",
		"Chinese (Traditional)": "Zh-Hant",
		"Chinese (Simplified)": "Zh-Hans",
		"Korean": "Ko",
		"Polish": "Pl",
		"Russian": "Ru",
		"Greek": "El",
		"Turkish": "Tr",
		"Czech": "Cs",
		"Hungarian": "Hu",
		"Catalan": "Ca",
		"Thai": "Th",
		"Croatian": "Hr",
		"Hindi": "Hi",
		"Arabic": "Ar",
		"Hebrew": "He",
		"Icelandic": "Is",
		"Slovenian": "Sl",
		"Romanian": "Ro",
		"Bulgarian": "Bg",
		"Ukrainian": "Uk",
		"Gaelic": "Gd",
		"Serbian": "Sr",
		"Indonesian": "Id",
		"Galician": "Gl",
		"Vietnamese": "Vi",
		"Esperanto": "Eo"
	}


def int_tryparse(s: str, base: int = 10) -> Union[int, None]:
	try:
		return int(s, base=base)
	except:
		return None


class ContentInfoType(IntEnum):
	Content = 0,
	TMD = 1,
	Unavailable = 2,
	Invalid = 3


class ContentInfoHashes:
	sha256: bytearray = None
	sha1: bytearray = None
	md5: bytearray = None
	crc32: bytearray = None

	def __init__(self, sha256: bytearray, sha1: bytearray, md5: bytearray, crc32: bytearray) -> None:
		self.sha256 = sha256
		self.sha1 = sha1
		self.md5 = md5
		self.crc32 = crc32


class ContentInfo:
	type: ContentInfoType = None
	http_headers: str = None

	raw_hashes: ContentInfoHashes = None
	cdnlevel_decrypted_hashes: ContentInfoHashes = None
	contentlevel_decrypted_hashes: ContentInfoHashes = None

	product_code: str = None

	size: int = None

	def __init__(self, file_path: str, is_tmd: bool = False) -> None:
		hashfile_path = f"{file_path}_hashes.txt"
		headerfile_path = f"{file_path}_headers.txt"

		if not os.path.exists(file_path) or not os.path.isfile(file_path):
			self.type = ContentInfoType.Invalid if not os.path.exists(
				f"{file_path}_unavailable") else ContentInfoType.Unavailable
			return

		if not os.path.exists(hashfile_path) or not os.path.exists(headerfile_path) or os.path.isdir(hashfile_path) or os.path.isdir(headerfile_path):
			raise Exception(
				"ERROR: Header/Hash file not found (forgot to use -rse?)")

		self.type = ContentInfoType.TMD if is_tmd else ContentInfoType.Content

		# hash file

		with open(hashfile_path, "r") as hashfile:
			hashfile_data = hashfile.read()

		if not HASHES_REGEX.match(hashfile_data):
			raise Exception(
				f"ERROR: \"{hashfile_path}\": Invalid hash file format")

		hashfile_lines = hashfile_data.rstrip("\n").split("\n")

		self.raw_hashes = ContentInfoHashes(
			bytearray.fromhex(hashfile_lines[0].split(":")[1].lstrip(" ")),
			bytearray.fromhex(hashfile_lines[1].split(":")[1].lstrip(" ")),
			bytearray.fromhex(hashfile_lines[2].split(":")[1].lstrip(" ")),
			bytearray.fromhex(hashfile_lines[3].split(":")[1].lstrip(" ")))

		self.size = int(hashfile_lines[4].split(":")[1].lstrip(" "))

		# headers file (cant exactly check that data, just gonna store as-is)

		with open(headerfile_path, "r") as headerfile:
			self.http_headers = headerfile.read()


class CDNDatGenerator:
	# logger
	_logger: Logger = None

	# paths
	_basepath: str = None
	_tmdpath: str = None

	# files in content folder
	_content_files: List[str] = []

	# tmd stuff
	_tmd: TitleMetadataReader = None
	_raw_tmd: bytearray

	# gotten from TMD
	_tmd_title_id: TitleID = None

	# as reported by ctrcdnfetch
	_dump_date: str = None
	_requested_title_id: TitleID = None

	# needed to decrypt
	_title_key: bytearray = None
	_title_key_password: str = None

	# cdn reader, to not repeatedly open one when it's needed
	_reader: CDNReader = None

	# individual content/tmd specific info
	_content_infos: Dict[str, ContentInfo] = {}

	# to set after initial verification

	# where the title is from
	_region: str = None
	_languages: List[str] = []

	# first content specific info
	_title_names: Dict[str, AppTitle] = {}

	# -- user defined info #
	_title_name: str = ""
	_alt_title_name: str = ""
	_region: str = ""
	_languages: List[str] = []
	_dumper: str = ""
	_dump_tool: str = ""
	_project: str = ""

	def __init__(self, content_path: str, log_to_file: bool = True, log_to_console: bool = True) -> None:
		if not os.path.exists(content_path) or not os.path.isdir(content_path):
			raise FileNotFoundError(
				f"\"{content_path}\" does not exist or is not a directory")

		self._logger = Logger(log_to_console, os.path.join(
			content_path, "verify.log")) if log_to_file else Logger(log_to_console)
		self._logger.set_namespace("DATGen Init")

		tid_txtfile_path = os.path.join(content_path, "info.txt")

		if not os.path.exists(tid_txtfile_path) or not os.path.isfile(tid_txtfile_path):
			self._logger.error(
				"info.txt does not exist in the specified directory or it is not a file")
			raise self._logger.get_exception_from_last_msg()

		with open(tid_txtfile_path, "r") as tid_txtfile:
			raw_infodata = tid_txtfile.read().rstrip("\n").split("\n")

			self._requested_title_id = TitleID(raw_infodata[0])
			self._dump_date = raw_infodata[1]


		self._logger.info(
			f"Identified Title ID from ctrcdnfetch: {self._requested_title_id.str(True)}")

		files = os.listdir(content_path)

		if not len(files):
			self._logger.error("Specified folder does not contain any files")
			raise self._logger.get_exception_from_last_msg()

		tmd_paths = [x for x in files if x.startswith(
			"tmd") and not x.endswith(".txt")]

		if len(tmd_paths) > 1:
			self._logger.error(
				"Specified folder contains more than one TMD file")
			raise self._logger.get_exception_from_last_msg()
		elif len(tmd_paths) < 1:
			self._logger.error("Specified folder does not contain a TMD")
			raise self._logger.get_exception_from_last_msg()

		self._content_files = [os.path.join(
			content_path, x) for x in files if int_tryparse(x, 10) != None]

		self._tmdpath = os.path.join(content_path, tmd_paths[0])

		self._logger.info(f"Identified TMD: {self._tmdpath}")
		for i in self._content_files:
			self._logger.info(f"Identified Content: {i}")

		self._basepath = content_path

		self._verify_tmd()
		self._open_cdnreader()
		self._load_contents()
		self._verify_contents_hash_cdnlevel()
		self._hash_contents_decrypted()
		self._load_content_product_codes()

	def _verify_tmd(self) -> None:
		self._logger.set_namespace("TMD Verify")

		#  this is the theoretical maximum tmd size, this should NOT happen, EVER
		if os.path.getsize(self._tmdpath) > 3148752:
			self._logger.error("TMD file exceeds maximum size")
			raise self._logger.get_exception_from_last_msg()

		with open(self._tmdpath, "rb") as tmdfile:
			tmd_data = tmdfile.read()

		# load the tmd first
		with BytesIO(tmd_data) as tmd_io:
			self._tmd = TitleMetadataReader.load(tmd_io, verify_hashes=True)

		# try opening hashes file for tmd
		try:
			tmd_cinfo = ContentInfo(self._tmdpath, True)
		except Exception as e:
			self._logger.error(e)
			raise self._logger.get_exception_from_last_msg()

		self._logger.info("Hashing")

		if hashlib.sha256(tmd_data).hexdigest() != tmd_cinfo.raw_hashes.sha256.hex():
			self._logger.error("TMD SHA-256 Hash mismatch")
			raise self._logger.get_exception_from_last_msg()

		self._logger.info("Hash Verified")
		self._logger.info("Verifying Signature")

		try:
			verify.tmd(tmd_data)  # verify tmd signature
		except:
			self._logger.error("TMD Signature verification failure")
			raise self._logger.get_exception_from_last_msg()

		self._logger.info("Signature Verified")

		self._content_infos[os.path.basename(self._tmdpath)] = tmd_cinfo
		self._tmd_title_id = TitleID(self._tmd.title_id)
		self._raw_tmd = bytearray(tmd_data)

		self._logger.info(
			f"Detected Title ID in TMD: {self._tmd_title_id.str(True)}")

		if self._tmd_title_id.is_twl() and self._tmd.content_count > 1:
			self._logger.error("TWL title has more than 1 content")
			raise self._logger.get_exception_from_last_msg()

		self._logger.info(
			f"Total Number of Contents: {self._tmd.content_count}")

	def _open_cdnreader(self) -> None:
		self._logger.set_namespace("Open CDNReader")
		titlekey_found = False

		self._logger.info("Attempting to Generate Title Key")

		for titlekey_password in KNOWN_TITLEKEY_PASSWORDS:
			self._logger.info(
				f"Trying Title Key Password \"{titlekey_password}\"")
			try:
				title_key = self._tmd_title_id.generate_titlekey(
					titlekey_password)
				reader = CDNReader(self._tmdpath, decrypted_titlekey=title_key)
				titlekey_found = True
				break
			except:
				self._logger.info(
					f"Title Key Password \"{titlekey_password}\" is not valid for this Title")
				pass

		if not titlekey_found:
			self._logger.error(
				"No known title keys were able to decrypt this title")
			raise self._logger.get_exception_from_last_msg()

		self._logger.info(
			f"Successfully Generated a Valid Title Key using Password \"{titlekey_password}\"")
		self._logger.info(f"Generated Title Key: {title_key.hex().upper()}")

		self._title_key = title_key
		self._title_key_password = titlekey_password
		self._reader = reader

	def _load_contents(self) -> None:
		self._logger.set_namespace("Content Load")

		for chunk_record in self._tmd.chunk_records:
			content_path = os.path.join(self._basepath, chunk_record.id)

			try:
				content_info = ContentInfo(content_path)
			except Exception as e:
				self._logger.error(e)
				raise self._logger.get_exception_from_last_msg()

			if content_info.type == ContentInfoType.Unavailable or content_info.type == ContentInfoType.Invalid:
				self._logger.error(
					f"ERROR: Content {chunk_record.id} itself, its Hash Data, its HTTP Reponse Header Data, or all are missing")
				raise self._logger.get_exception_from_last_msg()

			self._content_infos[chunk_record.id] = content_info

			self._logger.info(
				f"Loaded Raw Hash Data and HTTP Response Header Data for Content {chunk_record.id}")

	def _hash_file(self, fp: BinaryIO, size: int) -> ContentInfoHashes:
		cur_content_hash_sha256 = hashlib.sha256()
		cur_content_hash_sha1 = hashlib.sha1()
		cur_content_hash_md5 = hashlib.md5()
		crc = 0

		read = 0
		remaining = size
		to_read = min(remaining, 4096)

		while read != size:
			data = fp.read(to_read)

			if len(data) != to_read:
				raise Exception(
					f"ERROR: Could not read {to_read} bytes from file")

			cur_content_hash_sha256.update(data)
			cur_content_hash_sha1.update(data)
			cur_content_hash_md5.update(data)
			crc = zlib.crc32(data, crc)

			read = read + to_read
			remaining = remaining - to_read
			to_read = min(remaining, 4096)

		return ContentInfoHashes(
			bytearray(cur_content_hash_sha256.digest()),
			bytearray(cur_content_hash_sha1.digest()),
			bytearray(cur_content_hash_md5.digest()),
			bytearray(crc.to_bytes(4, "big")))

	def _verify_contents_hash_cdnlevel(self) -> None:
		self._logger.set_namespace("Content Verify")

		for cur_chunk_record in self._tmd.chunk_records:
			self._logger.info(
				f"Attempting to Verify and get CDN-Level Decrypted Hash for Content {cur_chunk_record.id}")
			cur_cinfo = self._content_infos[cur_chunk_record.id]

			if cur_cinfo.type == ContentInfoType.Unavailable:
				self._logger.error(
					f"ERROR: Content {cur_chunk_record.id} unavailable for hashing")
				raise self._logger.get_exception_from_last_msg()
			elif cur_cinfo.type == ContentInfoType.Invalid:
				self._logger.error(
					f"ERROR: Content ID {cur_chunk_record.id} unavailable (invalid) for hashing")
				raise self._logger.get_exception_from_last_msg()
			elif cur_cinfo.type == ContentInfoType.TMD:
				continue

			with self._reader.open_raw_section(cur_chunk_record.cindex) as cur_content:
				hash_data = self._hash_file(cur_content, cur_chunk_record.size)

			if hash_data.sha256.hex() != cur_chunk_record.hash.hex():
				self._logger.error(
					f"ERROR: Content {cur_chunk_record.id} hash mismatch")
				raise self._logger.get_exception_from_last_msg()

			cur_cinfo.cdnlevel_decrypted_hashes = hash_data

			self._logger.info(
				f"Successfully Verified and CDN-Level Hashed Content {cur_chunk_record.id}")

	def _hash_contents_decrypted(self) -> None:
		self._logger.set_namespace("Content Decrypted Hash")

		for cur_chunk_record in self._tmd.chunk_records:
			self._logger.info(
				f"Hashing Content {cur_chunk_record.id} in Content-Level Decrypted Mode")
			cur_cinfo = self._content_infos.get(cur_chunk_record.id)

			if not cur_cinfo:
				self._logger.error(
					f"Content {cur_chunk_record.id} not in parsed infos?")
				raise self._logger.get_exception_from_last_msg()
			elif cur_cinfo.type == ContentInfoType.Unavailable:
				self._logger.error(
					f"Content {cur_chunk_record.id} unavailable for hashing")
				raise self._logger.get_exception_from_last_msg()
			elif cur_cinfo.type == ContentInfoType.Invalid:
				self._logger.error(
					f"Content ID {cur_chunk_record.id} unavailable (invalid) for hashing")
				raise self._logger.get_exception_from_last_msg()
			elif cur_cinfo.type == ContentInfoType.TMD:
				continue

			if self._tmd_title_id.is_twl():  # TWL Titles do not use NCCH crypto, let alone NCCH
				self._logger.info(
					f"Title is a TWL Title; Reusing Hashes of CDN-Level Decrypted Content")
				cur_cinfo.contentlevel_decrypted_hashes = ContentInfoHashes(
					cur_cinfo.cdnlevel_decrypted_hashes.sha256.copy(),
					cur_cinfo.cdnlevel_decrypted_hashes.sha1.copy(),
					cur_cinfo.cdnlevel_decrypted_hashes.md5.copy(),
					cur_cinfo.cdnlevel_decrypted_hashes.crc32.copy()
				)
			else:
				with self._reader.contents[cur_chunk_record.cindex] as cur_enc_content:
					with cur_enc_content.open_raw_section(NCCHSection.FullDecrypted) as cur_content:
						cur_cinfo.contentlevel_decrypted_hashes = self._hash_file(
							cur_content, cur_chunk_record.size)

			self._logger.info(
				f"Successfully Hashed Content {cur_chunk_record.id} in Content-Level Decrypted Mode")

	def _load_content_product_codes(self) -> None:
		self._logger.set_namespace("Product Code Read")
		if self._tmd_title_id.is_twl():
			game_code = self._tmd_title_id.low_bytes().decode("ascii")
			self._content_infos[self._tmd.chunk_records[0].id].product_code = game_code
			self._logger.info(
				f"Title is a TWL Title; Game Code Read from Title ID: {game_code}")
		else:
			for chunk_record in self._tmd.chunk_records:
				with self._reader.contents[chunk_record.cindex] as content:
					self._content_infos[chunk_record.id].product_code = content.product_code
					self._logger.info(
						f"Read NCCH Product Code {content.product_code} from Content {chunk_record.id}")

	def _intbool(self, input: bool):
		return "1" if input else "0"

	def create_flags(self, bios: bool = False, licensed: bool = True, pirate: bool = False, physical: bool = False, complete: bool = True, nodump: bool = False, public: bool = True, dat: bool = True, adult: bool = False) -> ElementTree.Element:
		flags = ElementTree.Element("flags")

		flags.attrib["bios"] = self._intbool(bios)
		flags.attrib["licensed"] = self._intbool(licensed)
		flags.attrib["pirate"] = self._intbool(pirate)
		flags.attrib["physical"] = self._intbool(physical)
		flags.attrib["complete"] = self._intbool(complete)
		flags.attrib["nodump"] = self._intbool(nodump)
		flags.attrib["public"] = self._intbool(public)
		flags.attrib["dat"] = self._intbool(dat)
		flags.attrib["adult"] = self._intbool(adult)

		return flags

	def create_game(self, datternote: str = "", stickynote: str = "") -> ElementTree.Element:
		game = ElementTree.Element("game")
		game.attrib["name"] = ""

		# create archive
		archive = ElementTree.Element("archive")
		archive.attrib["name"] = self._title_name
		archive.attrib["namealt"] = self._alt_title_name
		archive.attrib["region"] = self._region
		archive.attrib["languages"] = ",".join(self._languages)
		archive.attrib["showlang"] = "2"
		archive.attrib["datternote"] = datternote
		archive.attrib["stickynote"] = stickynote

		archive.append(self.create_flags())

		source = ElementTree.Element("source")
		details = ElementTree.Element("details")
		details.attrib["section"] = "Trusted Dump"
		details.attrib["dumpdate"] = self._dump_date
		details.attrib["originalformat"] = "Default"
		details.attrib["knowndumpdate"] = "1"
		details.attrib["knownreleasedate"] = "0"
		details.attrib["dumper"] = self._dumper
		details.attrib["project"] = self._project
		details.attrib["tool"] = self._dump_tool
		details.attrib["region"] = self._region

		serials = ElementTree.Element("serials")

		serials.attrib["digitalserial1"] = self._requested_title_id.str()

		source.append(details)
		source.append(serials)

		for name, cinfo in self._content_infos.items():
			rom_raw = ElementTree.Element("rom")
			rom_cdndec = ElementTree.Element("rom")
			rom_fulldec = ElementTree.Element("rom")

			rom_raw.attrib["format"] = "Default"
			rom_cdndec.attrib["format"] = "Titlekey Decrypted"
			rom_fulldec.attrib["format"] = "Decrypted"

			rom_raw.attrib["forcename"] = rom_cdndec.attrib["forcename"] = rom_fulldec.attrib["forcename"] = name
			if cinfo.type == ContentInfoType.TMD:
				rom_raw.attrib["version"] = rom_cdndec.attrib["version"] = rom_fulldec.attrib["version"] = str(int(self._tmd.title_version))
			rom_raw.attrib["size"] = rom_cdndec.attrib["size"] = rom_fulldec.attrib["size"] = str(cinfo.size)

			rom_raw.attrib["crc"] = cinfo.raw_hashes.crc32.hex()
			rom_raw.attrib["sha256"] = cinfo.raw_hashes.sha256.hex()
			rom_raw.attrib["sha1"] = cinfo.raw_hashes.sha1.hex()
			rom_raw.attrib["md5"] = cinfo.raw_hashes.md5.hex()

			if cinfo.type == ContentInfoType.Content:
				rom_cdndec.attrib["crc"] = cinfo.cdnlevel_decrypted_hashes.crc32.hex()
				rom_fulldec.attrib["crc"] = cinfo.contentlevel_decrypted_hashes.crc32.hex()
				
				rom_cdndec.attrib["sha1"] = cinfo.cdnlevel_decrypted_hashes.sha1.hex()
				rom_fulldec.attrib["sha1"] = cinfo.contentlevel_decrypted_hashes.sha1.hex()

				rom_cdndec.attrib["sha256"] = cinfo.cdnlevel_decrypted_hashes.sha256.hex()
				rom_fulldec.attrib["sha256"] = cinfo.contentlevel_decrypted_hashes.sha256.hex()

				rom_cdndec.attrib["md5"] = cinfo.cdnlevel_decrypted_hashes.md5.hex()
				rom_fulldec.attrib["md5"] = cinfo.contentlevel_decrypted_hashes.md5.hex()

				rom_raw.attrib["serial"] = rom_cdndec.attrib["serial"] = rom_fulldec.attrib["serial"] = cinfo.product_code
			source.append(rom_raw)
			if cinfo.type == ContentInfoType.Content:
				source.append(rom_cdndec)
				source.append(rom_fulldec)

		archive.append(source)


		game.append(archive)

		with open(os.path.join(self._basepath, "data.xml"), "wb") as xml:
			xml.write(ElementTree.tostring(game))

	def set_title_name(self, input: str):
		self._title_name = input

	def set_title_name_alt(self, input: str):
		self._alt_title_name = input

	def set_region(self, input: str):
		self._region = input

	def set_languages(self, input: List[str]):
		self._languages = input
	
	def set_dump_tool(self, input: str):
		self._dump_tool = input

	def set_dumper(self, input: str):
		self._dumper = input
