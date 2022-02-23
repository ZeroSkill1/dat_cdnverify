import os
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256, SHA
from Cryptodome.PublicKey import RSA

CERTS_SHA256 = \
{
	'Root-CA00000001-CP00000004' : bytes.fromhex('74B9ABEABD3D69E618F12D368CA552A37B5D55496527685847493C8C9158E7B3'), # Wii retail TMD certs hash
	'Root-CA00000001-CP00000007' : bytes.fromhex('03CE2468F00D1AAEA52D7193A2312B0FE87ECE72D43381C3B6BD4C57E700CDD7'), # DSi retail TMD certs hash
	'Root-CA00000001-XS00000003' : bytes.fromhex('5A03B381450A422598BE140BB2F4DD42D0DE4388855C94D92B690A7E7E260D86'), # Wii retail Ticket certs hash
	'Root-CA00000001-XS00000006' : bytes.fromhex('61BADF43329EEC10E1FD952BA55777E116CD25EC5BEFCBE823F13439B8FAE0DC'), # DSi retail Ticket certs hash
	'Root-CA00000002-CP00000007' : bytes.fromhex('C91E634317306A81E28CA499CC485B4D826BD649B85CFE24FE749E2A43C7D875'), # Wii dev TMD certs hash
	'Root-CA00000002-XS00000006' : bytes.fromhex('857E80D355C9F7A206E73919E00254F48ADC56E9968BACE81626A3C2D3D05CA3'), # Wii dev Ticket certs hash
	'Root-CA00000003-CP0000000b' : bytes.fromhex('915F773A0782D427C4CEF5492533E8ECF6FEA1EB8CCF596E69BA2A388D738AE1'), # 3DS / WiiU retail TMD certs hash
	'Root-CA00000003-XS0000000c' : bytes.fromhex('DC153C2B8A0AC874A9DC78610E6A8FE3E6B134D5528873C961FBC795CB47E697'), # 3DS / WiiU retail Ticket certs hash
	'Root-CA00000004-CP0000000a' : bytes.fromhex('972A32FF9D4BAA2F1A24CF211387F538C64BD48FDF13213DFC72FC8D9FDD010E'), # 3DS dev TMD certs hash
	'Root-CA00000004-CP00000010' : bytes.fromhex('C77272F3FBAE6EBFC2EBB7AC350289C43ABD6A864AF325C2733704CD4F7218E5'), # WiiU dev TMD certs hash
	'Root-CA00000004-XS00000009' : bytes.fromhex('E97E52C9A540E13F5B26789057D7C9B8D7888AB2532C035ED27071C61A8C2C70'), # 3DS dev Ticket certs hash
	'Root-CA00000004-XS0000000f' : bytes.fromhex('7D52C748074650B51479C945570AA54CC77DBDC15CD54F55D0C3C60BC46664F4'), # WiiU dev Ticket certs hash
}

def signature(data: bytes, certs: bytes):
	hash_types = { '00010001' : SHA, '00010004' : SHA256 }
	
	sig_type = data[:0x4].hex() # we only support 00010001/00010004 (RSA_2048 SHA1/SHA256)
	signature = data[0x4:0x104]
	issuer = data[0x140:0x180].decode('ascii').replace('\x00', '')
	
	if int.from_bytes(data[0x104:0x140], 'big') != 0: # non standard padding
		raise Exception("Non-zero padding detected in signature padding")
	
	if not issuer in CERTS_SHA256:
		raise Exception("Unknown certificate issuer")
	elif len(certs) != 0x700:
		raise Exception("Invalid certificate size")
	elif SHA256.new(certs).digest() != CERTS_SHA256[issuer]:
		raise Exception("Certficiate hash mismatch")

	if not sig_type in hash_types:
		raise Exception("Invalid signature type")
	
	pub_key = int.from_bytes(certs[0x1C8:0x2C8], 'big')
	pub_exp = int.from_bytes(certs[0x2C8:0x2CC], 'big')

	pkcs1_15.new(RSA.construct((pub_key, pub_exp))).verify(hash_types[sig_type].new(data[0x140:]), signature)
	
	
def ticket(ticket: bytes):
	content_index_size = int.from_bytes(ticket[0x2A8:0x2AC], 'big')
	expected_size = 0x140 + 0x164 + content_index_size

	if len(ticket) < expected_size: # certs appended
		raise Exception("Invalid ticket size")

	with open(os.path.join(os.environ["HOME"], ".3ds/CA00000003-XS0000000c.bin"), "rb") as tik_cert:
		Root_CA00000003_XS0000000c = tik_cert.read()
	
	signature(ticket[:expected_size], Root_CA00000003_XS0000000c)
	

def tmd(tmd: bytes):
	content_count = int.from_bytes(tmd[0x1DE:0x1E0], 'big')
	
	expected_size = 0x140 + 0xC4 + (64 * 0x24) + (content_count * 0x30)

	if len(tmd) < expected_size:
		raise Exception("Invalid TMD size")

	with open(os.path.join(os.environ["HOME"], ".3ds/CA00000003-CP0000000b.bin"), "rb") as tmd_cert:
		Root_CA00000003_CP0000000b = tmd_cert.read()
	
	signature(tmd[:0x140+0xC4], Root_CA00000003_CP0000000b)
	
	tmd_info_rec = tmd[0x204:0xB04]

	if SHA256.new(tmd_info_rec).digest() != tmd[0x1E4:0x204]:
		raise Exception("TMD Content Info Records hash mismatch")

	tmd_chunk_rec = tmd[0xB04:0xB04 + (0x30 * content_count)]
	info = [tmd_info_rec[x:x + 0x24] for x in range(0, len(tmd_info_rec), 0x24)]

	for i in info:
		if i == b'\0' * 0x24:
			continue
		i_offset = int.from_bytes(i[0:2], 'big')
		i_size = int.from_bytes(i[2:4], 'big')
		i_hash = i[4:36]

		hash_gen_chunk = SHA256.new(tmd_chunk_rec[i_offset * 0x30:(i_offset * 0x30) + (i_size * 0x30)])

		if hash_gen_chunk.digest() != i_hash:
			raise Exception("Content Chunk Records in Info Record hash mismatch")