from Crypto.Cipher import AES
import hashlib as h
import os

__salt__: bytearray = bytearray([
    32,	31,	31,	31,	32,	32,	32,	32,
    5,	5,	5,	5,	5,	5,	5,	5,
    5,	5,	69,	69,	69,	69,	0,	0,
    0,	0,	0,	50,	50,	33,	33,	33
])


def GenerateSecretKey() -> bytearray:
	key = GetSalt(256)
	return GetPBKDFhmac(key, GetSalt(256))


def GetHashFromText(text: str) -> bytearray:
	return GetSha256(text, __salt__)


def GetSha256(text: str, salt: bytearray) -> bytearray:
	return bytearray(h.sha256(text.encode() + salt).digest())


def GetMasterKey(password: str, salt: bytearray) -> bytearray:
	return GetPBKDFhmac(password.encode('utf-8'), salt)


def GetPBKDFhmac(password: bytearray, salt: bytearray, len: int = 32) -> bytearray:
	return h.pbkdf2_hmac('sha256', password, salt, 100000, dklen=len)


def GetSalt(size: int = 32) -> bytearray:
	return bytearray(os.urandom(size))


def EncodeData(data: bytearray) -> bytearray:
	return bytearray(list(data) + [246] + [1] * (16 - (len(data) + 1) % 16))


def DecodeData(data: bytearray) -> bytearray:
	data = list(data)

	for i in range(-1, -18, -1):
		if data[i] == 246:
			return bytearray(data[:i])
	return data


def EncryptAes256(byteText: bytearray, password: bytearray, salt: bytearray) -> bytearray:
	if len(password) != 32:
		raise Exception('Некорректный пароль')

	if len(salt) != 16:
		raise Exception('Некорректная соль')

	cipher = AES.new(password, AES.MODE_CBC, iv=salt)
	cipherByteText = cipher.encrypt(EncodeData(byteText))
	return cipherByteText


def DecryptAes256(byteText: bytearray, password: bytearray, salt: bytearray) -> bytearray:
	if len(password) != 32:
		raise Exception('Некорректный пароль')

	if len(salt) != 16:
		raise Exception('Некорректная соль')

	cipher = AES.new(password, AES.MODE_CBC, iv=salt)
	cipherByteText = cipher.decrypt(byteText)
	return DecodeData(cipherByteText)


def EncryptFileAes256(inputPath: str, password: bytearray, salt: bytearray, outToFile: bool, outputPath: str=''):
	if not os.path.exists(inputPath) or not os.path.isfile(inputPath):
		raise Exception('Некорректный путь до входного файла')

	if outToFile and inputPath != outputPath:
		try:
			open(outputPath, 'w').close()
		except:
			raise Exception('Некорректный путь до выходного файла')
	
	byteText = open(inputPath, 'rb').read()
	encryptedByteText = EncryptAes256(byteText, password, salt)
	
	if outToFile: 
		open(outputPath, 'wb').write(encryptedByteText)
	else: 
		return encryptedByteText


def DecryptFileAes256(inputPath: str, password: bytearray, salt: bytearray, outToFile: bool, outputPath: str = ''):
	if not os.path.exists(inputPath) or not os.path.isfile(inputPath):
		raise Exception('Некорректный путь до входного файла')

	if outToFile and inputPath != outputPath:
		try:
			open(outputPath, 'w').close()
		except:
			raise Exception('Некорректный путь до выходного файла')

	byteText = open(inputPath, 'rb').read()
	decryptedByteText = DecryptAes256(byteText, password, salt)

	if outToFile:
		open(outputPath, 'wb').write(decryptedByteText)
	else:
		return decryptedByteText


def EncryptToFile(path: str, password: bytearray, salt: bytearray, text: str):
	encryptedText = EncryptAes256(text.encode('utf-8'), password, salt)
	with open(path, 'wb') as file:
		file.write(encryptedText)


def ChangeEncryptionPassword(path: str, password: bytearray, newPassword: bytearray, salt: bytearray):
	if not os.path.exists(path) or not os.path.isfile(path):
		raise Exception('Некорректный путь до входного файла')
	
	encryptedText = DecryptFileAes256(path, password, salt, False)

	with open(path, 'wb') as file:
		file.write(EncryptAes256(encryptedText, newPassword, salt))
