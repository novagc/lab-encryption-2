import security as S
import json
import os

class DB:
	__PASSWORD__ = bytearray([
		59, 59, 59, 59, 59, 59, 59, 59,
		59, 59, 59, 59, 59, 59, 59, 59,
		59, 59, 59, 59, 59, 59, 59, 59,
		59, 59, 59, 59, 59, 59, 59, 59
	])

	__SALT__ = bytearray([
		32,	32,	32,	32,	32,	32,	32,	32,	
		5 ,	5 ,	5 ,	5 ,	5 ,	5 ,	5 ,	5 ,	
		5 ,	5 ,	0 ,	0 ,	0 ,	0 ,	0 ,	0 ,
		0 ,	0 ,	0 ,	0 ,	0 ,	33,	33,	33
	])

	__SHORT_SALT__ = bytearray([
		32,	32,	32,	32,	32,	32,	32,	32,
		5,	5,	5,	5,	5,	5,	5,	5
	])


	def __init__(self, name: str):
		self.__name__ = name
		if not os.path.exists(f'./{name}.db'):
			open(f'./{name}.db', 'wb').write(S.EncryptAes256(bytearray(), DB.__PASSWORD__, DB.__SHORT_SALT__))
			self.__table__ = {}
		else:
			self.__table__ = json.loads(S.DecryptFileAes256(f'./{name}.db', DB.__PASSWORD__, DB.__SHORT_SALT__, False).decode('utf-8'))
	

	def AddUser(self, login: str, secretKey: bytearray, passwordHash: bytearray, salt: bytearray, path: str, masterKey: bytearray):
		if login in self.__table__:
			raise Exception('exist')

		self.Set(login, [
			S.EncryptAes256(secretKey, masterKey, self.__SHORT_SALT__).hex(),
			S.EncryptAes256(passwordHash, masterKey, self.__SHORT_SALT__).hex(),
			S.EncryptAes256(salt, masterKey, self.__SHORT_SALT__).hex(),
			S.EncryptAes256(path.encode(), masterKey, self.__SHORT_SALT__).hex()
		])


	def ChangeSecretKey(self, login: str, masterKey: bytearray, newSecretKey: bytearray):
		if not login in self.__table__:
			raise Exception('Don\'t exist')
		self.__table__[login][0] = S.EncryptAes256(newSecretKey, masterKey, self.__SHORT_SALT__).hex()


	def Exist(self, login: str):
		return login in self.__table__


	def GetUser(self, login: str, masterKey: bytearray):
		if not login in self.__table__:
			raise Exception('Don\'t exist')

		return [
			S.DecryptAes256(bytearray.fromhex(self.__table__[login][0]), masterKey, self.__SHORT_SALT__),
			S.DecryptAes256(bytearray.fromhex(self.__table__[login][1]), masterKey, self.__SHORT_SALT__),
			S.DecryptAes256(bytearray.fromhex(self.__table__[login][2]), masterKey, self.__SHORT_SALT__),
			S.DecryptAes256(bytearray.fromhex(self.__table__[login][3]), masterKey, self.__SHORT_SALT__).decode()
		]


	def Get(self, key:str):
		if not key in self.__table__:
			raise Exception('error')
		return self.__table__[key] 
		

	def Set(self, key:str, value):
		self.__table__[key] = value
		self.Save()


	def Remove(self, key:str):
		self.__table__.pop(key, None)
		self.Save()

	
	def Save(self):
		temp = json.dumps(self.__table__)
		S.EncryptToFile(f'./{self.__name__}.db', self.__PASSWORD__, self.__SHORT_SALT__, temp)
