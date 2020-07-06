import os
from db import DB
import security as S

def GetAllNotes(path: str) -> list:
	if not(os.path.exists(path) and os.path.isdir(path)):
		raise Exception('Некорректный путь')
	return [f'{path}/{x}' for x in os.listdir(path)]


def GetNote(path: str, password: bytearray, salt: bytearray) -> str:
	return S.DecryptFileAes256(path, password, salt, False).decode()


def AddNote(path: str, name: str, password: bytearray, salt: bytearray, text: str) -> str:
	fullPath = f'{path}/{name}.note'

	S.EncryptToFile(fullPath, password, salt, text)
	return fullPath


def DeleteNote(path: str):
	if not(os.path.exists(path) and os.path.isfile(path)):
		raise Exception('Некорректный путь')
	os.remove(path)


def ChangeNote(path: str, password: bytearray, salt: bytearray, newText: str):
	if not(os.path.exists(path) and os.path.isfile(path)):
		raise Exception('Некорректный путь')

	S.EncryptToFile(path, password, salt, newText)
