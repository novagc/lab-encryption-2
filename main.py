import os
import shutil
import getpass as gp
import security as S
import random as R
import notes as N

from db import DB

dbName = 'test'
auth = False

db = DB(dbName)
userPath = ''
userLogin = ''
userSalt = bytearray()
userMasterKey = bytearray()
userSecretKey = bytearray()
userPasswordHash = bytearray()

def Auth() -> int:
	global db
	global userMasterKey
	global userSecretKey
	global userPasswordHash
	global userSalt
	global userPath
	global userLogin
	global auth

	os.system('cls||clear')
	login = input('Login: ')
	
	if not db.Exist(login):
		print('Такого пользователя не существует\nДля продолжения нажмите ENTER')
		input()
		return 0
	
	password = gp.getpass('Password: ')
	os.system('cls||clear')
	
	userMasterKey = S.GetMasterKey(password, S.GetHashFromText(login))
	userInfo = db.GetUser(login, userMasterKey)

	if userInfo[1] != S.GetHashFromText(password):
		print('Неправильный пароль\nДля продолжения нажмите ENTER')
		input()
		return -1

	userSecretKey = userInfo[0]
	userPasswordHash = userInfo[1]
	userSalt = userInfo[2]
	userPath = userInfo[3]
	userLogin = login
	
	auth = True
	return 1


def Register() -> int:
	global db
	global userMasterKey
	global userSecretKey
	global userPasswordHash
	global userSalt
	global userPath
	global userLogin
	global auth

	os.system('cls||clear')
	login = input('Login: ')

	if db.Exist(login):
		print('Такого пользователь уже существует\nДля продолжения нажмите ENTER')
		input()
		return 0
	
	password = gp.getpass('Password: ')

	if password != gp.getpass('Repeat password: '):
		print('Пароли не совпадают\nДля продолжения нажмите ENTER')
		input()
		return -1

	userMasterKey = S.GetMasterKey(password, S.GetHashFromText(login))
	userSecretKey = S.GenerateSecretKey()
	userPasswordHash = S.GetHashFromText(password)
	userSalt = S.GetSalt()
	userPath = f'./{login}'
	userLogin = login

	db.AddUser(login, userSecretKey, userPasswordHash, userSalt, userPath, userMasterKey)

	if not os.path.exists(f'./{login}'):
		os.mkdir(f'./{login}')
	
	auth = True
	return 1


def DeleteUser() -> int:
	global db
	global userMasterKey
	global userSecretKey
	global userPasswordHash
	global userSalt
	global userPath
	global userLogin
	global auth

	os.system('cls||clear')
	ans = input('Вы уверены, что хотите удалить аккаунт? (y/n):\n')
	
	if ans != 'y':
		return -1

	db.Remove(userLogin)
	
	shutil.rmtree(userPath)

	userMasterKey = []
	userSecretKey = []
	userPasswordHash = []
	userSalt = []
	userPath = ''
	userLogin = ''
	auth = False

	return 1


def ChangeSecretKey():
	global db
	global userMasterKey
	global userSecretKey
	global userPasswordHash
	global userSalt
	global userPath
	global userLogin
	global auth

	os.system('cls||clear')
	ans = input('Вы уверены, что хотите удалить аккаунт? (y/n):\n')

	if ans != 'y':
		return -1

	osk = userSecretKey
	userSecretKey = S.GenerateSecretKey()

	db.ChangeSecretKey(userLogin, userMasterKey, userSecretKey)
	for x in N.GetAllNotes(userPath):
		S.ChangeEncryptionPassword(x, osk, userSecretKey, userSalt[:16])
	

def CreateNote():
	global db
	global userMasterKey
	global userSecretKey
	global userPasswordHash
	global userSalt
	global userPath
	global userLogin
	global auth

	os.system('cls||clear')

	buffer = []
	print('Чтобы закончить ввод введите в отдельной строке точку')

	while True:
		temp = input()
		if temp == '.':
			break
		buffer.append(temp)

	os.system('cls||clear')
	name = input('Введите название заметки: ')

	if name == '':
		print('Вы ввели пустую строку')
		name = R.randint(0, 10e75)
		print('Имя заметки - ', name)
	
	N.AddNote(userPath, name, userSecretKey, userSalt[:16], '\n'.join(buffer))


def DeleteNote():
	ans = input('Вы уверены, что хотите удалить заметку? (y/n):\n')

	if ans != 'y':
		return -1

	name = input('Введите имя заметки: ')
	N.DeleteNote(f'{userPath}/{name}.note')

def DeleteAllNotes():
	os.system('cls||clear')
	ans = input('Вы уверены, что хотите удалить все заметки? (y/n):\n')

	if ans != 'y':
		return -1
	
	shutil.rmtree(userPath)
	os.mkdir(userPath)
	return 1


def GetNote():
	ind = int(input('Номер заметки: '))
	notes = N.GetAllNotes(userPath)
	print(N.GetNote(notes[ind], userSecretKey, userSalt[:16]))
	print('Для продолжения нажмите ENTER')
	input()
	os.system('cls||clear')


def GetAllNotes():
	[print(f'{i}: {x}') for i, x in enumerate(N.GetAllNotes(userPath))]


def ChangeNote():
	ind = int(input('Номер заметки: '))
	notes = N.GetAllNotes(userPath)
	buffer = []
	print('Чтобы закончить ввод введите в отдельной строке точку')

	while True:
		temp = input()
		if temp == '.':
			break
		buffer.append(temp)
	
	N.ChangeNote(notes[ind], userSecretKey, userSalt[:16], '\n'.join(buffer))


def Main():
	while True:
		os.system('cls||clear')
		if not auth:
			c = input('1) Войти\n2) Зарегистрироваться\n> ')
			if c[0] == '1':
				Auth()
			elif c[0] == '2':
				Register()
		else:
			while auth:
				os.system('cls||clear')

				if not os.path.exists(userPath):
					os.mkdir(userPath)

				c = input('1) Управление аккаунтом\n2) Работа с заметками\n3) Общее\n> ')
				
				if c == '1':
					while auth:
						os.system('cls||clear')
						c = input('1) Удалить аккаунт\n2) Изменить ключ шифрования\n0) Назад\n> ')
						if c == '1':
							DeleteUser()
						elif c == '2':
							ChangeSecretKey()
						elif c == '0':
							break

				elif c == '2':
					os.system('cls||clear')

					while auth:
						print()
						c = input(
							'1) Создать заметку\n2) Изменить заметку\n3) Удалить заметку\n4) Удалить все заметки\n5) Получить список заметок\n6) Прочитать конкретную заметку\n0) Назад\n> ')
						print()
						if c == '1':
							CreateNote()
						elif c == '2':
							ChangeNote()
						elif c == '3':
							DeleteNote()
						elif c == '4':
							DeleteAllNotes()
						elif c == '5':
							GetAllNotes()
						elif c == '6':
							GetNote()
						elif c == '0':
							break
					
				elif c == '3':
					while auth:
						os.system('cls||clear')
						c = input('1) Выйти\n0) Назад\n> ')
						if c == '1':
							exit(0)
						elif c == '0':
							break


Main()
