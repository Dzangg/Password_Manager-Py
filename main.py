import base64
import os
import secrets
import json
from lib2to3.pytree import Base
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pathlib import Path
from getpass import getpass


dirName = os.getcwd()


def userDir(user, file):
    if file == 'userDataFile':
        userDataFile = dirName + '/users/{}/data-{}.txt'.format(user, user)
        return userDataFile
    if file == 'userKeyFile':
        userKeyFile = dirName + '/users/{}/filekey-{}.key'.format(user, user)
        return userKeyFile

# create password key
def encryptPassword(password, user, isRegistered):
    # if account is not registered
    #       generate the salt with secrets.token_bytes() 
    # else: acc exist -> does have salt already
    #       get salt from file
    userKeyFile = userDir(user, 'userKeyFile')
    password = password.encode('utf-8')
    if isRegistered == False:
        salt = secrets.token_urlsafe(16)
    if isRegistered == True:
        with open(userKeyFile, 'r') as file:
            salt = json.loads(file.read())['salt']

    kdf = PBKDF2HMAC (
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode('utf-8'),
        iterations=310000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password)) # generated password key

    data = {'salt':salt, 'password':key.decode('utf-8')}
    return json.dumps(data)

def encryptUserData(user):
    userDataFile = userDir(user,'userDataFile')
    userKeyFile = userDir(user, 'userKeyFile')

    try:
        with open(userDataFile, 'r') as file:
            file_data = file.read()
        file_data = bytes(file_data, 'utf-8')

        with open(userKeyFile, 'r') as file:
            salt = json.loads(file.read())['password']

        kdf = PBKDF2HMAC (
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode('utf-8'),
        iterations=310000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8'))) # generated password key
        f = Fernet(key)
        encrypted_data = f.encrypt(file_data)

        # write encrypted data to file
        with open(userDataFile, 'wb') as file:
            file.write(encrypted_data)

    except BaseException as err:
        print(err)


def decryptUserData(user):
    userDataFile = userDir(user,'userDataFile')
    userKeyFile = userDir(user, 'userKeyFile')

    size = os.path.getsize(userDataFile)

    if size == 0:
        return 'empty'
    else:
        try: 
            with open(userDataFile, 'rb') as file:
                file_data = file.read()

            with open(userKeyFile, 'r') as file:
                salt = json.loads(file.read())['password']

            kdf = PBKDF2HMAC (
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt.encode('utf-8'),
            iterations=310000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8'))) # generated password key
            f = Fernet(key)

            decrypted_data = f.decrypt(file_data)
            return decrypted_data

        except BaseException as err:
            print(err)

def addUserData(user):
    userDataFile = userDir(user,'userDataFile')

    size = os.path.getsize(userDataFile)

    userDataFile = userDir(user,'userDataFile')
    print("Add new record: ")
    userPage = input("Enter page: ")
    userLogin = input("Enter login: ")
    userPassword = getpass()
    try:
        if size == 0:
            new_dict = {'accounts':[]}
            data = {'id':0, 'page':userPage, 'login':userLogin, 'password':userPassword}
            new_dict['accounts'].append(data)
            with open(userDataFile, 'w') as file:
                file.write(json.dumps(new_dict))
            encryptUserData(user)
            print("Record added.")
        else:
            decryptedData = decryptUserData(user)
            jsonDict = json.loads(decryptedData)
            id = 0
            for item in range(0,len(jsonDict['accounts'])):
                id = id + 1
            new_dict = {'id':id,'page':userPage, 'login':userLogin, 'password':userPassword}
            jsonDict['accounts'].append(new_dict)
            with open(userDataFile, 'w') as file:
                file.write(json.dumps(jsonDict))
            encryptUserData(user)
            print("Record added.")
    except BaseException as err:
        print("Adding new record failed.")
        print(err)


def readUserData(user):
    userDataFile = userDir(user,'userDataFile')
    size = os.stat(userDataFile).st_size
    if size == 0:
        print('No records found')
    else:
        decryptedData = decryptUserData(user)
        jsonDict = json.loads(decryptedData)
        print("Your saved accounts: ")
        for item in range(0,len(jsonDict['accounts'])):
            print(jsonDict['accounts'][item])

def delUserData(user):
    userDataFile = userDir(user,'userDataFile')
    size = os.stat(userDataFile).st_size
    if size == 0:
        print('file is empty nothing to delete')
    else:
        try:
            readUserData(user)
            decryptedData = decryptUserData(user)
            jsonDict = json.loads(decryptedData)
            while True:
                record = int(input("Which record you want to delete? id number... "))
                for item in range(0,len(jsonDict['accounts'])):
                    print(jsonDict['accounts'][item])
                if record > -1 and record < len(jsonDict['accounts']):
                    for item in range(0, len(jsonDict['accounts'])):
                        if jsonDict['accounts'][item]['id'] == record:
                            x = record
                    jsonDict['accounts'].pop(x)
                    if len(jsonDict['accounts']) == 0:
                        with open(userDataFile, 'w') as file:
                            pass
                    else:
                        id = 0
                        for item in range(0,len(jsonDict['accounts'])):
                            jsonDict['accounts'][item]['id'] = id
                            id = id + 1
                        with open(userDataFile, 'w') as file:
                            file.write(json.dumps(jsonDict))
                        encryptUserData(user)
                        print("Record deleted.")
                    break
                else:
                    print("Enter valid number")
        except BaseException as err:
            print(err)

def userPanel(user):
    while True:
        choice = input("Choose your action: (1) List all (2) Add record (3) Delete record ")
        if choice in ['1','2','3']:
            if choice == '1':
                readUserData(user)
            if choice == '2':
                addUserData(user)
            if choice == '3':
                delUserData(user)
        else:
            print("Wrong option.")

def loginAcc():
    while True:
        user = input('Login as user: ') 

        userKeyFile = userDir(user, 'userKeyFile')
        path_to_file = userKeyFile
        path = Path(path_to_file)

        # if user exist check user authentication
        if path.is_file() == True:
            global password
            password = getpass()
            key = encryptPassword(password, user, isRegistered = True)
            
            key = json.loads(key)['password']

            with open(userKeyFile, 'r') as file:
                filekey = json.loads(file.read())['password']

            if key == filekey:
                print("Login successful. Hello {}".format(user))
                userPanel(user)
            else:
                print("Wrong password.")
        else:
            print("No user found...")
            return


# create user 
def setupAcc():
    while True:
        isRegistered = False
        user = input("Enter your NEW login: ")

        dirUser = dirName + '/users/{}'.format(user)

        # if directory doesn't exists create user directory
        if not os.path.exists(dirUser):
            os.makedirs(dirUser)
            password = getpass()
            
            with open('{}/filekey-{}.key'.format(dirUser, user), 'w') as filekey:
                pass

            json = encryptPassword(password, user, isRegistered)

            # append user key to file 
            with open('{}/filekey-{}.key'.format(dirUser, user), 'a') as filekey:
                filekey.write(json)
            # create data file
            with open('{}/data-{}.txt'.format(dirUser, user), 'w') as userDir:    
                pass
            print("Directory for ", user, " created. ")
            isRegistered = True
            return isRegistered
        else:
            break


def main():
    while True:
        choice = input("Welcome to Password Manager, please choose an action: (1) Sign Up (2) Log In: ")
        if choice not in ['1', '2']:
            print("Wrong option try again: ")
            continue
        else:
            if choice == '1':
                try:
                    isRegistered = setupAcc() 
                    if isRegistered:
                        print("Succesfully registered")
                    else:
                        print("You can't register, this name already exists.")
                except BaseException as err:
                    print("Something went wrong")
                    print('error is', err)
                    break
            else:
                loginAcc()


if __name__ == '__main__':
    main()
    

