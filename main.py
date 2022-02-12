import base64
import os
import secrets, bcrypt
import json
from lib2to3.pytree import Base
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pathlib import Path
from getpass import getpass


# get current directory
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
    if isRegistered == False:
        salt = secrets.token_urlsafe(16)
    if isRegistered == True:
        # get salt from json
        with open(userKeyFile, 'r') as file:
            salt = json.loads(file.read())['salt']


    print("salt: ", salt)
    kdf = PBKDF2HMAC (
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes(salt, 'utf-8'),
        iterations=310000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password)) # wygenerowany klucz hasla
    #salt = bytes(salt, 'utf-8')
    #salt = salt.decode('utf-8')
    #string = secrets.decode()

    data = {'salt':salt, 'password':key.decode('utf-8')}

    return json.dumps(data)


def encryptUserData(user):
    userDataFile = userDir(user,'userDataFile')
    userKeyFile = userDir(user, 'userKeyFile')

    try:
        # get key from json file
        with open(userKeyFile, 'r') as file:
            key = json.loads(file.read())['password']

        # get user data to encrypt
        with open(userDataFile, 'r') as file:
            file_data = file.read()
        file_data = bytes(file_data, 'utf-8')

        # encrypt data
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

    # get size of file
    size = os.path.getsize(userDataFile)

    # if file is empty
    if size == 0:
        return 'empty'
    else:
        try: 
            # get user key from file json
            with open(userKeyFile, 'r') as file:
                key = json.loads(file.read())['password']

            # get user encrypted data to decrypt
            with open(userDataFile, 'rb') as file:
                file_data = file.read()
            #print("file_data", file_data)
            
            f = Fernet(key)

            # decrypt data
            decrypted_data = f.decrypt(file_data)
            #print("decrypted_data = ", decrypted_data)
            
            # write decrypted data to file
            #with open(userDataFile, 'wb') as file:
                #file.write(decrypted_data)

        except BaseException as err:
            print(err)
    return decrypted_data

def addUserData(user):
    userDataFile = userDir(user,'userDataFile')

    # get size of file
    size = os.path.getsize(userDataFile)

    userDataFile = userDir(user,'userDataFile')
    print("You chose to add new record.")
    userPage = input("Enter page: ")
    userLogin = input("Enter login: ")
    userPassword = getpass()

    # if file is empty
    if size == 0:
        new_dict = {'accounts':[]}
        data = {'userPage':userPage, 'userLogin':userLogin, 'userPassword':userPassword}
        new_dict['accounts'].append(data)
        with open(userDataFile, 'w') as file:
            file.write(json.dumps(new_dict))
    else:
        decryptedData = decryptUserData(user)
        jsonDict = json.loads(decryptedData)
        new_dict = {'userPage':userPage, 'userLogin':userLogin, 'userPassword':userPassword}
        




    


# def addUserData(user):
#     userDataFile = userDir(user,'userDataFile')

#     # get size of file
#     size = os.path.getsize(userDataFile)

#     newFile = False
#     # if file is empty
#     if size == 0:
#         newFile = True
#     else:
#         decryptUserData(user)

#     print("You chose to add new record.")
#     # enter user data
#     userPage = input("Enter page: ")
#     userLogin = input("Enter login: ")
#     userPassword = getpass()

#     # if newFile
#     if newFile:
#         template = '   ' + 'Page' + '                ' + 'Login' + '               ' + 'Password' + '\n'
#         # write default template
#         with open(userDataFile, 'w') as file:
#             file.write(template)

#     # get number of lines
#     with open(userDataFile, 'r') as file:
#         lines_count = len(file.readlines())

#     empty_char1 = 20-len(userPage)
#     empty_char1 = empty_char1*' '
#     empty_char2 = 20-len(userLogin)
#     empty_char2 = empty_char2*' '
#     print("number of lines in file: ", lines_count)
#     id = lines_count 
#     id = str(id)
#     userArray = [id + '  ', userPage, empty_char1, userLogin, empty_char2, userPassword, '\n']

#     # append array to file
#     with open(userDataFile, 'a') as file:
#         file.writelines(userArray)
    
#     # encrypt added record
#     encryptUserData(user)
#     userPanel(user)

def readUserData(user):
    # get user directory
    userDataFile = dirName + '/users/{}/data-{}.txt'.format(user, user)
        
    # get size of file
    size = os.stat(userDataFile).st_size

    # if file is empty
    if size == 0:
        print('file is empty')
    else:
        print('file is not empty ' + str(size))
        # decrypt user data
        decryptUserData(user)

        # read the data
        with open(userDataFile, 'r') as file:
            data = file.read()
        print("Your records: ")
        print(data)
        encryptUserData(user)

def delUserData(user):
    # get user directory
    userDataFile = dirName + '/users/{}/data-{}.txt'.format(user, user)
    # get size of file
    size = os.stat(userDataFile).st_size

    # if file is empty
    if size == 0:
        print('file is empty nothing to delete')
    else:
        readUserData(user)
        try:
            decryptUserData(user)
            with open(userDataFile, 'r') as file:
                lines = file.readlines()
            lines_lenght = len(lines)
            print('lines_length', lines_lenght)
            while True:
                record = int(input("Which record you want to delete? number... "))
                if record != 0 and record < lines_lenght:
                    del lines[record]
                    with open(userDataFile, 'w+') as file:
                        for line in lines:
                            file.write(line)
                    encryptUserData(user)
                    break
                else:
                    print("Enter valid number")
        except ValueError:
            print('Enter valid number')
# control user data
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
        # user input
        user = input('Login as user: ') 

        # check user file key directory
        userKeyFile = userDir(user, 'userKeyFile')
        path_to_file = userKeyFile
        path = Path(path_to_file)

        # if user exist check user authentication
        if path.is_file() == True:
            # password input
            password = bytes(getpass(), 'utf-8')

            # get user salt from txt file ...
            

            key = encryptPassword(password, user, isRegistered = True)
            
            # json loads
            key = json.loads(key)['password']
            print("key from json ", key)

            with open(userKeyFile, 'r') as file:
                filekey = json.loads(file.read())['password']
                print('key from json FILE ', filekey)

            if key == filekey:
                print("Login successful. Hello {}".format(user))
                userPanel(user)
            else:
                print("Wrong password.")
        else:
            print("No user found...")


# create user 
def setupAcc():
    while True:
        isRegistered = False
        # get user login & password
        user = input("Enter your NEW login: ")

        # get user directory
        dirUser = dirName + '/users/{}'.format(user)

        # if directory doesn't exists create user directory
        if not os.path.exists(dirUser):
            os.makedirs(dirUser)

            password = bytes(getpass(), 'utf-8')
            print("Directory for ", user, " Created.")

            
            # create user key file
            with open('{}/filekey-{}.key'.format(dirUser, user), 'w') as filekey:
                pass

            # get password key
            json = encryptPassword(password, user, isRegistered)
            print('json', json)

            print("LLLLLLLLLLLLLLLLLLL")
            # append user key to file to second line
            with open('{}/filekey-{}.key'.format(dirUser, user), 'a') as filekey:
                filekey.write(json)
            print("KKKKKKKKKKKKKKKKKKKK")
            # create data file
            with open('{}/data-{}.txt'.format(dirUser, user), 'w') as userDir:    
                pass
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
                    isRegistered = setupAcc() # return zaszyfrowany klucz
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
    

