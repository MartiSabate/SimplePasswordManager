import getpass
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidKey # import InvalidKey exception to handle the master key wrong password input


def load_key(): # key = password + text to encrypt = random text > > > then > > > random text + key + password = text to encrypt
    file = open("key.key", "rb")
    key = file.read()
    file.close()
    return key

def write_key():
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)


key = load_key() # + master_pwd.encode() # encode the password to conver the string into bytes so fer can handle it
fer = Fernet(key) # initialize the encryption module with the loaded key
# key = load_key() + pwd.encode() # For some reason this line works in the tutorial, however it is not used at all as per its complexity  hence left as this
# fer = Fernet(key)

# token1 = fer.encrypt(b'secret1') #< How to encrypt
# print((fer.decrypt(token1)).decode()) #< how to decrypt


def generateMasterPassword(): #function used to generate the master key and a random salt and store it in local files

    # generete a random salt
    SALT = os.urandom(16)
    MASTER_PWD_RAW = getpass.getpass(prompt="Por favor inserta la contraseña maestra: ")

    # Convert the input string to a byte string (encoded as UTF-8)
    MASTER_PWD = MASTER_PWD_RAW.encode('utf-8')

    with open("salt.key", "wb") as salt_file:
        salt_file.write(SALT)

    # This computes the derived key and finalizes the internal state of kdf.
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=480000,
    )

    key = kdf.derive(MASTER_PWD)

    with open("master.key", "wb") as key_file:
        key_file.write(key)

def verifyMasterPassword(): #ask the user a master password and verify it

    with open("salt.key", "rb") as file: #import salt from salt.key file
        SALT = file.read()


    MASTER_PWD_RAW = getpass.getpass(prompt="Por favor inserta la contraseña maestra: ")

    # Convert the input string to a byte string (encoded as UTF-8)
    MASTER_PWD = MASTER_PWD_RAW.encode('utf-8')

    # verify
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=480000,
    )

    with open("master.key", "rb") as file: # read master password key from master.key file
        key = file.read()

    try:
        kdf.verify(MASTER_PWD, key)
    except InvalidKey:
        print("Wrong password")
        return False
    else:
        print("The master password is correct. Access granted.")
        return True
        

def view():
    with open('passwords.txt', 'r') as f:
        for line in f.readlines():
            data = line.rstrip() # rstrip won't print blank lines
            user, passwd = data.split("|")
            print("User: ", user + "\nPassword: " + str(fer.decrypt(passwd.encode()).decode()))
            #user, passws = data.split("|")
            #print("User: ", user + "| Password: ", fer.decrypt(passw.encode()))


def add():
    name = input("Account name: ")
    pwd = input("Password: ")
    with open('passwords.txt', 'a') as f:
        #f.write(name + "|" + fer.encrypt(pwd.encode()).decode() + "\n")
        f.write(name + "|" + str(fer.encrypt(pwd.encode()).decode()) + "\n") #once the password is encoded and encrypted, it is being decoded so it doesn't store as byte string

def validateInput(input, x, y): #validate input to filter it as a digit between x and y. If the input is validated returns true otherwise it returns false

    if input.isdigit():
        numberedOption = int(input)
        if numberedOption >= x and numberedOption <= y:
            return True 
        else:
            print("Please insert a digit between " + str(x) + " and " + str(y))
            return False
    else:
        print("Please insert a digit")
        return False

def menu():
    while True:
        print("Welcome to a very simple password manager, made by Martí Sabaté.")
        #prompt user with 3 menu option
        print("Please select an option")
        print("[1] - Generate master password")
        print("[2] - Validate master password")
        print("[3] - Exit")
        option = input()
        
        if validateInput(option, 1, 3): #input validation for a digit between 1 and 3
            break
        else: 
            print("something wrong happened...")
    option = int(option) #convert option data type to int
    return option
            
            

            

        
def passwordManager():
    print("Welcome to the Password Manager")
    while True:
        print("Please select an option")
        print("[1] - View password mode")
        print("[2] - Add new credentials")
        print("[3] - Logout")
        option = input()
        if validateInput(option, 1, 3): #input validation for a digit between 1 and 3
            option = int(option)
            match option:
                case 1:
                    print("View mode selected")
                    view()
                case 2:
                    print("Add mode selected")
                    add()
                case 3:
                    break
                case _:
                    print("Invalid mode")
                    continue



while True:
    option = menu()
    match option:
        case 1:
            generateMasterPassword()
        case 2:
            if verifyMasterPassword(): #if the master password is correct then list possible password manager options
                passwordManager()
        case 3:
            break
