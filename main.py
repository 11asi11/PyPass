# this is the main python file execute this file to run PyPass


import os
import json
from colorama import Fore
from hashlib import sha512
from getpass import getpass


from file_handler import add_credentails
from file_handler import remove_credentails
from file_handler import find_credentials_by_website
from file_handler import decrypt_credentials_file
import file_handler


from encryption import encrypt
from encryption import decrypt


CREDENTIALS_FILE_PATH = "credentials"
PASSWORD_FILE_PATH = "password"


file_handler.CREDENTIALS_FILE_PATH = CREDENTIALS_FILE_PATH

def banner():
    return """
 ██▓███ ▓██   ██▓ ██▓███   ▄▄▄        ██████   ██████ 
▓██░  ██▒▒██  ██▒▓██░  ██▒▒████▄    ▒██    ▒ ▒██    ▒ 
▓██░ ██▓▒ ▒██ ██░▓██░ ██▓▒▒██  ▀█▄  ░ ▓██▄   ░ ▓██▄   
▒██▄█▓▒ ▒ ░ ▐██▓░▒██▄█▓▒ ▒░██▄▄▄▄██   ▒   ██▒  ▒   ██▒
▒██▒ ░  ░ ░ ██▒▓░▒██▒ ░  ░ ▓█   ▓██▒▒██████▒▒▒██████▒▒
▒▓▒░ ░  ░  ██▒▒▒ ▒▓▒░ ░  ░ ▒▒   ▓▒█░▒ ▒▓▒ ▒ ░▒ ▒▓▒ ▒ ░
░▒ ░     ▓██ ░▒░ ░▒ ░       ▒   ▒▒ ░░ ░▒  ░ ░░ ░▒  ░ ░
░░       ▒ ▒ ░░  ░░         ░   ▒   ░  ░  ░  ░  ░  ░  
         ░ ░                    ░  ░      ░        ░  
         ░ ░                                          
"""


def status_fail():
    return Fore.WHITE + "[" + Fore.RED + " FAILED " + Fore.WHITE + "]"


def status_ok():
    return Fore.WHITE + "[" + Fore.GREEN + " OK " + Fore.WHITE + "]"


def status_note():
    return Fore.WHITE + "[ * ]"


def status_pause():
    input(Fore.WHITE + "press [" + Fore.GREEN + "ENTER" + Fore.WHITE + "] to continue")


def check_password(password: str):
    """check if the saved hased password is the specified password

    Args:
        password (str): the password to check with the hashed password

    Returns:
        bool: true if the password matches the hashed password false if not
        None: if the password file doesnt exist
    """
    
    hashed_password = sha512(password.encode()).hexdigest()
    if os.path.exists(PASSWORD_FILE_PATH):
        password_file = open(PASSWORD_FILE_PATH, "r")
        saved_password = password_file.read()
        return saved_password == hashed_password
    else:
        return None


def option_1():
    """change the password for encrypting the credentials file
    this function only changes the password saved hash and all the credentials that were saved with a diffrent password
    are now not accessible because they were encrypted using a diffrent password
    """
    print(status_note() + " if you will change your password all your encrypted credentials will be lost\nso choose a strong password that you will remember and never forget\nto maximize security use a very strong password that you didnt used in any website")
    password = getpass(Fore.WHITE + "enter your new password: ")
    hashed_password = sha512(password.encode()).hexdigest() # hash the new password
    password_file = open(PASSWORD_FILE_PATH, "w")
    password_file.write(hashed_password) # save the hash in the password file
    print(status_ok() + " password has been hashed and saved successfully in: " + Fore.GREEN + os.path.abspath(PASSWORD_FILE_PATH) + Fore.WHITE)
    status_pause()


def option_2():
    """adding credentials to the encrypted credentials file
    """
    print(status_note() + " you are adding encrypted credentials to the credentials file\nto encrypt and decrypt you must type in the password\nyour saved credentials will be saved in: " + Fore.GREEN + os.path.abspath(CREDENTIALS_FILE_PATH))
    password = getpass(Fore.WHITE + "enter your password: ")
    password_is_correct = check_password(password)
    if password_is_correct: # check if password is the same as the hashed password
        print(status_ok() + " correct password")
        print(status_note() + " enter the credentials you want to save:")
        # get the credentials the will be saved to the file
        _website = input(Fore.WHITE + "website: " + Fore.GREEN)
        _username = input(Fore.WHITE + "username: " + Fore.GREEN)
        _password = input(Fore.WHITE + "password: " + Fore.GREEN)
        # create json object convert it into str and add it to the credentials file
        credentials = { "website" : _website, "username" : _username, "password" : _password }
        credentials = json.dumps(credentials)
        add_credentails(credentials, password)
        print(status_ok() + " the credentials has been saved in: " + Fore.GREEN + os.path.abspath(CREDENTIALS_FILE_PATH) + Fore.WHITE)
    else:
        print(status_fail() + " wrong password")
    status_pause()


def option_3():
    """removing specific credentials from the credentials file
    """
    print(status_note() + " you are removing specific credentials from the credentials file")
    password = getpass(Fore.WHITE + "enter your password: ")
    password_is_correct = check_password(password)
    if password_is_correct:
        print(status_ok() + " correct password")
        print(status_note() + " enter the credetials you want to remove:")
        # get the credentials that will be removed
        _website = input(Fore.WHITE + "website: " + Fore.GREEN)
        _username = input(Fore.WHITE + "username: " + Fore.GREEN)
        _password = input(Fore.WHITE + "password: " + Fore.GREEN)
        
        credentials = { "website" : _website, "username" : _username, "password" : _password }
        credentials = json.dumps(credentials)
        remove_credentails(credentials, password) # remove the specified credentials from the credentials file
        print(status_ok() + " the credentials has been removed from: " + Fore.GREEN + os.path.abspath(CREDENTIALS_FILE_PATH))
    else:
        print(status_fail() + " wrong password")
    status_pause()


def option_4():
    """find all saved credentials that are for a specific website
    """
    print(status_note() + " find all your saved credentials for a specific website and decrypt them")
    password = getpass(Fore.WHITE + "enter your password: ")
    password_is_correct = check_password(password)
    if password_is_correct:
        _website = input("enter website: " + Fore.GREEN)
        credential_list = find_credentials_by_website(_website, password)
        if len(credential_list) == 0: # if no credentials for the specific website were found
            print(Fore.WHITE + "you dont have any saved credentials for the website: " + Fore.GREEN + _website)
        else:
            print(Fore.WHITE + "all your decrypted credentials for the website: " + Fore.GREEN + _website)
            for c in credential_list: # print the matching credentials that were found in the file
                print(c)
    else:
        print(status_fail() + " wrong password")
    status_pause()


def option_5():
    """decrypt the whole credentials file and print its content in plain text
    """
    print(status_note() + " you are decrypting the whole credentials file and all your credentials and passwords will be visible in plain text")
    password = getpass(Fore.WHITE + "enter your password: ")
    password_is_correct = check_password(password)
    if password_is_correct:
        print(status_ok() + " correct password")
        print(Fore.WHITE + "this is the decrypted credentials file:" + Fore.GREEN)
        for line in decrypt_credentials_file(password): # decrypt the credentials file and print the content
            print(line)
    else:
        print(status_fail() + " wrong password")
    status_pause()


def menu():
    """print the menu of the program

    Returns:
        str: users choice (1,2,3,4,5,exit)
    """
    print(Fore.WHITE + "\nMenu:")
    print(Fore.GREEN + "1)" + Fore.WHITE + " set my password")
    print(Fore.GREEN + "2)" + Fore.WHITE + " add credentials to the credentials file")
    print(Fore.GREEN + "3)" + Fore.WHITE + " remove credentials from the credentials file")
    print(Fore.GREEN + "4)" + Fore.WHITE + " find credentials in the credentials file")
    print(Fore.GREEN + "5)" + Fore.WHITE + " decrypt the whole credentials file and print it")
    print(Fore.GREEN + "exit)" + Fore.WHITE + " exit PyPass")
    return input(Fore.WHITE + "choose: " + Fore.GREEN)


def main():
    try:
        while True:
            os.system("clear") # if you are on windows change this to os.system("cls")
            print(Fore.RED + banner())
            menu_option = menu()
            if menu_option == "1":
                option_1()
            elif menu_option == "2":
                option_2()
            elif menu_option == "3":
                option_3()
            elif menu_option == "4":
                option_4()
            elif menu_option == "5":
                option_5()
            elif menu_option == "exit":
                exit()
            else:
                print(status_fail() + " unknown command: " + menu_option)
    except KeyboardInterrupt: # if Ctrl+C is pressed stop the program
        print(Fore.RED + "\nInterrupted" + Fore.WHITE)
        exit()
    finally:
        print(Fore.WHITE, end="") # change the color back to white


if __name__ == "__main__":
    main()
