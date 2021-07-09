# in this file there are all the credentials file handling functions
# using these functions its possible to access the encrypted credentials file
# without a risk of corrupting the encrypted data
# the credentials are saved in the format of json object:
# { "website" : "github", "username" : "11asi11", "password" : "s0m3P4ssw0rd" }


import json
from encryption import encrypt
from encryption import decrypt


CREDENTIALS_FILE_PATH = ""


def add_credentails(credentials: str, password: str):
    """encrypting credentials and adding them to the credentials file

    Args:
        credentials (str): the credentials to add in plain text
        password (str): the password to use with the encryption
    """
    credentials = encrypt(credentials, password) # encrypt the credentials
    file = open(CREDENTIALS_FILE_PATH, "a")
    file.write(credentials + "\n") # write the encrypted credentials to the file
    file.close()


def remove_credentails(credentials: str, password: str):
    """searching for any credentials in the file that matches the provided credentials
    and removes them from the credentials file

    Args:
        credentials (str): the credentials to remove in plain text
        password (str): the password to decrypting the saved credentials
    """
    file = open(CREDENTIALS_FILE_PATH, "r")
    content = file.readlines()
    file.close()
    credential_list = []
    for i in range(len(content)): # loop through the credentials file and check each credential
        credentials_from_file = decrypt(content[i], password) # decrypt credentials
        if credentials_from_file == credentials: # check if it matches to the provided credentials
            content[i] = "" # remove the credentials if matches
    file = open(CREDENTIALS_FILE_PATH, "w")
    file.writelines(content) # rewrite the credentials file
    file.close()


def find_credentials_by_website(website_name: str, password: str):
    """searching for any credentials for the specified website

    Args:
        website_name (str): the website name to search with
        password (str): the password for the credentials file to access

    Returns:
        list: list of all the credentials for the specified website
    """
    file = open(CREDENTIALS_FILE_PATH, "r")
    content = file.readlines()
    credential_list = []
    for c in content:
        credentials = decrypt(c, password)
        credentials = json.loads(credentials)
        if credentials["website"] == website_name: # if the website name matches add the credentials to the list
            credential_list.append(credentials)
    return credential_list


def decrypt_credentials_file(password: str):
    """decrypting the whole credentials file

    Args:
        password (str): password for decrypting the credentials file

    Returns:
        list: all the credentials in the file in plain text
    """
    file = open(CREDENTIALS_FILE_PATH, "r")
    content = file.readlines()
    credential_list = []
    for c in content:
        credentials = decrypt(c.replace("\n", ""), password) # decrypt each of credentials in the file and add it to the list
        credential_list.append(credentials)
    return credential_list
