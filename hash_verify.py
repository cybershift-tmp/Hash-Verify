# Import hashlib library (md5 method is part of it)
import hashlib

#md5 verification function!
def md5_check(file, orignal_hash):

    # File to check
    file_name = file

    # Correct original md5 goes here
    original_md5 = str(orignal_hash)  

    # Open,close, read file and calculate MD5 on its contents 
    with open(file_name, 'rb') as file_to_check:
        # read contents of the file
        data = file_to_check.read()    
        # pipe contents of the file through
        md5_returned = hashlib.md5(data).hexdigest()

    # Finally compare original MD5 with freshly calculated
    if original_md5 == md5_returned:
        print("MD5 verified.")
    else:
        print("MD5 verification failed!.")




#sha1 verification function!
def sha1_check(file, orignal_hash):
    file_name = file
    original_sha1 = str(orignal_hash)
    
    with open(file_name, 'rb') as file_to_check:
        data = file_to_check.read()
        sha1_returned = hashlib.sha1(data).hexdigest()

    if original_sha1 == sha1_returned:
        print('SHA1 verified.')
    else:
        print('SHA1 verification failed!.')





#sha256 verification function!
def sha256_check(file, orignal_hash):
    file_name = file
    original_sha256 = str(orignal_hash)
    
    with open(file_name, 'rb') as file_to_check:
        data = file_to_check.read()
        sha256_returned = hashlib.sha256(data).hexdigest()

    if original_sha256 == sha256_returned:
        print('SHA256 verified.')
    else:
        print('SHA256 verification failed!.')










#Interface and calling functions 
hash_type = input('Which hash to check? : ')
file = str(input('Enter the full path for the file : '))
orignal_hash = str(input('Enter the orignal hash : '))

if hash_type == 'sha1' or 'SHA1':
    sha1_check(file, orignal_hash)

elif hash_type == 'md5' or 'MD5':
    md5_check(file, orignal_hash)

elif hash_type == 'sha256' or 'SHA256':
    sha256_check(file, orignal_hash)

