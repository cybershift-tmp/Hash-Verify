
import os.path
import hashlib



# Function to check file size
# calculate file size in KB, MB, GB
def convert_bytes(size):
    """ Convert bytes to KB, or MB or GB"""
    for x in ['bytes', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return "%3.1f %s" % (size, x)
        size /= 1024.0






#md5 verification function!
def md5_check(file, orignal_hash):

    # File to check
    file_name = file

    # Correct original md5 goes here
    original_md5 = str(orignal_hash)   
    print('Be Patient!')
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
    print('Be Patient!')
    with open(file_name, 'rb') as file_to_check:
        data = file_to_check.read()
        sha1_returned = hashlib.sha1(data).hexdigest()

    if original_sha1 == sha1_returned:
        print('SHA1 verified.')
    else:
        print('SHA1 verification failed!.')

# sha256 verification function!
def sha256_check(file, orignal_hash):
    file_name = file
    original_sha256 = str(orignal_hash)
    print('Be Patient!')
    with open(file_name, 'rb') as file_to_check:
        data = file_to_check.read()
        sha256_returned = hashlib.sha256(data).hexdigest()

    if original_sha256 == sha256_returned:
        print('SHA256 verified.')
    else:
        print('SHA256 verification failed!.')

# sha512 verification function!
def sha512_check(file, orignal_hash):
    file_name = file
    original_sha512 = str(orignal_hash)
    print('Be Patient!')
    with open(file_name, 'rb') as file_to_check:
        data = file_to_check.read()
        sha512_returned = hashlib.sha512(data).hexdigest()

    if original_sha512 == sha512_returned:
        print('SHA512 verified.')
    else:
        print('SHA512 verification failed!.')

# sha256 verification function!
def sha3_256_check(file, orignal_hash):
    file_name = file
    original_sha3_256 = str(orignal_hash)
    print('Be Patient!')
    with open(file_name, 'rb') as file_to_check:
        data = file_to_check.read()
        sha3_256_returned = hashlib.sha3_256(data).hexdigest()

    if original_sha3_256 == sha3_256_returned:
        print('SHA3_256 verified.')
    else:
        print('SHA3_256 verification failed!.')



# Functions for large files
# A utility function that can be used in your code
def md5_check_large(file, orignal_hash):
    hash_md5 = hashlib.md5()
    original_md5 = str(orignal_hash) 
    print('Be Patient!')
    with open(file, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    md5_returned =  hash_md5.hexdigest()
    if original_md5 == md5_returned:
        print("MD5 verified.")
    else:
        print("MD5 verification failed!.")




#Interface and calling functions 
hash_type = input('Which hash to check? : ')
file = str(input('Enter the full path for the file : '))
orignal_hash = str(input('Enter the orignal hash : '))


# Checking file size
f_size = os.path.getsize(file)

file_size = (convert_bytes(f_size))
print(f'File Size Is : {file_size}')


if f_size < 6442450944:      
    if hash_type == 'sha1' or 'SHA1':
        sha1_check(file, orignal_hash)

    elif hash_type == 'md5' or 'MD5':
        md5_check(file, orignal_hash)

    elif hash_type == 'sha256' or 'SHA256':
        sha256_check(file, orignal_hash)

    elif hash_type == 'sha3' and '256' or 'SHA3' and '256':
        sha3_256_check(file, orignal_hash)

else:
    md5_check_large(file, orignal_hash)