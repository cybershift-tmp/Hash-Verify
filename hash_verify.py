import os.path
import hashlib




# md5 check function
def md5_check(file, orignal_hash):

    f_size = os.path.getsize(file)#checks the file size in byte
    file_name = file#renamed the variable so the function below can access it
    original_md5 = str(orignal_hash)#storing the original hash you got
    
    print('Be Patient!')

    if f_size < 4294967296:#condition so so it will full file directly and hash it or read in different chunks
        #directly reads and hashes the file consumes very much ram according to the file size
        with open(file_name, 'rb') as file_to_check:#opens the file in other variable called file_to_check
            data = file_to_check.read()    #reads the file
            md5_returned = hashlib.md5(data).hexdigest() #hashes the current file
    else:#reads and hashes the file in smaller chunks of size 51200 bytes
        hash_md5 = hashlib.md5()#calling the function in the variable
        with open(file, "rb") as file_to_check:#opens the file in other variable called file_to_check
            for chunk in iter(lambda: file_to_check.read(51200), b""):#for loop to read the file in smaller chunks of 51200 bytes until finished
                hash_md5.update(chunk)#updates the hash after reading every chunk
        md5_returned =  hash_md5.hexdigest()#converts the hash in the string into the readaable format
    
    print(f'orignal    : {original_md5}')#prints the orignal hash
    print(f'calculated : {md5_returned}')#prints the current calculated hash of the file
    
    if original_md5 == md5_returned:#checks if both the hashes are same
        print("MD5 verified.")
    else:
        print("MD5 verification failed!.")

# sha1 check function
def sha1_check(file, orignal_hash):
    f_size = os.path.getsize(file)
    file_name = file
    original_sha1 = str(orignal_hash)   
    
    print('Be Patient!')

    if f_size < 4294967296:
        with open(file_name, 'rb') as file_to_check:
            data = file_to_check.read()    
            sha1_returned = hashlib.sha1(data).hexdigest()
    else:
        hash_sha1 = hashlib.sha1()
        with open(file, "rb") as file_to_check:
            for chunk in iter(lambda: file_to_check.read(51200), b""):
                hash_sha1.update(chunk)
        sha1_returned =  hash_sha1.hexdigest()
    
    print(f'orignal    : {original_sha1}')
    print(f'calculated : {sha1_returned}')

    if original_sha1 == sha1_returned:
        print("SHA1 verified.")
    else:
        print("SHA1 verification failed!.")

# sha256 check function
def sha256_check(file, orignal_hash):
    f_size = os.path.getsize(file)
    file_name = file
    original_sha256 = str(orignal_hash)   
    
    print('Be Patient!')

    if f_size < 4294967296:
        with open(file_name, 'rb') as file_to_check:
            data = file_to_check.read()    
            sha256_returned = hashlib.sha256(data).hexdigest()
    else:
        hash_sha256 = hashlib.sha256()
        with open(file, "rb") as file_to_check:
            for chunk in iter(lambda: file_to_check.read(51200), b""):
                hash_sha256.update(chunk)
        sha256_returned =  hash_sha256.hexdigest()
    
    print(f'orignal    : {original_sha256}')
    print(f'calculated : {sha256_returned}')

    if original_sha256 == sha256_returned:
        print("SHA256 verified.")
    else:
        print("SHA256 verification failed!.")

# sha3_256 check function
def sha3_256_check(file, orignal_hash):
    f_size = os.path.getsize(file)
    file_name = file
    original_sha3_256 = str(orignal_hash)   
    
    print('Be Patient!')

    if f_size < 4294967296:
        with open(file_name, 'rb') as file_to_check:
            data = file_to_check.read()    
            sha3_256_returned = hashlib.sha3_256(data).hexdigest()
    else:
        hash_sha3_256 = hashlib.sha3_256()
        with open(file, "rb") as file_to_check:
            for chunk in iter(lambda: file_to_check.read(51200), b""):
                hash_sha3_256.update(chunk)
        sha3_256_returned =  hash_sha3_256.hexdigest()
    
    print(f'orignal    : {original_sha3_256}')
    print(f'calculated : {sha3_256_returned}')

    if original_sha3_256 == sha3_256_returned:
        print("SHA3_256 verified.")
    else:
        print("SHA3_256 verification failed!.")



#Interface and calling functions 
hash_type = input('Which hash to check? : ')
file = str(input('Enter the full path for the file : '))
orignal_hash = str(input('Enter the orignal hash : '))



if 'md5' in hash_type.lower():
    md5_check(file, orignal_hash)

elif 'sha' in hash_type.lower():
    if '3' in hash_type:
        sha3_256_check(file, orignal_hash)
    elif '256' in hash_type:
        sha256_check(file, orignal_hash)
    else:
        sha1_check(file, orignal_hash)

else:
    print('Ran into some problem, wait for a while!')