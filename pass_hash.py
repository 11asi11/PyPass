from hashlib import sha512
print(sha512('password'.encode()).hexdigest())
