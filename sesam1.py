from hashlib import pbkdf2_hmac

lower_case_letters = list("abcdefghijklmnopqrstuvwxyz")
upper_case_letters = list("abcdefghjklmnpqrtuvwxyz".upper())
numbers = list("0123456789")
spec_char = list('#!"§$%&/()[]{}=-_+*<>;:.')
pw_char = lower_case_letters + upper_case_letters + \
    numbers + spec_char
salt = 'pepper'


def convert_bytes_to_pw(hashed_bytes, length):
    number = int.from_bytes(hashed_bytes, byteorder="big")
    password = ""
    while number > 0 and len(password) < length:
        password += pw_char[number % len(pw_char)]
        number = number // len(pw_char)
    return password



master_password = input('Masterpasswort: ')
domain = input('Domain: ')

while len(domain) < 1:
    print('Please enter domain: ')
    domain = input('Domain: ')

hash_string = domain + master_password

hashed_bytes = pbkdf2_hmac(
    'sha512',
    hash_string.encode('utf-8'),
    salt.encode('utf-8'),
    4096)
    
print("Passwort: " + convert_bytes_to_pw(hashed_bytes, 10))

