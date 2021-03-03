import requests
import hashlib
import sys
import re


def read_pw_file(filename):
    password_dict = dict()
    with open(filename, 'r') as my_file:
        line_hold = ''
        key = None
        for line in my_file:
            temp = line.split(': ', 1)
            if line_hold == '':
                key = line.strip()
            elif temp[0] == 'password':
                password = temp[1].strip()
                password_dict[key] = password
            line_hold = line.strip()
    return password_dict


def convert_to_hash(password):
    hash_object = hashlib.sha1(password.encode())
    hash_code = hash_object.hexdigest()
    return hash_code


def split_hash(full_hash):
    hash_parts = {
        'first 5 chars': full_hash[:5],
        'remaining chars': full_hash[5:]
    }
    return hash_parts


def contact_api(first_5_hash_chars):
    pwned_url = f'https://api.pwnedpasswords.com/range/{first_5_hash_chars}'
    r = requests.get(pwned_url)
    if r.status_code == 200:
        hashes_received = r.text
        return hashes_received
    else:
        raise Exception('error connecting to API')


def check_if_pwned(remaining_hash, hashes_received, key=None):
    hashes_to_list = hashes_received.split()
    hash_data = []
    for hash_item in hashes_to_list:
        hash_and_count = hash_item.split(':')
        hash_data.append(hash_and_count)
    for hash_item in hash_data:
        if key and remaining_hash.upper() == hash_item[0]:
            return print(f"Password for '{key}' was found in {hash_item[1]} data breeches. Change it!!")
        elif remaining_hash.upper() == hash_item[0]:
            return print(f"'{password}' was found in {hash_item[1]} data breeches. Change it!!")
    if key:
        return print(f"Password for '{key}' is safe. Carry on.")
    else:
        return print(f"'{password}' is safe. Carry on.")


def process_password(password, key=None):
    new_hash = convert_to_hash(password)
    new_hash_split = split_hash(new_hash)
    hashes_received = contact_api(new_hash_split['first 5 chars'])
    if key:
        return check_if_pwned(new_hash_split['remaining chars'], hashes_received, key)
    else:
        return check_if_pwned(new_hash_split['remaining chars'], hashes_received)


if __name__ == '__main__':
    if len(sys.argv) > 1:
        file = sys.argv[1]
        password_dict = read_pw_file(file)
        for key, password in password_dict.items():
            process_password(password, key)
    else:
        password = 'temp'
        while password != 'q':
            password = input("Type the password you'd like to check or type 'q' to quit: ")
            if password == 'q':
                print('All done!')
                break
            else:
                process_password(password)
