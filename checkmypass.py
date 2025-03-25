import requests #this allows python to make web requests, like a browser
import hashlib #the API uses SHAI-1
import sys
import os


def request_api_data(query_char):
	url = 'https://api.pwnedpasswords.com/range/' + query_char #First 5 characters of hash password
	res = requests.get(url)
	if res.status_code != 200:
		raise RuntimeError(f'Error: {res.status_code}, check the API and try again')
	return res

def get_password_leaks_count(hashes, hash_to_check):
	hashes = (line.split(':') for line in hashes.text.splitlines())
	for h, count in hashes:
		if h == hash_to_check:
			return count
	return 0

def pwned_api_check(password):
	#check password if it exists in API response
	sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
	first5_char, tail = sha1password[:5], sha1password[5:]
	response = request_api_data(first5_char)
	print(response)
	return get_password_leaks_count(response, tail)

def main(filename):

	if not os.path.isfile(filename):
		print(f"File '{filename}' does not exist")
		return

	with open(filename, 'r') as file:
		passwords = [line.strip() for line in file if line.strip()]

	for password in passwords:
		count = pwned_api_check(password)
		if count:
			print(f'{password} was found {count} times... you should probably change your password')
		else:
			print(f'{password} was not Found! Keep it')
	return 'done'

if __name__ == '__main__':
	if len(sys.argv) != 2:
		print("Hey! the correct way to run the script is 'python checkmypass.py file.txt")
		sys.exit(1)
	sys.exit(main(sys.argv[1]))
