# You will not be able to run this file here and will need to copy it onto your computer and run it on your machine.
# You will also need to make sure you have installed the requests module from PyPi (pip install)
import hashlib

import requests
from flask import Flask, render_template, request

app = Flask(__name__)


@app.route('/')
def password_checker():
    return render_template('./index.html')


@app.route('/', methods=['POST'])
def password_checker_result():
    if request.method == "POST":
        password = request.form['pwd']
        count = pwned_api_check(password)
        if count:
            results = f'{password} was found {count} times... you should probably change your password!'
            return render_template('index.html', results=results, count=count)
        else:
            results = f'{password} was NOT found. Carry on!'
            return render_template('index.html', results=results, count=count)


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the api and try again')
    return res


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)


if __name__ == '__main__':
    app.run()
