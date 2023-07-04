#!/usr/bin/python3

from http import server
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from urllib.parse import urlparse
from socketserver import ThreadingMixIn
from datetime import datetime
from collections import OrderedDict

import http.client
import threading
import time
import binascii

import random
import json
import sys
import os
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

import sqlite3
import bcrypt

current_dir_path = os.path.dirname(os.path.abspath(__file__))
KEY_LENGTH = 32
action_ids = ["action" + str(i) for i in range(32)]
#_endpoint_data = {"trigger0" : "{ \"ConditionImageUrl\": \"https://imageurl.com/image.jpg\" }"}
server_salt = b'$2b$12$eGObDmmwNbOszD0FEEf83u'
nonce_pool = []
action_endpoint = "http://192.168.1.3:7778/action_data/"
dbPath = ""
self_ip = ''
self_port = -1
connection = ''
NONCE_TIMEWINDOW = 5
encrypted = ""

## TODO:
#POST methods:
#   - register_user : params {username, password, trigger_id, key_trigger} : returns {oauth_token}
#   - even_data : params: {trigger_endpoint, oauth_token, nonce} : returns {encrypted trigger blob}

def send_response(handler, response_code: int, response_string: str):
    handler.send_response(response_code)
    handler.send_header('Content-type', 'application/json')
    handler.send_header("Content-Length", str(len(response_string.encode())))
    handler.end_headers()
    handler.wfile.write(response_string.encode())

def verify_data(data, params):
    global nonce_pool
    nonce = data["nonce"]
    if nonce in nonce_pool:
        return False
    nonce_pool += [nonce]
    if "action_url" not in params:
        return False
    return params["action_url"] == action_endpoint

def verify_data_plain(data, params):
    # Nominal TAP does no verification
    return True

def generate_token(username, password):
    global server_salt
    h = bcrypt.kdf((username + password).encode(), server_salt, 64, 100)
    return binascii.hexlify(h).decode() 

def check_request_validity(body, request: str):
    global KEY_LENGTH
    global action_ids
    if request == 'register':
        for field in ['username', 'password', 'action_id', 'key_action']:
            if field not in body:
                return False
        tid = int(body['action_id'])
        if tid >= 32:
            return False
        return len(body['key_action']) == KEY_LENGTH * 2
    if request == 'action_data':
        for field in ['action_id', 'oauth_token', 'ciphertext', 'tag', 'params', 'iv']:
            if field not in body:
                return False
        tid = int(body['action_id'])
        if tid >= 32:
            return False
        return len(body['oauth_token']) == 128
    if request == 'action_data_plain':
        for field in ['action_id', 'oauth_token', 'body', 'params']:
            if field not in body:
                return False
        aid = int(body['action_id'])
        if aid >= 32:
            return False
        return True
    return False
        
def hash_password(password: str):
    global server_salt
    h = bcrypt.hashpw(password.encode(), server_salt)
    return h.decode()
    
class HandleRequests(BaseHTTPRequestHandler):
    # disable logging
    def log_message(self, format, *args):
        return

    def validate_string(self, string_to_validate):
        try:
            string_to_validate.encode('ASCII')
        except UnicodeEncodeError:
            package = {"error": "invalid char in body"}
            response = json.dumps(package)

            send_response(self, 400, response)
            return False

        if '[' in string_to_validate or ']' in string_to_validate:
            package = {"error": "invalid char in body"}
            response = json.dumps(package)
            return False

        return True

    def do_GET(self):
        response = {"success" : "HELLO from action service"}
        send_response(self, 200, json.dumps(response))

    def do_POST(self):
        global self_ip
        global self_port
        global dbPath

        content_len = int(self.headers.get('Content-Length'))
        post_body = self.rfile.read(content_len)
        #print (post_body)
        decoded_body = post_body.decode()

        #print (decoded_body)
        body = json.loads(decoded_body)

        try:
            connection = sqlite3.connect(dbPath, detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
        except Exception as e:
            package = {"error": "error opening database connection: ".format(e)}
            response = json.dumps(package)
        
            send_response(self, 500, response)
            return

        cursor = connection.cursor()
        try:
            route = urlparse(self.path)
        except UnicodeEncodeError:
            package = {"error": "error parsing POST body"}
            response = json.dumps(package)

            send_response(self, 400, response)
            return
        print (route.path)

        if route.path == "/register/":
           
            if not check_request_validity(body, 'register'):
                send_response(self, 400, json.dumps({"error": "error parsing POST JSON"}))
                return
            
            username = body['username']
            password = body['password']
            action_id = body['action_id']
            key_action = body['key_action']

            try:
                cursor.execute("SELECT count(username) FROM action%s WHERE username='%s'" % (action_id, username))
                result = cursor.fetchone()
            except Exception as e:
                message = "Internal server error1: {}".format(e)
                package = {"error": message}
                response = json.dumps(package)

                send_response(self, 500, response)
                return

            print ("result: " + str(result))
            if result[0] != 0:
                send_response(self, 400, json.dumps({"error": "Username already exists"}))
                return
            
            #Insert row
            token = generate_token(username, password)
            password_hash = hash_password(password)
            try:
                cursor.execute("INSERT INTO action%s VALUES ('%s', '%s', '%s', '%s')" % (action_id, token, username, password_hash, key_action))
                connection.commit()
            except Exception as e:
                message = "Internal server error2: {}".format(e)
                package = {"error": message}
                response = json.dumps(package)

                send_response(self, 500, response)
                return
            
            send_response(self, 200, json.dumps({"success" : "successfully registered user", "oauth_token" : token}))
            return

        if route.path == "/action_data_plain/":
            if not check_request_validity(body, 'action_data_plain'):
                send_response(self, 400, json.dumps({"error": "error parsing action_data_plain request"}))
                return
            try:
                cursor.execute("SELECT * from action%s where token='%s'" % (body['action_id'], body['oauth_token']))
                result = cursor.fetchall()
            except Exception as e:
                message = "Internal server error: {}".format(e)
                package = {"error": message}
                response = json.dumps(package)

                send_response(self, 500, response)
            
            if len(result) == 0:
                send_response(self, 400, json.dumps({"error": "Invalid Token"}))
                return

            params = body["params"]
            if verify_data_plain(body, params):
                send_response(self, 200, json.dumps({"error": "Successful action execution"}))
            else:
                send_response(self, 500, json.dumps({"error": "Data verification failed"}))
            return

            
        
        if route.path == '/action_data/':
            if not check_request_validity(body, 'action_data'):
                send_response(self, 400, json.dumps({"error": "error parsing action_data request"}))
                return
            try:
                cursor.execute("SELECT * from action%s where token='%s'" % (body['action_id'], body['oauth_token']))
                result = cursor.fetchall()
            except Exception as e:
                message = "Internal server error: {}".format(e)
                package = {"error": message}
                response = json.dumps(package)

                send_response(self, 500, response)
            
            if len(result) == 0:
                send_response(self, 400, json.dumps({"error": "Invalid Token"}))
                return
            
            print(result)
            key = binascii.unhexlify(result[0][3])

            dec_nonce = binascii.unhexlify(body["iv"])
            tag = binascii.unhexlify(body["tag"])
            ciphertext = binascii.unhexlify(body["ciphertext"])

            cipher = AES.new(key, AES.MODE_GCM, nonce=dec_nonce)

            #print (body['params'])
            #try:
            #    params = json.loads(body['params'])
            #except Exception as e:
            #    message = "Internal server error: {}".format(e)
            #    package = {"error": message}
            #    response = json.dumps(package)

            #    send_response(self, 500, response)
            
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            print (plaintext)

            send_response(self, 200, json.dumps({"error": "success"}))
            #if verify_data(plaintext, params):
            #    send_response(self, 200, json.dumps({"error": "success"}))
            #else:
            #    send_response(self, 500, json.dumps({"error": "Data verification failed"}))

def nonce_shuffle():
    global NONCE_TIMEWINDOW
    time.sleep(NONCE_TIMEWINDOW)
    nonce_pool.clear()

# ------------ end of handle request ------------
def populate_database(cursor, action_ids):
    for action_id in action_ids:
        cursor.execute(''' SELECT count(name) FROM sqlite_master WHERE type='table' AND name=? ''', (action_id,))
        if cursor.fetchone()[0] == 0:
            cursor.execute("CREATE TABLE %s (token text PRIMARY KEY, username text, password_hash text, enc_key text)" % (action_id))

class Server(ThreadingMixIn, HTTPServer):
    if __name__ == '__main__':
        global dbPath
        global self_ip
        global self_port
        global action_ids
        global connection
        global encrypted

        dbName = 'actions.db'
        dbPath = os.path.join(current_dir_path, dbName)
        self_ip = str(sys.argv[1])
        self_port = str(sys.argv[2])
        if len(sys.argv) == 4:
            encrypted = sys.argv[3]

        connection = sqlite3.connect(dbPath, detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
        cursor = connection.cursor()
        # make sure we only create the table once
        populate_database(cursor, action_ids)
        #cursor.execute(''' SELECT count(name) FROM sqlite_master WHERE type='table' AND name='records' ''')
        #if cursor.fetchone()[0] == 0:
        #    cursor.execute('''CREATE TABLE 'records' (key text PRIMARY KEY, value text, time integer )''')

        print("[+] Connected to Database")
        server = ThreadingHTTPServer((self_ip, int(self_port)), HandleRequests)
        print('Server initializing, reachable at http://{}:{}'.format(self_ip, self_port))
        
        # start nonce and timewindow thread
        t = threading.Thread(target=nonce_shuffle, daemon=True)
        t.start()
        
        # start server
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            # Clean-up server (close socket, etc.)
            # t.join()
            server.server_close()

