from http.server import HTTPServer, BaseHTTPRequestHandler
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta, timezone
from jwt.utils import base64url_encode, bytes_from_int
import json
import uuid
import jwt
import sqlite3

class RequestHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.db_connection = sqlite3.connect("totally_not_my_privateKeys.db")
        self.db_cursor = self.db_connection.cursor()

        self.db_cursor.execute('''
            CREATE TABLE IF NOT EXISTS keys(
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
            )
        ''')
        self.db_connection.commit()

    def do_PUT(self):
        self.send_response(405)
        self.end_headers()

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.end_headers()

            self.db_cursor.execute("SELECT key, exp FROM keys WHERE exp > ?", (datetime.now(tz=timezone.utc).timestamp(),))
            keys = self.db_cursor.fetchall()
            jwks = {"keys": []}

            for key, exp in keys:
                public_key = serialization.load_pem_public_key(key.encode("UTF-8"))
                jwk = {
                    "kid": str(uuid.uuid4()),
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "n": base64url_encode(bytes_from_int(public_key.public_numbers().n)).decode("UTF-8"),
                    "e": base64url_encode(bytes_from_int(public_key.public_numbers().e)).decode("UTF-8"),
                }
                jwks["keys"].append(jwk)

            self.wfile.write(json.dumps(jwks, indent=1).encode("UTF-8"))
            return
        else:
            self.send_response(405)
            self.end_headers()
            return

    def do_POST(self):
        if self.path == "/auth":
            self.send_response(200)
            self.end_headers()

            expired = self.headers.get("expired")  # Check if the "expired" header is present

            if expired:
                # Read an expired key from the database
                self.db_cursor.execute("SELECT key FROM keys WHERE exp <= ? LIMIT 1", (datetime.now(tz=timezone.utc).timestamp(),))
            else:
                # Read a valid (unexpired) key from the database
                self.db_cursor.execute("SELECT key FROM keys WHERE exp > ? LIMIT 1", (datetime.now(tz=timezone.utc).timestamp(),))

            key = self.db_cursor.fetchone()
            if key:
                key = key[0]
                private_key = serialization.load_pem_private_key(key.encode("UTF-8"), password=None)

                # Sign a JWT with the private key
                key_id = str(uuid.uuid4())
                expiry_time = datetime.now(tz=timezone.utc) + timedelta(seconds=3600)
                jwt_token = jwt.encode({"exp": expiry_time}, private_key, algorithm="RS256", headers={"kid": key_id})
                self.wfile.write(bytes(jwt_token, "UTF-8"))

            return
        else:
            self.send_response(405)
            self.end_headers()
            return

    def generate_key_pair(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return private_key

http_server = HTTPServer(("", 8080), RequestHandler)
print("HTTP Server is running on localhost port 8080!")

try:
    http_server.serve_forever()
except KeyboardInterrupt:
    pass

http_server.server_close()

