from Crypto.Hash import SHA256
import sqlite3
import base64
import time
import os
import utils


class DataBaseHandler:

    DB_FILE_NAME = "server.db"
    CLIENTS_TABLE = "clients"
    TEMP_FILE_PATH = "saved"
    FILES_TABLE = "files"

    def __init__(self):
        self.conn = sqlite3.connect(self.DB_FILE_NAME)
        self._create_tables()

    def create_new_client(self, username: str) -> None:
        self._validate_username(username)
        client_id = os.urandom(utils.CLIENT_ID_LEN)
        cursor = self.conn.cursor()
        cursor.execute(
            f"INSERT INTO {self.CLIENTS_TABLE} (id, name, public_key, last_seen, aes_key) VALUES (?, ?, ?, ?, ?);",
            (client_id, username, bytes(0), time.asctime(), bytes(0)),
        )
        self.conn.commit()
        cursor.close()

    def get_client_by_name(self, username: str):
        """Get a client by their username."""
        self._validate_username(username)

        cursor = self.conn.cursor()
        cursor.execute(
            f"SELECT * FROM {self.CLIENTS_TABLE} WHERE name = ?;", (username,)
        )
        rows = cursor.fetchall()
        cursor.close()
        if not rows:
            return []
        return rows[0]

    def get_client_by_id(self, client_id):
        """Get a client by their ID."""
        cursor = self.conn.cursor()
        cursor.execute(
            f"SELECT * FROM {self.CLIENTS_TABLE} WHERE id = ?;", (client_id,)
        )
        rows = cursor.fetchall()
        cursor.close()
        if not rows:
            return []
        return rows[0]

    def update_public_key(self, client_id, public_key):
        """Update a client's public key."""
        cursor = self.conn.cursor()
        cursor.execute(
            f"UPDATE {self.CLIENTS_TABLE} SET public_key = ? WHERE id = ?;",
            (public_key, client_id),
        )
        self.conn.commit()
        cursor.close()

    def update_aes_key(self, client_id, aes_key):
        """Update a client's AES key."""
        cursor = self.conn.cursor()
        cursor.execute(
            f"UPDATE {self.CLIENTS_TABLE} SET aes_key = ? WHERE id = ?;",
            (aes_key, client_id),
        )
        self.conn.commit()
        cursor.close()

    def insert_unvalidated_file(self, filename: str, file_content, file_id):
        """Insert a file into the database."""
        self._validate_filename(filename)

        if not os.path.exists(self.TEMP_FILE_PATH):
            os.mkdir(self.TEMP_FILE_PATH)
        file_path = self._id_to_path(file_id, filename)
        with open(file_path, "wb") as f:
            f.write(file_content)

        cursor = self.conn.cursor()
        cursor.execute(
            f"INSERT INTO {self.FILES_TABLE} (id, filename, saved_path, verified) VALUES (?, ?, ?, ?);",
            (file_id, filename, file_path, 0),
        )
        self.conn.commit()
        cursor.close()

    def set_file_to_valid(self, file_id):
        """Set a file to be valid."""
        cursor = self.conn.cursor()
        cursor.execute(
            f"UPDATE {self.FILES_TABLE} SET verified = ? WHERE filename = ?;",
            (1, file_id),
        )
        self.conn.commit()
        cursor.close()

    def _create_tables(self):
        cursor = self.conn.cursor()
        cursor.execute(
            f"""CREATE TABLE IF NOT EXISTS {self.CLIENTS_TABLE} (
                    id BLOB PRIMARY KEY,
                    name TEXT,
                    public_key BLOB,
                    last_seen TEXT,
                    aes_key BLOB
                )"""
        )
        cursor.execute(
            f"""CREATE TABLE IF NOT EXISTS {self.FILES_TABLE} (
                    id BLOB,
                    filename TEXT,
                    saved_path TEXT,
                    verified INTEGER
                )"""
        )
        cursor.close()

    def _validate_username(self, username: str) -> None:
        for ch in username:
            if not ch.isalpha() and ch != " ":
                raise ValueError("Invalid username.")

    def _validate_filename(self, username: str) -> None:
        for ch in username:
            if not ch.isalnum() and ch != " " and ch != "." and ch != "/":
                raise ValueError("Invalid filename.")

    def _id_to_path(self, file_id, filename):
        return (
            self.TEMP_FILE_PATH
            + "/"
            + str(base64.b32encode(file_id), "utf-8")
            + SHA256.new(bytes(filename, "utf-8")).hexdigest()
            + ".tmp"
        )
