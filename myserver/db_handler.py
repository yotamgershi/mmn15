import logging
import sqlite3
from typing import Optional, Tuple
from datetime import datetime


class DBHandler:
    def __init__(self, db_file: str):
        """Initialize the database connection."""
        self.connection = sqlite3.connect(db_file)
        self.create_tables()
        print(f"Database connection established: {db_file}")

    def create_tables(self):
        """Create the clients and files tables if they don't exist."""
        cursor = self.connection.cursor()

        # Create clients table
        cursor.execute('''CREATE TABLE IF NOT EXISTS clients (
                            ID BLOB PRIMARY KEY NOT NULL,
                            Name TEXT NOT NULL,
                            PublicKey BLOB NOT NULL,
                            LastSeen TEXT NOT NULL,
                            AESKey BLOB NOT NULL
                          )''')

        # Create files table
        cursor.execute('''CREATE TABLE IF NOT EXISTS files (
                            ID BLOB NOT NULL,
                            FileName TEXT NOT NULL,
                            PathName TEXT NOT NULL,
                            Verified BOOLEAN NOT NULL,
                            Checksum TEXT NOT NULL,
                            PRIMARY KEY (ID, FileName)
                          )''')

        self.connection.commit()

    def insert_client(self, client_id: bytes, name: bytes, public_key: bytes, last_seen: str, aes_key: bytes):
        """Insert a new client into the clients table."""
        name = name.rstrip(b'\x00').decode('utf-8')

        cursor = self.connection.cursor()
        cursor.execute('''INSERT INTO clients (ID, Name, PublicKey, LastSeen, AESKey)
                          VALUES (?, ?, ?, ?, ?)''', (client_id, name, public_key, last_seen, aes_key))
        self.connection.commit()
        logging.info(f"Inserted new client: {name} with ID: {client_id}")

    def is_registered(self, client_name: str) -> Optional[str]:
        """Check if a client with the given name is registered and return the client_id."""
        client_name = client_name.rstrip('\x00')

        logging.info(f"Checking if client is registered: {client_name}")

        cursor = self.connection.cursor()
        cursor.execute('SELECT ClientID FROM clients WHERE Name = ?', (client_name,))

        if (row := cursor.fetchone()) is not None:
            client_id = row[0]  # Assuming the first column is ClientID
            logging.info(f"Client is registered. ClientID: {client_id}")
            return client_id
        logging.info(f"Client not found: {client_name}")
        return None

    def get_client(self, client_id: bytes) -> Optional[Tuple]:
        """Fetch a client by ID."""
        cursor = self.connection.cursor()
        cursor.execute('SELECT * FROM clients WHERE ID = ?', (client_id,))
        return cursor.fetchone()

    def update_last_seen(self, client_id: bytes, last_seen: str):
        """Update the LastSeen field for a client."""
        cursor = self.connection.cursor()
        cursor.execute('''UPDATE clients
                          SET LastSeen = ?
                          WHERE ID = ?''', (last_seen, client_id))
        self.connection.commit()

    def insert_file(self, client_id: bytes, file_name: str, path_name: str, verified: bool, checksum: str):
        """Insert a new file entry for a client."""
        cursor = self.connection.cursor()
        cursor.execute('''INSERT INTO files (ID, FileName, PathName, Verified, Checksum)
                          VALUES (?, ?, ?, ?, ?)''', (client_id, file_name, path_name, verified, checksum))
        self.connection.commit()

    def get_file(self, client_id: bytes, file_name: str) -> Optional[Tuple]:
        """Fetch a file by client ID and file name."""
        cursor = self.connection.cursor()
        cursor.execute('SELECT * FROM files WHERE ID = ? AND FileName = ?', (client_id, file_name))
        return cursor.fetchone()

    def update_public_key(self, client_id: bytes, public_key: bytes) -> bool:
        """
        Updates the public key for a given client ID in the database.
        """
        try:
            cursor = self.connection.cursor()
            cursor.execute("""
                UPDATE clients
                SET PublicKey = ?
                WHERE ID = ?
            """, (public_key, client_id))

            self.connection.commit()
            logging.info(f"Updated public key for client {client_id.hex()}")
            return True
        except Exception as e:
            logging.error(f"Failed to update public key for client {client_id.hex()}: {e}")
            return False

    def get_aes_key(self, client_id: bytes) -> bytes:
        cursor = self.connection.cursor()
        cursor.execute("""
            SELECT AESKey FROM clients WHERE ID = ?
        """, (client_id,))
        result = cursor.fetchone()

        if result:
            return result[0]  # AES key is stored as the first column
        else:
            raise ValueError(f"No AES key found for client {client_id.hex()}")

    def update_client_keys(self, client_id: bytes, public_key: bytes, aes_key: bytes):
        """Update the client's public key, AES key, and LastSeen timestamp."""
        cursor = self.connection.cursor()
        last_seen = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Check if the client already exists in the database
        cursor.execute("SELECT ID FROM clients WHERE ID = ?", (client_id,))
        client = cursor.fetchone()

        if client:
            # Client exists, update their public key, AES key, and last seen timestamp
            cursor.execute("""
                UPDATE clients
                SET PublicKey = ?, AESKey = ?, LastSeen = ?
                WHERE ID = ?;
            """, (public_key, aes_key, last_seen, client_id))
        else:
            # Client does not exist, insert a new record
            cursor.execute("""
                INSERT INTO clients (ID, Name, PublicKey, LastSeen, AESKey)
                VALUES (?, ?, ?, ?, ?);
            """, (client_id, "ClientName", public_key, last_seen, aes_key))

    def close(self):
        """Close the database connection."""
        self.connection.close()
