
# Project Name: Client-Server File Transfer System

## Table of Contents
- [Project Description](#project-description)
- [Features](#features)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Known Issues](#known-issues)
- [Contributing](#contributing)
- [License](#license)

## Project Description

This project implements a client-server file transfer system with the following features:
- Secure file transfer using AES encryption for the file content and RSA for key exchange.
- CRC (Cyclic Redundancy Check) validation to ensure file integrity.
- Support for handling multiple packets in file transfer, allowing transmission of large files.
- Database integration to store metadata related to file transfers.

The system is designed to handle robust file communication between a client and server, ensuring data security and integrity during transmission.

## Features

- **File Transfer**: Send and receive files between client and server in packets.
- **Encryption**: AES encryption for secure file transmission and RSA for key exchange.
- **CRC Validation**: Integrity check using CRC values to verify file contents.
- **Database Integration**: Store metadata of files transferred, including checksum values and file details.

## Project Structure

```
.
├── client/                 # Client-side code
│   ├── src/
│   │   ├── client.cpp      # Main client logic
│   │   ├── requests.hpp    # Request handling definitions
│   │   └── requests.cpp    # Request handling implementation
│   └── README.md
├── server/                 # Server-side code
│   ├── main.py             # Main server logic
│   ├── db_handler.py       # Database handler
│   └── README.md
├── README.md               # Project README file
└── LICENSE                 # License information
```

## Requirements

- **Client**:
  - C++ compiler (MSVC, GCC, or Clang)
  - Boost library for networking
  - CMake for project configuration

- **Server**:
  - Python 3.7+
  - Required Python libraries (see below for installation)

### Python Libraries

For the server, install the dependencies using `pip`:
```bash
pip install -r server/requirements.txt
```

`requirements.txt` should include:
- `pycryptodome` (for AES encryption)
- `sqlite3` (for database handling, if not already included with Python)
- `logging` (for logging functionality)

## Installation

### Client

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/projectname.git
   ```

2. Navigate to the `client` directory and build the client using CMake:
   ```bash
   cd client
   mkdir build && cd build
   cmake ..
   make
   ```

### Server

1. Clone the repository (if not done already):
   ```bash
   git clone https://github.com/yourusername/projectname.git
   ```

2. Navigate to the `server` directory and install dependencies:
   ```bash
   cd server
   pip install -r requirements.txt
   ```

## Usage

### Running the Server

1. Start the server by running:
   ```bash
   python server/main.py
   ```

   The server will listen on the specified host and port for incoming client connections.

### Running the Client

1. Compile the client and run it, specifying the server’s IP address and port:
   ```bash
   ./client [server_ip] [port]
   ```

### Example Usage

1. The client will initiate a connection to the server and proceed with sign-up or sign-in.
2. Files can be sent in packets; the client splits large files into chunks and sends each as a separate packet.
3. Upon successful transfer, the server validates the file using CRC and stores file metadata in the database.

## Configuration

- **Client**:
  - Configure encryption keys and file paths in `client/src/client.cpp`.
  - Modify network settings in the code as necessary.

- **Server**:
  - Set database connection details in `db_handler.py`.
  - Update encryption settings in `main.py` if using different keys.

## Known Issues

- **Large Files**: Currently, large files may face transfer issues due to network constraints.
- **Error Handling**: Limited error handling for unexpected disconnections during file transfers.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request for any improvements.

1. Fork the repository.
2. Create a new branch (`git checkout -b feature/YourFeature`).
3. Commit your changes (`git commit -m 'Add some feature'`).
4. Push to the branch (`git push origin feature/YourFeature`).
5. Open a Pull Request.

## License

Distributed under the MIT License. See `LICENSE` for more information.
