
# fs-syslogd

`fs-syslogd` is a forward-secure syslog daemon designed to encrypt each log entry with a unique derived key using a Key Derivation Function (KDF). This ensures that even if one key is compromised, the security of previous and future logs is not affected. The system consists of a sender (the `fs-syslogd` daemon) and a receiver (the log receiver) which securely receives and decrypts log messages.

## Features

- **Forward Security**: Each log entry is encrypted with a unique derived key, ensuring robust forward security.
- **Asynchronous Logging**: Logs are sent asynchronously to reduce performance impact.
- **TLS Encryption**: All communications between the sender and receiver are secured using TLS.
- **Rate Limiting**: Prevents log flooding by limiting the number of log entries per second.
- **Log Rotation**: Supports log rotation and compression for better storage management.

## Repository Structure

```
fs-syslogd/
├── src/
│   ├── fs_syslogd.py           # Main sender implementation (fs-syslogd daemon)
│   ├── log_receiver.py         # Main receiver implementation (log receiver daemon)
│   ├── utils/
│   │   ├── encryption.py       # Utility functions for encryption/decryption
│   │   ├── kdf.py              # Utility functions for key derivation (KDF)
│   │   ├── config.py           # Configuration loading and management
│   └── benchmarks/
│       ├── benchmark_sender.py # Script for benchmarking the sender
│       ├── benchmark_receiver.py # Script for benchmarking the receiver
├── config/
│   ├── fs_syslogd_config.json  # Example configuration file for fs-syslogd
│   ├── receiver_config.json    # Example configuration file for log receiver
├── docs/
│   ├── deployment.md           # Deployment instructions and documentation
│   ├── architecture.md         # System architecture overview
│   └── benchmarking.md         # Detailed benchmarking instructions
├── systemd/
│   ├── fs-syslogd.service      # Systemd service file for fs-syslogd
│   └── log-receiver.service    # Systemd service file for log receiver
├── tests/
│   ├── test_encryption.py      # Unit tests for encryption functions
│   ├── test_kdf.py             # Unit tests for key derivation functions
│   └── test_integration.py     # Integration tests for the full system
├── README.md                   # Project overview and getting started guide
└── LICENSE                     # License file for the project
```

## Getting Started

### Prerequisites

- **Operating System**: Linux-based system (e.g., Ubuntu, CentOS)
- **Python**: Python 3.8 or higher installed on both sender and receiver systems
- **Systemd**: Systemd for managing services
- **OpenSSL**: OpenSSL installed for TLS/SSL operations

### Installation

1. **Clone the Repository**

```bash
git clone https://github.com/yourusername/fs-syslogd.git
cd fs-syslogd
```

2. **Install Dependencies**

```bash
pip install -r requirements.txt
```

3. **Set Up the Directory Structure**

```bash
mkdir -p /etc/fs-syslogd
mkdir -p /var/log/fs-syslogd
mkdir -p /var/log/fs-syslogd-received
chown -R root:fslogreaders /var/log/fs-syslogd-received
chmod -R 750 /var/log/fs-syslogd-received
```

### Configuration

1. **Create the Configuration File**

```bash
cp config/fs_syslogd_config.json /etc/fs-syslogd/fs_syslogd_config.json
cp config/receiver_config.json /etc/fs-syslogd/receiver_config.json
```

2. **Edit the Configuration**

Edit `/etc/fs-syslogd/fs_syslogd_config.json` and `/etc/fs-syslogd/receiver_config.json` to suit your environment. Key parameters include:

- **log_dir**: Directory for storing local logs.
- **key_file**: Path to the file storing the pre-shared key.
- **remote_log_servers**: List of log receiver endpoints.
- **shared_secret**: Pre-shared key used to derive encryption keys.

### Service Deployment

1. **Create Systemd Service Files**

```bash
cp systemd/fs-syslogd.service /etc/systemd/system/fs-syslogd.service
cp systemd/log-receiver.service /etc/systemd/system/log-receiver.service
```

2. **Enable and Start the Services**

```bash
systemctl enable fs-syslogd
systemctl start fs-syslogd

systemctl enable log-receiver
systemctl start log-receiver
```

3. **Check Service Status**

```bash
systemctl status fs-syslogd
systemctl status log-receiver
```


# Running Tests and Benchmarks for fs-syslogd

## Table of Contents

1. [Introduction](#introduction)
2. [Running Unit Tests](#running-unit-tests)
3. [Running Integration Tests](#running-integration-tests)
4. [Running Benchmarks](#running-benchmarks)
   - [Benchmarking the Sender](#benchmarking-the-sender)
   - [Benchmarking the Receiver](#benchmarking-the-receiver)
5. [Analyzing Results](#analyzing-results)

## Introduction

This document provides detailed instructions on how to run tests and benchmarks for the `fs-syslogd` project. The tests ensure that the encryption, key derivation, and overall integration work correctly, while benchmarks help you understand the performance characteristics of the system.

## Running Unit Tests

### 1. Setting Up the Environment

Before running the tests, ensure that you have installed the necessary dependencies:

```bash
pip install -r requirements.txt
```

### 2. Running the Unit Tests

Unit tests are located in the `tests/` directory and can be run using `unittest` or `pytest`.

#### Using `unittest`

```bash
python -m unittest discover -s tests
```

#### Using `pytest`

If you prefer `pytest`, you can run the tests with the following command:

```bash
pytest tests/
```

### 3. Unit Tests Included

- **test_encryption.py**: Tests the encryption and decryption functions to ensure that data can be securely encrypted and decrypted.
- **test_kdf.py**: Tests the key derivation function (KDF) to ensure consistent and correct key generation.
  
## Running Integration Tests

### 1. Running the Integration Tests

Integration tests verify that the sender and receiver work together as expected. The integration tests are also located in the `tests/` directory.

#### Using `unittest`

```bash
python -m unittest tests/test_integration.py
```

### 2. Test Coverage

The integration tests cover the following:

- Logging a message using `fs-syslogd`.
- Reading the log entry from the log file.
- Decrypting the log entry on the receiver side.
- Verifying that the decrypted message matches the original message.

## Running Benchmarks

### 1. Benchmarking the Sender

The sender benchmark measures the performance of the `fs-syslogd` daemon, including salt generation, key derivation, encryption, and total logging time.

#### Running the Benchmark

```bash
python3 src/benchmarks/benchmark_sender.py
```

#### Output Analysis

The output will display timing information for each log message, including:

- **Salt Time**: Time taken to generate a unique salt.
- **Key Derivation Time**: Time taken to derive the encryption key using the KDF.
- **Encryption Time**: Time taken to encrypt the log entry.
- **Total Log Time**: Total time taken to process the log entry.

### 2. Benchmarking the Receiver

The receiver benchmark measures the performance of the log receiver, including salt extraction, key derivation, decryption, and total processing time.

#### Running the Benchmark

```bash
python3 src/benchmarks/benchmark_receiver.py
```

#### Output Analysis

The output will display timing information for each received log message, including:

- **Salt Extraction Time**: Time taken to extract the salt from the log packet.
- **Key Derivation Time**: Time taken to derive the decryption key using the KDF.
- **Decryption Time**: Time taken to decrypt the log entry.
- **Total Decryption Time**: Total time taken to process and decrypt the log entry.

## Analyzing Results

1. **Compare Performance**: Use the benchmark results to compare the performance of the sender and receiver. Analyze how different parameters (e.g., salt size, log size) affect performance.

2. **Optimize Parameters**: Based on the results, you can optimize configuration parameters in the `fs-syslogd_config.json` and `receiver_config.json` files to balance security and performance.

3. **Monitor Resource Usage**: Use tools like `htop`, `top`, or `vmstat` to monitor CPU and memory usage during the benchmarks to identify potential bottlenecks.


## Contributing

Contributions are welcome! Please fork this repository, make your changes, and submit a pull request.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
