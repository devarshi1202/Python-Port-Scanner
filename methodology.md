# Scanning Methodology

## 1. Target
Use only a system you own or a host for which you have explicit authorization.

## 2. Resolution
The scanner resolves the supplied hostname to an IPv4 address before scanning.

## 3. TCP connection test
For each port, the program creates a TCP socket and attempts a connection with a configurable timeout.

## 4. Interpretation
A successful `connect_ex()` result of `0` is treated as an open TCP port. Other results are treated as not open/reachable by this simple scanner.

## 5. Reporting
Open ports are printed as `TCP/<port>`.

## Limitations
This is a learning project, not a production network scanner. It does not perform service/version detection, UDP scanning, OS fingerprinting, stealth scanning, banner grabbing, concurrency, or comprehensive error classification.
