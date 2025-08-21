# Operation WIRE STORM – CTMP Relay Server

## Overview

This project is my implementation of **[CoreTech Security’s “Operation WIRE STORM” challenge](https://www.coretechsec.com/operation-wire-storm)**.  
The assignment: create a resilient TCP relay that moves messages using the **CoreTech Message Protocol (CTMP)** between a single **source client** and multiple **destination clients**.

The relay must:
- Listen on port **33333** for the source client.
- Listen on port **44444** for destination clients.
- Receive CTMP messages, validate them, and broadcast them to all connected destinations.
- Discard malformed or invalid messages without interrupting service.

Enhancements introduced in this version:
- **Graceful shutdown** via `"quit"` command entered in the terminal.
- **Robust CTMP validation**, including magic byte checks and payload length verification.
- **Checksum validation** for sensitive messages (ensuring data integrity).
- **Optional packet capture** using Npcap for monitoring/debugging via `PacketOperations`.

---

## Features

- **Dual Listening Ports**
  - `33333`: source client
  - `44444`: multiple destination clients

- **Message Protocol Handling**
  - Magic byte validation (`0xCC`)
  - Payload length extraction and verification
  - Optional checksum for sensitive messages

- **Efficient I/O**
  - Uses `select()` for managing multiple socket connections.
  - `recv_all()` ensures full message reads, avoiding partial reads.

- **Interactive Control**
  - Type `"quit"` in the console at runtime to cleanly interrupt and shut down the server.

---

## Development Environment

This project was built and tested in a Windows environment:
- **Windows 10 / 11**
- **MinGW (GCC 14.2.0)**
- **Npcap SDK 1.15** (for packet capture)
- **Visual Studio Code** (as the IDE)

---

## Configure Npcap SDK Path

In `.vscode/tasks.json`, update the **Include** and **Lib** paths to point to your installed Npcap SDK:

```jsonc
"-IC:\\npcap-sdk-1.15\\Include", 
"-LC:\\npcap-sdk-1.15\\Lib\\x64"
```

## Running The Program
- Compile **main.cpp** in vscode or use the args for GCC found in **tasks.json** to compile in powershell.
- In the terminal, move to the folder with **main.cpp** file.
- Run the program with
```powershell
main.exe
``` 
- In order to run the program on localhost, select the loopback device to capture the packets.
    - If you want to run with the computers ip address then use the correct device e.g. PCIe for ethernet or WiFi 6. 