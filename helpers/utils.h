#ifndef UTILS_H
#define UTILS_H

#include <winsock2.h>

// Winsock server
struct ClientInformation {
    SOCKET clientSocket;
    int port;
};

int recv_all(SOCKET sock, char* buffer, int length) {
    int total_received = 0;
    while (total_received < length) {
        int n = recv(sock, buffer + total_received, length - total_received, 0);
        if (n <= 0) {
            return n; // error or connection closed
        }
        total_received += n;
    }
    return total_received;
};

#endif