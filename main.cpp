#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <pcap.h>
#include <thread>
#include <vector>
#include <atomic>

#include "./helpers/protocol_headers.h"
#include "./helpers/config.h"
#include "PacketOperations.h"
#include "./helpers/utils.h"

#pragma comment(lib, "wsock32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Packet.lib")

std::atomic<bool> server_running(true);

void console_listener() {
    std::string input;
    while (server_running) {
        std::getline(std::cin, input);
        if (input == "quit") {
            server_running = false;  // signal server to stop
            break;
        }
    }
}

SOCKET create_listen_socket(int port) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        std::cerr << "socket() failed: " << WSAGetLastError() << "\n";
        return INVALID_SOCKET;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(s, (SOCKADDR*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        std::cerr << "bind(" << port << ") failed: " << WSAGetLastError() << "\n";
        closesocket(s);
        return INVALID_SOCKET;
    }

    if (listen(s, port == 33333 ? 0 : SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "listen(" << port << ") failed: " << WSAGetLastError() << "\n";
        closesocket(s);
        return INVALID_SOCKET;
    }

    std::cout << "Listening on " << IP_ADDRESS << ":" << port << "\n";
    return s;
}

void config_server() {
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        std::cerr << "WSAStartup failed\n";
        return;
    }

    SOCKET s1 = create_listen_socket(PORT1);
    SOCKET s2 = create_listen_socket(PORT2);
    if (s1 == INVALID_SOCKET || s2 == INVALID_SOCKET) {
        WSACleanup();
        return;
    }

    fd_set master{};
    FD_ZERO(&master);
    FD_SET(s1, &master);
    FD_SET(s2, &master);

    std::vector<ClientInformation> clients;

    uint8_t buffer[1024]; 

    std::thread console_thread(console_listener);

    std::cout << "Server running.\n";

    while (server_running) {
        fd_set readset = master;
        timeval timeout{};
        timeout.tv_sec = 1;   // 1-second timeout
        timeout.tv_usec = 0;

        int rc = select(0, &readset, nullptr, nullptr, &timeout);
        if (rc == SOCKET_ERROR) break;

        for (u_int i = 0; i < readset.fd_count; ++i) {
            SOCKET sock = readset.fd_array[i];

            if (sock == s1 || sock == s2) {
                SOCKET c = accept(sock, nullptr, nullptr);
                if (c != INVALID_SOCKET) {
                    FD_SET(c, &master);
                    int port = (sock == s1) ? PORT1 : PORT2;
                    clients.push_back({c, port});
                    std::cout << "New client on port " << port << "\n";
                }
            } else {
        
                uint8_t header[8];

                // Step 1: read header
                int n = recv_all(sock, reinterpret_cast<char*>(header), 8);
                if (n <= 0) {
                    closesocket(sock);
                    FD_CLR(sock, &master);
                    continue;
                }

                // Step 2: validate header
                if (header[0] != MAGIC_BYTE) {
                    std::cerr << "[CTMP] Invalid Magic Byte, dropping.\n";
                    continue;
                }

                uint16_t payload_length;
                memcpy(&payload_length, &header[2], sizeof(payload_length));
                payload_length = ntohs(payload_length);

                // Step 3: read payload fully
                std::vector<uint8_t> payload(payload_length);
                n = recv_all(sock, reinterpret_cast<char*>(payload.data()), payload_length);
                if (n <= 0) {
                    closesocket(sock);
                    FD_CLR(sock, &master);
                    continue;
                }

                // Step 4: broadcast full message (header + payload)
                std::vector<uint8_t> fullmsg(8 + payload_length);
                memcpy(fullmsg.data(), header, 8);
                memcpy(fullmsg.data() + 8, payload.data(), payload_length);

                for (const auto& ci : clients) {
                    if (ci.clientSocket != sock && ci.port == PORT2) {
                        
                        send(ci.clientSocket, reinterpret_cast<char*>(fullmsg.data()), fullmsg.size(), 0);
                    }
                }

            }
        }
    }

    console_thread.join();

    closesocket(s1);
    closesocket(s2);
    WSACleanup();
    std::cout << "Server shut down cleanly.\n";
}

// ----------------- MAIN -----------------
int main() {

    std::cout << "Operation Wire Storm Reloaded started. Enter 'quit' to exit program.\n";

    PacketOperations packetOps;

    // Start Npcap capture in background
    std::thread sniffer(&PacketOperations::start_capture, &packetOps);

    // Run server
    config_server();

    sniffer.join();

    std::cout << "Exiting program...\n";
    return 0;
}