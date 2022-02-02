#include "getpid.h"
#include <iphlpapi.h>
#include <stdio.h>

int getOwningPIDFromLocalConn(int localPort, int remotePort)
{
    PMIB_TCPTABLE_OWNER_PID pTcpTable = NULL;
    DWORD dwSize = 0;

    if (ERROR_INSUFFICIENT_BUFFER != GetExtendedTcpTable(NULL, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)) {
        return -1;
    }
    pTcpTable = (PMIB_TCPTABLE_OWNER_PID) calloc(dwSize,1);
    if (pTcpTable == NULL) {
        return -2;
    }

    if (NO_ERROR != GetExtendedTcpTable(pTcpTable, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)) {
        free(pTcpTable);
        return -3;
    }

    char szLocalAddr[16] = {0};
    char szRemoteAddr[16] = {0};
    
    struct in_addr IpAddr;
    static const char localHost[] = "127.0.0.1";

    for (int i = 0; i < (int) pTcpTable->dwNumEntries; i++) {
        IpAddr.S_un.S_addr = (u_long) pTcpTable->table[i].dwLocalAddr;
        strcpy_s(szLocalAddr,  sizeof (szLocalAddr),  inet_ntoa(IpAddr));
        IpAddr.S_un.S_addr = (u_long) pTcpTable->table[i].dwRemoteAddr;
        strcpy_s(szRemoteAddr, sizeof (szRemoteAddr), inet_ntoa(IpAddr));

        if (strcmp(szLocalAddr, localHost) == 0 &&
            strcmp(szRemoteAddr, localHost) == 0 &&
            ntohs((u_short)pTcpTable->table[i].dwLocalPort) == localPort &&
            ntohs((u_short)pTcpTable->table[i].dwRemotePort) == remotePort &&
            pTcpTable->table[i].dwState == MIB_TCP_STATE_ESTAB) {
                DWORD pid = pTcpTable->table[i].dwOwningPid;

                if (pTcpTable != NULL) {
                    free(pTcpTable);
                    pTcpTable = NULL;
                }

                return pid;
        }

        dwSize = 0;
    }
    
    if (pTcpTable != NULL) {
        free(pTcpTable);
        pTcpTable = NULL;
    }

    return -4;
}
