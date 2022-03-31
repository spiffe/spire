#include <windows.h>
#include <iphlpapi.h>
#include <stdio.h>

unsigned long getOwningPIDFromLocalConn(int localPort, int remotePort, int *pid)
{
	PMIB_TCPTABLE_OWNER_PID pTcpTable = NULL;
	DWORD dwSize = 0;
	unsigned long retCode = 0;

	for (;;) {
		if (dwSize > 0) {
			pTcpTable = (PMIB_TCPTABLE_OWNER_PID)calloc(dwSize, 1);
			if (pTcpTable == NULL) {
				return ERROR_OUTOFMEMORY;
			}
		}

		retCode = GetExtendedTcpTable(pTcpTable, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
		if (retCode == NO_ERROR) {
			break;
		}

		free(pTcpTable);
		pTcpTable = NULL;

		if (retCode != ERROR_INSUFFICIENT_BUFFER) {
			return retCode;
		}
	
	}

	for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
		if (pTcpTable->table[i].dwLocalAddr == htonl(INADDR_LOOPBACK) &&
			pTcpTable->table[i].dwRemoteAddr == htonl(INADDR_LOOPBACK)  &&
			ntohs((u_short)pTcpTable->table[i].dwLocalPort) == localPort &&
			ntohs((u_short)pTcpTable->table[i].dwRemotePort) == remotePort &&
			pTcpTable->table[i].dwState == MIB_TCP_STATE_ESTAB) {
				*pid = pTcpTable->table[i].dwOwningPid;
				free(pTcpTable);
				return NO_ERROR;
		}
	}

	free(pTcpTable);

	return ERROR_NOT_FOUND;
}
