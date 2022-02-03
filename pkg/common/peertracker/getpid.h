#ifndef GETPID_H_
#define GETPID_H_

unsigned long getOwningPIDFromLocalConn(int localPort, int remotePort, int *pid);

#endif
