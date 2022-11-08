#ifndef D7A67088_9088_4607_92B6_5935AC28B5F8
#define D7A67088_9088_4607_92B6_5935AC28B5F8

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "shim-out/net/graal_net.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/sysinfo.h>
#include <cassert>
#define assertm(exp, msg) assert(((void)msg, exp))
//#define ____sigset_t_defined
#define __iovec_defined 1

#include "Enclave_u.h"
#include "sgx_urts.h"



#include "error/error.h"

#include "user_types.h"



/* Signal handlers */
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>
#include <map>
#include "ocall_logger.h"



//for get_nprocs()
#include <sys/sysinfo.h>



#endif /* D7A67088_9088_4607_92B6_5935AC28B5F8 */
