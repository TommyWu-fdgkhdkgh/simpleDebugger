#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <assert.h>
#include <sys/types.h>
#include <unistd.h>



int main(int argc, char *argv[]){
	pid_t child;
	
	if(argc<2){
		printf("usage: %s program\n", argv[0]);
		return -1;
	}

	if((child=fork())<0){
		printf("fork\n");
		return -1;
	}

	if(child == 0){
		if(ptrace(PTRACE_TRACEME, 0, 0, 0) <0){
			printf("ptrace error\n");
			return -1;
		}
		execvp(argv[1], argv+1);
		
		printf("execve error!\n");
		return -1;
	} else{
		int status;
		if(waitpid(child, &status, 0)<0){
			printf("wait error!\n");
			return -1;
		}
		assert(WIFSTOPPED(status));

		ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);
		ptrace(PTRACE_CONT, child, 0, 0);

		waitpid(child, &status, 0);

		printf("done\n");
		return -1;
	}

	return 0;
}



