#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include <sys/epoll.h>

#define SERVER_IP	"127.0.0.1" // LocalHost
#define SERVER_PORT	(uint16_t)(2000)
#define EPOLL_SIZE		(1)

typedef struct _THREAD_INFO
{
	int client_sockfd;
}THREAD_INFO, *PTHREAD_INFO;

void* socket_processing_thread(void *arg) {
	PTHREAD_INFO pthread_info = NULL;
	pthread_t tid;
	int ret;
	char buffer[1024]; // with NULL
	int index;
	int event_count;
	struct epoll_event* events = NULL;
	struct epoll_event init_event;
	int epoll_fd = 0;

	tid = pthread_self();
	pthread_info = (PTHREAD_INFO)arg;

	epoll_fd = epoll_create(EPOLL_SIZE); // Ŭ���̾�Ʈ���� 1
	events = malloc(sizeof(struct epoll_event)*EPOLL_SIZE);

	// ���Ӱ� ������ client_sockfd�� Ư������� �߻��ϱ⸦ ��ٸ��� �������� �߰��Ѵ�
	// Ŭ���̾�Ʈ����fd�� ���
	init_event.events = EPOLLIN;
	init_event.data.fd = pthread_info->client_sockfd;
	epoll_ctl(epoll_fd, EPOLL_CTL_ADD, pthread_info->client_sockfd, &init_event);

	//make epoll wait	
	while (1)
	{
		// Async �۾��� ���� epoll_wait()�Լ��� ����Ѵ�
		event_count = epoll_wait(epoll_fd, events, EPOLL_SIZE, -1);
		if (event_count == -1)
		{
			goto exit;
		}

		// ��¥�� �߻��ϴ� ������ ��ϵ� Ŭ���̾�Ʈ ���� �ϳ��̹Ƿ�
		index = 0;

		memset(buffer, 0, sizeof(buffer));	
		ret = recv(pthread_info->client_sockfd, buffer, sizeof(buffer), 0); // with NULL
		if (ret == -1) // ���� ����
		{
			printf("[TCP Client]recv error\n");
			goto exit;
		}
		else if (ret == 0) // ������ ����Ǿ��ٴ� �ǹ̷� ���ȴ�
		{
			goto exit;
		}
		else	//���� ����
		{
			printf("[%s]\n", buffer);
		}
	}

exit:
	exit(0);

	return 0;
}

int main(int argc, char* argv[])
{
	PTHREAD_INFO pthread_info = NULL;
	pthread_t thread;
	int sockfd;
	struct sockaddr_in server_addr;
	char buffer[1024]; // with NULL

	sockfd =socket(AF_INET, SOCK_STREAM, 0); // TCP

	memset(&server_addr, 0, sizeof(server_addr));

	server_addr.sin_family=AF_INET; // IPv4
	server_addr.sin_addr.s_addr=inet_addr(SERVER_IP); // ���ڸ� IP�ּҷ�, ���������
	server_addr.sin_port=htons(SERVER_PORT); // ���������
		
	if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1)
	{
		printf("[TCP Client]connect error\n");
		goto exit;
	}

	//recv ���� thread ����
	pthread_info = (PTHREAD_INFO)malloc(sizeof(THREAD_INFO));
	pthread_info->client_sockfd = sockfd;
	pthread_create(&thread, NULL, socket_processing_thread, pthread_info);

	//maind thread ������ input, send �溹
	while (1)
	{
		//input string from stdin
		char inputString[1024];
		//printf("[TCP Client]Input String: ");
		fgets(inputString, sizeof(inputString), stdin);
		//remove new line string
		size_t length = strlen(inputString);
    	if (length > 0 && inputString[length - 1] == '\n') {
        	inputString[length - 1] = '\0';
    	}

		strcpy(buffer, inputString);
		send(sockfd, buffer, sizeof(buffer), 0); // with NULL
		//printf("[TCP Client]sending data = %s\n", buffer);
		memset(buffer, 0, sizeof(buffer));		
	}

exit:
	if( sockfd != -1)
		close(sockfd);
	return 0;
}