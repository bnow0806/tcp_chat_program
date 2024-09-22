#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/epoll.h>
#include <pthread.h> // pthread�� ����ϱ� ���ؼ� �����մϴ�

#define SERVER_IP	"127.0.0.1" // LocalHost
#define SERVER_PORT	(uint16_t)(2000)

typedef struct _THREAD_INFO
{
	int client_sockfd;
}THREAD_INFO, *PTHREAD_INFO;

#define EPOLL_SIZE		(1)
#define MAX_CHARS	(1000)

void* socket_processing_thread(void *arg) {
	PTHREAD_INFO pthread_info = NULL;
	pthread_t tid;
	char buffer[MAX_CHARS];
	int ret;
	int event_count;
	int index;
	struct epoll_event* events = NULL;
	struct epoll_event init_event;
	int epoll_fd = 0;

	tid = pthread_self();
	pthread_info = (PTHREAD_INFO)arg;

	// client_addr, client_sockfd �� main���� ���� ���޹޾ƾ� �Ѵ�

	epoll_fd = epoll_create(EPOLL_SIZE); // Ŭ���̾�Ʈ���� 1
	events = malloc(sizeof(struct epoll_event)*EPOLL_SIZE);

	// ���Ӱ� ������ client_sockfd�� Ư������� �߻��ϱ⸦ ��ٸ��� �������� �߰��Ѵ�
	// Ŭ���̾�Ʈ����fd�� ���
	init_event.events = EPOLLIN;
	init_event.data.fd = pthread_info->client_sockfd;
	epoll_ctl(epoll_fd, EPOLL_CTL_ADD, pthread_info->client_sockfd, &init_event);

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
		ret = recv(pthread_info->client_sockfd, buffer, sizeof(buffer)-1, 0);
		if (ret == -1) // ���� ����
		{
			printf("[TCP Client]recv error\n");
			goto exit;
		}
		else if (ret == 0) // ������ ����Ǿ��ٴ� �ǹ̷� ���ȴ�
		{
			goto exit;
		}
		else // ����Ÿ�� �����ߴٴ� �ǹ�
		{
			printf("%s\n", buffer);
		}
	}
exit:
	if (pthread_info)
	{
		if (pthread_info->client_sockfd != -1)
		{
			if (epoll_fd)
				epoll_ctl(epoll_fd, EPOLL_CTL_DEL, pthread_info->client_sockfd, NULL);
			close(pthread_info->client_sockfd);
		}
		free(pthread_info);
	}
	if (epoll_fd)
		close(epoll_fd);
	if (events)
		free(events);

	exit(0);

	return 0;
}

int main(int argc, char* argv[])
{
	PTHREAD_INFO pthread_info = NULL;
	int sockfd;
	struct sockaddr_in server_addr;
	int ch;
	char buffer[MAX_CHARS]; // with NULL
	int ret;
	char *p_server_ipaddr;
	pthread_t thread;
	int i;

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
	
	pthread_info = (PTHREAD_INFO)malloc(sizeof(THREAD_INFO));
	pthread_info->client_sockfd = sockfd;
	pthread_create(&thread, NULL, socket_processing_thread, pthread_info);

	while (1)
	{
		memset(buffer, 0, MAX_CHARS);
		fgets(buffer, MAX_CHARS-1, stdin);
		i = strlen(buffer);
		send(sockfd, buffer, i, 0);
	}

exit:
	if( sockfd != -1)
		close(sockfd);
	return 0;
}