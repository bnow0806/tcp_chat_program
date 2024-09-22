#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/epoll.h>
#include <pthread.h> // pthread를 사용하기 위해서 정의합니다

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

	// client_addr, client_sockfd 를 main으로 부터 전달받아야 한다

	epoll_fd = epoll_create(EPOLL_SIZE); // 클라이언트소켓 1
	events = malloc(sizeof(struct epoll_event)*EPOLL_SIZE);

	// 새롭게 생성된 client_sockfd를 특정사건이 발생하기를 기다리는 목적으로 추가한다
	// 클라이언트소켓fd를 등록
	init_event.events = EPOLLIN;
	init_event.data.fd = pthread_info->client_sockfd;
	epoll_ctl(epoll_fd, EPOLL_CTL_ADD, pthread_info->client_sockfd, &init_event);

	while (1)
	{
		// Async 작업을 위해 epoll_wait()함수를 사용한다
		event_count = epoll_wait(epoll_fd, events, EPOLL_SIZE, -1);
		if (event_count == -1)
		{
			goto exit;
		}

		// 어짜피 발생하는 소켓은 등록된 클라이언트 소켓 하나이므로
		index = 0;

		memset(buffer, 0, sizeof(buffer));
		ret = recv(pthread_info->client_sockfd, buffer, sizeof(buffer)-1, 0);
		if (ret == -1) // 수신 에러
		{
			printf("[TCP Client]recv error\n");
			goto exit;
		}
		else if (ret == 0) // 연결이 종료되었다는 의미로 사용된다
		{
			goto exit;
		}
		else // 데이타를 수신했다는 의미
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
	server_addr.sin_addr.s_addr=inet_addr(SERVER_IP); // 문자를 IP주소로, 엔디안정렬
	server_addr.sin_port=htons(SERVER_PORT); // 엔디안정렬
		
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