#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <pthread.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT (uint16_t)(2000)
#define EPOLL_SIZE		(1)
#define TOTALSOCKETS	(3) // ���� 1 + Ŭ���̾�Ʈ 2
#define MAX_CLIENTS     TOTALSOCKETS-1

#define NoneUser		"There is no user!!"

typedef struct _CLIENTSOCKETS_INFO	// Ŭ���̾�Ʈ ������ ������ �迭�� ���ؽ� ����
{
	int client_sockfd[MAX_CLIENTS];
	pthread_mutex_t mutex;
}CLIENTSOCKETS_INFO, *PCLIENTSOCKETS_INFO;

typedef struct _THREAD_INFO
{
	struct sockaddr_in client_addr;
	int client_sockfd;
	PCLIENTSOCKETS_INFO pClientSocketsInfo;
}THREAD_INFO, *PTHREAD_INFO;

int find_another_clientsocketinfo(PCLIENTSOCKETS_INFO pClientSocketsInfo, int my_sockfd)
{
	int another_sockfd = 0;
	int i;

	pthread_mutex_lock(&pClientSocketsInfo->mutex);

	for (i = 0; i < TOTALSOCKETS - 1; i++)
	{
		if (pClientSocketsInfo->client_sockfd[i] == my_sockfd)	//���ٸ� ���
			continue;
		else if (pClientSocketsInfo->client_sockfd[i])
			another_sockfd = pClientSocketsInfo->client_sockfd[i];	//�ٸ��� �Ѱ��ֱ�
		break;
	}

	pthread_mutex_unlock(&pClientSocketsInfo->mutex);
	return another_sockfd;	//TODO : ��Ĺ Ȯ�强 �̰��
}

int insert_clientsocketinfo(PCLIENTSOCKETS_INFO pClientSocketsInfo, int my_sockfd){
	int ret = -1;
	int i;
	
	pthread_mutex_lock(&pClientSocketsInfo->mutex);	//client_sockfd �߰� ��, lock�� �Ǵ�.

	//�̹� �ִ� client_sockfd���, ����
	for (i = 0; i < TOTALSOCKETS - 1; i++)
	{
		if (pClientSocketsInfo->client_sockfd[i] == my_sockfd)
		{
			goto exit;
		}
	}

	//�ű� client_sockfd���, �߰�
	for (i = 0; i < TOTALSOCKETS - 1; i++)
	{
		if (pClientSocketsInfo->client_sockfd[i])	//pClientSocketsInfo->client_sockfd[i]�� �ִٸ� �Ѿ
			continue;
		pClientSocketsInfo->client_sockfd[i] = my_sockfd;	//pClientSocketsInfo->client_sockfd[i]�� ���ٸ� �ű� �߰�
		ret = 0;
		break;
	}

exit:
	pthread_mutex_unlock(&pClientSocketsInfo->mutex);
	return ret;
}

int remove_clientsocketinfo(PCLIENTSOCKETS_INFO pClientSocketsInfo, int my_sockfd)
{
	int ret = -1;
	int i;

	pthread_mutex_lock(&pClientSocketsInfo->mutex);

	for (i = 0; i < TOTALSOCKETS - 1; i++)
	{
		if (pClientSocketsInfo->client_sockfd[i] != my_sockfd)
			continue;
		pClientSocketsInfo->client_sockfd[i] = 0;	//���ٸ�, ����
		ret = 0;
		break;
	}

exit:
	pthread_mutex_unlock(&pClientSocketsInfo->mutex);
	return ret;
}

void* socket_processing_thread(void *arg) {
    PCLIENTSOCKETS_INFO pClientSocketsInfo = NULL;
	PTHREAD_INFO pthread_info = NULL;
	int client_sockfd = -1;
	int another_sockfd = -1;
	pthread_t tid;
	char client_buffer[1024];
	int ret;
	int event_count;
	int index;
	struct epoll_event* events = NULL;
	struct epoll_event init_event;
	int epoll_fd = 0;
	char *p_client_ipaddr;
	
	tid = pthread_self();
	pthread_info = (PTHREAD_INFO)arg;
	pClientSocketsInfo = pthread_info->pClientSocketsInfo;
	client_sockfd = pthread_info->client_sockfd;

    // client_addr, client_sockfd �� main���� ���� ���޹޾ƾ� �Ѵ�
	epoll_fd = epoll_create(EPOLL_SIZE); // Ŭ���̾�Ʈ���� 1
	events = malloc(sizeof(struct epoll_event)*EPOLL_SIZE);
	p_client_ipaddr = (char *)&(pthread_info->client_addr.sin_addr.s_addr);

    // ���Ӱ� ������ client_sockfd�� Ư������� �߻��ϱ⸦ ��ٸ��� �������� �߰��Ѵ�
	// Ŭ���̾�Ʈ����fd�� ���
	init_event.events = EPOLLIN;
	init_event.data.fd = pthread_info->client_sockfd;
	epoll_ctl(epoll_fd, EPOLL_CTL_ADD, pthread_info->client_sockfd, &init_event);

    while (1) 
    {
        // Async �۾��� ���� epoll_wait()�Լ��� ����Ѵ�
		event_count = epoll_wait(epoll_fd, events, EPOLL_SIZE, -1);
		printf("event_count : %d\n",event_count);
		if (event_count == -1)
		{
			goto exit;
		}
        // ��¥�� �߻��ϴ� ������ ��ϵ� Ŭ���̾�Ʈ ���� �ϳ��̹Ƿ�
		index = 0;

		//ret = recv(pthread_info->client_sockfd, client_buffer, sizeof(client_buffer), 0); 
		ret = recv(pthread_info->client_sockfd, client_buffer, sizeof(client_buffer), 0);
		printf("ret = %d\n", ret);
		printf("[recv] pthread_info->client_sockfd = %d\n", pthread_info->client_sockfd);

        if (ret <= 0) {
            // Ŭ���̾�Ʈ�� ������ ���ų� ������ �߻��� ���
            printf("Client disconnected\n");
            goto exit;
        }
        else{
			printf("[TCP Server]receiving data = %s\n", client_buffer);

            // for (int i = 0; i < MAX_CLIENTS; i++) {
			// 	if (pClientSocketsInfo->client_sockfd[i] && 
			// 		pClientSocketsInfo->client_sockfd[i] != pthread_info->client_sockfd) {	//�ڱ��ڽ��� �ƴ� client_sockfd���� ����
					
			// 		printf("pClientSocketsInfo->client_sockfd[i] != pthread_info->client_sockfd\n");
			// 		send(pClientSocketsInfo->client_sockfd[i], client_buffer, ret, 0);	//ret ���� ��ŭ �۽�
            //     }
            // }

			another_sockfd = find_another_clientsocketinfo(pClientSocketsInfo, client_sockfd);
			if(another_sockfd) // ������ �ִ� ���,
				send(another_sockfd, client_buffer, ret, 0);
			else // ������ ���� ���,
				send(client_sockfd, NoneUser, sizeof(NoneUser)-1, 0);
        }
		printf("------------------------------------------------------\n");
    }

exit:
	if (pthread_info)
	{
		if ((client_sockfd != -1)&&(client_sockfd != 0))
		{
			remove_clientsocketinfo(pClientSocketsInfo, client_sockfd);
			if (epoll_fd)
				epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client_sockfd, NULL);
			close(client_sockfd);
		}
		free(pthread_info);
	}
	return 0;
}

int main() {
	PCLIENTSOCKETS_INFO pClientSocketsInfo = NULL;
	PTHREAD_INFO pthread_info = NULL;
	int client_sockfd = -1;
	int server_sockfd = -1;
	struct sockaddr_in server_addr;
	struct sockaddr_in client_addr;
	socklen_t client_addrlen;
	int option = 1;
	struct epoll_event* events = NULL;
	struct epoll_event init_event;
	int epoll_fd = 0;
	int event_count;
	int index;
	int ret;
	pthread_t thread;
    int client_count = 0;

	pClientSocketsInfo = (PCLIENTSOCKETS_INFO)malloc(sizeof(CLIENTSOCKETS_INFO));
	pthread_mutex_init(&pClientSocketsInfo->mutex, NULL);

    server_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(server_sockfd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(SERVER_PORT);

    if (bind(server_sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1)
	{
        printf("[TCP Server]bind error\n");
        goto exit;
    }

    if (listen(server_sockfd, TOTALSOCKETS-1) == -1)
	{
        printf("[TCP Server]listen error\n");
        goto exit;
    }

    // epoll fd ����Ҹ� ����
	epoll_fd = epoll_create(EPOLL_SIZE); // �������� 1
	events = malloc(sizeof(struct epoll_event)*EPOLL_SIZE);

	// ��������fd�� ���
	init_event.events = EPOLLIN; // ����Ÿ�� ���ŵǴ°��� ��ٸ���
	init_event.data.fd = server_sockfd;
	epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_sockfd, &init_event);

    while (1) 
	{
		// Async �۾��� ���� epoll_wait()�Լ��� ����Ѵ�
		event_count = epoll_wait(epoll_fd, events, EPOLL_SIZE, -1);
		if (event_count == -1)
		{
			goto exit;
		}

		// ��¥�� �߻��ϴ� ������ ��ϵ� �������� �ϳ��̹Ƿ�
		index = 0;

		// connect��û�� ���°����� �ؼ��� �� �ִ�
		client_addrlen = sizeof(client_addr);
        client_sockfd = accept(server_sockfd, (struct sockaddr*)&client_addr, &client_addrlen);
        if (client_sockfd == -1) 
		{
            printf("[TCP Server]accept error\n");
            goto exit;
        }


        // Ŭ���̾�Ʈ ��Ͽ� �߰�
        //clients[client_count++] = pthread_info;
		ret = insert_clientsocketinfo(pClientSocketsInfo, client_sockfd);
		
		if(ret==0){	//���������� �߰��� ���
			pthread_info = (PTHREAD_INFO)malloc(sizeof(THREAD_INFO));
			pthread_info->client_sockfd = client_sockfd;
			memcpy(&pthread_info->client_addr, &client_addr, sizeof(struct sockaddr_in));
			printf("[pthread_create] pthread_info->client_sockfd = %d\n", pthread_info->client_sockfd);
			pthread_info->pClientSocketsInfo = pClientSocketsInfo;
			pthread_create(&thread, NULL, socket_processing_thread, pthread_info);
		}
    }

exit:
	pthread_mutex_destroy(&pClientSocketsInfo->mutex);
	
    close(server_sockfd);
    return 0;
}
