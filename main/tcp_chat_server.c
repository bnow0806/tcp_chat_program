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
#define EPOLL_SIZE		(1)
#define TOTALSOCKETS	(10+EPOLL_SIZE) // ���� 1 + Ŭ���̾�Ʈ 10
#define MAX_CHARS	(1000)
#define MAX_NAME_SIZE	(100)
#define BUFFER_SIZE (MAX_CHARS)

#define WelcomeMessage	"Welcome to chat server!!"
#define NoneUser		"<Error There is none>"
#define InvalidCommand	"<Error Invalid Command>"

typedef struct _CLIENTSOCKETS_INFO
{
	int client_sockfd[TOTALSOCKETS-1];	//��Ư�� �ټ��� client_sockfd
	pthread_mutex_t mutex;
	char MyName[TOTALSOCKETS - 1][MAX_NAME_SIZE];
	char OtherName[TOTALSOCKETS - 1][MAX_NAME_SIZE];
}CLIENTSOCKETS_INFO, *PCLIENTSOCKETS_INFO;

typedef struct _THREAD_INFO
{
	struct sockaddr_in client_addr;
	int client_sockfd;	//�� client_sockfd
	PCLIENTSOCKETS_INFO pClientSocketsInfo;
}THREAD_INFO, *PTHREAD_INFO;

int find_another_clientsocketinfo(PCLIENTSOCKETS_INFO pClientSocketsInfo, int my_sockfd)
{
	int another_sockfd = 0;
	int i;

	pthread_mutex_lock(&pClientSocketsInfo->mutex);

	for (i = 0; i < TOTALSOCKETS - 1; i++)
	{
		if (pClientSocketsInfo->client_sockfd[i] == my_sockfd)
			continue;
		else if (pClientSocketsInfo->client_sockfd[i])
			another_sockfd = pClientSocketsInfo->client_sockfd[i];
		break;
	}
	pthread_mutex_unlock(&pClientSocketsInfo->mutex);
	return another_sockfd;
}

int insert_clientsocketinfo(PCLIENTSOCKETS_INFO pClientSocketsInfo, int my_sockfd)
{
	int ret = -1;
	int i;

	pthread_mutex_lock(&pClientSocketsInfo->mutex);

	for (i = 0; i < TOTALSOCKETS - 1; i++)
	{
		if (pClientSocketsInfo->client_sockfd[i] == my_sockfd)
		{
			goto exit;
		}
	}

	for (i = 0; i < TOTALSOCKETS - 1; i++)
	{
		if (pClientSocketsInfo->client_sockfd[i])
			continue;
		pClientSocketsInfo->client_sockfd[i] = my_sockfd;
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
		pClientSocketsInfo->client_sockfd[i] = 0;
		ret = 0;
		break;
	}
exit:

	pthread_mutex_unlock(&pClientSocketsInfo->mutex);

	return ret;
}

//new func
void parse_input(const char *input, char *first_part, char *second_part) {
    // ù ��° ���ڿ� ����
    sscanf(input, "%s", first_part);

    // ���� ������ ������ ���ڿ� ����
    char *space_pos = strchr(input, ' ');
    if (space_pos != NULL) {
        strcpy(second_part, space_pos + 1);
    } else {
        second_part[0] = '\0'; // ������ ������ �� ���ڿ�
    }

    // ���� ���� ����
    second_part[strcspn(second_part, "\n")] = '\0';
}

//new func
int get_index(int client_sockfd[], int size, int value) {
    for (int i = 0; i < size; i++) {
        if (client_sockfd[i] == value) {
            return i;  // ��ġ�ϴ� ���� �ε��� ��ȯ
        }
    }
    return -1;  // ���� ������ -1 ��ȯ
}

//new func
int insert_nameinfo(PCLIENTSOCKETS_INFO pClientSocketsInfo, char* second_part, int my_sockfd){
	//int ret = -1;
	int index_sockfd =-1;
	index_sockfd = get_index(pClientSocketsInfo->client_sockfd, TOTALSOCKETS-1 ,my_sockfd);

	strcpy(pClientSocketsInfo->MyName[index_sockfd], second_part);
	strcpy(pClientSocketsInfo->OtherName[index_sockfd], second_part);

	//printf("index_sockfd : %d\n", index_sockfd);
	return index_sockfd;
}

//new func
int parse_command(PCLIENTSOCKETS_INFO pClientSocketsInfo, char * buffer, char * dst_buffer, int len, int my_sockfd)
{
	int parse_ret = 100;
	int index_nameinfo, my_index_sockfd;
	char first_part[100];  // ù ��° �κ� ����
    char second_part[100]; // �� ��° �κ� ����

    // sscanf(buffer, "%s %s", first_part, second_part); // sscanf�� ���� ���ķ� ������ �о����
    // second_part[strcspn(second_part, "n")] = '\0';	// second_part�� ���� ���ڰ� ���ԵǾ� ���� ��� ����
	parse_input(buffer, first_part, second_part);
    //printf("first_part: %s\n", first_part);
    //printf("second_part: %s\n", second_part);

	if (strcmp(first_part, "$NAME") == 0) {
		index_nameinfo = insert_nameinfo(pClientSocketsInfo, second_part, my_sockfd);
		snprintf(dst_buffer, BUFFER_SIZE, "CONNECTED %s\n", 
				pClientSocketsInfo->MyName[index_nameinfo]);
    }else if (strcmp(first_part, "$MENU") == 0) {
        int menu_offset = 0; // ���� ���� ��ġ

		// �� ���ڿ��� dst_buffer�� �߰�
		menu_offset += snprintf(dst_buffer + menu_offset, BUFFER_SIZE - menu_offset, "1. $NAME\n");
		menu_offset += snprintf(dst_buffer + menu_offset, BUFFER_SIZE - menu_offset, "2. $MENU\n");
		menu_offset += snprintf(dst_buffer + menu_offset, BUFFER_SIZE - menu_offset, "3. $SHOWNAMES\n");
		menu_offset += snprintf(dst_buffer + menu_offset, BUFFER_SIZE - menu_offset, "4. $WHO\n");
		menu_offset += snprintf(dst_buffer + menu_offset, BUFFER_SIZE - menu_offset, "5. $[NAME] [MESSAGE]\n");
    } else if (strcmp(first_part, "$SHOWNAMES") == 0) {
		int shownames_offset = 0;

		for (int i = 0; i < TOTALSOCKETS - 1; i++){
			if (pClientSocketsInfo->OtherName[i][0] != '\0')
				shownames_offset += snprintf(dst_buffer + shownames_offset, BUFFER_SIZE - shownames_offset, "NAME %s\n", 
									pClientSocketsInfo->OtherName[i]);
		}
	} else if (strcmp(first_part, "$WHO") == 0) {
		int found = 0;  // ��ġ ���θ� ����� ����
		
		//<NONE peter>, <NAME peter>
		for (int i = 0; i < TOTALSOCKETS - 1; i++){
			if (strcmp(pClientSocketsInfo->OtherName[i], second_part) == 0) {
				found = 1;  // ��ġ�ϴ� �׸��� ã������ ���
				break;      // ���� ����
        	}
		}
		if (found){
			snprintf(dst_buffer, BUFFER_SIZE, "NAME %s\n", second_part);
		} else {
			snprintf(dst_buffer, BUFFER_SIZE, "NONE %s\n", second_part);
		}
	} else{
		//printf("first_part - $[NAME]\n");
		char *trimmed_part = first_part + 1;
		//printf("trimmed_part : %s\n", trimmed_part);

		//check if name exist
		int found = -1;  // ��ġ ���θ� ����� ����
		//<NONE peter>, <NAME peter>
		for (int i = 0; i < TOTALSOCKETS - 1; i++){
			if (strcmp(pClientSocketsInfo->OtherName[i], trimmed_part) == 0) {
				found = i;  // ��ġ�ϴ� �׸��� ã������ ���
				break;      // ���� ����
        	}
		}
		if (found != -1){
			//�ڱ��ڽ����� ������ �� ���� ó��
			my_index_sockfd = get_index(pClientSocketsInfo->client_sockfd, TOTALSOCKETS-1 ,my_sockfd);
			if(strcmp(pClientSocketsInfo->MyName[my_index_sockfd], trimmed_part) == 0){
				parse_ret = -1;
				goto exit;
			}
			parse_ret = found;
			//printf("trimmed_part, second_part : %s , %s\n", trimmed_part, second_part);
			snprintf(dst_buffer, BUFFER_SIZE, "%s\n", second_part);
		} else {
			parse_ret = -1;
		}
	}

exit:
	return parse_ret;
}

void* socket_processing_thread(void *arg) {
	PCLIENTSOCKETS_INFO pClientSocketsInfo = NULL;
	PTHREAD_INFO pthread_info = NULL;
	int client_sockfd = -1;
	int another_sockfd = -1;
	pthread_t tid;
	char buffer[MAX_CHARS], dst_buffer[MAX_CHARS];
	int ret, parse_ret;
	int recvedsize;
	int event_count;
	int index;
	struct epoll_event* events = NULL;
	struct epoll_event init_event;
	int epoll_fd = 0;
	char *p_client_ipaddr;

	tid = pthread_self();
	pthread_info = (PTHREAD_INFO)arg;
	pClientSocketsInfo = pthread_info->pClientSocketsInfo;
	client_sockfd = pthread_info->client_sockfd;				// client_sockfd ���� �س���!

	epoll_fd = epoll_create(EPOLL_SIZE); // Ŭ���̾�Ʈ���� 1
	events = malloc(sizeof(struct epoll_event)*EPOLL_SIZE);

	p_client_ipaddr = (char *)&(pthread_info->client_addr.sin_addr.s_addr);

	// ���Ӱ� ������ client_sockfd�� Ư������� �߻��ϱ⸦ ��ٸ��� �������� �߰��Ѵ�
	// Ŭ���̾�Ʈ����fd�� ���
	init_event.events = EPOLLIN;
	init_event.data.fd = client_sockfd;
	epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_sockfd, &init_event);

	send(client_sockfd, WelcomeMessage, sizeof(WelcomeMessage)-1, 0);

	index = 0;
	memset(buffer, 0, sizeof(buffer));
	memset(dst_buffer, 0, sizeof(dst_buffer));

	// �迭�� ����ִ� ���ڿ��� �ʱ�ȭ
	memset(pClientSocketsInfo->MyName, '\0', sizeof(pClientSocketsInfo->MyName));
	memset(pClientSocketsInfo->OtherName, '\0', sizeof(pClientSocketsInfo->OtherName));

	while (1)
	{
		// Async �۾��� ���� epoll_wait()�Լ��� ����Ѵ�
		event_count = epoll_wait(epoll_fd, events, EPOLL_SIZE, -1);
		if (event_count == -1)
		{
			goto exit;
		}

		ret = recv(client_sockfd, buffer+index, sizeof(buffer)-index-1, 0);
		if (ret == -1) // ���� ����
		{
			printf("[TCP Server]recv error\n");
			goto exit;
		}
		else if (ret == 0) // ������ ����Ǿ��ٴ� �ǹ̷� ���ȴ�
		{
			// ���Ǵ� client_sockfd �� �ݰ�, ����� ��ٸ��� �ʵ��� �Ѵ�
			printf("[TCP Server]disconnected from Client IP Address = %d.%d.%d.%d\n"
				, p_client_ipaddr[0]
				, p_client_ipaddr[1]
				, p_client_ipaddr[2]
				, p_client_ipaddr[3]
			);
			// ����� ���� Ŭ���̾�Ʈ ���������� epoll fd ����ҷκ��� �����Ѵ�
			goto exit;
		}
		else // ����Ÿ�� �����ߴٴ� �ǹ�
		{
			// Newline�� ���������� Ȯ���Ѵ�
			if (buffer[index + ret - 1] != '\n')
			{
				index += ret;
				ret = 0;
				continue;
			}

			// ���ŵ� ����Ÿ�� �ؼ��Ѵ�
			recvedsize = index + ret; // recvedsize : ���� �� ����Ÿ ����, buffer : ���ŵ� ����Ÿ
			index = 0;

			parse_ret = parse_command(pClientSocketsInfo, buffer, dst_buffer, recvedsize, client_sockfd);
			printf("dst_buffer\n%s\n", dst_buffer);	//debug
			//memset(dst_buffer, 0, sizeof(dst_buffer));
			if (parse_ret == -1) // �߸��� ��ɾ�
			{
				send(client_sockfd, InvalidCommand, sizeof(InvalidCommand) - 1, 0);
				continue;
			}

			// �ٸ� ��ȭ��븦 Ȯ���Ѵ�	// ��ȭ ��밡 ȥ������ �ĺ��ϴ� �ڵ�
			another_sockfd = find_another_clientsocketinfo(pClientSocketsInfo, client_sockfd);
			if (!another_sockfd) // ������ ���ٸ�,
			{
				send(client_sockfd, NoneUser, sizeof(NoneUser) - 1, 0);
				continue;
			}
			
			// ��ȭ�� ������ �ִ� ���,
			if(parse_ret == 100){
				// ��ɾ��� ���, �ڱ� �ڽ����� �۽�
				send(client_sockfd, dst_buffer, strlen(dst_buffer), 0);
			} else{
				// ��ȭ�� ���, ���濡�� �۽�
				// ret = found; (client_sockfd�� index ��)
				send(pClientSocketsInfo->client_sockfd[parse_ret], dst_buffer, strlen(dst_buffer), 0);
			}
			memset(dst_buffer, 0, sizeof(dst_buffer));
		}
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
	if (epoll_fd)
		close(epoll_fd);
	if (events)
		free(events);
	return 0;
}

int main(int argc, char *argv[])
{
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

	pClientSocketsInfo = (PCLIENTSOCKETS_INFO)malloc(sizeof(CLIENTSOCKETS_INFO));
	pthread_mutex_init(&pClientSocketsInfo->mutex, NULL);

	server_sockfd =socket(AF_INET, SOCK_STREAM, 0); // TCP

	setsockopt(server_sockfd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));
	// bind �� ����� ��Ʈ�� �����ϰڴٰ� ������

	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family=AF_INET;
	server_addr.sin_addr.s_addr=htonl(INADDR_ANY); // ������ �ּҸ� ��� ���
	server_addr.sin_port=htons(SERVER_PORT);
	
	if (bind(server_sockfd, (struct sockaddr*) &server_addr, sizeof(server_addr)) == -1)
	{
		printf("[TCP Server]bind error\n");
		goto exit;
	}

	if(listen(server_sockfd, TOTALSOCKETS-1)==-1) // ���ӵǴ� Ŭ���̾�Ʈ�� �ִ������
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

		ret = insert_clientsocketinfo(pClientSocketsInfo, client_sockfd);
		if (ret == 0)
		{
			pthread_info = (PTHREAD_INFO)malloc(sizeof(THREAD_INFO));
			pthread_info->client_sockfd = client_sockfd;
			memcpy(&pthread_info->client_addr, &client_addr, sizeof(struct sockaddr_in));
			pthread_info->pClientSocketsInfo = pClientSocketsInfo;
			pthread_create(&thread, NULL, socket_processing_thread, pthread_info); // �Ϸ��� �۾��� ������� �ű��
		}
	}

exit:
	pthread_mutex_destroy(&pClientSocketsInfo->mutex);

	// ����� ���� ���� ���������� epoll fd ����ҷκ��� �����Ѵ�
	if (server_sockfd != -1)
	{
		if (epoll_fd)
			epoll_ctl(epoll_fd, EPOLL_CTL_DEL, server_sockfd, NULL);
		close(server_sockfd);
	}
	if (epoll_fd)
		close(epoll_fd);
	if (events)
		free(events);
	if (pClientSocketsInfo)
		free(pClientSocketsInfo);

	return 0;
}
