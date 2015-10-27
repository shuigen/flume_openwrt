#include <netinet/in.h>    // for sockaddr_in
#include <sys/types.h>    // for socket
#include <sys/socket.h>    // for socket
#include <stdio.h>        // for printf
#include <stdlib.h>        // for exit
#include <string.h>        // for bzero
#include <unistd.h>
 
#define SERVER_PORT 44444 
#define BUFFER_SIZE 1024
#define TIME_INTERVAL 1000

// 删除一个字符串两端的空格
void trim(char *scr)
{
	int i, startpos, endpos;
	startpos = 0;
	if(scr == NULL)
		return;
	for(i = 0; *(scr + i) == ' ' || *(scr + i) == '\t'; i++);
	startpos = i;
	endpos = i;
	for(; *(scr + i) != '\0';)
	{
		for(; *(scr + i) != ' ' && *(scr + i) != '\t' && *(scr + i) != '\0'; i++);
		endpos = i - 1;
		for(; *(scr + i) == ' ' || *(scr + i) == '\t'; i++);
	}
	// 说明字符串是由空格与制表符组成的
	if(startpos == endpos)
	{
		return;
	}
	memmove(scr, scr + startpos, endpos - startpos + 1);
	memset(scr + endpos - startpos + 1, 0, i - endpos + startpos);
}

/**
 * 判断字符串是否以某个字符串开头
 * @param str 目标字符串
 * @param reg 要比较的字符串
 * @return 如果以指定字符串开头返回1，否则返回0
 * */
int str_startwith(const char *str, const char *reg) 
{
	while (*str && *reg && *str == *reg)
    	{
		str ++;
		reg ++;
	}
	if (!*reg) 
		return 1;
	return 0;
}

int main(int argc, char **argv)
{
	char shellcmd[64];			/* shell命令名称 */
	const char *ifname = NULL;		/* 设备名称 */
	const char *ipaddr = NULL;		/* 服务器IP地址 */
	int port = SERVER_PORT;			/* 端口 */
	int time_interval = TIME_INTERVAL;	/* 扫描时间间隔 */

	int opt;				/* 操作选项 */

	// 获取输入参数
	while ((opt = getopt(argc, argv, "i:a:p:t:h")) != -1)
	{
		switch (opt)
		{
		// 设备地址
		case 'i':	
			ifname = optarg;
			break;
		// 服务器Ip地址
		case 'a':
			ipaddr = optarg;
			break;
		// 服务器端口
		case 'p':
			port = atoi(optarg);
			break;
		// 扫描时间间隔
		case 't':
			time_interval = atoi(optarg);
			break;
		// 帮助
		case 'h':
			printf(
				"Usage:\n"
				"-i {iface} -a {ipadd} [-p port]  [-t time interval]\n"
				"\n"
				"  -i iface\n"
				"    Specify interface to use, must be in monitor mode and\n"
				"    produce IEEE 802.11 Radiotap headers.\n\n"
				"  -a ipadd\n"
				"    The ip address which it will send to.\n\n"
				"  -p port\n"
				"    The host port.\n"
				"    The default port is %d.\n\n"
				"  -t time\n"
				"    Transmission time interval.\n"
				"    The default time interval is %d.\n\n"
				"  -h\n"
				"    Display this help.\n\n",
				SERVER_PORT,TIME_INTERVAL);
			return 1;
		}
	}

	// 设置一个socket地址结构client_addr,代表客户机internet地址, 端口
	struct sockaddr_in client_addr;
	// 把一段内存区的内容全部设置为0
	bzero(&client_addr,sizeof(client_addr));
	// internet协议族
	client_addr.sin_family = AF_INET;
	// INADDR_ANY表示自动获取本机地址
	client_addr.sin_addr.s_addr = htons(INADDR_ANY);
	// 0表示让系统自动分配一个空闲端口
	client_addr.sin_port = htons(0);
	// 创建用于internet的流协议(TCP)socket,用client_socket代表客户机socket
	int client_socket = socket(AF_INET,SOCK_STREAM,0);
	if( client_socket < 0)
	{
		printf("Create socket failed!\n");
		exit(1);
	}
	// 把客户机的socket和客户机的socket地址结构联系起来
	if( bind(client_socket,(struct sockaddr*)&client_addr,sizeof(client_addr)))
	{
		printf("Client bind port failed!\n"); 
		exit(1);
	}

	// 设置一个socket地址结构server_addr,代表服务器的internet地址, 端口
	struct sockaddr_in server_addr;
	bzero(&server_addr,sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	// 服务器的IP地址来自程序的参数
	if(inet_aton(ipaddr,&server_addr.sin_addr) == 0)
	{
		printf("Server IP address error!\n");
		exit(1);
	}
	server_addr.sin_port = htons(port);
	socklen_t server_addr_length = sizeof(server_addr);
	// 向服务器发起连接,连接成功后client_socket代表了客户机和服务器的一个socket连接
	if(connect(client_socket,(struct sockaddr*)&server_addr, server_addr_length) < 0)
	{
		printf("Can not connect to %s!\n",ipaddr);
		exit(1);
	}

	// 文件指针
	FILE *file = NULL;
	char buffer[BUFFER_SIZE];
	bzero(buffer,BUFFER_SIZE);

    	char ssid_val[BUFFER_SIZE] = {0};               /* ssid值 */
    	char mac_val[BUFFER_SIZE] = {0};                /* mac值 */
    	char rssi_val[BUFFER_SIZE] = {0};               /* rssi值 */

	// 获取shell脚本命令
	// iwlist wlan0 scan
	sprintf(shellcmd,"iw dev %s scan",ifname);  
	while(1)
	{
		// 休眠
		usleep(time_interval * 1000);
		// 执行shell脚本写入文件
		if(NULL == (file = popen(shellcmd,"r")))     
		{    
			printf("execute command failed!");     
			return -1;     
		} 
		char send_str[100*BUFFER_SIZE] = {0};           /* 向服务器发送所有的AP信息 */
    		strcpy(send_str , "[");   
		// 读取文件内容
		while(NULL != fgets(buffer, BUFFER_SIZE, file))    
		{    
			// 去除字符串前后空格
			trim(buffer);
		 	if(str_startwith(buffer,"SSID"))
			{
			    if(sscanf(buffer, "%*[0-9a-zA-Z\t ]:%[0-9a-zA-Z\t\\ ]", ssid_val)>0)
			    {
				// 去除字符串前后空格
				trim(ssid_val);
				// 临时AP信息
				char temp_str[BUFFER_SIZE] = {0};
				sprintf(temp_str,"{\"ssid\":\"%s\",\"mac\":\"%s\",\"rssi\":%s}," , ssid_val , mac_val ,rssi_val);
				// 去除字符串前后空格
				trim(temp_str);
				// 添加AP信息
				strcat(send_str , temp_str);
			    }
			}
			// AP的Mac值
			if(str_startwith(buffer,"BSS"))
			{
			    if(sscanf(buffer, "%*[0-9a-zA-Z\t]%[^(]", mac_val)>0)
				trim(mac_val);
			}
			// AP的RSSI值
			if(str_startwith(buffer,"signal"))
			{
			    if(sscanf(buffer, "%*[0-9a-zA-Z\t ]:%s", rssi_val)>0)
				trim(rssi_val);
			}
		}
		// 去除最后一个逗号并加上结尾
		if(send_str[strlen(send_str)-1] == ',')
	    		send_str[strlen(send_str)-1] = ']';
		else
			strcpy(send_str , "]");
		// 去除字符串前后空格
	    	trim(send_str); 
		// 向服务器发送buffer中的数据
		send(client_socket,send_str,strlen(send_str),0);
		// 关闭文件 
		pclose(file);
	}
	//关闭socket
	close(client_socket);
	return 0;
}
