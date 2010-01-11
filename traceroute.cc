#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#define BUF_SIZ			4096
#define PORT			33434
#define WAITTIME		3
#define NQUERIES		3
#define PACKETSIZE		40
#define MAX_PACKETSIZE		65535
#define PACKET_HEADER_LEN	28
#define MAX_TTL			64

enum {LAST_PACKET = 1, INVALID_PACKET};

struct sockaddr_in target_addr;

int display_ttl = 0, max_ttl = MAX_TTL, resolve = 1,
	port = PORT, nqueries = NQUERIES, verbose = 0,
	waittime = WAITTIME, packetsize = PACKETSIZE, id;

char *hostname = NULL;

int usage(char *prgname)
{
	char s[BUF_SIZ];
	unsigned int i, max;

	max = strlen("usage: ") + strlen(prgname) + 1;
	
	for (i = 0; (i < max) && (i < sizeof(s)); i++)
		s[i] = ' ';
	s[i] = '\0';
	
	fprintf(stderr,
		"usage: %s [-l] [-m max_ttl] [-n] [-p port] [-q nqueries]\n"
		"%s[-v] [-w waittime] host [packetsize]\n",
		prgname, s);

	fprintf(stderr, "\n    -l            Display the ttl value of the returned packet.");
	fprintf(stderr, "\n    -m max_ttl    Set max_ttl as the max time-to-live value (max hops)"
			"\n                  in the outgoing packets (default is %i)", MAX_TTL);
	fprintf(stderr, "\n    -n            Print hop addresses numerical instead of using hostnames"
			"\n                  (to save a DNS query)");
	fprintf(stderr, "\n    -p port       Use port as destination port for outgoing UDP packets"
			"\n                  (default port is %i)", PORT);
	fprintf(stderr, "\n    -q nqueries   Set the number of queries per address to nqueries"
			"\n                  (default is %i queries)", NQUERIES);
	fprintf(stderr, "\n    -v            Verbose output. Every received ICMP message is printed out");
	fprintf(stderr, "\n    -w waittime   Set the time (in seconds) to wait for a response"
			"\n                  (default is %i seconds)", WAITTIME);
	fprintf(stderr, "\n    host          Hostname or address to trace");
	fprintf(stderr, "\n    packetsize    Size of probe packets (default is %i)", PACKETSIZE);
	
	fputc('\n', stderr);
	fputc('\n', stderr);

	return 1;	
}

int send_udp_packet(int sock, struct sockaddr_in addr, int ttl, int port)
{
	char packet[MAX_PACKETSIZE];
	
	addr.sin_port = htons(port);
	
	if (setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) == -1)
	{
		perror("setsockopt() failed");
		return 1;
	}
	
	if (sendto(sock, packet, packetsize - PACKET_HEADER_LEN, 0,
		(struct sockaddr*)&addr, sizeof(addr)) == -1)
	{
		perror("sendto() failed");
		return 2;
	}

	return 0;
}

int icmp_recvd(int icmp_socket, int ttl, int n, struct timeval *tv_start)
{
	char buffer[BUF_SIZ];
	static char name[BUF_SIZ];
	unsigned int bytes;
	static u_long last_addr;
	struct icmp *icmp;
	struct udphdr *udp;
	struct ip *ip;
	struct timeval tv_end;
	struct hostent *host;
	u_long diff;
	
	bytes = read(icmp_socket, buffer, sizeof(buffer));
	
	if (bytes >= 2 * sizeof(*ip) + sizeof(*icmp) + sizeof(*udp))
	{
		udp = (struct udphdr*) (buffer+sizeof(*icmp)+2*sizeof(*ip));
		if (udp->uh_sport != htons(id))
			return INVALID_PACKET;
	}
	
	gettimeofday(&tv_end, NULL);
	diff = ((tv_end.tv_sec - tv_start->tv_sec) * 1000) +
		((tv_end.tv_usec - tv_start->tv_usec) / 1000);
		
	ip = (struct ip*) buffer;
	icmp = (struct icmp*) (buffer + sizeof(*ip));
	
	if (last_addr != ip->ip_src.s_addr)
	{
		strcpy(name, inet_ntoa(ip->ip_src));

		host = gethostbyaddr((char*) &ip->ip_src,
			sizeof(ip->ip_src), AF_INET);

		if (resolve && host)
			strcpy(name, host->h_name);
		
		printf("%s (%s)", name, inet_ntoa(ip->ip_src));
		
		if (display_ttl)
			printf(" ttl=%i", ip->ip_ttl);
		
		last_addr = ip->ip_src.s_addr;
	}
	

	if (verbose)
	{
		putchar('\n');
		putchar('\t');
		switch(icmp->icmp_type)
		{
			case ICMP_ECHOREPLY:
				printf("ICMP_ECHOREPLY"); break;
			case ICMP_UNREACH:
				printf("ICMP_UNREACH"); break;
			case ICMP_SOURCEQUENCH:
				printf("ICMP_SOURCEQUENCH"); break;
			case ICMP_REDIRECT:
				printf("ICMP_REDIRECT"); break;
			case ICMP_ECHO:
				printf("ICMP_ECHO"); break;
			case ICMP_TIMXCEED:
				printf("ICMP_TIMXCEED"); break;
			case ICMP_PARAMPROB:
				printf("ICMP_PARAMPROB"); break;
			case ICMP_TSTAMP:
				printf("ICMP_TSTAMP"); break;
			case ICMP_TSTAMPREPLY:
				printf("ICMP_TSTAMPREPLY"); break;
			case ICMP_IREQ:
				printf("ICMP_IREQ"); break;
			case ICMP_IREQREPLY:
				printf("ICMP_IREQREPLY"); break;
			case ICMP_MASKREQ:
				printf("ICMP_MASKREQ"); break;
			case ICMP_MASKREPLY:
				printf("ICMP_MASKREPLY"); break;
			default:
				printf("unknown ICMP"); break;
		}
		
		printf(" from %s after", inet_ntoa(ip->ip_src));
	}
	
	printf ("  %lu ms", !diff?1:diff);
	fflush(stdout);
		
	if (icmp->icmp_type != ICMP_TIMXCEED)
		return LAST_PACKET;

	return 0;
}

int trace(void)
{
	struct hostent *host;
	int udp_socket, icmp_socket, ttl, ret = 0, i;
	struct in_addr addr;
	struct sockaddr_in source_addr;
	struct timeval tv, tv_start;
	fd_set fds;
	
	if (!inet_aton(hostname, &addr))
	{
		if ( !(host = gethostbyname(hostname)) )
		{
			herror("gethostbyname() failed");
			return 1;
		}
		
		addr = *(struct in_addr*) host->h_addr;
	}
	
	target_addr.sin_addr = addr;
	target_addr.sin_family = AF_INET;
	
	printf("traceroute to %s (%s), %i hops max, %i byte packets\n",
		hostname, inet_ntoa(addr), max_ttl, packetsize);
	
	if ( (udp_socket = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
	{
		perror("socket() failed");
		return 2;
	}
	
	source_addr.sin_addr.s_addr = INADDR_ANY;
	source_addr.sin_port = htons(id);
	source_addr.sin_family = AF_INET;
	
	if (bind(udp_socket, (struct sockaddr*)&source_addr,
		sizeof(source_addr)) == -1)
	{
		perror("bind() failed");
		return 3;
	}
	
	if ( (icmp_socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1)
	{
		perror("socket() failed");
		return 4;
	}
	
	for(ttl = 1; ttl <= max_ttl && (ret != LAST_PACKET); ttl++)
	{
		printf(" %i ", ttl);
		fflush(stdout);
		for (i = 0; i < nqueries; i++)
		{
			gettimeofday(&tv_start, NULL);
			if (send_udp_packet(udp_socket, target_addr, ttl,
				port + i))
				return 5;
				
			invalid_packet:
			
			FD_ZERO(&fds);
			FD_SET(icmp_socket, &fds);
			tv.tv_sec = waittime;
			tv.tv_usec = 0;
		
			select(icmp_socket + 1, &fds, 0, 0, &tv);
		
			if (FD_ISSET(icmp_socket, &fds))
			{
				if ( (ret = icmp_recvd(icmp_socket, ttl, i,
					&tv_start)) == INVALID_PACKET)
					goto invalid_packet;
			}	
			else
				printf("  *");
			fflush(stdout);
		}
		putchar('\n');
	}
	
	close(icmp_socket);
	close(udp_socket);
		
	return 0;
}

int main(int argc, char *argv[])
{
	int i;
	
	if (argc < 2)
		return usage(argv[0]);

	id = (getpid() & 0x7fff) | 0x8000;
		
	for (i = 1; i < argc; i++)
	{
		if (!strcmp(argv[i], "-l"))
		{
			display_ttl = 1;
			continue;
		}
		
		if (!strcmp(argv[i], "-m"))
		{
			if (i + 1 < argc)
				max_ttl = atol(argv[++i]);
			else
				return usage(argv[0]);
			continue;
		}
		
		if (!strcmp(argv[i], "-n"))
		{
			resolve = 0;
			continue;
		}
			
		if (!strcmp(argv[i], "-p"))
		{
			if (i + 1 < argc)
				port = atol(argv[++i]);
			else
				return usage(argv[0]);
			continue;
		}
		
		if (!strcmp(argv[i], "-q"))
		{
			if (i + 1 < argc)
				nqueries = atol(argv[++i]);
			else
				return usage(argv[0]);
			continue;
		}
		
		if (!strcmp(argv[i], "-v"))
		{
			verbose = 1;
			continue;
		}
			
		if (!strcmp(argv[i], "-w"))
		{
			if (i + 1 < argc)
				waittime = atol(argv[++i]);
			else
				return usage(argv[0]);
			continue;
		}
		
		if (!hostname)
		{
			hostname = argv[i];
			continue;
		}
		
		if( (packetsize = atol(argv[i])) != 0)
			continue;
			
		fprintf(stderr, "unknown option: %s\n", argv[i]);
		return 1;
	}
	
	if (packetsize < PACKET_HEADER_LEN)
	{
		fprintf(stderr, "value of packetsize is too small! "
			"Use %i or more.\n", PACKET_HEADER_LEN);
		return 2;
	}
	
	return trace();
}

