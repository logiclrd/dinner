// first for FreeBSD's broken <sys/socket.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <iostream>
#include <sys/un.h>
#include <unistd.h>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <cstdio>
#include <string>
#include <vector>
#include <ctime>
#include <map>

using namespace std;

struct ip_addr
{
  unsigned char address[4];
  unsigned short port;

  ip_addr()
  {
    memset(address, 0, sizeof(address));
  }

  ip_addr(string parse_from)
  {
    int value[5];

    memset(value, 0, sizeof(value));

    parse_from = parse_from + '.';

    for (int i=0; i<5; i++)
    {
      int dot = parse_from.find('.');
      if (dot == string::npos)
        break;

      value[i] = atoi(parse_from.substr(0, dot).c_str());
      parse_from = parse_from.substr(dot + 1);
    }

    for (int i=0; i<4; i++)
      address[i] = (unsigned char)value[i];
    port = (unsigned short)value[4];
  }

  operator string() const
  {
    stringstream ss;

    for (int i=0; i<4; i++)
    {
      if (i > 0)
        ss << '.';
      ss << int(address[i]);
    }
    ss << ':' << port;

    return ss.str();
  }

  int to_int() const
  {
    return (address[0] << 24) | (address[1] << 16) | (address[2] << 8) | address[3];
  }

  bool same_ip(const ip_addr &other) const
  {
    for (int i=0; i<4; i++)
      if (address[i] != other.address[i])
        return false;
  }

  bool operator == (const ip_addr &other) const
  {
    return same_ip(other) && (port == other.port);
  }
};

ostream &operator <<(ostream &left, const ip_addr &right)
{
  return left << (string)right;
}

struct netid
{
  ip_addr id;
  ip_addr mask;

  netid()
  {
  }

  netid(string parse_from)
  {
    int slash = parse_from.find('/');

    string bits_str;

    if (slash != string::npos)
    {
      bits_str = parse_from.substr(slash + 1);
      parse_from = parse_from.substr(0, slash);
    }

    id = parse_from;

    if (bits_str.size() == 0) // no mask specified, must guess from the IP range
    {
      if (id.address[0] < 128)
        bits_str = "8";
      else if (id.address[0] < 192)
        bits_str = "16";
      else if (id.address[0] < 224)
        bits_str = "24";
      else
        bits_str = "32";
    }

    int dot = bits_str.find('.');
    if (dot == string::npos)
    {
      int bits = atoi(bits_str.c_str());
      if (bits > 32)
        bits = 32;

      int offset = 0;
      while (bits > 8)
        mask.address[offset++] = 0xff, bits -= 8;

      if (bits > 0)
        mask.address[offset] = (0xff << (8 - bits)) & 0xff;
    }
    else
      mask = bits_str;
  }

  bool matches(ip_addr address) const
  {
    for (int i=0; i<4; i++)
      address.address[i] &= mask.address[i];
    for (int i=0; i<4; i++)
      if (address.address[i] != id.address[i])
        return false;
    return true;
  }
};

struct tcpdump_line
{
  bool valid;

  ip_addr src_ip, dst_ip;
  int connection_code;

  tcpdump_line(string parse_from)
  {
    valid = false;

    int space = parse_from.find(' ');
    if (space == string::npos)
      return;

    src_ip = parse_from.substr(0, space);

    parse_from = parse_from.substr(space + 1);
    if (parse_from[0] != '>')
      return;
    if (parse_from[1] != ' ')
      return;
    parse_from = parse_from.substr(2);

    int colon = parse_from.find(':');
    if (colon == string::npos)
      return;

    dst_ip = parse_from.substr(0, colon);

    parse_from = parse_from.substr(colon + 1);
    if (parse_from[0] != ' ')
      return;

    connection_code = parse_from[1];

    valid = true;
  }
};

class mutex
{
  pthread_mutex_t mutex_obj;
  mutex(mutex &other) {} // prevent copying
public:
  mutex()
  {
    pthread_mutex_init(&mutex_obj, NULL);
  }

  ~mutex()
  {
    pthread_mutex_destroy(&mutex_obj);
  }

  void lock()
  {
    pthread_mutex_lock(&mutex_obj);
  }

  void unlock()
  {
    pthread_mutex_unlock(&mutex_obj);
  }

  bool trylock()
  {
    return (pthread_mutex_trylock(&mutex_obj) == 0);
  }
};

class mutex_lock
{
  mutex &mutex_obj;
  mutex_lock(mutex_lock &other) : mutex_obj(*(mutex *)NULL) {} // prevent copying
public:
  mutex_lock(mutex &mutex)
    : mutex_obj(mutex)
  {
    mutex_obj.lock();
  }

  ~mutex_lock()
  {
    mutex_obj.unlock();
  }
};

struct connection_info
{
  ip_addr src_ip, dst_ip;
  int outside_src_port, timeout;
};

FILE *inside, *outside;
netid inside_id;
ip_addr outside_ip;
map<int,vector<connection_info> > pending_connections_by_time;
map<int,map<unsigned short, connection_info> > pending_connections_by_ip;
map<int,map<unsigned short, connection_info> > current_connections_by_ip;
mutex pending_connections_lock, current_connections_lock;

volatile bool v_flag, vv_flag;

void v(string msg)
{
  if (v_flag || vv_flag)
    cerr << msg << endl;
}

void vv(string msg)
{
  if (vv_flag)
    cerr << msg << endl;
}

int clean_pending()
{
  int ctime = time(NULL);

  while (pending_connections_by_time.begin()->first < ctime)
  {
    vector<connection_info> &vec = pending_connections_by_time.begin()->second;

    for (vector<connection_info>::iterator i = vec.begin();
         i != vec.end();
         ++i)
    {
      map<int, map<unsigned short, connection_info> >::iterator it = pending_connections_by_ip.find(i->dst_ip.to_int());
      map<unsigned short, connection_info> &port_map = it->second;
      port_map.erase(port_map.find(i->dst_ip.port));
      if (port_map.size() == 0)
        pending_connections_by_ip.erase(it);
    }

    pending_connections_by_time.erase(pending_connections_by_time.begin());
  }

  return ctime;
}

void add_pending_connection(const ip_addr &src, const ip_addr &dst)
{
  connection_info info;

  info.src_ip = src;
  info.dst_ip = dst;

  int ctime = clean_pending();

  info.timeout = ctime;

  pending_connections_by_time[ctime + 90].push_back(info);
  pending_connections_by_ip[info.dst_ip.to_int()][info.dst_ip.port] = info;
}

bool match_and_remove_pending_connection(const ip_addr &dst, connection_info *result)
{
  clean_pending();

  map<int, map<unsigned short, connection_info> >::iterator it = pending_connections_by_ip.find(dst.to_int());

  map<unsigned short, connection_info> &port_map = it->second;
  map<unsigned short, connection_info>::iterator port_it = port_map.find(dst.port);

  if (port_it == port_map.end())
    return false;

  *result = port_it->second;

  map<int, vector<connection_info> >::iterator time_it = pending_connections_by_time.find(port_it->second.timeout);
  if (time_it != pending_connections_by_time.end())
  {
    vector<connection_info> &vec = time_it->second;
    for (vector<connection_info>::iterator i = vec.begin();
         i != vec.end();
         ++i)
      if (i->dst_ip == dst)
      {
        vec.erase(i);
        break;
      }
    if (vec.size() == 0)
      pending_connections_by_time.erase(time_it);
  }

  port_map.erase(port_it);

  if (port_map.size() == 0)
    pending_connections_by_ip.erase(it);

  return true;
}

void read_line(FILE *file, char *buf)
{
  buf[1023] = 0;
  for (int i=0; i<1023; i++)
  {
    int ch = getc(file);
    if (ch == '\n')
      ch = 0;

    buf[0] = ch;
    buf++;

    if (ch <= 0)
      break;
  }
}

void *inside_thread(void *arg)
{
  vv("I: inside the 'inside traffic' thread");

  char buf[1024];
  memset(buf, 0, sizeof(buf));
  while (true)
  {
    read_line(inside, buf);

    tcpdump_line line(buf);
    if (!line.valid)
      continue;

    if (!inside_id.matches(line.src_ip))
      continue;

    if (line.connection_code == 'S')
    {
      vv("I: a possible NATted connection was caught, locking the pending connections");
      mutex_lock lock(pending_connections_lock);
      vv("I: got the lock");

      add_pending_connection(line.src_ip, line.dst_ip);

      vv("I: unlocking the pending connections");
    }
  }
}

void *outside_thread(void *arg)
{
  vv("O: inside the 'outside traffic' thread");

  char buf[1024];
  memset(buf, 0, sizeof(buf));
  while (true)
  {
    read_line(outside, buf);

    tcpdump_line line(buf);
    if (!line.valid)
      continue;

    if ((line.connection_code == 'S') && (line.src_ip.same_ip(outside_ip)))
    {
      vv("O: a possible match for outbound connections has been caught, locking the pending connections");
      mutex_lock lock(pending_connections_lock);
      vv("O: got the lock");

      connection_info info;
      if (match_and_remove_pending_connection(line.dst_ip, &info))
      {
        vv("O: the outbound connection was matched and is now current, locking the current connections");
        mutex_lock lock(current_connections_lock);
        vv("O: got the lock");

        v("added a mapping to the table");

        current_connections_by_ip[line.dst_ip.to_int()][line.dst_ip.port] = info;

        vv("O: unlocking the current connections");
      }

      vv("O: unlocking the pending connections");
    }
    else if ((line.connection_code == 'F') || (line.connection_code == 'R'))
    {
      ip_addr addr;

      if (line.src_ip.same_ip(outside_ip))
        addr = line.dst_ip;
      else if (line.dst_ip.same_ip(outside_ip))
        addr = line.src_ip;
      else
        continue;

      vv("O: a possible connection close event was caught, locking the current connections");
      mutex_lock lock(current_connections_lock);
      vv("O: got the lock");

      map<int, map<unsigned short, connection_info> >::iterator it = current_connections_by_ip.find(addr.to_int());
      if (it == current_connections_by_ip.end())
        continue;

      map<unsigned short, connection_info> &port_map = it->second;

      map<unsigned short, connection_info>::iterator port_it = port_map.find(addr.port);
      if (port_it == port_map.end())
        continue;

      v("a mapping was removed from the table");

      port_map.erase(port_it);

      if (port_map.size() == 0)
        current_connections_by_ip.erase(it);

      vv("O: releasing the current connections");
    }
  }
}

void *client_thread(void *arg)
{
  int sockfd = (int)arg;

  vv("C: inside client thread");

  while (true)
  {
    char code;
    int bytes_read = recv(sockfd, &code, 1, 0);

    if (bytes_read < 1)
      break;

    stringstream ss;

    switch (code)
    {
      case 'l':
        {
          vv("C: client asked for a list, locking current connections");
          mutex_lock lock(current_connections_lock);
          vv("C: got the lock");

          for (map<int, map<unsigned short, connection_info> >::iterator i = current_connections_by_ip.begin();
               i != current_connections_by_ip.end();
               ++i)
            for (map<unsigned short, connection_info>::iterator j = i->second.begin();
                 j != i->second.end();
                 ++j)
            {
              connection_info &info = j->second;

              ss << info.src_ip << '\t' << info.dst_ip << '\t' << info.outside_src_port << '\n';
            }

          vv("C: unlocking current connections");
        }
        break;
      case 'i':
        {
          vv("C: client is asking about a specific destination");

          stringstream ip_ss;

          for (int i=0; i<20; i++)
          {
            if (i == 19)
            {
              close(sockfd);
              return NULL;
            }

            bytes_read = recv(sockfd, &code, 1, 0);
            if (bytes_read <= 0)
              break;

            if (code == '\n')
              break;

            ip_ss << code;
          }

          ip_addr ip(ip_ss.str());

          vv(string("C: the client is asking about the ip ") + ip_ss.str() + ", locking current connections");
          mutex_lock lock(current_connections_lock);
          vv("C: got the lock");

          map<int, map<unsigned short, connection_info> >::iterator it = current_connections_by_ip.find(ip.to_int());

          if (it == current_connections_by_ip.end())
            ss << "no\n";
          else
          {
            map<unsigned short, connection_info> &port_map = it->second;
            map<unsigned short, connection_info>::iterator port_it = port_map.find(ip.port);

            if (port_it == port_map.end())
              ss << "no\n";
            else
            {
              connection_info &info = port_it->second;

              ss << info.src_ip << '\t' << info.dst_ip << '\t' << info.outside_src_port << '\n';
            }
          }

          vv("C: releasing the lock");
        }
        break;
    }
    if ((bytes_read <= 0) || (code == 'q'))
      break;

    vv("C: sending reply to the client");

    const char *reply = ss.str().c_str();
    int reply_len = strlen(reply);

    while (reply_len)
    {
      int bytes_sent = send(sockfd, reply, reply_len, 0);

      if (bytes_sent <= 0)
        break;

      reply += bytes_sent;
      reply_len -= bytes_sent;
    }
  }

  close(sockfd);

  vv("C: exiting client thread normally");
}

int control_sockfd;

void *control_thread(void *arg)
{
  vv("CTRL: inside control thread");

  while (true)
  {
    sockaddr_in sin;
    socklen_t sin_len = sizeof(sin);

    memset(&sin, 0, sin_len);

    int client_sockfd = accept(control_sockfd, (sockaddr *)&sin, &sin_len);

    if (client_sockfd < 0)
    {
      cerr << "ERROR ACCEPTING ON CONTROL SOCKET!" << endl;
      usleep(10000000); // 10 seconds
      continue;
    }

    v("received a client connection");

    pthread_t client_thread_id;

    if (pthread_create(&client_thread_id, NULL, client_thread, (void *)client_sockfd))
    {
      cerr << "ERROR CREATING CLIENT THREAD" << endl;
      close(client_sockfd);
    }
  }
}

int main(int argc, char *argv[])
{
  v_flag = vv_flag = 0;

  if (argc < 4)
  {
    cerr << "usage: " << argv[0] << " <inside interface> <outside interface> <inside netid> <outside ip> [-v] [-vv]" << endl;
    cerr << "   <inside netid> is of the form 10.0.0.0/8 or 10/8 or 10/255.0.0.0" << endl;
    return 1;
  }

  int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  if (sockfd < 0)
  {
    cerr << "error: unable to allocate control socket" << endl;
    return 1;
  }

  int enable = 1;
  setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));

  sockaddr_in sin;
  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_port = htons(7838);

  if (bind(sockfd, (sockaddr *)&sin, sizeof(sin)))
  {
    cerr << "error: unable to bind control socket to port 7838" << endl;
    return 1;
  }

  if (listen(sockfd, 5))
  {
    cerr << "error: unable to listen on control socket" << endl;
    return 1;
  }

  control_sockfd = sockfd;

  inside = popen((string("tcpdump -i ") + argv[1] + " -l -n -t 'ip and tcp and (tcp[13] & 7 != 0)'").c_str(), "r");
  outside = popen((string("tcpdump -i ") + argv[2] + " -l -n -t 'ip and tcp and (tcp[13] & 7 != 0)'").c_str(), "r");

  inside_id = netid(argv[3]);
  outside_ip = ip_addr(argv[4]);

  for (int i=5; i<argc; i++)
  {
    string arg(argv[i]);

    if (arg == "-v")
    {
      if (v_flag == false)
        v_flag = true;
      else
        vv_flag = true;
    }
    else if (arg == "-vv")
      vv_flag = true;
  }

  pthread_t inside_id, outside_id;

  vv("about to create packet handler threads");

  if (pthread_create(&inside_id, NULL, inside_thread, NULL)
   || pthread_create(&outside_id, NULL, outside_thread, NULL))
  {
    cerr << "ERROR CREATING HANDLER THREADS!" << endl;
    return 1;
  }

  pthread_yield(); // try to allow the other threads to start up
  pthread_yield();
  pthread_yield();

  vv("entering control thread");

  control_thread(NULL);
}

