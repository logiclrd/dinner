// first for FreeBSD's broken <sys/socket.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <iostream>
#include <sys/un.h>
#include <unistd.h>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <cerrno>
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
        dot = parse_from.find(':');
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
char *linkname;

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

  while ((pending_connections_by_time.size() > 0) && (pending_connections_by_time.begin()->first < ctime))
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

  cerr << "I: link name is " << linkname << endl;

  int link_sockfd = socket(AF_LOCAL, SOCK_STREAM, 0);

  sockaddr_un sun;
  memset(&sun, 0, sizeof(sun));
  sun.sun_family = AF_LOCAL;
  strcpy(sun.sun_path, linkname);

  if (connect(link_sockfd, (sockaddr *)&sun, sizeof(sun)))
  {
    cerr << "ERROR: unable to connect to link in 'inside' child" << endl;
    return (void *)1;
  }
  else
    vv("'inside traffic' connected to the link");

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
      vv("I: a possible NATted connection was caught");

      string link_command = string("I") + ((string)line.src_ip) + ' ' + ((string)line.dst_ip) + '\n';
      send(link_sockfd, link_command.c_str(), link_command.size(), 0);
    }
  }
}

void *outside_thread(void *arg)
{
  vv("O: inside the 'outside traffic' thread");

  int link_sockfd = socket(AF_LOCAL, SOCK_STREAM, 0);

  sockaddr_un sun;
  memset(&sun, 0, sizeof(sun));
  sun.sun_family = AF_LOCAL;
  strcpy(sun.sun_path, linkname);

  if (connect(link_sockfd, (sockaddr *)&sun, sizeof(sun)))
  {
    cerr << "ERROR: unable to connect to link in 'outside' child" << endl;
    return (void *)1;
  }
  else
    vv("'outside traffic' connected to the link");

  char buf[1024];
  memset(buf, 0, sizeof(buf));
  while (true)
  {
    read_line(outside, buf);

    cerr << "outside traffic: " << buf << endl;

    tcpdump_line line(buf);
    if (!line.valid)
      continue;

    cerr << "reconstruction:  " << line.src_ip << " > " << line.dst_ip << ": " << char(line.connection_code) << endl;

    if ((line.connection_code == 'S') && (line.src_ip.same_ip(outside_ip)))
    {
      vv("O: a possible match for outbound connections has been caught");

      string link_command = string("O+") + ((string)line.dst_ip) + '\n';
      send(link_sockfd, link_command.c_str(), link_command.size(), 0);
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

      vv("O: a possible connection close event was caught");

      string link_command = string("O-") + ((string)addr) + '\n';
      send(link_sockfd, link_command.c_str(), link_command.size(), 0);
    }
  }
}

struct link_message_state
{
  stringstream *ss;
};

map<int, link_message_state> link_messagedata;

bool handle_link_message(int sockfd)
{
  vv("C: inside link thread");

  map<int, link_message_state>::iterator it = link_messagedata.find(sockfd);

  if (it == link_messagedata.end())
  {
    link_message_state state;
    state.ss = new stringstream();
    link_messagedata[sockfd] = state;
    it = link_messagedata.find(sockfd);
  }

  link_message_state &state = link_messagedata[sockfd];

  while (true)
  {
    char code;
    int bytes_read = recv(sockfd, &code, 1, 0);

    if (bytes_read == 0)
    {
      cerr << "ERROR: link closed!";
      return true;
    }

    if (bytes_read < 0)
    {
      if (errno == EWOULDBLOCK)
        return false;
      cerr << "ERROR: error on link!";
      return true;
    }

    if (code == '\n')
    {
      string link_message = state.ss->str();
      delete state.ss;
      state.ss = new stringstream();

      if (link_message[0] == 'I')
      {
        link_message = link_message.substr(1);

        int space = link_message.find(' ');
        if (space == string::npos)
          continue;

        string src_ip_str = link_message.substr(0, space);
        string dst_ip_str = link_message.substr(space + 1);

        add_pending_connection(src_ip_str, dst_ip_str);
      }
      else if (link_message[0] == 'O')
      {
        link_message = link_message.substr(1);

        if (link_message[0] == '+')
        {
          ip_addr dst_ip(link_message.substr(1));

          connection_info info;
          if (match_and_remove_pending_connection(dst_ip, &info))
          {
            vv("O: the outbound connection was matched and is now current");
            v("added a mapping to the table");
            current_connections_by_ip[dst_ip.to_int()][dst_ip.port] = info;
          }
        }
        else if (link_message[0] == '-')
        {
          ip_addr addr(link_message.substr(1));

          vv("O: a possible connection close event was caught");

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
        }
      }
    }
    else
      *state.ss << code;
  }

  vv("C: leaving link thread");
}

struct client_message_state
{
  int code;
  stringstream *ip_ss;
};

map<int, client_message_state> client_messagedata;

bool handle_client_message(int sockfd)
{
  vv("C: inside client thread");

  map<int, client_message_state>::iterator it = client_messagedata.find(sockfd);

  if (it == client_messagedata.end())
  {
    client_message_state state;
    state.code = -1;
    state.ip_ss = new stringstream();
    client_messagedata[sockfd] = state;
    it = client_messagedata.find(sockfd);
  }

  client_message_state &state = client_messagedata[sockfd];

  while (true)
  {
    char code;
    int bytes_read;

    if (state.code < 0)
    {
      bytes_read = recv(sockfd, &code, 1, 0);

      if (bytes_read < 1)
      {
        if ((bytes_read == 0) || (errno != EWOULDBLOCK))
        {
          delete state.ip_ss;
          client_messagedata.erase(it);
          return true;
        }
        break;
      }
    }
    else
      code = state.code;

    stringstream ss;

    switch (code)
    {
      case 'l':
        {
          vv("C: client asked for a list");

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
          state.code = -1;
        }
        break;
      case 'i':
        {
          vv("C: client is asking about a specific destination");

          stringstream &ip_ss = *state.ip_ss;

          for (int i=int(ip_ss.tellp()); i<20; i++)
          {
            if (i == 19)
            {
              delete state.ip_ss;
              client_messagedata.erase(it);
              return true;
            }

            bytes_read = recv(sockfd, &code, 1, 0);
            if (bytes_read == 0)
            {
              delete state.ip_ss;
              client_messagedata.erase(it);
              return true;
            }
            if (bytes_read < 0)
              return (errno != EWOULDBLOCK);

            if (code == '\n')
              break;

            ip_ss << code;
          }

          ip_addr ip(ip_ss.str());

          delete state.ip_ss;
          state.ip_ss = new stringstream();

          vv(string("C: the client is asking about the ip ") + ip_ss.str());

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
          state.code = -1;
        }
        break;
      case 'q':
        delete state.ip_ss;
        client_messagedata.erase(it);
        return true;
    }
    if (bytes_read <= 0)
    {
      if ((bytes_read == 0) || (errno != EWOULDBLOCK))
      {
        delete state.ip_ss;
        client_messagedata.erase(it);
        return true;
      }
      return false;
    }

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
  vv("C: exiting client thread abnormally");
  return true;
}

int control_sockfd, link1_sockfd, link2_sockfd;

void *control_thread(void *arg)
{
  vv("CTRL: inside control thread");

  int maxfd = control_sockfd;
  if (maxfd < link1_sockfd)
    maxfd = link1_sockfd;
  if (maxfd < link2_sockfd)
    maxfd = link2_sockfd;

  vector<int> clients;

  while (true)
  {
    fd_set read_set;

    FD_ZERO(&read_set);
    FD_SET(control_sockfd, &read_set);
    FD_SET(link1_sockfd, &read_set);
    FD_SET(link2_sockfd, &read_set);
    for (vector<int>::iterator i = clients.begin();
         i != clients.end();
         ++i)
    {
      int fd = *i;
      FD_SET(fd, &read_set);
    }

    select(maxfd + 1, &read_set, NULL, NULL, NULL);

    if (FD_ISSET(control_sockfd, &read_set))
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

      int truevalue = 1;

      ioctl(client_sockfd, FIONBIO, &truevalue);

      clients.push_back(client_sockfd);
    }
    if (FD_ISSET(link1_sockfd, &read_set))
      handle_link_message(link1_sockfd);
    if (FD_ISSET(link2_sockfd, &read_set))
      handle_link_message(link2_sockfd);
    for (vector<int>::iterator i = clients.begin();
         i != clients.end();
         ++i)
    {
      int fd = *i;
      if (FD_ISSET(fd, &read_set))
        handle_client_message(fd);
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

  int sockfd = socket(AF_LOCAL, SOCK_STREAM, 0);

  if (sockfd < 0)
  {
    cerr << "error: unable to allocate link socket" << endl;
    return 1;
  }

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

  linkname = tmpnam(NULL);

  cerr << "link name is " << linkname << endl;

  sockaddr_un sun;
  memset(&sun, 0, sizeof(sun));
  sun.sun_family = AF_INET;
  strcpy(sun.sun_path, linkname);

  if (bind(sockfd, (sockaddr *)&sun, sizeof(sun)))
  {
    cerr << "error: unable to bind link socket" << endl;
    return 1;
  }

  if (listen(sockfd, 5))
  {
    cerr << "error: unable to listen on link socket" << endl;
    return 1;
  }

  inside = popen((string("tcpdump -i ") + argv[1] + " -l -n -t 'ip and tcp and (tcp[13] & 7 != 0)'").c_str(), "r");
  outside = popen((string("tcpdump -i ") + argv[2] + " -l -n -t 'ip and tcp and (tcp[13] & 7 != 0)'").c_str(), "r");

  vv("forking to start handler threads");

  int pid = fork();

  if (pid == 0)
    return (int)inside_thread(NULL);

  socklen_t sun_len = sizeof(sun);

  link1_sockfd = accept(sockfd, (sockaddr *)&sun, &sun_len);

  pid = fork();

  if (pid == 0)
    return (int)outside_thread(NULL);

  link2_sockfd = accept(sockfd, (sockaddr *)&sun, &sun_len);

  close(sockfd);
  unlink(linkname);

  sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  if (sockfd < 0)
  {
    cerr << "error: unable to allocate control socket" << endl;
    return 1;
  }

  int enable = 1;
  setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));

  ioctl(link1_sockfd, FIONBIO, &enable);
  ioctl(link2_sockfd, FIONBIO, &enable);

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

  vv("entering control thread");

  control_thread(NULL);
}

