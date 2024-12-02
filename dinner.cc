#include <pthread.h>
#include <pcap.h>

#include <iostream>
#include <string>

using namespace std;

#define true 1
#define false 0

void prenat_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
  cerr << "got a prenat packet, length = " << header->len << ", captured = " << header->caplen << endl;
}

void postnat_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
  cerr << "got a postnat packet, length = " << header->len << ", captured = " << header->caplen << endl;
}

pcap_t *prenat_handle;

void *prenat_thread(void *prenat)
{
  pcap_loop(prenat_handle, -1, prenat_handler, NULL);
}

int main()
{
  pcap_if_t *alldevs;
  pcap_if_t *device;
  pcap_if_t *outside_device;
  int i=0;
  char errbuf[PCAP_ERRBUF_SIZE];

  if (pcap_findalldevs(&alldevs, errbuf) == -1)
  {
    cerr << "oh dear" << endl;
    return 1;
  }

  for (device=alldevs; device != NULL; device = device->next)
  {
    cout << (++i) << ". " << device->name;
    if (device->description != NULL)
      cout << " (" << device->description << ")" << endl;
    else
      cout << " (No description available)" << endl;
  }

  if (i == 0)
  {
    cerr << "No devices found! Is libpcap installed?" << endl;
    return 1;
  }

  cout << endl
       << "Select inside device: ";

  string dev_str;

  getline(cin, dev_str);

  int dev_num = atoi(dev_str.c_str());

  for (i=0, device=alldevs; (i<dev_num) && (device != NULL); i++, device = device->next);

  cout << endl
       << "Select outside device: ";

  getline(cin, dev_str);

  dev_num = atoi(dev_str.c_str());

  for (i=0, outside_device=alldevs; (i<dev_num) && (outside_device != NULL); i++, outside_device = outside_device->next);

  pcap_t *inside_handle, *outside_handle;

  inside_handle = pcap_open_live(device->name, 60, true, 0, errbuf);
  if (inside_handle == NULL)
  {
    cerr << "Unable to open " << device->name << " for the inside interface" << endl;
    return 1;
  }

  outside_handle = pcap_open_live(outside_device->name, 60, true, 0, errbuf);
  if (outside_handle == NULL)
  {
    cerr << "Unable to open " << outside_device->name << " for the outside interface" << endl;
    return 1;
  }

  pcap_freealldevs(alldevs);

  prenat_handle = inside_handle;

  pthread_t tid;
  pthread_create(&tid, NULL, prenat_thread, NULL);

  pcap_loop(outside_handle, -1, postnat_handler, NULL);
}
