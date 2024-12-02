#include <pthread.h>
#include <iostream>

using namespace std;

void *t(void *a)
{
  int i = (int)a;

  while (true)
    cerr << i;
}

int main()
{
  pthread_t foo;

  pthread_create(&foo, NULL, t, (void *)1);
  pthread_create(&foo, NULL, t, (void *)2);

  while (true)
    cerr << "m";
}
