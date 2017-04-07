#ifndef MY_QUEUE_H_INCLUDED_
#define MY_QUEUE_H_INCLUDED_

#include <stddef.h>
typedef struct my_queue_s  my_queue_t;

struct my_queue_s {
    my_queue_t  *prev;
    my_queue_t  *next;
};


#define my_queue_init(q)                                                     \
  do {                                                                        \
    (q)->prev = q;                                                            \
    (q)->next = q;                                                            \
  }                                                                           \
  while (0)


#define my_queue_empty(h)                                                    \
    (h == (h)->prev)


#define my_queue_insert_head(h, x)                                           \
  do {                                                                        \
    (x)->next = (h)->next;                                                    \
    (x)->next->prev = x;                                                      \
    (x)->prev = h;                                                            \
    (h)->next = x;                                                            \
  }                                                                           \
  while (0)


#define my_queue_insert_after   my_queue_insert_head


#define my_queue_insert_tail(h, x)                                           \
  do {                                                                        \
    (x)->prev = (h)->prev;                                                    \
    (x)->prev->next = x;                                                      \
    (x)->next = h;                                                            \
    (h)->prev = x;                                                            \
  }                                                                           \
  while (0)


#define my_queue_head(h)                                                     \
    (h)->next


#define my_queue_last(h)                                                     \
    (h)->prev


#define my_queue_sentinel(h)                                                 \
    (h)


#define my_queue_next(q)                                                     \
    (q)->next


#define my_queue_prev(q)                                                     \
    (q)->prev

#define my_queue_remove(x)                                                   \
  do {                                                                        \
    (x)->next->prev = (x)->prev;                                              \
    (x)->prev->next = (x)->next;                                              \
  }                                                                           \
  while (0)

#define my_queue_split(h, q, n)                                              \
  do {                                                                        \
    (n)->prev = (h)->prev;                                                    \
    (n)->prev->next = n;                                                      \
    (n)->next = q;                                                            \
    (h)->prev = (q)->prev;                                                    \
    (h)->prev->next = h;                                                      \
    (q)->prev = n;                                                            \
  }                                                                           \
  while (0)


#define my_queue_add(h, n)                                                   \
  do {                                                                        \
    (h)->prev->next = (n)->next;                                              \
    (n)->next->prev = (h)->prev;                                              \
    (h)->prev = (n)->prev;                                                    \
    (h)->prev->next = h;                                                      \
  }                                                                           \
  while (0)


#define my_queue_data(q, type, link)                                         \
    ((type *) ((unsigned char *) q - offsetof(type, link)))


#define my_queue_foreach(q, h)                                               \
    for ((q) = my_queue_head(h);                                             \
         (q) != my_queue_sentinel(h) && !my_queue_empty(h);                 \
         (q) = my_queue_next(q))


#endif 

