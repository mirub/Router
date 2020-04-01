#ifndef QUEUE_H
#define QUEUE_H

struct queue;
typedef struct queue *_queue;

/* create an empty queue */
extern _queue queue_create(void);

/* insert an element at the end of the queue */
extern void queue_enq(_queue q, void *element);

/* delete the front element on the queue and return it */
extern void *queue_deq(_queue q);

/* return a true value if and only if the queue is empty */
extern int queue_empty(_queue q);

#endif
