/* schedule.c
 * This file contains the primary logic for the 
 * scheduler.
 */
#include "schedule.h"
#include "macros.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "list.h"

#define NEWTASKSLICE (NS_TO_JIFFIES(100000000))
#define A 0.5
#define SCHED 3 // 1 min_burst || 2 standard goodness || 3 goodness
/* Local Globals
 * rq - This is a pointer to the runqueue that the scheduler uses.
 * current - A pointer to the current running task.
 */
struct runqueue *rq;
struct task_struct *current;

/* External Globals
 * jiffies - A discrete unit of time used for scheduling.
 *			 There are HZ jiffies in a second, (HZ is 
 *			 declared in macros.h), and is usually
 *			 1 or 10 milliseconds.
 */
extern long long jiffies;
extern struct task_struct *idle;

/*-----------------Initilization/Shutdown Code-------------------*/
/* This code is not used by the scheduler, but by the virtual machine
 * to setup and destroy the scheduler cleanly.
 */
 
 /* initscheduler
  * Sets up and allocates memory for the scheduler, as well
  * as sets initial values. This function should also
  * set the initial effective priority for the "seed" task 
  * and enqueu it in the scheduler.
  * INPUT:
  * newrq - A pointer to an allocated rq to assign to your
  *			local rq.
  * seedTask - A pointer to a task to seed the scheduler and start
  * the simulation.
  */
void initschedule(struct runqueue *newrq, struct task_struct *seedTask)
{
	seedTask->next = seedTask->prev = seedTask;
	newrq->head = seedTask;
	newrq->nr_running++;

	// rq=newrq;
	seedTask->exp_burst = 0;
	seedTask->burst = 0;
	seedTask->goodness = 0;
	seedTask->enterRQ = 0;
	seedTask->enterCPU = 0;
}

/* killschedule
 * This function should free any memory that 
 * was allocated when setting up the runqueu.
 * It SHOULD NOT free the runqueue itself.
 */
void killschedule()
{
	//
	return;
}


void print_rq () {
	struct task_struct *curr;
	
	printf("Rq: \n");
	curr = rq->head;
	if (curr)
		printf("%p", curr);
	while(curr->next != rq->head) {
		curr = curr->next;
		printf(", %p", curr);
	};
	printf("\n");
}


/*-------------Scheduler Code Goes Below------------*/
/* This is the beginning of the actual scheduling logic */

/* schedule
 * Gets the next task in the queue
 */
void schedule()
{
	struct task_struct *curr;
	struct task_struct *next;
	double min_exp_burst;
	unsigned long long max_waitRQ;
	double min_goodness;
	// printf("In schedule\n");
	//	print_rq();
	current->need_reschedule = 0;

	if (rq->nr_running == 1) {
        context_switch(rq->head);
    }else{
		current->need_reschedule = 0; /* Always make sure to reset that, in case *
									* we entered the scheduler because current*
									* had requested so by setting this flag   */
		// next = rq->head;
		current->exitCPU=sched_clock();	
		current->burst = current->exitCPU - current->enterCPU; //evgala to += gia na tsekarv me apotelesmata lysewn

		current->enterRQ=sched_clock();
		current->exp_burst=(double)(current->burst + A * (current->exp_burst)) / (double)(1+A);


		curr=rq->head->next;
		min_exp_burst=curr->exp_burst;
		#if SCHED==1
			next=curr;
		#endif
		curr=curr->next;

		//find min exp burst
		for(; curr!=rq->head; curr=curr->next){
			if(min_exp_burst > curr->exp_burst){
				min_exp_burst=curr->exp_burst;
				#if SCHED==1
					next=curr;
				#endif
			}
		}

		//find standard goodness
		#if SCHED==2
			curr=rq->head->next;

			curr->goodness = ((1 + curr->exp_burst) / (1 + min_exp_burst));
			min_goodness=curr->goodness;
			next=curr;
			curr=curr->next;

			for(; curr!=rq->head; curr=curr->next){

				curr->goodness = ((1 + curr->exp_burst) / (1 + min_exp_burst));

				if (curr->goodness < min_goodness){
					min_goodness=curr->goodness;
					next=curr;
				}
			}
		#endif

		//find goodness
		#if SCHED==3
			double time_now = (double) sched_clock();
			unsigned long long time_n_long = sched_clock();

			//calculate max_wait_RQ
			curr=rq->head->next;
			max_waitRQ = time_n_long - curr->enterRQ;
			for(; curr!=rq->head; curr=curr->next){
				if(time_n_long - curr->enterRQ > max_waitRQ){
					max_waitRQ = time_n_long - curr->enterRQ;
				}
			}

			//calculate min goodness
			curr=rq->head->next;
			curr->goodness=((1 + curr->exp_burst) / (1 + min_exp_burst)) *
				((1 + (double)max_waitRQ)/(1 + (time_now - (double)curr->enterRQ)));

			min_goodness=curr->goodness;
			next=curr;

			curr=curr->next;
			
			for(; curr!=rq->head; curr=curr->next){

				curr->goodness=((1 + curr->exp_burst) / (1 + min_exp_burst)) *
				((1 + (double)max_waitRQ)/(1 + (time_now - (double)curr->enterRQ)));
				
				if (curr->goodness < min_goodness){
					min_goodness=curr->goodness;
					next=curr;
				}
			}
		#endif



		// printf("%p\n",next);		
		if(next!=current){
			next->enterCPU=sched_clock();
		}else if (!next) {
			context_switch(rq->head);
		}
		context_switch(next);
	}
	
}


/* sched_fork
 * Sets up schedule info for a newly forked task
 */
void sched_fork(struct task_struct *p)
{
	p->exp_burst = 0;
	p->burst = 0;
	p->goodness = 0;
	p->enterRQ = 0;
	p->enterCPU = 0;
	p->time_slice = 100;
}

/* scheduler_tick
 * Updates information and priority
 * for the task that is currently running.
 */
void scheduler_tick(struct task_struct *p)
{	

	schedule();
	
}

/* wake_up_new_task
 * Prepares information for a task
 * that is waking up for the first time
 * (being created).
 */
void wake_up_new_task(struct task_struct *p)
{	
	p->next = rq->head->next;
	p->prev = rq->head;
	p->next->prev = p;
	p->prev->next = p;
	

	rq->nr_running++;
	p->enterRQ=sched_clock();
	
}

/* activate_task
 * Activates a task that is being woken-up
 * from sleeping.
 */
void activate_task(struct task_struct *p)
{
	p->next = rq->head->next;
	p->prev = rq->head;
	p->next->prev = p;
	p->prev->next = p;
	// p->burst=0;

	rq->nr_running++;
	p->enterRQ=sched_clock();
	
}

/* deactivate_task
 * Removes a running task from the scheduler to
 * put it to sleep.
 */
void deactivate_task(struct task_struct *p)
{
	p->prev->next = p->next;
	p->next->prev = p->prev;
	p->next = p->prev = NULL; /* Make sure to set them to NULL *
							   * next is checked in cpu.c      */

	rq->nr_running--;
}
