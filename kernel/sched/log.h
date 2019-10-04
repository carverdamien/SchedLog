#ifndef _SCHED_LOG_H_
#define _SCHED_LOG_H_

#include <linux/sched/clock.h>

#ifdef CONFIG_SCHED_LOG_TRACER

struct sched_log_tracer_entry {
	u64 timestamp;
	pid_t pid;
	int event;
	union {
		struct {
			s32 arg0, arg1;
		};
		u64 addr;
	};
};

struct sched_log_tracer {
	struct sched_log_tracer_entry *entry;
	loff_t consumer, producer;
	u64 dropped;
	spinlock_t lock;
	size_t size;
};

enum sched_log_traced_event {
	SCHED_LOG_EXEC,
	SCHED_LOG_EXIT,
	SCHED_LOG_WAKEUP,
	SCHED_LOG_WAKEUP_NEW,
	SCHED_LOG_BLOCK,
	SCHED_LOG_BLOCK_IO,
	SCHED_LOG_FORK,
	SCHED_LOG_TICK,
	SCHED_LOG_CTX_SWITCH,
	SCHED_LOG_MIGRATE,
	SCHED_LOG_RQ_SIZE,
	/* TODO
	SCHED_LOG_IDL_BLN_FAIR_BEG,
	SCHED_LOG_IDL_BLN_FAIR_END,
	SCHED_LOG_PER_BLN_FAIR_BEG,
	SCHED_LOG_PER_BLN_FAIR_END,
	*/
	SCHED_LOG_WAIT_FUTEX,
	SCHED_LOG_WAKE_FUTEX,
	SCHED_LOG_WAKER_FUTEX,
	NR_SCHED_LOG_TRACED_EVENTS, /* keep last */
};

enum sched_log_tracer_entry_format {
	SCHED_LOG_UNKNOWN,
	SCHED_LOG_NO_ARGS,
	SCHED_LOG_ONE_PTR,
	SCHED_LOG_ONE_INT,
	SCHED_LOG_TWO_INT,
	SCHED_LOG_8_CHAR,
};

static inline enum sched_log_tracer_entry_format sched_log_tracer_entry_format(struct sched_log_tracer_entry *e) {
	enum sched_log_tracer_entry_format format;
	switch(e->event) {
	case SCHED_LOG_EXEC:
		format = SCHED_LOG_8_CHAR;
		break;
	case SCHED_LOG_EXIT:
	case SCHED_LOG_WAKEUP:
	case SCHED_LOG_WAKEUP_NEW:
	case SCHED_LOG_BLOCK:
	case SCHED_LOG_BLOCK_IO:
		format = SCHED_LOG_NO_ARGS;
		break;
		/* TODO
	case SCHED_LOG_IDL_BLN_FAIR_BEG:
	case SCHED_LOG_IDL_BLN_FAIR_END:
	case SCHED_LOG_PER_BLN_FAIR_BEG:
	case SCHED_LOG_PER_BLN_FAIR_END:
		*/
	case SCHED_LOG_WAIT_FUTEX:
	case SCHED_LOG_WAKE_FUTEX:
	case SCHED_LOG_WAKER_FUTEX:
		format = SCHED_LOG_ONE_PTR;
		break;
	case SCHED_LOG_FORK:
	case SCHED_LOG_TICK:
	case SCHED_LOG_CTX_SWITCH:
		format = SCHED_LOG_ONE_INT;
		break;
	case SCHED_LOG_MIGRATE:
	case SCHED_LOG_RQ_SIZE:
		format = SCHED_LOG_TWO_INT;
		break;
	default:
		 format = SCHED_LOG_UNKNOWN;
	}
	return format;
}

DECLARE_PER_CPU(struct sched_log_tracer, sched_log_tracer);
extern bool sched_log_tracer_enabled;
extern bool sched_log_traced_event_enabled[NR_SCHED_LOG_TRACED_EVENTS];

static inline void __sched_log_trace(enum sched_log_traced_event evt,
				     int cpu,
				     struct task_struct *p,
				     int arg0, int arg1)
{
	struct sched_log_tracer *log = per_cpu_ptr(&sched_log_tracer, cpu);
	struct sched_log_tracer_entry *v;
	unsigned long flags;

	if (!sched_log_traced_event_enabled[evt])
		return;

	spin_lock_irqsave(&log->lock, flags);

	v = &log->entry[log->producer];
	v->timestamp = local_clock();
	v->pid = p->pid;
	v->event = evt;
	v->arg0 = arg0;
	v->arg1 = arg1;

	log->producer++;
	if (unlikely(log->producer >= log->size))
		log->producer = 0;

	if (unlikely(log->producer == log->consumer)) {
		log->consumer++;
		if (unlikely(log->consumer >= log->size))
			log->consumer = 0;
		log->dropped++;
	}

	spin_unlock_irqrestore(&log->lock, flags);
}

#define sched_log_trace(evt, cpu, task, arg0, arg1)			\
	do {								\
		if (unlikely(sched_log_tracer_enabled))	{		\
			__sched_log_trace(evt,				\
					  cpu,				\
					  task,				\
					  arg0,				\
					  arg1);			\
		}							\
	} while (0)

#else /* !CONFIG_SCHED_LOG_TRACER */
#define sched_log_trace(evt, cpu, task, arg0, arg1)
#endif /* CONFIG_SCHED_LOG_TRACER */

#endif /* _SCHED_LOG_H_ */
