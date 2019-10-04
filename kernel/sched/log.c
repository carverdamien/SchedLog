#include <linux/cpumask.h>
#include <linux/seq_file.h>
#include <linux/debugfs.h>

#include "sched.h"
#include "log.h"

#ifdef CONFIG_SCHED_LOG

static struct dentry *sched_log_dir;

#ifdef CONFIG_SCHED_LOG_TRACER
DEFINE_PER_CPU(struct sched_log_tracer, sched_log_tracer);
EXPORT_SYMBOL(sched_log_tracer);
bool sched_log_tracer_enabled;
EXPORT_SYMBOL(sched_log_tracer_enabled);

static const char* sched_log_traced_event_header_str[] = {
	"EVENT_NAME","CPU","PID","ARG0","ARG1",
};
#define NR_SCHED_LOG_TRACED_EVENT_HEADER ARRAY_SIZE(sched_log_traced_event_header_str)

static const char* sched_log_traced_event_str[] = {
	"EXEC","exec'ing thread's, before possible migration","caller","comm (high)","comm (low)",
        /* TODO: may need to add a SET_COMM event */
	"EXIT","exiting thread's","exiting thread","0","0",
	"WAKEUP","woken thread's new cpu","woken thread","0","0",
	"WAKEUP_NEW","new thread's","new thread","0","0",
	"BLOCK","blocked thread's","blocked thread","0","0",
	"BLOCK_IO","blocked thread's","blocked thread","0","0",
	"FORK","parent's","child's","parent's pid","0",
	"TICK","current's","current","need_resched","frequency",
	"CTX_SWITCH","prev's","prev","next pid","0",
	"MIGRATE","cpu of the thread commanding the migration","pid of the thread migrating from old_cpu to new_cpu","old_cpu","new_cpu",
	"RQ_SIZE","cpu of the runqueue","current","nr_running","difference",
	"IDL_BLN_FAIR_BEG", "task_cpu(current)", "current", "sd addr (high)", "sd addr (low)",
	"IDL_BLN_FAIR_END", "task_cpu(current)", "current", "sd addr (high)", "sd addr (low)",
	"PER_BLN_FAIR_BEG", "task_cpu(current)", "current", "sd addr (high)", "sd addr (low)",
	"PER_BLN_FAIR_END", "task_cpu(current)", "current", "sd addr (high)", "sd addr (low)",
	"WAIT_FUTEX","waiting thread's","waiting thread","futex uaddr","0",
	"WAKE_FUTEX","waker's","woken thread","futex uaddr","0",
	"WAKER_FUTEX","waker's","woker thread","futex uaddr","0",
};
#define sched_log_traced_event_name(evt) sched_log_traced_event_str[evt*NR_SCHED_LOG_TRACED_EVENT_HEADER+0]

bool sched_log_traced_event_enabled[NR_SCHED_LOG_TRACED_EVENTS];
EXPORT_SYMBOL(sched_log_traced_event_enabled);

/* Begin section /sys/kernel/debug/sched_log/tracer/reset */

static ssize_t sched_log_tracer_reset_write(struct file *file,
				  const char __user *user_buf,
				  size_t count, loff_t *ppos)
{
	int cpu;
	unsigned long flags;
	struct sched_log_tracer *log;
	
	for_each_possible_cpu(cpu) {
		log = per_cpu_ptr(&sched_log_tracer, cpu);
		
		spin_lock_irqsave(&log->lock, flags);
		log->consumer = log->producer;
		log->dropped = 0;
		spin_unlock_irqrestore(&log->lock, flags);
	}
	
	return count;
}

static const struct file_operations sched_log_tracer_reset_fops = {
	.open   = simple_open,
	.llseek = default_llseek,
	.write  = sched_log_tracer_reset_write,
};

/* End section /sys/kernel/debug/sched_log/tracer/reset */

/* Begin section /sys/kernel/debug/sched_log/tracer/{log,raw}/CPU */

static void *shed_log_tracer_seq_start(struct seq_file *s, loff_t *pos)
{
	unsigned long cpu = (unsigned long) s->private, flags;
	struct sched_log_tracer *log = per_cpu_ptr(&sched_log_tracer, cpu);
	int i;
	void *ret = NULL;

	spin_lock_irqsave(&log->lock, flags);

	if (*pos == 0 && log->dropped)
		seq_printf(s, "Dropped %llu events!!!!\n", log->dropped);

	i = (log->consumer + *pos) % log->size;
	if (i == log->producer)
		goto end;

	ret = (void *) &log->entry[i];

end:
	spin_unlock_irqrestore(&log->lock, flags);
	return ret;
}

static void shed_log_tracer_seq_stop(struct seq_file *s, void *v)
{
}

static void *shed_log_tracer_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	unsigned long cpu = (unsigned long) s->private, flags;
	struct sched_log_tracer *log = per_cpu_ptr(&sched_log_tracer, cpu);
	int i;
	void *ret = NULL;

	spin_lock_irqsave(&log->lock, flags);

	++*pos;
	i = (log->consumer + *pos) % log->size;
	if (i == log->producer)
		goto end;

	ret = (void *) &log->entry[i];

end:
	spin_unlock_irqrestore(&log->lock, flags);
	return ret;
}

/* End section /sys/kernel/debug/sched_log/tracer/{log,raw}/CPU */

/* Begin section /sys/kernel/debug/sched_log/tracer/log/CPU */

static int shed_log_tracer_seq_show(struct seq_file *s, void *v)
{
	struct sched_log_tracer_entry *evt = v;
	
	/* text output */
	switch (sched_log_tracer_entry_format(evt)) {
	case SCHED_LOG_NO_ARGS:
		seq_printf(s, "%llu %s %d\n",
			   evt->timestamp, sched_log_traced_event_name(evt->event),
			   evt->pid);
		break;
	case SCHED_LOG_ONE_PTR:
		seq_printf(s, "%llu %s %d 0x%p\n",
			   evt->timestamp, sched_log_traced_event_name(evt->event),
			   evt->pid, (void *)evt->addr);
		break;
	case SCHED_LOG_ONE_INT:
		seq_printf(s, "%llu %s %d %d\n",
			   evt->timestamp, sched_log_traced_event_name(evt->event),
			   evt->pid, evt->arg0);
		break;
	case SCHED_LOG_TWO_INT:
		seq_printf(s, "%llu %s %d %d %d\n",
			   evt->timestamp, sched_log_traced_event_name(evt->event),
			   evt->pid, evt->arg0, evt->arg1);
		break;
	case SCHED_LOG_8_CHAR:
		seq_printf(s, "%llu %s %d %c%c%c%c%c%c%c%c\n",
			   evt->timestamp, sched_log_traced_event_name(evt->event),
			   evt->pid,
			   ((char*)&evt->addr)[0],
			   ((char*)&evt->addr)[1],
			   ((char*)&evt->addr)[2],
			   ((char*)&evt->addr)[3],
			   ((char*)&evt->addr)[4],
			   ((char*)&evt->addr)[5],
			   ((char*)&evt->addr)[6],
			   ((char*)&evt->addr)[7]
			);
		break;
	default:
		seq_printf(s, "%llu UNKNOWN %d\n",
			   evt->timestamp, evt->pid);
	}

	return 0;
}

static const struct seq_operations shed_log_tracer_seq_ops = {
	.start = shed_log_tracer_seq_start,
	.next  = shed_log_tracer_seq_next,
	.stop  = shed_log_tracer_seq_stop,
	.show  = shed_log_tracer_seq_show
};

static int sched_log_tracer_open(struct inode *inode, struct file *file)
{
	int ret;
	unsigned long cpu;
	char *filename = file->f_path.dentry->d_iname;
	struct seq_file *sf;

	ret = seq_open(file, &shed_log_tracer_seq_ops);
	if (ret != 0)
		return ret;

	if (kstrtoul(filename, 10, &cpu) != 0)
		return -EINVAL;

	sf = (struct seq_file *) file->private_data;
	sf->private = (void *) cpu;

	return 0;
}

static const struct file_operations sched_log_tracer_fops = {
	.open    = sched_log_tracer_open,
	.llseek  = seq_lseek,
	.read    = seq_read,
	.release = seq_release,
};

/* End section /sys/kernel/debug/sched_log/tracer/log/CPU */

/* Begin section /sys/kernel/debug/sched_log/tracer/raw/CPU */

static int shed_log_tracer_seq_show_raw(struct seq_file *s, void *v)
{
	struct sched_log_tracer_entry *evt = v;

	/* binary output */
	seq_write(s, evt, sizeof(struct sched_log_tracer_entry));

	return 0;
}

static const struct seq_operations shed_log_tracer_seq_ops_raw = {
	.start = shed_log_tracer_seq_start,
	.next  = shed_log_tracer_seq_next,
	.stop  = shed_log_tracer_seq_stop,
	.show  = shed_log_tracer_seq_show_raw
};

static int sched_log_tracer_open_raw(struct inode *inode, struct file *file)
{
	int ret;
	unsigned long cpu;
	char *filename = file->f_path.dentry->d_iname;
	struct seq_file *sf;

	ret = seq_open(file, &shed_log_tracer_seq_ops_raw);
	if (ret != 0)
		return ret;

	if (kstrtoul(filename, 10, &cpu) != 0)
		return -EINVAL;

	sf = (struct seq_file *) file->private_data;
	sf->private = (void *) cpu;

	return 0;
}

static const struct file_operations sched_log_tracer_fops_raw = {
	.open    = sched_log_tracer_open_raw,
	.llseek  = seq_lseek,
	.read    = seq_read,
	.release = seq_release,
};

/* End section /sys/kernel/debug/sched_log/tracer/raw/CPU */

/* Begin section /proc/sched_log_traced_events */

static void *sched_log_traced_events_proc_start(struct seq_file *s, loff_t *pos)
{
	if (*pos >= NR_SCHED_LOG_TRACED_EVENTS)
		return NULL;
	return pos;
}

static void *sched_log_traced_events_proc_next(struct seq_file *s, void *v, loff_t *pos)
{
	*pos = *pos + 1;
	if (*pos >= NR_SCHED_LOG_TRACED_EVENTS)
		return NULL;
	return pos;
}

static void sched_log_traced_events_proc_stop(struct seq_file *s, void *v) {}

static int sched_log_traced_events_proc_show(struct seq_file *s, void *v)
{
	loff_t *pos = v;

	/* TODO: pretty print {"EVENT_NAME","CPU","PID","ARG0","ARG1"} */
	seq_printf(s, "%lld %s\n", *pos, sched_log_traced_event_name(*pos));

	return 0;
}

static const struct seq_operations sched_log_traced_events_proc_seq_ops = {
	.start = sched_log_traced_events_proc_start,
	.next  = sched_log_traced_events_proc_next,
	.stop  = sched_log_traced_events_proc_stop,
	.show  = sched_log_traced_events_proc_show
};

static int sched_log_traced_events_proc_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &sched_log_traced_events_proc_seq_ops);
}

static const struct file_operations sched_log_traced_events_fops = {
	.open = sched_log_traced_events_proc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release
};

/* End section /proc/sched_log_traced_events */

static int sched_log_tracer_init(void)
{
	int cpu, ret, i;
	char buf[10];
	struct dentry *tracer_dir, *tracer_log_dir, *events_dir, *raw_dir;
	struct sched_log_tracer *log;
	size_t buffer_size = CONFIG_SCHED_LOG_TRACER_BUFFER_SIZE << 20;

	/* Allocate per-cpu buffers */
	buffer_size -= (buffer_size % sizeof(struct sched_log_tracer_entry));
	for_each_possible_cpu(cpu) {
		log = per_cpu_ptr(&sched_log_tracer, cpu);
		log->entry = vmalloc(buffer_size);
		if (!log->entry) {
			ret = -ENOMEM;
			goto undo;
		}
		log->dropped = log->producer = log->consumer = 0;
		log->size = buffer_size / sizeof(struct sched_log_tracer_entry);
		spin_lock_init(&log->lock);
	}

	BUILD_BUG_ON(ARRAY_SIZE(sched_log_traced_event_str) != NR_SCHED_LOG_TRACED_EVENTS*NR_SCHED_LOG_TRACED_EVENT_HEADER);

	/* Create files in /sys/kernel/debug/sched_log/tracer */
	tracer_dir = debugfs_create_dir("tracer", sched_log_dir);
	debugfs_create_bool("enable", 0666, tracer_dir,
			    &sched_log_tracer_enabled);
	debugfs_create_file("reset", 0666, tracer_dir, NULL,
			    &sched_log_tracer_reset_fops);

	events_dir = debugfs_create_dir("events", tracer_dir);
	for (i = 0; i < NR_SCHED_LOG_TRACED_EVENTS; i++) {
		sched_log_traced_event_enabled[i] = false;
		debugfs_create_bool(sched_log_traced_event_name(i), 0666,
				    events_dir,
				    sched_log_traced_event_enabled + i);
	}

	tracer_log_dir = debugfs_create_dir("logs", tracer_dir);
	raw_dir = debugfs_create_dir("raw", tracer_dir);
	for_each_possible_cpu(cpu) {
		snprintf(buf, 10, "%d", cpu);

		debugfs_create_file(buf, 0444, tracer_log_dir, NULL,
				    &sched_log_tracer_fops);
		debugfs_create_file(buf, 0444, raw_dir, NULL,
				    &sched_log_tracer_fops_raw);
	}

	/* Create the /proc/sched_log_traced_events file */
	proc_create("sched_log_traced_events", 0444, NULL,
		    &sched_log_traced_events_fops);

	return 0;

undo:
	for (cpu = cpu - 1; cpu >= 0; cpu--) {
		log = per_cpu_ptr(&sched_log_tracer, cpu);
		free_pages_exact(log->entry, buffer_size);
	}

	pr_err("sched_log: tracer initialization failed\n");

	return ret;
}
#else   /* !CONFIG_SCHED_LOG_TRACER */
inline static int sched_log_tracer_init(void){ return 0; }
#endif	/* CONFIG_SCHED_LOG_TRACER */

static int __init sched_log_debugfs_init(void)
{
	sched_log_dir = debugfs_create_dir("sched_log", NULL);
	if (!sched_log_dir)
		goto exit;

	sched_log_tracer_init();

	return 0;
exit:
	return -ENOMEM;
}
late_initcall(sched_log_debugfs_init);

#endif /* CONFIG_SCHED_LOG */
