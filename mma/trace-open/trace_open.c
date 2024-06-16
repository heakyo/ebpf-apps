#include <uapi/linux/openat2.h>
#include <linux/sched.h>

struct data_t {
	u32 pid;
	u64 ts;
	char comm[TASK_COMM_LEN];
	char fname[NAME_MAX];
};

BPF_PERF_OUTPUT(myevents);

int hello_world(struct pt_regs *ctx, int dfd, const char __user * filename,
		struct open_how *how)
{
	struct data_t data = {};
	int ret = 0;

	data.pid = bpf_get_current_pid_tgid();
	data.ts = bpf_ktime_get_ns();

	ret = bpf_get_current_comm(&data.comm, sizeof(data.comm));
	if (!ret)
		bpf_probe_read(&data.fname, sizeof(data.fname), (void *)filename);

	myevents.perf_submit(ctx, &data, sizeof(data));
	return 0;
}
