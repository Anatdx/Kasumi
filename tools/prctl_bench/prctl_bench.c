/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE

#include <errno.h>
#include <grp.h>
#include <inttypes.h>
#include <linux/prctl.h>
#include <linux/types.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define KSM_REMOVED_PRCTL_GET_FD 0x48021UL

enum bench_case {
	BENCH_GETPID,
	BENCH_PRCTL_VALID,
	BENCH_PRCTL_NEIGHBOR,
	BENCH_PRCTL_LEGACY_KASUMI,
	BENCH_CASE_COUNT,
};

struct options {
	size_t samples;
	unsigned int batch;
	unsigned int warmup;
	int cpu;
	uid_t drop_uid;
	const char *raw_path;
	bool allow_root;
};

struct stats {
	double min;
	double median;
	double p95;
	double p99;
	double max;
	double mean;
	double mad;
};

static volatile long bench_sink;

#if defined(__aarch64__)
static inline long raw_syscall5(long nr, long a0, long a1, long a2,
				long a3, long a4)
{
	register long x0 __asm__("x0") = a0;
	register long x1 __asm__("x1") = a1;
	register long x2 __asm__("x2") = a2;
	register long x3 __asm__("x3") = a3;
	register long x4 __asm__("x4") = a4;
	register long x8 __asm__("x8") = nr;

	__asm__ volatile("svc 0"
			 : "+r"(x0)
			 : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x8)
			 : "memory", "cc");
	return x0;
}
#elif defined(__x86_64__)
static inline long raw_syscall5(long nr, long a0, long a1, long a2,
				long a3, long a4)
{
	register long rax __asm__("rax") = nr;
	register long r10 __asm__("r10") = a3;
	register long r8 __asm__("r8") = a4;

	__asm__ volatile("syscall"
			 : "+a"(rax)
			 : "D"(a0), "S"(a1), "d"(a2), "r"(r10), "r"(r8)
			 : "rcx", "r11", "memory", "cc");
	return rax;
}
#else
static inline long raw_syscall5(long nr, long a0, long a1, long a2,
				long a3, long a4)
{
	return syscall(nr, a0, a1, a2, a3, a4);
}
#endif

static inline long raw_prctl(unsigned long option, unsigned long arg2)
{
	return raw_syscall5(SYS_prctl, (long)option, (long)arg2, 0, 0, 0);
}

static inline long raw_getpid(void)
{
	return raw_syscall5(SYS_getpid, 0, 0, 0, 0, 0);
}

static uint64_t now_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) != 0) {
		perror("clock_gettime");
		exit(1);
	}
	return (uint64_t)ts.tv_sec * UINT64_C(1000000000) +
	       (uint64_t)ts.tv_nsec;
}

static long run_calls(enum bench_case which, unsigned int count)
{
	long result = 0;
	int fd = -1;
	unsigned int i;

	switch (which) {
	case BENCH_GETPID:
		for (i = 0; i < count; i++)
			result ^= raw_getpid();
		break;
	case BENCH_PRCTL_VALID:
		for (i = 0; i < count; i++)
			result ^= raw_prctl(PR_GET_DUMPABLE, 0);
		break;
	case BENCH_PRCTL_NEIGHBOR:
		for (i = 0; i < count; i++)
			result ^= raw_prctl(KSM_REMOVED_PRCTL_GET_FD ^ 1UL,
					    (unsigned long)(uintptr_t)&fd);
		break;
	case BENCH_PRCTL_LEGACY_KASUMI:
		for (i = 0; i < count; i++)
			result ^= raw_prctl(KSM_REMOVED_PRCTL_GET_FD,
					    (unsigned long)(uintptr_t)&fd);
		break;
	default:
		break;
	}
	bench_sink ^= result ^ fd;
	return result;
}

static int compare_u64(const void *left, const void *right)
{
	const uint64_t a = *(const uint64_t *)left;
	const uint64_t b = *(const uint64_t *)right;

	return (a > b) - (a < b);
}

static int compare_i64(const void *left, const void *right)
{
	const int64_t a = *(const int64_t *)left;
	const int64_t b = *(const int64_t *)right;

	return (a > b) - (a < b);
}

static size_t percentile_index(size_t count, unsigned int percentile)
{
	return ((count - 1) * percentile + 99) / 100;
}

static struct stats summarize_u64(uint64_t *values, size_t count,
				  unsigned int batch)
{
	struct stats out = {};
	uint64_t *deviations;
	long double sum = 0;
	uint64_t median;
	size_t i;

	qsort(values, count, sizeof(*values), compare_u64);
	median = values[count / 2];
	deviations = malloc(count * sizeof(*deviations));
	if (!deviations) {
		perror("malloc");
		exit(1);
	}
	for (i = 0; i < count; i++) {
		sum += values[i];
		deviations[i] = values[i] > median ? values[i] - median :
						       median - values[i];
	}
	qsort(deviations, count, sizeof(*deviations), compare_u64);

	out.min = (double)values[0] / batch;
	out.median = (double)median / batch;
	out.p95 = (double)values[percentile_index(count, 95)] / batch;
	out.p99 = (double)values[percentile_index(count, 99)] / batch;
	out.max = (double)values[count - 1] / batch;
	out.mean = (double)(sum / count) / batch;
	out.mad = (double)deviations[count / 2] / batch;
	free(deviations);
	return out;
}

static struct stats summarize_i64(int64_t *values, size_t count,
				  unsigned int batch)
{
	struct stats out = {};
	int64_t *deviations;
	long double sum = 0;
	int64_t median;
	size_t i;

	qsort(values, count, sizeof(*values), compare_i64);
	median = values[count / 2];
	deviations = malloc(count * sizeof(*deviations));
	if (!deviations) {
		perror("malloc");
		exit(1);
	}
	for (i = 0; i < count; i++) {
		sum += values[i];
		deviations[i] = values[i] > median ? values[i] - median :
						       median - values[i];
	}
	qsort(deviations, count, sizeof(*deviations), compare_i64);

	out.min = (double)values[0] / batch;
	out.median = (double)median / batch;
	out.p95 = (double)values[percentile_index(count, 95)] / batch;
	out.p99 = (double)values[percentile_index(count, 99)] / batch;
	out.max = (double)values[count - 1] / batch;
	out.mean = (double)(sum / count) / batch;
	out.mad = (double)deviations[count / 2] / batch;
	free(deviations);
	return out;
}

static unsigned long long parse_count(const char *text, const char *name)
{
	char *end;
	unsigned long long value;

	errno = 0;
	value = strtoull(text, &end, 10);
	if (errno || !text[0] || *end || value == 0) {
		fprintf(stderr, "invalid %s: %s\n", name, text);
		exit(2);
	}
	return value;
}

static uid_t parse_uid(const char *text)
{
	unsigned long long value = parse_count(text, "uid");

	if ((uid_t)value != value || value == 0) {
		fprintf(stderr, "invalid nonzero uid: %s\n", text);
		exit(2);
	}
	return (uid_t)value;
}

static unsigned int parse_uint(const char *text, const char *name)
{
	unsigned long long value = parse_count(text, name);

	if (value > UINT32_MAX) {
		fprintf(stderr, "%s is too large: %s\n", name, text);
		exit(2);
	}
	return (unsigned int)value;
}

static int parse_cpu(const char *text)
{
	char *end;
	long value;

	errno = 0;
	value = strtol(text, &end, 10);
	if (errno || !text[0] || *end || value < 0 || value >= CPU_SETSIZE) {
		fprintf(stderr, "invalid cpu: %s\n", text);
		exit(2);
	}
	return (int)value;
}

static void usage(FILE *stream, const char *program)
{
	fprintf(stream,
		"usage: %s [-n samples] [-b batch] [-w warmup] [-c cpu] "
		"[-r raw.csv] [--drop-uid uid] [--allow-root]\n",
		program);
}

static struct options parse_options(int argc, char **argv)
{
	struct options options = {
		.samples = 20000,
		.batch = 64,
		.warmup = 20000,
		.cpu = -1,
	};
	int i;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--allow-root") == 0) {
			options.allow_root = true;
		} else if (strcmp(argv[i], "-h") == 0 ||
			   strcmp(argv[i], "--help") == 0) {
			usage(stdout, argv[0]);
			exit(0);
		} else if (i + 1 < argc && strcmp(argv[i], "-n") == 0) {
			options.samples = (size_t)parse_count(argv[++i], "samples");
		} else if (i + 1 < argc && strcmp(argv[i], "-b") == 0) {
			options.batch = parse_uint(argv[++i], "batch");
		} else if (i + 1 < argc && strcmp(argv[i], "-w") == 0) {
			options.warmup = parse_uint(argv[++i], "warmup");
		} else if (i + 1 < argc && strcmp(argv[i], "-c") == 0) {
			options.cpu = parse_cpu(argv[++i]);
		} else if (i + 1 < argc && strcmp(argv[i], "-r") == 0) {
			options.raw_path = argv[++i];
		} else if (i + 1 < argc && strcmp(argv[i], "--drop-uid") == 0) {
			options.drop_uid = parse_uid(argv[++i]);
		} else {
			fprintf(stderr, "unknown argument: %s\n", argv[i]);
			usage(stderr, argv[0]);
			exit(2);
		}
	}
	if (options.samples > SIZE_MAX / BENCH_CASE_COUNT /
				      sizeof(uint64_t)) {
		fprintf(stderr, "sample count is too large\n");
		exit(2);
	}
	return options;
}

static void pin_to_cpu(int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	if (sched_setaffinity(0, sizeof(set), &set) != 0) {
		fprintf(stderr, "sched_setaffinity(cpu=%d): %s\n", cpu,
			strerror(errno));
		exit(2);
	}
}

static void drop_privileges(uid_t uid)
{
	if (geteuid() != 0) {
		fprintf(stderr, "--drop-uid requires an initial effective UID of 0\n");
		exit(2);
	}
	if (setgroups(0, NULL) != 0 || setgid((gid_t)uid) != 0 ||
	    setuid(uid) != 0) {
		fprintf(stderr, "drop privileges to uid=%lu: %s\n",
			(unsigned long)uid, strerror(errno));
		exit(2);
	}
	if (getuid() != uid || geteuid() != uid || getgid() != (gid_t)uid ||
	    getegid() != (gid_t)uid) {
		fprintf(stderr, "privilege drop verification failed\n");
		exit(2);
	}
}

static void print_stats(const char *name, long result,
			const struct stats *stats)
{
	printf("%-24s %8ld %9.2f %9.2f %9.2f %9.2f %9.2f %9.2f %9.2f\n",
	       name, result, stats->median, stats->p95, stats->p99, stats->mad,
	       stats->mean, stats->min, stats->max);
}

static void write_raw_csv(const char *path, uint64_t **samples,
			  size_t count, unsigned int batch)
{
	FILE *stream;
	size_t i;

	if (!path)
		return;
	stream = fopen(path, "w");
	if (!stream) {
		fprintf(stderr, "open %s: %s\n", path, strerror(errno));
		exit(1);
	}
	fprintf(stream,
		"sample,getpid_ns,prctl_valid_ns,prctl_neighbor_ns,"
		"prctl_kasumi_ns,magic_delta_ns\n");
	for (i = 0; i < count; i++) {
		const int64_t delta = (int64_t)samples[BENCH_PRCTL_LEGACY_KASUMI][i] -
				      (int64_t)samples[BENCH_PRCTL_NEIGHBOR][i];

		fprintf(stream, "%zu,%.3f,%.3f,%.3f,%.3f,%.3f\n", i,
			(double)samples[BENCH_GETPID][i] / batch,
			(double)samples[BENCH_PRCTL_VALID][i] / batch,
			(double)samples[BENCH_PRCTL_NEIGHBOR][i] / batch,
			(double)samples[BENCH_PRCTL_LEGACY_KASUMI][i] / batch,
			(double)delta / batch);
	}
	if (fclose(stream) != 0) {
		fprintf(stderr, "close %s: %s\n", path, strerror(errno));
		exit(1);
	}
}

int main(int argc, char **argv)
{
	static const char *const names[BENCH_CASE_COUNT] = {
		"getpid",
		"prctl_get_dumpable",
		"prctl_unknown_neighbor",
		"prctl_legacy_kasumi_option",
	};
	struct options options = parse_options(argc, argv);
	uint64_t *samples[BENCH_CASE_COUNT] = {};
	uint64_t *sorted;
	int64_t *deltas;
	struct stats result_stats[BENCH_CASE_COUNT];
	struct stats delta_stats;
	long results[BENCH_CASE_COUNT];
	uint64_t timer_min = UINT64_MAX;
	size_t i;
	int which;

	if (options.drop_uid)
		drop_privileges(options.drop_uid);
	if (geteuid() == 0 && !options.allow_root) {
		fprintf(stderr,
			"refusing to benchmark as root; run from adb shell without su\n");
		return 2;
	}
	if (options.cpu >= 0)
		pin_to_cpu(options.cpu);

	for (which = 0; which < BENCH_CASE_COUNT; which++) {
		samples[which] = calloc(options.samples, sizeof(uint64_t));
		if (!samples[which]) {
			perror("calloc");
			return 1;
		}
		results[which] = run_calls((enum bench_case)which, 1);
		run_calls((enum bench_case)which, options.warmup);
	}

	for (i = 0; i < 10000; i++) {
		uint64_t start = now_ns();
		uint64_t elapsed = now_ns() - start;

		if (elapsed < timer_min)
			timer_min = elapsed;
	}

	for (i = 0; i < options.samples; i++) {
		int offset;

		for (offset = 0; offset < BENCH_CASE_COUNT; offset++) {
			uint64_t start, elapsed;

			which = (int)((i + (size_t)offset) % BENCH_CASE_COUNT);
			start = now_ns();
			run_calls((enum bench_case)which, options.batch);
			elapsed = now_ns() - start;
			samples[which][i] = elapsed;
		}
	}

	write_raw_csv(options.raw_path, samples, options.samples, options.batch);

	sorted = malloc(options.samples * sizeof(*sorted));
	deltas = malloc(options.samples * sizeof(*deltas));
	if (!sorted || !deltas) {
		perror("malloc");
		return 1;
	}
	for (which = 0; which < BENCH_CASE_COUNT; which++) {
		memcpy(sorted, samples[which], options.samples * sizeof(*sorted));
		result_stats[which] = summarize_u64(sorted, options.samples,
						 options.batch);
	}
	for (i = 0; i < options.samples; i++)
		deltas[i] = (int64_t)samples[BENCH_PRCTL_LEGACY_KASUMI][i] -
			    (int64_t)samples[BENCH_PRCTL_NEIGHBOR][i];
	delta_stats = summarize_i64(deltas, options.samples, options.batch);

	printf("prctl_bench uid=%ld euid=%ld cpu=%d samples=%zu batch=%u "
	       "warmup=%u timer_min=%" PRIu64 "ns\n",
	       (long)getuid(), (long)geteuid(), sched_getcpu(), options.samples,
	       options.batch, options.warmup, timer_min);
	printf("%-24s %8s %9s %9s %9s %9s %9s %9s %9s\n",
	       "case", "raw_ret", "median", "p95", "p99", "MAD", "mean",
	       "min", "max");
	for (which = 0; which < BENCH_CASE_COUNT; which++)
		print_stats(names[which], results[which], &result_stats[which]);
	print_stats("magic_delta", results[BENCH_PRCTL_LEGACY_KASUMI] -
		    results[BENCH_PRCTL_NEIGHBOR], &delta_stats);
	printf("units: ns/syscall; magic_delta = kasumi option - unknown neighbor\n");
	if (results[BENCH_PRCTL_NEIGHBOR] != -EINVAL ||
	    results[BENCH_PRCTL_LEGACY_KASUMI] != -EINVAL)
		printf("warning: unknown prctl return values differ from expected -EINVAL\n");
	if (options.raw_path)
		printf("raw samples: %s\n", options.raw_path);

	free(sorted);
	free(deltas);
	for (which = 0; which < BENCH_CASE_COUNT; which++)
		free(samples[which]);
	(void)bench_sink;
	return 0;
}
