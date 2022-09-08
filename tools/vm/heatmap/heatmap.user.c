#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include "heatmap.skel.h"

#define MAP_SHIFT (12 + 9)

static bool terminate = false;

struct args {
	int memcg_id;
};

void handle_sigint(int sig)
{
	terminate = true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
													 va_list args)
{
	return vfprintf(stderr, format, args);
}

int run_aging(int aging_fd, int memcg_id)
{
	struct args ctx = {
		.memcg_id = memcg_id,
	};
	LIBBPF_OPTS(bpf_test_run_opts, tattr, .ctx_in = &ctx,
									.ctx_size_in = sizeof(ctx), );
	return bpf_prog_test_run_opts(aging_fd, &tattr);
}

int attach_progs(pid_t pid, struct heatmap_bpf **heatmap_obj, int *aging_fd,
								 int *heatmap_fd)
{
	int err;
	int fd;
	struct heatmap_bpf *obj;

	obj = heatmap_bpf__open();
	if (obj == NULL) {
		perror("Error when opening heatmap bpf object");
		return -1;
	}
	obj->bss->target_pid = pid;

	err = heatmap_bpf__load(obj);
	if (err) {
		perror("Error loading heatmap bpf object");
		goto cleanup;
	}

	fd = bpf_program__fd(obj->progs.memcg_run_aging);

	err = heatmap_bpf__attach(obj);
	if (err) {
		perror("Error attaching heatmap bpf object");
		goto cleanup;
	}

	*aging_fd = fd;
	*heatmap_fd = bpf_map__fd(obj->maps.heatmap);
	*heatmap_obj = obj;
	return 0;

cleanup:
	heatmap_bpf__destroy(obj);
	return err;
}

int bpf_map_delete_and_get_next_key(int fd, const void *key, void *next_key)
{
	int err = bpf_map_get_next_key(fd, key, next_key);
	bpf_map_delete_elem(fd, key);
	return err;
}

struct region_stat {
	__u16 accesses;
	__s8 mem_type; /* NON_ANON, ANON */
	__s8 node_id;
};

void dump_map(int fd)
{
	__u64 prev_key, key;
	struct region_stat value;
	int err;
	while (bpf_map_delete_and_get_next_key(fd, &prev_key, &key) == 0) {
		err = bpf_map_lookup_elem(fd, &key, &value);
		if (err < 0) {
			/* impossible if we don't have racing deletions */
			exit(-1);
		}
		printf("%llu %u %d %d\n", key << MAP_SHIFT, value.accesses,
					 value.mem_type, value.node_id);
		prev_key = key;
	}
}

void detach_progs(struct heatmap_bpf *heatmap_obj)
{
	heatmap_bpf__detach(heatmap_obj);
	heatmap_bpf__destroy(heatmap_obj);
}

int main(void)
{
	struct heatmap_bpf *heatmap_obj = NULL;
	int aging_fd = -1;
	int heatmap_fd = -1;
	int memcg_id = -1;
	int err;

	signal(SIGINT, handle_sigint);
	setvbuf(stdout, NULL, _IONBF, BUFSIZ);
	libbpf_set_print(libbpf_print_fn);

	while (!terminate) {
		char *buffer = NULL;
		if (scanf("%ms", &buffer) == 1) {
			if (strcmp(buffer, "exit") == 0) {
				printf("No hard feelings.\n");
				exit(0);

			} else if (heatmap_obj == NULL &&
								 strcmp(buffer, "attach") == 0) {
				pid_t pid_;
				int memcg_id_;
				if (scanf("%d %d", &pid_, &memcg_id_) == 2) {
					err = attach_progs(pid_, &heatmap_obj,
														 &aging_fd,
														 &heatmap_fd);
					if (err) {
						printf("error: aging %d\n",
									 err);
						goto next;
					}
					memcg_id = memcg_id_;
					printf("success: attach\n");

				} else {
					printf("error: invalid arguments\n");
				}

			} else if (heatmap_obj != NULL) {
				if (strcmp(buffer, "map") == 0) {
					dump_map(heatmap_fd);
					printf("success: map\n");

				} else if (strcmp(buffer, "age") == 0) {
					err = run_aging(aging_fd, memcg_id);
					if (err) {
						printf("error: age %d\n", err);
					} else {
						printf("success: age\n");
					}

				} else if (strcmp(buffer, "detach") == 0) {
					detach_progs(heatmap_obj);
					heatmap_obj = NULL;
					heatmap_fd = -1;
					aging_fd = -1;
					memcg_id = -1;
					printf("success: detach\n");
				}

			} else {
				printf("error: invalid command\n");
			}

	 next:
			free(buffer);
		} else {
			printf("error: invalid command\n");
		}
	}
}
