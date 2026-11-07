#include <helios/unix/spawn.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
extern char **environ;
extern int hu_spawn_native(pid_t *, const char *, const struct hu_spawn_actions *,
                           const struct hu_spawn_attr *, char *const[], char *const[]);

void hu_spawn_actions_init(struct hu_spawn_actions *actions)
{
    if (actions) {
        memset(actions, 0, sizeof(*actions));
    }
}

void hu_spawn_actions_destroy(struct hu_spawn_actions *actions)
{
    unsigned i;
    if (!actions) {
        return;
    }
    for (i = 0; i < actions->count; i++) {
        free(actions->items[i].path);
    }
    memset(actions, 0, sizeof(*actions));
}

static int action(struct hu_spawn_actions *actions, int kind, int source, int fd,
                  const char *path, int flags)
{
    struct hu_spawn_action *entry;
    if (!actions || actions->count >= HU_SPAWN_ACTIONS_MAX || fd < 0 || fd >= 4096 ||
        source < 0 || source >= 4096) {
        return EINVAL;
    }
    entry = &actions->items[actions->count];
    memset(entry, 0, sizeof(*entry));
    if (path) {
        entry->path = malloc(strlen(path) + 1);
        if (!entry->path) {
            return ENOMEM;
        }
        strcpy(entry->path, path);
    }
    entry->kind = kind;
    entry->source = source;
    entry->fd = fd;
    entry->flags = flags;
    actions->count++;
    return 0;
}

int hu_spawn_addclose(struct hu_spawn_actions *actions, int fd)
{
    return action(actions, 0, 0, fd, NULL, 0);
}

int hu_spawn_adddup2(struct hu_spawn_actions *actions, int source, int destination)
{
    return action(actions, 1, source, destination, NULL, 0);
}

int hu_spawn_addopen(struct hu_spawn_actions *actions, int fd, const char *path,
                     int flags)
{
    if (!path) {
        return EINVAL;
    }
    return action(actions, 2, 0, fd, path, flags);
}

int hu_spawn(pid_t *pid, const char *name, const struct hu_spawn_actions *actions,
             const struct hu_spawn_attr *attr, char *const argv[], char *const env[])
{
    if (!pid || !name || !*name || !argv || !argv[0]) {
        return EINVAL;
    }
    return hu_spawn_native(pid, name, actions, attr, argv, env ? env : environ);
}

int hu_spawnp(pid_t *pid, const char *name, const struct hu_spawn_actions *actions,
              const struct hu_spawn_attr *attr, char *const argv[], char *const env[])
{
    const char *path, *end;
    char candidate[1024];
    size_t length;
    int error, access_denied = 0;
    if (!name || !*name) {
        return EINVAL;
    }
    if (strchr(name, '/')) {
        return hu_spawn(pid, name, actions, attr, argv, env);
    }
    path = getenv("PATH");
    if (!path) {
        path = "/helios/local/bin:/helios/bin:/helios/bin/x11";
    }
    do {
        end = strchr(path, ':');
        if (!end) {
            end = path + strlen(path);
        }
        length = end - path;
        if (length + strlen(name) + 2 >= sizeof(candidate)) {
            return ENAMETOOLONG;
        }
        memcpy(candidate, path, length);
        if (length) {
            candidate[length++] = '/';
        }
        strcpy(candidate + length, name);
        error = hu_spawn(pid, candidate, actions, attr, argv, env);
        if (!error) {
            return 0;
        }
        if (error == EACCES) {
            access_denied = 1;
        } else if (error != ENOENT && error != ENOTDIR) {
            return error;
        }
        path = *end ? end + 1 : NULL;
    } while (path);
    return access_denied ? EACCES : ENOENT;
}
