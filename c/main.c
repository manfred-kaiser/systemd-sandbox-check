/* Entry point: dispatches between orchestrator mode (default) and the two
 * internal, never-user-facing self-reexec modes. See ssc.h for why this
 * one binary plays both roles. */
#include <string.h>

#include "ssc.h"

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "--ssc-probe-internal") == 0) {
        return run_probe();
    }
    if (argc >= 2 && strcmp(argv[1], "--ssc-noop") == 0) {
        /* Used only by the NoExecPaths=/ExecPaths= probe (see probe.c) to
         * test whether *this binary* can be exec'd from a non-allowlisted
         * path, without recursing into a full nested probe run. */
        return 0;
    }
    return run_cli(argc, argv);
}
