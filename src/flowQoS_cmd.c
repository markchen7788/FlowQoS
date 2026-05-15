/**
 * @file flowQoS_cmd.c
 * @author Mark Chen (markchen77888@gmail.com)
 * @brief cmdline module built by dpdk cmdline
 * @version 0.1
 * @date 2024-01-11
 *
 * @copyright Copyright (c) 2024
 *
 */
#include "flowQoS_cmd.h"
#include "rte_cycles.h"

#define MAX_CMD 32                              ///< maximum cmds the cmd moudle con keep
static int cmd_len = 0;                         ///< amount of cmds in cmd module
cmdline_parse_ctx_t main_ctx[MAX_CMD] = {NULL}; ///< cmd array storing defined cmds
static struct cmdline *cl = NULL;

/**
 * @brief default cmd for quit from cmdline
 *
 */
struct cmd_quit_result
{
    cmdline_fixed_string_t quit;
};
/**
 * @brief quit cmd callback
 *
 * @param parsed_result
 * @param cl
 * @param data
 */
static void cmd_quit_parsed(__rte_unused void *parsed_result,
                            struct cmdline *cl,
                            __rte_unused void *data)
{
    cmdline_printf(cl, "Quit from the app......\n");
    cmdline_quit(cl);
}
cmdline_parse_token_string_t cmd_quit_quit =
    TOKEN_STRING_INITIALIZER(struct cmd_quit_result, quit, "quit");

/**
 * @brief object of quit cmd
 *
 */
cmdline_parse_inst_t cmd_quit = {
    .f = cmd_quit_parsed, /* function to call */
    .data = NULL,         /* 2nd arg of func */
    .help_str = "quit",
    .tokens = {
        /* token list, NULL terminated */
        (void *)&cmd_quit_quit,
        NULL,
    },
};

int flowQoS_registCmd(cmdline_parse_inst_t *ctx)
{
    main_ctx[cmd_len] = ctx;
    return cmd_len++;
}

struct cmdline *flowQoS_getCmd()
{
    return cl;
}

void flowQoS_cmd()
{
    flowQoS_registCmd(&cmd_quit);
    rte_delay_ms(10);
    cl = cmdline_stdin_new(main_ctx, "FlowQoS-ENV@localhost:~$ ");
    if (cl == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create cmdline instance\n");
    cmdline_interact(cl);
    cmdline_stdin_exit(cl);
}