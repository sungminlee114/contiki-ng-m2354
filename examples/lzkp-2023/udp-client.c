#include "udp-client.h"
#include "project-conf.h"
#include <string.h>

#define LOG_MODULE "App"
#define LOG_LEVEL LOG_LEVEL_INFO

static void
shell_printf(const char *str)
{
  printf("%s", str);
}

static
PT_THREAD(cmd_help(struct pt *pt, char* args))
{
  PT_BEGIN(pt);
  SHELL_OUTPUT("Available commands:\n");
  for(int i = 0; builtin_shell_commands[i].name != NULL; i++) {
    SHELL_OUTPUT("  %-10s %s\n", builtin_shell_commands[i].name, builtin_shell_commands[i].help);
  }
  PT_END(pt);
}

static
PT_THREAD(cmd_hello(struct pt *pt, char* args))
{
  PT_BEGIN(pt);
  SHELL_OUTPUT("Hello World!\n");
  PT_END(pt);
}

static
PT_THREAD(cmd_reboot(struct pt *pt, char* args))
{
  
  PT_BEGIN(pt);

  SHELL_OUTPUT("Rebooting...\n");
  watchdog_reboot();

  PT_END(pt);
}

/*---------------------------------------------------------------------------*/

struct shell_command_t builtin_shell_commands[] = {
  { "help",           cmd_help, "'> help': Shows this help" },
  { "reboot",         cmd_reboot, "'> help': Reboot the node" },
  { "hello",           cmd_hello, "'> help': Hello" },
  { NULL, NULL, NULL }
};

struct shell_command_t*
handle_shell_input(const char *cmd)
{
  static char *args;

  /* Shave off any leading spaces. */
  while(*cmd == ' ') {
    cmd++;
  }

  /* Ignore empty lines */
  if(*cmd == '\0') {
    return NULL;
  }

  args = strchr(cmd, ' ');
  if(args != NULL) {
    *args = '\0';
    args++;
  }

  for(int i = 0; builtin_shell_commands[i].name != NULL; i++) {
    if (strcmp(builtin_shell_commands[i].name, cmd) == 0) {
      return &builtin_shell_commands[i];
    }
  }

  return NULL;
}

/*---------------------------------------------------------------------------*/
PROCESS(udp_client_process, "UDP client");
AUTOSTART_PROCESSES(&udp_client_process);
/*---------------------------------------------------------------------------*/
static struct pt cmd_handler_pt;
PROCESS_THREAD(udp_client_process, ev, data)
{
	// static unsigned char buf[1024];
  static struct shell_command_t *cmd_descr = NULL;
  PROCESS_BEGIN();

  while (1) {
    SHELL_OUTPUT("> ");
    PROCESS_WAIT_EVENT_UNTIL(ev == serial_line_event_message && data != NULL);

    cmd_descr = handle_shell_input(data);

    if (cmd_descr != NULL && cmd_descr->func != NULL) {
      PROCESS_PT_SPAWN(&cmd_handler_pt, cmd_descr->func(&cmd_handler_pt, NULL));
    } else {
      SHELL_OUTPUT("Command not found. Type 'help' for a list of commands\n");
    }
  }

  PROCESS_END();
}
