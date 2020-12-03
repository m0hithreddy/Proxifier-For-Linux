/* Proxifier main method.

Copyright (C) 2020  Mohith Reddy

Proxifier is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Proxifier is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>. */

#include "proxifier.h"
#include "proxy.h"
#include "proxy_http.h"
#include "proxy_structures.h"
#include "proxy_configuration.h"
#include <signal.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main(int argc, char** argv)
{

	if (getuid() != 0 && geteuid() != 0) {
		exit(0);
	}

	/* Block SIGPIPE, SIGRTMIN, SIGCHLD, SIGTERM */

	sigset_t sigmask;

	sigemptyset(&sigmask);
	sigaddset(&sigmask, SIGPIPE);	// get EPIPE instead
	sigaddset(&sigmask, SIGRTMIN);	// use as sync signal
	sigaddset(&sigmask, SIGCHLD);	// use as a notifier for child termination
	sigaddset(&sigmask, SIGTERM);	// systemctl signaling for quit
	sigaddset(&sigmask, SIGINT);	// just in case of user interrupt

	if (pthread_sigmask(SIG_BLOCK, &sigmask, NULL) != 0)
		exit(1);

	int exit_status = 0;

	/* Read the config_file and get proxy_handler{} */

	struct proxy_bag* handlers_bag = create_proxy_bag();

	if (get_proxy_handlers(PROXY_DEFAULT_CONFIG_FILE, handlers_bag) != PROXY_ERROR_NONE || \
			handlers_bag->n_pockets <= 0) {
		goto proxifier_quit;
	}

	/* Register the proxy_handlers */

	struct proxy_pocket* tmp_pocket = NULL;

	for (struct proxy_pocket* px_pocket = handlers_bag->start; px_pocket != NULL; ) {

		struct proxy_handler* px_handler = (struct proxy_handler*) px_pocket->data;

		if (px_handler->protocol == PROXY_PROTOCOL_HTTP) {
			if (pthread_create(&px_handler->tid, NULL, http_proxy_init, px_handler) != 0)
				goto delete_next;
			else
				goto normal_next;
		}
		else
			goto delete_next;

		normal_next:
		px_pocket = px_pocket->next;
		continue;

		delete_next:
		tmp_pocket = px_pocket->next;
		delete_proxy_pocket(handlers_bag, &px_pocket);
		px_pocket = tmp_pocket;
	}

	if (handlers_bag->n_pockets <= 0)
		goto proxifier_quit;

	/* Make a signal mask on which main should be listening */

	sigset_t listenmask;

	sigemptyset(&listenmask);
	sigaddset(&listenmask, SIGRTMIN);
	sigaddset(&listenmask, SIGTERM);
	sigaddset(&listenmask, SIGINT);

	/* Cleanup handlers or wait for termination */

	int signo;

	for ( ; ; ) {
		if (sigwait(&listenmask, &signo) < 0) {
			exit_status = 1;
			goto proxifier_quit;
		}
		else if (signo == SIGINT || signo == SIGTERM) {
			exit_status = 0;
			goto proxifier_quit;
		}
	}

	proxifier_quit:

	for (struct proxy_pocket* px_pocket = handlers_bag->start; \
	px_pocket != NULL; px_pocket = px_pocket->next) {
		struct proxy_handler* px_handler = (struct proxy_handler*) px_pocket->data;

		px_handler->quit = 1;
		pthread_kill(px_handler->tid, SIGRTMIN);
	}

	for (struct proxy_pocket* px_pocket = handlers_bag->start; \
	px_pocket != NULL; px_pocket = px_pocket->next) {
		struct proxy_handler* px_handler = (struct proxy_handler*) px_pocket->data;

		pthread_join(px_handler->tid, NULL);
		free_proxy_handler((struct proxy_handler**) &px_pocket->data);
	}

	free_proxy_bag(&handlers_bag);

	exit(exit_status);
}
