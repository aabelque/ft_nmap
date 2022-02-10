/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   interactive.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fherbine <fherbine@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/02/10 13:59:01 by fherbine          #+#    #+#             */
/*   Updated: 2022/02/10 13:59:01 by fherbine         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../include/ft_nmap.h"

extern t_env e;

static int8_t _is_ip(char *s)
{
	char **tab = ft_strsplit(s, '.');

	for (size_t i = 0; tab[i]; i++) {
		if (!strisdigit(tab[i])) {
			ft_free_tab(tab);
			return false;
		}

		int64_t _token = ft_atoi(tab[i]);

		if (_token < 0 || _token > 255) {
			ft_free_tab(tab);
			return false;
		}
	}
	ft_free_tab(tab);
	return true;
}

static int8_t str_has_space(char *s)
{
	int i = 0;
    while(s[i])
	{
		if (isspace(s[i]))
			return true;
		i++;
	}
	return false;
}

static uint8_t mode_selection(void)
{
	char *selection;
	t_menu menu;
	char *_choices[3] = {"ip / hostname (manual)\0", "ips from file\0", NULL};
	char **choices = ft_copy_tab(_choices);
	uint8_t mode;

	menu.selection_idx = 0;
	menu.alignement = 'v';
	menu.title = ft_strdup("Choose target hosts mode");

	create_menu(&menu, (char **)choices);
	selection = display_menu(&menu, &on_selection_no_op);

	destroy_menu(&menu);
	ft_free_tab(choices);

	mode = (!ft_strcmp(_choices[0], selection)) ? INT_IP_HOST : INT_FILE;
	free(selection);

	return mode;
}

static char *get_input(char *prompt)
{
	char input[255];
	printf("%s", prompt);
	fgets(input, 255, stdin);
	return ft_strdup(input);
}

static char *get_manual_ip_host(void)
{
	while (true) {
		char *_ip_host = get_input("Enter a target IP / hostname: ");
		char *ip_host = ft_strtrim(_ip_host);
		free(_ip_host);

		if (str_has_space(ip_host))
			continue ;
		
		return ip_host;
	}
}

static char *get_filepath(void)
{
	while (true) {
		char *_path = get_input("Please enter the path of the IPs file: ");
		char *path = ft_strtrim(_path);
		free(_path);

		if (str_has_space(path))
			continue ;

		if (access(path, F_OK ) == -1)
			continue ;
		
		return path;
	}
}

static char *scan_selection(void)
{
	char *selection;
	t_menu menu;
	char *_choices[7] = { "SYN","NULL","FIN","XMAS","ACK","UDP", NULL };
	char **choices = ft_copy_tab(_choices);
	uint8_t mode;

	menu.selection_idx = 0;
	menu.alignement = 'h';
	menu.title = ft_strdup("Choose a scan type");

	create_menu(&menu, (char **)choices);
	selection = display_menu(&menu, &on_selection_no_op);

	destroy_menu(&menu);
	ft_free_tab(choices);

	return selection;
}

int interactive_nmap(void)
{
	uint8_t _mode;
	char *mode, *target, *scan_type, command[1024];
	START_IHM_CONTEXT();

	_mode = mode_selection();

	END_IHM_CONTEXT();
	
	if (_mode == INT_IP_HOST)
	{
		target = get_manual_ip_host();
		mode = ft_strdup((_is_ip(target)) ? "--ip" : "--hostname");
	}
	else
	{
		target = get_filepath();
		mode = ft_strdup("--file");
	}

	START_IHM_CONTEXT();
	
	scan_type = scan_selection();

	END_IHM_CONTEXT();

	int argc = 9;
	char *_argv[10] = {"./ft_nmap", mode, target, "--scan", scan_type, "--ports", "1-1024", "--speedup", "250", NULL};
	sprintf(command, "./ft_nmap %s %s --scan %s --ports 1-1024 --speedup 250", mode, target, scan_type);

	char **argv = ft_copy_tab(_argv);
	free(mode);
	free(target);
	free(scan_type);

	e.iargv = argv;

	printf("\n\nTrying to perform: %s\n", command);
	
	int8_t pret = parse_arg(argc, argv);

	return pret;
}
