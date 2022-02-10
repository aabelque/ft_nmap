/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ihm.c                                              :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fherbine <fherbine@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/02/10 13:49:47 by fherbine          #+#    #+#             */
/*   Updated: 2022/02/10 13:49:47 by fherbine         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../include/ft_nmap.h"

static char getch() {
        char buf = 0;
        struct termios old = {0};
        if (tcgetattr(0, &old) < 0)
                perror("tcsetattr()");
        old.c_lflag &= ~ICANON;
        old.c_lflag &= ~ECHO;
        old.c_cc[VMIN] = 1;
        old.c_cc[VTIME] = 0;
        if (tcsetattr(0, TCSANOW, &old) < 0)
                perror("tcsetattr ICANON");
        if (read(0, &buf, 1) < 0)
                perror ("read()");
        old.c_lflag |= ICANON;
        old.c_lflag |= ECHO;
        if (tcsetattr(0, TCSADRAIN, &old) < 0)
                perror ("tcsetattr ~ICANON");
        return (buf);
}

static uint64_t get_command(void) {
	char c = getch();
	if (c == '\033') { // if the first value is esc
		getch();
		switch(getch()) {
			case 'A':
				return (CMD_ARROW_UP);
				break;
			case 'B':
				return (CMD_ARROW_DW);
				break;
			case 'C':
				return (CMD_ARROW_RG);
				break;
			case 'D':
				return (CMD_ARROW_LF);
				break;
		}
	} else if (c == '\n')
		return (CMD_ENTER);
	return (CMD_NOOP);
}

static void set_menu_idx(t_menu *menu, size_t idx)
{
	size_t tablen = ft_tab_len(menu->menu_content);
	
	if (menu->selection_idx + idx < 0)
		menu->selection_idx = tablen - 1;
	else if (menu->selection_idx + idx >= tablen)
		menu->selection_idx = 0;
	else
		menu->selection_idx += idx;
}

void on_selection_no_op(char *dummy)
{
	(void)dummy;
}

void print_box(unsigned int w, unsigned int h, unsigned int x, unsigned int y)
{
	char *line = NULL;

	for (unsigned int i = 0; i < h; i++) {
		if (i == 0)
		{
			line = ft_strnew(w);
			line = ft_memset(line, '_', w);
			line[0] = ' ';
			line[w-1] = ' ';
			line[w] = 0;
		}
		else if (i == h-1)
		{
			line = ft_strnew(w);
			line = ft_memset(line, '_', w);
			line[0] = '\\';
			line[w-1] = '/';
			line[w] = 0;
		}
		else
		{
			line = ft_strnew(w);
			line = ft_memset(line, ' ', w);
			if (i == 1) {
				line[0] = '/';
				line[w-1] = '\\';
			} else {
				line[0] = '|';
				line[w-1] = '|';
			}
			line[w] = 0;
		}
		printf("\e[%d;%dH%s", y+i, x, line);
		free(line);
	}
}

char *display_menu(t_menu *menu, void (*on_selection)(char *))
{
	size_t i = 0;
	char *buffer = ft_strdup("");
	printf("\e[2J\e[H%s\e[H", menu->title);
	printf(
"\e[1;35m"
"  __ _                                   \n"
" / _| |_     _ __  _ __ ___   __ _ _ __  \n"
"| |_| __|   | '_ \\| '_ ` _ \\ / _` | '_ \\ \n"
"|  _| |_    | | | | | | | | | (_| | |_) |\n"
"|_|  \\__|___|_| |_|_| |_| |_|\\__,_| .__/ \n"
"       |_____|                    |_|    \n"
"\n\e[3;32mInteractive mode\e[0m\n%s\n\n", menu->title);

	if (menu->selection_idx >= 0)
		on_selection(menu->menu_content[menu->selection_idx]);
	
	printf("\e[11;0H");

	while (menu->menu_content[i] != NULL)
	{
		buffer = ft_strjoin(buffer, "➤ ");

		if (i == menu->selection_idx)
			buffer = ft_strjoin(buffer, "\e[7m");

		buffer = ft_strjoin(buffer, menu->menu_content[i]);

		if (i == menu->selection_idx)
			buffer = ft_strjoin(buffer, "\e[0m");

		buffer = ft_strjoin(buffer, (menu->alignement == 'v') ? "\n" : "\t");
		i++;
	}

	printf("%s", buffer);
	fflush(stdout);
	free(buffer);

	while (true) {
		uint64_t cmd = get_command();

		if (cmd == ((menu->alignement == 'v') ? CMD_ARROW_UP : CMD_ARROW_LF))
			set_menu_idx(menu, -1);
		else if (cmd == ((menu->alignement == 'v') ? CMD_ARROW_DW : CMD_ARROW_RG))
			set_menu_idx(menu, +1);
		else if (cmd == CMD_ENTER)
			break ;
		return(display_menu(menu, on_selection));
	}

	return (ft_strdup(menu->menu_content[menu->selection_idx]));
}

void create_menu(t_menu *menu, char **tab)
{
	menu->menu_content =  ft_copy_tab(tab);
}

void destroy_menu(t_menu *menu)
{
	free(menu->title);
	ft_free_tab(menu->menu_content);
}

void display_loading_bar(int x, int y, uint8_t percent, char *title)
{
	uint8_t progress = (uint8_t)(30.0 * (double)percent / 100.0), i = 1;
	char *progress_bar = ft_strnew(33);
	ft_memset(progress_bar, ' ', 32);
	progress_bar[0] = '[';
	progress_bar[32] = ']';
	while (i <= progress+1) {
		progress_bar[i] = '=';
		i++;
	}
	printf("\e[%d;%dH%s %s %3d %%\n", y, x, title, progress_bar, percent);
	free(progress_bar);
}