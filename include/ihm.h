/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ihm.h                                              :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fherbine <fherbine@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/02/10 13:48:59 by fherbine          #+#    #+#             */
/*   Updated: 2022/02/10 13:48:59 by fherbine         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef IHM_H
# define IHM_H

# include <stdio.h>
# include <unistd.h>
# include <termios.h>
# include <stdint.h>

# define CMD_NOOP		0x0
# define CMD_ENTER		0x1
# define CMD_ARROW_UP	0x10
# define CMD_ARROW_DW	0x11
# define CMD_ARROW_LF	0x12
# define CMD_ARROW_RG	0x13
# define START_IHM_CONTEXT() printf("\e[J\e[H\e[?25l")
# define END_IHM_CONTEXT() printf("\e[?25h")

/* https://gist.github.com/fnky/458719343aabd01cfb17a3a4f7296797 */

typedef struct  s_menu {
	char		**menu_content;
	size_t		selection_idx;
	char		alignement; /* v or h */
	char		*title;
}				t_menu;

void 	on_selection_no_op(char *dummy);
char	*display_menu(t_menu *menu, void (*on_selection)(char *));
void 	create_menu(t_menu *menu, char **tab);
void 	destroy_menu(t_menu *menu);
void 	print_box(unsigned int w, unsigned int h, unsigned int x, unsigned int y);
void 	display_loading_bar(int x, int y, uint8_t percent, char *title);

#endif
