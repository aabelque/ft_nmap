# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: aabelque <aabelque@student.42.fr>          +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2021/12/25 11:44:30 by aabelque          #+#    #+#              #
#    Updated: 2022/01/28 17:02:47 by zizou            ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

H_DIR = include/
C_DIR = srcs/
O_DIR = objs/

NAME = ft_nmap

CC = gcc
DEBUG = -g
CFLAG = -Wall -Wextra -Werror -Wpadded
THREAD_FLAG = -lpthread
PCAP_FLAG = -lpcap

SRC = ft_nmap.c
SRC += errors.c
SRC += utils.c
SRC += libc.c
SRC += parser.c
SRC += parser_helper.c
SRC += setup.c
SRC += resolve_host.c
SRC += scan.c
SRC += send_packet.c
SRC += get_response.c
SRC += decode.c
SRC += result.c
SRC += service.c
SRC += print.c
SRC += filter.c
SRC += thread.c

all: $(NAME)

welcome:
	@figlet ft_nmap | lolcat 2>/dev/null
	@echo "\n"

OBJS = $(addprefix $(O_DIR),$(SRC:.c=.o))
	
$(NAME): welcome $(OBJS) $(H_DIR)
	@echo "✅ Source files: $(shell echo $(SRC) | wc -w) / $(shell echo $(SRC) | wc -w)\033[0m --> \033[1;32m[Done]\033[0m\n"
	@$(CC) $(DEBUG) $(CFLAGS) -o $(NAME) $(OBJS) $(PCAP_FLAG) $(THREAD_FLAG)
	@tput dl; tput el1; tput cub 100; echo "\033[33mBuilt:\033[0m \033[32;1;4m$(notdir $@)\033[0m"

$(OBJS): $(O_DIR)%.o: $(C_DIR)%.c
	@mkdir -p $(O_DIR) 2> /dev/null || echo "" > /dev/null
	@$(CC) $(DEBUG) $(CFLAGS) -o $@ -c $< -fPIC -I$(H_DIR) $(PCAP_FLAG) $(THREAD_FLAG)

clean:
	@rm -rf $(O_DIR) 2> /dev/null || echo "" > /dev/null

fclean: clean
	@rm -rf $(NAME) 2> /dev/null || echo "" > /dev/null
	@echo "\033[33mRemoved: \033[32;1;4m$(NAME)\033[0m"

re: fclean all

.PHONY: all clean fclean re
