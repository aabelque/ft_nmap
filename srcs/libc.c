/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   libc.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: aabelque <aabelque@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/12/26 18:57:59 by aabelque          #+#    #+#             */
/*   Updated: 2022/02/03 16:42:27 by aabelque         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_nmap.h"

void *ft_memcpy(void *dest, const void *src, size_t n)
{
        void *d = dest;

        while (n) {
                *((char *)dest++) = *((char *)src++);
                n--;
        }
        return d;
}

void *ft_memalloc(size_t size)
{
        void *buff;

        if ((buff = malloc(size)) == NULL)
                return NULL;
        ft_memset(buff, '\0', size);
        return buff;
}

inline void *ft_memset(void *s, int c, size_t n)
{
        while (n) {
                *(char *)s = (unsigned char)c;
                s++;
                n--;
        }
        return s;
}

inline size_t ft_strlen(const char *s)
{
        const char *b = s;

        if (!s)
                return 0;
        while (*s)
                s++;
        return s - b;
}

static inline int ft_isdigit(char c)
{
        if (c >= '0' && c <= '9')
                return 1;
        return 0;
}

inline int8_t strisdigit(const char *s)
{
        if (!s || !ft_strlen(s))
                return 0;
        while (*s != '\0' && *s != '.')
                if (!ft_isdigit(*s++))
                        return 0;
        return 1;
}

char *ft_strcpy(char *dest, const char *src)
{
        char *tmp = dest;

        while ((*dest++ = *src++));
        return tmp;
}

char *ft_strncpy(char *dest, const char *src, size_t n)
{
        char *tmp = dest;

        while (n) {
                if ((*dest = *src))
                        src++;
                dest++;
                n--;
        }
        return tmp;
}

char	*ft_strdup(const char *s)
{
        char *ptr;

        ptr = ft_memalloc(sizeof(*ptr) * (ft_strlen(s) + 1));
        if (!ptr)
                return NULL;
        ft_strcpy(ptr, s);
        return ptr;
}

int8_t ft_strcmp(const char *s1, const char *s2)
{
        for ( ; *s1 == *s2; s1++, s2++)
                if (*s1 == '\0')
                        return 0;
        return *(unsigned char *)s1 - *(unsigned char *)s2;
}

static inline int8_t ft_isspace(char c)
{
        if (c == ' ' || c == '\t' || c == '\f' || c == '\r' \
                        || c == '\n'|| c == '\v')
                return 1;
        return 0;
}

int64_t ft_atoi(const char *str)
{
        int8_t i, sign;
        int64_t nbr;

        i = 0;
        sign = 1;
        nbr = 0;
        if (!str[i])
                return 0;
        while (ft_isspace(str[i]))
                i++;
        if (str[i] == '-' || str[i] == '+') {
                if (str[++i] == '-')
                        sign = -1;
        }
        while (str[i] < '0' || str[i] > '9')
                i++;
        while (str[i] >= '0' && str[i] <= '9')
                nbr = (nbr * 10) + (str[i++] - '0');
        return nbr * sign;
}

static size_t ft_count_word(char const *s, char c)
{
        int i = 0;
        size_t count = 0;
        
        while (s[i] != '\0') {
                if (s[i] != c && (s[i + 1] == c || s[i + 1] == '\0'))
                        count++;
                s++;
        }
        return count;
}

static size_t ft_size_word(char const *s, char c)
{
        int i = 0;
        size_t siz = 0;

        while (s[i] != c && s[i] != '\0') {
                i++;
                siz++;
        }
        return siz;
}

char **ft_strsplit(char const *s, char c)
{
        char **tab;
        size_t i;
        size_t count;
        size_t size;

        if (!s)
                return NULL;
        count = ft_count_word(s, c);
        if (!(tab = malloc(sizeof(char *) * (count + 1))))
                return NULL;
        i = -1;
        while (++i < count && *s) {
                while (*s == c)
                        s++;
                size = ft_size_word(s, c);
                if (!(tab[i] = malloc(sizeof(char) + (size + 1))))
                        return NULL;
                ft_strncpy(tab[i], s, size);
                tab[i][size] = '\0';
                s += size;
        }
        tab[i] = NULL;
        return tab;
}

static size_t ft_size_number(int n)
{
        int count = 0;

        if (n < 0)
                count++;
        if (!n)
                return 1;
        while (n) {
                n /= 10;
                count++;
        }
        return count;
}

inline static int ft_abs(int val)
{
        return val < 0 ? -val : val;
}

char *ft_itoa(int n)
{
        char *str;
        size_t len;

        len = ft_size_number(n);
        str = malloc(sizeof(*str) * len + 1);
        if (!str)
                return NULL;
        if (n < 0)
                str[0] = '-';
        str[len] = '\0';
        while (1) {
                str[len - 1] = ft_abs(n % 10) + '0';
                n /= 10;
                if (!n)
                        break;
                len--;
        }
        return str;
}

char		**ft_add_tab_elem(char **tab, char *elem)
{
	char	**new;
	int		i;

	if (!tab) {
		if (!(tab = (char **)malloc(sizeof(char *) * (1))))
			exit(EXIT_FAILURE);
		tab[0] = 0;
		return (tab);
	}


	if (!(new = (char **)malloc(sizeof(char *) * (ft_tab_len(tab) + 2))))
		exit(EXIT_FAILURE);
	i = 0;
	while (tab[i])
	{
		new[i] = ft_strdup(tab[i]);
		i++;
	}
	ft_free_tab(tab);
	new[i] = ft_strdup(elem);
	new[i + 1] = 0;
	return (new);
}

void	ft_free_tab(char **tab)
{
	int	i;

	i = 0;
	while (tab[i])
	{
		free(tab[i]);
		i++;
	}
	free(tab);
}

int		ft_tab_len(char **tab)
{
	int	i;

	i = 0;
	while (tab[i])
		i++;
	return (i);
}

char		**ft_copy_tab(char **tab)
{
	int		i;
	char	**new;

	if (!(new = (char **)malloc(sizeof(char *) * (ft_tab_len(tab) + 1))))
		exit(EXIT_FAILURE);
	i = 0;
	while (tab[i] && tab[i] != NULL)
	{
		new[i] = ft_strdup(tab[i]);
		i++;
	}
	new[i] = 0;
	return (new);
}

char	*ft_strnew(size_t size)
{
	char *ret;

	if ((ret = (char *)ft_memalloc(size + 1)) == NULL)
		return (NULL);
	return (ret);
}

static char	*null_str(char *to_free)
{
	char	*ret;

	if (to_free)
		free(to_free);
	ret = ft_strdup("NULL");
	return (ret);
}

char		*ft_strjoin(char *s1, const char *s2)
{
	char	*joined;
	size_t	i;
	size_t	i2;

	i = 0;
	i2 = 0;
	if (!(s1) || !(s2))
		return (null_str(s1));
	if (!(joined = (char *)ft_memalloc(sizeof(char) * (ft_strlen(s1) + \
						ft_strlen(s2) + 2))))
		exit(EXIT_FAILURE);
	while (s1[i])
	{
		joined[i] = s1[i];
		i++;
	}
	while (i2 < ft_strlen(s2))
	{
		joined[i] = s2[i2];
		i++;
		i2++;
	}
	joined[i] = '\0';
	free(s1);
	return (joined);
}

char	*ft_strsub(const char *s, unsigned int start, size_t len)
{
	char			*cpy;
	unsigned int	i;

	i = 0;
	if (!(s))
		return (NULL);
	if ((cpy = (char *)malloc(sizeof(char) * (len + 1))) == NULL)
		return (NULL);
	while ((size_t)i < len)
	{
		cpy[i] = s[start];
		start++;
		i++;
	}
	cpy[i] = '\0';
	return (cpy);
}


char	*ft_strtrim(const char *s)
{
	unsigned int	strt;
	size_t			len;
	size_t			end;

	strt = 0;
	if (!s)
		return (NULL);
	len = ft_strlen(s);
	end = len - 1;
	while (s[strt] == ' ' || s[strt] == '\n' || s[strt] == '\t')
		strt++;
	if (strt != len)
	{
		while (s[end] == ' ' || s[end] == '\n' || s[end] == '\t')
			end--;
	}
	else
		return (ft_strnew(0));
	return (ft_strsub(s, strt, end - (size_t)strt + 1));
}  