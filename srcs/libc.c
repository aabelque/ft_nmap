/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   libc.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: aabelque <aabelque@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/12/26 18:57:59 by aabelque          #+#    #+#             */
/*   Updated: 2022/01/04 13:40:06 by aabelque         ###   ########.fr       */
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
        ft_memset(buff, 0, size);
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

inline int ft_strlen(const char *s)
{
        const char *b = s;

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

inline int strisdigit(const char *s)
{
        if (!s || !ft_strlen(s))
                return 0;
        while (*s != '\0')
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

int ft_strcmp(const char *s1, const char *s2)
{
        for ( ; *s1 == *s2; s1++, s2++)
                if (*s1 == '\0')
                        return 0;
        return *(unsigned char *)s1 - *(unsigned char *)s2;
}

static inline int ft_isspace(char c)
{
        if (c == ' ' || c == '\t' || c == '\f' || c == '\r' \
                        || c == '\n'|| c == '\v')
                return 1;
        return 0;
}

int ft_atoi(const char *str)
{
        int i, sign;
        long nbr;

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

static int ft_count_word(char const *s, char c)
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

static int ft_size_word(char const *s, char c)
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
                if (!(tab[i] = malloc((size + 1) * sizeof(char))))
                        return NULL;
                ft_strncpy(tab[i], s, size);
                tab[i][size] = '\0';
                s += size;
        }
        tab[i] = NULL;
        return tab;
}