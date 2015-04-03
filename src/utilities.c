/*
 * Copyright (c) 2013-2015, Dalian Futures Information Technology Co., Ltd.
 *
 * Xiaoye Meng <mengxiaoye at dce dot com dot cn>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <ifaddrs.h>
#include <netdb.h>
#include <string.h>
#include <time.h>
#include "utilities.h"

/* FIXME */
int cmpstr(const void *x, const void *y) {
	return strcmp((char *)x, (char *)y);
}

/* FIXME: Peter J. Weinberger hash */
unsigned hashpjw(const void *key) {
	const char *ptr = key;
	unsigned int val = 0, tmp;

	while (*ptr != '\0') {
		val = (val << 4) + *ptr++;
		if ((tmp = val & (unsigned int)0xf0000000) != 0)
			val = (val ^ (tmp >> 24)) ^ tmp;
	}
	return val;
}

/* FIXME */
unsigned hashdjb2(const void *key) {
	const char *ptr = key;
	int c;
	unsigned hash = 5381;

	while ((c = *ptr++))
		/* hash * 33 + c */
		hash = ((hash << 5) + hash) + c;
	return hash;
}

/* FIXME */
unsigned hashmurmur2(const void *key) {
	const uint32_t m = 0x5bd1e995;
	const uint32_t r = 24;
	size_t len = strlen(key);
	const unsigned char *data = (const unsigned char *)key;
	uint32_t hash = 5381 ^ len;

	while (len >= 4) {
		uint32_t k = *(uint32_t *)data;

		k *= m;
		k ^= k >> r;
		k *= m;
		hash *= m;
		hash ^= k;
		data += 4;
		len  -= 4;
	}
	switch (len) {
	case 3: hash ^= data[2] << 16;
	case 2: hash ^= data[1] << 8;
	case 1: hash ^= data[0]; hash *= m;
	};
	hash ^= hash >> 13;
	hash *= m;
	hash ^= hash >> 15;
	return (unsigned)hash;
}

/* FIXME */
unsigned intlen(int32_t i) {
	if (i >= 1000000000) return 10;
	if (i >= 100000000 ) return 9;
	if (i >= 10000000  ) return 8;
	if (i >= 1000000   ) return 7;
	if (i >= 100000    ) return 6;
	if (i >= 10000     ) return 5;
	if (i >= 1000      ) return 4;
	if (i >= 100       ) return 3;
	if (i >= 10        ) return 2;
	if (i >= 1         ) return 1;
	return 0;
}

/* FIXME */
dstr getipv4(void) {
	struct ifaddrs *ifaddr, *ifa;
	char host[NI_MAXHOST];
	dstr res = NULL;

	if (getifaddrs(&ifaddr) == -1)
		return NULL;
	for (ifa = ifaddr; ifa; ifa = ifa->ifa_next)
		if (ifa->ifa_addr->sa_family == AF_INET && !strcmp(ifa->ifa_name, "eth0"))
			break;
	if (ifa && getnameinfo(ifa->ifa_addr, sizeof (struct sockaddr_in), host, NI_MAXHOST,
		NULL, 0, NI_NUMERICHOST) == 0)
		res = dstr_new(host);
	freeifaddrs(ifaddr);
	return res;
}

/* FIXME */
int diffday(int startday, int endday) {
	time_t t = time(NULL);
	struct tm ls, le;
	int res, rem;

	localtime_r(&t, &ls);
	localtime_r(&t, &le);
	ls.tm_mday = startday % 100;
	ls.tm_mon  = startday / 100 % 100 - 1;
	ls.tm_year = startday / 10000 - 1900;
	le.tm_mday = endday   % 100;
	le.tm_mon  = endday   / 100 % 100 - 1;
	le.tm_year = endday   / 10000 - 1900;
	res = difftime(mktime(&le), mktime(&ls)) / (24 * 60 * 60);
	return res / 7 * 5 + ((rem = res % 7) == 6 ? 5 : rem);
}

/* FIXME */
int diffnow(int endday) {
	time_t t = time(NULL);
	struct tm le;
	int res, rem;

	localtime_r(&t, &le);
	le.tm_mday = endday % 100;
	le.tm_mon  = endday / 100 % 100 - 1;
	le.tm_year = endday / 10000 - 1900;
	res = difftime(mktime(&le), t) / (24 * 60 * 60);
	return res / 7 * 5 + ((rem = res % 7) == 6 ? 5 : rem);
}

