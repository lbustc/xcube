#
# Copyright (c) 2013-2015, Dalian Futures Information Technology Co., Ltd.
#
# Guodong Zhang <zhangguodong at dce dot com dot cn>
# Xiaoye Meng   <mengxiaoye at dce dot com dot cn>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

C++      = g++
CC       = gcc
CPPFLAGS = -I../include/
CFLAGS   = -fPIC -Wall -march=corei7 -g -O2
LDFLAGS1 = -ltcmalloc
LDFLAGS2 = stl.so
RPATH    = /var/lib/rmc
TARGET1  = stl.so
TARGET2  = app_ema.so
OBJ1     = stl.o
OBJ2     = app_ema.o

all : $(TARGET1) $(TARGET2)

$(TARGET1) : $(OBJ1)
	$(C++) -shared $^ $(LDFLAGS1) -Wl,-soname -Wl,$@ -o $@

$(TARGET2) : $(OBJ2)
	$(CC)  -shared $^ $(LDFLAGS2) -Wl,-rpath,$(RPATH) -Wl,-soname -Wl,$@ -o $@

$(OBJ1) : stl.cpp
	$(C++) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(OBJ2) : app_ema.c
	$(CC)  $(CPPFLAGS) $(CFLAGS) -c $< -o $@

.PHONY: all clean

clean:
	rm -f $(TARGET1) $(TARGET2) $(OBJ1) $(OBJ2)

