UNAME = ARM1
HNAME = $(USER)

ifeq ($(UNAME), ARM)
CXX = /home/$(HNAME)/toolchain-bai/bin/arm-linux-androideabi-g++
CFLAGS=-fPIC -std=c++11 
INCLUDES += -I/home/moslab/Qt/5.8/android_armv7/include -I/home/$(HNAME)/Desktop/pydoccli/cppcli/obj/include/libzip
LIBS=-L/home/moslab/Qt/5.8/android_armv7/lib -L/home/moslab/Desktop/pydoccli/cppcli/obj/lib
LDFLAGS = -lQt5Core -lzip -lz -Wl,-rpath,/home/moslab/Qt/5.8/android_armv7/lib
else
ifeq ($(HNAME), pengzhan)
CXX = g++
INCLUDES += -I/usr/local/Trolltech/Qt-4.7.4/include/ 
LIBS = -L/usr/local/Trolltech/Qt-4.7.4/lib/
LDFLAGS	+= -lQtCore -lzip -lz
CFLAGS=-fPIC -std=c++11
endif
ifeq ($(HNAME), moslab)
INCLUDES += -I/home/moslab/Qt/5.8/gcc_64/include 
LIBS=-L/home/moslab/Qt/5.8/gcc_64/lib
CFLAGS=-fPIC -std=c++11 
LDFLAGS	+= -lQt5Core -lzip -lz -Wl,-rpath,/home/moslab/Qt/5.8/gcc_64/lib
endif
endif


all: main

main: main.cpp api.cpp cmp.cpp fm.cpp
	$(CXX) -o main $(CFLAGS) main.cpp api.h api.cpp cmp.cpp cmp.h diff_match_patch.h diff_match_patch.cpp fm.h fm.cpp $(INCLUDES) $(LIBS) $(LDFLAGS)

cmp: cmp.cpp diff_match_patch.cpp
	$(CXX) -o cmp $(CFLAGS)  diff_match_patch.h cmp.cpp diff_match_patch.cpp $(INCLUDES) $(LIBS) $(LDFLAGS)

clean: data_clean
	rm main cmp

data_clean:
	rm -rf backup diff_gen diff_tmp
