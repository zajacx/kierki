CXX = g++ -g
CXXFLAGS = -Wall -Wextra -O2 -std=c++20
LFLAGS =

.PHONY: all clean

TARGET1 = kierki-klient
TARGET2 = kierki-serwer

all: $(TARGET1) $(TARGET2)

$(TARGET1): $(TARGET1).o kierki-common.o err.o common.o
	$(CXX) $(LFLAGS) -o $@ $^

$(TARGET2): $(TARGET2).o kierki-common.o err.o common.o
	$(CXX) $(LFLAGS) -o $@ $^

err.o: err.cpp err.h
	$(CXX) $(CXXFLAGS) -c -o $@ $<

common.o: common.cpp err.h common.h
	$(CXX) $(CXXFLAGS) -c -o $@ $<

kierki-common.o: kierki-common.cpp kierki-common.h
	$(CXX) $(CXXFLAGS) -c -o $@ $<

kierki-klient.o: kierki-klient.cpp kierki-common.h err.h common.h
	$(CXX) $(CXXFLAGS) -c -o $@ $<

kierki-serwer.o: kierki-serwer.cpp kierki-common.h err.h common.h
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -f $(TARGET1) $(TARGET2) *.o *~
