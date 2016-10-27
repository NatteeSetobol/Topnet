# Project: 

CPP  = gcc
CC   = gcc
WINDRES = 
RES  = 
OBJ  =   main.o  $(RES)
LINKOBJ  = main.o  $(RES)
LIBS = -lpcap -lncurses -lpthread  
INCS =  
CXXINCS = -w
BIN  = topnet
CXXFLAGS = $(CXXINCS)  
CFLAGS = $(INCS)  
RM = rm -f

.PHONY: all all-before all-after clean clean-custom

all: all-before topnet all-after


clean: clean-custom
	${RM} $(OBJ) $(BIN)

$(BIN): $(OBJ)
	$(CPP) $(LINKOBJ) $(INCS)  -o "topnet"   $(LIBS)

main.o: main.c
	$(CPP) -c main.c -o main.o   $(CXXFLAGS)


