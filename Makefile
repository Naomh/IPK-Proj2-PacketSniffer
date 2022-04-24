# IPK projekt 2
# Tomáš Švondr

FILE = sniffer.cpp
OUTPUT = ipk-sniffer

all:
	g++ -o $(OUTPUT) $(FILE) -lpcap

clean:
	rm -f $(OUTPUT)
