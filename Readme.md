# IPK - Projekt 2
Autor: Tomáš Švondr
## Varianta ZETA: Sniffer paketů

Cílem vybrané varianty projektu ZETA byl navrhnout a implementovat síťový analyzátor, který bude schopný na určitém síťovém rozhraním zachytávat a filtrovat pakety podle protokolu, portu a rozhraní. Packety podporují zachytávání z protokolu TCP, UDP. Jako vybraný jazyk pro vypracování byl zvolen C++, zdrojový kód je uložený v souboru sniffer.cpp.

### Způsob zkompilování pomocí Makefile
make all - spustí makefile a zkompiluje zdrojový kód, výstupem je nový spustitelný soubor s názvem sniffer
make clean - „vyčistí“ současný adresář od souborů vzniklých spouštěním makefile

### Spuštění
./ipk-sniffer [-i rozhraní | --interface rozhraní] {-p ­­port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}

#### Příklady spuštění

$ sudo ./ipk-sniffer -i wlan0 -p 443
$ sudo ./ipk-sniffer -i  wlan0 -t -n 30   
$ sudo ./ipk-sniffer -i   



