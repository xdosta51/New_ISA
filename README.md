Filtrující DNS Resolver

Autor: xdosta51

Popis programu:
DNS Resolver, který přijímá dotazy typu A a filtruje je podle souboru s blokovanými doménami. Pokud se doména či její poddoména na seznamu blokovaných nenachází
je dotaz odeslán na specifikovaný DNS Server, pokud je jiný dotaž než A, odešle se odpověď zpět s RCODE: NOTIMP, pokud je doména blokována odešle se odpověď zpět
s RCODE: REFUSED.

Program je napsaný v jazyce c++.
Pokud je program spouštěn na portu 53, je potřeba jej spustit pomocí příkazu sudo
Přeložení lze provést příkazem make
Projekt lze spustit pomocí příkazu ./dns -s adresa nebo doménové jméno DNS Serveru [-p port, na kterém aplikace naslouchá (výchozí 53)] -f filter_file seznam blokovaných domén.
Je zde volitelny argument -v vypisuje chování uvnitř programu.
Program lze spustit bez argumentů a vypíše nápovědu.

Odevzdané soubory:
dns.cpp
Makefile
README
manual.pdf
test.sh