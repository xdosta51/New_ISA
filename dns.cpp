#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>
#include <fstream>
#include <bits/stdc++.h> 
#include <signal.h>

#define BUFFER	(1024)   

// glob. promenna pro verbose
int v = 0;

std::unordered_set <std::string> blacklist; // hash set pro seznam domen (rychle vyhledavani)

struct addrinfo *res = 0; // struktura pro getaddrinfo
/**
 * @brief osetreni signalu.
 *
 * @param signum kod signalu.
 * @return void.
 */
void catch_terminating(int sigcode) { // osetreni signalu ctrl+c a nasledne uvolneni pametu
    if (sigcode == 2) {
        if (v)
            printf("konec programu uvolneni pameti\n");
        freeaddrinfo(res); // uvolneni struktury addrinfo
        exit(0); 
    }
    else 
        exit(1);
}

void print_help() {
    std::cout << "program se spousti jako ./dns -s server nebo ip addr -f filter_file [-p cislo_portu]" << "\n";
    std::cout << "cislo_portu je cislo portu, na kterem ma dany resolver bezet" << "\n";
    std::cout << "filter_file je soubor se seznamem blokovanych domen # v souboru se bere jako komentar" << "\n";
    std::cout << "argument -s ip adresa nebo domenove jmeno DNS server napr. 8.8.8.8 nebo dns.google" << "\n";
    std::cout << "KONEC NAPOVEDY _______________________________" << "\n";
    exit(0);
}

/**
 * @brief funkce pro chybove ukonceni v pripade spatnych argumentu.
 * parametr arg podle ktereho se rozhodne jakou hlasku vypsat
 * @param arg kod chyby.
 * @return void.
 */
void arg_alert(int arg) {
    if (arg == 0) {
        printf("Nezadali jste argument\n");
    }
    exit(1);
}
/**
 * @brief Funkce pro hledani domeny z dns paketu v queries na blacklistu
 * argument je domena z dns paketu
 * @param domenacmp domena ke zpracovani.
 * @return filter_domain true nebo false pokud je na blacklistu.
 */
bool filter_domain(std::string domenacmp) {
  
    unsigned long int position = 0; //pozice na ktere je tecka
    std::vector<std::string> token; // token (label)
    while ((position = domenacmp.find(".")) != std::string::npos) { //hleda dokud neni konec
        token.push_back(domenacmp.substr(0, position)); // label se pushne do vektoru
        domenacmp.erase(0, position + 1); // label se smaze z puvodni promenne
    }
    token.push_back(domenacmp); // posledni label se taky pushne
    
    int token_iter = token.size()-1; // promenna pro prochazeni
    std::string final_token; // vysledny token
    while (token_iter >= 0) { // prochazeni domeny od zadu a slepovani pomoci tecky
        
        if (final_token.compare(""))
            final_token = token[token_iter] + "." + final_token; // tecka se dava pokud uz je nejaky label
        else 
            final_token = token[token_iter] + final_token;
        token_iter--;
        
        if (blacklist.find(final_token) == blacklist.end()) { //hledani v blacklistu pokud je na konci nenasel jinak nasel
        }
        else{
            return false;
        }
    }
    return true; // pokud nenasel vraci true
}

/**
 * @brief funkce pro odeslani paketu na dns server
 * arg buffer, buffer, ktery se ma odeslat na server
 * arg msg_size, delka odesilaneho bufferu
 * pointer je ukazal pres ktery si vratim delku prijate zpravy
 * tato funkce vraci pole znaku s prijmutou zpravou
 * @param buffer buffer k odeslani na dns serveru.
 * @param msg_size delka zpravy k odeslani
 * @param *pointer ukazatel k ulozeni delky prijate zpravy
 * @return send_request buffer ktery prisel z dns serveru.
 */

char* send_request(char buffer[BUFFER], int msg_size, int *client_msg_size) {
    int client_sock, client_i; // osetreni chyb soketu a sendto
    struct sockaddr_in from; // struktura od koho prijde odpoved
    socklen_t len; // velikost struktury

    if ((client_sock = socket(res->ai_family , SOCK_DGRAM , 0)) == -1) { //vytvoreni socketu na urcitem family bud ipv6 nebo ipv4
        std::cerr << "vytvareni socketu selhalo" << "\n";
        exit(1);
    }
    
    client_i = sendto(client_sock,buffer,msg_size,0,res->ai_addr, res->ai_addrlen); //odeslani socketu na dns server
    if (client_i == -1) {
        std::cerr << "posilani packetu selhalo" << "\n";
        exit(1);
    }                             
    else if (client_i != msg_size) {
        std::cerr << "buffer se neposlal cely" << "\n";
        exit(1);
    }
    len = sizeof(from); // nastaveni promenne len na size struktury

       
    if (getsockname(client_sock,(struct sockaddr *) &from, &len) == -1) {
        std::cerr << "selhalo getsockname()" << "\n";
        exit(1);
    }
      
    if ((client_i = recvfrom(client_sock,buffer, BUFFER,0,(struct sockaddr *) &from, &len)) == -1)  {   //prijeti paketu z dns serveru
        std::cerr << "selhalo recvfrom()" << "\n";
        exit(1);
    }

    *client_msg_size = client_i;

    close(client_sock);

    return buffer;
}

/**
 * @brief funkce pro ziskani citelne formy domeny z dns paketu
 * @param buffer buffer ke zpracovani
 * @param *dotaz_type ukazatel na typ dotazu
 * @return std::string citelna forma domeny z queries.
 */

std::string qnametohost(char buffer[BUFFER], int *dotaz_type) {
/*          
algoritmus pro vytahnuti domeny z paketu 
domena vypada napriklad takto 6seznam2cz
je si treba pamatovat kolikrat nahrat novy znak a kde zacina dalsi pocitadlo
*/
    std::string domenatocmp;
    int segmentlen = buffer[12]; // delka prvniho labelu
    int printsegment = 1; // promenna pro while
    int bufferpointer = 13; // ukazatel do bufferu zacina na prvnim znaku prvniho labelu
    while (printsegment <= segmentlen) { // dokud se nedoslo nakonec labelu
        domenatocmp += buffer[bufferpointer]; // sklada se znak po znaku domena
                
        bufferpointer++; // inkrementuje se ukazatel do bufferu
                
        if (printsegment == segmentlen) { // pokud se doslo nakonec labelu
                    
                    
            printsegment = 0; // nastavi se promnne pro pruchod cyklem na 0
            segmentlen = buffer[bufferpointer]; // delka dalsiho lbelu se nastavi
            bufferpointer++; // inkrementujes se ukazatel do bufferu
            if(segmentlen == 0) // pokud se doslo nakonec brzda
                break;
            domenatocmp += "."; // jinak se priradi tecka oddeleni labelu
        }
                
        printsegment++; //inkrementace printovani
                
    }
            // ziskani query type z paketu, podporujeme pouze A, coz je 1
    *dotaz_type = buffer[bufferpointer+1];
    return domenatocmp;
}


/**
 * @brief funkce ktera zacne poslouchat na vsech adresach na urcitem portu
 * @param port_number port na kterem ma poslouchat
 * @return void
 */

void start_listening(int port_number) {
    int server_socket;  // osetreni chyb soketu                         
    int reuseaddr = 1; // znovupouziti adresy (flag)
    struct sockaddr_in6 server = {}; // struktura pro ipv6
    int msg_size, server_i;  // osetreni chyb   
    char buffer[BUFFER]; // prijmuty buffer            
    struct sockaddr_in6 client = {}; // struktura klienta pro ipv6
    socklen_t length; // delka struktury
  
    server.sin6_family = AF_INET6; // nastaveni soketu na ipv6
    server.sin6_port = htons(port_number); // na port z arg
    server.sin6_addr = in6addr_any; // posloucha na vsech adresach           
  
  
    if ((server_socket = socket(AF_INET6, SOCK_DGRAM, 0)) == -1) { // vytvoreni ipv6 socketu
        std::cerr << "selhalo vytvareni socketu" << "\n";
        exit(1);
    }
    if (v) printf("socket vytvoren\n");

    int yes = 0; // nastaveni flagu na prijimani ipv6 a ipv4 a taky reuseaddr

    setsockopt(server_socket, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&yes, sizeof(yes)); 

    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr));

    if (bind(server_socket, (struct sockaddr *)&server, sizeof(server)) == -1) { // nabindovnai serveru
        std::cerr << "selhalo bind()" << "\n";
        exit(1);
    }

    if (v) printf("uspesny bind\n");

    length = sizeof(client);
    
    while ((msg_size = recvfrom(server_socket, buffer, BUFFER, 0, (struct sockaddr *)&client, &length)) >= 0) { // nekonecny cyklus pro prijimani zprav na serveru
        
        int dotaz_type = 0;

        std::string domenatocmp = qnametohost(buffer, &dotaz_type);
            
        // pokud to neni dotaz A
        if (dotaz_type != 1) {

            if (v) printf("Prijaty dotaz neni A odeslani zpet s RCODE NOTIMP\n");

            buffer[2] |= 0x80; // nastaveni QR na 1
            buffer[3] = (buffer[3] & 0xf0) | 0x04; // odeslani s flagem NOTIMP
            
            server_i = sendto(server_socket, buffer, msg_size, 0, (struct sockaddr *)&client, length); // odeslani zpet

            if (server_i == -1) {
                std::cerr << "selhalo sendto()" << "\n";
                exit(1);
            }

            else if (server_i != msg_size) {
                std::cerr << "Neposlal se cely buffer" << "\n";
                exit(1);
            }
                
        }
        else {
            if (filter_domain(domenatocmp)) {

                if (v) printf("Prijaty dotaz je v poradku odeslani na DNS server\n");
                // pokud neni domena na blacklistu odesle se na dns server, dotaz je 1
                char* tmp_buffer;

                int pointer;
                // poslani requeqestu do tmp_buffer se ulozi odpoved a do pointer se ulozi delka zpravy
                tmp_buffer = send_request(buffer, msg_size, &pointer);

                // prekopirovani do buffer z tmp_buffer
                for (int i = 0; i < pointer; i++) {
                    buffer[i] = tmp_buffer[i];
                }
                // odeslani zpet klientovi s dns odpovedi
                server_i = sendto(server_socket, buffer, pointer, 0, (struct sockaddr *)&client, length); 

                if (server_i == -1) {
                    std::cerr << "selhalo sendto()" << "\n";
                    exit(1);
                }

                else if (server_i != pointer) {
                    std::cerr << "Neposlal se cely buffer" << "\n";
                    exit(1);
                }

                if (v) printf("Preposlana odpoved z DNS SERVERU\n");
            
            }
            else {
                if (v) printf("Prijaty dotaz je vyfiltrovani odeslani odpovedi s flagem REFUSED\n");
                // domena je na blacklistu

                buffer[2] |= 0x80; // nastaveni qr na 1
                buffer[3] = (buffer[3] & 0xf0) | 0x05; // nstaveni na refused
                
                server_i = sendto(server_socket, buffer, msg_size, 0, (struct sockaddr *)&client, length); // odeslani zpet klientovi

                if (server_i == -1) {
                    std::cerr << "selhalo sendto()" << "\n";
                    exit(1);
                }

                else if (server_i != msg_size) {
                    std::cerr << "Neposlal se cely buffer" << "\n";
                    exit(1);
                }
            }
        }

    }

    close(server_socket); // uzavreni soketu

    return;
}
/**
 * @brief funkce pro nacteni blacklistu do pametu
 * @param filter_file nazev souboru s domenami
 * @return void
 */

void nacti_soubor(std::string filter_file) {
    // otevreni souboru
    std::ifstream in(filter_file.c_str());
    // pokud neni chyba
    if(!in) {
        std::cerr << "Nelze otevrit soubor : "<<filter_file<<std::endl;
    }
    // promenan pro radek
    std::string str;
    // nacitani radek po radku
    

    while (std::getline(in, str)) {
        if(str.size() > 0) {
            
            if (!str.empty() && str[str.size() - 1] == '\r')
                str.erase(str.size() - 1);
            if (str[0] != '#' && str[0] != ' ' && str[0] != '\r' && str[0] != '\n' && str[0] > 30) {
                
                //all_domains.push_back(str);
                blacklist.insert(str);
            }
        }
    }
    // zavreni souboru
    in.close();
}
/**
 * @brief nacte adresu dns serveru
 * @param domena ip adresa/ domena ke zpracovani
 * @return void
 */

void nacti_dns_server (std::string domena) {
     // zjisteni infa o adrese
    getaddrinfo(domena.c_str(), "53" ,NULL,&res);
    // pokud zadne neni chyba
    if (!res) {
        std::cerr << "domena nema ip adresu" << "\n";
        exit(1);
    }
}

/** 
 * @brief funkce main, zacina tady parse argument, parse souboru a zavola se poslouchani na serveru
 * @param argc kolik je argumentu
 * @param argv pole argumentu
 * @return integer chybovy kod
 */
int main(int argc, char* argv[])
{
    
    std::string domena; // promenna pro arg -s
    int port_number = 53; // promenna pro arg -p
    std::string filter_file; // promenna pro arg -f
    
    signal(SIGINT, catch_terminating); // nastaveni odchytavani signalu

    if (argc < 5) { // malo argumentu
        print_help();
    }
    
    else {
        // parse argumentu
        for (int i = 1; i < argc; i++) {
            if (!strcmp(argv[i], "-s")) {
                if (i+1 >= argc) {
                    arg_alert(0);
                }
                domena = argv[i+1];
                i++;    
            }
            else if (!strcmp(argv[i], "-p")) {
                if (i+1 >= argc) {
                    break;
                }
                if (atoi(argv[i+1])) {
                    port_number = atoi(argv[i+1]);    
                    i++;
                }
            }
            else if (!strcmp(argv[i], "-f")) {
                if (i+1 >= argc) {
                    arg_alert(0);
                }
                filter_file = argv[i+1];
                i++;    
            }
            else if (!strcmp(argv[i], "-v")) {
                v = 1; 
            }
            else if (!strcmp(argv[i], "-h")) {
                print_help();
            }
            else if (!strcmp(argv[i], "--help")) {
                print_help();
            }
            else {
                printf("neznamy argument\n");
                print_help();
                exit(0);
            }
        }
    }
    
    if (v) printf("Nacitani souboru\n");

    nacti_soubor(filter_file);


    if (v) printf("Konec nacitani souboru\n");

    nacti_dns_server(domena);
    
    if (v) printf("Zapnuti serveru na portu %i\n", port_number);

    // zacina poslouchat
    start_listening(port_number);

    freeaddrinfo(res);
    
    return(0);
}
