#include "crypto.h"
#include <unordered_map>
#include <ctime>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <algorithm>

struct Network{
    Crypto crypto;

    struct Ip{
    private:
        const char* domain{};
        hostent* host;
        time_t whenItWasReceived = 0;
    public:
        Ip(const char* domain = ""){
            this->domain = domain;
            updateHost();
        };

        void updateHost(){
            if (!isActual()){
                host = gethostbyname(domain);
                whenItWasReceived = std::time(nullptr);
            }
        }

        hostent* get(){
            updateHost();
            return host;
        }
        bool isActual(){
            if (std::time(nullptr) - whenItWasReceived > 3600 /* 1 час */ || host){
#ifdef NDEBUG
                std::cout << "DEBUG: срок действия кеша истек";
#endif
                return false;
            }
#ifdef NDEBUG
            std::cout << "DEBUG: срок действия кеша не истек";
#endif
            return true;
        }
    };

    std::unordered_map<const char*, Ip> cashedIp;

    Network(){

    }

    Ip resolveIp(const char* domain){
        if (cashedIp.find(domain) != cashedIp.end()){
            return cashedIp.find(domain)->second;
        }
        Ip ip{domain};
        cashedIp[domain] = ip;

        return ip;
    }

    struct Request{
        int sock = -1;
        SSL *ssl = nullptr;
        Ip ip;
        sockaddr_in server_addr{};

        Request(const char* domain, Network& network, bool sockNonBlock = false) : ip{domain}{
            sock = socket(AF_INET, SOCK_STREAM, 0);

            if (sock < 0){
              perror("Socket creation failed");
              return;
            }

            if (sockNonBlock){
                // делаем сокет не блокирующим
                int flags = fcntl(sock, F_GETFL, 0);
                fcntl(sock, F_SETFL, flags | O_NONBLOCK);
            }

            if (!network.crypto.ctx) {
                std::cerr << "SSL context is not initialized." << std::endl;
                close(sock);
                return;
            }

            ssl = SSL_new(network.crypto.ctx);
            if (!ssl){
              std::cerr << "Error creating SSL object." << std::endl;
              close(sock);
              return;
            }

            SSL_set_fd(ssl, sock);

            server_addr.sin_family = AF_INET;
            server_addr.sin_port = htons(443);

            ip = network.resolveIp(domain);

            memcpy(&server_addr.sin_addr.s_addr, ip.get()->h_addr_list[0], sizeof server_addr.sin_addr.s_addr);
        }

    };

};
