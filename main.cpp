#include <string>
#include <iostream>
#include <unistd.h>
#include <fcntl.h>
#include <queue>
#include <boost/beast.hpp>
#include <sstream>
#include <chrono>
#include <cstring>
#include <openssl/ssl.h>

#include "network.h"

namespace http = boost::beast::http;

#define BUFFER_SIZE 65536

std::queue<std::function<bool()>> func_on_writed;
std::queue<std::function<void()>> func_on_ssl_connect;
std::queue<std::function<bool()>> func_on_connect;
std::queue<std::function<bool()>> func_connect_;

void run(){
  while (true){
    if (func_connect_.empty() &&
        func_on_connect.empty() &&
        func_on_ssl_connect.empty() &&
        func_on_writed.empty() == true) break;

    if (!func_connect_.empty()){
      auto func = func_connect_.front();

      if (func() == 0){
        func_connect_.push(func);
      }
      func_connect_.pop();
    }
    if (!func_on_connect.empty()){
      auto func = func_on_connect.front();

      if (func() == 0){
        func_on_connect.push(func);
      }
      func_on_connect.pop();
    }
    if (!func_on_ssl_connect.empty()){
      auto func = func_on_ssl_connect.front();
      func();
      func_on_ssl_connect.pop();
    }
    if (!func_on_writed.empty()){
      auto func = func_on_writed.front();

      if (func() == 0){
        func_on_writed.push(func);
      }
      func_on_writed.pop();
    }
  }
}

std::string getReq(int day){
  boost::beast::http::request<boost::beast::http::string_body> req;
  req.method(http::verb::get);
  req.target("/api/v2/schedule/operations/get-by-date?date_filter=2025-02-" + std::to_string(day));
  req.version(11); // HTTP/1.1

  // Устанавливаем заголовки
  req.set(http::field::host, "123");
  req.set(http::field::authorization, "Bearer ");
  req.set(http::field::referer, "123/");
  req.set(http::field::accept_language, "ru_RU, ru");
  req.set(http::field::user_agent, "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36");
  req.set(http::field::accept, "application/json, text/plain, */*");
  req.set(http::field::connection, "keep-alive");

  // Устанавливаем кастомные заголовки (нестандартные)
  req.set("sec-ch-ua-platform", "\"Linux\"");
  req.set("sec-ch-ua", "\"Chromium\";v=\"130\", \"Google Chrome\";v=\"130\", \"Not?A_Brand\";v=\"99\"");
  req.set("sec-ch-ua-mobile", "?0");
  req.prepare_payload();

  std::ostringstream oss;
  oss << req;

  return oss.str();
}

std::string getExampleReq(){
  boost::beast::http::request<boost::beast::http::string_body> req;
  req.method(http::verb::get);
  req.target("/");
  req.version(11); // HTTP/1.1

  // Устанавливаем заголовки
  req.set(http::field::host, "google.com");
  req.set(http::field::user_agent, "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36");
  req.prepare_payload();

  std::ostringstream oss;
  oss << req;

  return oss.str();
}


void set_on_write(std::function<bool()> func){
  func_on_writed.push(func);
}

void set_on_ssl_connect(std::function<void()> func){
  func_on_ssl_connect.push(func);
}


void set_on_connect(std::function<bool()> func){
  func_on_connect.push(func);
}


void set_connect(std::function<bool()> func){
  func_connect_.push(func);
}

std::unordered_map<const char*, hostent*> cash;

void get(std::string request,
         const char* domain,
         std::unordered_map<int, std::string>& answers,
         int index){

  Network network;
  Network::Request req(domain, network);

  if (connect(req.sock, (sockaddr*)&req.server_addr, sizeof(req.server_addr)) == -1){
    std::cerr << "Не возможно подключиться к серверу" << errno << std::endl;
    return;
  }

  if (!req.ssl){
    std::cerr << "SSL not initialized\n";
  }

  if (SSL_connect(req.ssl) == -1){
    std::cerr << "Не возможно подключить SSL\n";
    return;
  }

  SSL_CTX_set_verify(network.crypto.ctx, SSL_VERIFY_PEER, nullptr);

  SSL_write(req.ssl, request.c_str(), request.size());

  std::string result;

  char buffer[BUFFER_SIZE];

  if (SSL_read(req.ssl, buffer, BUFFER_SIZE) > 0){
    result += buffer;
    // std::fill(buffer, buffer + BUFFER_SIZE, 0);
  }

  if (!result.empty()){
    int pos = result.find("\n\r"); // позиция тела запроса (body)
    if (pos != std::string::npos && strcmp(result.c_str(), "[]")){ // если тело не равно []
      answers[index] = result.substr(pos+3);
      std::cout << answers[index] << std::endl;
    }
  }
}

void asyncGet(std::string request,
              const char* domain,
              std::unordered_map<int,std::string>& answers,
              int index){
  std::cout << index << std::endl;
  Network network;
  Network::Request req(domain, network, true);


  set_connect([req, request, &answers, index, &network](){
    if (connect(req.sock, (sockaddr*)&req.server_addr, sizeof(req.server_addr)) == -1){
      return false;
    }

    set_on_connect([req, request, &answers, index, &network](){
      if (SSL_connect(req.ssl) == -1){
        return false;
      }
      set_on_ssl_connect([req, request, &answers, index, &network](){
        // SSL_CTX_set_verify(network.crypto.ctx, SSL_VERIFY_PEER, nullptr);

        SSL_write(req.ssl, request.c_str(), request.size());

        set_on_write([req, &answers, index](){
          std::string result;

          char buffer[BUFFER_SIZE];
          while (SSL_read(req.ssl, buffer, BUFFER_SIZE) > 0){
            result += buffer;
            std::fill(buffer, buffer + BUFFER_SIZE, 0);
          }

          if (!result.empty()){
            int pos = result.find("\n\r"); // позиция тела запроса (body)
            if (pos != std::string::npos && strcmp(result.c_str(), "[]")){ // если тело не равно []
              answers[index] = result.substr(pos+3);
              std::cout << answers[index] << std::endl;
            }
          }

          return !result.empty();
        });
      });
      return true;
    });
    return true;
  });
}

int main(){
  auto now = std::chrono::system_clock::now();
  ulong ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();

  const char* host = "www.google.com";

  std::unordered_map<int, std::string> answers;

  for (int i = 0; i <= 10; i++){
    auto request = getExampleReq();
    get(request, host, answers, i);
  }
  std::cout << "run" << std::endl;
  run();
  std::cout << "end run" << std::endl;
  for (int i{}; i < answers.size(); ++i){
    if (!answers[i].empty()){
      std::cout << answers[i] << std::endl;
    }
  }

  auto now2 = std::chrono::system_clock::now();
  ulong ms2 = std::chrono::duration_cast<std::chrono::milliseconds>(
        now2.time_since_epoch()).count();

  std::cout << "Программа завершилась за " << ms2 - ms << " мс" <<std::endl;
  return 0;
}
