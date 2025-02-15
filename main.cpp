#include <string>
#include <iostream>
#include <unistd.h>
#include <fcntl.h>
#include <queue>
#include <boost/beast.hpp>
#include <sstream>
#include <chrono>
#include <cstring>
#include <format>
#include <openssl/ssl.h>
#include "json.hpp"

#include "network.h"

namespace http = boost::beast::http;

#define BUFFER_SIZE 65536

std::queue<std::function<bool()>> func_on_writed;
std::queue<std::function<void()>> func_on_ssl_connect;
std::queue<std::function<bool()>> func_on_connect;
std::queue<std::function<bool()>> func_connect_;

void run(){
  while (func_connect_.empty() &&
         func_on_connect.empty() &&
         func_on_ssl_connect.empty() &&
         func_on_writed.empty()){

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

struct HttpData{
  std::string headers;
  std::string body;
  int errorCode{};
  std::string httpVersion;
  std::string msg;

  static std::string getHeaderData(std::string headers_, const char* key){
    int posKey = headers_.find(key);
    if (posKey == std::string::npos){
      std::cerr << "Ключ не найден" << std::endl;
    }

    int posValue = posKey + std::strlen(key) + 2;
    return headers_.substr(posValue, headers_.find('\n', posValue) - posValue - 1);
  }
};

std::string getReq(int day){
  boost::beast::http::request<boost::beast::http::string_body> req;
  req.method(http::verb::get);
  req.target("/api/v2/schedule/operations/get-by-date?date_filter=2025-02-" + std::to_string(day));
  req.version(11); // HTTP/1.1

  // Устанавливаем заголовки
  req.set(http::field::host, "msapi.top-academy.ru");
  req.set(http::field::authorization, "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczpcL1wvbXNhcGkuaXRzdGVwLm9yZyIsImlhdCI6MTczOTQzMzEyMCwiYXVkIjoxLCJleHAiOjE3Mzk0NTQ3MjAsImFwaUFwcGxpY2F0aW9uSWQiOjEsImFwaVVzZXJUeXBlSWQiOjEsInVzZXJJZCI6NDk3OTIsImlkQ2l0eSI6MTE2fQ.YoY9KTKJUAS51zS79tyJFKpArpvtx9VUTGHCCC6J1nE");
  req.set(http::field::referer, "https://journal.top-academy.ru/");
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

HttpData get(std::string request,
             const char* domain){

  Network network;
  Network::Request req(domain, network);

  if (connect(req.sock, (sockaddr*)&req.server_addr, sizeof(req.server_addr)) == -1){
    std::cerr << "Не возможно подключиться к серверу" << errno << std::endl;
    return HttpData{};
  }

  if (!req.ssl){
    std::cerr << "SSL not initialized\n";
  }

  if (SSL_connect(req.ssl) == -1){
    std::cerr << "Не возможно подключить SSL\n";
    return HttpData{};
  }

  SSL_CTX_set_verify(network.crypto.ctx, SSL_VERIFY_PEER, nullptr);

  int bytes_written = SSL_write(req.ssl, request.c_str(), request.size());

  if (bytes_written <= 0) {
    int err = SSL_get_error(req.ssl, bytes_written);
    fprintf(stderr, "SSL_write error: %d\n", err);
  }

  std::string result;

  char buffer[BUFFER_SIZE];

  if (SSL_read(req.ssl, buffer, BUFFER_SIZE) > 0){
    result += buffer;

    int pos = result.find("\n\r"); // позиция тела запроса (body)
    if (pos != std::string::npos && strcmp(result.c_str(), "[]")){ // если тело не равно []
      std::string statusLine = result.substr(0, result.find("\n"));

      std::string httpVersion;
      std::string statusCode;
      std::string msg;

      int posSpace1 = statusLine.find(' ');
      int posSpace2 = statusLine.find(' ', posSpace1 + 1);

      httpVersion = statusLine.substr(0, posSpace1);
      statusCode = statusLine.substr(posSpace1 + 1, 3);
      msg = statusLine.substr(posSpace2 + 1);

      std::string contentLen = HttpData::getHeaderData(result, "Content-Length");
      if (!contentLen.empty()){
        int contentLen_int = stoi(contentLen);
        return HttpData
        {
          result.substr(0, pos),
              result.substr(pos+3, contentLen_int),
              std::stoi(statusCode),
              httpVersion,
              msg
        };
      }
      // должен быть chunked
      std::cerr << "Content-Length отсутствует " << result<< std::endl;
    }
  }
  return HttpData{};
}

void asyncGet(std::string request,
              const char* domain,
              std::unordered_map<int,std::string>& answers,
              int index){
  Network network;
  Network::Request req(domain, network, true);


  set_connect([req, request, &answers, index, network](){
    if (connect(req.sock, (sockaddr*)&req.server_addr, sizeof(req.server_addr)) == -1){
      return false;
    }

    set_on_connect([req, request, &answers, index, network](){
      if (SSL_connect(req.ssl) == -1){
        return false;
      }

      SSL_CTX_set_verify(network.crypto.ctx, SSL_VERIFY_PEER, nullptr);

      set_on_ssl_connect([req, request, &answers, index](){
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

std::string getHeaderAuth(const char* username = "",
                          const char* password = ""){
  boost::beast::http::request<boost::beast::http::string_body> req;
  req.method(http::verb::post);
  req.target("/api/v2/auth/login");
  req.version(11); // HTTP/1.1

  // Устанавливаем заголовки
  req.set(http::field::host, "msapi.top-academy.ru");
  req.set(http::field::authorization, "Bearer null");
  req.set(http::field::referer, "https://journal.top-academy.ru/");
  req.set(http::field::accept_language, "ru_RU, ru");
  req.set(http::field::user_agent, "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36");
  req.set(http::field::content_type, "application/json");
  req.set(http::field::accept, "application/json, text/plain, */*");
  req.set(http::field::connection, "close");

  // Устанавливаем кастомные заголовки (нестандартные)
  req.set("sec-ch-ua-platform", "\"Linux\"");
  req.set("sec-ch-ua", "\"Chromium\";v=\"130\", \"Google Chrome\";v=\"130\", \"Not?A_Brand\";v=\"99\"");
  req.set("sec-ch-ua-mobile", "?0");

  const char* defaultAppKey = "6a56a5df2667e65aab73ce76d1dd737f7d1faef9c52e8b8c55ac75f565d8e8a6";

  req.body() = std::format(R"({{"application_key":"{}","id_city":null,"password":"{}", "username":"{}"}})", defaultAppKey, password, username);

  req.prepare_payload();

  std::ostringstream oss;
  oss << req;

  return oss.str();
}

std::string getHeaderSchedule(const char* accessToken){
  boost::beast::http::request<boost::beast::http::string_body> req;
  req.method(http::verb::get);
  req.target("/api/v2/schedule/operations/get-month?date_filter=2025-02-0");
  req.version(11); // HTTP/1.1

  // Устанавливаем заголовки
  req.set(http::field::host, "msapi.top-academy.ru");

  std::string auth = std::format("Bearer {}", accessToken);

  req.set(http::field::authorization, auth.c_str());
  req.set(http::field::referer, "https://journal.top-academy.ru/");
  req.set(http::field::accept_language, "ru_RU, ru");
  req.set(http::field::user_agent, "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36");
  req.set(http::field::content_type, "application/json");
  req.set(http::field::accept, "application/json, text/plain, */*");
  req.set(http::field::connection, "close");

  // Устанавливаем кастомные заголовки (нестандартные)
  req.set("sec-ch-ua-platform", "\"Linux\"");
  req.set("sec-ch-ua", "\"Chromium\";v=\"130\", \"Google Chrome\";v=\"130\", \"Not?A_Brand\";v=\"99\"");
  req.set("sec-ch-ua-mobile", "?0");

  req.prepare_payload();

  std::ostringstream oss;
  oss << req;

  return oss.str();
}


void getSchedule(){
  // Получаем bearer токен
  auto headers = getHeaderAuth();
  const char* domain = "msapi.top-academy.ru";

  HttpData authResponse = get(headers, domain);
  if (authResponse.errorCode == 200){
    nlohmann::json authData = nlohmann::json::parse(authResponse.body);
    std::string accessToken = authData["access_token"];

    HttpData schedule = get(getHeaderSchedule(accessToken.c_str()), domain);

    if (schedule.errorCode == 200){
      std::cout << schedule.body << std::endl;
    }
    else{
      std::cerr << "Статус код: " << schedule.errorCode << std::endl;
    }
  }
  else{
    std::cerr << "Статус код: " << authResponse.errorCode << std::endl;
  }
}

int main(){
  auto now = std::chrono::system_clock::now();
  ulong ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();

  std::unordered_map<int, std::string> answers;

  // for (int i = 0; i <= 10; i++){
  //   auto request = getExampleReq();
  //   asyncGet(request, host, answers, i);
  // }

  getSchedule();

  run();

  for (int i{}; i < answers.size(); ++i){
    if (!answers[i].empty()){
      std::cout << i << std::endl;
    }
  }

  auto now2 = std::chrono::system_clock::now();
  ulong ms2 = std::chrono::duration_cast<std::chrono::milliseconds>(
        now2.time_since_epoch()).count();

  std::cout << "Программа завершилась за " << ms2 - ms << " мс" <<std::endl;
  return 0;
}
