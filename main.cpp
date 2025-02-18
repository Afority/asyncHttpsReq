#define NDEBUG

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
#include <memory>
#include "json.hpp"

#include "network.h"

namespace http = boost::beast::http;

#define BUFFER_SIZE 65536

std::queue<std::function<bool()>> functions;

void run(){
  while (!functions.empty()){
    std::function<bool()> func = functions.front();

    if (func() == 0){
      functions.push(func);
    }
    functions.pop();
  }
}

void registerToQueue(std::function<bool()> func){
  functions.push(func);
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
      return "";
    }

    int posValue = posKey + std::strlen(key) + 2;
    return headers_.substr(posValue, headers_.find('\n', posValue) - posValue - 1);
  }
};


std::string getExampleReq(){
  boost::beast::http::request<boost::beast::http::string_body> req;
  req.method(http::verb::get);
  req.target("/");
  req.version(11); // HTTP/1.1

  // Устанавливаем заголовки
  req.set(http::field::host, "ya.ru");
  req.set(http::field::user_agent, "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36");
  req.prepare_payload();

  std::ostringstream oss;
  oss << req;

  return oss.str();
}

HttpData handleRequest(std::string request){
  int pos = request.find("\n\r"); // позиция тела запроса (body)

  std::string statusLine = request.substr(0, request.find("\n"));

  std::string httpVersion;
  std::string statusCode;
  std::string msg;

  int posSpace1 = statusLine.find(' ');
  int posSpace2 = statusLine.find(' ', posSpace1 + 1);

  httpVersion = statusLine.substr(0, posSpace1);
  statusCode = statusLine.substr(posSpace1 + 1, 3);
  msg = statusLine.substr(posSpace2 + 1);

  if (pos != std::string::npos && strcmp(request.c_str(), "[]")){ // если тело не равно []
    std::string contentLen = HttpData::getHeaderData(request, "Content-Length");
    if (!contentLen.empty()){
      int contentLen_int = stoi(contentLen);
      return HttpData
      {
        request.substr(0, pos),
            request.substr(pos+3, contentLen_int),
            std::stoi(statusCode),
            httpVersion,
            msg
      };
    }
    // должен быть chunked
  }
  return HttpData{"", request, std::stoi(statusCode), httpVersion, msg};
}

std::string readFromSocket(SSL* ssl){
  /*
   * Фукнция будет читать данные с сокета
   * не важно, сокет с блокировкой потока или без
   */

  std::string response;

  char buffer[BUFFER_SIZE];

  if (SSL_read(ssl, buffer, BUFFER_SIZE) > 0){
    response += buffer;
  }
  return response;

  const int pending = SSL_pending(ssl);

  if (pending == 0){
    std::cout << ssl << std::endl;
    return {};
  }

  for (int readBytes{}; readBytes != pending; ){
    if (pending > BUFFER_SIZE){
      readBytes += SSL_read(ssl, buffer, BUFFER_SIZE);
    }
    else{
      readBytes += SSL_read(ssl, buffer, pending);
    }
    std::fill(buffer, buffer + BUFFER_SIZE, 0);
  }
  return response;
}

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

    return handleRequest(result);
  }
  return HttpData{};
}

void asyncGet(const std::string& request,
              const char* domain,
              std::unordered_map<int, HttpData>& answers,
              const int& index){

  std::shared_ptr<Network> network = std::make_shared<Network>();
  std::shared_ptr<Network::Request> req = std::make_shared<Network::Request>(domain, *network, true);

  auto onSSL_write = [req, index, &answers]() -> bool
  {
    // read from socket
    std::string result = readFromSocket(req->ssl);

    if (!result.empty()){
      answers[index] = handleRequest(result);

      SSL_shutdown(req->ssl);
      close(req->sock);
      return true;
    }
    return false;
  };

  auto onSSL_connected = [req, request = std::move(request), onSSL_write = std::move(onSSL_write)]() -> bool
  {
    SSL_write(req->ssl, request.c_str(), request.size());
    std::cout << "writed" << std::endl;
    // registerToQueue(onSSL_write);
    return true;
  };

  auto onServerConnected =[req, network, onSSL_connected = std::move(onSSL_connected)]() -> bool
  {
    // connect to SSL
    if (SSL_connect(req->ssl) == -1) return false;

    SSL_CTX_set_verify(network->crypto.ctx, SSL_VERIFY_PEER, nullptr);

    registerToQueue(onSSL_connected);
    return true;
  };

  auto connectToServer = [req, onServerConnected = std::move(onServerConnected)]() -> bool
  {
    if (connect(req->sock, (sockaddr*)&req->server_addr, sizeof(req->server_addr)) == -1) return false;
    registerToQueue(onServerConnected);
    return true;
  };

  registerToQueue(connectToServer);
}

std::string getHeaderAuth(const char* username,
                          const char* password){
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

std::string getHeaderSchedule(const char* accessToken, int day){
  boost::beast::http::request<boost::beast::http::string_body> req;
  req.method(http::verb::get);
  req.target("/api/v2/schedule/operations/get-by-date?date_filter=2025-02-" + std::to_string(day));
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
  auto headers = getHeaderAuth("Shayh_up14", "18wt7U4t");
  const char* domain = "msapi.top-academy.ru";

  HttpData authResponse = get(headers, domain);
  if (authResponse.errorCode == 200){
    nlohmann::json authData = nlohmann::json::parse(authResponse.body);
    std::string accessToken = authData["access_token"];

    std::unordered_map<int /* index */, HttpData> answers;

    for (int i{3}; i <= 28; ++i){
      asyncGet(getHeaderSchedule(accessToken.c_str(), i), domain, answers, i);
    }
    run();
    for (int i{}; i < answers.size(); ++i){
      if (answers[i].errorCode != 0){
        std::cout << answers[i].body << std::endl;
      }
    }
  }
  else{
    std::cerr << "Статус код: " << authResponse.body << std::endl;
  }
}

int main(){
  auto now = std::chrono::system_clock::now();
  ulong ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();

  std::unordered_map<int /* index */, HttpData> answers;

  for (int i = 1; i <= 1000; i++){
    auto request = getExampleReq();
    asyncGet(request, "ya.ru", answers, i);
  }

  //getSchedule();

  run();

  for (int i{}; i < answers.size(); ++i){
    // std::cout << answers[i].msg << std::endl;
  }

  auto now2 = std::chrono::system_clock::now();
  ulong ms2 = std::chrono::duration_cast<std::chrono::milliseconds>(
        now2.time_since_epoch()).count();

  std::cout << "Программа завершилась за " << ms2 - ms << " мс" <<std::endl;
  return 0;
}
