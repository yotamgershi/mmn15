#include "client.hpp"
#include <string>
#include <chrono>

int main()
{
    std::string host = "localhost";
    std::string port = "1234";
    Client client(host, port);
    client.connect();
	std::string name = "yotam";
	std::string clientID = "1234567890";
	SignUpRequest sign_up_request(clientID, name);
	std::vector<uint8_t> data = sign_up_request.buildRequest();
	client.send(data);
	std::this_thread::sleep_for(std::chrono::seconds(1));
    client.close();	
    return 0;
}