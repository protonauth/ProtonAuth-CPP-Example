#include <iostream>
#include "api/proton_auth.hpp"

proton::api auth(p_xor("1.0"), p_xor("9UiYh22JKLXyL36zZI7xaIuiEYxUGEhVjXChFOifJdV"), p_xor("b708f441dfd4fd65fd090ae8b2d35a91"));

int option;
bool version = "1.2";

std::string user, email, pass, token;

std::string tm_to_readable_time(tm ctx) 
{
    char buffer[25];
    strftime(buffer, sizeof(buffer), "%m/%d/%y", &ctx);
    return std::string(buffer);
}

void userinformations()
{
    std::cout << "  " << auth.user_data.username << std::endl;                          // Writing logged client username
    std::cout << "  " << auth.user_data.email << std::endl;                             // Writing logged client email
    std::cout << "  " << tm_to_readable_time(auth.user_data.expires) << std::endl;      // Writing logged client expiration
    std::cout << "  " << auth.user_data.var << std::endl;                               // Writing logged client data variables
    std::cout << "  " << auth.user_data.rank << std::endl;                              // Writing logged client data rank (user level)
}