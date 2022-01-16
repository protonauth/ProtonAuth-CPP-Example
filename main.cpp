/*

   proton.cc is a free/paid c++ licensing system.
   this cpp example as been made by lana rhoades#9607.
   more informations on our official github, github.com/protonauth

*/

#include <iostream>
#include "api/proton.hpp"

proton::api authentification(p_xor("PROGRAM_VERSION"), p_xor("PROGRAM_KEY"), p_xor("PROGRAM_API/ENCRYPTION_KEY")); // Put your own things here. (available on your dashboard)

std::string tm_to_readable_time(tm ctx) 
{
    char buffer[25];

    strftime(buffer, sizeof(buffer), "%m/%d/%y", &ctx);      // Simple code who convert a current date to a readable text for the program

    return std::string(buffer);
}

void userinformations()
{
    std::cout << authentification.user_data.username << std::endl;                          // Writing logged client username
    std::cout << authentification.user_data.email << std::endl;                             // Writing logged client email
    std::cout << tm_to_readable_time(authentification.user_data.expires) << std::endl;      // Writing logged client expiration
    std::cout << authentification.user_data.var << std::endl;                               // Writing logged client data variables
    std::cout << authentification.user_data.rank << std::endl;                              // Writing logged client data rank (user level)
}

int main()
{
    SetConsoleTitleA(p_xor("Proton 1.1 c++ example."));
    int user_options;                                                   // Define user_options for the option selector.
    std::string user, pass, token;                                      // Don't touch this
    authentification.init();                                            // Initialize authentification program.
    nigger:                                                             // Making a simple way, can be used for GOTO
    std::cout << p_xor("Please select an option: ") << std::endl;
    std::cout << p_xor("\n");
    std::cout << p_xor("- [1] Login") << std::endl;
    std::cout << p_xor("- [2] Register") << std::endl;
    std::cout << p_xor("- [3] Upgrade") << std::endl;
    std::cout << p_xor("- [4] Key only") << std::endl;
    std::cout << p_xor("\n");
    std::cout << p_xor("  >> ");
    std::cin >> user_options;                                           // define user options
    switch (user_options)
    {
    case 1: // LOGIN
        system(p_xor("CLS"));
        std::cout << p_xor("\n\n");
        std::cout << p_xor("Username: ");
        std::cin >> user;
        std::cout << p_xor("\n");
        std::cout << p_xor("Password: ");
        std::cin >> pass;

        if (authentification.login(user, pass)) {
            system(p_xor("CLS"));
            std::cout << p_xor("Successfully logged in.") << std::endl;

            userinformations(); // (optional) print current user informations.
            
            /*
            
            Here you are now logged in, paste your code for the next here.

            */


            Sleep(-1); // ud infinite time.
        }
        else
        {
            std::cout << p_xor("Invalid username or password.") << std::endl;
            Sleep(1000);
            exit(0);
        }
    case 2: // REGISTER
    {
        system("CLS");
        std::cout << p_xor("\n\n");
        std::cout << p_xor("Username: ");
        std::cin >> user;
        std::cout << p_xor("\n");
        std::cout << p_xor("Password: ");
        std::cin >> pass;
        std::cout << p_xor("\n");
        std::cout << p_xor("Key: ");
        std::cin >> token;

        if (authentification.register(user, pass, token))
        {
            /*
            
            Your account is now registered, you have to login with it now.

            */

            system("CLS");
            std::cout << p_xor("Successfully registered.") << std::endl;
            std::cout << p_xor("Redirecting in 5 seconds . . .") << std::endl;
            Sleep(5000);
            system("CLS");
            goto nigger;
        }
        else
        {
            std::cout << p_xor("Invalid username, password or key.") << std::endl;
        }
      }
    case 3: // KEY
    {
        system("CLS");
        
        std::cout << p_xor("Username: ");
        std::cin >> user;
        std::cout << p_xor("Key: ");
        std::cin >> token;

        if (authentification.activate(user, token))
        {
            std::cout << p_xor("Successfully activated ") << token << " on " << user << std::endl;

            Sleep(-1);
        }
        else
        {
            std::cout << p_xor("Failed to active ") << token << " on " << user << std::endl;
        }

      
    }
    case 4:
    {
        system("CLS");

        std::cout << p_xor("Enter license key: ") << std::endl;
        std::cin >> token;
        if (authentification.all_in_one(token))
        {
            std::cout << p_xor("Successfully logged to ") << token << " " << p_xor("!") << std::endl;
        }
        else
        {
            std::cout << p_xor("Failed to login to ") << token << " " << "." << std::endl;
        }

      }

   }

}