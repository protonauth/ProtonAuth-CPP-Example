/*
   proton.cc is a free/paid c++ licensing system.
   this cpp example as been made by unstable#7777.
   more informations on our official github, github.com/protonauth

   ---------------------------------------------------------------

   [1.2] Fixed API and cleaned code.

*/

#include <iostream>
#include "api/proton_auth.hpp"
#include "utils.h"

int main()
{
    system(p_xor("color 0B"));
    SetConsoleTitleA(p_xor("Proton 1.2 c++ example."));

    std::cout << p_xor("\n\n") << p_xor("  ") << p_xor("  Initializing . . .") << std::endl;
    Sleep(1000);
    auth.init();

    system("CLS");
    nigger:

    std::cout << p_xor("  Please select an option: ") << std::endl;
    std::cout << p_xor("\n");
    std::cout << p_xor("- [1] Login") << std::endl;
    std::cout << p_xor("- [2] Register") << std::endl;
    std::cout << p_xor("- [3] Upgrade") << std::endl;
    std::cout << p_xor("- [4] Key only") << std::endl;
    std::cout << p_xor("\n");
    std::cout << p_xor("  >> ");

    std::cin >> option;

    switch (option)
    {
        case 1:
            system(p_xor("CLS"));
            std::cout << "\n\n" << p_xor("  Username: ");
            std::cin >> user;

            std::cout << p_xor("\n") << p_xor("  Password: ");
            std::cin >> pass;

            if (auth.login(user, pass))
            {
                system(p_xor("CLS"));
                std::cout << p_xor("\n\n") << p_xor("  Successfully logged in.") << std::endl;

                userinformations(); // (optional) print current user informations.
      
                /* here you are logged in, paste your code for the next here. */
                /* auth.file can be used, follow documentation for more https://www.protonauth.xyz/documentation/index.html */
                
            }

            else 
            {
                std::cout << p_xor("\n\n") << p_xor("  Invalid username or password.") << std::endl;
            }
            break;

            case 2:
            std::cout << p_xor("\n\n") << p_xor("  Username: ");
            std::cin >> user;

            std::cout << p_xor("\n") << p_xor("  Email: ");
            std::cin >> email;

            std::cout << p_xor("\n") << p_xor("  Password: ");
            std::cin >> pass;

            std::cout << p_xor("\n") << p_xor("  Key: ");
            std::cin >> token;

            

            if (auth.register(user, email, pass, token))
            {
                system("CLS");
                std::cout << p_xor("  Successfully registered.") << std::endl;
                std::cout << p_xor("  Redirecting in 5 seconds . . .") << std::endl;
                Sleep(5000);
                system("CLS");
                goto nigger;
            }
            
            else
            {
                std::cout << p_xor("\n\n") << p_xor("  Invalid username, password or key.") << std::endl;
            }
            break;

            case 3:
            {
                std::cout << p_xor("\n\n") << p_xor("  Username: ");
                std::cin >> user;

                std::cout << p_xor("\n") << p_xor("  Key: ");
                std::cin >> token;

                if (auth.activate(user, token))
                {
                    std::cout << p_xor("Successfully activated ") << token << " on " << user << std::endl;
                    std::cout << p_xor("Redirecting in 5 seconds . . .") << std::endl;
                    Sleep(5000);
                    system("CLS");
                    goto nigger;
                }
                else
                {
                    std::cout << p_xor("\n\n") << p_xor("Invalid user or key.") << std::endl;
                }
                    
            } break;
            



        case 4:
        {
            std::cout << p_xor("\n") << p_xor("  Key: ");
            std::cin >> token;

            if (auth.all_in_one(token))
            {
                std::cout << p_xor("\n\n") << p_xor("  Successfully logged to ") << token << " " << p_xor("!") << std::endl;
            }

            else 
            {
                std::cout << p_xor("  Failed to login to ") << token << " " << "." << std::endl;
            } break;
            

             default:

            std::cout << p_xor("\n\n") << "Invalid option\n";
        } break;
        
    }

    std::cin >> option;
}

