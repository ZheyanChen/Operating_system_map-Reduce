#include <iostream> // cout, endl
#include <string>   // string
#include <locale>   // locale and toupper

extern "C" {
/// print a message in all caps
///
/// @param message The message to print
void print_upper(std::string message) {
    using namespace std;
    locale loc;
    for (string::size_type i = 0; i < message.length(); ++i)
        cout << toupper(message[i], loc);
    cout << endl;
}
}