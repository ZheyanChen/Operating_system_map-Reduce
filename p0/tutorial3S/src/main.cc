# include <printer.h>  // automatically include #includes defined in .h file and function sig

// We need an external declaration of the printSomething() function, or else we
// can't compile this file.

/// Use the `printSomething` function to print "Hello World"
int main() { printSomething("Hello World"); }