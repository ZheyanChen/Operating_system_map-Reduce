/**
 * int_ops.cc
 *
 * Int_ops demonstrates a few basic operations on an array of integers:
 * - creating integer arrays from a deterministic pseudo-random number
 *   generator.
 * - printing (text or binary)
 * - searching (linear or binary)
 * - sorting (via the C qsort() function)
 *
 * NB: running this program with the -b flag and some nice large -n value is a
 *     good way to create binary data files for subsequent tutorials.
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <errno.h>
#include <libgen.h>
#include <unistd.h>
#include <utility>

/**
 * Display a help message to explain how the command-line parameters for this
 * program work
 *
 * @progname The name of the program
 */
void usage(char *progname) {
  printf("%s: Demonstrate some basic operations on arrays of integers.\n",
         basename(progname));
  printf("  -n [int] Number of integers to put into an array\n");
  printf("  -r [int] Random seed to use when generating integers\n");
  printf("  -s       Sort the integer array?\n");
  printf("  -f [int] Find an integer in the array using binary search\n");
  printf("  -l [int] Find an integer in the array using linear search\n");
  printf("  -p       Print the array as text, with one int per line\n");
  printf("  -b       Print the array as binary\n");
  printf("  -h       Print help (this message)\n");
}

/**
 * Create an array of the requested size, and populate it with
 * randomly-generated integers
 *
 * @param num   The number of elements to put into the array
 * @param _seed The seed for the random-number generator
 */
unsigned *create_array(unsigned num, unsigned _seed) {
  // NB: we are using C-style allocation here, instead of 'new unsigned[num]'
  unsigned *arr = (unsigned *)malloc(num * sizeof(unsigned));  // allocate on the heap
  if (arr == nullptr) {
    char buf[1024];
    fprintf(stderr, "Error calling malloc: %s\n",
            strerror_r(errno, buf, sizeof(buf)));
    exit(0);
  }
  unsigned seed = _seed;
  for (unsigned i = 0; i < num; ++i) {
    arr[i] = rand_r(&seed);
  }
  return arr;
}

/**
 * A helper routine for comparing two integers (which are passed by pointer),
 * for use in the C quick sort algorithm.
 *
 * @param l The "left" element
 * @param r The "right" element
 *
 * @return -1 if left < right, 0 if equal, 1 if left > right
 */
static int uintcompare(const void *l, const void *r) {
  int lf = *(int *)l, rt = *(int *)r;
  return (lf < rt) ? -1 : (lf > rt) ? 1 : 0;
}

/**
 * Sort an array of unsigned integers by using the built-in C quicksort
 * function.
 *
 * NB: the C++ sort algorithm is better.  Because it uses C++ templates, it can
 *     get inlined more effectively.  This qsort() function will actually make
 *     function calls to uintcompare(), which will be slow.
 *
 * @param arr  The array to sort
 * @param size The number of elements in the array
 */
void sort_array(unsigned *arr, unsigned size) {
  qsort(arr, size, sizeof(unsigned), uintcompare);
}

/**
 * Recursive binary search algorithm.  Remember that modern compilers will apply
 * tail-call optimizations, so it's fine to use recursion if you are compiling
 * at -O1 or greater.
 *
 * NB: for an array of size X, the call should use 0 for lo, and X-1 for hi.
 *
 * @param arr The array of integers in which to search
 * @param lo  The lowest index to consider in the array
 * @param hi  The highest index to consider in the array
 * @param key The value to search for in the array
 *
 * @return index at which key can be found, or -1
 */
int binary_search(unsigned arr[], int lo, int hi, unsigned key) {
  if (hi >= lo) {
    int mid = lo + (hi - lo) / 2; // mid point
    if (arr[mid] == key)
      return mid; // On success, return the index
    if (arr[mid] > key)
      return binary_search(arr, lo, mid - 1, key); // go left (we're too big)
    return binary_search(arr, mid + 1, hi, key);   // go right (we're too small)
  }
  return -1; // not found
}

/**
 * Linear search algorithm.
 *
 * @param arr The array of integers in which to search
 * @param num The number of elements in the array
 * @param key The value to search for in the array
 *
 * @return index at which key can be found, or -1
 */
int linear_search(unsigned arr[], unsigned num, unsigned key) {
  for (unsigned i = 0; i < num; ++i)
    if (arr[i] == key)
      return i;
  return -1;
}

/**
 * Print the contents of an integer array as text, with one entry per line
 *
 * @param arr The array of integers to print
 * @param num The number of elements in the array
 */
void print_text(unsigned arr[], unsigned num) {
  for (unsigned i = 0; i < num; ++i)
    printf("%d\n", arr[i]);
}

/**
 * Print the contents of an integer array as binary
 *
 * @param arr The array of integers to print
 * @param num The number of elements in the array
 */
void print_binary(unsigned arr[], unsigned num) {
  if (fwrite(&arr[0], sizeof(unsigned), num, stdout) < num) {
    char buf[1024];
    fprintf(stderr, "Error calling fwrite: %s\n",
            strerror_r(errno, buf, sizeof(buf)));
    exit(0);
  }
}

/** arg_t is used to store the command-line arguments of the program */
struct arg_t {
  /** The number of random elements to put into the array */
  unsigned num = 16;

  /** A random seed to use when generating elements to put into the array */
  unsigned seed = 0;

  /** Sort the array? */
  bool sort = false;

  /** Key to use for a binary search in the array */
  std::pair<bool, unsigned> bskey = {false, 0};

  /** Key to use for a linear search in the array */
  std::pair<bool, unsigned> lskey = {false, 0};

  /** Print the array as text? */
  bool printtext = false;

  /** Print the array as binary? */
  bool printbinary = false;

  /** Display a usage message? */
  bool usage = false;
};

/**
 * Parse the command-line arguments, and use them to populate the provided args
 * object.
 *
 * @param argc The number of command-line arguments passed to the program
 * @param argv The list of command-line arguments
 * @param args The struct into which the parsed args should go
 */
void parse_args(int argc, char **argv, arg_t &args) {  // 3rd arg passed by reference
  long opt;
  while ((opt = getopt(argc, argv, "n:r:sf:l:pbh")) != -1) {
    switch (opt) {
    case 'n':
      args.num = atoi(optarg);   //If the option takes a value, that value is pointer to the external variable optarg.
      break;
    case 'r':
      args.seed = atoi(optarg);
      break;
    case 's':
      args.sort = true;
      break;
    case 'f':
      // NB: C++ pair objects are a convenient way to store a tuple :)
      args.bskey = std::make_pair(true, atoi(optarg));
      break;
    case 'l':
      args.lskey = std::make_pair(true, atoi(optarg));
      break;
    case 'p':
      args.printtext = true;
      break;
    case 'b':
      args.printbinary = true;
      break;
    case 'h':
      args.usage = true;
      usage(argv[0]);
      break;
    }
  }
}

int main(int argc, char *argv[]) {
  arg_t args;
  parse_args(argc, argv, args);

  // if help was requested, give help, then quit
  if (args.usage) {
    usage(argv[0]);
    return 0;
  }

  // make the array, and maybe sort it
  unsigned *arr = create_array(args.num, args.seed);
  if (args.sort)
    sort_array(arr, args.num);

  // do any requested searches
  //
  // NB: you can time the program, using the 'time' command, to get a sense for
  //     the impact of linear vs. binary search, but the cost of creating the
  //     array will get in the way of drawing good conclusions.
  if (args.bskey.first) {
    int idx = binary_search(arr, 0, args.num - 1, args.bskey.second);
    if (idx != -1)
      printf("a[%d] == %u\n", idx, arr[idx]);
    else
      printf("key %u not found\n", args.bskey.second);
  }
  if (args.lskey.first) {
    int idx = linear_search(arr, args.num, args.lskey.second);
    if (idx != -1)
      printf("a[%d] == %u\n", idx, arr[idx]);
    else
      printf("key %u not found\n", args.lskey.second);
  }

  // do any requested prints
  //
  // NB: never time a program that has prints to the screen... they take
  //     forever.  To convince yourself, time the program, then run it again but
  //     redirect stdout to a file (i.e., int_ops.exe > file).  If the output is
  //     big, you'll see a *huge* difference
  if (args.printtext)
    print_text(arr, args.num);
  if (args.printbinary)
    print_binary(arr, args.num);
}