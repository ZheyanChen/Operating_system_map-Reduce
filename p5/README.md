# Assignment #5: A Virtual Execution Environment

In this assignment, we will gain a deeper appreciation for the power of
virtualization.  We will do so in two ways.  First, we will transform our
key/value store into a server that provides a new feature: map/reduce
functionality.  Second, we will heavily use the process abstraction to keep our
server secure while we provide this new feature.

## Do This First

Immediately after pulling `p5` from Bitbucket, you should start a container,
navigate to the `p5` folder, and type `chmod +x solutions/*.exe`.  This command
only needs to be run once.  It will make sure that certain files from the
assignment have their executable bit set.

## Assignment Details

In Java, it is possible to use *dynamic class loading* to load `.class` files
into a running program.  If the loaded class implements an `interface` that the
program already understands, it can use the new class anywhere that the old
interface was used.

In C++, we can do something very similar: we can compile a `.cc` file to a
*shared object* (`.so`), and then load it into our program.  When we load it, we
can pick out functions within the shared object and use them.  Shared objects
(or "DLLs", in Windows) are incredibly powerful for a number of reasons that you
should understand.  The use of shared objects in this assignment is not the most
common, but it is critical to many on-line services.

To leverage this feature, we will add an *administrator* concept to our server.
The administrator's user name will be given on the command line.  The
administrator will have a new command that only it can execute from the client:
`KVF`, which registers functions.  Note that you will still need to *register*
an administrator account... it will not be created automatically, despite the
command-line argument.

To use KVF, the administrator needs a `.so` with two functions: `map()` and
`reduce()`.  Any user can use a `KMR` command to request that these functions be
used.

To use the functions, the server will do something similar to a `KVA`: it will
iterate through all the key/value pairs, obeying 2pl.  For each pair, it will
call the `map()` function, and append the result to a temporary `vector`.  Once
all the pairs have been visited, then the server will pass the temporary vector
to the `reduce()` function.  The final result will be sent back to the user.

Your server will need to maintain a `std::unordered_map` to hold the registered
functions. It should use a `std::shared_mutex` (a readers/writer lock), so that
multiple threads can get functions from the map simultaneously, but only one
thread can insert new functions.

We have one final requirement: running user-provided code inside the server
process is dangerous.  We don't want to simply trust the administrator to only
load safe code.  Instead, the server should `fork()` a child process and use
`pipe()` to create channels for communicating with the child.  The parent will
iterate through keys, and will send them to the child.  The child will execute
the `map()` and `reduce()` functions.  The child will then write the result back
on a pipe, so that a server thread can send the result to the client.

In and of itself, running the code in a separate process may not seem like it
adds much security.  However, because of the way that `fork()` works, the server
can "sandbox" the executable code.  In particular, we will use the `seccomp`
feature of modern Linux to disable the creation of new files in the child
process.  This means that the child cannot open back-doors or snoop the file
system.

## Getting Started

Your git repository has a new folder, `p5`, which contains a significant portion
of the code for the final solution to this assignment.  It also includes binary
files that represent much of the solution to assignment 4.  The `Makefile` has
been updated so that you do not need to have completed the first four
assignments in order to get full credit for this assignment.

There is a test script called `scripts/p5.py`, which you can use to test your
code.  Reading these tests will help you to understand the expected behavior of
the server.

The new commands and API extensions have been added to `protocol.h`.

You will need to understand many concepts to do well on this assignment.  You
will need to start early.  Some features, like using a `std::shared_mutex`, are
not very hard.  Some features, like using `fork()`, are difficult.  Note that
you can make a functional but insecure server by calling the `map()` and
`reduce()` functions from the main server process.  This will help when
debugging your interaction with .so files, and is a good way to get started on
the `KMR` requirement.

## Tips and Reminders

When you call `fork()` from a multithreaded process, the new child process will
only have one thread: a clone of the thread who called `fork()`.  There are no
guarantees about the state of any locks in the child process.  Therefore, it is
essential that you do not have the child access the key/value store: it could
wait forever.

If you `dlclose()` a .`so`, its functions are no longer available.  You will need
to keep open any `.so` that you have loaded, and only close them at shutdown time.

When calling `dlopen()`, you cannot re-use file names, even after deleting the
files.  You also cannot load a `.so` from a `std::vector`... you must use a
temporary file.  You should think carefully about how to make unique file names
to pass to `dlopen()`.

You do not need to enforce quotas on the `KMR` and `KVF` functions.

**Start Early**.  Just reading the code and understanding what is happening
takes time.  If you start reading the assignment early, you'll give yourself
time to think about what is supposed to be happening, and that will help you to
figure out what you will need to do.

As always, please be careful about not committing unnecessary files into your
repository.

Your server should **not** store plain-text passwords in the file.

## Grading

The `scripts` folder has two scripts that exercise the main portions of the
assignment: `KVF`, basic `KMR`, and process-based isolation.  These scripts use
specialized `Makefiles` that integrate some of the solution code with some of
your code, so that you can get partial credit when certain portions of your code
work.  Note that these `Makefiles` are very strict: they will crash on any
compiler warning.  You should *not* turn off the warnings; they are there to
help you. If your code does not compile with the scripts, you will not receive
any credit. If you have partial solutions and you do not know how to coerce the
code into being warning-free, you should ask the professor.

If the scripts pass, then you will receive full "functionality" points.  We will
manually inspect your code to determine if it is correct with regard to
atomicity, and to ensure that it is cleaning up after itself correctly.  As
before, we reserve the right to deduct "style" points if your code is especially
convoluted.  Please be sure to use your tools well.  For example, Visual Studio
Code (and emacs, and vim) have features that auto-format your code.  You should
use these features.

While it is our intention to give partial credit, *no credit will be given for
code that does not compile without warnings.*  If you decide to move functions
between files, or add files, or do other things that break the scripts in the
grading folder, then you will lose at least 10%. If you think some change is
absolutely necessary, speak with the professor first.

There are five main graded portions of the assignment:

* Do .so files load correctly and securely on the server?
* Can clients invoke functions on the server?
* Are map() and reduce() running in a child process?
* Is the child process using seccomp features?
* Is the program correct with regard to concurrency?

## Notes About the Reference Solution

You will need to implement `my_functable.cc`.  Note that every valid `.so` will
have a function called `map()` and a function called `reduce()`.  Also, note
that the `.cc` files that produce the .so files must avoid C++ name mangling,
through the use of `extern "C" {}`.  While you do not need to write any new
shared objects, it is good to understand the code that we provide.

The design of the `func_table` object is not completely specified for you.  You
will need to think about what fields it requires, and you will need a strategy
for having unique names.  The reference solution is 118 lines of code.

The implementation of `register_mr()` in `server/my_storage.cc` is very simple:
it just authenticates and then calls the `functable`'s `register_mr()`.
However, `functable::register_mr()` is not quite so simple.  It requires about
40 lines of code.

The implementation of `invoke_mr` is much more complex, because it needs to
`fork()` and `waitpid()`, manage `pipe()` objects, interact with `seccomp`, run
a `do_all_readonly()`, and interact with a child process by reading and writing
via pipes.  The reference solution is about 130 lines of code, including all of
the error handling.  This code also makes use of a helper function, which is run
by the child process.  The helper is the code that actually runs the functions
on the data that is extracted from the k/v store.  It is about 45 lines.

## Collaboration and Getting Help

You may work in teams of 2 for this assignment.  If you plan to work in a team,
you must notify the instructor by November 29th, so that we can set up your
repository access.  If you notify us after that date, we will deduct 10 points.
If you wish to have a different team than in the last assignment, or to disband
your team and work alone, please contact the professor by November 29th. If you
are working in a team, you should **pair program** for the entire assignment.
After all, your goal is to learn together, not to each learn half the material.

If you require help, you may seek it from any of the following sources:

* The professor and TAs, via office hours or Piazza
* The Internet, as long as you use the Internet as a read-only resource and do
  not post requests for help to online sites.

It is not appropriate to share code with past or current CSE 303 / CSE 403
students, unless you are sharing code with your teammate.

If you are familiar with `man` pages, please note that the easiest way to find a
man page is via Google.  For example, typing `man printf` will probably return
`https://linux.die.net/man/3/printf` as one of the first links.  It is fine to
use Google to find man pages.

StackOverflow is a wonderful tool for professional software engineers.  It is a
horrible place to ask for help as a student.  You should feel free to use
StackOverflow, but only as a *read only* resource.  In this class, you should
**never** need to ask a question on StackOverflow.

## Deadline

You should be done with this assignment before 11:59 PM on December 10th, 2021.
Please be sure to `git commit` and `git push` before that time, so that we can
promptly collect and grade your work.
