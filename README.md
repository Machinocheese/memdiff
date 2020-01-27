# memdiff
Compares memory between different instances in program execution
To install, just run `source <memdiff.py file location>` in gdb.

How to use:
1. Ensure the program is running.
2. Use `memsnap` to record the current memory state of the program.
3. Use `memsnap` to record another memory state.
4. Use `memdiff <memsnap #> <memsnap #>` to view a list of all comparable mappings.
5. Use `memdiff <memsnap #> <memsnap #> <mapping #>` to view all bytes that have changed.
