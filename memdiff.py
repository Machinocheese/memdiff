import hashlib
import tempfile

class memdiffGDBCommand(gdb.Command):
    """
    Wrapper of gdb.Command for "memdiff" command
    """
    def __init__(self, cmdname="memdiff"):
        self.cmdname = cmdname
        self.__doc__ = "Compares memory snapshots created via memsnap"
        super(memdiffGDBCommand, self).__init__(self.cmdname, gdb.COMMAND_DATA)

    #handles the memdiff <#> <#> case
    def print_mapping_diff(self, argc, argv, mapdiff):
        final_str = "ID".ljust(4) + ("Memsnap #" + argv[0]).center(35) + " || " + ("Memsnap #" + argv[1]).center(35) + "objfile\n"
        for i in range(0, len(mapdiff)):
            final_str += (str(i) + ":").ljust(4)
            if mapdiff[i][0] == (): #only modified has it
                final_str += print_green(mapdiff[i][1][0]['range'].center(35)) + " || " + mapdiff[i][1][0]['name'] + "\n"
                continue
            if mapdiff[i][1] == (): #only original has it
                final_str += " ".center(35) + " || " + print_red(mapdiff[i][0][0]['range'].center(35)) + mapdiff[i][0][0]['name'] + "\n"
                continue

            (md1, fd1) = mapdiff[i][0]
            (md2, fd2) = mapdiff[i][1]
            if md1['md5sum'] == md2['md5sum']:
                final_str += md1['range'].center(35) + " || " + md2['range'].center(35)
            else:
                final_str += print_green(md1['range'].center(35)) + " || " + print_red(md2['range'].center(35))

            final_str += md1['name']
            if md1['name'] != md2['name']:
                final_str += " (" + md2['name'] + ")"
            final_str += "\n"
        print(final_str)
        return

    # mapdiff = [((md1, fd1), (md2, fd2)),
    #            ((md3, fd3), (md4, fd4))
    #            ...]
    # md = metadata,
    # - name, start_addr, end_addr, range
    # fd = file descriptor
    # - stores the /tmp/ fd where the mapping bytes are stoprint_red
    def create_mapdiff(self, argc, argv):
        global records
        targets = []
        for i in range(0, 2):
            for elem in records[int(argv[i])]:
                (md, fd) = elem
                md['target_id'] = argv[i]
                #0 for print_green/original, 1 for print_red/modified
                targets.append((md, fd))
        targets.sort(key=record_compare)

        mapdiff = []
        last_seen = False
        #counter, last_seen, and md5sum all repeat. can i merge them into one?
        for i in range(0, len(targets)):
            if last_seen:
                last_seen = False
                continue
            (md1, fd1) = targets[i]
            md1['map_id'] = len(mapdiff)
            md1['md5sum'] = md5(fd1.name)
            if i != (len(targets) - 1):
                (md2, fd2) = targets[i + 1]
                md2['map_id'] = len(mapdiff)
                md2['md5sum'] = md5(fd2.name)
                if md1['range'] == md2['range']: #mapping range has stayed the same between memsnaps
                    last_seen = True
                    mapdiff.append(((md1, fd1), (md2, fd2)))
                else: #mapping range has changed!
                    if md1['target_id'] == 0: #original
                        mapdiff.append(((), (md1, fd1)))
                    else:
                        mapdiff.append(((md1, fd1), ()))
            else:
                if md1['target_id'] == 0: #original
                    mapdiff.append(((), (md1, fd1)))
                else:
                    mapdiff.append(((md1, fd1), ()))
        return mapdiff

    def print_byte_diff(self, argc, argv, mapdiff):
        mapid = int(argv[2])
        spacing = 73
        if mapid >= len(mapdiff) or mapid < 0:
            print("Invalid mapping number. Allowed values are: %d - %d" % (0, len(mapdiff) - 1))
            return
        (target1, target2) = mapdiff[mapid]
        if target1 == () or target2 == ():
            print("New mapping was created. No comparison can be made")
            return
        (md1, fd1) = target1
        (md2, fd2) = target2
        if md1['md5sum'] == md2['md5sum']:
            print("Mappings are identical")
            return
        else:
            print(("Memsnap #" + argv[0]).center(spacing) + " || " + ("Memsnap #" + argv[1]).center(spacing) + "   Symbols")
            xxd1 = tmpfile()
            xxd2 = tmpfile()
            result1 = execute("shell xxd %s > %s" % (mapdiff[mapid][0][1].name, xxd1.name))
            result2 = execute("shell xxd %s > %s" % (mapdiff[mapid][1][1].name, xxd2.name))
            for line1 in xxd1:
                line1 = line1[:-1]
                line2 = xxd2.readline()[:-1]
                if line1 != line2:
                    hex1, text1 = line1.split("  ") #hex1 = Addr: 00 11 22
                    hex2, text2 = line2.split("  ") #text = ...A...B..ZXCV
                    hex1 = hex1.split(" ")
                    hex2 = hex2.split(" ")
                    final1 = final2 = hex(int(hex1[0][:-1], 16) + int(md1['start_addr'], 16)) + ": "
                    result3 = execute("info symbol %s" % (final1[:-2])).rstrip()
                    for i in range(1, len(hex1)): #first one is the address, no need for comparison
                        for bot, top in ((0, 2), (2, 4)):
                            if hex1[i][bot:top] == hex2[i][bot:top]:
                                final1 += hex1[i][bot:top]
                                final2 += hex2[i][bot:top]
                            else:
                                final1 += print_green(hex1[i][bot:top])
                                final2 += print_red(hex2[i][bot:top])
                        final1 += " "
                        final2 += " "
                    final1 += " "
                    final2 += " "

                    for i in range(0, len(text1)):
                        if text1[i] == text2[i]:
                            final1 += text1[i]
                            final2 += text2[i]
                        else:
                            final1 += print_green(text1[i])
                            final2 += print_red(text2[i])

                    print(final1.center(spacing) + " || " + final2.center(spacing) + "   " + result3)
        return

    def invoke(self, arg_string, from_tty):
        self.dont_repeat() #prevents command repetition upon newline
        argc, argv = process_arguments(arg_string)
        if argc != 2 and argc != 3:
            print("Usage: memdiff <memsnap #> <memsnap #> to get mappings available to each")
            print("Usage: memdiff <memsnap #> <memsnap #> <mapping #>")
            string = ""
            if len(records) == 1:
                string = "0"
            elif len(records) > 1:
                string = "0 - " + str(len(records) - 1)
            print("Available memsnaps: " + string)
            return

        #sets up records (global variable) to allow for easier printing and access
        mapdiff = self.create_mapdiff(argc, argv)

        if argc == 2:  #prints a comparison between mappings in snapshots
            self.print_mapping_diff(argc, argv, mapdiff)
        if argc == 3:  #given a mapping, prints a comparison between bytes in that mapping between snapshots
            self.print_byte_diff(argc, argv, mapdiff)
        return

def print_red(text):
    retval = "\033[;31m%s\033[0m" % (text)
    return retval

def print_green(text):
    retval = "\033[;32m%s\033[0m" % (text)
    return retval

#returns a temporary file handle
def tmpfile(is_binary_file=False):
    mode = 'w+b' if is_binary_file else 'w+'
    return tempfile.NamedTemporaryFile(mode=mode)

#gets the md5 checksum of a file
def md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

#used to help sorting
def record_compare(item):
   (md, fd) = item
   return md['range']

#needed - otherwise gdb output from gdb.execute can't be accessed
def execute(gdb_command):
    logfd = tmpfile()
    result = None
    gdb.execute('set logging off') # prevent nested call
    gdb.execute('set height 0') # disable paging
    gdb.execute('set logging file %s' % logfd.name)
    gdb.execute('set logging overwrite on')
    gdb.execute('set logging redirect on')
    gdb.execute('set logging on')
    try:
        gdb.execute(gdb_command)
        gdb.flush()
        gdb.execute('set logging off')
        logfd.flush()
        result = logfd.read()
        logfd.close()
    except Exception as e:
        gdb.execute('set logging off')
        logfd.close()
        print(e)
    return result

def process_arguments(arguments):
    results = arguments.split(" ")
    return len(results), results

class memsnapGDBCommand(gdb.Command):
    def __init__(self, cmdname="memsnap"):
        self.cmdname = cmdname
        self.__doc__ = "Snapshots memory"
        super(memsnapGDBCommand, self).__init__(self.cmdname, gdb.COMMAND_DATA)

    def processMappings(self, mappings):
        results = []
        for elem in mappings:
            temp = {}
            spaces = [var for var in elem.split(" ") if var]
            temp['start_addr'] = spaces[0].split("-")[0]
            temp['end_addr'] = spaces[0].split("-")[1]
            temp['range'] = spaces[0]
            temp['permissions'] = spaces[1]
            temp['name'] = spaces[5].rstrip()

            if 'r' in temp['permissions']:
                results.append(temp)

        return results

    #this is called every time the command string is run
    def invoke(self, arg_string, from_tty):
        global records

        procinfo = execute("info proc")
        if procinfo == None:
            return
        
        procid = (procinfo.split("\n")[0]).split(" ")[1]
        with open('/proc/%s/maps' % procid) as f:
            content = f.readlines()

        #will extract all readable memory regions (marked with r in terms of permissions)
        mappings = self.processMappings(content)
        mapfiles = []

        #reads from memory regions and stores them in some corresponding tmpfiles
        for elem in mappings:
            recordfd = tmpfile(is_binary_file=True)
            out = execute("dump memory %s 0x%s 0x%s" % (recordfd.name, elem['start_addr'], elem['end_addr']))
            recordfd.flush()
            if out is None:
                recordfd.close()
            else:
                mapfiles.append((elem, recordfd))

        records.append(mapfiles)
        print("Creating memsnap " + str(len(records) - 1))
        return

records = []
memdiffGDBCommand()
memsnapGDBCommand()
