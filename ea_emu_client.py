import socket

from api_funcs import *
from cPickle import dumps, loads
from ea_UI import Emulate_UI
from ea_utils import QtWidgets, ea_warning, get_bits, root_dir
from idaapi import *
from os import name
from subprocess import Popen
from time import sleep
from security import safe_command

# Importing Unicorn Emulator directly into the IDAPython environment causes instability in IDA (random crashes ect.)
# As a result, Unicorn emulator is decoupled from IDA and runs as a seperate process communicating with IDA using a local socket (port 28745)
# The following client code runs within IDAPython and ships emulation requests to ea_emu_server which is a pure Python process

class Hook(DBG_Hooks):

    def __init__(self):
        """This function initializes the DBG_Hooks class.
        Parameters:
            - self (object): The object to be initialized.
        Returns:
            - None: This function does not return anything.
        Processing Logic:
            - Initialize the DBG_Hooks class.
            - No parameters are needed.
            - No return value is expected.
            - Calls the __init__ function of the DBG_Hooks class."""
        
        DBG_Hooks.__init__(self)

    def dbg_bpt(self, tid, ea):
        """"Sets a breakpoint at the specified address for the given thread ID and returns 0 if successful."
        Parameters:
            - tid (int): Thread ID to set breakpoint for.
            - ea (int): Address to set breakpoint at.
        Returns:
            - int: 0 if breakpoint was successfully set.
        Processing Logic:
            - Sends a command to set breakpoint.
            - Returns 0 if successful."""
        
        send()
        return 0

    def dbg_step_into(self):
        """"Executes a step into debugging command and returns 0 upon completion."
        Parameters:
            - self (object): The current object.
        Returns:
            - int: 0 upon successful completion of the step into command.
        Processing Logic:
            - Executes the send() function.
            - Returns 0 upon completion."""
        
        send()
        return 0

    def dbg_step_until_ret(self):
        """"""
        
        send()
        return 0

    def dbg_step_over(self):
        """"Executes a single step in the debugging process and returns 0 upon completion."
        Parameters:
            - self (object): The debugger object.
        Returns:
            - int: 0 upon completion of the step.
        Processing Logic:
            - Executes a single step.
            - Sends the step command.
            - Returns 0 upon completion."""
        
        send()
        return 0


def send(addr=None, code=None):
    """Sends the specified address and code to the server for emulation and annotation.
    Parameters:
        - addr (int): The address to be sent to the server for emulation.
        - code (str): The code to be sent to the server for annotation.
    Returns:
        - None: Does not return any value.
    Processing Logic:
        - Checks if the process is paused/suspended.
        - If the process is not paused/suspended, it gets the current instruction pointer (RIP) and sets a breakpoint at that address.
        - Reads the memory at the specified address.
        - If the process was paused/suspended, it removes the breakpoint.
        - Creates a socket and connects to the server.
        - Sends the address, code, number of bits, and server print to the server.
        - Receives data from the server and processes it accordingly.
        - Closes the socket.
        - If the annotation flag is set, it checks if the RIP is in the arguments and removes it.
        - Loops through the arguments and checks if there are any changes to the registers.
        - If there are changes, it adds a comment to the address with the register changes.
        - If there are no changes, it adds a comment to the address stating that there were no register changes."""
    

    if get_process_state() != -1:
        ea_warning("Process must be paused/suspended")

    else:
        if not addr:

            flags = None
            addr = get_rg("RIP")
            bp = get_bp(addr,False)

            if bp:
                flags = bp.flags
                bp.flags = 2
                update_bpt(bp)

            code = dbg_read_memory(addr & 0xfffffffffffff000, 0x1000)

            if flags:
                bp.flags = flags
                update_bpt(bp)

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            s.connect((TCP_IP, TCP_PORT))
        except socket.error:
            launch_server()
            sleep(0.5)
            s.connect((TCP_IP, TCP_PORT))

        s.send(dumps(("emu", (addr,code, get_bits(), server_print))))
        error = False

        while True:
            data = s.recv(BUFFER_SIZE)
            if not data: break
            func, args = loads(data)

            if func == "result":
                break
            if func == "error":
                ea_warning(args)
                error = True
                break

            s.send(dumps(globals()[func](*args)))

        s.close()

        if not error and annotate:

            rip = get_rg("RIP")

            if rip in args:
                del args[rip]

            for c, v in args.items():
                v = [i for i in v if i[0] not in ("rip", "eip")]
                comment = GetCommentEx(c, 0)

                if v:
                    annotation = " ".join(a + "=" + hex(b).replace("L", "") for a, b in v)
                    if comment and "e:" in comment:
                        comment = comment[:comment.find("e:")].strip(" ")
                    MakeComm(c, (comment if comment else "").ljust(10) + " e: " + annotation)
                else:
                    if comment and "e:" in comment:
                        comment = comment[:comment.find("e:")].strip(" ")
                    MakeComm(c, (comment if comment else "").ljust(10) + " e: " + "No reg changes")


def launch_server():
    """"Launches an emulation server as a separate process."
    Parameters:
        - None
    Returns:
        - None
    Processing Logic:
        - Uses safe_command.run() to launch the server.
        - Sets server_running to True.
        - Uses Popen to execute the command.
        - Uses root_dir to specify the directory.
    Example:
        launch_server()"""
    

    # Launch emulation server as a seperate process (see top for details why)
    global server_running
    safe_command.run(Popen, "python \"%sea_emu_server.py\"" % root_dir, shell=True if name=="posix" else False)

    server_running = True

def close_server(arg):
    """Closes the server by setting the global variable server_running to False.
    Parameters:
        - arg (any): Optional argument, not used in this function.
    Returns:
        - None: No return value.
    Processing Logic:
        - Sets server_running to False.
        - Creates a socket object.
        - Connects to the specified TCP_IP and TCP_PORT.
        - Sends a message to the server to quit.
    Example:
        close_server()"""
    

    global server_running

    server_running = False

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((TCP_IP, TCP_PORT))
    s.send(dumps(("quit", (0, 0, 0, 0))))


def ea_emulate():
    """"""
    

    global form
    global a
    global server_running

    if not server_running:
        launch_server()

    a = QtWidgets.QFrame()
    form = Emulate_UI()
    form.setupUi(a)
    if hooked:
        form.checkBox.click()

    form.checkBox.stateChanged.connect(toggle_hooking)
    form.pushButton.clicked.connect(a.close)
    form.pushButton_2.clicked.connect(send)
    form.checkBox_3.stateChanged.connect(set_annotate)
    form.checkBox_2.stateChanged.connect(set_server_print)
    # a.setWindowFlags(a.windowFlags() | QtCore.Qt.WindowStaysOnTopHint)
    a.closeEvent = close_server
    a.show()




def toggle_hooking(state):
    """"""
    

    global h
    global hooked

    if state:
        if not hooked:
            h = Hook()
            h.hook()
            hooked = True
    else:
        h.unhook()
        hooks = False


def set_annotate(state):
    """"""
    
    global annotate
    annotate = True if state else False


def set_server_print(state):
    """"""
    
    global server_print
    server_print = True if state else False


TCP_IP = '127.0.0.1';
TCP_PORT = 28745;
BUFFER_SIZE = 0x4000;
comments = []

file_name = None
h = None
hooked = False
form = None
a = None
bp = None
server_running = False
annotate = True
server_print = True

