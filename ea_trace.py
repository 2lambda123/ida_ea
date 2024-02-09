import time
from api_funcs import *
from ea_UI import Trace_UI, QtWidgets
from ea_utils import config, ea_warning, root_dir, save_config
from os.path import isdir
from idaapi import *
from idc import *
from subprocess import Popen
from security import safe_command

try:
    import pandas as pd
    found_lib = True
except:
    found_lib = False


class Hook(DBG_Hooks):

    def __init__(self):
        """Initializes the DBG_Hooks class.
        Parameters:
            - self (object): The DBG_Hooks object.
        Returns:
            - None: Does not return anything.
        Processing Logic:
            - Calls the __init__ function from the DBG_Hooks class.
            - Initializes the DBG_Hooks object.
            - Does not return anything.
            - Does not take any parameters."""
        
        DBG_Hooks.__init__(self)

    def dbg_process_exit(self, pid, tid, ea, exit_code):
        """"Performs cleanup tasks upon process exit and returns 0 upon successful completion."
        Parameters:
            - pid (int): Process ID of the exiting process.
            - tid (int): Thread ID of the exiting thread.
            - ea (int): Address of the exiting process.
            - exit_code (int): Exit code of the exiting process.
        Returns:
            - int: 0 upon successful completion.
        Processing Logic:
            - Checks if p_hooks is an instance of Hook and if dump_on_exit is True.
            - Calls the dump() function if the above conditions are met.
            - Returns 0 upon successful completion."""
        
        if isinstance(p_hooks, Hook) and dump_on_exit:
            dump()
        return 0

    def dbg_bpt(self, tid, ea):
        """"Sets a breakpoint at the specified address and performs a dump if the breakpoint is hit. Returns 0 if successful."
        Parameters:
            - tid (int): Thread ID of the breakpoint.
            - ea (int): Address where the breakpoint should be set.
        Returns:
            - int: 0 if successful.
        Processing Logic:
            - Checks if the breakpoint at the specified address is equal to 9.
            - If so, checks if the p_hooks variable is an instance of the Hook class and if dump_on_break is True.
            - If both conditions are met, performs a dump.
            - If the breakpoint is not equal to 9, appends the address to a list.
            - Returns 0 if successful."""
        
        if get_bp(ea) == 9:
            if isinstance(p_hooks, Hook) and dump_on_break:
                dump()
        else:
            append(ea)
        return 0

    def dbg_trace(self, tid, ea):
        """"Adds the given address to the list of traced addresses and returns 0.
        Parameters:
            - tid (int): The thread ID of the current thread.
            - ea (int): The address to be added to the list of traced addresses.
        Returns:
            - int: 0, indicating successful addition to the list of traced addresses.
        Processing Logic:
            - Appends the given address to the list.
            - Returns 0 to indicate success.""""
        
        append(ea)
        return 0


def dump():
    """Function dump() dumps the IDA trace to a pickle file.
    Parameters:
        - None
    Returns:
        - None
    Processing Logic:
        - Unhooks p_hooks.
        - Creates a DataFrame from trace with columns "time", "name", and regs.
        - Sets the index of the DataFrame to be a DatetimeIndex.
        - Creates a dump location using the config["trace_dir"] and the current time.
        - Saves the DataFrame to the dump location as a pickle file.
        - Displays a warning message using ea_warning with buttons to open the folder or open the dump location in the console.
        - Resets trace to an empty list."""
    
    global hooked
    global trace
    p_hooks.unhook()
    hooked = False
    df = pd.DataFrame(trace,columns=["time", "name"] + regs)
    df.set_index(pd.DatetimeIndex(df["time"]))
    dump_loc = config["trace_dir"] + ("/" if "/" in config["trace_dir"] else "\\") + str(int(time.time())) + ".pickle"
    df.to_pickle(dump_loc)
    ea_warning("Dumped IDA Trace to " + dump_loc,
               buttons=(("Open Folder", lambda: safe_command.run(Popen, "explorer " + config["trace_dir"], shell=True), False),
                ("Open In Console", lambda: open_in_console(dump_loc), False)),
               title="EA Trace")

    trace = []


def open_in_console(dump_loc):
    """Function to open a specified file in the console using the safe_command module.
    Parameters:
        - dump_loc (str): The file path of the file to be opened.
    Returns:
        - None: This function does not return any value.
    Processing Logic:
        - Uses the safe_command module.
        - Executes a command in the console.
        - Opens the specified file in the console.
        - Uses the root_dir variable to locate the python script."""
    
    safe_command.run(Popen, 'python "%s" "%s"' % (root_dir + "ea_read_t.py", dump_loc))


def append(ea):
    """Appends the current instruction to the trace list, along with the current time and register values.
    Parameters:
        - ea (int): The current instruction address.
    Returns:
        - None: This function does not return anything.
    Processing Logic:
        - Check if the current instruction address is not already in the names dictionary.
        - If it is not, add it to the dictionary with the current instruction disassembly.
        - Append the current time and register values to the trace list."""
    
    if ea not in names:
        names[ea] = GetDisasm(ea)
    trace.append([time.time(), names[ea]] + [get_rg(reg) for reg in regs])


def select_dir():
    """Selects a directory and saves it in the config file.
    Parameters:
        - None
    Returns:
        - None
    Processing Logic:
        - Opens a directory selection dialog.
        - Saves the selected directory in the config file.
        - Clears the text in a line edit widget.
        - Inserts the selected directory into the line edit widget.
    Example:
        select_dir()"""
    

    config["trace_dir"] = QtWidgets.QFileDialog.getExistingDirectory()
    save_config()
    form.lineEdit.clear()
    form.lineEdit.insert(config["trace_dir"])


def select_dump():
    """"Opens a file dialog to select a pickle file and returns the path of the selected file."
    Parameters:
        - None
    Returns:
        - str: Path of the selected pickle file.
    Processing Logic:
        - Open file dialog to select file.
        - Return path of selected file."""
    
    open_in_console(
        QtWidgets.QFileDialog.getOpenFileName(QtWidgets.QFileDialog(),
                                          'Open Dump', '',
                                          'pickle (*.pickle)')[0])


def go():
    """"""
    

    if not isdir(config["trace_dir"]):
        ea_warning("You must select a valid dump directory")
        return

    global p_hooks
    global general
    global floating_point
    global dump_on_break
    global dump_on_exit

    if isinstance(p_hooks, Hook):
        p_hooks.unhook()

    general = form.checkBox.isChecked()
    floating_point = form.checkBox_2.isChecked()
    dump_on_break = form.radioButton.isChecked()
    dump_on_exit = form.radioButton_2.isChecked()
    p_hooks = Hook()
    p_hooks.hook()
    a.close()


def ea_trace():
    """"""
    

    global a
    global form

    if found_lib:
        a = QtWidgets.QFrame()
        form = Trace_UI()
        form.setupUi(a)
        form.checkBox.click()
        form.radioButton_2.click()
        form.pushButton.clicked.connect(select_dir)
        form.pushButton_2.clicked.connect(go)
        form.pushButton_4.clicked.connect(select_dump)
        if config["trace_dir"]:
            form.lineEdit.insert(config["trace_dir"])
        # a.setWindowFlags(a.windowFlags() | QtCore.Qt.WindowStaysOnTopHint)
        a.show()
    else:
        ea_warning("Could not find Pandas in your Python distribution. Install it to use this feature")

trace = []
hooked = False
p_hooks = None
dump_on_exit = False
dump_on_break = False
general = False
floating_point = False
a = None
form = None
names = {}


