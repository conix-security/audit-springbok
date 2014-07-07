#! /usr/bin/env python
# -*- coding: utf-8 -*-

import sys
sys.path.append("../")

import os
import re
from Gtk import Gtk_Main

# Linux console color #
WHITE = '\033[37m'
BLUE = '\033[34m'
RED = '\033[31m'
GREEN = '\033[32m'
YELLOW = '\033[33m'
CYAN = '\033[36m'

# used to redirect output #
SYS_OUT = sys.stdout
SYS_ERR = sys.stderr
DEV_NULL = open(os.devnull, 'w')


# get reference output #
def get_ref(file):
    content = ''
    with open(file, 'r') as content_file:
        content += content_file.read()

    if content[-1] == '\n':
        content = content[0:-1]

    return content


# print main output #
def display_main():
    print BLUE + ' ' * 15 + '┌' + '─' * 24 + '┐'
    print ' ' * 15 + '│' + ' ' * 5 + GREEN + 'Springbok test' + BLUE + ' ' * 5 + '│'
    print ' ' * 15 + '└' + '─' * 24 + '┘'
    print '\n.' + WHITE


# print folder name #
def display_folder_test(file):
    print BLUE + '├─ [ ' + YELLOW + file + BLUE + ' ]' + WHITE


# print result OK in green or KO in red #
def display_result(file, res, ref):
    print BLUE + '├─── ' + CYAN + file + BLUE + ' ' * (50 - len(file)),
    if re.search(ref, res, re.S):
        print '[' + GREEN + 'OK' + BLUE + ']' + WHITE
    else:
        print '[' + RED + 'KO' + BLUE + ']' + WHITE
        print RED + 'Res : \n' + WHITE + res
        print RED + 'Ref : \n' + WHITE + ref


# redirect stdout stderr to /dev/null #
def redirect_null():
    sys.stdout = DEV_NULL
    sys.stderr = DEV_NULL


# reset stdout and stderr #
def redirect_standard():
    sys.stdout = SYS_OUT
    sys.stderr = SYS_ERR


def launch_test():
    """ Springbok test.
    This function initialize a no graphic mode and :
    - get all folder in current folder no starting with '.'
    - for each folder:
        - import the test.py file
        - call the test function for each file in the folder matching 'test_.*\.txt'
    """
    # get real folder path
    folder = os.path.dirname(os.path.realpath(__file__))
    # call to initialize our main instance to no-graphic mode
    Gtk_Main.Gtk_Main('no-graphic')
    display_main()
    # list all files
    for file in os.listdir(folder):
        # test if directory
        if os.path.isdir(file) and not file.startswith('.'):
            # get folder path
            sub_folder = os.path.join(folder, file)
            # import test kit (all file in subfolder must implement this)
            _test_kit = __import__(file + '.test', fromlist=['a'])
            display_folder_test(file)
            # list all test file in sub-folder
            for file_test in os.listdir(sub_folder):
                name, ext = os.path.splitext(os.path.join(sub_folder, file_test))
                # check if it is a file to test (file to test must implement this pattern)
                if file_test.startswith('test_') and ext == '.txt':
                    split = re.split('_|\.', file_test)
                    # get reference
                    ref = get_ref(os.path.join(sub_folder, 'ref_' + split[1] + ext))
                    redirect_null()
                    res = _test_kit.test(os.path.join(sub_folder, file_test))
                    redirect_standard()
                    display_result(file_test, res, ref)


if __name__ == '__main__':
    launch_test()
