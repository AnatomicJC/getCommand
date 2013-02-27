#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import logging
from xml.dom import minidom

BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(8)

#The background is set with 40 plus the number of the color, and the foreground with 30

#These are the sequences need to get colored ouput
RESET_SEQ = "\033[0m"
COLOR_SEQ = "\033[1;%dm"
BOLD_SEQ = "\033[1m"

def formatter_message(message, use_color = True):
    if use_color:
        message = message.replace("$RESET", RESET_SEQ).replace("$BOLD", BOLD_SEQ)
    else:
        message = message.replace("$RESET", "").replace("$BOLD", "")
    return message

COLORS = {
    'WARNING': YELLOW,
    'INFO': WHITE,
    'DEBUG': BLUE,
    'CRITICAL': YELLOW,
    'ERROR': RED
}

class ColoredFormatter(logging.Formatter):
    def __init__(self, msg, use_color = True):
        logging.Formatter.__init__(self, msg)
        self.use_color = use_color

    def format(self, record):
        levelname = record.levelname
        if self.use_color and levelname in COLORS:
            levelname_color = COLOR_SEQ % (30 + COLORS[levelname]) + levelname + RESET_SEQ
            record.levelname = levelname_color
        return logging.Formatter.format(self, record)

class getCommand(object):
    def __init__(self, file):
        self.file = file

    def getStringsData(self):
        strings_command = 'strings "%s"' % self.file
        strings_data = os.popen(strings_command).read()
        xml_pos = strings_data.find('<?xml')
        strings_data = strings_data[xml_pos:]
        end_pos = strings_data.find('</assembly>') + 11
        return strings_data[:end_pos]

    def getFileData(self):
        file_command = 'file "%s"' % self.file
        file_data = os.popen(file_command).read()
        l = file_data.split(': ')
        n = len(l)
        d = {}

        # this awful piece of code convert file output to a dictionnary
        for i in range(n-1, 0, -1):
            lcount = len(l[i].split(', '))
            if lcount == 1: lcount = 2 # lcount is at least equal to 2 to prevent empty values
            d[l[i-1].split(', ').pop()] = " ".join(l[i].split(', ')[:lcount-1]).replace('\n', '')

        return d

    def getInnoCommand(self):
        return '"./%s" /SP /VERYSILENT /NORESTART' % self.file

    def getNSISCommand(self):
        return '"./%s" /S' % self.file

    def getMozillaCommand(self):
        return '"./%s" -ms' % self.file

    def getMSI32Command(self):
        return 'msiexec /i "%s" /qn ALLUSERS=1' % self.file

    def getMSI64Command(self):
        return '$(cygpath -W)/sysnative/msiexec /i "%s" /qn ALLUSERS=1' % self.file

    def getRegCommand(self):
        return 'regedit /s "%s"' % self.file

    def getBatCommand(self):
        return '"./%s"' % self.file

    def getCommand(self):
        log.debug("Parsing %s:" % self.file)

        strings_data = self.getStringsData()
        file_data = self.getFileData()

        if "PE32 executable" in file_data[self.file]:
            # Not an MSI file, maybe InnoSetup or NSIS
            log.debug("%s is a PE32 executable" % self.file)
            installer = None

            if strings_data.startswith('<?xml'):
                xmldoc = minidom.parseString(strings_data)
                identity = xmldoc.getElementsByTagName('assemblyidentity')

                if len(identity) == 0:
                    # if assemblyIdentity don't exists, try assemblyIdentity
                    identity = xmldoc.getElementsByTagName('assemblyIdentity')

                if identity > 0:
                    if identity[0].hasAttribute('name'):
                        installer = identity[0].getAttribute('name')

            if installer == "JR.Inno.Setup":
                log.debug("InnoSetup detected")
                return self.getInnoCommand()
            elif installer == "Nullsoft.NSIS.exehead":
                log.debug("NSIS detected")
                return self.getNSISCommand()
            elif installer == "7zS.sfx.exe":
                log.debug("7zS.sfx detected (Mozilla app inside ?)")
                if not os.system("grep Mozilla '%s' > /dev/null" % self.file): # return code is 0 if file match
                    log.debug("Mozilla App detected")
                    return self.getMozillaCommand()
                else:
                    return log.info("I can't get a command for %s" % self.file)
            else:
                return log.info("I can't get a command for %s" % self.file)

        elif file_data[self.file] == "Composite Document File V2 Document Little Endian":
            # MSI files
            if "Template" in file_data:
                if "x64" in file_data['Template']:
                    log.debug("%s is a x64 MSI file" % self.file)
                    return self.getMSI64Command()
                elif "Intel" in file_data['Template']:
                    log.debug("%s is a 32-bit MSI file" % self.file)
                    return self.getMSI32Command()
                else:
                    return log.info("I can't get a command for %s" % self.file)
            else:
                return log.info("No Template Key for %s" % self.file)
        elif file_data[self.file] == 'ASCII text':
            if self.file.endswith(".reg"):
                log.debug("Reg file detected")
                return self.getRegCommand()
            elif self.file.endswith(".bat"):
                log.debug("MS-DOS Batch file detected")
                return self.getBatCommand()
        else:
            return log.info("I don't know what to do with %s (%s)" % (self.file, file_data[self.file]))

if __name__ == "__main__":
    level = logging.DEBUG
    log = logging.getLogger('getCommand')
    log.setLevel(level)
    formatter = ColoredFormatter("%(levelname)-18s %(message)s")
    handler_stream = logging.StreamHandler()
    handler_stream.setFormatter(formatter)
    #handler_stream.setLevel(level)
    log.addHandler(handler_stream)

    for file in os.listdir('.'):
        c = getCommand(file)
        command = c.getCommand()
        if command is not None:
            log.info("%s: %s" % (file, command))
        print
