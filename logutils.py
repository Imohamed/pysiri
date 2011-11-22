"""
Useful logging related utilities.

Copyright (C) 2011 Jared Hobbs

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""
import os
import re
import sys
import logging
import platform

# Configure the default logger returned by the logging.getLogger() method

# logging.basicConfig(level=logging.INFO, format="%(message)s")


# Private variables
_dateTimeFormat = "%y-%m-%d %H:%M:%S"
_infoLevelColor = '\x1b[32m' # green

def _getDefaultEmit(fn):
    # The FileHandler subclasses the StreamHandler so we need to
    # get rid of the ansi escape characters before writing to disk
    _ansiEscapes = re.compile(r'(\x1b\[0m)|(\x1b\[3[1235]m)')
    def new(*args):
        args[0].msg = re.sub(_ansiEscapes, "", args[0].msg)
        return fn(*args)
    return new

def _getColorEmit(fn):
    # This doesn't work on Windows since Windows doesn't support 
    # the ansi escape characters
    def new(handler):
        levelno = handler.levelno
        if(levelno >= logging.CRITICAL):
            color = '\x1b[31m' # red
        elif(levelno >= logging.ERROR):
            color = '\x1b[31m' # red
        elif(levelno >= logging.WARNING):
            color = '\x1b[33m' # yellow
        elif(levelno >= logging.INFO):
            color = _infoLevelColor # green or normal 
        elif(levelno >= logging.DEBUG):
            color = '\x1b[35m' # pink
        else:
            color = '\x1b[0m' # normal
        handler.msg = color + handler.msg + '\x1b[0m'  # normal
        return fn(handler)
            
    return new

# Some methods to reconfigure the default logger

def turnOffInfoColor():
    global _infoLevelColor
    _infoLevelColor = '\x1b[0m' # normal

def setLogLevel(level):
    logger.setLevel(level)

def enableLogging():
    logger.disabled = False

def disableLogging():
    logger.disabled = True

def setLogFormat(format="%(message)s", verbose=False):
    if verbose:
        format = "%(asctime)s (%(levelname)s): %(message)s"
    formatter = logging.Formatter(format, _dateTimeFormat)
    for handler in logger.handlers:
        handler.setFormatter(formatter)

def addLogFile(filename, format="%(asctime)s (%(levelname)s): %(message)s"):
    handler = logging.FileHandler(filename, 'a')
    handler.emit = _getDefaultEmit(handler.emit)
    if platform.system() != 'Windows':
        formatter = logging.Formatter(format, _dateTimeFormat)
    handler.setFormatter(formatter)
    logger.addHandler(handler)

def closeLogFiles():
    """
    Close all log files and remove file handlers.
    """
    fileHandlers = [h for h in logger.handlers if isinstance(h, logging.FileHandler)]
    for handler in fileHandlers:
        handler.close()
        logger.removeHandler(handler)


_customLoggerID = 0
def makeLogger(level=logging.INFO,
               format="%(message)s",
               verbose=False,
               logFile=None,
               color=False,
               stream=True,
               mode='a'):
    """
    Create a custom logger with the specified properties.
    """
    global _customLoggerID
    logger = logging.getLogger('LOGGER_%d' % _customLoggerID)
    _customLoggerID = _customLoggerID + 1
    logger.setLevel(level)
    if verbose:
        format = "%(asctime)s (%(levelname)s): %(message)s"
    formatter = logging.Formatter(format, _dateTimeFormat)
    if stream:
        streamHandler = logging.StreamHandler()
        if platform.system() != 'Windows' and color:
            streamHandler.emit = _getColorEmit(streamHandler.emit)
        streamHandler.setFormatter(formatter)
        logger.addHandler(streamHandler)
    if logFile:
        fileHandler = logging.FileHandler(logFile, mode=mode, delay=True)
        if platform.system() != 'Windows':
            fileHandler.emit = _getDefaultEmit(fileHandler.emit)
        fileHandler.setFormatter(formatter)
        logger.addHandler(fileHandler)
    return logger


# Define standard loggers

# Expose the root logger as an attribute of this module
logger = makeLogger(color=True)

# Create a special "null" logger that prints no messages
nullLogger = makeLogger(level=logging.CRITICAL + 1)

# Create a special logger that prints INFO messages to the screen
screenLogger = makeLogger()

# Create a special logger that prints debug messages
debugLogger = makeLogger(level=logging.DEBUG, color=True)


# Test code

def _test():
    msg = "Hello %s"
    arg = "World!"

    print "Default logger..."
    sys.stdout.write("info msg: ")
    sys.stdout.flush()
    logger.info(msg, arg)
    sys.stdout.write("warning msg: ")
    sys.stdout.flush()
    logger.warn(msg, arg)
    sys.stdout.write("error msg: ")
    sys.stdout.flush()
    logger.error(msg, arg)
    sys.stdout.write("debug msg: ")
    sys.stdout.flush()
    logger.debug(msg, arg)
    print
    print

    print "Debug logger..."
    sys.stdout.write("info msg: ")
    sys.stdout.flush()
    debugLogger.info(msg, arg)
    sys.stdout.write("warning msg: ")
    sys.stdout.flush()
    debugLogger.warn(msg, arg)
    sys.stdout.write("error msg: ")
    sys.stdout.flush()
    debugLogger.error(msg, arg)
    sys.stdout.write("debug msg: ")
    sys.stdout.flush()
    debugLogger.debug(msg, arg)
    print

    print "disableLogging()..."
    disableLogging()
    sys.stdout.write("info msg: ")
    sys.stdout.flush()
    logger.info(msg, arg)
    print
    print

    print "enableLogging()..."
    enableLogging()

    print "setLogFormat(verbose=True)..."
    setLogFormat(verbose=True)

    sys.stdout.write("info msg: ")
    sys.stdout.flush()
    logger.info(msg, arg)
    sys.stdout.write("warning msg: ")
    sys.stdout.flush()
    logger.warn(msg, arg)
    sys.stdout.write("error msg: ")
    sys.stdout.flush()
    logger.error(msg, arg)
    sys.stdout.write("debug msg: ")
    sys.stdout.flush()
    logger.debug(msg, arg)
    print
    print

    tmpFile = "logutils-log.txt"
    try:
        print 'addLogFile("%s")' % tmpFile
        addLogFile(tmpFile, format='%(message)s')
        sys.stdout.write("info msg: ")
        sys.stdout.flush()
        logger.info(msg, arg)
        print
        closeLogFiles()
    except TypeError:
        raise
    finally:
        log = open(tmpFile)
        sys.stdout.write("Line from log: ")
        sys.stdout.flush()
        print log.readline()
        log.close()
        os.remove(tmpFile)

    sys.stdout.write("null logger: ")
    sys.stdout.flush()
    nullLogger.info(msg, arg)
    print

    sys.stdout.write("custom logger: ")
    sys.stdout.flush()
    logger2 = makeLogger(format='CUSTOM: %(message)s')
    logger2.info(msg, arg)

if __name__ == '__main__':
    _test()
