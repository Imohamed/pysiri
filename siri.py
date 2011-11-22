#!/usr/bin/env python
"""
This is a simple library to interact with Siri. It's based off the work done by
Applidium (http://applidium.com/en/news/cracking_siri/) and the code they
released (https://github.com/applidium/Cracking-Siri). 
 
Requires plutil which means you need to be running on a Mac.

Requires PyAudio (http://people.csail.mit.edu/hubert/pyaudio/), 
audiospeex from py-audio (http://code.google.com/p/py-audio/),
biplist (https://github.com/wooster/biplist), and the speexEnc binary (compiled
from the sources found https://github.com/applidium/Cracking-Siri).
 
The audio dependencies are only used when communicating with the real Siri
server; they aren't required if you simply want to recover your keys.
 
The compiled code included in this directory will work on an x86_64 Mac. You'll
need to compile the code yourself if you're on something else.
 
To get Siri authentication keys for your iPhone 4S, you'll need to install the
"ca.crt" CA certificate to your iPhone. The easiest way to install it is to
email the "ca.crt" file to yourself. Open the email on your iPhone 4S and
install it.

After installing the certificate, run this script as root with the --server
option: sudo ./siri.py --server --save-keys

Change the DNS server on the iPhone to the IP of the computer running this
script (Settings -> Wi-Fi -> <blue arrow on connected network> -> DNS)

Open Siri and say something. You should see your speech packets scroll by. Exit
the script with Ctrl+C (you'll probably have to press it twice) and your keys 
will be displayed at the bottom of the console. They'll also be saved in a
pickle file in the current directory (where they're used in the client
application of this script).

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
import sys
import ssl
import time
import wave
import zlib
import uuid
import socket
import pprint
import urllib
import logging
import optparse
import commands
import plistlib
import cPickle as pickle
from multiprocessing import Process

def debug(t, v, tb):
    import traceback, pdb
    traceback.print_exception(t, v, tb)
    print
    pdb.pm()

# Private variables
_dateTimeFormat = "%y-%m-%d %H:%M:%S"
_infoLevelColor = '\x1b[32m' # green
_customLoggerID = 0

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

def makeLogger(level=logging.INFO,
               format="%(message)s"):
    """
    Create a custom logger with the specified properties.
    """
    global _customLoggerID
    logger = logging.getLogger('LOGGER_%d' % _customLoggerID)
    _customLoggerID += 1
    logger.setLevel(level)
    formatter = logging.Formatter(format, _dateTimeFormat)
    streamHandler = logging.StreamHandler()
    try:
        streamHandler.emit = _getColorEmit(streamHandler.emit)
    except:
        pass
    streamHandler.setFormatter(formatter)
    logger.addHandler(streamHandler)
    return logger

logger = makeLogger()
debugLogger = makeLogger(level=logging.DEBUG)

PEM = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAqvmSuDVkmfNFgFQTPUEXeiCu92ic71WssXD2+KAd+0VZ2OjU
YDTh4l76YI8fc37eqNkftiPtutTy1UBglA15vR5c6wboehWPsTRGBA58MrQairue
7ZbG40ePoDkGtULhx3YEAhW9HBsJtgFxwiajrAFV1nq+4TaCxbuzu8wlUjz3m+im
MrM2/GBaNA9BjnBAt2aXaT4l2vi1OvU3BwTPo4vPXh+7zGAmu0zPMnzHUvxXy8Sb
AafR8ymqhDjTkaN4GQDsiGfGGOZC5MFus+XmaZYZMUMwPBzVZ2i5K19MP8DiYqaI
E09OkEAljPj30QYrScGwHTidF5Rqf1B6unKaAwIDAQABAoIBAByNu6wZ9qgjUash
32iucz5JMQ9OoE70LvgfVo+lJfyt01h/YeCDVGoa1JPFs0n1mTf3su0XSP+XyspE
ixyOt5MW/AugRrkE2s+MXFkXFjTdkUU0GlGxiZuxetIWVAF3nv9RvU+f08pa1Z9Y
1GfJTjJOssg0DabNFL/zHgwyBtWZ5PZnmzL9QboRUDdlTY9MUoaqt0MW+F/vYdHx
dD3mFmh8mbde5YaI2miqKs00JUDnowLpSLw52ea/2w6o2IfxYB2/+AhSk4rpQsxW
HJ5ZQEj8wc8juiEQ5uHLpfx7NbdwTC35gQ1jw0WNduSh6OEq09S0Et9KytXQjDwd
8cVcdZECgYEA3w0ScQlo9DrrSJDuMXU+fd1+29O7Uffk7LJIvqwxygRu6gJdwKiB
8N0ToNqc+GX0ZOjmhRDDP3No/GtA6nAU3L3zYVTo4AUSK5Hpx5aoh1wb7HcJ2Iov
SsWxoV9Yv5nkU26thkQ/zetATuV2rneD9HxnYdkarPaJscl4JDHH0UsCgYEAxDsu
lUdnwwRfzRDEjslGTSeToAkY7oezEp/wpY8LthtJ2JyaXIBRi9Yd98o0R/dfMbiw
Y/r7xZdnwc2P9mXhZ6lcC2qiYk/f1ur4kCh+Q0iU++pk6Ub3V9AhnVlXZyOap71d
fQ0wF54VCuGXEWZVQlggPTTZ8PT3fnpWaTcOHykCgYEAselJVmQ9FOGSHjWL6GMu
T1LHByyhc0YZkTq7j2rl488ZcQomIa/GxYpxR5JYNkGMaJjklirCse+qQ/yAsP5p
hZD1eiMyBM3Gqn4eTJa9Igq0My7X6aJ/ClMZ1i+pKFrlpi7XtgrmIaeNieC5g3vN
Asvf4ko7Xs7fEbIzZBtY2HUCgYBUtL9dDR/LXR4FpVFT2aqRL55YHNU4UjeIuKXm
saL6jzkHWkJ/35xT4q+5AP4kerILApCR+AuqtbrCO/wC/uOYHdFv1C4YhiY33eJC
SFiIrtIxFHNPB6VJsLxx8dj62rGt6t5qVsEF0OWAdvUBO81eADCaezABBZ24aRLY
BD4CUQKBgHgG8Ai6CusOoxKaYzPhgIsu78x6y8jl+H4jbTTOG/qT/1e0+QBmi735
7DxmogQhnsq1iVQ3q3BH5JjYdWhyT01XQ6VDUrKoqVh7wE/73DeRaUB7KLRFVaLT
qfABN3/nv2GYh/dCBebyhyvawfH2ppDqnqIREmEQ+U+vG2sXFIZR
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIDeTCCAmECAQIwDQYJKoZIhvcNAQEFBQAwgZMxCzAJBgNVBAYTAlVTMRMwEQYD
VQQIDApOZXcgTWV4aWNvMREwDwYDVQQHDAhTYW50YSBGZTERMA8GA1UECgwIUHlI
YWNrZXIxDTALBgNVBAsMBFNpcmkxFTATBgNVBAMMDHB5aGFja2VyLmNvbTEjMCEG
CSqGSIb3DQEJARYUamFyZWRob2Jic0BnbWFpbC5jb20wHhcNMTExMTE1MDY0NzM5
WhcNMTIxMTE0MDY0NzM5WjBxMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZv
cm5pYTESMBAGA1UEBwwJQ3VwZXJ0aW5vMQ4wDAYDVQQKDAVBcHBsZTENMAsGA1UE
CwwEU2lyaTEaMBgGA1UEAwwRZ3V6em9uaS5hcHBsZS5jb20wggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQCq+ZK4NWSZ80WAVBM9QRd6IK73aJzvVayxcPb4
oB37RVnY6NRgNOHiXvpgjx9zft6o2R+2I+261PLVQGCUDXm9HlzrBuh6FY+xNEYE
DnwytBqKu57tlsbjR4+gOQa1QuHHdgQCFb0cGwm2AXHCJqOsAVXWer7hNoLFu7O7
zCVSPPeb6KYyszb8YFo0D0GOcEC3ZpdpPiXa+LU69TcHBM+ji89eH7vMYCa7TM8y
fMdS/FfLxJsBp9HzKaqEONORo3gZAOyIZ8YY5kLkwW6z5eZplhkxQzA8HNVnaLkr
X0w/wOJipogTT06QQCWM+PfRBitJwbAdOJ0XlGp/UHq6cpoDAgMBAAEwDQYJKoZI
hvcNAQEFBQADggEBAA36JZRbZK5vceQDsvuiygWyIWUlN9LD+TUToBN5ESm8J6WO
zGEWvstRElrSaEIJMQSNCyzaCvXK0+NukXhqoNuv5Uv4AappziNPPYPjY/HS4dsb
Pov5aEWlQdnaqpvz2D/uzks+X0HI1Jd2WCFRM7CYdYuW9tc4vEMWXn7nOFEV0tuD
DW1zMQlrJj4oyc0GQ8cKYvq9N/vApKR0mXRN6rleGMdW7AoKFH0R41RRCGnX8lvI
uyLMlfK7FboKdY+gb4JJ8JIs5815yBplVe2qQSt8xv8iTQPLThlZXshq6PBwfTLX
V9NwhP5buaa9xclGpkDVo6AZMA50PZ+n/eeteeo=
-----END CERTIFICATE-----"""

def record(output=None):
    """
    Record some audio.
    """
    import pyaudio
    import audiospeex
    chunk = 1024
    channels = 1
    format = pyaudio.paInt16
    rate = 44100
    p = pyaudio.PyAudio()
    stream = p.open(format=format, channels=channels, rate=rate,
                    input=True, frames_per_buffer=chunk)
    logger.info('Recording... (press Ctrl+C to stop)')
    rec = []
    while True:
        try:
            rec.append(stream.read(chunk))
        except IOError as e:
            if e[1] == pyaudio.paInputOverflowed:
                rec.append('\x00' * 16 * chunk * channels)
        except:
            break
    stream.close()
    p.terminate()
    speex = []
    downsample = None
    for d in rec:
        frag, downsample = audiospeex.resample(d, input_rate=rate, output_rate=8000, quality=8, state=downsample)
        speex.append(frag)
    data = ''.join(speex)
    try:
        wf = wave.open('tentative.raw', 'wb')
        wf.setnchannels(channels)
        wf.setsampwidth(p.get_sample_size(format))
        wf.setframerate(8000)
        wf.writeframes(data)
        wf.close()
        data = commands.getoutput('./speexEnc')
    finally:
        if False:#os.path.exists('tentative.raw'):
            os.remove('tentative.raw')
    if output is not None:
        print 'Saving recording to %s' % output
        with open(output, 'wb') as f:
            f.write(data)
    return data

class DNSQuery(object):
    def __init__(self, data):
        self.data = data
        self.domain = ''
        t = (ord(data[2]) >> 3) & 15 # Opcode bits
        if t == 0:                   # Standard query
            ini = 12
            lon = ord(data[ini])
            while lon != 0:
                self.domain += data[ini+1:ini+lon+1] + '.'
                ini += lon+1
                lon = ord(data[ini])

    def response(self, ip):
        packet = ''
        if self.domain:
            packet += self.data[:2] + "\x81\x80"
            packet += self.data[4:6] + self.data[4:6] + '\x00\x00\x00\x00' # Questions and Answers Counts
            packet += self.data[12:]                                       # Original Domain Name Question
            packet += '\xc0\x0c'                                           # Pointer to domain name
            packet += '\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'           # Response type, ttl and resource data length -> 4 bytes
            packet += ''.join(map(lambda x: chr(int(x)), ip.split('.')))   # 4bytes of IP
        return packet

def dnsServer(local):
    udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udps.bind(('', 53))
    logger.info('[DNS] Fake DNS dom.query. 60 IN A %s', local)
    try:
        while True:
            data, addr = udps.recvfrom(1024)
            dns = DNSQuery(data)
            udps.sendto(dns.response(local), addr)
            logger.info('[DNS] Response: %s -> %s', dns.domain, local)
    except socket.error as e:
        import errno
        if e.args[0] == errno.EACCES:
            logger.exception('[DNS] Failed to start server. Are you root? Try: "sudo %s"' % ' '.join(sys.argv))
        sys.exit(e.args[0])
    except KeyboardInterrupt:
        logger.info('[DNS] Shutting down DNS server')
        udps.close()

class SiriServer(object):
    pongCount = 0
    stream = ''
    keys = {}
    compressor = zlib.compressobj(zlib.Z_BEST_COMPRESSION)
    decompressor = zlib.decompressobj()
    def __init__(self, pem):
        self.bindsocket = socket.socket()
        self.bindsocket.bind(('0.0.0.0', 443))
        self.bindsocket.listen(5)
        self.pem = pem

    def runForever(self):
        while True:
            s, addr = self.bindsocket.accept()
            try:
                self.conn = ssl.wrap_socket(s, server_side=True, certfile=self.pem, keyfile=self.pem)
                p = Process(target=self.ponger)
                p.start()
                self.handleClient()
            except KeyboardInterrupt:
                break
            finally:
                p.terminate()
                try:
                    self.conn.shutdown(socket.SHUT_RDWR)
                    self.conn.close()
                except:
                    pass

    def pong(self):
        self.pongCount += 1
        chunk = hex(0x0400000000 + eval(hex(self.pongCount)))[2:].zfill(10).decode('hex')
        data = self.compressor.compress(chunk)
        return data + self.compressor.flush(zlib.Z_SYNC_FLUSH)

    def sendData(self, data):
        try:
            self.conn.write(data)
        except socket.error:
            sys.exit(1)

    def ponger(self):
        try:
            while True:
                self.sendData(self.pong())
                logger.info('[Server] Sent pong')
                time.sleep(1)
        except Exception as e:
            logger.exception('[Server] Something went wrong sending pongs!')

    def removeLeadingHex(self, data, hexStr):
        length = len(hexStr) / 2
        return data[length:] if data[:length].encode('hex') == hexStr else data

    def handleClient(self):
        conn = self.conn
        header = conn.read()
        header = header.split('\r\n')
        end = header.index('')
        data = header[-1]
        header = header[:end]
        logger.info('[Client]\n' + '\n'.join(header))
        self.keys['X-Ace-Host'] = header[-1].split(': ')[1]
        data += conn.read()
        while data:
            line = self.removeLeadingHex(data, '0d0a') # newline
            line = self.removeLeadingHex(line, 'aaccee02') # ACE header
            if line:
                try:
                    d = self.decompressor.decompress(line)
                except Exception as e:
                    import pdb; pdb.set_trace()
                self.stream += d
                self.parse()
            try:
                data = conn.read()
            except:
                logger.exception('[Server] Something went wrong reading data from client!')
                conn.shutdown(socket.SHUT_RDWR)
                conn.close()

    def parse(self):
        import biplist
        header = self.stream[:5].encode('hex')
        if header.startswith('030000'): # Ignore PING requests
            logger.info('[Client] PING: %d', int(header[-4:], 16))
            self.stream = self.stream[5:]
        header = self.stream[:5].encode('hex')
        chunkSize = 1000000 if not header.startswith('0200') else int(header[-6:], 16)
        if chunkSize < len(self.stream) + 5:
            plistData = self.stream[5:chunkSize + 5]
            plist = biplist.readPlistFromString(plistData)
            if 'sessionValidationData' in plist.get('properties', {}):
                plist['properties']['sessionValidationData'] = plist['properties']['sessionValidationData'].encode('hex')
                self.keys['sessionValidationData'] = plist['properties']['sessionValidationData']
                self.keys['assistantId'] = plist['properties']['assistantId']
                self.keys['speechId'] = plist['properties']['speechId']
            if 'packets' in plist.get('properties', {}):
                encodedPackets = []
                with open('data.spx', 'a+') as f:
                    for packet in plist['properties']['packets']:
                        f.write(packet)
                        encodedPackets.append(packet.encode('hex'))
                plist['properties']['packets'] = encodedPackets
            logger.info('[Client]')
            logger.info(pprint.pformat(plist))
            self.stream = self.stream[chunkSize+5:]

class SiriClient(object):
    pingCount = 0
    stream = ''
    compressor = zlib.compressobj(zlib.Z_BEST_COMPRESSION)
    decompressor = zlib.decompressobj()
    def __init__(self, url, keys, speech, ca=None):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ssl_sock = ssl.wrap_socket(s, ca_certs=ca,
                                        cert_reqs=ssl.CERT_OPTIONAL)
        self.ssl_sock.connect((url, 443))
        self.keys = keys
        self.speech = speech

    def httpHeaders(self):
        return "\r\n".join(["ACE /ace HTTP/1.0", "Host: guzzoni.apple.com",
                            "User-Agent: Assistant(iPhone/iPhone4,1; iPhone OS/5.0/9A334) Ace/1.0",
                            "Content-Length: 2000000000",
                            "X-Ace-Host: " + self.keys['X-Ace-Host']]) + "\r\n\r\n"
    
    def contentHeader(self):
        return 'aaccee02'.decode('hex')

    def ping(self):
        self.pingCount += 1
        chunk = hex(0x0300000000 + eval(hex(self.pingCount)))[2:].zfill(10).decode('hex')
        data = self.compressor.compress(chunk)
        return data + self.compressor.flush(zlib.Z_SYNC_FLUSH)

    def createPlist(self, data):
        import biplist
        plist_data = biplist.writePlistToString(data, binary=False)
        try:
            with open('tmp.plist', 'w') as f:
                f.write(plist_data)
            os.system('plutil -convert binary1 tmp.plist')
            with open('tmp.plist', 'rb') as f:
                plist_data = f.read()
        finally:
            os.unlink('tmp.plist')
        header = hex(0x0200000000 + eval(hex(len(plist_data))))[2:].zfill(10).decode('hex')
        data = self.compressor.compress(header) + self.compressor.compress(plist_data)
        return data + self.compressor.flush(zlib.Z_SYNC_FLUSH)

    def loadAssistant(self):
        plist = {'class': 'LoadAssistant',
                 'aceId': str(uuid.uuid4()).upper(),
                 'group': 'com.apple.ace.system',
                 'properties': {'speechId': self.keys['speechId'],
                                'assistantId': self.keys['assistantId'],
                                'sessionValidationData': plistlib.Data(self.keys['sessionValidationData'].decode('hex'))}}
        return self.createPlist(plist)

    def setRestrictions(self):
        plist = {'class': 'SetRestrictions',
                 'aceId': str(uuid.uuid4()).upper(),
                 'group': 'com.apple.ace.system'}
        return self.createPlist(plist)

    def clearContext(self):
        plist = {'class': 'ClearContext',
                 'aceId': str(uuid.uuid4()).upper(),
                 'group': 'com.apple.ace.system'}
        return self.createPlist(plist)

    def startSpeechRequest(self):
        self.speech_session_ace_id = str(uuid.uuid4()).upper()
        plist = {'class': 'StartSpeechRequest',
                 'aceId': self.speech_session_ace_id,
                 'group': 'com.apple.ace.system',
                 'properties': {'audioSource': 'BuiltInMic',
                                'codec': 'Speex_WB_Quality8',
                                'handsFree': False}}
        return self.createPlist(plist)

    def setRequestOrigin(self):
        info = urllib.urlopen('http://api.hostip.info/get_html.php?position=true').read().split('\n')
        plist = {'aceId': str(uuid.uuid4()).upper(),
                 'class': 'SetRequestOrigin',
                 'group': 'com.apple.ace.system',
                 'properties': {'age': 0,
                                'altitude': 2014.172607421875,
                                'direction': -1.0,
                                'horizontalAccuracy': 1728.9098617821555,
                                'latitude': float(info[-3].split(': ')[1]),
                                'longitude': float(info[-2].split(': ')[1]),
                                'speed': -1.0,
                                'verticalAccuracy': 55.68375145211797},
                 'refId': self.speech_session_ace_id}
        return self.createPlist(plist)

    def startSpeechDictation(self):
        self.speech_session_ace_id = str(uuid.uuid4()).upper()
        plist = {'class': 'StartSpeechDictation',
                 'aceId': self.speech_session_ace_id,
                 'group': 'com.apple.ace.speech',
                 'properties': {'keyboardType': 'Default',
                                'applicationName': 'com.apple.mobilenotes',
                                'applicationVersion': '1.0',
                                'fieldLabel': '',
                                'prefixText': '',
                                'language': 'en-US',
                                'censorSpeech': False,
                                'selectedText': '',
                                'codec': 'Speex_WB_Quality8',
                                'audioSource': 'BuiltInMic',
                                'region': 'en_US',
                                'postfixText': '',
                                'keyboardReturnKey': 'Default',
                                'interactionId': str(uuid.uuid4()).upper(),
                                'fieldId': 'UIWebDocumentView0, NoteTextView1, NoteContentLayer0, NotesBackgroundView0, UIViewControllerWrapperView0, UINavigationTransitionView0, UILayoutContainerView0, UIWindow'}}
        return self.createPlist(plist)

    def sendSpeechPackets(self):
        idx = 0
        with open(self.speech, 'rb') as f:
            data = f.readlines()
            total = len(data)
            for line in data:
                plist = {'class': 'SpeechPacket',
                         'refId': self.speech_session_ace_id,
                         'group': 'com.apple.ace.speech',
                         'aceId': str(uuid.uuid4()).upper(),
                         'properties': {'packets': [line],#.encode('hex')],
                                        'packetNumber': idx}}
                self.sendData(self.createPlist(plist))
                idx += 1
                logger.info('[Client] Sent speech packet %d of %d', idx, total)
        return idx

    def finishSpeech(self, idx):
        plist = {'class': 'FinishSpeech',
                 'refId': self.speech_session_ace_id,
                 'group': 'com.apple.ace.speech',
                 'aceId': str(uuid.uuid4()).upper(),
                 'properties': {'packetCount': idx}}
        return self.createPlist(plist)

    @staticmethod
    def pinger(client):
        try:
            while True:
                client.sendData(client.ping())
                logger.info('[Client] Sent ping')
                time.sleep(1)
        except Exception as e:
            logger.exception('[Client] Something went wrong sending pings!')

    def removeLeadingHex(self, data, hexStr):
        length = len(hexStr) / 2
        return data[length:] if data[:length].encode('hex') == hexStr else data

    @staticmethod
    def getResponse(client):
        try:
            while True:
                conn = client.ssl_sock
                header1 = conn.read()
                header = header1.split('\r\n')
                if '' in header:
                    end = header.index('')
                    data = header[-1]
                    header = header[:end]
                else:
                    data = ''
                if 'Server' in header1:
                    logger.info('[Server]\n' + '\n'.join(header))
                else:
                    data = '\r\n'.join(header)
                data += conn.read()
                while data:
                    line = client.removeLeadingHex(data, '0d0a') # newline
                    line = client.removeLeadingHex(line, 'aaccee02') # ACE header
                    if line:
                        d = client.decompressor.decompress(line)
                        client.stream += d
                        client.parse()
                    data = conn.read()
                time.sleep(1)
        except Exception as e:
            logger.exception('[Client] Something went wrong getting response from server!')

    def parse(self):
        import biplist
        header = self.stream[:5].encode('hex')
        if header.startswith('040000'): # Ignore PONG requests
            logger.info('[Server] PONG: %d', int(header[-4:], 16))
            self.stream = self.stream[5:]
        header = self.stream[:5].encode('hex')
        chunkSize = 1000000 if not header.startswith('0200') else int(header[-6:], 16)
        if chunkSize < len(self.stream) + 5:
            plistData = self.stream[5:chunkSize + 5]
            plist = biplist.readPlistFromString(plistData)
            logger.info('[Server]')
            logger.info(pprint.pformat(plist))
            if plist.get('class', '') == 'GetSessionCertificateResponse':
                der = plist['properties']['certificate'][6:]
                self.processCertificate(der)
            self.stream = self.stream[chunkSize+5:]

    def processCertificate(self, der):
        pass

    def sendData(self, data):
        try:
            self.ssl_sock.write(data)
        except socket.error:
            sys.exit(1)

def siriClient(url='guzzoni.apple.com', keyPickle='keys.pickle', speech='input.sif'):
    try:
        with open(keyPickle, 'rb') as f:
            keys = pickle.load(f)
        client = SiriClient(url, keys, speech, 'ca.crt')
        p = Process(target=client.pinger, args=[client])
        p2 = Process(target=client.getResponse, args=[client])
        client.sendData(client.httpHeaders())
        logger.info('[Client] Sent HTTP headers')
        client.sendData(client.contentHeader())
        logger.info('[Client] Sent content header')
        client.sendData(client.ping())
        p2.start()
        logger.info('[Client] Sent ping')
        client.sendData(client.loadAssistant())
        logger.info('[Client] Sent LoadAssistant')
        client.sendData(client.startSpeechDictation())
        logger.info('[Client] Sent StartSpeechDictation')
        idx = client.sendSpeechPackets()
        logger.info('[Client] Sent all speech packets')
        client.sendData(client.finishSpeech(idx))
        logger.info('[Client] Sent FinishSpeech')
        p.start()
        p.join()
    except KeyboardInterrupt:
        logger.info('[Client] Shutting down Siri client')
        p.terminate()
        p2.terminate()
    except Exception as e:
        raise

def siriServer(saveKeys=False, keyPickle='keys.pickle'):
    try:
        pem = 'tmp.pem'
        with open(pem, 'w') as f:
            f.write(PEM)
        server = SiriServer(pem)
        local = socket.gethostbyname(socket.getfqdn())
        p = Process(target=dnsServer, args=[local])
        p.start()
        logger.info('[Server] Siri server started on localhost:443')
        logger.info('[Server] To recover iPhone 4S Siri auth keys, change DNS address on iPhone to %s and make a Siri request.', local)
        server.runForever()
    except KeyboardInterrupt:
        logger.info('[Server] Shutting down Siri server')
        p.terminate()
    except socket.error as e:
        import errno
        if e.args[0] == errno.EACCES:
            logger.exception('[Server] Failed to start server. Are you root? Try: "sudo %s"' % ' '.join(sys.argv))
        raise
    except Exception as e:
        raise
    finally:
        os.unlink(pem)
        if saveKeys:
            logger.info('[Server] Recovered iPhone 4S keys:')
            logger.info(pprint.pformat(server.keys))
            with open(keyPickle, 'wb') as f:
                pickle.dump(server.keys, f)
        
def main(options, args):
    global logger
    if options.debug:
        sys.excepthook = debug
        logger = debugLogger
    if options.record:
        data = record('input.sif')
    if options.client:
        siriClient(url='localhost' if options.debug else 'guzzoni.apple.com',
                   keyPickle=options.keys, speech=options.speech_file)
    if options.server:
        siriServer(saveKeys=options.save_keys, keyPickle=options.keys)
    
if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.set_usage("""%%prog [OPTIONS]
%s

See --help for more details.""" % __doc__)
    parser.add_option('--debug', action='store_true', default=False,
                      help="Turn on debug logging and PM debugging")
    parser.add_option('--record', action='store_true', default=False,
                      help="Record some audio")
    client = optparse.OptionGroup(parser, 'Client options',
                                  "These options communicate with the Siri server (real or fake).")
    client.add_option('--client', action='store_true', default=False,
                      help="Run the Siri client")
    client.add_option('--speech-file', action='store', default='input.sif',
                      help="Specify a speech file to send to the Siri server. "
                           "Format should be the same that you get when running "
                           "the --record option of this script.")
    parser.add_option_group(client)
    server = optparse.OptionGroup(parser, 'Server options',
                                  "These options create a fake Siri server.")
    server.add_option('--server', action='store_true', default=False,
                      help="Run the Siri server")
    server.add_option('--save-keys', action='store_true', default=False,
                      help="If enabled, the keys recovered from the iPhone 4S "
                           "will be saved to a pickle file. The saved keys can "
                           "then be used with the --client option of this script.")
    parser.add_option_group(server)
    parser.add_option('--keys', action='store', default='keys.pickle',
                      help="Specify a pickle file for the Siri authentication "
                           "keys. If we're running in server mode, the keys will "
                           "be saved to this file. If running in client mode, "
                           "the keys will be read from this file.")
    options, args = parser.parse_args()
    if all(options.__dict__[k] == v for k, v in parser.defaults.iteritems()):
        parser.print_usage()
        sys.exit(1)
    main(options, args)  

