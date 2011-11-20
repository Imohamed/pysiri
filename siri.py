#!/usr/bin/env python
"""
This is a simple library to interact with Siri. It's based off the work done by
Applidium (http://applidium.com/en/news/cracking_siri/) and the code they
released (https://github.com/applidium/Cracking-Siri).                                                                                                           
 
Requires PyAudio (http://people.csail.mit.edu/hubert/pyaudio/), 
audiospeex from py-audio (http://code.google.com/p/py-audio/),
biplist (https://github.com/wooster/biplist), and the speexEnc binary (compiled
from the sources found https://github.com/applidium/Cracking-Siri).
 
The audio dependencies are only used when communicating with the real Siri
server; they aren't required if you simply want to recover your keys.
 
The compiled code included in this directory will work on an x86_64 Mac. You'll
need to compile the code yourself if you're on something else.
 
To get Siri authentication keys for your iPhone 4S, you'll need to install the
following CA certificate to your iPhone. The easiest way to install it is to
save the file as "ca.crt" and email it to yourself. Open the email on your
iPhone and install it:
 
-----BEGIN CERTIFICATE-----
MIID+zCCAuOgAwIBAgIJAMync/ikJ03iMA0GCSqGSIb3DQEBBQUAMIGTMQswCQYD
VQQGEwJVUzETMBEGA1UECAwKTmV3IE1leGljbzERMA8GA1UEBwwIU2FudGEgRmUx
ETAPBgNVBAoMCFB5SGFja2VyMQ0wCwYDVQQLDARTaXJpMRUwEwYDVQQDDAxweWhh
Y2tlci5jb20xIzAhBgkqhkiG9w0BCQEWFGphcmVkaG9iYnNAZ21haWwuY29tMB4X
DTExMTExNTA2NDUwOFoXDTEyMTExNDA2NDUwOFowgZMxCzAJBgNVBAYTAlVTMRMw
EQYDVQQIDApOZXcgTWV4aWNvMREwDwYDVQQHDAhTYW50YSBGZTERMA8GA1UECgwI
UHlIYWNrZXIxDTALBgNVBAsMBFNpcmkxFTATBgNVBAMMDHB5aGFja2VyLmNvbTEj
MCEGCSqGSIb3DQEJARYUamFyZWRob2Jic0BnbWFpbC5jb20wggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQDJgq9D3RhiakWPQbBqWdlhi0GgV31uxDc1Bx+X
PbRvKAJIQAP9ONwQi1hSf/0zQMy1vQ+f7OAbXUPDMT16fNBdgt84Ysvxmnm/mNi3
Ywo+yZFk+IK1dt1WFEOM3Uc44GGUdN5y7MiUtdP2DoPNY99dEGxY0+6qS1RHSm32
FcRbDX96JQiT1q1tDgdql6Ka5eAk8aZrJw0aaMe6z3Hk0oIK0a1iPj+JKFINfeY/
f0yyTavE4Zqa5FHyUceKOqhLOoijXyOLi+9aS1gPxMQ47+GFYe+iTAVUoThLMnRu
Nagz4vGmOlCimmVQKFfHFKCc6YnJrchdJmAc1Lk08c2FAiqHAgMBAAGjUDBOMB0G
A1UdDgQWBBSs8WPSaxCLmukQ4GMmd4Y44TUj6zAfBgNVHSMEGDAWgBSs8WPSaxCL
mukQ4GMmd4Y44TUj6zAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4IBAQAt
+A07AQ8iRz83XF9YydG6SDZeH5ewxWXkQbKU5OuP+BlR9QIu1YJOQ79EgIctFm5e
yJJvPtYgewD/ikO9ryCRvkMbv8bN3EhMw5JcfkU7YtYPWrjcYJlb4VKiJUs70KqJ
DGLecXd9Nq/4xeLdSYwf0dl+OFuc0zlEtYbEPRc6zo6P9MT/ddTJh9bEpRmQPcVy
1SdIJdgvQeOWLt8YGCFtrVV5vH8jTxJI/B/Gm7fy9ZoQBl+PLXcNCuWSSlaXqxg0
dimWuwdtblK3pZGE1SjKlmpYcWB+CvF/f9utWFWCmf5NjyDbJ+1W1phgDrFqBAmf
uINRrcZ3ww0ITa5IWZh7
-----END CERTIFICATE-----

After installing the certificate, run this script as root with the --server
option: sudo ./siri.py --server

Change the DNS server on the iPhone to the IP of the computer running this
script (Settings -> Wi-Fi -> <blue arrow on connected network> -> DNS)

Open Siri and say something. You should see your speech packets scroll by. Exit
the script with Ctrl+C (you'll probably have to press it twice) and your keys 
will be displayed at the bottom of the console.

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
import tty
import wave
import zlib
import ssl
import socket
import pprint
import httplib
import optparse
import commands
from OpenSSL import SSL
from select import select
from cStringIO import StringIO
from multiprocessing import Process
from BaseHTTPServer import HTTPServer
from SimpleHTTPServer import SimpleHTTPRequestHandler

from logutils import logger, debugLogger

def debug(t, v, tb):
    import traceback, pdb
    traceback.print_exception(t, v, tb)
    print
    pdb.pm()

DEBUG = False

if DEBUG:
    sys.excepthook = debug
    logger = debugLogger
else:
    logger = logger

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

class SiriServer(HTTPServer):
    def __init__(self):
        HTTPServer.__init__(self, ('0.0.0.0', 443), SiriHandler)
        ctx = SSL.Context(SSL.SSLv23_METHOD)
        self.pem = 'tmp.pem'
        with open('tmp.pem', 'w') as f:
            f.write(PEM)
        ctx.use_privatekey_file(self.pem)
        ctx.use_certificate_file(self.pem)
        s = socket.socket()
        self.socket = SSL.Connection(ctx, s)
        self.server_bind()
        self.server_activate()

    def shutdown_request(self, request):
        request.shutdown()

    def __del__(self):
        if os.path.exists(self.pem):
            os.unlink(self.pem)

class SiriHandler(SimpleHTTPRequestHandler):
    keys = {}
    stream = ''
    binary = False
    deflator = zlib.decompressobj()
    def setup(self):
        self.connection = self.request
        self.rfile = socket._fileobject(self.request, 'rb', self.rbufsize)
        self.wfile = socket._fileobject(self.request, 'wb', self.wbufsize)

    def removeLeadingHex(self, data, hexStr):
        length = len(hexStr) / 2
        return data[length:] if data[:length].encode('hex') == hexStr else data

    def do_ACE(self):
        logger.info(self.headers.__str__().strip())
        self.keys['X-Ace-Host'] = self.headers['x-ace-host']
        try:
            for line in self.rfile:
                line = self.removeLeadingHex(line, '0d0a') # newline
                line = self.removeLeadingHex(line, 'aaccee02') # ACE header
                self.stream += self.deflator.decompress(line)
                self.parse()
        except SSL.SysCallError:
            self.finish()

    def parse(self):
        import biplist
        header = self.stream[:5].encode('hex')
        if header.startswith('030000'): # Ignore PING requests
            logger.info('PING: %d', int(header[-4:], 16))
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
            logger.info(pprint.pformat(plist))
            self.stream = self.stream[chunkSize+5:]

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

def siriServer():
    try:
        httpd = SiriServer()
        local = socket.gethostbyname(socket.getfqdn())
        p = Process(target=dnsServer, args=[local])
        p.start()
        logger.info('[Server] Siri server started on localhost:443')
        logger.info('[Server] To recover iPhone 4S Siri auth keys, change DNS address on iPhone to %s and make a Siri request.', local)
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info('[Server] Shutting down Siri server')
        p.terminate()
        if 'httpd' in locals():
            logger.info('[Server] Recovered iPhone 4S keys:')
            logger.info(pprint.pformat(SiriHandler.keys))
    except socket.error as e:
        import errno
        if e.args[0] == errno.EACCES:
            logger.exception('[Server] Failed to start server. Are you root? Try: "sudo %s"' % ' '.join(sys.argv))
        raise
    except Exception as e:
        raise
        
def main(options, args):
    if options.record:
        data = record('input.sif')
#    if options.client:
#        siriClient()
    if options.server:
        siriServer()
    
if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.set_usage("""%%prog [OPTIONS]
%s

See --help for more details.""" % __doc__)
    parser.add_option('--record', action='store_true', default=False,
                      help="Record some audio")
#    parser.add_option('--client', action='store_true', default=False,
#                      help="Run the Siri client")
    parser.add_option('--server', action='store_true', default=False,
                      help="Run the Siri server")

    options, args = parser.parse_args()
    if all(options.__dict__[k] == v for k, v in parser.defaults.iteritems()):
        parser.print_usage()
        sys.exit(1)
    main(options, args)  

