"""
    :Authors:
        Petrov D.M. GROUP: CIT-26b
    :Version: 0.0.1 of 2018/12/15
    :platform: Unix, Windows
    |
    |
    |
"""
import socket
from datetime import datetime
import bitstring
import base64




def SessionNum(session):
    """
    :param session: String  with number of session.
    >>> SessionNum(session='Session: 9562D061; timeout=60')
    9562D061
    :return: Number of Session.
    """
    num1 = session.find('Session:')
    num1 += 9
    SessiontTime = session[num1:]
    num2 = SessiontTime.find(';')
    session = SessiontTime[:num2]
    return session


def SessionFrame(fr):
    """
    :param fr: String frame with part of photo.
    >>> P = frame[2]
    P: False
    >>> X = frame[3]
    X: False
    >>>version = frame[0:2].uint
    Version: 2  CC(size sender): 0
    >>> CC = frame[4:8].uint  # size sender
    CC(size sender): 0
    >>> M = frame[8]
    M: False
    >>> PT = frame[9:16].uint  # type encoding name
    PT: 96
    >>> SN = frame[16:32].uint  # number of packege
    NUMBER Package: 51196
    >>> TimeMarker = frame[32:64].uint
    TimeMarker: 3395095627
    >>> SSRC = frame[64:96]
    SSRC: 0x90ea0a57
    :return:  data with part of photo.
    """
    start_bytes2 = b'\x00\x00\x01'
    frame = bitstring.BitArray(fr)
    version = frame[0:2].uint

    P = frame[2]
    X = frame[3]
    CC = frame[4:8].uint  # size sender
    M = frame[8]
    PT = frame[9:16].uint  # type encoding name
    SN = frame[16:32].uint  # number of packege
    TimeMarker = frame[32:64].uint
    SSRC = frame[64:96]
    cont1 = frame[96:99]

    F = frame[96]  # 1 - error 0 - OK
    NRI = frame[97:99]  # 0 <  need frame, 0 - not need frame
    TypeFrame = frame[99:104].uint
    cont2 = frame[107:112]

    S = frame[104]  # 1 - start
    E = frame[105]  # 1 - end
    R = frame[106]  # continue
    TypeNAL = frame[107:112].uint
    # print(f"Version: {version} X: {X} CC(size sender): {CC}")
    # print(f"P: {P} M: {M} PT: {PT} ")
    # print(f"NUMBER Package: {SN}")
    # print(f"TimeMarker: {TimeMarker}")
    # print(f"SSRC: {SSRC}")
    # print(f"F: {F}")
    # print(f"NRI: {NRI}")
    if TypeFrame == 7:
        # print("Type: SPS")
        return start_bytes2 + fr[12:]

    if TypeFrame == 8:
        # print("Type: PPS")
        return start_bytes2 + fr[12:]

    # print(f"S: {S}")
    # print(f"E: {E}")
    # print(f"TypeNAL: {TypeNAL}")

    cont = cont1 + cont2
    # print("Cont1: ", cont1)
    # print("Cont2: ", cont2)
    # print("Cont: ",  cont)
    # print("Cont of bytes: ", cont.bytes)
    # # print("Start_ bytes1: ", start_bytes1)
    # print("Start_ bytes2: ", start_bytes2)


    if S == True:
        # head = start_bytes1 + cont.bytes
        # print(head)
        head = start_bytes2 + cont.bytes
        return head + fr[14:]
    else:
        head = b''
        return head + fr[14:]

    if E == True:
        Sleep(0.1)
        head = b''
        return head + fr[14:]


client_port = [40700, 40701]
"""
    client port for udp stream
"""

host = '10.168.0.186'
ip = '10.168.0.125'
SPS = b'Z0IAKeNQFAe2AtwEBAaQeJEV'
"""Data in 64-bit type."""
PPD = b'aM48gA=='
"""Data in 64-bit type."""

Base16SPS = base64.b64decode(SPS)
"""Data in 64-bit type. The SPS NAL unit contains parameters that apply to a series of consecutive coded video pictures, referred to as a “coded video sequence” in the h.264 standard"""
Base16PPS = base64.b64decode(PPD)
"""Data in 64-bit type. The PPS NAL unit contains parameters that apply to the decoding of one or more individual pictures inside a coded video sequence."""

messageOne = "OPTIONS rtsp://"+ host +"/axis-media/media.amp " \
             "RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: RTSPClient\r\n\r\n"

"""The OPTIONS method requests information about arguments available users."""

messageTwo = "DESCRIBE rtsp://"+ host +"/axis-media/media.amp " \
             "RTSP/1.0\r\nCSeq: 2\r\nUser-Agent: RTSPClient\r\nAccept: application/sdp\r\n\r\n"

"""The DESCRIBE method is used to retrieve the description of a media data from a server."""

messageThree = "SETUP rtsp://"+ host +"/axis-media/media.amp/trackID=1 " \
               "RTSP/1.0\r\nCSeq: 3\r\nUser-Agent: RTSPClient\r\n" \
               "Transport: RTP/AVP;unicast;client_port=" + str(client_port[0]) + "-" + str(client_port[1]) + "\r\n\r\n"
"""The SETUP request for a URI specifies the transport mechanism to be used for the streamed media."""
FileName = 'MyStream.h264'
"""File name for stream."""

size = 2048
"""Size data for read."""
port = 554
"""TCP port."""
address = (host, port)
"""Address for TCP Stream."""



"""Start TCP SERVER"""

print("Starting the clientTCP: ", datetime.now())
clientTCP = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
clientTCP.connect(address)

"""OPTIONS rtsp://10.168.0.186/axis-media/media.amp"""

clientTCP.send(bytes(messageOne, 'utf-8'))
data = clientTCP.recv(size)
print(messageOne)
print(data.decode('utf-8'))

'''DESCRIBE rtsp://10.168.0.186/axis-media/media.amp'''

clientTCP.send(bytes(messageTwo, 'utf-8'))
data = clientTCP.recv(size)
print(messageTwo)
print(data.decode('utf-8'))

"""SETUP rtsp://10.168.0.186/axis-media/media.amp"""

clientTCP.send(bytes(messageThree, 'utf-8'))
data = clientTCP.recv(size)
print(messageThree)
print(data.decode('utf-8'))

NumSession = data.decode('utf-8')
NumSession = SessionNum(NumSession)

messageFour = "PLAY rtsp://"+ host +"/axis-media/media.amp " \
              "RTSP/1.0\r\nCSeq: 4\r\nUser-Agent: " \
              "RTSPClient\r\nSession: " + NumSession + "\r\nRange: npt=0.000-\r\n\r\n"

"""The PLAY method tells the server to start sending data
 via the mechanism specified in SETUP and which part of the media should be played out."""

messageFive = "TEARDOWN rtsp://" + host + "/axis-media/media.amp RTSP/1.0\r\n" \
              "CSeq: 5\r\nSession: " + NumSession + "\r\nUser-Agent: RTSPClient\r\n\r\n"

"""The TEARDOWN client-to-server request stops the stream
 delivery for the given URI, freeing the resources associated with it."""



"""Start UDP SERVER"""
print("Starting the serverUDP: ", datetime.now())
server_address = (ip, client_port[0])
serverUDP = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
serverUDP.bind(server_address)
"""PLAY rtsp://10.168.0.186/axis-media/media.amp"""

clientTCP.send(bytes(messageFour, 'utf-8'))
data = clientTCP.recv(size)
print(messageFour)
print(data.decode('utf-8'))

"""Read with port 40700 and host 10.168.0.125 my computer"""
start_bytes = b'\x00\x00\x01'
# start_bytes = bytes(startbytes, 'utf-8')
print(start_bytes)
NumFrame = 1
filek = open(FileName, 'wb')

print("Start_ bytes: ", filek.write(start_bytes))
print("Base16SPS: ", filek.write(Base16SPS))
print("Start_ bytes: ", filek.write(start_bytes))
print("Base16PPS: ", filek.write(Base16PPS))
print('\n\n\n')
while NumFrame <= 10:
    dataUDP, ser = serverUDP.recvfrom(size)
    print(f"NumFrame: {NumFrame}")
    test = SessionFrame(dataUDP)
    print("Test LEN: ", len(test))
    print("Size: ", filek.write(test))
    NumFrame += 1
    print()
filek.close()
print('\n')

'''TEARDOWN rtsp://10.168.0.186/axis-media/media.amp'''

clientTCP.send(bytes(messageFive, 'utf-8'))
data = clientTCP.recv(size)
print(messageFive)
print(data.decode('utf-8'))

serverUDP.close()
clientTCP.close()
