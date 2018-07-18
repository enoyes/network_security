import socket
import sys
import argparse
import hmac
from hashlib import sha256
from struct import pack

# ECHO SERVER VARIABLES
echo_key = "\x4b\xe6\x34\x72\xec\x59\xe9\x8b\x38\x12\xdd\x32\x47\xa4\x03\xc4"
echo_ip = "129.10.117.100"
echo_port = 5454

def attack_echo_server(msg):

	global echo_ip, echo_port
	
	# Open connection
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	sock.connect((echo_ip, echo_port))
	
	msg = hmac_encrypt_sha256(msg).digest()

	msg = append_msg_len(msg, len(msg))

	sock.send(msg)

	recv = sock.recv(8192)
	
	print recv

	return

def append_msg_len(msg, len):
	
	msg_header = pack('h', len)
	msg = msg_header + msg
	
	return msg


def hmac_encrypt_sha256(msg):
	global echo_key
	return hmac(echo_key, msg, sha256)


def main():
	parser = argparse.ArgumentParser()

	parser.add_argument('--echo_nice', '-en', help='send an echo msg to the echo server',
                                    nargs='+')
	parser.add_argument('--msg', '-m', help='butt', nargs='+')
	args = parser.parse_args()

	print args
	if args.echo_nice:
        	print 'Contacting echo server'
        	payload = ''.join(args.echo_nice)
        	contact_echo_server(payload)
	if args.msg:
        	print 'Contacting msg server'
        	payload = ''.join(args.msg)
        	attack_msg_server(payload)


