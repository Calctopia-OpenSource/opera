import argparse
import socket
import sys
import os
import random
# from typing import NamedTuple
import collections

ATTEST_REQUEST = 1
INT_SIZE = 4
QUOTE_VALIDITY_SIZE = 2
VERBOSE = False

# class ValueAndSize(NamedTuple):
#     value: bytes
#     size: int
#     name: str = None
ValueAndSize = collections.namedtuple('ValueAndSize', ['value', 'size', 'name'])

# class Quote(NamedTuple):
#     quote: ValueAndSize
#     grp_verif_cert: ValueAndSize
#     gvc_ias_res: ValueAndSize
#     gvc_ias_sig: ValueAndSize
#     gvc_ias_crt: ValueAndSize
#     priv_rl: ValueAndSize
#     sig_rl: ValueAndSize
Quote = collections.namedtuple('Quote', ['quote', 'grp_verif_cert', 'gvc_ias_res', 'gvc_ias_sig', 'gvc_ias_crt', 'priv_rl', 'sig_rl'])

def net_int(net_bytes):
    return int.from_bytes(net_bytes, byteorder='little')

def verbose_print(*objects):
    global VERBOSE
    if VERBOSE: print(*objects)

def establish_parser():
    global VERBOSE
    parser = argparse.ArgumentParser(description='A psuedoapp that can perform \
                                     remote attestation of an OPERA and RAPTOE \
                                     ISV')
    parser.add_argument('isve_ip', help='The ip address of the ISV running the \
                        IsvE to be attested', metavar='isve-ip')
    parser.add_argument('isve_port', help='The port of the ISV running the \
                        IsvE to be attested', type=int, metavar='isve-port')
    parser.add_argument('asve_ip', help='The ip address of the server running \
                        the asve that can verify the IsvE quote',
                        metavar='asve-ip')
    parser.add_argument('asve_port', help='The port of the server running the \
                        asve that can verify the opera quote', type=int,
                        metavar='asve-port')
    parser.add_argument('-v', '--verbose', help='Verbose output',
                        action='store_true')
    parser.add_argument('-m', '--message', help='The file to read the message \
                        sent to the enclave from. If none is specified a \
                        default message is used.')
    parser.add_argument('-r', '--random-message', help='Send a random message \
                        as the challenge message to the enclave.',
                        action='store_true')
    args = parser.parse_args()
    VERBOSE = args.verbose
    if args.message != None and args.random_message:
        print('Cannot specify a message and use a random message.. aborting')
        sys.exit()
    if args.message != None and not os.path.isfile(args.message):
        print('The message file "{0}" must be a file that exists.. aborting'
              .format(arg.message))
    verbose_print('Program started in verbose mode')
    return args

def recv_or_die(socket, size, err_msg='Error receiving value.. aborting',
                print_val=None,
                err_msg_with_printed_val='Error recieving {0}.. aborting'):
    val = socket.recv(size)
    if not val:
        print(err_msg if (print_val==None) else
              err_msg_with_printed_val.format(print_val))
        socket.close()
        sys.exit()
    return val

def recv_val_and_size(socket, name='value', size_name=None):
    if size_name == None:
        size_name = name + ' size'

    size = net_int(recv_or_die(socket, INT_SIZE, print_val=size_name))
    verbose_print('Received {0} of: {1}'.format(size_name, hex(size)))

    value = recv_or_die(socket, size, print_val=name)
    verbose_print('Received {0}:'.format(name) ,value.hex(),
                  '\t {0} bytes'.format(len(value)))

    return ValueAndSize(value, size, name)

def recv_quote(socket):
    quote = recv_val_and_size(socket, name='quote')
    grp_verif_cert = recv_val_and_size(socket, name='grp_verif_cert')
    gvc_ias_res = recv_val_and_size(socket, name='gvc_ias_res')
    gvc_ias_sig = recv_val_and_size(socket, name='gvc_ias_sig')
    gvc_ias_crt = recv_val_and_size(socket, name='gvc_ias_crt')
    priv_rl = recv_val_and_size(socket, name='priv_rl')
    sig_rl = recv_val_and_size(socket, name='sig_rl')

    verbose_print('Received quote from isve')
    return Quote(quote, grp_verif_cert, gvc_ias_res, gvc_ias_sig, gvc_ias_crt,
                 priv_rl, sig_rl)

def send_quote(socket, quote: Quote):
    for v in quote:
        socket.sendall(v.size.to_bytes(INT_SIZE, byteorder='little'))
        socket.sendall(v.value)
        verbose_print('Sent {0}'.format(v.name))
    verbose_print('Sent quote to asve')

def send_challenge(socket, args):
    msg = b"Test message to send to enclave"
    if args.message:
        with open(args.message, 'rb') as f:
            msg = f.read()
    elif args.random_message:
        msglen = 128
        msg = random.getrandbits(msglen*8).to_bytes(msglen, byteorder='little')
    msglen = len(msg)
    socket.sendall(msglen.to_bytes(INT_SIZE, byteorder='little'))
    socket.sendall(msg)
    verbose_print('Sent challenge of length {0}: {1}'.format(msglen, msg.hex()))

def main():
    args = establish_parser()

    isve_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    isve_socket.connect((args.isve_ip, args.isve_port))
    verbose_print('Socket connection established with ISV/IsvE')

    send_challenge(isve_socket, args)
    verbose_print('Attestation request sent to ISV/IsvE')

    isve_quote = recv_quote(isve_socket)
    isve_socket.close()

    asve_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    asve_socket.connect((args.asve_ip, args.asve_port))
    verbose_print('Socket connection established with server running asve')

    send_quote(asve_socket, isve_quote)
    quote_validity = asve_socket.recv(QUOTE_VALIDITY_SIZE)
    asve_socket.close()

    if not quote_validity:
        print('Error receiving quote verification.. aborting')
        asve_socket.close()
        return -1
    quote_validity = int.from_bytes(quote_validity, byteorder='big')
    verbose_print('Received quote verification: {0}'.format(quote_validity))

    print('Quote valid' if (quote_validity == 1) else 'Quote invalid')

if __name__ == '__main__':
    main()
