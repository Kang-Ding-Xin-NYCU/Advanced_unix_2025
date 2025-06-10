#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
import sys
import base64
import zlib
from pwn import *
from solpow import solve_pow
from itertools import permutations
from collections import defaultdict

def generate_numbers():
    return [''.join(p) for p in permutations("0123456789", 4)]

def count_ab(guess, answer):
    bulls = 0
    cows = 0
    for i in range(len(guess)):
        if guess[i] == answer[i]:
            bulls += 1
    for i in range(len(guess)):
        for j in range(len(answer)):
            if guess[i] == answer[j]:
                cows += 1
    cows = cows - bulls
    return (bulls, cows)

def min_guess(possible_num):
    remaining = sys.maxsize
    best_guess = None
    for guess in possible_num:
        score_table = defaultdict(int)
        for answer in possible_num:
            score = count_ab(answer, guess)
            score_table[score] += 1
        worst = max(score_table.values())
        if worst < remaining:
            remaining = worst
            best_guess = guess
    return best_guess

def decode_message(message):
    data = base64.b64decode(message)
    return zlib.decompress(data[4:])

def encode_message(message):
    zm = zlib.compress(message.encode())
    mlen = len(zm)
    return base64.b64encode(mlen.to_bytes(4, 'little') + zm)

def decode_ab(message):
    numbers = (int(message[3]), int(message[-2]))
    return numbers

def first_receive(guess, possible_num):
    encoded_msg = r.recvline().strip().decode()
    decoded_msg = decode_message(encoded_msg)
    print(decoded_msg.decode())
    encoded_msg = r.recvline().strip().decode()
    decoded_msg = decode_message(encoded_msg)
    print(decoded_msg.decode())
    print(guess)
    r.sendline(encode_message(guess))
    encoded_msg = r.recvline().strip().decode()
    decoded_msg = decode_message(encoded_msg)
    feedback = decode_ab(decoded_msg)
    print(f"{feedback[0]}A{feedback[1]}B")
    possible_num = [num for num in possible_num if count_ab(num, guess) == feedback]
    guess = min_guess(possible_num)

    return feedback, guess, possible_num

def receive(guess, possible_num):
    encoded_msg = r.recvline().strip().decode()
    decoded_msg = decode_message(encoded_msg)
    print(decoded_msg.decode())
    encoded_msg = r.recvline().strip().decode()
    decoded_msg = decode_message(encoded_msg)
    print(decoded_msg.decode())
    print(guess)
    r.sendline(encode_message(guess))
    encoded_msg = r.recvline().strip().decode()
    decoded_msg = decode_message(encoded_msg)
    feedback = decode_ab(decoded_msg)
    print(f"{feedback[0]}A{feedback[1]}B")
    possible_num = [num for num in possible_num if count_ab(num, guess) == feedback]
    guess = min_guess(possible_num)

    return feedback, guess, possible_num

def final_receive():
    encoded_msg = r.recvline().strip().decode()
    decoded_msg = decode_message(encoded_msg)
    print(decoded_msg.decode())

    return None

if len(sys.argv) > 1:
    r = remote('up.zoolab.org', 10155)
    solve_pow(r)
else:
    r = process('./guess.dist.py', shell=False)

feedback = (0, 0)
guess = "0123"
possible_num = generate_numbers()
feedback, guess, possible_num = first_receive(guess, possible_num)
guess_time = 0
while feedback != (4, 0):
    try:
        feedback, guess, possible_num = receive(guess, possible_num)
        guess_time += 1
    except:
        guess_time = 11
        break

if guess_time > 10:
    print("Can't solve answer")
final_receive()