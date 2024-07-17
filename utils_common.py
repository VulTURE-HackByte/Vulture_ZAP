import string
import random

def generate_random(length):
    res = ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))
    return res