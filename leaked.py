#!/usr/bin/env python
import os

import colorama

import leakz

try:
    input = raw_input
except NameError:
    pass


def clear():
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')


def back():
    print()
    back = input('\033[92mDo you want to contunue? [Yes/No]: ')
    if back[0].upper() == 'Y':
        print()
        menu()
    elif back[0].upper() == 'N':
        print('\033[93mRemember to checkout: https://GitHackTools.blogspot.com')
        exit(0)
    else:
        print('\033[92m?')
        exit(0)


def banner():
    print("""\033[93m
 ___       _______   ________  ___  __    _______   ________  ________
|\  \     |\  ___ \ |\   __  \|\  \|\  \ |\  ___ \ |\   ___ \|\_____  \
\ \  \    \ \   __/|\ \  \|\  \ \  \/  /|\ \   __/|\ \  \_|\ \|____|\  \
 \ \  \    \ \  \_|/_\ \   __  \ \   ___  \ \  \_|/_\ \  \ \\ \    \ \__\
  \ \  \____\ \  \_|\ \ \  \ \  \ \  \\ \  \ \  \_|\ \ \  \_\\ \    \|__|
   \ \_______\ \_______\ \__\ \__\ \__\\ \__\ \_______\ \_______\       ___
    \|_______|\|_______|\|__|\|__|\|__| \|__|\|_______|\|_______|      |\__\\
                                                                        \|__| 1.2
     A Checking tool for Hash codes and Passwords leaked""")


def menu():
    try:
        print("""\033[96mWhat do you want to check?
    1. Password Hashes      3. About Author
    2. Hash Leaked          4. Exit""")
        print()

        choice = input('Enter your choice (1-4): ')
        if choice == '1':
            password = input('\nEnter or paste a password you want to check: ')
            hashes = leakz.hashes_from_password(password)
            print("""\n\033[93mIT LEAKED!!! The Hash codes of the Password is:
   MD5: """ + hashes['md5'] + """
  SHA1: """ + hashes['sha1'] + """
SHA224: """ + hashes['sha224'] + """
SHA256: """ + hashes['sha256'] + """
SHA384: """ + hashes['sha384'] + """
SHA512: """ + hashes['sha512'] + """""")
            back()

        elif choice == '2':
            hash = input('\nEnter or paste a hash code you want to check: ')
            password = leakz.password_from_hash(hash)
            print(
                '\n\033[93mTHAT HASH CODE HAS BEEN LEAKED! It means: ' + password)
            back()

        elif choice == '3':
            print("""\033[93mLeaked? 1.2 - A Checking tool for Hash codes and Passwords leaked

    AUTHOR: https://GitHackTools.blogspot.com
            https://twitter.com/SecureGF
            https://fb.com/TVT618
            https://plus.google.com/+TVT618""")
            back()

        elif choice == '4':
            print('\033[93mRemember https://GitHackTools.blogspot.com')
            exit(0)

        else:
            print('Invalid choice\n')
            menu()

    except KeyboardInterrupt:
        print("\nExiting...")
        exit(0)
    except leakz.exceptions.LeakzRequestException:
        print('\033[91mYour Internet Offline!!!')
        exit(1)
    except leakz.exceptions.LeakzJSONDecodeException:
        print('\033[93mCongratulations! It was not leaked!!!')
        print()
        menu()


if __name__ == "__main__":
    colorama.init()
    clear()
    banner()
    menu()
