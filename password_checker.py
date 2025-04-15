#import useful modules
import pandas as pd
import difflib
import re

#import password csv file
df = pd.read_csv('fake_websites_passwords.csv', delimiter=',')

#uses difflib to compare the similarities of two passwords
def similarity(pass1, pass2, threshold=0.8):
    return difflib.SequenceMatcher(None, pass1, pass2).ratio() >= threshold

#prints alert if two passwords are too similare to each other
def alert(df, threshold=0.8):
    #keeps track of previously seen passwords
    seen = []
    #iterates through csv file
    for index, row in df.iterrows():
        curr_pass = row["Password"]
        curr_site = row["Website"]
        for prev_pass, prev_site in seen:
            if similarity(curr_pass, prev_pass, threshold):
                print(f"{curr_site}'s password is too similar to {prev_site}'s password")
                break
        seen.append((curr_pass, curr_site))

#determines if a password is weak or not based on a set of rules
def valid_password(password):
    score = 0
    length_regex = re.compile(r'^.{8,}$')
    upper_regex = re.compile(r'[A-Z]')
    lower_regex = re.compile(r'[a-z]')
    digit_regex = re.compile(r'\d')
    special_regex = re.compile(r'[\W_]')

    #Checks if the password is longer than 8 characters
    len = length_regex.search(password)
    #Checks if the password has uppercase characters, lowercase characters, special characters, and digits
    upper = upper_regex.search(password)
    lower = lower_regex.search(password)
    digit = digit_regex.search(password)
    special = special_regex.search(password)

    if upper:
        score+=1
    if lower:
        score+=1
    if digit:
        score+=1
    if special:
        score+=1

    #Returns false if the password is too short or if it fails 2 or more checks
    return len and score >= 3

#Prints a list of weak passwords
def pass_checker(df):
    for index, row in df.iterrows():
        curr_pass = row["Password"]
        curr_site = row["Website"]

        if not valid_password(curr_pass):
            print(f"{curr_site}'s password is too weak")

print("\n Weak Passwords:")
pass_checker(df)

print("\n Similar Passwords")
alert(df)

print("\n It is reccomended that you change these passwords as soon as possible")