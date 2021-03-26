import requests
import sys
import hashlib
import random
import array

#first of all we have to create a function which will give us response from API(haveieverbeenpwnedAPI)

def response_giver(password):
    url = "https://api.pwnedpasswords.com/range/" + password
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f"Error fetching : {res.status_code},check the api again!" )
    return res

#converting the password into Hash code and deviding it into two part
# first 5 char as first5_letter and rest char as tail

def hash_converter(password):
    hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_letter,tail = hash[:5],hash[5:]
    res = response_giver(first5_letter)
    return counter(res,tail)

#this function will return the count as how many times user password have been hacked
def counter(hashes,tail):
    hashes = (line.split(":") for line in hashes.text.splitlines())
    for h,count in hashes :
        if h == tail :
            return count
    return 0

#Take user password as argument and return how many time password has been hacked
def main(password):
    count = hash_converter(password)
    return count


#this function will generate 6 passwords and will check whether it have been hacked or not
#and will return back one of the password if it is not found in data breach
def userFav(f_name, l_name, birthday) :
    birth = birthday.split('/')
    lucky_num = birth[0]
    birth_year = birth[2]

    # check through api and put if condition accordingly
    password1 = f_name.capitalize() + l_name[0] + random.choice(['@', '$', '%', '#']) + random.choice(
        ['@', '$', '%', '#']) + birth_year[2:] + lucky_num
    password2 = l_name.capitalize() + random.choice(['@', '$', '%', '#']) + random.choice(
        ['#', '@', '$', '&']) + birth_year[0:2] + lucky_num
    password3 = f_name.capitalize() + random.choice(['@', '$', '%', '#']) + random.choice(
        ['#', '@', '$', '&']) + birth_year[0:2] + lucky_num
    password4 = random.choice(['@', '$', '%', '#']) + random.choice(
        ['@', '$', '%', '#']) + f_name.capitalize() + birth_year[0:2] + lucky_num
    password5 = lucky_num + random.choice(['@', '$', '%', '#']) + random.choice(
        ['@', '$', '%', '#']) + f_name + birth_year
    password6 = f_name.capitalize() + lucky_num + random.choice(
        ['@', '$', '%', '#']) + l_name.capitalize() + random.choice(
        ['#', '@', '$', '&']) + birth_year[1:3]

    counter = [main(password1),main(password2),main(password3),main(password4),main(password5),main(password6)]
    passwords = [password1,password2,password3,password4,password5,password6]
    securePassword =  []
    base_counter = 0
    i = -1
    for count in counter :
        i += 1
        if not count :
            base_counter += 1
            securePassword.append(passwords[i])
        else :
            continue
    if base_counter != 0 :
        return random.choice(securePassword)
    else :
        return ""

def systemPass():
    # maximum length of password needed
    # this can be changed to suit your password length
    maxLen = 12

    # declare arrays of the character that we need in out password
    # Represented as chars to enable easy string concatenation
    digits = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
    lowercaseCharacters = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
                         'i', 'j', 'k', 'm', 'n', 'o', 'p', 'q',
                         'r', 's', 't', 'u', 'v', 'w', 'x', 'y',
                         'z']

    uppercaseCharacters = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                         'I', 'J', 'K', 'M', 'N', 'O', 'p', 'Q',
                         'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y',
                         'Z']

    symbols = ['@', '#', '$', '%', '=', ':', '?', '.', '/', '|', '~', '>',
               '*', '(', ')', '<']

    # combines all the character arrays above to form one array
    combinedCharacters = digits + uppercaseCharacters + lowercaseCharacters + symbols

    # randomly select at least one character from each character set above
    rand_digit = random.choice(digits)
    rand_upper = random.choice(uppercaseCharacters)
    rand_lower = random.choice(lowercaseCharacters)
    rand_symbol = random.choice(symbols)

    # combine the character randomly selected above
    # at this stage, the password contains only 4 characters but
    # we want a 12-character password
    temp_pass = rand_digit + rand_upper + rand_lower + rand_symbol

    # now that we are sure we have at least one character from each
    # set of characters, we fill the rest of
    # the password length by selecting randomly from the combined
    # list of character above.
    for x in range(maxLen):
        temp_pass = temp_pass + random.choice(combinedCharacters)

        # convert temporary password into array and shuffle to
        # prevent it from having a consistent pattern
        # where the beginning of the password is predictable
        temp_pass_list = array.array('u', temp_pass)
        random.shuffle(temp_pass_list)

    # traverse the temporary password array and append the chars
    # to form the password
    password = ""
    for x in temp_pass_list:
        password = password + x

    # returning out password
    return password



#this function will show the strength of password
def password_check(password) :

    # calculating the length
    length_error = len(password) < 8

    # searching for digits
    digit_error = re.search(r"\d", password) is None

    # searching for uppercase
    uppercase_error = re.search(r"[A-Z]", password) is None

    # searching for lowercase
    lowercase_error = re.search(r"[a-z]", password) is None

    # searching for symbols
    symbol_error = re.search(r"[ @!#$%&'()*+,-./[\\\]^_`{|}~"+r'"]', password) is None

    # overall result
    password_ok = not ( length_error or digit_error or uppercase_error or lowercase_error or symbol_error )

    return {
        'password_ok' : password_ok,
        'length_error' : length_error,
        'digit_error' : digit_error,
        'uppercase_error' : uppercase_error,
        'lowercase_error' : lowercase_error,
        'symbol_error' : symbol_error,
    }


#testing Section

f_name = "dhruv"
l_name = "prajapati"
birthday = "22/10/2001"

userEnteredPass = input("Enter any password : ")
hackedCount = main(userEnteredPass) #it will check for the user entered password
if not hackedCount :
    print(userEnteredPass + " Is Hacked for " + str(hackedCount) + " Times"  )
    error = password_check(userEnteredPass)
    false_count = 0
    error_names = []
    true_count = 0
    print_status = 0
    for i in error:
        if error[i] and i == "password_ok":
            print("Excellent password")
            print_status = 1
        elif not error[i]:
            true_count += 1
        else :
            false_count +=1
            error_names.append(i)
    if print_status == 0 :
        if (false_count < 3):
            print("Better password")
            print(error_names)
        else:
            print("OK password")
            print(error_names)
else :
    altPass = userFav(f_name, l_name, birthday)
    if altPass == "" :
        sysPass = systemPass()
        print("Our recommended password for you is given below ")
        print(sysPass)
    else :
        print("Our recommended password for you is given below ")
        print(altPass)









