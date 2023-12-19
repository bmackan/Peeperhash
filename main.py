import hashlib

def hash_password(password, salt, pepper):
    # Generate the hash value of the password
    try:
        hashed_password = hashlib.sha256(password.encode() + salt.encode() + pepper.encode()).hexdigest()
    except ValueError:
        print("Invalid password!")
        return None
    return hashed_password

def check_password(password, hashed_password, salt, pepper):
    # Check the hash value of the entered password
    try:
        if hashlib.sha256(password.encode() + salt.encode() + pepper.encode()).hexdigest() == hashed_password:
            return True
        else:
            return False
    except ValueError:
        print("Invalid password!")
        return False

def main():
    # Password creation
    password = input("Please enter a password: ")
    salt = os.urandom(16)
    pepper = os.urandom(32)
    hashed_password = hash_password(password, salt, pepper)
    print("Password hash value:", hashed_password)

    # Password check
    password_check = input("Please enter your password again: ")
    if check_password(password_check, hashed_password, salt, pepper):
        print("Password is correct!")
    else:
        print("Password is incorrect!")

if __name__ == "__main__":
    main()
