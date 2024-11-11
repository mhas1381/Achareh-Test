import random

def otp_generator():
    otp = random.randint(100000, 999999)  # Ensure the OTP is always a 6-digit number
    return otp
