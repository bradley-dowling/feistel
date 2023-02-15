# Bradley Dowling
# Python 3
# CS 427
# BRAD; 2 18 1 4; 5 67 3 11

NAME_PRIMES = [5, 67, 3, 11]
KEY_SIZE = 16
FEISTEL_ROUNDS = 4


# key should be passed into sub_key_n as an int
def sub_key_n(key, n):
    # rol key n times and get the lower byte
    lower_byte_key = 255 & ((key << (n * 4)) | (key >> (KEY_SIZE - (n * 4))))
    lower_byte_name_primes = 255 & NAME_PRIMES[n]
    return lower_byte_key ^ lower_byte_name_primes

# sub_key and input_data should both be ints
def f(sub_key, input_data):
    return sub_key ^ input_data


# input_data and key ashould both be ints
def feistel_struct(feistel_input, key):
    # calculate left and right halves of the input data
    input_left_half = feistel_input >> 8
    input_right_half = feistel_input & 255

    # run through encryption rounds
    for r in range(0, FEISTEL_ROUNDS):
        new_input_right_half = input_left_half ^ f(sub_key_n(key, r), input_right_half)
        input_left_half = input_right_half
        input_right_half = new_input_right_half

    # calculate the final output
    final_left = input_right_half << 8
    return final_left | input_left_half


# input data, key, nonce, and counter are are all ints
def encrypt(input_data, key, nonce, counter):
    feistel_input = nonce ^ counter
    feistel_output = feistel_struct(feistel_input, key)
    return input_data ^ feistel_output


if __name__ == "__main__":

    ##########################################
    # Error checking user input...
    #

    user_input = input().split()
    nonce_as_str = user_input[0]
    key_as_str = user_input[1]
    message_as_str = user_input[2]
    # NOTE: If grading on Windows, you may need to comment out the 4 lines above and uncomment the 3 lines below.
    # nonce_as_str = input().strip()
    # key_as_str = input().strip()
    # message_as_str = input().strip()

    # check for invalid nonce/key string lengths
    if len(nonce_as_str) != 4 or len(key_as_str) != 4:
        print("Nonce and key must both be 16 bits in length.")
        exit(1)

    # check if the message is a valid length
    if len(message_as_str) % 2 != 0:
        print("Message must have even number of hex characters.")
        exit(1)

    # check if we need to pad the message with 0's
    if len(message_as_str) % 4 != 0:
        message_as_str = message_as_str + '00'

    # get integer representation of the key
    key_as_int = int(key_as_str, 16)

    # get integer representation of the nonce
    nonce_as_int = int(nonce_as_str, 16)

    # split message into 4 char chunks
    message_chunks = [message_as_str[i:i + 4] for i in range(0, len(message_as_str), 4)]

    # set the counter
    count = 0

    # encrypt!
    output_values = []
    for chunk in message_chunks:
        chunk_int = int(chunk, 16)
        output_values.append(f"{encrypt(chunk_int, key_as_int, nonce_as_int, count):04x}")
        count += 1

    # print the encrypted output
    output_message = "".join(output_values)
    print(output_message)
