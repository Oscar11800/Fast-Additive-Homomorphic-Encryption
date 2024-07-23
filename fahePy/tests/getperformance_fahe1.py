from fahe_timed import FAHE1, FAHE2
import os

FAHE1_MINIMUM = (128, 32, 6, 32, 2 ** (6 - 1)) # (LAMBDA_PARAM, M_MAX, ALPHA, MSG_SIZE, NUM_ADDITIONS)
FAHE2_MINIMUM = (128, 32, 29, 32, 100) # (LAMBDA_PARAM, M_MAX, ALPHA, MSG_SIZE, NUM_ADDITIONS)
NUM_TRIALS = 1000

def extract_mintest():
    # Initialize an empty list to store the extracted numbers
    numbers_list = []

    # Get the path to the current directory where the script is located
    current_directory = os.path.dirname(os.path.abspath(__file__))

    # Construct the full path to the mintest.txt file
    file_path = os.path.join(current_directory, "mintest.txt")

    # Open the file and read its content
    with open(file_path, 'r') as file:
        for line in file:
            # Split the line by commas and extract the numbers
            numbers = line.strip().split(',')
            for num in numbers:
                try:
                    # Convert each number to an integer and append to the list
                    numbers_list.append(int(num))
                except ValueError:
                    # Ignore non-numeric values
                    pass
    print("mintest.txt extracted")
    return numbers_list

print("Number of trials = {}".format(NUM_TRIALS))
msg_list = extract_mintest()
num_messages_per_trial = len(msg_list)
assert num_messages_per_trial <= FAHE1_MINIMUM[4]
keygen_time_per_trial_list = []
total_enc_time_per_trial_list = []
total_dec_time_per_trial_list = []

for i in range(NUM_TRIALS):
    testcase = FAHE1(*FAHE1_MINIMUM)
    keygen_time = testcase.keygen_time
    keygen_time_per_trial_list.append(keygen_time)
    ciph_list, enc_time_list = testcase.enc_list(msg_list)
    total_enc_time_per_trial_list.append(sum(enc_time_list))
    m_outcome_list, dec_time_list = testcase.dec_list(ciph_list)
    total_dec_time_per_trial_list.append(sum(dec_time_list))
    assert m_outcome_list == msg_list

average_keygen_time_per_trial = sum(keygen_time_per_trial_list) / NUM_TRIALS
average_enc_time_per_trial = sum(total_enc_time_per_trial_list) / NUM_TRIALS
average_dec_time_per_trial = sum(total_dec_time_per_trial_list) / NUM_TRIALS
average_enc_time_per_message = average_enc_time_per_trial / num_messages_per_trial
average_dec_time_per_message = average_dec_time_per_trial / num_messages_per_trial

print("Average key generation time per trial:   {} seconds\n"
      "Average encryption time per trial:       {} seconds\n"
      "Average decryption time per trial:       {} seconds\n"
      "Average encryption time per message:     {} seconds\n"
      "Average decryption time per message:     {} seconds".format(
          average_keygen_time_per_trial,
          average_enc_time_per_trial,
          average_dec_time_per_trial,
          average_enc_time_per_message,
          average_dec_time_per_message,
      ))


