# select the keycard applet
keycard-select
# set the secrets we had from the initialization
keycard-set-secrets 123456 123456789012 KeycardDefaultPairing
# pairing is usually done once per device
keycard-pair
keycard-open-secure-channel
keycard-verify-pin {{ session_pin }}
# we unpair the current device so that we don't use one of the 5 available slots.
keycard-unpair {{ session_pairing_index }}

# sign a message
keycard-sign-message hello
