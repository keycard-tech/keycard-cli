# Install keycard applet

# select sending custom apdu command
# gp-send-apdu 00A4040000

gp-select
gp-open-secure-channel
gp-delete D2760000850101
gp-delete A00000080400010101
gp-delete A00000080400010301
gp-delete A0000008040001
gp-load _assets/keycard-math-soft.cap A0000008040002
gp-load _assets/keycard_v3.0.2.cap A0000008040001
# NDEF applet
gp-install-for-install A0000008040001 A000000804000102 D2760000850101 0024d40f12616e64726f69642e636f6d3a706b67696d2e7374617475732e657468657265756d
# Keycard applet
gp-install-for-install A0000008040001 A000000804000101 A00000080400010101
# Cash applet
gp-install-for-install A0000008040001 A000000804000103 A00000080400010301
