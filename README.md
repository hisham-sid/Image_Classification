# Image_Classification
Firstly, place all the contents in the tutorials/exercises/basic folder, for the P4 VM available online (tested withn 2019 version)

Then follow the same method as you would normally to initialize the mininet topology and terminals:
1. Navigate to the basic folder
2. Run make
3. Run xterm h1 h2

When invoking the send script from a host terminal, use the name of the image you wish to send as the argument instead of the message.

For e.g:
  ./send.py 10.0.2.2 index2.png
