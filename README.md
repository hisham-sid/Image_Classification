# Image_Classification
1. Download the P4 Virtual Machine from: https://p4.org/events/2019-04-30-p4-developer-day/

2. Once the VM is imported and running, clone the P4 tutorial exercies from: https://github.com/p4lang/tutorials
3. Next, clone this repository from: https://github.com/hisham-sid/Image_Classification
  (use git clone [name of the repositoy])

4. Once done, move all the files from the Image_Classification repository to the exercises/basic folder inside the P4 tutorial clone. This will overwrite the files already there with the same name
  ( cd Image_Classification
  mv * [wherever the tutorials\exercises\basic folder is] )
  
5. Next, navigate to the basic folder using cd
6  Run make
7. Once the mininet CLI is up, run xterm h1 h2
8. Run the receive script from your receiving host using ./receive.py
8. When invoking the send script from a host terminal, use the name of the image you wish to send as the argument instead of the message.

For e.g:
  (for sending from h1 to h2) 
  Command at h2 => ./receive.py
  Command at h1 => ./send.py 10.0.2.2 index2.png
