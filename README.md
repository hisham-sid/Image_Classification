#  Towards Network-accelerated ML-based Distributed Computer Vision Systems

This system was developed for the purpose of performing image classification on edge networking devices, such as programmable switches. The system consists of a data plane program written in **P4**, targeting the **v1model** architecture (we use the **BMv2** software switch in our experiments), alongside a control plane program written in **Python**

## Data Plane

The data plane is written on the P4 v16 language, found in the file titled *basic.p4*, which is converted to *basic.json* to run on the switch

It implements the classification program using the programmable switch pipeline, wherein images are received by the switch on a chunk basis, features are calculated and a decision tree is used to classify the image. The result is then relayed back to the image source.

## Control Plane
The control plane is written in Python 3.8, found in the files titled *RuleSetterNew.py*, *MakeTree.py* and *commands.txt*

MakeTree.py generates the decision tree based on the dataset that is referred to in the program.

RuleSetterNew.py then converts this decision tree to rules which can be installed on the data plane switch, using commands.txt as the output

The control plane then uses this output to relay the rules to the switch.

## Other files
*send.py* -> Python script that replicates an image producing device

*receive.py* -> Python script that replicates the receving of the class decision

*NPMath.p4* -> Header file containing the math functions written in p4, to emulate floating point arithmetic, division and multiplication



# Instructions

1. Download the P4 Virtual Machine from: https://p4.org/events/2019-04-30-p4-developer-day/

2. Clone this repository from: https://github.com/hisham-sid/Image_Classification
  (use git clone [name of the repositoy])

3. Run the veth_setup.sh script:
  cd Image_Classification
  chmod +x veth_setup.sh
  ./veth_setup.sh
  
4. Next, navigate to the Control Plane folder using cd.
5. Follow the instructions in readme.txt in Control Plane folder to generate the tree.txt file
6. Copy the tree.txt file from Control Plane folder to original folder
  cd ..
  cp ./Control Plane/tree.txt ./
7. Run RuleSetterNew.py script:
 python3 RuleSetterNew.py
8. Open 4 terminals in the Image_Classification folder
9. In terminal 1:
  p4c --target bmv2 --arch v1model basic.p4
  sudo simple_switch_grpc -i 1@veth1 -i 2@veth2 --log-console basic.json
10. In terminal 2:
  sudo simple_switch_CLI --thrift-port 9090 < commands.txt
11. In terminal 3 (we will use this as host 2):
  sudo python3 receive.py
12. In terminal 4 (we will use this as host 1):
  sudo python3 send.py 10.0.2.2 [name of the image]
