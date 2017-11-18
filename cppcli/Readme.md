# Edge Courier client (cpp)

This folder contains a cpp version edge-courier client component. It was simple written using in c++ with a support of qt4.

## How to compile it

First, configure the makefile to the point to the correct path of qt, then make it using:  
  
~~~~bash
make all
~~~~

## How to run it

Client works only with corresponding edge instance is running. So before running the client, you need to first boot up edge part. For more details, check the folder "edge".
  
With edge instances booted, you can run the client with command:

~~~~bash
./main [IP addr of edge instance] [port of edge] [the user name you used in the edge instance]
~~~~
  
then follow up printed instructions to authorize edge courier to be able to connect file sync service and then upload the file you need.
