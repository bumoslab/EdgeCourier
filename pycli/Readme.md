# Edge courier client (python)

We wrote this python client based on our cpp client to provide a fast scaling up experiment framework. In our paper, we need to test the pressure on edge device when running edge instances grow. Our cpp client are used for mobile, so it is very hard to use for this test. We need to have a client easy to manage and booting on x86.

## How to run it

You can simple run watch file by command:  

~~~~bash
python watch.py
~~~~

This will start an endless loop to watch a file, once this file is modifid, our code will upload the updated file to cloud using our edge-courier solution.
