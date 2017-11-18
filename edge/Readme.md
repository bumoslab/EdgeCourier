# Edge component
  
This folder contains all files needed to boot edge instances. Our edge-courier support two online file synchronization services, dropbox and onedrive. And edge parts can run as a docker container or a unikernel.  

## Folders organization

* src  
Src folder contains the original source code of edge instances. The original source code is developed based on dropbox, and it can works perfectly with simplely run *python main.py*.  
Unfortunately, dropbox deprecated the first generation of authentication after we published our paper which makes our code not working nowadays. For now, we don't have any plan to add supports of new oauth.  

* onedrive_iso
We modified original source code to support rumprun unikernel. Rumprun unikernel doesn't support auto code dependency resolving, so we integrate libraries we need, such as onedrive sdk, python request library into this folder. All files and folders within **onedrive_iso** folder will be zipped to an image file in order to be combined with rumprun kernel and python binary.

* dropbox_iso  
Same as **onedrive** folder, this is a modified version of original source code for supporting rumprun unikernel.

* dropbox_docker
This folder include our original edge instances source code and a docker file so you can directly generate a docker image. We also provide some script to boot multiple docker containers for performance test of scaling up edge instances.

* image
Image folder relies on **onedrive_iso** and **dropbox_iso** folders, which is the pre-compiled images for our experiments. We will talked about how to generate and run these images in [following sections](#How-to-generate-and-run-rumprun-images)
  
## How to generate and run rumprun images

### How to generate rumprun images

We used rumprun, a rich-libraries-and-language supporting xen based unikernel, as our platform. Rumprun support a lot of different language, frameworks and libraries. It also provided thoroughly documents. We developed our edge instances using python. To execute a python module on rumprun, we need three core parts:

* Rumprun kernel
We first need a rumprun kernel. Rumprun provide a simple instructions [here](https://github.com/rumpkernel/wiki/wiki/Tutorial%3A-Building-Rumprun-Unikernels). By doing this, we will have a rumprun kernel binary and a toolchains set of rumprun-accepted compiler.
* Python official module and interpreter.
We suggest you to follow instructions in [here](https://github.com/rumpkernel/rumprun-packages/tree/master/python3) to compile python interpreter with rumprun-compiler toolchains that generated after we compile rumprun kernel.
* User module
Using *genisoimage* command or other way to create a iso image with all your user code in it. Our *onedrive_iso* and *dropbox_iso* basically is our user level code to be put in in images.

For easily explained how to exeucte it, we call python official module and interpreter as "python.bin" and user code image as "main.iso" as examples in following sections.

### How to run a rumprun images

After generating images, we have the rumprun platform which has a script named "rumprun" for starting our instances. We can simple using command, easy but complicated if you want to boot a large amount instances.

~~~~bash
sudo rumprun xen -i -I newnet,xenif,'bridge=virbr0,mac=00:16:3e:00:00:04' -W newnet,inet,dhcp \
	-b python.iso,/python/lib/python3.5 \
   	-b diff_patch.iso ,/python/lib/python3.5/site-packages/diff_match_patch \
	-b dropbox.iso,/python/lib/python3.5/site-packages/dropbox \
	-b main.iso,/python/lib/python3.5/site-packages \
	-e PYTHONHOME=/python -- python.bin -m main
~~~~

* Arguments simple explaination
    * -I set netback type an connection configurations
    * -W network interface configurations
    * -b loading image name and locations
    * -e executed command

We also provided script to boot large amount rumprun-based edge instances. You can simple run:  
~~~~bash
python command.py [create|clean] [edge instance amount]
~~~~