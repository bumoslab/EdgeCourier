# Edge Courier (Edge-involved Cloud file service synchronization traffic deduction with Project)

Author: Pengzhan Hao, Moslab  

## Overview

In this project, we introduce edge based solution for decreasing traffic usage when user frequently apply small changes to files that are going to be uploaded to cloud file sync services. We observed that in most cases, cloud file sync services such as onedrive, google drive and dropbox mobile will upload whole file to cloud no matter what changes user has made. Our proposal is deploy a edge personal service for each user, that can detect user changes are decreasing the traffic between end devices and edge device (router).

<img src="/sys.png" width="800">

According to the design above, you can find our solution composed by two parts: mobile component(client) and edge EPS (edge instances). In project folder, we organized code in two categories, client and edge. For futher information, please reference to readme files within sub folders.

## Publication

* [EdgeCourier: An Edge-hosted Personal Service for Low-bandwidth Document Synchronization in Mobile Cloud Storage Services](https://dl.acm.org/citation.cfm?id=3134447)
