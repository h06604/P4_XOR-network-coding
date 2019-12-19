# Network Coding On P4
###### tags: `P4`
## **Introduction**
**The goal of this project is to utilize network coding to support the end-to-end reliability in P4 enabled network environment.
In this project, the capability of P4 is explored in terms of packet processing and its supported functionalities. 
Github: https://github.com/h06604/P4_XOR-network-coding**
## **Github Opensource**
**https://github.com/h06604/P4_XOR-network-coding**
![](https://i.imgur.com/AkR6yIY.jpg)
As shown in the Figure above, two hosts h1 and h11 simultaneously send TCP packets (realtime video streaming) to h2 and h22, respectively. Instead of directly forwarding packets in the S1~S5 formed network, each switch (i.e., S1~S5) correspondingly processes the received packets before forwarding. The steps are as following example:

1. S1 network encodes received packets by XOR (i.e., P1 and P2) and then sends to S5 in additional to forward P1 and P2 to S3 and S4, respectively.

2. S3~S5 just forward received packets to S2.

3. S2 reconstructs the received packets conditionally.

As a results, in this example, a lost packet can be tolerant during transmission. Even though two packets are missing during the transmission, each receiver (i.e., h2 and h22) only experience one packet loss.

[![Watch the video](https://i.imgur.com/8wf5LP4.png)](https://drive.google.com/file/d/1VK6IBAxl_pRLyR4dnMvYS4OXZG7fwztw/view)
**Demo of XOR for two TCP flows, Dec. 2019**

This is the demo of network coding by XOR for two video streaming application in parallel. The video shows the payloads as well as the displayed videos at h2 and h22 (i.e., two receivers)

## **Reference Our Projects**
```
@electronic{programmable-network-coding:project,
  author = {Huang, Hong-Zhi and Huang, Chin-Ya and Kuo, Hsun-Yu},
  title = {Enhancing End-to-End Reliability in P4-enabled Networks},
  url = {https://sites.google.com/gapps.ntust.edu.tw/chin-ya-huang/project/security/network-coding-on-p4},
  year = {2019}
}
```

## **Give us feedback**
**We want to learn how people use our opensource project and what aspects we might improve. Please report any issues or comments using the bug-tracker and do not hesitate to approach us via e-mail.**

## **Contact**
* Chin-Ya Huang: chinya@gapps.ntust.edu.tw
* Hong-Zhi Huang: M10802207@mail.ntust.edu.tw 