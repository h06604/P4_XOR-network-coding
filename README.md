# Network Coding On P4
###### tags: `P4`
## Introduction
實驗目標為透過Network Coding實現鏈路回復功能，在`h1`→`h2`及`h11`→`h22`兩個TCP連線中，每當`s1`→`s4`或是`s4`→`s2`之間的鏈路斷開時，`h11`→`h22`的連接不會因此中斷。實驗中`P2`的封包在經過`s1`時除了轉發到`s4`之外， 還必須產生1個冗餘封包，冗餘封包的內容是`P1`與`P2`進行XOR編碼的結果，並轉發到`s5`，冗餘封包在`s2`必須解碼完成回復為原來的形式。

![](https://i.imgur.com/AkR6yIY.jpg)