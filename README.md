# CryptoComm
A secure, end-to-end encrypted(twice!), messenger for chatting in local Windows networks. UNDER DEVELOPMENT!

# Commiting
Wanna commit? Clone/Fork, edit, create a P/R. 

# A few words about SSL
`First.pfx` and `publickey.cer` are 2 keys that are used to encrypt/decrypt messages in the first stage.
First stage is just a gate that stops everyone from just reading the messages. Keys of the first stage are not that important. But, for safety, change them if you want to actually use the programm.
The second stage(in development) is a more complicated gate. 2 clients share the same first stage key, and perform handshaking with their own TEMPORARILY KEYS. After that, ALL messages are encrypted twice. By the first stage's keys, and by local keys. Local keys should be updated to new when a new conversation is started. 

# todo

- actual messaging
- figure out how to change form controls via threads(there might be a transfer to async tasks, )


# Under development 
![gif https://upload.wikimedia.org/wikipedia/commons/1/1c/Under-Construction-Bulldozer.gif](https://upload.wikimedia.org/wikipedia/commons/1/1c/Under-Construction-Bulldozer.gif)

## license stuff
* GIF IS LICENSED UNDER LICENSE Creative Commons Attribution-Share Alike 4.0 International LICENSE
* I DON'T OWN IT! CREDITS TO THE ORIGINAL AUTHOR: JMichaelTX
* SOURCE: [https://commons.wikimedia.org/wiki/File:Under-Construction-Bulldozer.gif](https://commons.wikimedia.org/wiki/File:Under-Construction-Bulldozer.gif)
