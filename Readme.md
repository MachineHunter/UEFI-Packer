# UEFI module packer
packs(encrypt) UEFI module.
* [master branch](https://github.com/MachineHunter/UEFI-Packer/blob/master/custom-packer/x64/Debug/custom-packer.exe): simple one-byte XOR encryption
* [tpm-key-packing branch](https://github.com/MachineHunter/UEFI-Packer/blob/feature/tpm-key-packing/custom-packer/x64/Debug/custom-packer.exe): encrypt with TPM key (Endorsement Key)

<br/>
<br/>

# Usage

## XOR packer
Just download the packer program from [here](https://github.com/MachineHunter/UEFI-Packer/blob/master/custom-packer/x64/Debug/custom-packer.exe) and execute as follows.
```
./custom-packer.exe original.efi packed.efi
```

## TPM key packer (Hard)
Currently, this works fine but the usage is complex, since this is for my own research.  
There's an asymmetric key called EK(Endorsement Key) in the TPM. EK is a key unique to each TPM(PC). This packer uses public key of EK for both encryption and decryption. 

1. You need to first extract your PC's EK. You can simply do this by executing [this UEFI module](https://github.com/MachineHunter/UEFI-Packer/blob/feature/tpm-key-packing/src/for-printing-your-public-ek/BOOTX64.EFI).

2. Remember the output of EK pub-key and copy that value in [here](https://github.com/MachineHunter/UEFI-Packer/blob/feature/tpm-key-packing/src/custom-packer.cpp#L85-L87). This is the source code of packer. Since I can't expose my EK pub-key on github, source code is using `dummy_pubkey`. So modify this to use `endorsement_pubkey` instead.

3. Now you have to build this packer with Visual Studio (I'm using Visual Studio 2019). I'm git-ignoring lots of files so maybe the `.sln` file won't correctly open. But it's just a simple C++ program for windows and I haven't done any additional setup on Visual Studio so create your own windows executable project, put the custom-packer.cpp's content and build it. You'll get your own TPM key packer executable `custom-packer.exe`

4. Pack your module like this `./custom-packer.exe original.efi packed.efi`.