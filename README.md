## Install the relevant requirements using:

```
pip install -r requirements.txt
```

# If you want to encrypt your file, use:

```
python encryption_tool.py encrypt FILENAME
```

Two files will then be produced. ```FILENAME.encrypted``` (where FILENAME is your file's name) and ```encrypted_key.txt```. You can delete ```FILENAME``` and store ```encrypted_key.txt``` somewhere safe for when you want to decrypt your file one day. 

# If you want to decrypt the file, make sure ```encrypt_key.txt``` is in the same folder as the python script and the encrypted file and run:

```
python encryption_tool.py decrypt FILENAME
```
