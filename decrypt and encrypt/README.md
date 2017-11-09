##SETUP  
First compile the oracle from other folder and place the oracle here.  
```make clean```  
```make```  

##GENERATE PADDED PLAINTEXT  
Generate a padded plaintext `padded_plaintext` and ciphertext `ciphertext` with ```python plaintext_and_ciphertext_gen.py```

##ENCRYPTION  
javac encrypt.java  
java encrypt "padded_plaintext" > "custom_ciphertext"

##DECRYPTING THE GENERAYED CIPHERTEXT  
java decrypt "ciphertext" | xxd  

##DECRYPTING OUR CUSTOM ENCRYPTED CIPHERTEXT  
java decrypt "custom_ciphertext" | xxd  
