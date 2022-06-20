## Encrypted Notepad Application
#### Author: Ellie Day
#### Date: June 19th 2022

#### Purpose: 
A recreation of an old tool I made in VB.Net and Visual Studio. An application similar to Windows' Notepad application that secures the integrity of the data by encrypting/decrypting automatically - using a separate file as the 'key'

#### Note:
File chosen as encryption key should be something personal (so, not a shortcut to Google Chrome's executable for example), and something that remains relatively constant. If the encryption key file is ever changed, the resulting future hash values will be altered from the original, resulting in a different encryption key. If the file is changed, encrypted documents will be irretrievable through normal means.
