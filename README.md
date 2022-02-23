# dat_cdnverify
Python script(s) to generate metadata from Nintendo 3DS titles to be added into the DAT-o-MATIC database

Does what it says it does. ~ (the HOME directory) must contain `CA00000003-CP0000000b.bin` (retail TMD verification certificate).

# Usage
In the same directory as `main.py`, run `python3 main.py {path to cdn contents folder}`. Will output `verify.log` and `data.xml` (on success) into the specified content folder.
