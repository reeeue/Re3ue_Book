# [ Re3ue ] PE_Parse.py

import sys
import os

class PEParse :
    def __init__(self, filePath) :
        self.filePath = filePath

    def parse(self) :
        print("Program Start.")

        with open(self.filePath, "rb") as f :
            # 1. DOS Header
            self.get_dos_header(f)
            # 2. DOS Stub
            self.get_dos_stub(f)
            # 3. PE Signature
            self.get_pe_signature(f)
            # 4. File Header
            self.get_file_header(f)
            # 5. Optional Header
            self.get_optional_header(f)
            # 6. Section Headers
            self.get_section_headers(f)

        print("Program End.")
    
    def get_dos_header(self, f) :
        print("# DOS Header")

    def get_dos_stub(self, f) :
        print("# DOS Stub")
    
    def get_pe_signature(self, f) :
        print("# PE Signature")

    def get_file_header(self, f) :
        print("# File Header")

    def get_optional_header(self, f) :
        print("# Optional Header")
    
    def get_section_headers(self, f) :
        print("# Section Headers")

if __name__ == "__main__" :
    # How to Use
    if len(sys.argv) != 2 :
        print("How to Use : python PEParse.py < PE File Path >")
        sys.exit(1)
    
    pe_file = sys.argv[1]
    parse = PEParse(pe_file)
    parse.parse()
