# [ Re3ue ] RVA_RAW.py

import os
import sys

"""
"""
class RVARAW :
    """
    """
    def __init__(self) :
        self.rva = 0
        self.raw = 0
        self.VirtualAddress = 0
        self.PointerToRawData = 0
    
    """
    """
    def get_rva_from_raw(self) :
        self.rva = self.raw + self.VirtualAddress - self.PointerToRawData

        print(f"RVA : {self.rva}")
    
    """
    """
    def get_raw_from_rva(self) :
        self.raw = self.rva - self.VirtualAddress + self.PointerToRawData

        print(f"RAW : {self.raw}")
    
    """
    """
    def get_result(self) :
        output = 0

        print("# Input")
        index = input("[ 1 : Get RVA From RAW / 2 : Get RAW From RVA ] : ")

        if index == "1" :
            print("RAW")
            self.raw = int(input(">>>> "))
            print("VirtualAddress")
            self.VirtualAddress = int(input(">>>> "))
            print("PointerToRawData")
            self.PointerToRawData = int(input(">>>> "))

            self.get_rva_from_raw()
        
        elif index == "2" :
            print("RVA")
            self.rva = int(input(">>>> "))
            print("VirtualAddress")
            self.VirtualAddress = int(input(">>>> "))
            print("PointerToRawData")
            self.PointerToRawData = int(input(">>>> "))

            self.get_raw_from_rva()

        else :   
            print("...")

# Main
if __name__ == "__main__" :
    # How to Use
    if len(sys.argv) != 1 :
        print("How to Use : python RVA_RAW.py")
        sys.exit(1)
    
    rvaraw = RVARAW()
    rvaraw.get_result()
