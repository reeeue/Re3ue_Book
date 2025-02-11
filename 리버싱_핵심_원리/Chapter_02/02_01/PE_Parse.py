# [ Re3ue ] PE_Parse.py

import os
import sys
import struct

DOS_HEADER_SIGNATURE = b'\x4D\x5A'
NT_HEADER_SIGNATURE = b'\x50\x45\x00\x00'

class PEParse :
    """
    """
    def __init__(self, file_path) :
        self.file_path = file_path
        self.section_list = []

    """
    """
    def print_hex(self, int) :
        format = "0x" + f"{hex(int)[2:].upper()}"

        return format
    
    """
    """
    def get_dos_header(self, f) :
        print("\n# DOS Header")

        f.seek(0)
        e_magic = f.read(2) # DOS Header Signature

        if e_magic != DOS_HEADER_SIGNATURE :
            print("\n[ ERROR ] FAIL - DOS Header Signature")
            print(f">>>>>>>>>> File Path : {self.file_path}")
            sys.exit(1)
        
        dos_header_data = f.read(62)
        dos_header_fields = struct.unpack("<HHHHHHHHHHHHH8sHH20sI", dos_header_data)

        e_lfanew = dos_header_fields[17] # NT Header Offset

        print(f"[ + ] e_magic ( Magic Number ) : {" ".join(f"{byte:02X}" for byte in e_magic)}")
        print(f"  ( ... )")
        print(f"[ + ] e_lfanew ( NT Header Offset ) : {self.print_hex(e_lfanew)}")

        return e_lfanew
    
    """
    """
    def get_data_directory_name(self, data_directory_index) :
        data_directory_names = {
            0 : "Export Directory",
            1 : "Import Directory",
            2 : "Resource Directory",
            3 : "Exception Directory",
            4 : "Security Directory",
            5 : "Base Relocation Directory",
            6 : "Debug Directory",
            7 : "( * Reserved * ) Archiecture Specific Data",
            8 : "( * Reserved * ) Global Pointer Register",
            9 : "TLS Directory",
            10 : "Load Configuration Directory",
            11 : "Bound Import Directory",
            12 : "IAT ( Import Address Table )",
            13 : "Delay Import Directory",
            14 : "( .NET ) COM Descriptor Directory",
            15 : "( * Reserved * )",
        }

        return data_directory_names.get(data_directory_index)
    
    """
    """
    def get_data_directory(self, data_directory_index, data_directory_data) :
        data_directory_name = self.get_data_directory_name(data_directory_index)

        print(f"    [ - ] #{data_directory_index} {data_directory_name}")
        print(f"        Virtual Address : {self.print_hex(data_directory_data[0])}")
        print(f"        Size : {self.print_hex(data_directory_data[1])}")
    
    """
    """
    def get_data_directories(self, data_directory_number, data_directory) :
        index = 0

        for offset in range(data_directory_number) :
            data_directory_data = struct.unpack("<II", data_directory[offset*8:(offset+1)*8])

            self.get_data_directory(index, data_directory_data)

            index += 1

    """
    """
    def get_dos_stub(self, f, nt_header_offset) :
        print("\n# DOS Stub")

        dos_stub_size = nt_header_offset - 64
        dos_stub_data = f.read(dos_stub_size)

        for i in range(0, dos_stub_size, 16) :
            line = " ".join(f"{byte:02X}" for byte in dos_stub_data[i:i+16])
            print(line)
    
    """
    """
    def get_file_header(self, file_header_data) :
        print("\n# NT Header - File Header")

        file_header_fields = struct.unpack("<HHIIIHH", file_header_data)

        Machine = file_header_data[0]
        NumberOfSections = file_header_fields[1]
        SizeOfOptionalHeader = file_header_fields[5]
        Characteristics = file_header_data[6]

        print(f"[ + ] Machine : {self.print_hex(Machine)}")
        print(f"[ + ] Number of Sections : ( Decimal ) {NumberOfSections}")
        print(f"  ( ... )")
        print(f"[ + ] Size of Optional Header : ( Decimal ) {SizeOfOptionalHeader}")
        print(f"[ + ] Characteristics : {self.print_hex(file_header_data[6])}")

        return NumberOfSections, SizeOfOptionalHeader
    
    """
    """
    def get_optional_header(self, optional_header_data) :
        print("\n# NT Header - Optional Header")

        if len(optional_header_data) == 224 :
            print("    >>>> PE32")

            optional_header_fields = struct.unpack("<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII128s", optional_header_data)

            Magic = optional_header_fields[0]
            AddressOfEntryPoint = optional_header_fields[6]
            ImageBase = optional_header_fields[9] # 4 Bytes
            SectionAlignment = optional_header_fields[10]
            FileAlignment = optional_header_fields[11]
            SizeOfImage = optional_header_fields[19]
            SizeOfHeaders = optional_header_fields[20]
            Subsystem = optional_header_fields[22]
            NumberOfRvaAndSizes = optional_header_fields[29]
            DataDirectory = optional_header_fields[30]
        
        elif len(optional_header_data) == 240 :
            print("    >>>> PE32+")

            optional_header_fields = struct.unpakc("<HBBIIIIIQIIHHHHHHIIIIHHQQQQII128s", optional_header_data)

            Magic = optional_header_fields[0]
            AddressOfEntryPoint = optional_header_fields[6]
            ImageBase = optional_header_fields[8] # 8 Bytes
            SectionAlignment = optional_header_fields[9]
            FileAlignment = optional_header_fields[10]
            SizeOfImage = optional_header_fields[18]
            SizeOfHeaders = optional_header_fields[19]
            Subsystem = optional_header_fields[21]
            NumberOfRvaAndSizes = optional_header_fields[28]
            DataDirectory = optional_header_fields[29]

        else :
            print("    >>>> ??")

            return
                
        print(f"[ + ] Magic : {self.print_hex(Magic)}")
        print(f"  ( ... )")
        print(f"[ + ] AddressOfEntryPoint : {self.print_hex(AddressOfEntryPoint)}")
        print(f"  ( ... )")
        print(f"[ + ] ImageBase : {self.print_hex(ImageBase)}")
        print(f"[ + ] SectionAlignment : {self.print_hex(SectionAlignment)}")
        print(f"[ + ] FileAlignment : {self.print_hex(FileAlignment)}")
        print(f"  ( ... )")
        print(f"[ + ] SizeOfImage : {self.print_hex(SizeOfImage)}")
        print(f"[ + ] SizeOfHeaders : {self.print_hex(SizeOfHeaders)}")
        print(f"  ( ... )")
        print(f"[ + ] Subsystem : {self.print_hex(Subsystem)}")
        print(f"  ( ... )")
        print(f"[ + ] NumberOfRvaAndSizes : ( Decimal ) {NumberOfRvaAndSizes}")
        print(f"[ + ] DataDirectory")

        self.get_data_directories(NumberOfRvaAndSizes, DataDirectory)

        return
    
    """
    """
    def get_nt_header(self, f, nt_header_offset) :
        print("\n# NT Header")

        f.seek(nt_header_offset)
        nt_header_signature = f.read(4)

        if nt_header_signature != NT_HEADER_SIGNATURE :
            print("\n[ ERROR ] FAIL - NT Header Signature")
            print(f">>>>>>>>>> File Path : {self.file_path}")
            sys.exit(1)
        
        file_header_data = f.read(20)
        NumberOfSections, SizeOfOptionalHeader = self.get_file_header(file_header_data)

        optional_header_data = f.read(SizeOfOptionalHeader)
        self.get_optional_header(optional_header_data)

        section_headers_offset = nt_header_offset + 24 + SizeOfOptionalHeader

        return NumberOfSections, section_headers_offset

    """
    """
    def get_section_header(self, f, index) :
        print(f"\n#{index} - Section Header")

        section_name = f.read(8).decode("utf-8", errors="ignore")

        section_header_data = f.read(32)

        section_header_fields = struct.unpack("<IIIIIIHHI", section_header_data)

        VirtualSize = section_header_fields[1]
        VirtualAddress = section_header_fields[2]
        SizeOfRawData = section_header_fields[3]
        PointerToRawData = section_header_fields[4]
        Characteristics = section_header_fields[8]

        print(f"[ + ] Section Name : {section_name}")
        print(f"[ + ] VirtualSize : {self.print_hex(VirtualSize)}")
        print(f"[ + ] VirtualAddress : {self.print_hex(VirtualAddress)}")
        print(f"[ + ] SizeOfRawData : {self.print_hex(SizeOfRawData)}")
        print(f"[ + ] PointerToRawData : {self.print_hex(PointerToRawData)}")
        print(f"[ + ] Characteristics : {self.print_hex(Characteristics)}")
    
    """
    """
    def get_section_headers(self, f, NumberOfSections, section_headers_offset) :
        print("\n# Section Headers")

        print("\n========================================")

        section_list = []

        for index in range(NumberOfSections) :
            f.seek(section_headers_offset + 40 * index)
            self.get_section_header(f, index)
        
        print("\n========================================")

    """
    """
    def parse(self) :
        print("Program Start.")

        with open(self.file_path, "rb") as f :
            # 1-1. DOS Header
            nt_header_offset = self.get_dos_header(f)
            # 1-2. DOS Stub
            self.get_dos_stub(f, nt_header_offset)
            # 2. NT Header : File Header + Optional Header
            NumberOfSections, section_headers_offset = self.get_nt_header(f, nt_header_offset)
            # 3. Section Headers
            self.get_section_headers(f, NumberOfSections, section_headers_offset)

        print("\nProgram End.")

# Main
if __name__ == "__main__" :
    # How to Use
    if len(sys.argv) != 2 :
        print("How to Use : python PEParse.py < PE File Path >")
        sys.exit(1)
    
    pe_file = sys.argv[1]
    parse = PEParse(pe_file)
    parse.parse()
