import os
import struct
import json
import tkinter as tk
from tkinter import filedialog
from tkinter import simpledialog



class pcapng_block:
    """! This class manages each block of pcapng file

    """

    def __init__(self, fp):
        """! Constructor for the pcapng_block class
        @param: file pointer of input pcapng to read and fill block data
        """
        self.valid = False
        self.new_data = None
        try:
            type = fp.read(4)
            self.raw_type = type
            if type == b"\n\r\r\n":
                self.type = 'S'
            elif type == b"\x01\x00\x00\x00" :
                self.type = 'ID'
            elif type == b"\x02\x00\x00\x00" :
                self.type = 'P'
            elif type == b"\x03\x00\x00\x00" :
                self.type = 'SP'
            elif type == b"\x04\x00\x00\x00" :
                self.type = 'NR'
            elif type == b"\x05\x00\x00\x00":
                self.type = 'IS'
            elif type == b"\x06\x00\x00\x00":
                self.type = 'EP'
            elif type == b"\x07\x00\x00\x00":
                self.type = 'T'
            elif type == b"\x08\x00\x00\x00":
                self.type = 'I'
            else:
                return

            self.len = struct.unpack('<i',fp.read(4))[0]
            if self.len < 12 or self.len%4 != 0 :
                return
            elif self.len > 12 :
                self.data = fp.read(self.len - 12)

            ### Read repeated last 4 bytes in block to move file pointer to start of next pcapng block
            fp.read(4)
            ### Set validity flag indicating successful block parsing
            self.valid = True

        except:
            self.valid = False


    def section_order_validity(self,valid_states):
        """! This function checks if read section is valid based on PCAPNG standard file format

        @type state: string
        @param valid_states The valid states that the file pointer should reach

        @return: True or False based on block validity
        """
        return  self.type in valid_states



    def add_comment(self,comment,option_len):
        """! The function constructs an option section adding the input comment into it

        @param comment The user provided comment
        @param option_len The read option section, zero if there was no current section

        @return The created option section
        """

        ### 2-bytes option code in little-endian order
        comment_option_section = (1).to_bytes(2, 'little')
        ### check if the comment size is aligned with 32-bit alignment standard
        if len(comment) % 4 != 0:
            comment_size = (len(comment) + (4 - len(comment) % 4))
            comment_option_section += comment_size.to_bytes(2, 'little')
            comment_option_section += comment.encode()
            ### Add zero padding for alignment
            comment_option_section += b"\x00" * (4 - len(comment) % 4)
        else:
            comment_size = len(comment)
            comment_option_section += (len(comment)).to_bytes(2, 'little')
            comment_option_section += comment.encode()

        ### update block size with newly added comment option section
        self.len += 4 + comment_size - option_len
        return comment_option_section



    def add_comment_routine(self,comment):
        """! The function parses Enhanced Packet section to find and manipulate comment optional section

         @param comment The user provided comment

         @return
         """

        ### Reading 4-bytes caplen part
        caplen = struct.unpack('<i', self.data[12:16])[0]
        ### Increase size to packet data if is not aligned to the 32-bit alignment
        if caplen % 4 != 0:
            caplen += (4 - (caplen % 4))

        ### Move forward to start of optional sections
        start_option = 20 + caplen
        new_data = self.data[0:20 + caplen]

        comment_added = False
        ### Move over optional sections to find comment part for the packet
        while start_option+4 <= len(self.data) :

            option_code = struct.unpack('<h', self.data[start_option:start_option + 2])[0]
            option_len = struct.unpack('<h', self.data[start_option + 2:start_option + 4])[0]
            ### Add padding size to option len if it is not aligned
            if option_len % 4 != 0:
                option_len += 4 - option_len % 4

            ### Comment optional type
            if option_code == 1:
                comment_added = True
                new_data += self.add_comment(comment,option_len)

            else:
                ### If data reached end of optional section and there was no comment section
                if option_code == 0 and not comment_added:
                    comment_added = True
                    new_data += self.add_comment(comment,0)

                new_data += self.data[start_option: start_option + 4 + option_len]
            ### move to next section
            start_option += 2 + 2 + option_len

        ### if there was no optional section then add both comment section and a 4-byte end section
        if not comment_added :
            new_data += self.add_comment(comment, 0)
            self.len += 4
            new_data += b"\x00\x00\x00\x00"

        self.data = new_data



    def read_comment_routine(self,desired_packet):

        """! The function parses Enhanced Packet section to find and read comment optional section

         @param desired_packet The packet number to be read

         @return
         """

        caplen = struct.unpack('<i', self.data[12:16])[0]
        ### Increase size to packet data if is not aligned to the 32-bit alignment
        if caplen % 4 != 0:
            caplen += (4 - (caplen % 4))

        ### Move forward to start of optional sections
        start_option = 20 + caplen

        ### Move over optional sections to find comment part for the packet
        while start_option+4 <= len(self.data) :

            option_code = struct.unpack('<h', self.data[start_option:start_option + 2])[0]
            option_len = struct.unpack('<h', self.data[start_option + 2:start_option + 4])[0]
            ### Add padding size to option len if it is not aligned
            if option_len % 4 != 0:
                option_len += 4 - option_len % 4

            ### Comment optional type
            if option_code == 1:
                    print(json.dumps({"packet_number": str(desired_packet),"comment":self.data[start_option+4:start_option+4+option_len].decode("utf-8").rstrip('\x00') }) )
                    return

            ### move to next section
            start_option += 2 + 2 + option_len

        ### Prints null for requested packet comment if no comment optional section was found
        print(json.dumps({"packet_number": str(desired_packet),"comment":None}) )
        return




def main():
    root = tk.Tk()
    root.withdraw()
    try:

        mode =  int(simpledialog.askstring(title="Mode selection",prompt="Please Enter the mode:\n1.Read Comment\n2.Add Comment\n3.exit\n"))
        while mode not in [1,2,3]:
            print("The mode number entered is not valid !!")
            mode = int(simpledialog.askstring(title="Mode selection", prompt="Please Enter the comment mode:\n1.Read Comment\n2.Add Comment\n3.exit\n"))
        if mode == 3:
            exit()
        elif mode == 1:
            print("Mode: Read Comment")
        else:
            print("Mode: Add Comment")


        print("select pcapng file ...")
        file_input = filedialog.askopenfilename(filetypes=[("PCAPNG files", "*.pcapng")])
        while not os.path.exists(file_input):
            file_input = filedialog.askopenfilename(filetypes=[("PCAPNG files", "*.pcapng")])
        print("selected file: ",file_input)

        desired_packet =  int(simpledialog.askstring(title="Packet Number",prompt="Please Enter a packet number higher than 0\n"))
        while desired_packet < 1:
            print("The packet number entered is not valid !!")
            desired_packet = int(simpledialog.askstring(title="Packet Number",prompt="Please Enter a packet number higher than 0\n"))

    except:
        print("Invalid Input")
        exit()


    with open(file_input,"rb") as fp:

        ### Read first block from input file
        block = pcapng_block(fp)

        ### The first section of pcapng file always should be a Section Header
        valid_section_state = ["S"]
        current_packet = 0

        ### Adding Mode
        if mode == 2:

            comment = simpledialog.askstring(title="Comment",prompt="Please Enter your comment to be added to packet number: " + str(desired_packet) + "\n")

            ### Create and open new file for writing new pcapng with comment
            file_output = file_input[0:file_input.rfind(".") + 1]
            file_output += "comment_added.pcapng"
            write_fp = open(file_output, "wb")

            ### loops over block till read block is invalid
            while block.valid and block.section_order_validity(valid_section_state):

                ### Checks if the crrent block is an Enhanced Packet
                if block.type == "EP" :
                    current_packet += 1
                    ### Checks if the current packet block is the number needed by the user
                    if desired_packet == current_packet:
                        block.add_comment_routine(comment)

                ### Writing the block (the block data is changed if the comment was added)
                write_fp.write(block.raw_type)
                write_fp.write(block.len.to_bytes(4,"little"))
                write_fp.write(block.data)
                write_fp.write(block.len.to_bytes(4,"little"))

                ### Reads next block
                block = pcapng_block(fp)
                valid_section_state = ["S","ID","SP","EP","IS","NR","I","T","P"]

            write_fp.close()
            print("File is saved as ",file_output)

        ### Reading Mode
        else:

            ### loops over block till read block is invalid
            while block.valid and block.section_order_validity(valid_section_state):

                ### Checks if the crrent block is an Enhanced Packet
                if block.type == "EP":
                    current_packet += 1
                    ### Checks if the current packet block is the number needed by the user
                    if desired_packet == current_packet:
                        block.read_comment_routine(desired_packet)

                ### Reads next block
                block = pcapng_block(fp)
                valid_section_state = ["S", "ID", "SP", "EP", "IS", "NR", "I", "T", "P"]

        ### If the Enhanced Packet block are lower than packet number specified by the user
        if desired_packet > current_packet:
            print("Out of range packet number")






if __name__ == "__main__":
    main()