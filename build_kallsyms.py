import struct
import ctypes
import sys
KERNEL_POINTER_PREFIX=0xffffff8000000000
KALLSYMS_ADDRESSES_CHECK_COUNT=40
LABEL_ALIGN=0x100
MAX_KALLSYMS_COUNT=200000
MAX_TOKEN_LEN=0x40
TOKEN_COUNT=0x100
PAGE_SIZE=0x1000
kallsyms_addresses_p = 0
kallsyms_num_syms_p = 0
kallsyms_names_p = 0
kallsyms_markers_p = 0
kallsyms_token_table_p = 0
kallsyms_token_index_p = 0
kallsyms_addresses = []
kallsyms_num_syms = 0
#uint8_t kallsyms_names[MAX_KALLSYMS_COUNT * 0x20];
kallsyms_names = []
#uint8_t kallsyms_token_table[MAX_TOKEN_LEN * TOKEN_COUNT]
kallsyms_token_table = []
#uint16_t kallsyms_token_index[TOKEN_COUNT]

def extract_c_string(byte_data):
    null_index = byte_data.find(b'\0')
    if null_index != -1:
        return byte_data[:null_index].decode('ascii')
    else:
        # 如果没有 '\0'，则解码整个 bytes 对象
        return byte_data.decode('ascii')

def is_special_ascii(value):
    return (value == ord('_') or
            value == ord('.') or
            ord('0') <= value <= ord('9') or
            ord('a') <= value <= ord('z') or
            ord('A') <= value <= ord('Z'))

def is_kernel_pointer(pointer):
    return (pointer & KERNEL_POINTER_PREFIX) == KERNEL_POINTER_PREFIX

def is_kallsym_address_page(page):
    addresses = struct.unpack("<" + KALLSYMS_ADDRESSES_CHECK_COUNT*"Q", page[:KALLSYMS_ADDRESSES_CHECK_COUNT * 8])
    # print(addresses)
    pre = 0
    for addr in addresses:
        if addr < pre or (not is_kernel_pointer(addr)):
            return False
        pre = addr
    return True

def main(filename="kernel_dump.data"):
    f = open(filename, "rb")
    kernel_data = f.read()
    f.close()
    print("[ ] try to find kallsyms_addresses pointer...")
    most_front_page_addr = -1
    for page_off in range(0, 6000, 100):
        if is_kallsym_address_page(kernel_data[page_off * PAGE_SIZE : page_off * PAGE_SIZE + PAGE_SIZE]):
            most_front_page_addr = page_off
            break
    if most_front_page_addr == -1:
        print("[-] can't find kallsyms_addresses")
        return
    # print(f"most_front_page_addr {most_front_page_addr}")
    page_off = most_front_page_addr - 1
    while page_off > 0:
        if is_kallsym_address_page(kernel_data[page_off * PAGE_SIZE : page_off * PAGE_SIZE + PAGE_SIZE]):
            most_front_page_addr = page_off
            page_off -= 1
        else:
            break
    kallsyms_addresses_p = 0
    # print(f"most_front_page_addr2 {most_front_page_addr}")
    previous_page = most_front_page_addr - 1
    if previous_page < 0:
        print("[-] can't find kallsyms_addresses unexpected")
        return
    addresses = struct.unpack("<" + 512*"Q", kernel_data[previous_page * PAGE_SIZE: previous_page * PAGE_SIZE + PAGE_SIZE])
    index = 510
    while index >= 0:
        if is_kernel_pointer(addresses[index]) and is_kernel_pointer(addresses[index + 1]):
            kallsyms_addresses_p = previous_page * PAGE_SIZE + index * 8
            index -= 2
        else:
            break
    if not kallsyms_addresses_p:
        print("[-] can't find kallsyms_addresses unexpected 2")
        return
    print(f"[+] find kallsyms_addresses at {kallsyms_addresses_p:#x}")
    print("[ ] try to find kallsyms_num_syms...")
    max_search_offset = MAX_KALLSYMS_COUNT * 8
    search_off = 0
    while search_off < max_search_offset:
        clip_data = kernel_data[kallsyms_addresses_p + search_off: kallsyms_addresses_p + search_off + 16]
        values = struct.unpack("<QQ", clip_data)
        if (not is_kernel_pointer(values[0])) and (values[1] == 0):
            kallsyms_num_syms_p = kallsyms_addresses_p + search_off
            kallsyms_num_syms = values[0]
            break
        search_off += 0x100
    if search_off >= max_search_offset:
        print("[-] do not find kallsyms_num_syms. unexpected")
        return
    print(f"[+] find kallsyms_num_syms of value {kallsyms_num_syms} at {kallsyms_num_syms_p:#x}")
    kallsyms_names_p = kallsyms_num_syms_p + 0x100
    print(f"[+] find kallsyms_names at {kallsyms_names_p:#x}")
    print("[ ] try to find kallsyms_markers...")
    max_search_offset = MAX_KALLSYMS_COUNT * 32
    search_off = 0
    while search_off < max_search_offset:
        clip_data = kernel_data[kallsyms_names_p + search_off: kallsyms_names_p + search_off + 16]
        values = struct.unpack("<QQ", clip_data)
        # print(values)
        if (values[0] == 0) and (values[1] > 0):
            kallsyms_markers_p = kallsyms_names_p + search_off
            break
        search_off += 0x100
    if search_off >= max_search_offset:
        print("[-] do not find kallsyms_markers. unexpected")
        return
    print(f"[+] find kallsyms_markers_p at {kallsyms_markers_p:#x}");
    print("[ ] try to find kallsyms_token_table...");
    max_search_offset = 0x5000
    search_off = 0
    while search_off < max_search_offset:
        values = kernel_data[kallsyms_markers_p + search_off: kallsyms_markers_p + search_off + 16]
        if is_special_ascii(values[6]) or is_special_ascii(values[7]):
            kallsyms_token_table_p = kallsyms_markers_p + search_off
            break
        search_off += 0x100
    if search_off >= max_search_offset:
        print("[-] do not find kallsyms_token_table. unexpected")
        return
    print(f"[+] find kallsyms_token_table_p at {kallsyms_token_table_p:#x}")
    print("[ ] try to find kallsyms_token_index...")
    max_search_offset = 0x1000
    search_off = 0
    while search_off < max_search_offset:
        clip_data = kernel_data[kallsyms_token_table_p + search_off: kallsyms_token_table_p + search_off + 4]
        values = struct.unpack("<HH", clip_data)
        # print(values)
        if (values[0] == 0) and (values[1] > 0):
            kallsyms_token_index_p = kallsyms_token_table_p + search_off
            break
        search_off += 0x100
    if search_off >= max_search_offset:
        print("[-] do not find kallsyms_token_index_p. unexpected")
        return
    print(f"[+] find kallsyms_token_index_p at {kallsyms_token_index_p:#x}")
    print("[ ] start parse kallsyms...")
    for index in range(TOKEN_COUNT):
        token_off = struct.unpack("<H", kernel_data[kallsyms_token_index_p + index * 2 :  kallsyms_token_index_p + index * 2 + 2])[0]
        c_string = extract_c_string(kernel_data[kallsyms_token_table_p + token_off:kallsyms_token_index_p])
        kallsyms_token_table.append(c_string)
    # print(kallsyms_token_table)
    cur_pos = kallsyms_names_p
    kallsyms_output_line = []
    for index in range(kallsyms_num_syms):
        sym_token_len = struct.unpack("<B", kernel_data[cur_pos:cur_pos + 1])[0]
        cur_pos += 1
        symbol = ""
        for _ in range(sym_token_len):
            symbol += kallsyms_token_table[kernel_data[cur_pos]]
            cur_pos += 1
        kallsyms_names.append(symbol)
        kallsyms_addresses.append(struct.unpack("<Q", kernel_data[kallsyms_addresses_p + 8 * index : kallsyms_addresses_p + 8 * index + 8])[0])
        kallsyms_output_line.append(f"{kallsyms_addresses[index]:#x} {kallsyms_names[index]}\n")
    f = open("kallsyms.txt", "w")
    f.writelines(kallsyms_output_line)
    f.close()
    print("[ ] Done. Please check result in 'kallsyms.txt'")

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        main(sys.argv[1])
    else:
        main()


